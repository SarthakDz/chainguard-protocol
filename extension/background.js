// ChainGuard Extension — Background Service Worker
// Intercepts all blockchain RPC calls and routes to Sentinel Backend

const SENTINEL_URL = 'http://localhost:8000';
const RPC_PATTERNS = [
  '*://*.infura.io/*',
  '*://*.alchemy.com/*',
  '*://*.quicknode.io/*',
  '*://*.helius-rpc.com/*',
  '*://polygon-rpc.com/*',
];

// Threat cache (avoid redundant API calls)
const threatCache = new Map(); // key: tx_hash/address → {verdict, timestamp}
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

let protectionActive = false;
let sessionStats = { threats_blocked: 0, txs_analyzed: 0, start_time: null };
let wsConnection = null;

// ─── INITIALIZATION ─────────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    protection_active: false,
    sentinel_url: SENTINEL_URL,
    risk_threshold: 70,
    session_stats: sessionStats
  });
  console.log('[ChainGuard] Extension installed. Click ACTIVATE to protect.');
});

// ─── MESSAGE HANDLERS (from popup and content scripts) ─────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.type) {
    
    case 'ACTIVATE_PROTECTION':
      activateProtection().then(sendResponse);
      return true;
    
    case 'DEACTIVATE_PROTECTION':
      deactivateProtection().then(sendResponse);
      return true;
    
    case 'GET_STATUS':
      sendResponse({
        active: protectionActive,
        stats: sessionStats,
        agents: agentStatuses
      });
      break;
    
    case 'TX_INTERCEPT':
      // Content script intercepted a tx signing request
      handleTransactionIntercept(message.data).then(sendResponse);
      return true;
    
    case 'WALLET_ACCESS_DETECTED':
      handleWalletAccess(message.data).then(sendResponse);
      return true;
      
    case 'CONTRACT_INTERACTION':
      handleContractInteraction(message.data).then(sendResponse);
      return true;
  }
});

// ─── PROTECTION ACTIVATION ──────────────────────────────────────────────────

async function activateProtection() {
  try {
    // Check Sentinel backend is reachable
    const healthCheck = await fetch(`${SENTINEL_URL}/health`);
    if (!healthCheck.ok) {
      return { success: false, error: 'Cannot reach ChainGuard Sentinel backend' };
    }
    
    // Start all agents via backend
    const activateResponse = await fetch(`${SENTINEL_URL}/api/v1/activate`, {
      method: 'POST'
    });
    const data = await activateResponse.json();
    
    if (!data.all_agents_active) {
      return { success: false, error: 'Some agents failed to start', details: data };
    }
    
    protectionActive = true;
    sessionStats = { 
      threats_blocked: 0, 
      txs_analyzed: 0, 
      start_time: Date.now() 
    };
    
    // Connect WebSocket for live threat stream
    connectWebSocket();
    
    // Update extension icon
    chrome.action.setIcon({ path: 'icons/icon_active.png' });
    chrome.action.setBadgeText({ text: 'ON' });
    chrome.action.setBadgeBackgroundColor({ color: '#10b981' });
    
    await chrome.storage.local.set({ 
      protection_active: true,
      session_stats: sessionStats
    });
    
    return { success: true, agent_count: 8 };
    
  } catch (error) {
    return { success: false, error: error.message };
  }
}

async function deactivateProtection() {
  protectionActive = false;
  
  if (wsConnection) {
    wsConnection.close();
    wsConnection = null;
  }
  
  chrome.action.setIcon({ path: 'icons/icon.png' });
  chrome.action.setBadgeText({ text: '' });
  
  await chrome.storage.local.set({ protection_active: false });
  
  return { success: true };
}

// ─── WEBSOCKET CONNECTION ────────────────────────────────────────────────────

function connectWebSocket() {
  try {
    wsConnection = new WebSocket(`ws://localhost:8000/ws/monitor`);
    
    wsConnection.onmessage = (event) => {
      const data = JSON.parse(event.data);
      
      if (data.type === 'threat_blocked') {
        // Show browser notification
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon48.png',
          title: '🛡️ ChainGuard: Threat Blocked',
          message: data.threat.headline,
          priority: 2
        });
        
        sessionStats.threats_blocked++;
        updateBadgeWithThreat();
      }
    };
    
    wsConnection.onclose = () => {
      // Reconnect after 5 seconds
      if (protectionActive) {
        setTimeout(connectWebSocket, 5000);
      }
    };
  } catch (e) {
    console.error('[ChainGuard] WebSocket connection failed:', e);
  }
}

// ─── TRANSACTION INTERCEPTION ────────────────────────────────────────────────

async function handleTransactionIntercept(txData) {
  if (!protectionActive) return { proceed: true };
  
  sessionStats.txs_analyzed++;
  
  try {
    // Check cache first
    const cacheKey = `tx:${txData.hash || txData.to}`;
    const cached = threatCache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
      return { 
        proceed: cached.verdict !== 'BLOCK', 
        verdict: cached.verdict,
        from_cache: true 
      };
    }
    
    // Send to Sentinel for analysis
    const response = await fetch(`${SENTINEL_URL}/api/v1/scan/transaction`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tx_hash: txData.hash,
        chain: txData.chain || 'ethereum',
        raw_data: txData.data,
        method: txData.method,
        to: txData.to,
        from: txData.from,
        value: txData.value,
        requesting_process: 'browser_extension'
      })
    });
    
    const result = await response.json();
    
    // Cache the result
    threatCache.set(cacheKey, { 
      verdict: result.verdict, 
      timestamp: Date.now() 
    });
    
    if (result.verdict === 'BLOCK') {
      sessionStats.threats_blocked++;
      updateBadgeWithThreat();
    }
    
    return {
      proceed: result.verdict !== 'BLOCK',
      verdict: result.verdict,
      risk_score: result.risk_score,
      threat_type: result.threat_type,
      user_message: result.threat_type === 'BLOCK' 
        ? `Transaction blocked: ${result.threat_type} detected (${result.risk_score}/100 risk)`
        : null
    };
    
  } catch (error) {
    console.error('[ChainGuard] Scan failed:', error);
    // Fail open (don't block if scanner is unavailable)
    return { proceed: true, error: error.message };
  }
}

// ─── CONTRACT INTERACTION HANDLER ───────────────────────────────────────────

async function handleContractInteraction(data) {
  if (!protectionActive) return { proceed: true };
  
  try {
    const response = await fetch(`${SENTINEL_URL}/api/v1/scan/contract`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    
    const result = await response.json();
    
    return {
      proceed: result.verdict !== 'BLOCK',
      verdict: result.verdict,
      risk_score: result.risk_score,
      user_explanation: result.user_explanation,
      simulation_result: result.simulation_result
    };
    
  } catch (error) {
    return { proceed: true };
  }
}

// ─── UI HELPERS ─────────────────────────────────────────────────────────────

function updateBadgeWithThreat() {
  chrome.action.setBadgeText({ text: '!' });
  chrome.action.setBadgeBackgroundColor({ color: '#ef4444' });
  
  // Reset after 5 seconds
  setTimeout(() => {
    if (protectionActive) {
      chrome.action.setBadgeText({ text: 'ON' });
      chrome.action.setBadgeBackgroundColor({ color: '#10b981' });
    }
  }, 5000);
}

let agentStatuses = {};

// Poll agent status every 30 seconds
setInterval(async () => {
  if (!protectionActive) return;
  try {
    const response = await fetch(`${SENTINEL_URL}/api/v1/agents/status`);
    const data = await response.json();
    agentStatuses = data.agents;
  } catch (e) {}
}, 30000);
