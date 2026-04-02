// ChainGuard Extension — Content Script
// Hooks window.ethereum and window.solana to intercept all signing requests

(function() {
  'use strict';

  // Inject our wallet hook into page context
  const script = document.createElement('script');
  script.src = chrome.runtime.getURL('injected.js');
  script.onload = function() { this.remove(); };
  (document.head || document.documentElement).appendChild(script);

  // Listen for events from injected.js (page context → content script)
  window.addEventListener('chainguard:tx_request', async (event) => {
    const { txData, requestId } = event.detail;
    
    // Forward to background script for analysis
    const result = await chrome.runtime.sendMessage({
      type: 'TX_INTERCEPT',
      data: txData
    });
    
    // Send result back to page context
    window.dispatchEvent(new CustomEvent(`chainguard:tx_response:${requestId}`, {
      detail: result
    }));
  });

  window.addEventListener('chainguard:contract_interaction', async (event) => {
    const { data, requestId } = event.detail;
    
    const result = await chrome.runtime.sendMessage({
      type: 'CONTRACT_INTERACTION',
      data
    });
    
    window.dispatchEvent(new CustomEvent(`chainguard:contract_response:${requestId}`, {
      detail: result
    }));
  });

  // Monitor clipboard for private keys
  document.addEventListener('paste', (event) => {
    const text = event.clipboardData?.getData('text') || '';
    if (text.length > 50) {
      chrome.runtime.sendMessage({
        type: 'CLIPBOARD_CONTENT',
        data: { content: text.substring(0, 200), source: 'paste_event' }
      });
    }
  });

})();
