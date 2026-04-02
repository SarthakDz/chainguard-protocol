# 🔧 ChainGuard Protocol — Backend API Specification

## Overview

The Sentinel Backend is a **FastAPI Python service** that coordinates:
- All 8 AI agents via Redis Streams
- Threat intelligence aggregation
- Risk scoring engine
- WebSocket live threat stream
- On-chain contract interactions

**Base URL:** `http://localhost:8000/api/v1`

---

## Core API Endpoints

### POST `/scan/transaction`
Scan a transaction for malicious content.

**Request:**
```json
{
  "tx_hash": "0xabc123...",
  "chain": "ethereum",
  "raw_data": "4d5a9000...",
  "method": "eth_getTransactionByHash",
  "requesting_process": "chrome.exe"
}
```

**Response:**
```json
{
  "scan_id": "scan_7f3a9b2c",
  "verdict": "BLOCK",
  "risk_score": 94,
  "threat_type": "ransomware_dropper",
  "malware_family": "locky_v4",
  "confidence": 0.97,
  "indicators": [
    "PE header (MZ) detected in OP_RETURN data",
    "Entropy 7.91 — consistent with packed executable",
    "Signature match: Locky v4 byte pattern 0x4a7f..."
  ],
  "action_taken": "RPC_CALL_BLOCKED",
  "agent_verdicts": {
    "payload_scanner": "CRITICAL",
    "threat_intel": "HIGH",
    "reputation_oracle": "HIGH",
    "network_guard": "HIGH"
  },
  "processing_time_ms": 187
}
```

---

### POST `/scan/contract`
Analyze a smart contract before user interaction.

**Request:**
```json
{
  "contract_address": "0xDeadBeef...",
  "chain": "ethereum",
  "proposed_method": "approve",
  "proposed_params": {"spender": "0xEvil...", "amount": "115792089..."},
  "user_wallet": "0xUser...",
  "simulation": true
}
```

**Response:**
```json
{
  "contract_address": "0xDeadBeef...",
  "risk_score": 88,
  "risk_level": "HIGH",
  "is_verified": false,
  "contract_age_days": 3,
  "verdict": "BLOCK",
  "vulnerabilities": [
    {
      "type": "unlimited_approval_drain",
      "severity": "CRITICAL",
      "description": "Requesting MAX_UINT256 approval — grants unlimited token access",
      "impact": "Spender can drain entire token balance at any time"
    }
  ],
  "simulation_result": {
    "user_tokens_sent": [],
    "user_tokens_received": [],
    "approvals_granted": [
      {"token": "USDC", "spender": "0xEvil...", "amount": "UNLIMITED"}
    ],
    "net_assessment": "No immediate token loss, but UNLIMITED approval granted to unverified contract"
  },
  "user_explanation": "This transaction would give an unknown contract unlimited access to all your USDC. This is a common wallet drainer setup.",
  "scam_pattern": "drainer"
}
```

---

### POST `/threat/report`
Submit a new threat to the registry.

**Request:**
```json
{
  "indicator_type": "address",
  "value": "0xMalicious...",
  "threat_type": "wallet_drainer",
  "severity": "HIGH",
  "evidence_description": "Contract drained 47 wallets in 24 hours",
  "evidence_files": ["base64_screenshot...", "base64_txlist..."]
}
```

---

### GET `/threat/lookup/{indicator}`
Look up a threat indicator.

**Response:**
```json
{
  "indicator": "0xSuspicious...",
  "is_blacklisted": true,
  "reputation_score": 4,
  "risk_category": "BLACKLISTED",
  "threat_type": "ransomware_c2",
  "malware_family": "locky_v4",
  "first_reported": "2025-01-10T08:23:00Z",
  "confirmations": 5,
  "sources": ["chainabuse", "misttrack", "chainguard_oracle"],
  "evidence_ipfs": "QmXxx...",
  "on_chain_record": true
}
```

---

### GET `/agents/status`
Get health status of all 8 agents.

**Response:**
```json
{
  "all_active": true,
  "agents": {
    "orchestrator": {
      "status": "ACTIVE",
      "uptime_seconds": 3847,
      "events_processed": 1243,
      "threats_detected": 7,
      "avg_response_ms": 89
    },
    "payload_scanner": { "status": "ACTIVE", ... },
    "wallet_sentinel": { "status": "ACTIVE", ... },
    "threat_intel": { "status": "ACTIVE", "last_sync": "2025-01-15T14:28:00Z" },
    "contract_auditor": { "status": "ACTIVE", "simulations_run": 43 },
    "incident_responder": { "status": "ACTIVE", "incidents_handled": 3 },
    "reputation_oracle": { "status": "ACTIVE", "addresses_scored": 891 },
    "network_guard": { "status": "ACTIVE", "processes_monitored": 127 }
  }
}
```

---

### WebSocket `/ws/monitor`
Live threat stream for dashboard.

**Connection:**
```javascript
const ws = new WebSocket('ws://localhost:8000/ws/monitor');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  // data.type: "tx_scanned" | "threat_blocked" | "agent_alert" | "heartbeat"
  
  if (data.type === "threat_blocked") {
    // Show alert to user
    showThreatAlert(data.threat);
  }
};
```

**Event Types:**
```json
// tx_scanned
{
  "type": "tx_scanned",
  "tx_hash": "0xabc...",
  "verdict": "PASS",
  "risk_score": 12,
  "timestamp": "2025-01-15T14:32:07Z"
}

// threat_blocked  
{
  "type": "threat_blocked",
  "threat": {
    "type": "ransomware_dropper",
    "malware_family": "locky_v4",
    "headline": "Ransomware dropper blocked",
    "summary": "...",
    "severity": "CRITICAL"
  }
}

// agent_alert
{
  "type": "agent_alert",
  "agent": "network_guard",
  "message": "Non-browser process attempting blockchain access",
  "severity": "HIGH"
}
```

---

## Backend Module: sentinel.py

```python
from fastapi import FastAPI, WebSocket, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import json
from .agents.orchestrator import OrchestratorAgent
from .rpc_proxy import RPCProxy
from .scoring_engine import ScoringEngine
from .intel_aggregator import IntelAggregator

app = FastAPI(title="ChainGuard Sentinel", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "chrome-extension://"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize core components
orchestrator = OrchestratorAgent()
rpc_proxy = RPCProxy()
scorer = ScoringEngine()
intel = IntelAggregator()

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    
    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except:
                self.active_connections.remove(connection)

manager = ConnectionManager()

@app.post("/api/v1/scan/transaction")
async def scan_transaction(request: TransactionScanRequest):
    result = await orchestrator.analyze_transaction(request)
    await manager.broadcast({
        "type": "tx_scanned",
        "tx_hash": request.tx_hash,
        "verdict": result.verdict,
        "risk_score": result.risk_score
    })
    
    if result.verdict == "BLOCK":
        await manager.broadcast({
            "type": "threat_blocked",
            "threat": result.threat_summary
        })
    
    return result

@app.post("/api/v1/scan/contract")
async def scan_contract(request: ContractScanRequest):
    return await orchestrator.audit_contract(request)

@app.get("/api/v1/threat/lookup/{indicator}")
async def lookup_threat(indicator: str):
    return await intel.lookup(indicator)

@app.get("/api/v1/agents/status")
async def get_agent_status():
    return await orchestrator.get_all_agent_status()

@app.websocket("/ws/monitor")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await asyncio.sleep(10)
            await websocket.send_text(json.dumps({"type": "heartbeat"}))
    except:
        pass

@app.on_event("startup")
async def startup():
    await orchestrator.initialize_all_agents()
    asyncio.create_task(intel.start_polling())
    print("✅ ChainGuard Sentinel started. All agents active.")
```

---

## Risk Scoring Engine

```python
# backend/scoring_engine.py

class ScoringEngine:
    """
    Multi-factor risk scoring engine.
    Input: signals from all agents
    Output: 0-100 risk score + verdict
    """
    
    WEIGHTS = {
        "payload_scanner": 0.30,     # Highest weight — direct evidence
        "threat_intel": 0.25,        # Strong — multiple sources
        "reputation_oracle": 0.20,   # Important context
        "contract_auditor": 0.15,    # Pre-execution evidence
        "network_guard": 0.10,       # Process-level context
    }
    
    SEVERITY_SCORES = {
        "CRITICAL": 100,
        "HIGH": 75,
        "MEDIUM": 45,
        "LOW": 20,
        "CLEAN": 0
    }
    
    def calculate_score(self, agent_signals: dict) -> tuple[int, str]:
        """
        Returns (risk_score, verdict)
        """
        weighted_score = 0
        
        for agent_id, signal in agent_signals.items():
            weight = self.WEIGHTS.get(agent_id, 0.1)
            severity_score = self.SEVERITY_SCORES.get(signal.severity, 0)
            weighted_score += weight * severity_score * signal.confidence
        
        # Auto-escalations
        if any(s.severity == "CRITICAL" for s in agent_signals.values()):
            weighted_score = max(weighted_score, 90)
        
        risk_score = min(100, int(weighted_score))
        
        if risk_score >= 70:
            verdict = "BLOCK"
        elif risk_score >= 40:
            verdict = "WARN"
        else:
            verdict = "PASS"
        
        return risk_score, verdict
```
