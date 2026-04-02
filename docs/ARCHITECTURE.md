# 🏗️ ChainGuard Protocol — System Architecture

## 1. Architectural Philosophy

ChainGuard is built on three core principles:

1. **Intercept the pipeline, not the chain** — Blockchain data cannot be removed, but the path from chain to execution can be broken at every step.
2. **Decentralize the defense** — Mirror the attacker's use of decentralization by deploying threat intelligence on-chain, making it equally uncensorable.
3. **Zero-Trust Execution** — Every piece of blockchain data is treated as potentially malicious until proven safe by multi-layer verification.

---

## 2. High-Level System Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                        CHAINGUARD PROTOCOL — FULL STACK                      │
└──────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────┐     ┌─────────────────────────────────────────────────────┐
  │   USER      │────▶│              SHIELD DASHBOARD (React)               │
  │  BROWSER    │     │   One-click activation, real-time threat monitor     │
  └─────────────┘     └───────────────────────┬─────────────────────────────┘
         │                                    │
         │ Web3 calls                         │ REST / WebSocket
         ▼                                    ▼
  ┌─────────────────────┐    ┌───────────────────────────────────────────┐
  │  CHAINGUARD         │    │          SENTINEL BACKEND (Python)        │
  │  BROWSER EXTENSION  │    │                                           │
  │  ─────────────────  │    │  ┌──────────┐  ┌──────────┐  ┌────────┐  │
  │  • RPC Interceptor  │───▶│  │  Threat  │  │  Risk    │  │ Agent  │  │
  │  • TX Simulator     │    │  │  Intel   │  │  Scorer  │  │  Bus   │  │
  │  • Wallet Guard     │    │  │  Aggreg. │  │  Engine  │  │        │  │
  │  • Signature Scan   │    │  └────┬─────┘  └────┬─────┘  └───┬────┘  │
  └─────────────────────┘    └───────┼─────────────┼────────────┼───────┘
         │                           │             │            │
         │                           ▼             ▼            ▼
         │                  ┌─────────────────────────────────────────┐
         │                  │         AI AGENT NETWORK (8 Agents)     │
         │                  │                                         │
         │                  │  [Orchestrator] → routes to specialists │
         │                  │  [PayloadScanner]  [WalletSentinel]     │
         │                  │  [ThreatIntel]     [ContractAuditor]    │
         │                  │  [IncidentResponder] [ReputationOracle] │
         │                  │  [NetworkGuard]                         │
         │                  └─────────────────────┬───────────────────┘
         │                                        │
         ▼                                        ▼
  ┌──────────────────────────────────────────────────────────────┐
  │                   BLOCKCHAIN LAYER                            │
  │                                                               │
  │  ┌─────────────────┐  ┌──────────────────┐  ┌─────────────┐ │
  │  │ ThreatRegistry  │  │ ReputationOracle │  │IncidentVault│ │
  │  │ .sol (blacklist)│  │ .sol (scoring)   │  │ .sol (proof)│ │
  │  └─────────────────┘  └──────────────────┘  └─────────────┘ │
  │                                                               │
  │  Ethereum / Polygon / Arbitrum / Solana (multi-chain)        │
  └──────────────────────────────────────────────────────────────┘
         │
         ▼
  ┌──────────────────────┐
  │  EXTERNAL THREAT     │
  │  INTELLIGENCE FEEDS  │
  │  • Chainabuse API    │
  │  • MistTrack         │
  │  • Etherscan Labels  │
  │  • AML Bot           │
  │  • OFAC SDN List     │
  │  • VirusTotal        │
  └──────────────────────┘
```

---

## 3. Component Deep-Dive

### 3.1 ChainGuard Browser Extension

The **first line of defense** — intercepts every Web3 interaction before it reaches the blockchain or executes locally.

```
EXTENSION ARCHITECTURE:

manifest.json
    │
    ├── background.js (Service Worker)
    │       • Intercepts all fetch/XHR calls to known RPC endpoints
    │       • Maintains in-memory threat cache (TTL: 5 min)
    │       • Communicates with Sentinel Backend
    │       • Routes suspicious calls to PayloadScannerAgent
    │
    ├── content.js (Injected into every page)
    │       • Hooks window.ethereum (MetaMask provider)
    │       • Hooks window.solana (Phantom provider)
    │       • Intercepts eth_sendTransaction, eth_signTypedData
    │       • Pre-execution simulation trigger
    │
    └── popup/ (User Interface)
            • One-click toggle: PROTECT / UNPROTECT
            • Real-time threat status
            • Recent blocked transactions log
            • Risk score of current dApp
```

**RPC Endpoint Intercept List:**
```yaml
rpc_intercept_targets:
  ethereum:
    - "*.infura.io"
    - "*.alchemy.com"
    - "*.quicknode.io"
    - "mainnet.infura.io"
  polygon:
    - "polygon-rpc.com"
    - "*.polygon.io"
  solana:
    - "api.mainnet-beta.solana.com"
    - "*.helius-rpc.com"
  generic:
    - "*:8545"  # Local Geth
    - "*:8546"  # Local Geth WebSocket
    - "*:9650"  # Avalanche
```

---

### 3.2 Sentinel Backend (Python/FastAPI)

Central coordination hub — aggregates threat intelligence, scores risk, dispatches agents.

```
SENTINEL BACKEND MODULES:

sentinel.py (main FastAPI app)
    │
    ├── /api/v1/scan/transaction      ← Scan tx data for malware
    ├── /api/v1/scan/contract         ← Scan contract address
    ├── /api/v1/scan/payload          ← Scan raw bytes for shellcode
    ├── /api/v1/threat/report         ← Submit new threat
    ├── /api/v1/threat/lookup/{addr}  ← Look up address reputation
    └── /ws/monitor                  ← WebSocket live threat stream

rpc_proxy.py
    • Transparent proxy for blockchain RPC calls
    • Inspects all eth_call, eth_getTransactionByHash
    • Extracts OP_RETURN data, contract bytecode, storage reads
    • Passes to PayloadScannerAgent before forwarding

intel_aggregator.py
    • Polls 6 external threat intelligence sources every 60 seconds
    • Normalizes data into unified ThreatIndicator schema
    • Writes to local Redis cache + ThreatRegistry smart contract

scoring_engine.py
    • Multi-factor risk scoring (0-100)
    • Inputs: entropy, known signatures, reputation, behavior patterns
    • Threshold: score > 70 = BLOCK, 40-70 = WARN, <40 = PASS
```

---

### 3.3 AI Agent Network

Eight specialized agents connected via an **async message bus** (Redis Streams).

```
AGENT COMMUNICATION TOPOLOGY:

                    ┌─────────────────────┐
                    │  OrchestratorAgent  │
                    │  (Master Router)    │
                    └──────────┬──────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │            ┌───────┴──────┐             │
          ▼            ▼              ▼             ▼
  [PayloadScanner] [ThreatIntel] [ContractAuditor] [NetworkGuard]
          │            │              │             │
          └────────────┴──────────────┴─────────────┘
                               │
                    ┌──────────┴──────────┐
                    │  IncidentResponder  │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
      [WalletSentinel] [ReputationOracle]  [Alert to User]
```

**Message Schema (Redis Stream):**
```json
{
  "event_id": "evt_7f3a9b2c",
  "timestamp": 1720000000,
  "source_agent": "NetworkGuardAgent",
  "target_agent": "OrchestratorAgent",
  "priority": "CRITICAL",
  "payload": {
    "type": "SUSPICIOUS_RPC_CALL",
    "process_name": "explorer.exe",
    "rpc_endpoint": "https://mainnet.infura.io/v3/xxx",
    "method": "eth_getTransactionByHash",
    "tx_hash": "0xabc123...",
    "raw_data": "4d5a9000...",
    "entropy_score": 7.8
  }
}
```

---

### 3.4 Smart Contract Layer

Three contracts deployed on Ethereum mainnet + Polygon for redundancy.

#### ThreatRegistry.sol
```
Purpose: Immutable, decentralized blacklist of malicious addresses & tx hashes
Access: Public read, multi-sig write (requires 3/5 trusted security orgs)
Events: ThreatAdded, ThreatEscalated, ThreatDisputed

Storage:
  mapping(address => ThreatRecord) public threats;
  mapping(bytes32 => ThreatRecord) public maliciousTxHashes;
  
ThreatRecord {
  uint8 severity;       // 1=LOW, 2=MED, 3=HIGH, 4=CRITICAL
  uint64 timestamp;
  bytes32 evidenceHash; // IPFS CID of evidence
  address reporter;
  uint16 confirmations; // How many orgs confirmed
}
```

#### ReputationOracle.sol
```
Purpose: On-chain reputation scoring for addresses (0-100 score)
Mechanism: Chainlink oracle integration for off-chain data feeds
Updates: Every 1 hour via keeper network

Score Factors:
  - Age of address
  - Transaction history patterns
  - Association with flagged addresses
  - Smart contract code quality score
  - Community reports from Chainabuse
```

#### IncidentVault.sol
```
Purpose: Cryptographic evidence storage for confirmed attacks
Content: IPFS hashes of: memory dumps, network captures, payload samples
Use Case: Legal/law enforcement evidence chain
Access: Public read, incident responder write
```

---

### 3.5 Shield Dashboard (React Frontend)

```
DASHBOARD PAGES:

/ (Home)
  └── One-Click Protect Button
  └── Real-time threat meter (live WebSocket)
  └── Recent blocks scanned counter
  └── Active protection status

/monitor
  └── Live transaction stream with risk scores
  └── Blocked transaction history
  └── Agent status panel (all 8 agents health)

/threats
  └── Threat intelligence feed
  └── Submit new threat form
  └── ThreatRegistry browser (on-chain data)

/wallet
  └── Connected wallets (MetaMask, Phantom)
  └── Wallet isolation controls
  └── Approval history + revocation tool
  └── Hardware wallet binding status

/settings
  └── Risk threshold configuration
  └── Whitelist management
  └── Notification preferences
  └── Chain selection (ETH/Polygon/Arbitrum/Solana)
```

---

## 4. Data Flow — Complete Attack Interception

```
SCENARIO: Ransomware dropper attempts to read payload from OP_RETURN

Step 1: Malware process calls eth_getTransactionByHash via HTTP
                │
Step 2: NetworkGuardAgent detects non-browser process making RPC call
        → ALERT sent to OrchestratorAgent (Priority: HIGH)
                │
Step 3: OrchestratorAgent spawns parallel analysis:
        → PayloadScannerAgent: analyze the tx data bytes
        → ThreatIntelAgent: check tx hash against blacklists
        → ReputationOracleAgent: check sender/target address scores
                │
Step 4: PayloadScannerAgent finds: entropy=7.9, MZ header detected
        ThreatIntelAgent finds: tx_hash in Chainabuse DB
        ReputationOracle: address score = 3/100 (critically low)
                │
Step 5: OrchestratorAgent: CONSENSUS = MALICIOUS
        → RPC proxy blocks the call (returns empty response)
        → IncidentResponderAgent triggered
                │
Step 6: IncidentResponderAgent:
        → Isolates the malicious process
        → Captures memory dump
        → Uploads evidence to IPFS
        → Writes incident to IncidentVault.sol
        → Notifies user with full explanation
        → Reports to ThreatRegistry.sol
                │
Step 7: User sees notification:
        "🛡️ BLOCKED: Ransomware dropper detected and quarantined.
         Process: svchost_fake.exe
         Attempted to read malicious payload from Ethereum transaction.
         Evidence preserved. Your system is safe."
```

---

## 5. Technology Stack

| Layer | Technology | Rationale |
|---|---|---|
| Frontend | React 18 + Viem + TailwindCSS | Modern Web3 UI with type-safe contract calls |
| Backend | Python 3.11 + FastAPI + Redis | Async, high-throughput threat processing |
| AI Agents | LangChain + Claude API + Custom Tools | Sophisticated reasoning + tool use |
| Contracts | Solidity 0.8.24 + Hardhat | Industry standard, auditable |
| Database | PostgreSQL + Redis | Persistent storage + fast cache |
| Extension | Manifest V3 + Service Workers | Modern, secure browser extension |
| Chain Data | Viem (ETH) + @solana/web3.js | Official SDK integrations |
| Monitoring | Prometheus + Grafana | Real-time system observability |
| Deployment | Docker Compose + AWS ECS | Scalable, containerized |

---

## 6. Security Model

See full specification in [SECURITY.md](./SECURITY.md)

**Key guarantees:**
- ChainGuard itself runs in a **sandboxed, read-only mode** — cannot modify blockchain state
- All agent communications are **encrypted and authenticated** (mTLS)
- Smart contracts are **audited by OpenZeppelin** before mainnet deployment
- User data: **zero PII collected**, all processing local-first
- API keys: **never stored in extension**, proxied through Sentinel backend

---

## 7. Multi-Chain Support Matrix

| Chain | RPC Intercept | Contract Deployed | Solana Programs |
|---|---|---|---|
| Ethereum Mainnet | ✅ | ✅ | — |
| Polygon | ✅ | ✅ | — |
| Arbitrum | ✅ | ✅ | — |
| Base | ✅ | ✅ | — |
| Solana | ✅ | — | ✅ |
| BSC | ✅ | Planned | — |
| Avalanche | Planned | Planned | — |
