# ⛓️🛡️ ChainGuard Protocol

> **One-Click Blockchain Malware Defense Platform**
> The world's first decentralized, AI-powered security layer for Web3 — stopping blockchain-hosted malware, ransomware droppers, and wallet drainers before they execute.

---

## 🚨 The Problem

Blockchain-based malware uses the chain's own immutability against users:
- **Ransomware droppers** (Locky, CryptoLocker variants) read payloads from `OP_RETURN` fields and smart contract storage
- **Wallet credential stealers** target MetaMask and Phantom private keys / seed phrases
- **Decentralized C2 servers** — no host to take down, payload lives on thousands of nodes forever
- **IPFS-hosted shellcode** referenced by on-chain CIDs, immune to traditional takedowns

## ✅ The Solution: ChainGuard Protocol

A **5-component, 8-agent, fully decentralized security stack** that intercepts the malware pipeline at every layer:

```
USER CLICKS "PROTECT ME" → ChainGuard activates all 8 agents simultaneously
                         → Real-time RPC monitoring begins
                         → Wallet isolation mode enabled
                         → Threat intelligence oracle connected
                         → Pre-execution simulation active
                         → DONE. Protected in < 3 seconds.
```

---

## 🏗️ System Components

| Component | Role |
|---|---|
| **ChainGuard Extension** | Browser-level RPC interceptor + tx simulator |
| **Guardian Smart Contracts** | On-chain decentralized threat blacklist oracle |
| **AI Agent Network** | 8 specialized agents (see AGENTS.md) |
| **Sentinel Backend** | Threat intelligence aggregation + scoring API |
| **Shield Dashboard** | One-click control panel (React + Viem) |

---

## 🤖 Agent Network (8 Agents)

1. **OrchestratorAgent** — Master coordinator, routes threats to specialists
2. **PayloadScannerAgent** — Analyzes blockchain tx data for shellcode/malware
3. **WalletSentinelAgent** — Guards MetaMask/Phantom from unauthorized access
4. **ThreatIntelAgent** — Aggregates live threat feeds (Chainabuse, MistTrack, etc.)
5. **ContractAuditorAgent** — Pre-execution smart contract risk simulation
6. **IncidentResponderAgent** — Automated quarantine + user notification
7. **ReputationOracleAgent** — Manages decentralized on-chain blacklist
8. **NetworkGuardAgent** — Deep packet inspection on blockchain RPC calls

> Full specs: [AGENTS.md](./docs/AGENTS.md)

---

## ⚡ Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/chainguard-protocol/chainguard
cd chainguard

# 2. Install all dependencies
npm install && pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env
# Fill in your RPC endpoints and API keys

# 4. Deploy smart contracts (local testnet)
npx hardhat run scripts/deploy.js --network localhost

# 5. Start the backend sentinel
python backend/sentinel.py

# 6. Start the frontend dashboard
cd frontend && npm run dev

# 7. Load browser extension
# Chrome: chrome://extensions → Load Unpacked → /extension folder
```

---

## 📁 Project Structure

```
chainguard/
├── README.md                    ← You are here
├── docs/
│   ├── ARCHITECTURE.md          ← Full system design
│   ├── AGENTS.md                ← All 8 agent specs
│   ├── PIPELINE.md              ← Complete execution pipeline
│   ├── PROMPTS.md               ← All AI agent prompts
│   ├── SMART_CONTRACTS.md       ← Contract specifications
│   ├── FRONTEND.md              ← UI/UX specifications
│   ├── BACKEND.md               ← API and backend specs
│   ├── SECURITY.md              ← Security model & threat matrix
│   └── ROADMAP.md               ← Development roadmap
├── agents/
│   ├── orchestrator.py          ← OrchestratorAgent
│   ├── payload_scanner.py       ← PayloadScannerAgent
│   ├── wallet_sentinel.py       ← WalletSentinelAgent
│   ├── threat_intel.py          ← ThreatIntelAgent
│   ├── contract_auditor.py      ← ContractAuditorAgent
│   ├── incident_responder.py    ← IncidentResponderAgent
│   ├── reputation_oracle.py     ← ReputationOracleAgent
│   └── network_guard.py         ← NetworkGuardAgent
├── contracts/
│   ├── ThreatRegistry.sol       ← Main blacklist oracle
│   ├── ReputationOracle.sol     ← On-chain reputation scoring
│   ├── IncidentVault.sol        ← Incident evidence storage
│   └── GovernanceDAO.sol        ← Protocol governance
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── components/
│   │   └── hooks/
│   └── package.json
├── backend/
│   ├── sentinel.py              ← Main API server
│   ├── rpc_proxy.py             ← Blockchain RPC interceptor
│   ├── intel_aggregator.py      ← Threat feed aggregator
│   └── scoring_engine.py        ← Risk scoring engine
├── extension/
│   ├── manifest.json
│   ├── background.js            ← Service worker interceptor
│   ├── content.js               ← Page-level protection
│   └── popup/                   ← Extension UI
├── scripts/
│   ├── deploy.js                ← Contract deployment
│   ├── setup_agents.py          ← Agent initialization
│   └── seed_threatdb.py         ← Seed initial threat data
└── config/
    ├── agents.yaml              ← Agent configuration
    ├── chains.yaml              ← Supported chain configs
    └── threats.yaml             ← Threat signature database
```

---

## 🔐 Security Guarantee

ChainGuard operates on a **Zero-Trust Blockchain Execution Model**:

> *"No blockchain data shall be executed until it passes all 6 verification layers and achieves a risk score below the configured threshold."*

- **Layer 1** — RPC Gateway interception
- **Layer 2** — On-chain payload static analysis
- **Layer 3** — Smart contract pre-execution sandbox
- **Layer 4** — Wallet isolation & hardware enclave binding
- **Layer 5** — Decentralized threat intelligence consensus
- **Layer 6** — EDR-grade endpoint process monitoring

---

## 📜 License

MIT License — Open source, community-driven security for all Web3 users.

---

## 🤝 Contributing

See [CONTRIBUTING.md](./docs/CONTRIBUTING.md) — All security researchers, blockchain developers, and AI/ML engineers welcome.

---

*Built to make blockchain malware's greatest strength — immutability — its biggest weakness.*
