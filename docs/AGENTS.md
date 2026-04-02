# 🤖 ChainGuard Agent Network — Complete Specifications

## Overview

ChainGuard deploys **8 specialized AI agents** that work in concert via an async message bus. Each agent has a single responsibility, its own LLM context, dedicated tools, and defined escalation paths. Together they form a multi-layered defense that no single threat can bypass.

```
AGENT HIERARCHY:

                        ┌──────────────────────┐
                        │  OrchestratorAgent   │ ← COMMANDER
                        │  Priority: CRITICAL  │
                        └──────────┬───────────┘
                                   │
          ┌────────────────────────┼────────────────────────┐
          │                        │                        │
          ▼                        ▼                        ▼
┌──────────────────┐   ┌──────────────────┐   ┌──────────────────────┐
│ PayloadScanner   │   │  ThreatIntel     │   │   NetworkGuard       │
│ Agent            │   │  Agent           │   │   Agent              │
│ (Static Analysis)│   │ (Intel Feeds)    │   │ (Process Monitor)    │
└──────────────────┘   └──────────────────┘   └──────────────────────┘
          │                        │                        │
          └────────────────────────┼────────────────────────┘
                                   │
                        ┌──────────┴───────────┐
                        │  ContractAuditor     │
                        │  Agent               │
                        │  (Pre-exec Sandbox)  │
                        └──────────┬───────────┘
                                   │
                        ┌──────────┴───────────┐
                        │  IncidentResponder   │ ← ACTION TAKER
                        │  Agent               │
                        └──────────┬───────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              ▼                    ▼                    ▼
  ┌───────────────────┐ ┌──────────────────┐ ┌──────────────────┐
  │  WalletSentinel   │ │ ReputationOracle │ │  [User Alert]    │
  │  Agent            │ │ Agent            │ │  Notification    │
  │  (Wallet Guard)   │ │ (On-chain Intel) │ │  System          │
  └───────────────────┘ └──────────────────┘ └──────────────────┘
```

---

## Agent 1: OrchestratorAgent

### Identity
```yaml
name: OrchestratorAgent
id: agent_orchestrator_001
role: Master Coordinator and Threat Router
priority_level: CRITICAL
model: claude-sonnet-4-20250514
temperature: 0.1  # Low — consistent, deterministic routing
```

### Responsibilities
- Receives ALL incoming threat signals from other agents and the extension
- Performs consensus analysis across multi-agent findings
- Makes final BLOCK / WARN / PASS decisions
- Escalates critical threats to IncidentResponderAgent
- Maintains global threat context for the current session

### Input Events
```python
LISTENS_TO = [
    "rpc.call.intercepted",
    "process.suspicious_activity",
    "wallet.access.unauthorized",
    "contract.interaction.pending",
    "payload.analysis.result",
    "threat.intel.hit",
    "reputation.score.low",
    "network.anomaly.detected"
]
```

### Output Actions
```python
EMITS = [
    "decision.block",        # Block the action entirely
    "decision.warn",         # Allow with user warning
    "decision.pass",         # Clean, proceed normally
    "dispatch.incident",     # Trigger IncidentResponder
    "dispatch.scan",         # Request deeper analysis
    "update.context"         # Update global threat context
]
```

### Decision Logic
```python
def make_decision(self, signals: list[Signal]) -> Decision:
    """
    Consensus-based decision from multi-agent signals.
    Any CRITICAL signal = automatic BLOCK.
    2+ HIGH signals = BLOCK.
    1 HIGH signal = WARN.
    All LOW/MEDIUM = PASS with logging.
    """
    critical_count = sum(1 for s in signals if s.severity == "CRITICAL")
    high_count = sum(1 for s in signals if s.severity == "HIGH")
    
    if critical_count >= 1 or high_count >= 2:
        return Decision.BLOCK
    elif high_count == 1:
        return Decision.WARN
    else:
        return Decision.PASS
```

### Tools Available
- `query_all_agents()` — Request analysis from any specialist agent
- `get_threat_context()` — Retrieve current session threat state
- `execute_decision()` — Push BLOCK/WARN/PASS to extension
- `escalate_incident()` — Trigger full incident response

---

## Agent 2: PayloadScannerAgent

### Identity
```yaml
name: PayloadScannerAgent
id: agent_payload_002
role: Static Malware Analysis Specialist
priority_level: HIGH
model: claude-sonnet-4-20250514
temperature: 0.0  # Fully deterministic for security decisions
```

### Responsibilities
- Extracts raw byte data from blockchain transactions
- Performs multi-stage static analysis for malware patterns
- Detects: PE/ELF executables, shellcode, encoded payloads, steganographic data
- Calculates Shannon entropy to identify encrypted/packed payloads
- Maintains a signature database for known malware families

### Malware Detection Capabilities

| Malware Family | Detection Method | Confidence |
|---|---|---|
| Locky Ransomware | Signature matching (4 unique byte patterns) | 99% |
| CryptoLocker | File extension target list + encryption routine signatures | 97% |
| MetaMask Drainer | JS injection pattern detection | 95% |
| Phantom Stealer | Solana key derivation path scanning | 93% |
| Generic Shellcode | Entropy > 7.4 + no valid headers | 88% |
| Encoded Payloads | Multi-layer decode (base64, hex, XOR detection) | 91% |

### Analysis Pipeline
```python
class PayloadScannerAgent:
    
    def analyze(self, raw_data: bytes) -> ScanResult:
        results = []
        
        # Stage 1: Header Analysis
        results.append(self._check_executable_headers(raw_data))
        
        # Stage 2: Entropy Analysis
        entropy = self._shannon_entropy(raw_data)
        if entropy > 7.2:
            results.append(Finding("HIGH_ENTROPY", severity="HIGH", 
                                   detail=f"entropy={entropy:.2f}"))
        
        # Stage 3: Signature Matching
        for sig in self.signature_db:
            if sig.pattern in raw_data:
                results.append(Finding("KNOWN_MALWARE", severity="CRITICAL",
                                       detail=sig.family))
        
        # Stage 4: Decode and Re-scan
        for decoder in [base64, hex, xor_common_keys]:
            try:
                decoded = decoder(raw_data)
                sub_result = self.analyze(decoded)  # Recursive
                if sub_result.is_malicious:
                    results.append(Finding("ENCODED_PAYLOAD", 
                                           severity="CRITICAL",
                                           detail=f"via {decoder.__name__}"))
            except:
                pass
        
        # Stage 5: AI Deep Analysis (LLM)
        llm_finding = self._ai_deep_analysis(raw_data, results)
        results.append(llm_finding)
        
        return ScanResult(findings=results, 
                         verdict=self._consensus_verdict(results))
```

### Tools Available
- `extract_tx_data(tx_hash)` — Pull raw bytes from any transaction
- `shannon_entropy(data)` — Calculate byte entropy
- `match_signatures(data)` — Run against signature DB
- `decode_payload(data, method)` — Multi-method decoder
- `disassemble_code(bytes)` — x86/x64 disassembler
- `query_virustotal(hash)` — External scan for known malware

---

## Agent 3: WalletSentinelAgent

### Identity
```yaml
name: WalletSentinelAgent
id: agent_wallet_003
role: Crypto Wallet Protection Specialist
priority_level: CRITICAL
model: claude-sonnet-4-20250514
temperature: 0.1
```

### Responsibilities
- Monitors all access to MetaMask and Phantom wallet storage
- Intercepts signing requests and evaluates for drainer patterns
- Detects clipboard hijacking attacks (address substitution)
- Guards seed phrase access — zero-tolerance policy
- Manages wallet isolation mode during active threats

### Protection Scope

```
METAMASK PROTECTION:
├── File System
│   ├── %APPDATA%\MetaMask\             ← Access monitoring
│   ├── %LOCALAPPDATA%\...\Local Storage\ ← LevelDB access guard
│   └── Any process reading vault.json  ← CRITICAL ALERT
├── Browser Extension
│   ├── window.ethereum hook protection
│   ├── eth_requestAccounts audit
│   ├── eth_signTypedData v4 deep scan
│   └── personal_sign content analysis
└── Memory
    ├── Process memory scan for seed phrase patterns
    └── Clipboard monitoring for private key patterns (64-hex chars)

PHANTOM PROTECTION:
├── File System
│   ├── ~/.config/Phantom/             ← Linux
│   └── %APPDATA%\Phantom\             ← Windows
├── Solana Web3
│   ├── window.solana hook protection
│   ├── signTransaction audit
│   └── connect() approval logging
└── Key Detection
    └── Base58 private key pattern scanning (87-88 char strings)
```

### Drainer Detection Rules
```python
DRAINER_PATTERNS = {
    "unlimited_approval": {
        "method": "approve",
        "amount": 2**256 - 1,  # Max uint256
        "action": "WARN — Unlimited token approval requested"
    },
    "setApprovalForAll": {
        "method": "setApprovalForAll",
        "operator": "unknown_address",
        "action": "BLOCK — NFT collection drain attempt"
    },
    "permit_signature": {
        "method": "permit",
        "deadline": "suspicious_deadline",
        "action": "WARN — Gasless approval signature"
    },
    "malicious_delegate": {
        "method": "delegatecall",
        "target": "unverified_contract",
        "action": "BLOCK — Delegatecall to unverified contract"
    }
}
```

### Tools Available
- `monitor_wallet_files()` — File system watcher for wallet directories
- `intercept_signing_request(request)` — Analyze before signing
- `simulate_approval(token, spender, amount)` — Simulate token approval outcome
- `get_approval_history(wallet)` — List all active approvals
- `revoke_approval(token, spender)` — Emergency approval revocation
- `enable_isolation_mode()` — Block all wallet interactions

---

## Agent 4: ThreatIntelAgent

### Identity
```yaml
name: ThreatIntelAgent
id: agent_intel_004
role: Threat Intelligence Aggregation Specialist
priority_level: HIGH
model: claude-sonnet-4-20250514
temperature: 0.2
```

### Responsibilities
- Polls 6 external threat intelligence sources every 60 seconds
- Normalizes heterogeneous threat data into unified schema
- Maintains local cache with TTL management
- Correlates new threats against current session activity
- Generates threat briefings for OrchestratorAgent

### Intelligence Sources
```yaml
threat_feeds:
  - name: Chainabuse
    url: "https://www.chainabuse.com/api/v0/reports"
    type: community_reports
    refresh_interval: 300
    priority: HIGH

  - name: MistTrack
    url: "https://openapi.misttrack.io/v1/risk_score"
    type: on_chain_analytics
    refresh_interval: 300
    priority: HIGH

  - name: Etherscan Labels
    url: "https://api.etherscan.io/api?module=account&action=txlist"
    type: labeled_addresses
    refresh_interval: 600
    priority: MEDIUM

  - name: OFAC SDN List
    url: "https://www.treasury.gov/ofac/downloads/sdn.xml"
    type: sanctions_list
    refresh_interval: 3600
    priority: CRITICAL

  - name: VirusTotal
    url: "https://www.virustotal.com/api/v3/files/{hash}"
    type: file_reputation
    refresh_interval: 0  # Query on demand
    priority: HIGH

  - name: ChainGuard Oracle
    contract: "ThreatRegistry.sol"
    type: on_chain_blacklist
    refresh_interval: 60
    priority: CRITICAL
```

### Unified Threat Schema
```python
@dataclass
class ThreatIndicator:
    indicator_type: str          # "address", "tx_hash", "contract", "domain"
    value: str                   # The actual indicator
    threat_type: str             # "ransomware", "drainer", "c2", "phishing"
    severity: int                # 1-10
    confidence: float            # 0.0-1.0
    sources: list[str]           # Which feeds confirmed this
    first_seen: datetime
    last_seen: datetime
    evidence_hash: str           # IPFS hash of supporting evidence
    tags: list[str]              # ["locky", "c2", "bitcoin", etc.]
```

### Tools Available
- `poll_chainabuse()` — Fetch latest Chainabuse reports
- `query_misttrack(address)` — Get MistTrack risk score
- `check_ofac(address)` — OFAC sanctions check
- `query_virustotal(hash)` — VT file reputation
- `lookup_on_chain_blacklist(address)` — Query ThreatRegistry.sol
- `correlate_indicators(indicator_list)` — Find connections between threats
- `generate_threat_briefing(session)` — LLM-generated threat summary

---

## Agent 5: ContractAuditorAgent

### Identity
```yaml
name: ContractAuditorAgent
id: agent_auditor_005
role: Smart Contract Pre-Execution Security Auditor
priority_level: HIGH
model: claude-sonnet-4-20250514
temperature: 0.1
```

### Responsibilities
- Forks mainnet state and simulates every pending transaction before signing
- Analyzes contract bytecode for malicious patterns
- Detects reentrancy, honeypots, proxy manipulation, and price manipulation
- Calculates net asset change for user (what will this tx actually do to my wallet?)
- Assigns risk scores to contract interactions

### Simulation Architecture
```
TRANSACTION PRE-EXECUTION FLOW:

User wants to: approve(0x_drainer, MAX_UINT256)
                        │
                        ▼
          ┌─────────────────────────┐
          │  Fork mainnet at block N │
          │  (Anvil/Hardhat Network) │
          └────────────┬────────────┘
                       │
          ┌────────────▼────────────┐
          │  Execute tx in sandbox   │
          │  Trace ALL opcodes       │
          └────────────┬────────────┘
                       │
          ┌────────────▼────────────┐
          │  Analyze state changes:  │
          │  - Token balances before │
          │  - Token balances after  │
          │  - ETH balance delta     │
          │  - New approvals granted │
          │  - DELEGATECALL targets  │
          │  - SELFDESTRUCT called?  │
          └────────────┬────────────┘
                       │
          ┌────────────▼────────────┐
          │  Generate user report:   │
          │                          │
          │  ⚠️ This transaction will │
          │  grant 0xABCD unlimited  │
          │  access to your USDC.    │
          │  Risk Score: 92/100      │
          │  RECOMMENDATION: REJECT  │
          └──────────────────────────┘
```

### Audit Checks
```python
AUDIT_CHECKS = [
    "reentrancy_vulnerability",
    "unchecked_external_calls",
    "integer_overflow_underflow",
    "access_control_missing",
    "selfdestruct_present",
    "delegatecall_to_unknown",
    "price_oracle_manipulation",
    "honeypot_pattern",           # Can buy but not sell
    "hidden_mint_function",
    "ownership_renounced",        # Could be rug
    "proxy_upgrade_risk",
    "unlimited_approval_drain",
    "flash_loan_attack_vector",
    "sandwich_attack_vulnerable"
]
```

### Tools Available
- `fork_mainnet(block_number)` — Create sandboxed fork
- `simulate_transaction(tx)` — Execute in sandbox
- `trace_opcodes(tx)` — Full EVM opcode trace
- `calculate_balance_delta(before, after)` — Net asset change
- `decompile_bytecode(bytecode)` — Bytecode analysis
- `check_verified_source(address)` — Is contract verified on Etherscan?
- `run_slither_analysis(source_code)` — Static analysis via Slither

---

## Agent 6: IncidentResponderAgent

### Identity
```yaml
name: IncidentResponderAgent
id: agent_responder_006
role: Automated Incident Response Coordinator
priority_level: CRITICAL
model: claude-sonnet-4-20250514
temperature: 0.0  # Zero creativity — pure action execution
```

### Responsibilities
- Executes automated response playbooks when threats are confirmed
- Collects and preserves forensic evidence
- Isolates affected processes and wallet connections
- Submits threat reports to on-chain ThreatRegistry
- Generates human-readable incident reports for users

### Response Playbooks
```python
PLAYBOOKS = {
    
    "RANSOMWARE_DROPPER": [
        Action("KILL_PROCESS", target="malicious_process"),
        Action("BLOCK_RPC_ENDPOINT", target="rpc_endpoint"),
        Action("QUARANTINE_FILE", target="dropper_file"),
        Action("DUMP_MEMORY", target="process_memory"),
        Action("ENABLE_WALLET_ISOLATION"),
        Action("UPLOAD_EVIDENCE_IPFS"),
        Action("SUBMIT_TO_THREAT_REGISTRY"),
        Action("NOTIFY_USER", severity="CRITICAL"),
        Action("GENERATE_INCIDENT_REPORT")
    ],
    
    "WALLET_DRAINER": [
        Action("BLOCK_SIGNING_REQUEST"),
        Action("REVOKE_SUSPICIOUS_APPROVALS"),
        Action("ENABLE_HARDWARE_WALLET_MODE"),
        Action("BLACKLIST_CONTRACT_ADDRESS"),
        Action("UPLOAD_EVIDENCE_IPFS"),
        Action("SUBMIT_TO_THREAT_REGISTRY"),
        Action("NOTIFY_USER", severity="CRITICAL"),
        Action("SUGGEST_WALLET_MIGRATION")  # If keys may be compromised
    ],
    
    "CREDENTIAL_STEALER": [
        Action("TERMINATE_ALL_WALLET_CONNECTIONS"),
        Action("LOCK_WALLET_FILES"),
        Action("KILL_PROCESS"),
        Action("SCAN_CLIPBOARD"),
        Action("NOTIFY_USER", severity="CRITICAL", 
               message="ROTATE YOUR SEED PHRASE IMMEDIATELY"),
        Action("UPLOAD_EVIDENCE_IPFS"),
        Action("SUBMIT_TO_THREAT_REGISTRY")
    ],
    
    "SUSPICIOUS_CONTRACT": [
        Action("BLOCK_TRANSACTION"),
        Action("SUBMIT_CONTRACT_FOR_AUDIT"),
        Action("NOTIFY_USER", severity="HIGH"),
        Action("FLAG_IN_REPUTATION_ORACLE")
    ]
}
```

### Tools Available
- `kill_process(pid)` — Terminate malicious process
- `quarantine_file(path)` — Move to quarantine directory
- `dump_memory(pid)` — Capture process memory
- `upload_to_ipfs(data)` — Store evidence on IPFS
- `submit_threat_registry(indicator)` — Write to ThreatRegistry.sol
- `revoke_token_approval(token, spender)` — Emergency revoke
- `notify_user(message, severity)` — Push notification to dashboard
- `generate_incident_report(incident)` — LLM-generated report

---

## Agent 7: ReputationOracleAgent

### Identity
```yaml
name: ReputationOracleAgent
id: agent_reputation_007
role: On-Chain Reputation Scoring Manager
priority_level: MEDIUM
model: claude-sonnet-4-20250514
temperature: 0.3
```

### Responsibilities
- Maintains and updates on-chain reputation scores for all queried addresses
- Builds transaction graph analysis (is this address connected to known bad actors?)
- Manages community dispute resolution for falsely flagged addresses
- Provides reputation context to OrchestratorAgent for decision-making
- Syncs local reputation cache with ThreatRegistry.sol

### Reputation Score Calculation
```python
def calculate_reputation_score(address: str) -> ReputationScore:
    """
    Score: 0 (perfectly malicious) to 100 (perfectly trusted)
    Default for new/unknown addresses: 50 (neutral)
    """
    
    factors = {
        "age_score": get_address_age_score(address),         # 0-20 pts
        "volume_score": get_tx_volume_score(address),        # 0-15 pts
        "association_score": get_association_score(address),  # 0-25 pts
        "code_quality_score": get_code_score(address),       # 0-20 pts (contracts only)
        "community_score": get_community_reports(address),   # 0-20 pts
    }
    
    # Penalties (can subtract points)
    penalties = {
        "ofac_listed": -100,       # Immediate to 0
        "confirmed_drainer": -100, # Immediate to 0
        "chainabuse_reports": -5 * report_count,
        "associated_with_flagged": -10 * flagged_associations,
        "reentrancy_vulnerable": -15,
        "unverified_contract": -5
    }
    
    raw_score = sum(factors.values()) + sum(penalties.values())
    return max(0, min(100, raw_score))
```

### Graph Analysis
```python
# Detect if address is connected to known malicious addresses
# within N hops in the transaction graph
def transaction_graph_analysis(address: str, max_hops: int = 3) -> GraphResult:
    graph = build_transaction_graph(address, depth=max_hops)
    malicious_connections = []
    
    for node in graph.nodes:
        rep = self.get_reputation(node.address)
        if rep.score < 20:  # Highly suspicious
            path = graph.shortest_path(address, node.address)
            malicious_connections.append({
                "address": node.address,
                "hops": len(path) - 1,
                "threat_type": rep.threat_type,
                "confidence": rep.confidence
            })
    
    return GraphResult(
        center_address=address,
        malicious_connections=malicious_connections,
        contamination_risk=calculate_contamination_risk(malicious_connections)
    )
```

### Tools Available
- `get_reputation_score(address)` — Query local cache + on-chain
- `submit_reputation_update(address, score, evidence)` — Update on-chain
- `build_transaction_graph(address, depth)` — On-chain graph analysis
- `dispute_false_positive(address, evidence)` — Submit dispute to DAO
- `batch_reputation_check(addresses)` — Bulk reputation lookup

---

## Agent 8: NetworkGuardAgent

### Identity
```yaml
name: NetworkGuardAgent
id: agent_network_008
role: Network-Level Anomaly Detection Specialist
priority_level: HIGH
model: claude-sonnet-4-20250514
temperature: 0.1
```

### Responsibilities
- Monitors all processes making RPC calls to blockchain endpoints
- Detects non-browser / non-wallet processes accessing blockchain APIs
- Deep packet inspection on unencrypted RPC calls
- Identifies C2 (Command & Control) patterns in blockchain communication
- Rate anomaly detection — malware often polls rapidly

### Process Allowlist
```yaml
# Processes ALLOWED to make blockchain RPC calls
allowed_processes:
  browsers:
    - "chrome.exe"
    - "firefox.exe"
    - "brave.exe"
    - "msedge.exe"
  wallets:
    - "MetaMask"  # Browser extension context
    - "Phantom"
    - "ledger_live.exe"
    - "trezor_suite.exe"
  development_tools:
    - "node.exe"      # Only in dev mode
    - "hardhat"
    - "foundry"

# ANY OTHER PROCESS making blockchain RPC calls = SUSPICIOUS
```

### Anomaly Detection Rules
```python
ANOMALY_RULES = [
    
    Rule(
        name="non_browser_rpc_call",
        condition="process_name NOT IN allowed_processes AND "
                  "destination IN blockchain_rpc_endpoints",
        severity="HIGH",
        action="ALERT_ORCHESTRATOR"
    ),
    
    Rule(
        name="rapid_polling_pattern",
        condition="same_process makes >10 RPC calls in 30 seconds",
        severity="HIGH",
        description="Malware C2 polling pattern detected",
        action="ALERT_ORCHESTRATOR"
    ),
    
    Rule(
        name="office_doc_blockchain",
        condition="process_name IN ['winword.exe', 'excel.exe', "
                  "'powerpnt.exe'] AND destination IN rpc_endpoints",
        severity="CRITICAL",
        description="Office document accessing blockchain — macro malware",
        action="IMMEDIATE_BLOCK"
    ),
    
    Rule(
        name="script_host_blockchain",
        condition="process_name IN ['wscript.exe', 'cscript.exe', "
                  "'powershell.exe'] AND destination IN rpc_endpoints",
        severity="CRITICAL",
        description="Script host accessing blockchain — dropper malware",
        action="IMMEDIATE_BLOCK"
    ),
    
    Rule(
        name="entropy_file_write",
        condition="process writes file with entropy > 7.5",
        severity="HIGH",
        description="Encrypted payload being written — possible ransomware",
        action="SHADOW_COPY_AND_ALERT"
    )
]
```

### Tools Available
- `monitor_process_network(pid)` — Track process network calls
- `get_process_list()` — Current running processes
- `intercept_rpc_call(request)` — Capture and inspect RPC call
- `check_process_allowlist(process_name)` — Is this process allowed?
- `get_process_entropy_writes(pid)` — Monitor high-entropy file writes
- `block_process_network(pid)` — Cut network access for a process
- `deep_packet_inspect(packet)` — Analyze packet payload

---

## Agent Communication Protocol

### Message Format
```json
{
  "msg_id": "msg_abc123",
  "timestamp": "2025-01-15T10:30:00Z",
  "source": "agent_network_008",
  "destination": "agent_orchestrator_001",
  "priority": "CRITICAL",
  "type": "THREAT_DETECTED",
  "payload": {
    "threat_type": "ransomware_dropper",
    "process": "fake_updater.exe",
    "pid": 4821,
    "target_rpc": "https://mainnet.infura.io/v3/xxx",
    "method": "eth_getTransactionByHash",
    "tx_hash": "0xdeadbeef...",
    "evidence": {
      "entropy": 7.91,
      "headers": "MZ_DETECTED",
      "signatures": ["locky_v4_sig_001"]
    }
  },
  "requires_response": true,
  "response_deadline_ms": 500
}
```

### Agent Health Monitoring
```python
# Each agent publishes heartbeat every 10 seconds
HEARTBEAT_SCHEMA = {
    "agent_id": str,
    "status": "ACTIVE" | "DEGRADED" | "OFFLINE",
    "last_event_processed": datetime,
    "events_processed_total": int,
    "threats_detected_session": int,
    "threats_blocked_session": int,
    "average_response_time_ms": float
}
```

---

## Agent Configuration File

```yaml
# config/agents.yaml

global:
  model: "claude-sonnet-4-20250514"
  max_tokens: 1000
  message_bus: "redis://localhost:6379"
  log_level: "INFO"

agents:
  orchestrator:
    id: "agent_orchestrator_001"
    temperature: 0.1
    decision_timeout_ms: 1000
    consensus_threshold: 0.6

  payload_scanner:
    id: "agent_payload_002"
    temperature: 0.0
    entropy_threshold: 7.2
    signature_db: "config/signatures.yaml"
    enable_recursive_decode: true

  wallet_sentinel:
    id: "agent_wallet_003"
    temperature: 0.1
    monitor_metamask: true
    monitor_phantom: true
    clipboard_scan_interval_ms: 500
    seed_phrase_pattern_alert: true

  threat_intel:
    id: "agent_intel_004"
    temperature: 0.2
    poll_interval_seconds: 60
    cache_ttl_seconds: 300

  contract_auditor:
    id: "agent_auditor_005"
    temperature: 0.1
    simulation_network: "anvil_fork"
    risk_threshold_block: 70
    risk_threshold_warn: 40

  incident_responder:
    id: "agent_responder_006"
    temperature: 0.0
    auto_quarantine: true
    ipfs_gateway: "https://ipfs.io/ipfs/"
    evidence_retention_days: 90

  reputation_oracle:
    id: "agent_reputation_007"
    temperature: 0.3
    cache_ttl_seconds: 3600
    min_confirmations_to_blacklist: 3
    graph_analysis_depth: 3

  network_guard:
    id: "agent_network_008"
    temperature: 0.1
    poll_interval_ms: 100
    rapid_poll_threshold: 10
    rapid_poll_window_seconds: 30
```
