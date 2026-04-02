# ⚙️ ChainGuard Protocol — Complete Execution Pipeline

## Pipeline Overview

ChainGuard operates across **3 pipeline tiers**:
- **Tier 1: Prevention** — Stop malware before it accesses the chain
- **Tier 2: Detection** — Identify malicious patterns in real-time
- **Tier 3: Response** — Automated incident handling and recovery

Each tier contains multiple stages executed in sequence or parallel depending on context.

---

## TIER 1: Prevention Pipeline

### Stage 1.1 — System Initialization (One-Click Activation)

```
USER CLICKS "PROTECT ME" BUTTON
              │
              ▼
┌──────────────────────────────────────────────────────────────┐
│  INITIALIZATION SEQUENCE (< 3 seconds total)                  │
│                                                               │
│  T+0.0s: OrchestratorAgent boots, loads session context       │
│  T+0.2s: NetworkGuardAgent starts process monitoring          │
│  T+0.4s: WalletSentinelAgent hooks window.ethereum/solana     │
│  T+0.6s: Extension RPC interceptor activates                  │
│  T+0.8s: ThreatIntelAgent syncs latest threat feeds           │
│  T+1.0s: ReputationOracleAgent connects to ThreatRegistry.sol │
│  T+1.5s: ContractAuditorAgent forks mainnet for simulation    │
│  T+2.0s: PayloadScannerAgent loads signature database         │
│  T+2.5s: All agents publish READY heartbeat                   │
│  T+3.0s: Dashboard shows "✅ FULLY PROTECTED"                 │
└──────────────────────────────────────────────────────────────┘
```

**Initialization Checklist:**
```python
INIT_CHECKLIST = [
    ✓ Redis message bus reachable
    ✓ Sentinel backend API responding
    ✓ All 8 agents ACTIVE
    ✓ ThreatRegistry.sol queryable (on-chain)
    ✓ Latest threat feed pulled (< 5 min old)
    ✓ window.ethereum hook installed
    ✓ window.solana hook installed
    ✓ RPC endpoint intercept rules loaded
    ✓ Process allowlist loaded
    ✓ Signature database loaded (current version)
    ✓ Mainnet fork ready for simulation
]
```

---

### Stage 1.2 — RPC Call Interception

Every outbound blockchain call passes through this gate:

```
OUTBOUND BLOCKCHAIN REQUEST DETECTED
              │
              ▼
       ┌──────────────┐
       │ Source Check │
       └──────┬───────┘
              │
    ┌─────────▼──────────┐
    │ Is caller in        │
    │ allowed_processes?  │
    └─────────┬───────────┘
              │
        ┌─────┴─────┐
       YES           NO
        │             │
        ▼             ▼
   Continue     ┌──────────────────┐
   to Stage     │ IMMEDIATE ALERT  │
   1.3          │ NetworkGuard →   │
                │ Orchestrator     │
                │ BLOCK CALL       │
                └──────────────────┘
```

---

### Stage 1.3 — Request Content Analysis

For allowed processes, analyze the request content:

```
REQUEST CONTENT PIPELINE:

INPUT: { method: "eth_getTransactionByHash", params: ["0xabc..."] }
          │
          ├──▶ PayloadScannerAgent: analyze request parameters
          │    └── Are any params known malicious hashes? → ThreatIntelAgent lookup
          │
          ├──▶ ReputationOracleAgent: check all addresses in request
          │    └── Score < 20? → BLOCK
          │
          └──▶ OrchestratorAgent: aggregate findings
               └── Decision: PASS / WARN / BLOCK
```

---

### Stage 1.4 — Pre-Execution Transaction Simulation

For `eth_sendTransaction` and `eth_signTypedData`:

```
TRANSACTION SIMULATION PIPELINE:

1. EXTRACT transaction from signing request
           │
2. FORK mainnet at current block (Anvil)
           │
3. EXECUTE transaction in sandbox:
   ├── Record all state changes
   ├── Trace all opcodes (SSTORE, CALL, DELEGATECALL, etc.)
   ├── Calculate balance deltas for user wallet
   ├── Identify all contracts called
   └── Detect all events emitted
           │
4. ANALYZE results:
   ├── Any SELFDESTRUCT? → CRITICAL
   ├── Any DELEGATECALL to unknown? → HIGH
   ├── Unlimited approval granted? → HIGH
   ├── Net balance change negative? → Calculate magnitude
   └── Events indicate fund drain? → CRITICAL
           │
5. SCORE transaction: 0-100
   ├── 0-39: PASS (safe to proceed)
   ├── 40-69: WARN (show user details, require confirmation)
   └── 70-100: BLOCK (reject automatically)
           │
6. PRESENT results to user (if WARN or BLOCK):
   ┌────────────────────────────────────────────┐
   │  ⚠️ Transaction Risk Analysis               │
   │                                            │
   │  Contract: 0xDeadBeef... (UNVERIFIED)      │
   │  Risk Score: 78/100 — HIGH RISK            │
   │                                            │
   │  What this transaction will do:            │
   │  ❌ Grant unlimited USDC to 0xDead...      │
   │  ❌ Contract has no verified source code   │
   │  ❌ Similar to known drainer pattern       │
   │                                            │
   │  [REJECT] [Proceed Anyway (Advanced)]      │
   └────────────────────────────────────────────┘
```

---

## TIER 2: Detection Pipeline

### Stage 2.1 — Continuous Blockchain Data Monitoring

```
INCOMING BLOCKCHAIN DATA MONITORING LOOP (runs every block):

For each new block:
    For each transaction in block:
        │
        ├──▶ Extract OP_RETURN data (if present)
        │    └── PayloadScannerAgent: analyze for shellcode/malware
        │
        ├──▶ Extract contract creation bytecode (if present)
        │    └── ContractAuditorAgent: audit new contracts
        │
        ├──▶ Check all addresses against ReputationOracle
        │    └── Flag any with score < 30
        │
        └──▶ Check all tx hashes against ThreatRegistry.sol
             └── Flag any known malicious transactions
```

---

### Stage 2.2 — Payload Analysis Deep-Scan

```
PAYLOAD ANALYSIS PIPELINE:

RAW BYTES (from OP_RETURN, contract storage, IPFS)
          │
          ▼
┌─────────────────────────────────────────────────────┐
│  LAYER 1: Format Detection                           │
│  • Check magic bytes: MZ (PE), ELF, Mach-O, ZIP     │
│  • Detect script: PS1, BAT, SH, JS, VBS             │
│  • Detect encoding: base64, hex, ROT13, XOR          │
└──────────────────────────┬──────────────────────────┘
                           │
          ┌────────────────▼──────────────────┐
          │  LAYER 2: Entropy Analysis         │
          │  Shannon entropy on 256-byte chunks│
          │  • < 5.0: Likely plain text        │
          │  • 5.0-7.0: Possible encoding      │
          │  • > 7.0: Encrypted/compressed     │
          │  • > 7.5: HIGH RISK — shellcode    │
          └────────────────┬──────────────────┘
                           │
          ┌────────────────▼──────────────────┐
          │  LAYER 3: Signature Matching       │
          │  Compare against 500+ malware sigs │
          │  Families: Locky, CryptoLocker,    │
          │  WannaCry, Ryuk, MetaMask stealers │
          └────────────────┬──────────────────┘
                           │
          ┌────────────────▼──────────────────┐
          │  LAYER 4: Decode & Re-scan         │
          │  Attempt: base64 → re-scan         │
          │  Attempt: hex → re-scan            │
          │  Attempt: XOR(0xFF) → re-scan      │
          │  Attempt: zlib decompress → rescan │
          │  (Max 5 recursion levels)          │
          └────────────────┬──────────────────┘
                           │
          ┌────────────────▼──────────────────┐
          │  LAYER 5: AI Deep Analysis         │
          │  LLM analyzes:                     │
          │  • Disassembled code intent        │
          │  • String patterns & API calls     │
          │  • Network communication patterns  │
          │  • Registry key manipulation       │
          │  Produces: verdict + explanation   │
          └────────────────┬──────────────────┘
                           │
                    FINAL VERDICT:
                    CLEAN / SUSPICIOUS / MALICIOUS
```

---

### Stage 2.3 — Wallet Access Monitoring

```
CONTINUOUS WALLET MONITORING LOOP:

Every 500ms:
  ├── Scan clipboard for private key patterns
  │   Pattern: [0-9a-fA-F]{64}  (Ethereum private key)
  │   Pattern: [1-9A-HJ-NP-Za-km-z]{87,88}  (Solana private key)
  │   IF FOUND → CRITICAL ALERT + Clear clipboard
  │
  ├── Monitor wallet file system paths
  │   IF unexpected process reads wallet files:
  │   → KILL PROCESS + CRITICAL ALERT
  │
  └── Monitor signing request queue
      If new signing request arrives:
      → Route to Stage 1.4 (Transaction Simulation)
      → Hold request until simulation complete
```

---

### Stage 2.4 — Threat Intelligence Correlation

```
REAL-TIME THREAT CORRELATION:

New threat indicator arrives (address/hash/domain)
              │
              ▼
  ┌────────────────────────────┐
  │  Check against all feeds:  │
  │  • Local Redis cache        │
  │  • ThreatRegistry.sol       │
  │  • Chainabuse API           │
  │  • MistTrack                │
  │  • OFAC SDN List            │
  └────────────────┬───────────┘
                   │
         ┌─────────▼─────────┐
         │  Correlation Score │
         │  1 source: LOW     │
         │  2 sources: MEDIUM │
         │  3+ sources: HIGH  │
         │  OFAC: CRITICAL    │
         └─────────┬──────────┘
                   │
         ┌─────────▼──────────────────────────┐
         │  If MEDIUM+: Check transaction      │
         │  graph for user exposure            │
         │  (Has user ever interacted with     │
         │   flagged address or its neighbors?)│
         └─────────┬──────────────────────────┘
                   │
         If YES → Warn user of historical exposure
         If NO  → Update cache only
```

---

## TIER 3: Response Pipeline

### Stage 3.1 — Threat Classification

```
CONFIRMED THREAT ARRIVES AT IncidentResponderAgent
              │
              ▼
┌────────────────────────────────────────────────────┐
│  CLASSIFY THREAT TYPE:                              │
│                                                    │
│  RANSOMWARE_DROPPER:                               │
│    - Non-browser process read blockchain tx        │
│    - Payload contains PE/executable bytes          │
│    - Process began writing high-entropy files      │
│                                                    │
│  WALLET_DRAINER:                                   │
│    - Malicious approval/permit signature requested │
│    - Contract matches known drainer patterns       │
│    - Transaction simulation shows fund loss        │
│                                                    │
│  CREDENTIAL_STEALER:                               │
│    - Process accessed wallet file system           │
│    - Private key pattern found in clipboard        │
│    - Memory scan found seed phrase pattern         │
│                                                    │
│  SUSPICIOUS_C2:                                    │
│    - Rapid polling of blockchain RPC               │
│    - Non-browser process + blockchain = C2 pattern │
└────────────────────────────────────────────────────┘
```

---

### Stage 3.2 — Automated Response Execution

```
RESPONSE EXECUTION (parallel where possible):

RANSOMWARE_DROPPER response (example):

  T+0ms:   BLOCK RPC call (prevent payload download)
  T+50ms:  KILL malicious process (pid: xxxx)
  T+100ms: QUARANTINE dropper file
  T+200ms: DUMP process memory for forensics
  T+300ms: ENABLE wallet isolation mode
  T+500ms: UPLOAD evidence bundle to IPFS
  T+600ms: SUBMIT to ThreatRegistry.sol (on-chain)
  T+700ms: UPDATE ReputationOracle for malicious tx/address
  T+800ms: GENERATE incident report (LLM-written)
  T+1000ms: NOTIFY user with full explanation
  T+2000ms: REPORT to ChainGuard community threat feed
```

---

### Stage 3.3 — Evidence Preservation

```
EVIDENCE BUNDLE STRUCTURE:

evidence_bundle_{incident_id}/
├── metadata.json              ← Incident summary, timestamps, verdict
├── process_info.json          ← Malicious process details
├── network_capture.pcap       ← Network traffic at time of incident
├── memory_dump.bin            ← Process memory (compressed)
├── file_sample.bin            ← Malware file (password protected)
├── blockchain_data.json       ← The tx/contract that was accessed
├── agent_logs/
│   ├── orchestrator.log
│   ├── payload_scanner.log
│   ├── network_guard.log
│   └── incident_responder.log
└── report.md                  ← Human-readable incident report

All files → ZIP → IPFS upload → Hash stored in IncidentVault.sol
```

---

### Stage 3.4 — On-Chain Threat Reporting

```
THREAT REGISTRY SUBMISSION PIPELINE:

IncidentResponderAgent confirms threat
              │
              ▼
  Prepare ThreatRecord:
  {
    indicator_type: "tx_hash",
    value: "0xdeadbeef...",
    severity: 4,  // CRITICAL
    evidence_ipfs_hash: "QmXxx...",
    malware_family: "locky_ransomware",
    reporter: ChainGuard_agent_address
  }
              │
              ▼
  Submit to ThreatRegistry.sol
  (requires ChainGuard multisig approval for critical entries)
              │
              ▼
  Broadcast to all ChainGuard Extension users
  (via WebSocket push from Sentinel Backend)
              │
              ▼
  All connected users now protected from this threat
  in real-time — community defense achieved
```

---

### Stage 3.5 — User Notification & Recovery Guidance

```
USER NOTIFICATION TEMPLATE:

┌──────────────────────────────────────────────────────────────┐
│  🚨 CHAINGUARD SECURITY ALERT                                │
│  Severity: CRITICAL | Time: 14:32:07 UTC                     │
├──────────────────────────────────────────────────────────────┤
│  THREAT DETECTED AND NEUTRALIZED                             │
│                                                               │
│  Type: Ransomware Dropper                                    │
│  Malware Family: Locky Variant                               │
│  Blocked Action: Payload download from Ethereum tx           │
│                                                               │
│  WHAT HAPPENED:                                              │
│  A malicious process (fake_windows_update.exe) attempted     │
│  to download ransomware from Ethereum transaction            │
│  0x7f3a9b2c... The payload was a Locky ransomware variant    │
│  that would have encrypted your files.                       │
│                                                               │
│  WHAT CHAINGUARD DID:                                        │
│  ✅ Blocked the blockchain RPC call                          │
│  ✅ Killed the malicious process                             │
│  ✅ Quarantined the dropper file                             │
│  ✅ Preserved forensic evidence                              │
│  ✅ Reported to community threat registry                    │
│                                                               │
│  RECOMMENDED ACTIONS:                                        │
│  1. Run a full antivirus scan                                │
│  2. Check if dropper file came from recent email/download    │
│  3. Change passwords as precaution                           │
│                                                               │
│  [View Full Incident Report] [View Evidence on IPFS]        │
└──────────────────────────────────────────────────────────────┘
```

---

## Complete End-to-End Pipeline Summary

```
FULL PIPELINE FLOWCHART:

USER ACTIVATES CHAINGUARD
         │
         ▼
┌─────────────────┐
│  STAGE 1.1      │ ← All 8 agents initialize (< 3 seconds)
│  Initialization │
└────────┬────────┘
         │
         ▼
┌─────────────────┐         ┌─────────────────┐
│  STAGE 1.2      │◀────────│  STAGE 2.3      │
│  RPC Intercept  │         │  Wallet Monitor  │
└────────┬────────┘         └─────────────────┘
         │                           ▲
         ▼                           │
┌─────────────────┐         ┌────────┴────────┐
│  STAGE 1.3      │         │  STAGE 2.4      │
│  Request        │         │  Threat Intel   │
│  Analysis       │         │  Correlation    │
└────────┬────────┘         └─────────────────┘
         │                           ▲
         ▼                           │
┌─────────────────┐         ┌────────┴────────┐
│  STAGE 1.4      │         │  STAGE 2.1/2.2  │
│  Pre-execution  │         │  Continuous     │
│  Simulation     │         │  Monitoring     │
└────────┬────────┘         └─────────────────┘
         │
    ┌────┴────┐
  CLEAN      THREAT
    │           │
    ▼           ▼
  Allow   ┌────────────────┐
  Call    │  STAGE 3.1     │
          │  Classification│
          └───────┬────────┘
                  │
                  ▼
          ┌───────────────┐
          │  STAGE 3.2    │
          │  Auto Response│
          └───────┬───────┘
                  │
                  ▼
          ┌───────────────┐
          │  STAGE 3.3    │
          │  Evidence     │
          │  Preservation │
          └───────┬───────┘
                  │
                  ▼
          ┌───────────────┐
          │  STAGE 3.4    │
          │  On-Chain     │
          │  Reporting    │
          └───────┬───────┘
                  │
                  ▼
          ┌───────────────┐
          │  STAGE 3.5    │
          │  User Notify  │
          └───────────────┘
```

---

## Pipeline Performance Targets

| Stage | Target Latency | SLA |
|---|---|---|
| Initialization | < 3 seconds | 99.9% |
| RPC Interception | < 10ms | 99.99% |
| Payload Scan (simple) | < 100ms | 99.9% |
| Payload Scan (deep) | < 2 seconds | 99% |
| Threat Intel Lookup | < 200ms | 99.5% |
| Transaction Simulation | < 5 seconds | 99% |
| Incident Response | < 1 second | 99.9% |
| On-chain Submission | < 30 seconds | 95% (blockchain latency) |
| User Notification | < 2 seconds | 99.9% |
