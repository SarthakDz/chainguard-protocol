"""
ChainGuard Agent Network — All 8 Agents
Each agent is an async class with analyze() method.
In production: LLM-backed via Anthropic API.
In test mode: deterministic rule-based logic.
"""
import asyncio
import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

from backend.scoring_engine import (
    AgentSignal, Severity, scan_payload, shannon_entropy
)
from backend.intel_aggregator import ThreatIntelAggregator

logger = logging.getLogger("chainguard.agents")


# ─── BASE AGENT ─────────────────────────────────────────────────────────────

class BaseAgent:
    def __init__(self, agent_id: str, name: str, intel: ThreatIntelAggregator):
        self.agent_id = agent_id
        self.name = name
        self.intel = intel
        self.status = "ACTIVE"
        self.events_processed = 0
        self.threats_detected = 0
        self._start_time = time.time()
        logger.info(f"[{self.name}] ACTIVE")

    def _emit(self, severity: Severity, detail: str,
              confidence: float = 0.9, indicators: list = None) -> AgentSignal:
        self.events_processed += 1
        if severity in (Severity.HIGH, Severity.CRITICAL):
            self.threats_detected += 1
        return AgentSignal(
            agent_id=self.agent_id,
            severity=severity,
            confidence=confidence,
            detail=detail,
            indicators=indicators or [],
        )

    def heartbeat(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "status": self.status,
            "uptime_seconds": round(time.time() - self._start_time, 1),
            "events_processed": self.events_processed,
            "threats_detected": self.threats_detected,
        }


# ─── AGENT 1: PAYLOAD SCANNER ────────────────────────────────────────────────

class PayloadScannerAgent(BaseAgent):
    def __init__(self, intel):
        super().__init__("payload_scanner", "PayloadScannerAgent", intel)

    async def analyze(self, raw_data: bytes, tx_hash: str = "") -> AgentSignal:
        logger.info(f"[PayloadScanner] Analyzing {len(raw_data)} bytes "
                    f"(tx={tx_hash[:12] if tx_hash else 'N/A'}...)")
        result = scan_payload(raw_data)

        if result["severity"] == "CRITICAL":
            detail = (f"CRITICAL: {', '.join(result['indicators'][:2])} | "
                      f"entropy={result['entropy']} | "
                      f"family={result.get('malware_family','unknown')}")
            return self._emit(Severity.CRITICAL, detail, 0.97, result["indicators"])

        elif result["severity"] == "HIGH":
            detail = f"HIGH entropy payload ({result['entropy']}) — possible shellcode"
            return self._emit(Severity.HIGH, detail, 0.80, result["indicators"])

        elif result["severity"] == "MEDIUM":
            detail = f"Elevated entropy ({result['entropy']}) — suspicious encoding"
            return self._emit(Severity.MEDIUM, detail, 0.60, result["indicators"])

        return self._emit(Severity.CLEAN, f"Clean payload — entropy={result['entropy']}", 0.95)


# ─── AGENT 2: THREAT INTEL ───────────────────────────────────────────────────

class ThreatIntelAgent(BaseAgent):
    def __init__(self, intel):
        super().__init__("threat_intel", "ThreatIntelAgent", intel)

    async def analyze(self, indicator_type: str, value: str) -> AgentSignal:
        logger.info(f"[ThreatIntel] Checking {indicator_type}={value[:20]}...")
        threat = self.intel.lookup(indicator_type, value)

        if not threat:
            return self._emit(Severity.CLEAN,
                              f"No threat intel match for {value[:16]}...", 0.70)

        sev = Severity(threat.severity)
        detail = (f"THREAT MATCH: {threat.threat_type} | "
                  f"family={threat.malware_family} | "
                  f"sources={threat.sources}")
        return self._emit(sev, detail, threat.confidence,
                          [f"Source: {s}" for s in threat.sources])


# ─── AGENT 3: REPUTATION ORACLE ─────────────────────────────────────────────

class ReputationOracleAgent(BaseAgent):
    # Known-good addresses (exchanges, verified protocols)
    WHITELIST = {
        "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984",  # UNI
        "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",  # Uniswap Router
        "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",  # WETH
    }

    def __init__(self, intel):
        super().__init__("reputation_oracle", "ReputationOracleAgent", intel)

    def _score(self, address: str) -> int:
        """Compute 0-100 reputation score."""
        address_lower = address.lower()
        if address_lower in self.WHITELIST:
            return 95  # Verified trusted
        threat = self.intel.lookup("address", address)
        if threat:
            if threat.severity == "CRITICAL":
                return 2
            if threat.severity == "HIGH":
                return 15
            if threat.severity == "MEDIUM":
                return 35
        # Deterministic pseudo-score based on address hash (for testing)
        h = int(hashlib.md5(address_lower.encode()).hexdigest(), 16)
        return 50 + (h % 30)  # 50-79 for unknowns

    async def analyze(self, address: str) -> AgentSignal:
        logger.info(f"[ReputationOracle] Scoring {address[:16]}...")
        score = self._score(address)

        if score <= 10:
            return self._emit(Severity.CRITICAL,
                              f"Reputation score CRITICAL ({score}/100) — confirmed malicious",
                              0.98)
        elif score <= 30:
            return self._emit(Severity.HIGH,
                              f"Reputation score HIGH RISK ({score}/100)", 0.85)
        elif score <= 50:
            return self._emit(Severity.MEDIUM,
                              f"Reputation score SUSPICIOUS ({score}/100)", 0.65)
        elif score <= 70:
            return self._emit(Severity.LOW,
                              f"Reputation score NEUTRAL ({score}/100)", 0.50)
        return self._emit(Severity.CLEAN,
                          f"Reputation score TRUSTED ({score}/100)", 0.90)


# ─── AGENT 4: WALLET SENTINEL ────────────────────────────────────────────────

class WalletSentinelAgent(BaseAgent):
    DRAINER_METHODS = {
        "setApprovalForAll": "NFT collection drain — grants unlimited access to all NFTs",
        "approve":           "Token approval — check amount (MAX_UINT256 is dangerous)",
        "permit":            "Gasless approval signature — can drain without gas cost",
        "transferFrom":      "Token transfer — verify spender is legitimate",
    }
    UNLIMITED = 2**256 - 1

    def __init__(self, intel):
        super().__init__("wallet_sentinel", "WalletSentinelAgent", intel)

    async def analyze(self, method: str, params: dict, contract: str = "") -> AgentSignal:
        logger.info(f"[WalletSentinel] Analyzing method={method} contract={contract[:16]}...")

        # Check drainer patterns
        if method == "setApprovalForAll":
            return self._emit(Severity.CRITICAL,
                              "setApprovalForAll detected — NFT collection drain pattern",
                              0.95, ["Drainer pattern: setApprovalForAll"])

        if method == "approve":
            amount = params.get("amount", 0)
            if isinstance(amount, str):
                try:
                    amount = int(amount)
                except ValueError:
                    amount = 0
            if amount >= self.UNLIMITED:
                return self._emit(Severity.CRITICAL,
                                  "approve(MAX_UINT256) — unlimited token drain approval",
                                  0.99, ["Unlimited ERC20 approval to unverified contract"])
            if amount > 10**24:  # > 1M tokens (18 decimals)
                return self._emit(Severity.HIGH,
                                  f"approve({amount}) — very large token approval",
                                  0.75, ["Large token approval — verify contract"])

        if method == "permit":
            return self._emit(Severity.HIGH,
                              "permit() — gasless approval, verify deadline and spender",
                              0.70, ["Permit signature requested"])

        return self._emit(Severity.CLEAN,
                          f"Method {method} appears safe", 0.80)

    async def check_clipboard(self, text: str) -> AgentSignal:
        """Detect private key / seed phrase in clipboard."""
        import re
        # Ethereum private key (64 hex chars)
        if re.fullmatch(r'[0-9a-fA-F]{64}', text.strip()):
            return self._emit(Severity.CRITICAL,
                              "Ethereum private key detected in clipboard!",
                              1.0, ["Private key in clipboard — CLEAR IMMEDIATELY"])
        # Solana private key (87-88 base58)
        if re.fullmatch(r'[1-9A-HJ-NP-Za-km-z]{87,88}', text.strip()):
            return self._emit(Severity.CRITICAL,
                              "Solana private key detected in clipboard!",
                              1.0, ["Solana key in clipboard"])
        # 12/24-word mnemonic
        words = text.strip().split()
        if len(words) in (12, 24) and all(w.isalpha() for w in words):
            return self._emit(Severity.CRITICAL,
                              "Seed phrase (mnemonic) detected in clipboard!",
                              0.95, ["Mnemonic phrase in clipboard"])
        return self._emit(Severity.CLEAN, "Clipboard content appears safe", 0.90)


# ─── AGENT 5: CONTRACT AUDITOR ───────────────────────────────────────────────

class ContractAuditorAgent(BaseAgent):
    # Known-safe contract addresses (for testing)
    KNOWN_SAFE = {
        "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",  # Uniswap V2 Router
        "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",  # Uniswap V3 Router
    }

    def __init__(self, intel):
        super().__init__("contract_auditor", "ContractAuditorAgent", intel)

    async def analyze(self, contract_address: str, method: str,
                      is_verified: bool = False, age_days: int = 0) -> AgentSignal:
        logger.info(f"[ContractAuditor] Auditing {contract_address[:16]}... "
                    f"method={method} verified={is_verified} age={age_days}d")
        issues = []
        risk = 0

        if contract_address.lower() in self.KNOWN_SAFE:
            return self._emit(Severity.CLEAN,
                              "Known safe contract (Uniswap/verified protocol)", 0.98)

        # Check threat intel — try both "contract" and "address" types
        threat = self.intel.lookup("contract", contract_address) \
              or self.intel.lookup("address", contract_address)
        if threat:
            return self._emit(Severity.CRITICAL,
                              f"Contract in threat registry: {threat.threat_type}",
                              0.99, ["Blacklisted contract"])

        if not is_verified:
            issues.append("Unverified source code")
            risk += 20
        if age_days < 7:
            issues.append(f"Very new contract ({age_days} days old)")
            risk += 25
        elif age_days < 30:
            issues.append(f"New contract ({age_days} days old)")
            risk += 10

        if method in ("setApprovalForAll", "approve"):
            issues.append(f"Sensitive method: {method}")
            risk += 30

        if risk >= 60:
            return self._emit(Severity.HIGH,
                              f"Contract audit HIGH RISK: {'; '.join(issues)}",
                              0.80, issues)
        elif risk >= 30:
            return self._emit(Severity.MEDIUM,
                              f"Contract audit MEDIUM RISK: {'; '.join(issues)}",
                              0.65, issues)
        return self._emit(Severity.LOW,
                          f"Contract audit LOW RISK: {'; '.join(issues) or 'No issues'}",
                          0.70)


# ─── AGENT 6: NETWORK GUARD ─────────────────────────────────────────────────

class NetworkGuardAgent(BaseAgent):
    ALLOWED_PROCESSES = {
        "chrome", "firefox", "brave", "msedge", "chromium",
        "metamask", "ledger_live", "trezor_suite", "python3",
        "node", "pytest", "uvicorn",
    }
    CRITICAL_BLOCKED = {
        "winword", "excel", "powerpnt",
        "wscript", "cscript", "mshta",
    }
    RPC_PATTERNS = [
        "infura.io", "alchemy.com", "quicknode.io",
        "helius-rpc.com", "polygon-rpc.com", ":8545", ":8546",
    ]

    def __init__(self, intel):
        super().__init__("network_guard", "NetworkGuardAgent", intel)

    async def analyze(self, process_name: str, destination: str,
                      call_count: int = 1, window_sec: int = 30) -> AgentSignal:
        logger.info(f"[NetworkGuard] process={process_name} → {destination[:30]} "
                    f"({call_count} calls/{window_sec}s)")
        proc_lower = process_name.lower().replace(".exe", "")

        # Immediate block for office/script-host processes
        if proc_lower in self.CRITICAL_BLOCKED:
            return self._emit(Severity.CRITICAL,
                              f"CRITICAL: {process_name} accessing blockchain RPC — "
                              "dropper/macro malware pattern",
                              1.0, [f"Blocked process: {process_name}",
                                    f"Destination: {destination}"])

        # Unknown process accessing blockchain
        is_rpc = any(p in destination for p in self.RPC_PATTERNS)
        if is_rpc and proc_lower not in self.ALLOWED_PROCESSES:
            sev = Severity.HIGH
            detail = (f"Non-whitelisted process '{process_name}' accessing "
                      f"blockchain RPC: {destination[:40]}")
            return self._emit(sev, detail, 0.85,
                              [f"Unknown process: {process_name}",
                               f"RPC endpoint: {destination}"])

        # Rapid polling (C2 pattern)
        if call_count >= 10 and window_sec <= 30:
            return self._emit(Severity.HIGH,
                              f"Rapid polling: {call_count} calls in {window_sec}s — "
                              "possible C2 communication",
                              0.80, ["Rapid blockchain polling detected"])

        return self._emit(Severity.CLEAN,
                          f"Process '{process_name}' — normal blockchain access", 0.90)


# ─── AGENT 7: INCIDENT RESPONDER ────────────────────────────────────────────

class IncidentResponderAgent(BaseAgent):
    def __init__(self, intel):
        super().__init__("incident_responder", "IncidentResponderAgent", intel)
        self.incident_log: list[dict] = []

    async def respond(self, verdict, threat_type: str,
                      details: dict) -> dict:
        from backend.scoring_engine import Verdict
        incident_id = f"INC_{int(time.time())}_{len(self.incident_log):04d}"
        logger.warning(f"[IncidentResponder] INCIDENT {incident_id} — "
                       f"verdict={verdict.value} type={threat_type}")

        playbook = self._select_playbook(threat_type)
        actions_taken = []

        for action in playbook:
            result = await self._execute_action(action, details)
            actions_taken.append({"action": action, "result": result})
            logger.info(f"[IncidentResponder] ✅ {action}: {result}")

        incident = {
            "incident_id": incident_id,
            "timestamp": time.time(),
            "verdict": verdict.value,
            "threat_type": threat_type,
            "details": details,
            "actions_taken": actions_taken,
            "status": "RESOLVED",
        }
        self.incident_log.append(incident)
        self.threats_detected += 1
        return incident

    def _select_playbook(self, threat_type: str) -> list[str]:
        playbooks = {
            "ransomware_dropper": [
                "BLOCK_RPC_CALL",
                "KILL_PROCESS",
                "QUARANTINE_FILE",
                "DUMP_MEMORY",
                "ENABLE_WALLET_ISOLATION",
                "UPLOAD_EVIDENCE_IPFS",
                "SUBMIT_THREAT_REGISTRY",
                "NOTIFY_USER",
            ],
            "wallet_drainer": [
                "BLOCK_SIGNING_REQUEST",
                "REVOKE_SUSPICIOUS_APPROVALS",
                "UPLOAD_EVIDENCE_IPFS",
                "SUBMIT_THREAT_REGISTRY",
                "NOTIFY_USER",
            ],
            "credential_stealer": [
                "TERMINATE_WALLET_CONNECTIONS",
                "LOCK_WALLET_FILES",
                "KILL_PROCESS",
                "CLEAR_CLIPBOARD",
                "NOTIFY_USER_CRITICAL",
                "SUBMIT_THREAT_REGISTRY",
            ],
            "suspicious_process": [
                "BLOCK_NETWORK_ACCESS",
                "LOG_INCIDENT",
                "NOTIFY_USER",
            ],
        }
        return playbooks.get(threat_type, ["LOG_INCIDENT", "NOTIFY_USER"])

    async def _execute_action(self, action: str, details: dict) -> str:
        await asyncio.sleep(0.01)  # Simulate async work
        simulated = {
            "BLOCK_RPC_CALL":             "RPC call blocked at proxy layer",
            "KILL_PROCESS":               f"Process '{details.get('process','unknown')}' terminated",
            "QUARANTINE_FILE":            "File moved to /quarantine/",
            "DUMP_MEMORY":                "Memory dump saved to /evidence/",
            "ENABLE_WALLET_ISOLATION":    "Wallet isolation mode ENABLED",
            "UPLOAD_EVIDENCE_IPFS":       "Evidence bundle uploaded → QmFake1234…",
            "SUBMIT_THREAT_REGISTRY":     "Submitted to ThreatRegistry.sol (simulated)",
            "NOTIFY_USER":                "Push notification sent to dashboard",
            "BLOCK_SIGNING_REQUEST":      "Signing request REJECTED",
            "REVOKE_SUSPICIOUS_APPROVALS":"Token approvals revoked",
            "TERMINATE_WALLET_CONNECTIONS":"All wallet connections terminated",
            "LOCK_WALLET_FILES":          "Wallet file access LOCKED",
            "KILL_PROCESS":               "Process killed",
            "CLEAR_CLIPBOARD":            "Clipboard cleared",
            "NOTIFY_USER_CRITICAL":       "CRITICAL alert sent to user",
            "BLOCK_NETWORK_ACCESS":       "Process network access blocked",
            "LOG_INCIDENT":               "Incident logged to database",
        }
        return simulated.get(action, f"Action {action} executed")


# ─── AGENT 8: ORCHESTRATOR ───────────────────────────────────────────────────

class OrchestratorAgent(BaseAgent):
    def __init__(self, intel: ThreatIntelAggregator):
        super().__init__("orchestrator", "OrchestratorAgent", intel)
        self.payload_scanner   = PayloadScannerAgent(intel)
        self.threat_intel      = ThreatIntelAgent(intel)
        self.reputation_oracle = ReputationOracleAgent(intel)
        self.wallet_sentinel   = WalletSentinelAgent(intel)
        self.contract_auditor  = ContractAuditorAgent(intel)
        self.network_guard     = NetworkGuardAgent(intel)
        self.incident_responder = IncidentResponderAgent(intel)
        logger.info("[Orchestrator] All 7 specialist agents initialized")

    async def analyze_transaction(self, tx: dict) -> dict:
        """
        Full pipeline: intake → parallel agent analysis → consensus → response.
        tx keys: hash, chain, data (bytes/hex), method, to, from_, value, process_name
        """
        from backend.scoring_engine import ScoringEngine, Verdict
        logger.info(f"[Orchestrator] analyze_transaction: hash={str(tx.get('hash',''))[:16]}...")

        raw = tx.get("data", b"")
        if isinstance(raw, str):
            try:
                raw = bytes.fromhex(raw.replace("0x", ""))
            except ValueError:
                raw = raw.encode()

        # Parallel agent analysis
        signals = await asyncio.gather(
            self.payload_scanner.analyze(raw, tx.get("hash", "")),
            self.threat_intel.analyze("tx_hash", tx.get("hash", "")),
            self.reputation_oracle.analyze(tx.get("to", "0x0")),
            self.network_guard.analyze(
                tx.get("process_name", "unknown"),
                tx.get("rpc_endpoint", ""),
                tx.get("call_count", 1),
            ),
        )

        scorer = ScoringEngine()
        result = scorer.calculate(list(signals))

        response = {
            "hash": tx.get("hash", ""),
            "verdict": result.verdict.value,
            "risk_score": result.risk_score,
            "primary_severity": result.primary_severity.value,
            "explanation": result.explanation,
            "agent_breakdown": result.breakdown,
            "timestamp": time.time(),
        }

        # Trigger incident response if blocked
        if result.verdict == Verdict.BLOCK:
            threat_type = self._classify_threat(signals)
            incident = await self.incident_responder.respond(
                result.verdict, threat_type,
                {"process": tx.get("process_name", "unknown"), "hash": tx.get("hash", "")}
            )
            response["incident_id"] = incident["incident_id"]
            response["actions_taken"] = [a["action"] for a in incident["actions_taken"]]

        return response

    async def analyze_contract_interaction(self, req: dict) -> dict:
        """Analyze a smart contract signing request."""
        from backend.scoring_engine import ScoringEngine, Verdict
        logger.info(f"[Orchestrator] analyze_contract: {req.get('contract','')[:16]}...")

        signals = await asyncio.gather(
            self.wallet_sentinel.analyze(
                req.get("method", ""),
                req.get("params", {}),
                req.get("contract", ""),
            ),
            self.contract_auditor.analyze(
                req.get("contract", ""),
                req.get("method", ""),
                req.get("is_verified", False),
                req.get("age_days", 0),
            ),
            self.reputation_oracle.analyze(req.get("contract", "0x0")),
            self.threat_intel.analyze("contract", req.get("contract", "")),
        )

        scorer = ScoringEngine()
        result = scorer.calculate(list(signals))

        response = {
            "contract": req.get("contract", ""),
            "method": req.get("method", ""),
            "verdict": result.verdict.value,
            "risk_score": result.risk_score,
            "explanation": result.explanation,
            "agent_breakdown": result.breakdown,
            "timestamp": time.time(),
        }

        if result.verdict == Verdict.BLOCK:
            incident = await self.incident_responder.respond(
                result.verdict, "wallet_drainer",
                {"contract": req.get("contract", ""), "method": req.get("method", "")}
            )
            response["incident_id"] = incident["incident_id"]

        return response

    def _classify_threat(self, signals) -> str:
        for sig in signals:
            d = sig.detail.lower()
            if "ransomware" in d or "locky" in d or "pe32" in d or "elf" in d:
                return "ransomware_dropper"
            if "drainer" in d or "approval" in d or "setapproval" in d:
                return "wallet_drainer"
            if "private key" in d or "mnemonic" in d or "clipboard" in d:
                return "credential_stealer"
        return "suspicious_process"

    def all_heartbeats(self) -> dict:
        agents = [
            self, self.payload_scanner, self.threat_intel,
            self.reputation_oracle, self.wallet_sentinel,
            self.contract_auditor, self.network_guard,
            self.incident_responder,
        ]
        return {a.name: a.heartbeat() for a in agents}
