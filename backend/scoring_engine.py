"""
ChainGuard Scoring Engine
Multi-factor risk scoring with weighted agent signals.
"""
import math
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CLEAN = "CLEAN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Verdict(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    BLOCK = "BLOCK"


@dataclass
class AgentSignal:
    agent_id: str
    severity: Severity
    confidence: float  # 0.0 – 1.0
    detail: str = ""
    indicators: list = field(default_factory=list)


@dataclass
class ScoringResult:
    risk_score: int          # 0–100
    verdict: Verdict
    primary_severity: Severity
    contributing_agents: list
    breakdown: dict
    explanation: str


SEVERITY_SCORES = {
    Severity.CLEAN:    0,
    Severity.LOW:     20,
    Severity.MEDIUM:  45,
    Severity.HIGH:    75,
    Severity.CRITICAL: 100,
}

AGENT_WEIGHTS = {
    "payload_scanner":    0.30,
    "threat_intel":       0.25,
    "reputation_oracle":  0.20,
    "contract_auditor":   0.15,
    "network_guard":      0.10,
}


class ScoringEngine:
    BLOCK_THRESHOLD = 70
    WARN_THRESHOLD  = 40

    def calculate(self, signals: list[AgentSignal]) -> ScoringResult:
        if not signals:
            return ScoringResult(
                risk_score=0, verdict=Verdict.PASS,
                primary_severity=Severity.CLEAN,
                contributing_agents=[], breakdown={},
                explanation="No threat signals — clean."
            )

        # Auto-escalate on any CRITICAL
        has_critical = any(s.severity == Severity.CRITICAL for s in signals)
        high_count   = sum(1 for s in signals if s.severity == Severity.HIGH)

        weighted = 0.0
        breakdown = {}
        for sig in signals:
            w  = AGENT_WEIGHTS.get(sig.agent_id, 0.10)
            sv = SEVERITY_SCORES[sig.severity]
            contribution = w * sv * sig.confidence
            weighted += contribution
            breakdown[sig.agent_id] = {
                "severity": sig.severity.value,
                "confidence": sig.confidence,
                "contribution": round(contribution, 2),
            }

        if has_critical:
            weighted = max(weighted, 90)
        if high_count >= 2:
            weighted = max(weighted, 75)

        risk_score = min(100, int(weighted))

        if risk_score >= self.BLOCK_THRESHOLD:
            verdict = Verdict.BLOCK
        elif risk_score >= self.WARN_THRESHOLD:
            verdict = Verdict.WARN
        else:
            verdict = Verdict.PASS

        primary = max(signals, key=lambda s: SEVERITY_SCORES[s.severity])
        explanation = self._explain(signals, verdict, risk_score)

        return ScoringResult(
            risk_score=risk_score,
            verdict=verdict,
            primary_severity=primary.severity,
            contributing_agents=[s.agent_id for s in signals],
            breakdown=breakdown,
            explanation=explanation,
        )

    def _explain(self, signals, verdict, score) -> str:
        critical = [s for s in signals if s.severity == Severity.CRITICAL]
        high     = [s for s in signals if s.severity == Severity.HIGH]
        parts = []
        if critical:
            parts.append(f"CRITICAL signal from {critical[0].agent_id}: {critical[0].detail}")
        if high:
            parts.append(f"HIGH signal from {high[0].agent_id}: {high[0].detail}")
        return f"[Score {score}/100 → {verdict.value}] " + "; ".join(parts or ["No critical signals."])


# ─── PAYLOAD ANALYSIS ENGINE ────────────────────────────────────────────────

MALWARE_SIGNATURES = {
    "locky_v4":          bytes.fromhex("5468697320686f73"),        # fake "This hos"
    "cryptolocker":      bytes.fromhex("436c6f73654861"),           # fake "CloseHa"
    "metamask_drainer":  b"setApprovalForAll",
    "phantom_stealer":   b"solana_keystore",
    "generic_c2":        b"blockchain_c2_beacon",
}

EXECUTABLE_HEADERS = {
    "PE32":  b"\x4d\x5a",           # MZ
    "ELF":   b"\x7f\x45\x4c\x46",   # ELF
    "MacO":  b"\xca\xfe\xba\xbe",   # Mach-O
}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    n = len(data)
    for count in freq.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def scan_payload(raw: bytes) -> dict:
    """Full static analysis of raw bytes. Returns structured finding dict."""
    result = {
        "entropy": shannon_entropy(raw),
        "length": len(raw),
        "executable_header": None,
        "malware_family": None,
        "severity": "CLEAN",
        "indicators": [],
    }

    # Header check
    for name, magic in EXECUTABLE_HEADERS.items():
        if raw[:len(magic)] == magic:
            result["executable_header"] = name
            result["indicators"].append(f"{name} executable header detected")
            result["severity"] = "CRITICAL"
            result["malware_family"] = f"{name.lower()}_executable"

    # Signature match
    for family, sig in MALWARE_SIGNATURES.items():
        if sig in raw:
            result["malware_family"] = family
            result["indicators"].append(f"Signature match: {family}")
            result["severity"] = "CRITICAL"

    # Entropy thresholds
    if result["entropy"] > 7.5 and result["severity"] == "CLEAN":
        result["severity"] = "HIGH"
        result["indicators"].append(f"Very high entropy ({result['entropy']}) — likely packed/encrypted payload")
    elif result["entropy"] > 7.0 and result["severity"] == "CLEAN":
        result["severity"] = "MEDIUM"
        result["indicators"].append(f"Elevated entropy ({result['entropy']}) — possible encoding")

    # Decode attempts
    import base64
    try:
        decoded = base64.b64decode(raw)
        sub = scan_payload(decoded)
        if sub["severity"] in ("CRITICAL", "HIGH"):
            result["severity"] = sub["severity"]
            result["indicators"].append(f"base64-decoded payload: {sub['indicators']}")
            if sub.get("malware_family"):
                result["malware_family"] = sub["malware_family"] + "_b64"
    except Exception:
        pass

    return result
