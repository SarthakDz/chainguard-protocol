"""
ChainGuard Threat Intelligence Aggregator
Polls external feeds, normalizes data, caches results.
Works with mocked feeds when APIs unavailable (dev/test mode).
"""
import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field, asdict
from typing import Optional
import httpx

logger = logging.getLogger("chainguard.intel")


@dataclass
class ThreatIndicator:
    indicator_type: str       # address | tx_hash | contract | domain
    value: str
    threat_type: str          # ransomware | drainer | phishing | c2 | sanctioned
    severity: str             # CRITICAL | HIGH | MEDIUM | LOW
    confidence: float         # 0.0 – 1.0
    sources: list = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_seen: float  = field(default_factory=time.time)
    malware_family: str = ""
    tags: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


# Simulated seed threat database (realistic-looking hashes/addresses)
SEED_THREATS: list[ThreatIndicator] = [
    ThreatIndicator(
        indicator_type="address",
        value="0xDeAdBeEf00000000000000000000000000000001",
        threat_type="wallet_drainer",
        severity="CRITICAL",
        confidence=0.99,
        sources=["chainabuse", "misttrack", "chainguard_oracle"],
        malware_family="metamask_drainer_v3",
        tags=["drainer", "erc20", "unlimited_approval"],
    ),
    ThreatIndicator(
        indicator_type="tx_hash",
        value="0xbaadf00d00000000000000000000000000000000000000000000000000000001",
        threat_type="ransomware",
        severity="CRITICAL",
        confidence=0.97,
        sources=["chainguard_oracle", "virustotal"],
        malware_family="locky_v4",
        tags=["ransomware", "op_return", "pe_payload"],
    ),
    ThreatIndicator(
        indicator_type="address",
        value="0xC0FFEE00000000000000000000000000000000002",
        threat_type="phishing",
        severity="HIGH",
        confidence=0.85,
        sources=["chainabuse", "etherscan_labels"],
        malware_family="",
        tags=["phishing", "fake_dapp"],
    ),
    ThreatIndicator(
        indicator_type="address",
        value="0x0fac00000000000000000000000000000000003",
        threat_type="sanctioned",
        severity="CRITICAL",
        confidence=1.00,
        sources=["ofac"],
        malware_family="",
        tags=["sanctioned", "ofac"],
    ),
]


class ThreatIntelAggregator:
    """
    Aggregates threat intelligence from multiple sources.
    Falls back to seed data in offline/test mode.
    """

    def __init__(self, offline_mode: bool = True):
        self._cache: dict[str, ThreatIndicator] = {}
        self._offline = offline_mode
        self._load_seed_data()
        logger.info(f"ThreatIntelAggregator init — offline={offline_mode}, "
                    f"seed_threats={len(SEED_THREATS)}")

    def _load_seed_data(self):
        for t in SEED_THREATS:
            key = self._cache_key(t.indicator_type, t.value)
            self._cache[key] = t
        logger.info(f"Loaded {len(self._cache)} seed threat indicators")

    def _cache_key(self, indicator_type: str, value: str) -> str:
        return hashlib.sha256(f"{indicator_type}:{value.lower()}".encode()).hexdigest()[:16]

    def lookup(self, indicator_type: str, value: str) -> Optional[ThreatIndicator]:
        key = self._cache_key(indicator_type, value)
        result = self._cache.get(key)
        if result:
            logger.info(f"THREAT HIT: {indicator_type}={value[:20]}... "
                        f"[{result.severity}] {result.malware_family}")
        else:
            logger.debug(f"CLEAN: {indicator_type}={value[:20]}...")
        return result

    def add_indicator(self, indicator: ThreatIndicator):
        key = self._cache_key(indicator.indicator_type, indicator.value)
        self._cache[key] = indicator
        logger.info(f"Added indicator: {indicator.value[:20]}... [{indicator.severity}]")

    def get_all(self) -> list[ThreatIndicator]:
        return list(self._cache.values())

    def stats(self) -> dict:
        all_threats = self.get_all()
        return {
            "total": len(all_threats),
            "critical": sum(1 for t in all_threats if t.severity == "CRITICAL"),
            "high":     sum(1 for t in all_threats if t.severity == "HIGH"),
            "medium":   sum(1 for t in all_threats if t.severity == "MEDIUM"),
        }

    async def poll_feeds(self):
        """Background task — polls external feeds if online."""
        if self._offline:
            logger.info("Offline mode — skipping external feed poll")
            return
        # In production, poll Chainabuse, MistTrack, OFAC, etc.
        logger.info("Polling external threat feeds…")
