"""Scanner adapters. Each returns a unified Verdict: BLOCK | WARN | ALLOW."""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Literal

import httpx

Verdict = Literal["BLOCK", "WARN", "ALLOW", "ERROR"]


@dataclass
class ScanResult:
    scanner: str
    verdict: Verdict
    risk_score: float | None
    latency_ms: float
    raw: dict
    error: str | None = None


class ChainGuardAdapter:
    name = "chainguard"

    def __init__(self):
        from backend.intel_aggregator import ThreatIntelAggregator
        from agents.agent_network import OrchestratorAgent

        self.orchestrator = OrchestratorAgent(ThreatIntelAggregator())

    async def scan(self, sample: dict) -> ScanResult:
        t0 = time.perf_counter()
        try:
            if sample.get("kind") == "contract":
                out = await self.orchestrator.analyze_contract_interaction(sample["payload"])
            else:
                out = await self.orchestrator.analyze_transaction(sample["payload"])
            return ScanResult(
                scanner=self.name,
                verdict=out["verdict"],
                risk_score=out.get("risk_score"),
                latency_ms=(time.perf_counter() - t0) * 1000,
                raw=out,
            )
        except Exception as e:
            return ScanResult(self.name, "ERROR", None,
                              (time.perf_counter() - t0) * 1000, {}, str(e))


class BlockaidAdapter:
    """Blockaid public transaction-scan API. Requires BLOCKAID_API_KEY."""
    name = "blockaid"
    ENDPOINT = "https://api.blockaid.io/v0/evm/transaction/scan"

    def __init__(self):
        self.api_key = os.getenv("BLOCKAID_API_KEY")

    async def scan(self, sample: dict) -> ScanResult:
        t0 = time.perf_counter()
        if not self.api_key:
            return ScanResult(self.name, "ERROR", None, 0, {},
                              "BLOCKAID_API_KEY not set")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(
                    self.ENDPOINT,
                    headers={"X-API-KEY": self.api_key},
                    json=sample["payload"],
                )
                data = r.json()
            verdict = self._map(data.get("validation", {}).get("result_type", ""))
            return ScanResult(self.name, verdict,
                              data.get("validation", {}).get("score"),
                              (time.perf_counter() - t0) * 1000, data)
        except Exception as e:
            return ScanResult(self.name, "ERROR", None,
                              (time.perf_counter() - t0) * 1000, {}, str(e))

    @staticmethod
    def _map(result_type: str) -> Verdict:
        return {
            "Malicious": "BLOCK",
            "Warning": "WARN",
            "Benign": "ALLOW",
        }.get(result_type, "ERROR")


class GoPlusAdapter:
    """GoPlus free address-security API. No key required for basic use."""
    name = "goplus"
    ENDPOINT = "https://api.gopluslabs.io/api/v1/address_security/{addr}"

    async def scan(self, sample: dict) -> ScanResult:
        t0 = time.perf_counter()
        addr = sample["payload"].get("to") or sample["payload"].get("contract")
        if not addr:
            return ScanResult(self.name, "ERROR", None, 0, {}, "no address")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(self.ENDPOINT.format(addr=addr),
                                     params={"chain_id": sample.get("chain_id", 1)})
                data = r.json().get("result", {})
            flags = sum(int(data.get(k, "0") or "0") for k in (
                "honeypot_related_address", "phishing_activities",
                "blacklist_doubt", "stealing_attack", "malicious_mining_activities",
            ))
            verdict: Verdict = "BLOCK" if flags >= 1 else "ALLOW"
            return ScanResult(self.name, verdict, float(flags),
                              (time.perf_counter() - t0) * 1000, data)
        except Exception as e:
            return ScanResult(self.name, "ERROR", None,
                              (time.perf_counter() - t0) * 1000, {}, str(e))
