"""
ChainGuard detection benchmark.

Runs every scanner adapter against every corpus sample, scores TP/FP/FN,
reports catch-rate + p95 latency. Exits non-zero if ChainGuard falls below
parity threshold vs best competitor (used as CI gate).

Usage:
    python -m tests.benchmark.run_benchmark
    python -m tests.benchmark.run_benchmark --scanners chainguard,blockaid
    python -m tests.benchmark.run_benchmark --min-catch-rate 0.70
"""
from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

from tests.benchmark.adapters import (
    BlockaidAdapter, ChainGuardAdapter, GoPlusAdapter, ScanResult,
)

CORPUS_DIR = Path(__file__).parent / "corpus"
ALL_SCANNERS = {
    "chainguard": ChainGuardAdapter,
    "blockaid": BlockaidAdapter,
    "goplus": GoPlusAdapter,
}
MALICIOUS_VERDICTS = {"BLOCK", "WARN"}


def load_corpus() -> list[dict]:
    samples = []
    for label, path in [("malicious", "drainers.jsonl"),
                        ("benign", "safe.jsonl")]:
        fp = CORPUS_DIR / path
        if not fp.exists():
            continue
        for line in fp.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            s = json.loads(line)
            s["label"] = label
            samples.append(s)
    return samples


async def run_scanner(adapter, samples) -> list[ScanResult]:
    results = []
    for s in samples:
        results.append(await adapter.scan(s))
    return results


def score(scanner: str, samples, results) -> dict:
    tp = fp = tn = fn = err = 0
    latencies = []
    for s, r in zip(samples, results):
        latencies.append(r.latency_ms)
        if r.verdict == "ERROR":
            err += 1
            continue
        flagged = r.verdict in MALICIOUS_VERDICTS
        malicious = s["label"] == "malicious"
        if flagged and malicious: tp += 1
        elif flagged and not malicious: fp += 1
        elif not flagged and malicious: fn += 1
        else: tn += 1
    n_mal = tp + fn
    n_ben = fp + tn
    return {
        "scanner": scanner,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn, "errors": err,
        "catch_rate": tp / n_mal if n_mal else 0.0,
        "false_positive_rate": fp / n_ben if n_ben else 0.0,
        "p50_ms": round(statistics.median(latencies), 1) if latencies else 0,
        "p95_ms": round(statistics.quantiles(latencies, n=20)[18], 1)
                  if len(latencies) >= 20 else round(max(latencies or [0]), 1),
    }


def print_report(scores: list[dict]) -> None:
    print("\n=== ChainGuard Benchmark ===")
    cols = ["scanner", "tp", "fp", "tn", "fn", "errors",
            "catch_rate", "false_positive_rate", "p50_ms", "p95_ms"]
    w = {c: max(len(c), max(len(str(s[c])) for s in scores)) for c in cols}
    print(" | ".join(c.ljust(w[c]) for c in cols))
    print("-+-".join("-" * w[c] for c in cols))
    for s in scores:
        row = []
        for c in cols:
            v = s[c]
            if c in ("catch_rate", "false_positive_rate"):
                v = f"{v:.2%}"
            row.append(str(v).ljust(w[c]))
        print(" | ".join(row))
    print()


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scanners", default="chainguard,blockaid,goplus")
    ap.add_argument("--min-catch-rate", type=float, default=0.0,
                    help="Fail (exit 1) if chainguard catch_rate below this.")
    ap.add_argument("--parity-gap", type=float, default=0.10,
                    help="Fail if chainguard is more than N behind best peer.")
    ap.add_argument("--json", action="store_true", help="Emit JSON scores.")
    args = ap.parse_args()

    samples = load_corpus()
    if not samples:
        print("ERROR: corpus empty. Add entries to tests/benchmark/corpus/*.jsonl")
        sys.exit(2)

    wanted = [s.strip() for s in args.scanners.split(",") if s.strip()]
    scanners = {k: ALL_SCANNERS[k]() for k in wanted if k in ALL_SCANNERS}

    all_scores = []
    for name, adapter in scanners.items():
        print(f"[run] {name} on {len(samples)} samples...")
        results = await run_scanner(adapter, samples)
        all_scores.append(score(name, samples, results))

    if args.json:
        print(json.dumps(all_scores, indent=2))
    else:
        print_report(all_scores)

    cg = next((s for s in all_scores if s["scanner"] == "chainguard"), None)
    peers = [s for s in all_scores if s["scanner"] != "chainguard" and s["errors"] < len(samples)]
    if cg:
        if cg["catch_rate"] < args.min_catch_rate:
            print(f"FAIL: chainguard catch_rate {cg['catch_rate']:.2%} "
                  f"< min {args.min_catch_rate:.2%}")
            sys.exit(1)
        if peers:
            best = max(s["catch_rate"] for s in peers)
            if best - cg["catch_rate"] > args.parity_gap:
                print(f"FAIL: chainguard {cg['catch_rate']:.2%} trails best peer "
                      f"{best:.2%} by >{args.parity_gap:.0%}")
                sys.exit(1)
    print("OK")


if __name__ == "__main__":
    asyncio.run(main())
