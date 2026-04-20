# ChainGuard Detection Benchmark

Phase 0 gate for MBS. Prove detection is competitive before building product.

## Run

```bash
# from repo root
pip install -r requirements.txt
pip install httpx                 # benchmark-only dep
python -m tests.benchmark.run_benchmark
```

Compare ChainGuard only:
```bash
python -m tests.benchmark.run_benchmark --scanners chainguard
```

CI gate example:
```bash
python -m tests.benchmark.run_benchmark --min-catch-rate 0.70 --parity-gap 0.10
```
Exit code 1 if ChainGuard catch-rate < 70% OR trails best peer by >10 pts.

## Env

- `BLOCKAID_API_KEY` — request at blockaid.io. Without it, Blockaid adapter reports ERROR.
- `GoPlus` — no key needed for basic address checks.

## Corpus

Format: JSONL, one sample per line. Two files:

- `corpus/drainers.jsonl` — known-malicious (label=malicious)
- `corpus/safe.jsonl`     — known-benign (label=benign)

Sample schema:
```json
{
  "id": "drain-001",
  "kind": "tx | contract",
  "source": "scamsniffer | chainabuse | rekt | uniswap | ...",
  "chain_id": 1,
  "payload": { ... same keys as backend /scan/* input ... }
}
```

`payload` for `kind=tx`: `hash, to, from_, value, data, method, process_name`.
`payload` for `kind=contract`: `contract, method, params, is_verified, age_days`.

## Populate to 100+100

Repo seeds 5 + 5 so harness is runnable today. To reach Phase 0 gate (100 + 100):

1. **Drainer corpus**
   - Scam Sniffer weekly report: https://dune.com/scam-sniffer
   - Chainabuse search by category "Wallet Drainer": https://www.chainabuse.com
   - rekt.news leaderboard + incident post-mortems
   - GoPlus public malicious-address lists
   - For each, pull the malicious contract/tx, extract selectors + approval targets, write JSONL entry
2. **Safe corpus**
   - Top 50 verified contracts on Etherscan by tx count (Uniswap, Aave, Compound, Lido, Curve, ENS, USDC/USDT, WETH)
   - Random sample of normal user txs (transfer, swap, stake) from a block range

Keep `source` accurate — used for slicing results per data origin.

## Interpreting results

- `catch_rate = TP / (TP + FN)` — how many real threats we catch.
- `false_positive_rate = FP / (FP + TN)` — how often we block benign traffic. Target < 3%.
- `p95_ms` — per-sample latency. Target < 2000ms for Safe webhook SLA.
- `errors` — network/adapter failures (not detection misses).

## Phase 0 exit criteria

- ChainGuard `catch_rate` ≥ Blockaid `catch_rate - 0.10`.
- ChainGuard `false_positive_rate` ≤ 0.03.
- ChainGuard `p95_ms` ≤ 3000.

If any fail: do Phase 1 detection work (LLM reasoning, on-chain simulation, real feeds) before touching wedge/billing.
