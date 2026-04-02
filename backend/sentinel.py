"""
ChainGuard Sentinel Backend — FastAPI Application
Provides REST API + WebSocket for the dashboard and browser extension.
"""
import asyncio
import logging
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.intel_aggregator import ThreatIntelAggregator
from backend.scoring_engine import scan_payload
from agents.agent_network import OrchestratorAgent

# ─── LOGGING ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("chainguard.sentinel")

# ─── GLOBALS ────────────────────────────────────────────────────────────────
intel: Optional[ThreatIntelAggregator] = None
orchestrator: Optional[OrchestratorAgent] = None
ws_clients: list[WebSocket] = []
session_stats = {"txs_analyzed": 0, "threats_blocked": 0, "start_time": time.time()}


@asynccontextmanager
async def lifespan(app: FastAPI):
    global intel, orchestrator
    logger.info("🛡️  ChainGuard Sentinel starting up…")
    intel = ThreatIntelAggregator(offline_mode=True)
    orchestrator = OrchestratorAgent(intel)
    logger.info("✅  All 8 agents active. Sentinel ready.")
    yield
    logger.info("🔻  Sentinel shutting down.")


app = FastAPI(
    title="ChainGuard Sentinel",
    description="Blockchain malware defense backend API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── REQUEST MODELS ──────────────────────────────────────────────────────────

class TxScanRequest(BaseModel):
    hash: str = ""
    chain: str = "ethereum"
    data: str = ""           # hex string
    method: str = ""
    to: str = "0x0"
    from_: str = "0x0"
    value: str = "0"
    process_name: str = "unknown"
    rpc_endpoint: str = ""
    call_count: int = 1

class ContractScanRequest(BaseModel):
    contract: str
    method: str
    params: dict = {}
    is_verified: bool = False
    age_days: int = 0
    user_wallet: str = "0x0"

class ThreatReportRequest(BaseModel):
    indicator_type: str   # address | tx_hash | contract
    value: str
    threat_type: str
    severity: str
    description: str = ""

class PayloadScanRequest(BaseModel):
    data: str             # hex-encoded bytes
    context: str = ""


# ─── HEALTH CHECK ────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "ChainGuard Sentinel",
        "agents_active": orchestrator is not None,
        "uptime_seconds": round(time.time() - session_stats["start_time"], 1),
    }


# ─── AGENT STATUS ────────────────────────────────────────────────────────────

@app.get("/api/v1/agents/status")
async def agents_status():
    if not orchestrator:
        raise HTTPException(503, "Agents not initialized")
    return {
        "all_active": True,
        "agents": orchestrator.all_heartbeats(),
        "session": session_stats,
    }


# ─── TRANSACTION SCAN ────────────────────────────────────────────────────────

@app.post("/api/v1/scan/transaction")
async def scan_transaction(req: TxScanRequest):
    if not orchestrator:
        raise HTTPException(503, "Agents not ready")

    result = await orchestrator.analyze_transaction(req.model_dump())

    session_stats["txs_analyzed"] += 1
    if result["verdict"] == "BLOCK":
        session_stats["threats_blocked"] += 1
        await _broadcast({
            "type": "threat_blocked",
            "threat": {
                "headline": f"Threat blocked: {result['primary_severity']}",
                "summary": result["explanation"],
                "risk_score": result["risk_score"],
            }
        })
    else:
        await _broadcast({
            "type": "tx_scanned",
            "tx_hash": req.hash[:16],
            "verdict": result["verdict"],
            "risk_score": result["risk_score"],
        })

    return result


# ─── CONTRACT SCAN ────────────────────────────────────────────────────────────

@app.post("/api/v1/scan/contract")
async def scan_contract(req: ContractScanRequest):
    if not orchestrator:
        raise HTTPException(503, "Agents not ready")
    result = await orchestrator.analyze_contract_interaction(req.model_dump())
    if result["verdict"] == "BLOCK":
        session_stats["threats_blocked"] += 1
    return result


# ─── PAYLOAD SCAN ─────────────────────────────────────────────────────────────

@app.post("/api/v1/scan/payload")
async def scan_payload_endpoint(req: PayloadScanRequest):
    try:
        raw = bytes.fromhex(req.data.replace("0x", ""))
    except ValueError:
        raw = req.data.encode()
    result = scan_payload(raw)
    result["context"] = req.context
    return result


# ─── THREAT LOOKUP ────────────────────────────────────────────────────────────

@app.get("/api/v1/threat/lookup/{indicator}")
async def lookup_threat(indicator: str, indicator_type: str = "address"):
    if not intel:
        raise HTTPException(503, "Intel not ready")
    threat = intel.lookup(indicator_type, indicator)
    if not threat:
        return {"indicator": indicator, "is_blacklisted": False, "reputation": "NEUTRAL"}
    return {
        "indicator": indicator,
        "is_blacklisted": True,
        "threat_type": threat.threat_type,
        "severity": threat.severity,
        "confidence": threat.confidence,
        "malware_family": threat.malware_family,
        "sources": threat.sources,
        "tags": threat.tags,
    }


# ─── THREAT REPORT ────────────────────────────────────────────────────────────

@app.post("/api/v1/threat/report")
async def report_threat(req: ThreatReportRequest):
    from backend.intel_aggregator import ThreatIndicator
    if not intel:
        raise HTTPException(503, "Intel not ready")
    indicator = ThreatIndicator(
        indicator_type=req.indicator_type,
        value=req.value,
        threat_type=req.threat_type,
        severity=req.severity,
        confidence=0.70,
        sources=["user_report"],
        malware_family="",
        tags=[req.threat_type],
    )
    intel.add_indicator(indicator)
    return {"status": "reported", "indicator": req.value,
            "message": "Threat submitted for review"}


# ─── INTEL STATS ─────────────────────────────────────────────────────────────

@app.get("/api/v1/intel/stats")
async def intel_stats():
    if not intel:
        raise HTTPException(503, "Intel not ready")
    return intel.stats()


# ─── WEBSOCKET ───────────────────────────────────────────────────────────────

@app.websocket("/ws/monitor")
async def ws_monitor(websocket: WebSocket):
    await websocket.accept()
    ws_clients.append(websocket)
    logger.info(f"[WS] Client connected — {len(ws_clients)} total")
    try:
        while True:
            await asyncio.sleep(10)
            await websocket.send_json({"type": "heartbeat", "ts": time.time()})
    except WebSocketDisconnect:
        ws_clients.remove(websocket)
        logger.info(f"[WS] Client disconnected — {len(ws_clients)} remaining")


async def _broadcast(message: dict):
    dead = []
    for ws in ws_clients:
        try:
            await ws.send_json(message)
        except Exception:
            dead.append(ws)
    for ws in dead:
        ws_clients.remove(ws)
