"""Sentri OT — FastAPI application for deployment-ready passive BMS monitoring.

Database-backed persistence, async scan runner, full REST API with
passive BACnet discovery, compliance evaluation, and PDF reporting.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import FileResponse

from backend.db import (
    init_db,
    save_scan,
    get_latest_scan,
    get_scan_history,
    update_scan_status,
    get_assets,
    get_asset_by_id,
    get_alerts,
    acknowledge_alert,
    resolve_alert,
    get_compliance_report,
    get_latest_compliance_summary,
    get_summary_stats,
    prune_old_data,
    close_db,
)
from backend.ot_discovery import scan_environment_async
from backend.report_gen import generate_pdf_report

# ── configuration from env ──────────────────────────────────────────────────

BACKEND_VERSION = "0.2.0"
SCAN_MODE = os.environ.get("SENTRI_OT_SCAN_MODE", "passive")
SCAN_INTERVAL_MINUTES = int(os.environ.get("SENTRI_OT_SCAN_INTERVAL", "60"))
SCAN_NETWORKS = os.environ.get("SENTRI_OT_SCAN_NETWORKS", "")
BACNET_DISCOVERY = os.environ.get("SENTRI_OT_BACNET_DISCOVERY", "whois")
API_KEY = os.environ.get("SENTRI_OT_API_KEY", "").strip()
CORS_ORIGINS = os.environ.get(
    "SENTRI_OT_CORS_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000",
)

# ── app ─────────────────────────────────────────────────────────────────────

app = FastAPI(title="Sentri OT API", version=BACKEND_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in CORS_ORIGINS.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def optional_api_key_auth(request: Request, call_next):
    """Protect API routes when SENTRI_OT_API_KEY is configured.

    Demo/local deployments remain open by default. For real building networks, set
    SENTRI_OT_API_KEY and send Authorization: Bearer <key> or X-API-Key: <key>.
    """
    if API_KEY and request.method != "OPTIONS" and request.url.path.startswith("/api/"):
        supplied = request.headers.get("x-api-key", "")
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            supplied = auth.split(" ", 1)[1].strip()
        if supplied != API_KEY:
            return JSONResponse({"detail": "Unauthorized"}, status_code=401)
    return await call_next(request)

# ── scan runner state ───────────────────────────────────────────────────────

_scan_task: asyncio.Task | None = None
_started_at: str | None = None
_app_started_at: str | None = None
_config_lock = asyncio.Lock()
_scan_progress: dict[str, Any] = {"progress": 0, "message": "Ready to scan"}


def _progress_callback(progress: int, message: str) -> None:
    """Store in-memory progress for /api/scan/status during a running scan."""
    _scan_progress["progress"] = max(0, min(100, int(progress)))
    _scan_progress["message"] = message


async def _run_scan() -> None:
    """Core scan runner: executes discovery, persists results."""
    global _scan_task, _started_at

    try:
        _started_at = datetime.now(timezone.utc).isoformat()
        _scan_progress.update({"progress": 1, "message": "Scan started"})
        scan_result = await scan_environment_async(progress_cb=_progress_callback)

        # Persist to database
        scan_id = await save_scan(scan_result)

        # Prune old data if needed
        await prune_old_data(max_scans=100)

    except Exception as exc:
        # Create a failed scan record
        failed_scan = {
            "scan_id": str(uuid.uuid4()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan_type": SCAN_MODE,
            "status": "failed",
            "assets": [],
            "summary": {
                "total_assets": 0,
                "total_vulnerabilities": 0,
                "critical_vulnerabilities": 0,
                "compliance_score": 0,
                "vulnerabilities_by_severity": {},
                "protocols_discovered": {},
                "zones_discovered": {},
            },
            "compliance": {},
            "alerts": [{
                "id": f"ALERT-ERR-{uuid.uuid4().hex[:8]}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "severity": "High",
                "title": "Scan Failed",
                "message": f"Scan error: {exc}",
                "asset_id": None,
                "status": "Active",
            }],
        }
        await save_scan(failed_scan)
    finally:
        _scan_task = None
        _started_at = None
        _scan_progress.update({"progress": 0, "message": "Ready to scan"})


def _start_async_scan() -> bool:
    """Start scan in background if not already running. Returns accepted."""
    global _scan_task
    if _scan_task is not None and not _scan_task.done():
        return False
    _scan_task = asyncio.create_task(_run_scan())
    return True


# ── startup / shutdown ──────────────────────────────────────────────────────


@app.on_event("startup")
async def startup() -> None:
    """Initialize database and optionally run initial scan."""
    global _app_started_at
    _app_started_at = datetime.now(timezone.utc).isoformat()
    await init_db(os.environ.get("SENTRI_OT_DB_PATH", "sentri_ot.db"))

    # Seed with a simulated scan if no data exists
    latest = await get_latest_scan()
    if latest is None:
        # First run — do an initial scan in background
        _start_async_scan()

    # Start periodic auto-scan if interval > 0
    if SCAN_INTERVAL_MINUTES > 0:
        asyncio.create_task(_periodic_scanner())


@app.on_event("shutdown")
async def shutdown() -> None:
    """Cancel active scans and close DB connection."""
    global _scan_task
    if _scan_task is not None and not _scan_task.done():
        _scan_task.cancel()
        try:
            await _scan_task
        except asyncio.CancelledError:
            pass
    await close_db()


async def _periodic_scanner() -> None:
    """Run scans at configured interval."""
    while True:
        await asyncio.sleep(SCAN_INTERVAL_MINUTES * 60)
        try:
            _start_async_scan()
        except Exception:
            pass


# ── API: health & version ───────────────────────────────────────────────────


@app.get("/api/health")
async def health() -> dict[str, Any]:
    """Extended health check with version, uptime, mode, device count."""
    stats = await get_summary_stats()
    return {
        "status": "ok",
        "version": BACKEND_VERSION,
        "scan_mode": SCAN_MODE,
        "bacnet_discovery": BACNET_DISCOVERY,
        "total_assets": stats.get("total_assets", 0),
        "total_scans": stats.get("total_scans", 0),
        "scan_running": _scan_task is not None and not (_scan_task.done() if _scan_task else True),
        "db_status": "connected",
        "started_at": _app_started_at,
    }


@app.get("/api/version")
async def version() -> dict[str, str]:
    return {"version": BACKEND_VERSION}


@app.get("/api/stats/summary")
async def stats_summary() -> dict[str, Any]:
    """Return the latest scan summary for the dashboard."""
    from backend.db import get_latest_scan
    latest = await get_latest_scan()
    if latest and latest.get("summary"):
        return latest["summary"]
    return {}


# ── API: scan control ──────────────────────────────────────────────────────


@app.post("/api/scan/start")
async def start_scan() -> dict[str, Any]:
    """Start a new scan. Returns accepted status."""
    if not _start_async_scan():
        return {
            "accepted": False,
            "status": "running",
            "message": "A scan is already in progress.",
        }
    return {
        "accepted": True,
        "status": "running",
        "message": "Scan started.",
        "started_at": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/scan")
async def start_scan_legacy() -> dict[str, Any]:
    """Compatibility alias for older docs/scripts."""
    return await start_scan()


@app.get("/api/scan/status")
async def scan_status() -> dict[str, Any]:
    """Current scan status, read from database."""
    latest = await get_latest_scan()
    running = _scan_task is not None and not (_scan_task.done() if _scan_task else True)

    if running:
        return {
            "status": "running",
            "progress": _scan_progress.get("progress", 50),
            "message": _scan_progress.get("message", "Scan in progress"),
            "started_at": _started_at,
        }

    if latest:
        summary = latest.get("summary", {})
        return {
            "status": latest.get("status", "idle"),
            "progress": 100 if latest.get("status") == "complete" else 0,
            "message": "Scan complete" if latest.get("status") == "complete" else "No scan data",
            "started_at": latest.get("generated_at"),
            "scan_id": latest.get("scan_id"),
            "total_assets": summary.get("total_assets", 0),
            "compliance_score": summary.get("compliance_score", 0),
        }

    return {
        "status": "idle",
        "progress": 0,
        "message": "Ready — no scan history",
        "started_at": None,
    }


# ── API: scan results & history ──────────────────────────────────────────────


@app.get("/api/scan/latest/result")
async def latest_scan_result() -> dict[str, Any]:
    """Full latest scan data."""
    scan = await get_latest_scan()
    if scan is None:
        return {
            "scan_id": "pending",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "assets": [],
            "summary": {
                "total_assets": 0,
                "total_vulnerabilities": 0,
                "critical_vulnerabilities": 0,
                "compliance_score": 0,
                "vulnerabilities_by_severity": {},
                "protocols_discovered": {},
                "zones_discovered": {},
                "device_types": {},
                "total_bacnet_objects": 0,
                "top_vendors": {},
            },
            "compliance": {},
            "alerts": [],
        }
    return scan


@app.get("/api/scan/history")
async def scan_history_endpoint(limit: int = Query(20, ge=1, le=100)) -> dict[str, Any]:
    """List of scan summaries."""
    history = await get_scan_history(limit=limit)
    return {"history": history}


@app.get("/api/scans")
async def scans_legacy(limit: int = Query(20, ge=1, le=100)) -> dict[str, Any]:
    """Compatibility alias for older docs/scripts."""
    return await scan_history_endpoint(limit=limit)


@app.get("/api/scan/latest/alerts")
async def latest_alerts_endpoint() -> dict[str, Any]:
    """Latest scan alerts."""
    scan = await get_latest_scan()
    if scan is None:
        return {"alerts": []}
    return {"alerts": scan.get("alerts", [])}


# ── API: assets ──────────────────────────────────────────────────────────────


@app.get("/api/assets")
async def list_assets(
    page: int = Query(1, ge=1),
    per_page: int = Query(100, ge=1, le=500),
    search: Optional[str] = None,
    device_type: Optional[str] = None,
    protocol: Optional[str] = None,
    segmentation_zone: Optional[str] = None,
    criticality: Optional[str] = None,
    risk_level: Optional[str] = None,
) -> dict[str, Any]:
    """Paginated asset list with search and filter."""
    filters: dict[str, Any] = {}
    if search:
        filters["search"] = search
    if device_type:
        filters["device_type"] = device_type
    if protocol:
        filters["protocol"] = protocol
    if segmentation_zone:
        filters["segmentation_zone"] = segmentation_zone
    if criticality:
        filters["criticality"] = criticality
    if risk_level:
        filters["risk_level"] = risk_level

    return await get_assets(filters=filters or None, page=page, per_page=per_page)


@app.get("/api/devices")
async def list_devices_legacy(
    page: int = Query(1, ge=1),
    per_page: int = Query(100, ge=1, le=500),
    search: Optional[str] = None,
) -> dict[str, Any]:
    """Compatibility alias for older docs/scripts."""
    return await list_assets(page=page, per_page=per_page, search=search)


@app.get("/api/assets/stats")
async def asset_stats() -> dict[str, Any]:
    """Aggregated asset statistics for dashboard."""
    return await get_summary_stats()


@app.get("/api/assets/{asset_id}")
async def asset_detail(asset_id: str) -> dict[str, Any]:
    """Single asset with full details."""
    asset = await get_asset_by_id(asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@app.get("/api/devices/{asset_id}")
async def device_detail_legacy(asset_id: str) -> dict[str, Any]:
    """Compatibility alias for older docs/scripts."""
    return await asset_detail(asset_id)


# ── API: alerts ──────────────────────────────────────────────────────────────


@app.get("/api/alerts")
async def list_alerts(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    asset_id: Optional[str] = None,
) -> dict[str, Any]:
    """Paginated alerts with filtering."""
    filters: dict[str, Any] = {}
    if severity:
        filters["severity"] = severity
    if status:
        filters["status"] = status
    if asset_id:
        filters["asset_id"] = asset_id

    return await get_alerts(filters=filters or None, page=page, per_page=per_page)


@app.put("/api/alerts/{alert_id}/acknowledge")
async def ack_alert(alert_id: str) -> dict[str, Any]:
    """Acknowledge an active alert."""
    ok = await acknowledge_alert(alert_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Alert not found or already acknowledged")
    return {"status": "acknowledged", "alert_id": alert_id}


@app.put("/api/alerts/{alert_id}/resolve")
async def resolve_alert_endpoint(alert_id: str) -> dict[str, Any]:
    """Resolve an alert."""
    ok = await resolve_alert(alert_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"status": "resolved", "alert_id": alert_id}


# ── API: compliance ─────────────────────────────────────────────────────────


@app.get("/api/compliance/latest")
async def compliance_latest() -> dict[str, Any]:
    """Latest compliance report with categorized controls."""
    compliance_data = await get_latest_compliance_summary()
    if compliance_data is None:
        return {
            "score": 0,
            "rating": "N/A",
            "frameworks": {"DESC": {"categories": [], "score": 0}, "IEC 62443": {"categories": [], "score": 0}},
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
    # Transform flat controls into categorized format for the frontend
    frameworks = compliance_data.get("frameworks", {})
    for fw_name, fw_data in frameworks.items():
        if not isinstance(fw_data, dict):
            continue
        controls = fw_data.get("controls", [])
        cat_scores = fw_data.get("category_scores", {})
        # Group controls by category (skip non-dict entries)
        cat_map: dict[str, list] = {}
        for ctrl in controls:
            if not isinstance(ctrl, dict):
                continue
            cat = ctrl.get("category", "General")
            if cat not in cat_map:
                cat_map[cat] = []
            cat_map[cat].append(ctrl)
        # Build categories list with scores
        categories = []
        for cat_name, cat_ctrls in cat_map.items():
            cat_info = cat_scores.get(cat_name, {"total": len(cat_ctrls), "passed": 0, "partial": 0, "failed": 0, "score": 0})
            categories.append({
                "name": cat_name,
                "score": cat_info.get("score", 0),
                "passed": cat_info.get("passed", 0),
                "total": cat_info.get("total", len(cat_ctrls)),
                "controls": cat_ctrls,
            })
        # Replace controls with categories
        fw_data["categories"] = categories
        fw_data.pop("controls", None)
        fw_data.pop("category_scores", None)
    return compliance_data


@app.get("/api/compliance/overview")
async def compliance_overview_legacy() -> dict[str, Any]:
    """Compatibility alias for older docs/scripts."""
    return await compliance_latest()


@app.get("/api/compliance/frameworks")
async def compliance_frameworks() -> dict[str, list[dict[str, Any]]]:
    """List supported compliance frameworks."""
    try:
        from backend.compliance_framework import DESC_FRAMEWORK, IEC62443_FRAMEWORK
        desc_count = len(DESC_FRAMEWORK)
        iec_count = len(IEC62443_FRAMEWORK)
    except ImportError:
        desc_count = 46
        iec_count = 47
    return {
        "frameworks": [
            {
                "id": "DESC",
                "name": "DESC ICS/OT Security Standard alignment",
                "version": "assessment mapping",
                "controls_count": desc_count,
                "scope_note": "Internal evidence mapping for OT/BMS controls; not an official DESC certification or ISR v3 assessment.",
            },
            {
                "id": "IEC 62443",
                "name": "ISA/IEC 62443-3-3 base SR alignment",
                "version": "3-3",
                "controls_count": iec_count,
                "scope_note": "Base security requirement alignment only; requirement enhancements and security-level certification are out of scope.",
            },
        ]
    }


@app.get("/api/compliance/controls")
async def compliance_controls(framework: str = Query("DESC")) -> dict[str, Any]:
    """List controls for a given framework."""
    compliance_data = await get_latest_compliance_summary()
    if compliance_data is None:
        return {"framework": framework, "controls": [], "score": 0}

    frameworks = compliance_data.get("frameworks", {})
    fw_data = frameworks.get(framework, {})
    controls = fw_data.get("controls", []) if isinstance(fw_data, dict) else []
    return {
        "framework": framework,
        "controls": controls,
        "score": fw_data.get("score", compliance_data.get("score", 0)) if isinstance(fw_data, dict) else compliance_data.get("score", 0),
        "rating": compliance_data.get("rating", ""),
    }


# ── API: report ──────────────────────────────────────────────────────────────


@app.get("/api/report/pdf")
async def report_pdf() -> Response:
    """Download PDF report."""
    scan = await get_latest_scan()
    if scan is None:
        raise HTTPException(status_code=404, detail="No report data available")

    pdf = generate_pdf_report(scan)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": "attachment; filename=sentri-ot-report.pdf"
        },
    )


# ── API: config ──────────────────────────────────────────────────────────────


@app.get("/api/config")
async def get_config() -> dict[str, Any]:
    """Show current scanner configuration."""
    async with _config_lock:
        return {
            "mode": SCAN_MODE,
            "bacnet_discovery": BACNET_DISCOVERY,
            "interval_minutes": SCAN_INTERVAL_MINUTES,
            "networks": SCAN_NETWORKS or "auto-detect",
            "version": BACKEND_VERSION,
            "cors_origins": CORS_ORIGINS,
            "api_auth_enabled": bool(API_KEY),
        }


@app.put("/api/config")
async def update_config(config: dict[str, Any]) -> dict[str, Any]:
    """Update scanner configuration (runtime overrides).

    Persisted settings are re-read from env on next startup.
    This endpoint updates the current runtime config only.
    """
    global SCAN_MODE, SCAN_INTERVAL_MINUTES, BACNET_DISCOVERY

    async with _config_lock:
        if "mode" in config:
            mode = config["mode"].lower()
            if mode not in ("passive", "active", "simulate"):
                raise HTTPException(status_code=400, detail="Invalid mode. Use: passive, active, simulate")
            SCAN_MODE = mode
            os.environ["SENTRI_OT_SCAN_MODE"] = mode

        if "bacnet_discovery" in config:
            bd = config["bacnet_discovery"].lower()
            if bd not in ("whois", "listen", "full"):
                raise HTTPException(status_code=400, detail="Invalid bacnet_discovery. Use: whois, listen, full")
            BACNET_DISCOVERY = bd
            os.environ["SENTRI_OT_BACNET_DISCOVERY"] = bd

        if "interval_minutes" in config:
            interval = int(config["interval_minutes"])
            if interval < 0 or interval > 1440:
                raise HTTPException(status_code=400, detail="Interval must be 0 (manual) to 1440")
            SCAN_INTERVAL_MINUTES = interval

        if "networks" in config:
            global SCAN_NETWORKS
            SCAN_NETWORKS = config["networks"]
            if SCAN_NETWORKS:
                os.environ["SENTRI_OT_SCAN_NETWORKS"] = SCAN_NETWORKS
            else:
                os.environ.pop("SENTRI_OT_SCAN_NETWORKS", None)

    return await get_config()


# ── serve frontend static files ────────────────────────────────────────────

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BACKEND_DIR)
FRONTEND_DIST_CANDIDATES = [
    os.path.join(PROJECT_DIR, "frontend", "dist"),  # bare-metal/source checkout
    os.path.join(BACKEND_DIR, "static"),             # Docker image copy target
]
FRONTEND_DIST = next((path for path in FRONTEND_DIST_CANDIDATES if os.path.isdir(path)), "")
if FRONTEND_DIST:
    app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIST, "assets")), name="assets")

    @app.get("/")
    async def serve_frontend() -> FileResponse:
        return FileResponse(os.path.join(FRONTEND_DIST, "index.html"))

    @app.exception_handler(404)
    async def spa_fallback(request, exc):
        path = request.url.path
        if path.startswith("/api/") or path.startswith("/docs") or path.startswith("/openapi"):
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail": "Not Found"}, status_code=404)
        return FileResponse(os.path.join(FRONTEND_DIST, "index.html"))
else:
    @app.get("/")
    async def root() -> dict[str, Any]:
        return {
            "service": "Sentri OT",
            "version": BACKEND_VERSION,
            "scan_mode": SCAN_MODE,
            "docs": "/docs",
            "health": "/api/health",
        }
