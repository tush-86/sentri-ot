"""Sentri OT — Async SQLite persistence layer.

Provides all database operations for scan data, assets, alerts,
and compliance reports using aiosqlite for async compatibility
with FastAPI.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import aiosqlite


# ── module-level singleton ──────────────────────────────────────────────────
_db_path: str = os.environ.get("SENTRI_OT_DB_PATH", "sentri_ot.db")
_db_connection: aiosqlite.Connection | None = None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _uuid4() -> str:
    return str(uuid.uuid4())


# ── schema SQL ──────────────────────────────────────────────────────────────

CREATE_SCANS_TABLE = """
CREATE TABLE IF NOT EXISTS scans (
    id              TEXT PRIMARY KEY,
    generated_at    TEXT NOT NULL,
    scan_type       TEXT NOT NULL DEFAULT 'passive',
    device_count    INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'running',
    summary_json    TEXT NOT NULL DEFAULT '{}'
);
"""

CREATE_ASSETS_TABLE = """
CREATE TABLE IF NOT EXISTS assets (
    id                  TEXT PRIMARY KEY,
    scan_id             TEXT NOT NULL,
    hostname            TEXT NOT NULL DEFAULT '',
    ip_address          TEXT NOT NULL DEFAULT '',
    device_type         TEXT NOT NULL DEFAULT '',
    protocol            TEXT NOT NULL DEFAULT '',
    protocol_version    TEXT NOT NULL DEFAULT '',
    vendor_id           INTEGER DEFAULT 0,
    vendor_name         TEXT NOT NULL DEFAULT '',
    firmware_version    TEXT NOT NULL DEFAULT '',
    segmentation_zone   TEXT NOT NULL DEFAULT '',
    criticality         TEXT NOT NULL DEFAULT 'Medium',
    risk_level          TEXT NOT NULL DEFAULT '',
    auth_method         TEXT NOT NULL DEFAULT '',
    ports_json          TEXT NOT NULL DEFAULT '[]',
    vulnerabilities_json TEXT NOT NULL DEFAULT '[]',
    first_seen          TEXT NOT NULL DEFAULT '',
    last_seen           TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
"""

CREATE_ALERTS_TABLE = """
CREATE TABLE IF NOT EXISTS alerts (
    id          TEXT PRIMARY KEY,
    scan_id     TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'Info',
    title       TEXT NOT NULL DEFAULT '',
    message     TEXT NOT NULL DEFAULT '',
    asset_id    TEXT,
    status      TEXT NOT NULL DEFAULT 'Active',
    FOREIGN KEY (scan_id) REFERENCES scans(id),
    FOREIGN KEY (asset_id) REFERENCES assets(id)
);
"""

CREATE_COMPLIANCE_TABLE = """
CREATE TABLE IF NOT EXISTS compliance_reports (
    id          TEXT PRIMARY KEY,
    scan_id     TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    framework   TEXT NOT NULL,
    score       REAL NOT NULL DEFAULT 0,
    rating      TEXT NOT NULL DEFAULT '',
    report_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
"""

CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_assets_scan_id ON assets(scan_id);",
    "CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip_address);",
    "CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname);",
    "CREATE INDEX IF NOT EXISTS idx_assets_device_type ON assets(device_type);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_scan_id ON alerts(scan_id);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);",
    "CREATE INDEX IF NOT EXISTS idx_compliance_scan_id ON compliance_reports(scan_id);",
    "CREATE INDEX IF NOT EXISTS idx_compliance_framework ON compliance_reports(framework);",
]


# ── connection helpers ──────────────────────────────────────────────────────


async def get_connection() -> aiosqlite.Connection:
    """Return the module-level singleton connection, creating it if needed."""
    global _db_connection, _db_path
    if _db_connection is None:
        _db_connection = await aiosqlite.connect(_db_path)
        _db_connection.row_factory = aiosqlite.Row
        # Enable WAL mode for concurrent reads and wait briefly on writer locks
        await _db_connection.execute("PRAGMA journal_mode=WAL;")
        await _db_connection.execute("PRAGMA busy_timeout=5000;")
        # Enable foreign keys
        await _db_connection.execute("PRAGMA foreign_keys=ON;")
    return _db_connection


async def close_db() -> None:
    """Close the module-level connection, if open."""
    global _db_connection
    if _db_connection is not None:
        await _db_connection.close()
        _db_connection = None


# ── init ────────────────────────────────────────────────────────────────────


async def init_db(db_path: str = "sentri_ot.db") -> None:
    """
    Initialise the database, creating tables if they do not exist.

    Call once at application startup.
    """
    global _db_path
    _db_path = db_path
    conn = await get_connection()
    await conn.execute(CREATE_SCANS_TABLE)
    await conn.execute(CREATE_ASSETS_TABLE)
    await conn.execute(CREATE_ALERTS_TABLE)
    await conn.execute(CREATE_COMPLIANCE_TABLE)
    for idx_sql in CREATE_INDEXES:
        await conn.execute(idx_sql)
    await conn.commit()


# ── scans ───────────────────────────────────────────────────────────────────


async def save_scan(scan_data: dict[str, Any]) -> str:
    """
    Persist a full scan result (scan + assets + alerts + compliance).

    Returns the scan ID.
    """
    conn = await get_connection()
    scan_id = scan_data.get("scan_id", _uuid4())
    generated_at = scan_data.get("generated_at", _now_iso())
    scan_type = scan_data.get("scan_type", "passive")
    assets = scan_data.get("assets", [])
    alerts = scan_data.get("alerts", [])
    compliance = scan_data.get("compliance", {})
    summary = scan_data.get("summary", {})

    device_count = len(assets)
    summary_json = json.dumps(summary)
    status = "complete"

    await conn.execute(
        "INSERT OR REPLACE INTO scans (id, generated_at, scan_type, device_count, status, summary_json) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (scan_id, generated_at, scan_type, device_count, status, summary_json),
    )

    for asset in assets:
        await conn.execute(
            "INSERT OR REPLACE INTO assets "
            "(id, scan_id, hostname, ip_address, device_type, protocol, protocol_version, "
            " vendor_id, vendor_name, firmware_version, segmentation_zone, criticality, "
            " risk_level, auth_method, ports_json, vulnerabilities_json, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                asset.get("id", _uuid4()),
                scan_id,
                asset.get("hostname", ""),
                asset.get("ip", ""),
                asset.get("device_type", asset.get("type", "")),
                asset.get("protocol", ""),
                asset.get("protocol_version", ""),
                asset.get("vendor_id", 0),
                asset.get("vendor_name", ""),
                asset.get("firmware_version", ""),
                asset.get("segmentation_zone", ""),
                asset.get("criticality", "Medium"),
                asset.get("risk_level", ""),
                asset.get("auth_method", asset.get("authentication", "")),
                json.dumps(asset.get("ports", [])),
                json.dumps(asset.get("vulnerabilities", [])),
                asset.get("first_seen", generated_at),
                asset.get("last_seen", generated_at),
            ),
        )

    for alert in alerts:
        await conn.execute(
            "INSERT OR REPLACE INTO alerts (id, scan_id, timestamp, severity, title, message, asset_id, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                alert.get("id", _uuid4()),
                scan_id,
                alert.get("timestamp", generated_at),
                alert.get("severity", "Info"),
                alert.get("title", ""),
                alert.get("message", ""),
                alert.get("asset_id", None),
                alert.get("status", "Active"),
            ),
        )

    frameworks_data = compliance.get("frameworks", {})
    for framework_name, fw_data in frameworks_data.items():
        report_id = _uuid4()
        if isinstance(fw_data, dict):
            ctrl_list = fw_data.get("controls", [])
            cat_scores = fw_data.get("category_scores", {})
            fw_score = fw_data.get("score", 0)
        else:
            ctrl_list = fw_data if isinstance(fw_data, list) else []
            cat_scores = {}
            fw_score = compliance.get("score", 0)
        report_json = json.dumps({
            "score": fw_score,
            "rating": compliance.get("rating", ""),
            "controls": ctrl_list,
            "category_scores": cat_scores,
        })
        await conn.execute(
            "INSERT OR REPLACE INTO compliance_reports "
            "(id, scan_id, generated_at, framework, score, rating, report_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                report_id,
                scan_id,
                compliance.get("generated_at", generated_at),
                framework_name,
                compliance.get("score", 0),
                compliance.get("rating", ""),
                report_json,
            ),
        )

    await conn.commit()
    return scan_id


async def get_latest_scan() -> Optional[dict[str, Any]]:
    """Return the most recent complete scan with its assets."""
    conn = await get_connection()
    cursor = await conn.execute(
        "SELECT * FROM scans WHERE status = 'complete' ORDER BY generated_at DESC LIMIT 1"
    )
    row = await cursor.fetchone()
    if row is None:
        return None

    scan_id = row["id"]
    scan = _row_to_dict(row)
    scan["summary"] = json.loads(scan.get("summary_json", "{}"))
    scan.pop("summary_json", None)

    cur2 = await conn.execute(
        "SELECT * FROM assets WHERE scan_id = ? ORDER BY last_seen DESC", (scan_id,)
    )
    scan["assets"] = []
    for r in await cur2.fetchall():
        asset = _row_to_dict(r)
        asset["ports"] = json.loads(asset.pop("ports_json", "[]"))
        asset["vulnerabilities"] = json.loads(asset.pop("vulnerabilities_json", "[]"))
        scan["assets"].append(asset)

    cur3 = await conn.execute(
        "SELECT * FROM alerts WHERE scan_id = ? AND status != 'Resolved' ORDER BY timestamp DESC", (scan_id,)
    )
    scan["alerts"] = [_row_to_dict(r) for r in await cur3.fetchall()]

    cur4 = await conn.execute(
        "SELECT * FROM compliance_reports WHERE scan_id = ? ORDER BY generated_at DESC", (scan_id,)
    )
    rows4 = await cur4.fetchall()
    frameworks: dict[str, dict] = {}
    score = 0
    rating = ""
    for r in rows4:
        cr = _row_to_dict(r)
        report_data = json.loads(cr.get("report_json", "{}"))
        fw_name = cr["framework"]
        frameworks[fw_name] = {
            "controls": report_data.get("controls", []),
            "category_scores": report_data.get("category_scores", {}),
            "score": report_data.get("score", 0),
        }
        score = max(score, report_data.get("score", 0))
        if not rating and report_data.get("rating"):
            rating = report_data["rating"]
    scan["compliance"] = {
        "score": score,
        "rating": rating,
        "frameworks": frameworks,
        "generated_at": rows4[0]["generated_at"] if rows4 else _now_iso(),
    }
    # Regenerate critical findings and strengths from stored controls
    try:
        from backend.compliance_framework import _find_critical_findings, _find_strengths
        all_desc = []
        all_iec = []
        for fw_name, fw_data in frameworks.items():
            ctrls = fw_data.get("controls", [])
            if fw_name == "DESC":
                all_desc.extend(ctrls)
            else:
                all_iec.extend(ctrls)
        scan["compliance"]["critical_findings"] = _find_critical_findings(all_desc, all_iec)
        scan["compliance"]["strengths"] = _find_strengths(all_desc, all_iec)
    except (ImportError, Exception):
        scan["compliance"]["critical_findings"] = []
        scan["compliance"]["strengths"] = []

    scan["scan_id"] = scan.pop("id")
    return scan


async def get_scan_history(limit: int = 20) -> list[dict[str, Any]]:
    """Return a list of scan summaries for the history view."""
    conn = await get_connection()
    cursor = await conn.execute(
        "SELECT id, generated_at, scan_type, device_count, status, summary_json "
        "FROM scans ORDER BY generated_at DESC LIMIT ?",
        (limit,),
    )
    result = []
    for row in await cursor.fetchall():
        entry = _row_to_dict(row)
        s = json.loads(entry.pop("summary_json", "{}"))
        entry["total_assets"] = entry.pop("device_count", s.get("total_assets", 0))
        entry["compliance_score"] = s.get("compliance_score", 0)
        entry["critical_vulnerabilities"] = s.get("critical_vulnerabilities", 0)
        entry["scan_id"] = entry.pop("id")
        result.append(entry)
    return result


async def update_scan_status(scan_id: str, status: str, summary: dict | None = None) -> None:
    """Update the status (and optionally summary) of an existing scan."""
    conn = await get_connection()
    if summary is not None:
        await conn.execute(
            "UPDATE scans SET status = ?, summary_json = ? WHERE id = ?",
            (status, json.dumps(summary), scan_id),
        )
    else:
        await conn.execute("UPDATE scans SET status = ? WHERE id = ?", (status, scan_id))
    await conn.commit()


# ── assets ──────────────────────────────────────────────────────────────────


async def get_assets(
    filters: dict[str, Any] | None = None,
    page: int = 1,
    per_page: int = 100,
) -> dict[str, Any]:
    """Paginated asset query with optional filters.

    Supported filter keys: device_type, protocol, segmentation_zone, criticality, risk_level, search.
    """
    conn = await get_connection()
    where_clauses: list[str] = []
    params: list[Any] = []

    if filters:
        for key in ("device_type", "protocol", "segmentation_zone", "criticality", "risk_level"):
            val = filters.get(key)
            if val:
                where_clauses.append(f"{key} = ?")
                params.append(val)
        search = filters.get("search", "").strip()
        if search:
            where_clauses.append("(hostname LIKE ? OR ip_address LIKE ? OR vendor_name LIKE ?)")
            like = f"%{search}%"
            params.extend([like, like, like])

    where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"
    offset = (page - 1) * per_page

    count_cursor = await conn.execute(
        f"SELECT COUNT(*) as cnt FROM assets WHERE {where_sql}", params
    )
    count_row = await count_cursor.fetchone()
    total = count_row["cnt"] if count_row else 0

    cursor = await conn.execute(
        f"SELECT * FROM assets WHERE {where_sql} ORDER BY last_seen DESC LIMIT ? OFFSET ?",
        [*params, per_page, offset],
    )
    items = []
    for r in await cursor.fetchall():
        asset = _row_to_dict(r)
        asset["ports"] = json.loads(asset.pop("ports_json", "[]"))
        asset["vulnerabilities"] = json.loads(asset.pop("vulnerabilities_json", "[]"))
        items.append(asset)

    return {
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": max(1, (total + per_page - 1) // per_page),
    }


async def get_asset_by_id(asset_id: str) -> Optional[dict[str, Any]]:
    """Return a single asset with full details."""
    conn = await get_connection()
    cursor = await conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,))
    row = await cursor.fetchone()
    if row is None:
        return None
    asset = _row_to_dict(row)
    asset["ports"] = json.loads(asset.pop("ports_json", "[]"))
    asset["vulnerabilities"] = json.loads(asset.pop("vulnerabilities_json", "[]"))
    return asset


# ── alerts ──────────────────────────────────────────────────────────────────


async def get_alerts(
    filters: dict[str, Any] | None = None,
    page: int = 1,
    per_page: int = 50,
) -> dict[str, Any]:
    """Paginated alerts with optional filtering by severity / status / asset_id."""
    conn = await get_connection()
    where_clauses: list[str] = []
    params: list[Any] = []

    if filters:
        for key in ("severity", "status", "asset_id"):
            val = filters.get(key)
            if val:
                where_clauses.append(f"{key} = ?")
                params.append(val)

    where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"
    offset = (page - 1) * per_page

    count_cursor = await conn.execute(
        f"SELECT COUNT(*) as cnt FROM alerts WHERE {where_sql}", params
    )
    count_row = await count_cursor.fetchone()
    total = count_row["cnt"] if count_row else 0

    cursor = await conn.execute(
        f"SELECT * FROM alerts WHERE {where_sql} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        [*params, per_page, offset],
    )
    rows = await cursor.fetchall()

    return {
        "items": [_row_to_dict(r) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": max(1, (total + per_page - 1) // per_page),
    }


async def acknowledge_alert(alert_id: str, note: str = "") -> bool:
    """Mark an alert as Acknowledged. Returns True if found."""
    conn = await get_connection()
    cursor = await conn.execute(
        "UPDATE alerts SET status = 'Acknowledged' WHERE id = ? AND status = 'Active'",
        (alert_id,),
    )
    await conn.commit()
    return cursor.rowcount > 0


async def resolve_alert(alert_id: str) -> bool:
    """Mark an alert as Resolved. Returns True if found."""
    conn = await get_connection()
    cursor = await conn.execute(
        "UPDATE alerts SET status = 'Resolved' WHERE id = ?", (alert_id,)
    )
    await conn.commit()
    return cursor.rowcount > 0


# ── compliance ──────────────────────────────────────────────────────────────


async def get_compliance_report(scan_id: str | None = None) -> Optional[dict[str, Any]]:
    """Return the latest compliance report, optionally for a specific scan."""
    conn = await get_connection()
    if scan_id:
        cursor = await conn.execute(
            "SELECT * FROM compliance_reports WHERE scan_id = ? ORDER BY generated_at DESC LIMIT 1",
            (scan_id,),
        )
    else:
        cursor = await conn.execute(
            "SELECT * FROM compliance_reports ORDER BY generated_at DESC LIMIT 1"
        )
    row = await cursor.fetchone()
    if row is None:
        return None
    cr = _row_to_dict(row)
    cr["report"] = json.loads(cr.pop("report_json", "{}"))
    return cr


async def get_latest_compliance_summary() -> Optional[dict[str, Any]]:
    """Return aggregate compliance info from the latest scan."""
    scan = await get_latest_scan()
    if scan is None:
        return None
    return scan.get("compliance", {})


# ── pruning ─────────────────────────────────────────────────────────────────


async def prune_old_data(max_scans: int = 100) -> int:
    """Remove old scans, keeping only the most recent *max_scans*."""
    conn = await get_connection()
    cursor = await conn.execute(
        "SELECT id FROM scans ORDER BY generated_at DESC LIMIT -1 OFFSET ?",
        (max_scans,),
    )
    old_ids = [row["id"] for row in await cursor.fetchall()]
    if not old_ids:
        return 0

    placeholders = ",".join("?" for _ in old_ids)
    for table in ("alerts", "compliance_reports", "assets"):
        await conn.execute(f"DELETE FROM {table} WHERE scan_id IN ({placeholders})", old_ids)
    await conn.execute(f"DELETE FROM scans WHERE id IN ({placeholders})", old_ids)
    await conn.commit()
    return len(old_ids)


# ── summary stats ───────────────────────────────────────────────────────────


async def get_summary_stats() -> dict[str, Any]:
    """Aggregated statistics for the dashboard."""
    conn = await get_connection()

    cur = await conn.execute("SELECT COUNT(*) as cnt FROM scans")
    total_scans = (await cur.fetchone())["cnt"]

    cur = await conn.execute("SELECT COUNT(*) as cnt FROM assets")
    total_assets = (await cur.fetchone())["cnt"]

    cur = await conn.execute("SELECT DISTINCT protocol FROM assets WHERE protocol != ''")
    protocols = [r["protocol"] for r in await cur.fetchall()]

    cur = await conn.execute(
        "SELECT severity, COUNT(*) as cnt FROM alerts WHERE status = 'Active' GROUP BY severity"
    )
    active_alerts_by_severity = {r["severity"]: r["cnt"] for r in await cur.fetchall()}

    cur = await conn.execute("SELECT COUNT(*) as cnt FROM assets WHERE criticality = 'Critical'")
    critical_assets = (await cur.fetchone())["cnt"]

    latest = await get_latest_scan()

    return {
        "total_scans": total_scans,
        "total_assets": total_assets,
        "critical_assets": critical_assets,
        "protocols": protocols,
        "active_alerts_by_severity": active_alerts_by_severity,
        "latest_summary": latest.get("summary", {}) if latest else {},
    }


# ── helpers ─────────────────────────────────────────────────────────────────


def _row_to_dict(row: aiosqlite.Row) -> dict[str, Any]:
    return dict(row) if row else {}
