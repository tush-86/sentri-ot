"""Professional PDF report generation for Sentri OT.

Generates DESC and IEC 62443 compliance reports with executive summary,
asset overview, control evaluation tables, severity charts, and findings.
"""
from __future__ import annotations

import os
from datetime import datetime
from io import BytesIO
from typing import Any

from fpdf import FPDF, XPos, YPos


# ── colour palette ─────────────────────────────────────────────────────────

SENTRI_DARK = (15, 23, 42)
SENTRI_WHITE = (248, 250, 252)
SENTRI_GREEN = (34, 197, 94)
SENTRI_RED = (239, 68, 68)
SENTRI_AMBER = (245, 158, 11)
SENTRI_CYAN = (6, 182, 212)
SENTRI_SLATE = (100, 116, 139)
SENTRI_SLATE_LIGHT = (148, 163, 184)
SECTION_BG = (30, 41, 59)
ROW_ALT = (24, 33, 52)

SEVERITY_COLORS = {
    "Critical": (239, 68, 68),
    "High": (249, 115, 22),
    "Medium": (245, 158, 11),
    "Low": (34, 197, 94),
}

STATUS_COLORS = {
    "PASS": (34, 197, 94),
    "FAIL": (239, 68, 68),
    "PARTIAL": (245, 158, 11),
    "NOT_OBSERVABLE": (100, 116, 139),
}


def _safe(value: Any) -> str:
    """Encode safely for latin-1 PDF."""
    if value is None:
        return ""
    return str(value).encode("latin-1", "replace").decode("latin-1")


class SentriReport(FPDF):
    """Professional Sentri OT PDF report."""

    def header(self) -> None:
        self.set_fill_color(*SENTRI_DARK)
        self.rect(0, 0, 210, 22, "F")
        # Title
        self.set_text_color(*SENTRI_GREEN)
        self.set_font("Helvetica", "B", 14)
        self.set_y(5)
        self.cell(0, 7, "Sentri OT  -  BMS Security & Compliance Report", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        # Thin green accent line
        self.set_draw_color(*SENTRI_GREEN)
        self.set_line_width(0.4)
        self.line(10, 22, 200, 22)
        self.ln(4)

    def footer(self) -> None:
        self.set_y(-15)
        self.set_text_color(*SENTRI_SLATE)
        self.set_font("Helvetica", "I", 7)
        self.cell(0, 10, f"Confidential  |  Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}  |  Page {self.page_no()}/{{nb}}", align="C")

    def section_title(self, title: str, color=SENTRI_GREEN) -> None:
        self.set_fill_color(*SECTION_BG)
        self.set_text_color(*color)
        self.set_font("Helvetica", "B", 11)
        self.cell(0, 8, f"  {title}", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(3)

    def kv_row(self, label: str, value: Any, label_w: int = 60) -> None:
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*SENTRI_SLATE_LIGHT)
        self.cell(label_w, 6, label, new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*SENTRI_WHITE)
        self.cell(0, 6, _safe(value), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def draw_bar_chart(self, data: list[tuple[str, int, tuple]], max_val: int | None = None) -> None:
        """Draw a horizontal bar chart with labels and values."""
        if not data:
            return
        if max_val is None:
            max_val = max(v for _, v, _ in data) or 1
        bar_max_w = 110
        left_label_w = 50
        right_val_w = 20
        for label, value, colour in data:
            bar_w = (value / max_val) * bar_max_w
            x_start = self.get_x() + left_label_w
            # Label
            self.set_font("Helvetica", "", 8)
            self.set_text_color(*SENTRI_WHITE)
            self.cell(left_label_w, 5, _safe(label), new_x=XPos.RIGHT, new_y=YPos.TOP)
            # Bar
            self.set_fill_color(*colour)
            self.rect(x_start, self.get_y() + 0.5, bar_w, 4, "F")
            # Value
            self.set_xy(x_start + bar_max_w + 2, self.get_y())
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(*colour)
            self.cell(right_val_w, 5, str(value), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.ln(0.5)

    def compliance_gauge(self, score: int | float, rating: str) -> None:
        """Draw a simple textual score gauge."""
        self.set_font("Helvetica", "B", 36)
        if score >= 85:
            self.set_text_color(*SENTRI_GREEN)
        elif score >= 65:
            self.set_text_color(*SENTRI_AMBER)
        else:
            self.set_text_color(*SENTRI_RED)
        self.cell(30, 14, f"{score:.0f}", new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_font("Helvetica", "", 14)
        self.set_text_color(*SENTRI_SLATE)
        self.cell(10, 14, "/100", new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_x(self.get_x() + 8)
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(*SENTRI_WHITE)
        status_col = SENTRI_GREEN if score >= 85 else SENTRI_AMBER if score >= 65 else SENTRI_RED
        self.set_text_color(*status_col)
        self.cell(50, 14, f"[ {rating} ]", new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def generate_pdf_report(payload: dict[str, Any]) -> bytes:
    """Generate a professional compliance PDF report."""
    summary = payload.get("summary", {})
    compliance = payload.get("compliance", {})
    assets = payload.get("assets", [])
    alerts = payload.get("alerts", [])
    scan_id = payload.get("scan_id", "N/A")[:12]
    gen_time = payload.get("generated_at", datetime.utcnow().isoformat())

    pdf = SentriReport()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.set_margins(12, 22, 12)
    pdf.add_page()

    # ═══════════════════════════════════════════════════════════════════════
    # PAGE 1: EXECUTIVE SUMMARY
    # ═══════════════════════════════════════════════════════════════════════
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*SENTRI_SLATE)
    pdf.cell(0, 5, f"Scan: {scan_id}  |  Generated: {gen_time[:19].replace('T', ' ')} UTC", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)

    pdf.section_title("Executive Summary", SENTRI_GREEN)

    # Score gauge
    score = compliance.get("score", 0)
    rating = compliance.get("rating", "N/A")
    pdf.compliance_gauge(score, rating)
    pdf.ln(3)

    # Key metrics in a 2-column layout
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*SENTRI_SLATE_LIGHT)
    pdf.cell(90, 6, "Metric", new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.cell(0, 6, "Value", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_draw_color(*SENTRI_SLATE)
    pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + 176, pdf.get_y())
    pdf.ln(1)

    rows = [
        ("Total Assets", summary.get("total_assets", 0)),
        ("Total Vulnerabilities", summary.get("total_vulnerabilities", 0)),
        ("Critical Vulnerabilities", summary.get("critical_vulnerabilities", 0)),
        ("BACnet Objects Discovered", summary.get("total_bacnet_objects", 0)),
        ("Network Zones Detected", len(summary.get("zones_discovered", {}))),
        ("Compliance Score", f"{score:.1f}% ({rating})"),
        ("DESC Framework", f"{compliance.get('frameworks', {}).get('DESC', {}).get('score', 0):.0f}%"),
        ("IEC 62443 Framework", f"{compliance.get('frameworks', {}).get('IEC 62443', {}).get('score', 0):.0f}%"),
    ]
    for label, value in rows:
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*SENTRI_SLATE_LIGHT)
        pdf.cell(90, 6, _safe(label), new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*SENTRI_WHITE)
        pdf.cell(0, 6, _safe(value), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)

    # ═══════════════════════════════════════════════════════════════════════
    # ASSET & PROTOCOL DISTRIBUTION
    # ═══════════════════════════════════════════════════════════════════════
    pdf.section_title("Asset & Protocol Distribution", SENTRI_CYAN)

    # Protocol bar chart
    protocols = summary.get("protocols_discovered", {})
    if protocols:
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*SENTRI_CYAN)
        pdf.cell(0, 5, "Protocols Discovered", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        proto_colors = {
            "BACnet": SENTRI_GREEN, "Modbus": SENTRI_AMBER, "LoRaWAN": SENTRI_CYAN,
            "OPC-UA": (139, 92, 246), "HTTPS": SENTRI_SLATE_LIGHT
        }
        max_proto = max(protocols.values()) if protocols else 1
        bar_data = [(p, c, proto_colors.get(p, SENTRI_SLATE_LIGHT)) for p, c in sorted(protocols.items(), key=lambda x: -x[1])]
        pdf.draw_bar_chart(bar_data, max_proto)
        pdf.ln(3)

    # Device types
    device_types = summary.get("device_types", {})
    if device_types:
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*SENTRI_CYAN)
        pdf.cell(0, 5, "Device Types", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        max_dev = max(device_types.values()) if device_types else 1
        dev_colors = {
            "BMS Controller": SENTRI_GREEN, "VAV Controller": SENTRI_CYAN, "AHU Controller": SENTRI_AMBER,
            "PLC": SENTRI_RED, "Gateway": (139, 92, 246), "Sensor": SENTRI_SLATE_LIGHT,
            "Thermostat": (236, 72, 153), "Engineering Workstation": SENTRI_AMBER,
            "Historian": (168, 85, 247), "LoRaWAN Gateway": SENTRI_CYAN,
            "LoRaWAN Sensor": (34, 211, 238),
        }
        pdf.draw_bar_chart(
            [(dt, c, dev_colors.get(dt, SENTRI_SLATE_LIGHT)) for dt, c in sorted(device_types.items(), key=lambda x: -x[1])],
            max_dev,
        )
        pdf.ln(2)

    # ═══════════════════════════════════════════════════════════════════════
    # VULNERABILITY OVERVIEW
    # ═══════════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("Vulnerability Overview", SENTRI_RED)

    vulns_by_sev = summary.get("vulnerabilities_by_severity", {})
    sev_order = ["Critical", "High", "Medium", "Low"]
    sev_data = [(s, vulns_by_sev.get(s, 0), SEVERITY_COLORS.get(s, SENTRI_SLATE_LIGHT)) for s in sev_order if vulns_by_sev.get(s, 0) > 0]
    if sev_data:
        pdf.draw_bar_chart(sev_data, max(v for _, v, _ in sev_data) if sev_data else 1)
    pdf.ln(4)

    # Zone distribution
    zones = summary.get("zones_discovered", {})
    if zones:
        pdf.section_title("Zone Distribution", SENTRI_AMBER)
        zone_colors = {"Zone 0": SENTRI_RED, "Zone 1": SENTRI_GREEN, "Zone 2": SENTRI_AMBER,
                       "Zone 3": SENTRI_CYAN, "DMZ": (139, 92, 246)}
        pdf.draw_bar_chart(
            [(z, c, zone_colors.get(z, SENTRI_SLATE_LIGHT)) for z, c in sorted(zones.items(), key=lambda x: -x[1])],
            max(zones.values()) if zones else 1,
        )
        pdf.ln(2)

    # Top vendors
    vendors = summary.get("top_vendors", {})
    if vendors:
        pdf.section_title("Top Device Vendors", SENTRI_CYAN)
        pdf.draw_bar_chart(
            [(v, c, SENTRI_SLATE_LIGHT) for v, c in list(sorted(vendors.items(), key=lambda x: -x[1]))[:10]],
            max(vendors.values()) if vendors else 1,
        )
        pdf.ln(2)

    # ═══════════════════════════════════════════════════════════════════════
    # COMPLIANCE CONTROLS (DESC)
    # ═══════════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("Compliance Controls - DESC (Dubai ICS/OT Standard)", SENTRI_GREEN)
    _render_compliance_section(pdf, compliance, "DESC")

    # ═══════════════════════════════════════════════════════════════════════
    # COMPLIANCE CONTROLS (IEC 62443)
    # ═══════════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("Compliance Controls - IEC 62443-3-3 SR", SENTRI_GREEN)
    _render_compliance_section(pdf, compliance, "IEC 62443")

    # ═══════════════════════════════════════════════════════════════════════
    # CRITICAL FINDINGS & ALERTS
    # ═══════════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title("Critical Findings & Alerts", SENTRI_RED)

    critical_findings = compliance.get("critical_findings", [])
    strengths = compliance.get("strengths", [])

    if critical_findings:
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*SENTRI_RED)
        pdf.cell(0, 6, f"Critical Findings ({len(critical_findings)})", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(1)
        for finding in critical_findings[:8]:
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(*SENTRI_RED)
            pdf.cell(5, 5, _safe("!"), new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.cell(0, 5, _safe(finding[:120]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(0.5)
    else:
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*SENTRI_GREEN)
        pdf.cell(0, 6, "No critical findings from network monitoring.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Active alerts
    pdf.ln(3)
    pdf.section_title("Active Alerts", SENTRI_AMBER)
    if alerts:
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*SENTRI_SLATE_LIGHT)
        pdf.cell(40, 5, "Severity", new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.cell(0, 5, "Alert", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + 176, pdf.get_y())
        pdf.ln(1)
        for alert in alerts[:15]:
            sev = alert.get("severity", "Info")
            colour = SEVERITY_COLORS.get(sev, SENTRI_SLATE_LIGHT)
            pdf.set_text_color(*colour)
            pdf.set_font("Helvetica", "B", 7)
            pdf.cell(40, 5, _safe(sev), new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.set_text_color(*SENTRI_WHITE)
            pdf.set_font("Helvetica", "", 7)
            pdf.cell(0, 5, _safe(alert.get("title", "")), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    else:
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*SENTRI_GREEN)
        pdf.cell(0, 6, "No active alerts.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Strengths
    pdf.ln(4)
    if strengths:
        pdf.section_title("Compliance Strengths", SENTRI_GREEN)
        for strength in strengths[:5]:
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(*SENTRI_GREEN)
            pdf.cell(5, 5, _safe("+"), new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.cell(0, 5, _safe(strength[:120]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(0.5)

    # ═══════════════════════════════════════════════════════════════════════
    # HIGH-RISK ASSETS
    # ═══════════════════════════════════════════════════════════════════════
    if assets:
        pdf.add_page()
        pdf.section_title("High-Risk Asset Detail", SENTRI_RED)
        high_risk = [a for a in assets if a.get("risk_level") in ("Critical", "High")][:10]
        for asset in high_risk:
            hostname = asset.get("hostname", "unknown")
            ip = asset.get("ip", asset.get("ip_address", ""))
            typ = asset.get("device_type", "Unknown")
            risk = asset.get("risk_level", "Low")
            vulns = asset.get("vulnerabilities", [])
            colour = SEVERITY_COLORS.get(risk, SENTRI_SLATE_LIGHT)

            if isinstance(colour, tuple):
                pdf.set_fill_color(*colour)
            else:
                pdf.set_fill_color(239, 68, 68)
            pdf.set_text_color(*SENTRI_WHITE)
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(0, 6, _safe(f"  {hostname} ({ip})  |  {typ}  |  Risk: {risk}"), fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            for v in vulns[:3]:
                pdf.set_font("Helvetica", "", 7)
                v_sev = v.get("severity", "Low")
                v_colour = SEVERITY_COLORS.get(v_sev, SENTRI_SLATE_LIGHT)
                pdf.set_text_color(*v_colour)
                pdf.cell(5, 4, _safe("-"), new_x=XPos.RIGHT, new_y=YPos.TOP)
                pdf.cell(0, 4, _safe(v.get("title", "")), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(2)

    # Flatten output
    output = pdf.output(dest="S")
    if isinstance(output, str):
        return output.encode("latin-1")
    if isinstance(output, bytearray):
        return bytes(output)
    buffer = BytesIO()
    buffer.write(output)
    return buffer.getvalue()


def _render_compliance_section(pdf: SentriReport, compliance: dict, fw_name: str) -> None:
    """Render a framework's compliance controls by category."""
    fw_data = compliance.get("frameworks", {}).get(fw_name, {})
    if isinstance(fw_data, list):
        # Old format - treat as flat list
        controls = fw_data
        categories = [{"name": fw_name, "score": 0, "passed": 0, "total": len(controls), "controls": controls}]
    else:
        categories = fw_data.get("categories", [])
        if not categories:
            # Fall back to controls
            controls = fw_data.get("controls", [])
            if controls:
                categories = [{"name": fw_name, "score": fw_data.get("score", 0), "passed": 0, "total": len(controls), "controls": controls}]

    if not categories:
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*SENTRI_SLATE)
        pdf.cell(0, 6, "No compliance data available for this framework.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        return

    # Summary bar
    total_passed = sum(c.get("passed", 0) for c in categories)
    total_ctrls = sum(c.get("total", len(c.get("controls", []))) for c in categories)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*SENTRI_SLATE_LIGHT)
    pdf.cell(0, 5, f"Controls: {total_passed}/{total_ctrls} passed", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)

    for cat in categories:
        name = cat.get("name", "General")
        cat_score = cat.get("score", 0)
        controls = cat.get("controls", [])
        passed = sum(1 for c in controls if c.get("status") == "PASS")
        failed = sum(1 for c in controls if c.get("status") == "FAIL")
        partial = sum(1 for c in controls if c.get("status") == "PARTIAL")
        not_obs = sum(1 for c in controls if c.get("status") == "NOT_OBSERVABLE")
        total = len(controls)

        if total == 0:
            continue

        # Category header
        pdf.set_fill_color(*SECTION_BG)
        pdf.set_text_color(*SENTRI_WHITE)
        pdf.set_font("Helvetica", "B", 8)
        score_col = SENTRI_GREEN if cat_score >= 80 else SENTRI_AMBER if cat_score >= 50 else SENTRI_RED
        pdf.set_text_color(*score_col)
        pdf.cell(0, 6, _safe(f"  {name}  [{cat_score:.0f}%]"), fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # Status summary
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(*SENTRI_SLATE_LIGHT)
        status_parts = []
        if passed:
            status_parts.append(f"\x1b[32m{passed} PASS\x1b[0m")
        if failed:
            status_parts.append(f"{failed} FAIL")
        if partial:
            status_parts.append(f"{partial} PARTIAL")
        if not_obs:
            status_parts.append(f"{not_obs} N/O")
        pdf.cell(0, 4, _safe(f"  {passed} PASS  |  {failed} FAIL  |  {partial} PARTIAL  |  {not_obs} N/O"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # Controls
        for ctrl in controls[:8]:
            ctrl_id = ctrl.get("id", "")
            status = ctrl.get("status", "N/A")
            req = ctrl.get("requirement", ctrl.get("title", ""))
            s_colour = STATUS_COLORS.get(status, SENTRI_SLATE)
            pdf.set_text_color(*s_colour)
            pdf.set_font("Helvetica", "B", 7)
            pdf.cell(0, 4, _safe(f"  [{status}] {ctrl_id}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_text_color(*SENTRI_WHITE)
            pdf.set_font("Helvetica", "", 7)
            pdf.cell(0, 4, _safe(f"    {req[:120]}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            # Gaps
            gaps = ctrl.get("gaps", [])
            if gaps:
                pdf.set_text_color(*SENTRI_AMBER)
                for gap in gaps[:2]:
                    pdf.cell(0, 3, _safe(f"      Gap: {str(gap)[:100]}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(0.5)

        if len(controls) > 8:
            pdf.set_font("Helvetica", "I", 7)
            pdf.set_text_color(*SENTRI_SLATE)
            pdf.cell(0, 4, _safe(f"  ... and {len(controls) - 8} more controls in this category"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.ln(1.5)
