"""Sentri OT — Large-scale BMS simulation engine.

Generates realistic BACnet/BMS synthetic data for demo and testing.
Updated to match the new asset schema with BACnet device_id, vendor_id,
vendor_name, object_count, security_status, etc.
"""

from __future__ import annotations

import random
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from backend.compliance_framework import evaluate_compliance

# ── vendor data ─────────────────────────────────────────────────────────────

BACNET_VENDORS: dict[int, str] = {
    2: "Siemens",
    5: "Honeywell",
    7: "Schneider Electric",
    8: "Trane",
    12: "Johnson Controls",
    14: "Carrier",
    15: "Delta Controls",
    16: "Mitsubishi Electric",
    20: "Daikin",
    26: "Alerton",
    27: "Distech Controls",
    28: "KMC Controls",
    37: "Trend Controls",
    56: "Tridium",
    60: "CONTEC",
    155: "Automated Logic",
    245: "Siemens (Building Technologies)",
    268: "Honeywell (Tridium)",
    279: "Loytec",
    300: "Chipkin Automation Systems",
    366: "Contemporary Controls",
    380: "WAGO",
    477: "Beckhoff Automation",
    522: "Moxa",
    538: "Phoenix Contact",
}

ZONES = ["Zone 0", "Zone 1", "Zone 2", "Zone 3", "DMZ"]

# ── vulnerability catalog ────────────────────────────────────────────────────

VULNERABILITY_DETAILS = [
    {
        "id": "SENTRI-PL-001",
        "title": "Default vendor credentials exposed",
        "severity": "Critical",
        "desc_control": "IAM-02",
        "isa_iec_control": "IEC 62443-3-3 SR 1.1",
        "recommendation": "Rotate credentials and enforce unique, vaulted service accounts.",
        "standards": ["DESC", "IEC 62443"],
        "protocols": ["Modbus", "BACnet", "LoRaWAN", "OPC-UA"],
    },
    {
        "id": "SENTRI-PL-002",
        "title": "Insecure plaintext industrial protocol",
        "severity": "High",
        "desc_control": "NWS-04",
        "isa_iec_control": "IEC 62443-3-3 SR 2.1",
        "recommendation": "Segment traffic and tunnel management flows over authenticated channels.",
        "standards": ["DESC", "IEC 62443"],
        "protocols": ["Modbus", "BACnet"],
    },
    {
        "id": "SENTRI-PL-003",
        "title": "Unsupported firmware version",
        "severity": "High",
        "desc_control": "AST-03",
        "isa_iec_control": "IEC 62443-3-3 SR 3.2",
        "recommendation": "Upgrade firmware through an approved OT maintenance window.",
        "standards": ["DESC", "IEC 62443"],
        "protocols": ["Modbus", "BACnet", "LoRaWAN", "OPC-UA"],
    },
    {
        "id": "SENTRI-PL-004",
        "title": "Missing network segmentation tag",
        "severity": "Medium",
        "desc_control": "NWS-01",
        "isa_iec_control": "IEC 62443-3-3 SR 2.8",
        "recommendation": "Move device into the appropriate Purdue-model security zone.",
        "standards": ["DESC", "IEC 62443"],
        "protocols": ["Modbus", "BACnet", "HTTPS", "OPC-UA"],
    },
    {
        "id": "SENTRI-PL-005",
        "title": "Telemetry logging not forwarded to SIEM",
        "severity": "Medium",
        "desc_control": "LOG-02",
        "isa_iec_control": "IEC 62443-3-3 DI 4.1",
        "recommendation": "Forward OT security events to a monitored log destination.",
        "standards": ["DESC", "IEC 62443"],
        "protocols": ["Modbus", "BACnet", "HTTPS", "OPC-UA"],
    },
    {
        "id": "SENTRI-PL-006",
        "title": "No recent verified backup",
        "severity": "Low",
        "desc_control": "BCM-01",
        "isa_iec_control": "IEC 62443-2-1 SL 2",
        "recommendation": "Validate backup integrity and recovery procedures.",
        "standards": ["DESC", "IEC 62443"],
        "protocols": ["Modbus", "BACnet", "HTTPS", "OPC-UA"],
    },
]

SEVERITY_WEIGHT = {"Critical": 12, "High": 8, "Medium": 4, "Low": 1}
RISK_BY_SCORE = [(16, "Critical"), (9, "High"), (4, "Medium"), (0, "Low")]


def _risk_level(vulnerabilities: list[dict]) -> str:
    score = sum(SEVERITY_WEIGHT.get(v["severity"], 0) for v in vulnerabilities)
    for threshold, label in RISK_BY_SCORE:
        if score >= threshold:
            return label
    return "Low"


def _device_vulnerabilities(protocol: str, criticality: str) -> list[dict]:
    applicable = [v for v in VULNERABILITY_DETAILS if protocol in v["protocols"]]
    random.shuffle(applicable)
    if criticality == "Critical":
        count = random.choices([1, 2, 3], weights=[2, 4, 4], k=1)[0]
    elif criticality == "High":
        count = random.choices([0, 1, 2], weights=[1, 4, 4], k=1)[0]
    else:
        count = random.choices([0, 1], weights=[2, 3], k=1)[0]
    count = min(max(1, count), len(applicable))
    selected = applicable[:count]
    return [
        {
            **item,
            "cvss": round(random.uniform(4.0, 9.4), 1),
            "description": item["recommendation"],
            "protocol": protocol,
        }
        for item in selected
    ]


# ── device templates ──────────────────────────────────────────────────────────

DEVICE_TEMPLATES = [
    {
        "device_type": "BMS Controller",
        "protocol": "BACnet",
        "protocol_version": "BACnet 1.4",
        "ports": [47808],
        "default_auth": "None",
        "criticality": "High",
        "min_objects": 100,
        "max_objects": 600,
        "host_prefix": "bms-ctrl",
        "ip_base": 20,
    },
    {
        "device_type": "VAV Controller",
        "protocol": "BACnet",
        "protocol_version": "BACnet 1.2",
        "ports": [47808],
        "default_auth": "None",
        "criticality": "Medium",
        "min_objects": 20,
        "max_objects": 80,
        "host_prefix": "vav-box",
        "ip_base": 22,
    },
    {
        "device_type": "AHU Controller",
        "protocol": "BACnet",
        "protocol_version": "BACnet 1.4",
        "ports": [47808],
        "default_auth": "None",
        "criticality": "High",
        "min_objects": 80,
        "max_objects": 200,
        "host_prefix": "ahu-ctrl",
        "ip_base": 24,
    },
    {
        "device_type": "PLC",
        "protocol": "Modbus",
        "protocol_version": "Modbus TCP",
        "ports": [502],
        "default_auth": "None",
        "criticality": "Critical",
        "min_objects": 10,
        "max_objects": 50,
        "host_prefix": "plc",
        "ip_base": 10,
    },
    {
        "device_type": "Gateway",
        "protocol": "BACnet",
        "protocol_version": "BACnet 1.4",
        "ports": [47808, 443],
        "default_auth": "Basic",
        "criticality": "High",
        "min_objects": 30,
        "max_objects": 150,
        "host_prefix": "gw",
        "ip_base": 30,
    },
    {
        "device_type": "Sensor",
        "protocol": "BACnet",
        "protocol_version": "BACnet 1.0",
        "ports": [47808],
        "default_auth": "None",
        "criticality": "Low",
        "min_objects": 1,
        "max_objects": 5,
        "host_prefix": "sensor",
        "ip_base": 40,
    },
    {
        "device_type": "Historian",
        "protocol": "OPC-UA",
        "protocol_version": "OPC-UA 1.04",
        "ports": [4840],
        "default_auth": "Certificate",
        "criticality": "High",
        "min_objects": 50,
        "max_objects": 200,
        "host_prefix": "hist",
        "ip_base": 50,
    },
    {
        "device_type": "Engineering Workstation",
        "protocol": "HTTPS",
        "protocol_version": "HTTPS",
        "ports": [443, 3389],
        "default_auth": "Certificate",
        "criticality": "High",
        "min_objects": 0,
        "max_objects": 0,
        "host_prefix": "eng-ws",
        "ip_base": 60,
    },
    {
        "device_type": "Thermostat",
        "protocol": "BACnet",
        "protocol_version": "BACnet 1.0",
        "ports": [47808],
        "default_auth": "None",
        "criticality": "Low",
        "min_objects": 3,
        "max_objects": 10,
        "host_prefix": "tstat",
        "ip_base": 70,
    },
    {
        "device_type": "LoRaWAN Gateway",
        "protocol": "LoRaWAN",
        "protocol_version": "LoRaWAN 1.0.4",
        "ports": [1700],
        "default_auth": "PSK",
        "criticality": "Medium",
        "min_objects": 20,
        "max_objects": 100,
        "host_prefix": "lora-gw",
        "ip_base": 80,
    },
    {
        "device_type": "LoRaWAN Sensor",
        "protocol": "LoRaWAN",
        "protocol_version": "LoRaWAN 1.0.4",
        "ports": [1700],
        "default_auth": "None",
        "criticality": "Low",
        "min_objects": 1,
        "max_objects": 3,
        "host_prefix": "lora-sensor",
        "ip_base": 81,
    },
]


def _simulate_device(
    template: dict, device_id: int, index: int, total: int
) -> dict[str, Any]:
    """Simulate a single BACnet/BMS device."""
    vendor_ids = list(BACNET_VENDORS.keys())
    vendor_id = random.choice(vendor_ids)
    vendor_name = BACNET_VENDORS[vendor_id]
    protocol = template["protocol"]
    ip_base = template["ip_base"]
    third_octet = ip_base + (index // 200)
    ip = f"10.42.{min(third_octet, 254)}.{10 + (index % 240)}"
    zone = random.choice(ZONES)
    objects = random.randint(template["min_objects"], template["max_objects"]) if template["max_objects"] > 0 else 0
    firmware = f"{random.randint(2,6)}.{random.randint(0,9)}.{random.randint(0,99)}"

    protocols = [protocol]
    extra_ports = list(template["ports"])

    vulns = _device_vulnerabilities(protocol, template["criticality"])

    asset = {
        "id": str(uuid.uuid4()),
        "hostname": f"{template['host_prefix']}-{index + 1:04d}",
        "ip": ip,
        "device_type": template["device_type"],
        "device_id": device_id,
        "vendor_id": vendor_id,
        "vendor_name": vendor_name,
        "firmware_version": firmware,
        "protocols": protocols,
        "protocol": protocol,
        "protocol_version": template["protocol_version"],
        "ports": extra_ports,
        "criticality": template["criticality"],
        "risk_level": _risk_level(vulns),
        "segmentation_zone": zone,
        "auth_method": template["default_auth"],
        "object_count": objects,
        "last_seen": datetime.now(timezone.utc).isoformat(),
        "security_status": "Monitored" if random.random() > 0.15 else "Unmonitored",
        "vulnerabilities": vulns,
    }
    return asset


def simulate_network_scan(asset_count: int | None = None) -> dict[str, Any]:
    """Generate a realistic large-scale BMS/BACnet scan result.

    Args:
        asset_count: Number of devices to simulate. Default 200 for a
                     mid-sized building. Use 1000+ for a large campus.
    """
    total = asset_count or 200

    # Distribute across templates proportionally
    template_weights = [3, 6, 2, 1, 1, 8, 1, 1, 3, 2, 2]  # more sensors, VAVs, LoRaWAN
    total_weight = sum(template_weights)
    devices_per_template = [
        max(1, int(total * w / total_weight)) for w in template_weights
    ]
    # Adjust rounding
    diff = total - sum(devices_per_template)
    if diff > 0:
        devices_per_template[-1] += diff
    elif diff < 0:
        devices_per_template[0] += diff

    assets: list[dict[str, Any]] = []
    device_id_base = random.randint(1000, 9999)
    global_index = 0

    for t_idx, template in enumerate(DEVICE_TEMPLATES):
        count = devices_per_template[t_idx]
        for i in range(count):
            dev_id = device_id_base + global_index
            asset = _simulate_device(template, dev_id, global_index, total)
            assets.append(asset)
            global_index += 1

    # Compute summary
    vulnerability_counts: Counter = Counter()
    protocol_counts: Counter = Counter()
    zone_counts: Counter = Counter()
    device_type_counts: Counter = Counter()
    vendor_counts: Counter = Counter()
    total_bacnet_objects = 0

    for asset in assets:
        for v in asset.get("vulnerabilities", []):
            vulnerability_counts[v.get("severity", "Low")] += 1
        for p in asset.get("protocols", []):
            if p:
                protocol_counts[p] += 1
        zone = asset.get("segmentation_zone", "Unknown")
        if zone:
            zone_counts[zone] += 1
        dt = asset.get("device_type", "Unknown")
        if dt:
            device_type_counts[dt] += 1
        vendor = asset.get("vendor_name", "")
        if vendor:
            vendor_counts[vendor] += 1
        total_bacnet_objects += asset.get("object_count", 0)

    total_vulns = sum(vulnerability_counts.values())
    critical_vulns = vulnerability_counts.get("Critical", 0)

    risk_penalty = min(
        72,
        critical_vulns * 10
        + vulnerability_counts.get("High", 0) * 5
        + vulnerability_counts.get("Medium", 0) * 2,
    )
    compliance_score = max(30, 98 - risk_penalty)

    scan = {
        "scan_id": str(uuid.uuid4()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_type": "simulate",
        "status": "complete",
        "assets": assets,
        "summary": {
            "total_assets": len(assets),
            "total_vulnerabilities": total_vulns,
            "critical_vulnerabilities": critical_vulns,
            "compliance_score": compliance_score,
            "vulnerabilities_by_severity": {
                severity: vulnerability_counts.get(severity, 0)
                for severity in ["Critical", "High", "Medium", "Low"]
            },
            "protocols_discovered": dict(protocol_counts),
            "zones_discovered": dict(zone_counts),
            "device_types": dict(device_type_counts),
            "total_bacnet_objects": total_bacnet_objects,
            "top_vendors": dict(vendor_counts.most_common(10)),
        },
    }

    scan["compliance"] = run_compliance_check(scan)
    scan["alerts"] = run_alert_feed(scan)
    return scan


# ── compliance ────────────────────────────────────────────────────────────────


def _control_status(gaps: list[str], score: int) -> str:
    if not gaps:
        return "PASS"
    if score >= 65 and len(gaps) <= 2:
        return "PARTIAL"
    return "FAIL"


def run_compliance_check(scan: dict) -> dict:
    """Evaluate scan output using the comprehensive compliance framework.

    Delegates to compliance_framework.evaluate_compliance() for full
    DESC + IEC 62443-3-3 control assessment with evidence evaluation.
    """
    assets = scan.get("assets", [])
    summary = scan.get("summary", {})
    return evaluate_compliance(assets, summary)


def run_alert_feed(scan: dict) -> list[dict]:
    """Create alert feed from the latest scan. Sorted by severity."""
    assets = scan.get("assets", [])
    alerts = []
    now = datetime.now(timezone.utc).isoformat()
    for asset in assets:
        for vuln in asset.get("vulnerabilities", []):
            if vuln["severity"] in {"Critical", "High"}:
                alerts.append({
                    "id": f"ALERT-{asset['id'][:8]}-{vuln['id']}",
                    "timestamp": now,
                    "severity": vuln["severity"],
                    "title": vuln["title"],
                    "message": f"{asset['hostname']} ({asset['ip']}) exposed {vuln['title']} via {asset['protocol']}.",
                    "asset_id": asset["id"],
                    "asset_hostname": asset["hostname"],
                    "status": "Active",
                })
    if not alerts:
        alerts.append({
            "id": "ALERT-OK-0001",
            "timestamp": now,
            "severity": "Info",
            "title": "No active critical or high vulnerabilities",
            "message": "Detected OT posture is stable for the current scan.",
            "asset_id": None,
            "asset_hostname": None,
            "status": "Info",
        })
    return sorted(alerts, key=lambda a: (a["severity"] != "Critical", a["severity"] != "High", a["timestamp"]))
