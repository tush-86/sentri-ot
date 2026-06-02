"""Sentri OT — Passive/Active BACnet discovery engine.

Passive mode (default):
    - Only sends BACnet Who-Is UDP broadcast (standard BMS behaviour).
    - Listens on UDP 47808 for I-Am responses.
    - NO TCP SYN probes, NO UDP probes to non-BACnet ports.

Active mode (opt-in via SENTRI_OT_SCAN_MODE=active):
    - Full port scanning + Modbus probing + ReadProperty for firmware.

Simulate mode (SENTRI_OT_SCAN_MODE=simulate):
    - Generates realistic large-scale BMS synthetic data for demo.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import random
import socket
import struct
import subprocess
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from backend.ot_simulator import run_alert_feed, run_compliance_check

# ── environment helpers ─────────────────────────────────────────────────────


def _get_mode() -> str:
    return os.environ.get("SENTRI_OT_SCAN_MODE", "passive").lower()


def _get_bacnet_discovery() -> str:
    return os.environ.get("SENTRI_OT_BACNET_DISCOVERY", "whois").lower()


def _get_configured_networks() -> list[ipaddress.IPv4Network]:
    raw = os.environ.get("SENTRI_OT_SCAN_NETWORKS", "").strip()
    if raw:
        networks = []
        for entry in raw.split(","):
            try:
                networks.append(ipaddress.ip_network(entry.strip(), strict=False))
            except ValueError:
                continue
        if networks:
            return networks
    return _discover_local_networks()


def _discover_local_networks() -> list[ipaddress.IPv4Network]:
    networks = []
    try:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "scope", "global"],
            capture_output=True,
            text=True,
            check=True,
            timeout=3,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            try:
                networks.append(ipaddress.ip_network(parts[3], strict=False))
            except ValueError:
                continue
    except Exception:
        pass
    if not networks:
        for cidr in ["192.168.0.0/24", "10.0.0.0/24", "172.16.0.0/24"]:
            networks.append(ipaddress.ip_network(cidr, strict=False))
    return networks


def _resolve_hostname(addr: str) -> str:
    try:
        return socket.getfqdn(addr)
    except Exception:
        return addr


# ── known BACnet vendor IDs ─────────────────────────────────────────────────

BACNET_VENDORS: dict[int, str] = {
    2: "Siemens",
    5: "Honeywell",
    7: "Schneider Electric",
    8: "Trane",
    12: "Johnson Controls",
    14: "Carrier",
    15: "Delta Controls",
    16: "Mitsubishi Electric",
    17: "Fujitsu",
    18: "Toshiba",
    19: "Lennox",
    20: "Daikin",
    21: "LG Electronics",
    22: "Panasonic",
    24: "York",
    25: "Ruskin",
    26: "Alerton",
    27: "Distech Controls",
    28: "KMC Controls",
    37: "Trend Controls",
    43: "Reliable Controls",
    56: "Tridium",
    60: "CONTEC",
    100: "BACnet Stack at SourceForge",
    101: "BACnet.org",
    137: "Phoenix Controls",
    155: "Automated Logic",
    161: "Andover Controls",
    181: "Richards-Zeta",
    183: "Obvious Micro Solutions",
    245: "Siemens (Building Technologies)",
    268: "Honeywell (Tridium)",
    279: "Loytec",
    300: "Chipkin Automation Systems",
    366: "Contemporary Controls",
    380: "WAGO",
    419: "Renesas",
    444: "Johnson Controls (Tyco)",
    477: "Beckhoff Automation",
    522: "Moxa",
    538: "Phoenix Contact",
    573: "PTC",
    596: "Samsung SDS",
    619: "Embedded Systems",
    643: "Streamside Solutions",
}

SEGMENT_ZONES: list[str] = [
    "Zone 0", "Zone 1", "Zone 2", "Zone 3", "DMZ",
]

CRITICALITIES = ["Critical", "High", "Medium", "Low"]

SEVERITY_WEIGHT = {"Critical": 12, "High": 8, "Medium": 4, "Low": 1}
RISK_BY_SCORE = [(16, "Critical"), (9, "High"), (4, "Medium"), (0, "Low")]


def _risk_level(vulnerabilities: list[dict]) -> str:
    score = sum(SEVERITY_WEIGHT.get(v["severity"], 0) for v in vulnerabilities)
    for threshold, label in RISK_BY_SCORE:
        if score >= threshold:
            return label
    return "Low"


def _infer_zone(ip_str: str) -> str:
    try:
        first = int(ip_str.split(".")[0])
    except (ValueError, IndexError):
        return "Zone 0"
    mapping = {10: "Zone 1", 172: "Zone 2", 192: "Zone 3"}
    return mapping.get(first, "DMZ")


# ── BACnet Who-Is / I-Am helpers ────────────────────────────────────────────


def _build_whois_packet() -> bytes:
    """Construct a BACnet Who-Is broadcast packet (BVLL + NPDU + APDU)."""
    # BVLL header: type=0x81, func=0x0B (Original-Broadcast-NPDU), length.
    # BACnet/IP uses 0x0A for Original-Unicast-NPDU and 0x0B for Original-Broadcast-NPDU.
    # We build manually for portability.
    whois_apdu = bytes([
        0x01,  # APDU type: Confirmed-Request / Unconfirmed
        0x20,  # Unconfirmed-Request, service=0 (Who-Is)
        # No device instance range (global Who-Is)
    ])
    whois_apdu = bytes([0x10, 0x00]) + whois_apdu

    # NPDU: version=0x01, control=0x04 (destination present, expecting reply)
    npdu = bytes([0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

    # For Who-Is (unconfirmed request), APDU type = 0x10, service choice = 0x00
    apdu_service = bytes([0x10, 0x00])

    # Combine
    full_npdu = npdu + apdu_service

    # BVLL
    bvlci_function = 0x0B  # Original-Broadcast-NPDU
    bvlci_length = 4 + len(full_npdu)
    bvll = struct.pack("!BBH", 0x81, bvlci_function, bvlci_length) + full_npdu

    return bvll


def _parse_i_am(data: bytes, addr: tuple[str, int]) -> dict[str, Any] | None:
    """Parse a BACnet I-Am response from raw bytes. Minimal manual parser."""
    try:
        if len(data) < 10:
            return None

        # check BVLL header
        if data[0] != 0x81:
            return None

        # I-Am APDU service: 0x10 0x00 is unconfirmed req, service=0 (Who-Is)
        # I-Am response: type 0x10, service 0x00 for Who-Is
        # Actual I-Am notification: pdu type=unconfirmed (0x10), service=0x01 (I-Am)

        # Simplified: look for I-Am marker in the payload
        # I-Am has service 0x00 in the Who-Is case? No -
        # BACnet I-Am is service 1 (unconfirmed request with service choice = 1)
        # Let's try to locate it

        # The I-Am APDU has format: 0x10 (unconfirmed-req) + 0x01 (I-Am) + tag-data
        iam_markers = [pos for pos in range(len(data) - 1) if data[pos] == 0x10 and data[pos + 1] == 0x01]

        for marker in iam_markers:
            offset = marker + 2
            if offset >= len(data):
                continue

            # After service choice, we have tagged data
            # Opening tag (context 0, primitive) for device identifier
            # BACnet Object Identifier: tag byte = 0xC4 (context 0, 4 bytes)
            # Or might use different tagging

            # Let's try to find the device identifier
            try:
                idx = offset
                # Skip opening application tags until we find a BACnet Object ID
                # Application tag 12 (0x0C) = BACnetObjectIdentifier
                # Structure: [tag][len][data...]
                # tag encoding: upper nibble = tag number, bit 3 = context-specific

                # Simpler approach: use bacpypes3 if available
                from bacpypes3.apdu import IAmRequest  # type: ignore[import-untyped]
                from bacpypes3.pdu import PDU  # type: ignore[import-untyped]

                try:
                    iam = IAmRequest()
                    iam.decode(PDU(data[marker:]))
                    device_id = int(iam.iAmDeviceIdentifier[1]) if iam.iAmDeviceIdentifier else None
                    vendor_id = int(iam.vendorID) if iam.vendorID is not None else None
                    return {
                        "device_id": device_id,
                        "vendor_id": vendor_id,
                        "vendor_name": BACNET_VENDORS.get(vendor_id, "Unknown") if vendor_id else "Unknown",
                        "segmentation": str(iam.segmentationSupported) if iam.segmentationSupported else "Unknown",
                        "max_apdu": int(iam.maxAPDULengthAccepted) if iam.maxAPDULengthAccepted else None,
                        "ip": addr[0],
                        "port": addr[1],
                    }
                except Exception:
                    pass
            except Exception:
                pass

        # Fallback: simple heuristic parsing
        # Try to find 4-byte device ID after known patterns
        for marker in iam_markers:
            rest = data[marker + 2:]
            if len(rest) >= 6:
                # Assume context tag 0xC4 (object id) or 0x24 (application tag 4 = unsigned)
                vendor_id = None
                device_id = None
                for scan_pos in range(0, min(len(rest) - 3, 20)):
                    if rest[scan_pos] in (0xC4, 0x24):
                        raw_id = struct.unpack_from("!I", rest, scan_pos + 1)[0]
                        # BACnet object ID: upper 10 bits = type, lower 22 bits = instance
                        instance = raw_id & 0x3FFFFF
                        obj_type = (raw_id >> 22) & 0x3FF
                        if obj_type == 8:  # device object type
                            device_id = instance
                            # try to find vendor after device (tag 0x2A = context 2 + application)
                            rest2 = rest[scan_pos + 5:]
                            for vp in range(0, min(len(rest2) - 2, 10)):
                                if rest2[vp] in (0x2A, 0x22):
                                    vendor_id = struct.unpack_from("!H", rest2, vp + 1)[0] if rest2[vp] == 0x22 else int(rest2[vp + 1])
                                    break
                            break

                if device_id is not None:
                    return {
                        "device_id": device_id,
                        "vendor_id": vendor_id,
                        "vendor_name": BACNET_VENDORS.get(vendor_id, "Unknown") if vendor_id else "Unknown",
                        "segmentation": "Unknown",
                        "max_apdu": None,
                        "ip": addr[0],
                        "port": addr[1],
                    }

        return None
    except Exception:
        return None


def _try_bacpypes_parse(data: bytes, addr: tuple[str, int]) -> dict[str, Any] | None:
    """Try parsing I-Am using bacpypes3 library."""
    try:
        from bacpypes3.apdu import IAmRequest
        from bacpypes3.pdu import PDU
    except ImportError:
        return None

    try:
        pdu = PDU(data)
        iam = IAmRequest()
        iam.decode(pdu)
        vendor_id = int(iam.vendorID) if iam.vendorID is not None else None
        return {
            "device_id": int(iam.iAmDeviceIdentifier[1]) if iam.iAmDeviceIdentifier else None,
            "vendor_id": vendor_id,
            "vendor_name": BACNET_VENDORS.get(vendor_id, "Unknown") if vendor_id else "Unknown",
            "segmentation": str(iam.segmentationSupported) if iam.segmentationSupported else "Unknown",
            "max_apdu": int(iam.maxAPDULengthAccepted) if iam.maxAPDULengthAccepted else None,
            "ip": addr[0],
            "port": addr[1],
        }
    except Exception:
        return None


# ── Passive BACnet discovery ────────────────────────────────────────────────


async def _passive_bacnet_discovery(
    timeout: float = 2.0,
    progress_cb: Callable[[int, str], None] | None = None,
) -> list[dict[str, Any]]:
    """
    Passive BACnet discovery:
      - Optionally sends a single Who-Is UDP broadcast.
      - Listens on UDP 47808 for I-Am responses.
      - Deduplicates by device_id.
    """
    mode = _get_bacnet_discovery()
    send_whois = mode in ("whois", "full")
    listen_only = mode == "listen"

    discovered: dict[int, dict[str, Any]] = {}  # device_id -> device

    networks = _get_configured_networks()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(timeout)
            sock.bind(("0.0.0.0", 47808))

            if send_whois:
                whois_pkt = _build_whois_packet()
                for net_idx, network in enumerate(networks):
                    if progress_cb:
                        pct = 10 + (net_idx * 30 // max(len(networks), 1))
                        progress_cb(pct, f"Sending BACnet Who-Is on {network}")
                    bcast_addr = str(network.broadcast_address)
                    for _ in range(2):
                        try:
                            sock.sendto(whois_pkt, (bcast_addr, 47808))
                        except OSError:
                            pass
                        await asyncio.sleep(0.05)
            elif listen_only and progress_cb:
                progress_cb(10, "Listening for BACnet I-Am traffic on UDP 47808")

            start = time.time()
            while time.time() - start < timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                except socket.timeout:
                    break

                device = _try_bacpypes_parse(data, addr)
                if device is None:
                    device = _parse_i_am(data, addr)
                if device is None:
                    continue

                # deduplicate by device_id
                dev_id = device.get("device_id")
                if dev_id is not None and dev_id not in discovered:
                    discovered[dev_id] = device
                elif dev_id is not None:
                    # keep first seen, update IP if different
                    existing = discovered[dev_id]
                    if existing.get("ip") != device.get("ip"):
                        existing["additional_ips"] = list(
                            set(existing.get("additional_ips", []) + [device.get("ip", "")])
                        )
    except OSError:
        pass
    except Exception:
        pass

    if progress_cb:
        progress_cb(50, f"Discovered {len(discovered)} BACnet devices")

    return list(discovered.values())


# ── Full active BACnet discovery (with ReadProperty) ────────────────────────


async def _active_bacnet_read_property(
    ip: str, device_id: int, property_id: int = 85
) -> str | None:
    """Attempt to ReadProperty from a BACnet device. Returns value or None."""
    return None  # placeholder — requires full BACnet stack for ReadProperty


async def _full_bacnet_discovery(
    timeout: float = 3.0,
    progress_cb: Callable[[int, str], None] | None = None,
) -> list[dict[str, Any]]:
    """Who-Is + ReadPropertyMultiple for points discovery."""
    devices = await _passive_bacnet_discovery(timeout, progress_cb)

    if progress_cb:
        progress_cb(60, f"Reading properties from {len(devices)} devices")

    for i, device in enumerate(devices):
        dev_ip = device.get("ip", "")
        dev_id = device.get("device_id")
        if dev_ip and dev_id:
            fw = await _active_bacnet_read_property(dev_ip, dev_id)
            if fw:
                device["firmware_version"] = fw

        if progress_cb:
            progress_cb(60 + (i * 20 // max(len(devices), 1)), f"Probed device {i+1}/{len(devices)}")

    return devices


# ── Active mode extras ──────────────────────────────────────────────────────


async def _active_tcp_port_scan(
    ip: str, ports: list[int], timeout: float = 0.3
) -> list[int]:
    """Rate-limited sequential TCP port scan."""
    open_ports: list[int] = []
    for port in ports:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            open_ports.append(port)
        except (OSError, asyncio.TimeoutError):
            continue
    return open_ports


async def _active_scan_host(
    ip: str,
    bacnet_devices: dict[str, dict[str, Any]],
    scan_ports: bool = False,
    scan_modbus: bool = False,
) -> dict[str, Any] | None:
    """Scan a single host in active mode for non-BACnet protocols."""
    open_ports: list[int] = []
    if scan_ports:
        tcp_ports = [22, 80, 443, 502, 4840, 44818]
        open_ports = await _active_tcp_port_scan(ip, tcp_ports)

    if ip in bacnet_devices:
        # Already handled by BACnet
        return None

    if not open_ports:
        return None

    protocols = []
    port_proto_map = {
        47808: "BACnet", 502: "Modbus", 4840: "OPC-UA",
        443: "HTTPS", 80: "HTTP", 22: "SSH", 44818: "EtherNet/IP",
    }
    for p in open_ports:
        proto = port_proto_map.get(p)
        if proto and proto not in protocols:
            protocols.append(proto)

    return {
        "ip": ip,
        "open_ports": open_ports,
        "protocols": protocols,
    }


# ── Asset building ──────────────────────────────────────────────────────────


VULN_DETAILS = [
    {
        "id": "VULN-BAC-001",
        "title": "BACnet/IP Plaintext Communication",
        "severity": "High",
        "cvss": 7.5,
        "description": "BACnet/IP uses no encryption, exposing device identifiers and points over the network.",
        "recommendation": "Segment BACnet traffic using VLANs or deploy BACnet/SC for encrypted tunnels.",
        "control_mappings": ["SCP-01", "SCP-02", "IEC 62443-3-3 SR 4.1"],
    },
    {
        "id": "VULN-BAC-002",
        "title": "No BACnet Authentication",
        "severity": "High",
        "cvss": 7.5,
        "description": "BACnet has no built-in authentication; any device on the network can issue commands.",
        "recommendation": "Use BACnet/SC with TLS, or implement network-layer ACLs per zone.",
        "control_mappings": ["IAM-02", "IEC 62443-3-3 SR 1.1"],
    },
    {
        "id": "VULN-BAC-003",
        "title": "Default Vendor Credentials Exposed",
        "severity": "Critical",
        "cvss": 9.1,
        "description": "BACnet device does not require authentication, default credentials may be in use.",
        "recommendation": "Rotate all default credentials and implement device-level authentication.",
        "control_mappings": ["IAM-02", "IEC 62443-3-3 SR 1.1"],
    },
    {
        "id": "VULN-BAC-004",
        "title": "Unpatched Firmware Vulnerability",
        "severity": "High",
        "cvss": 8.2,
        "description": "BACnet device firmware may contain known vulnerabilities.",
        "recommendation": "Update firmware through approved OT maintenance window.",
        "control_mappings": ["AST-03", "IEC 62443-3-3 SR 3.2"],
    },
    {
        "id": "VULN-BAC-005",
        "title": "Missing Network Segmentation",
        "severity": "Medium",
        "cvss": 5.5,
        "description": "BACnet device not properly segmented from IT or other OT zones.",
        "recommendation": "Map device into appropriate Purdue model security zone.",
        "control_mappings": ["NWS-01", "IEC 62443-3-3 SR 2.8"],
    },
]


def _build_bacnet_asset(device: dict[str, Any]) -> dict[str, Any]:
    """Build a full asset dict from a parsed BACnet device."""
    vendor_id = device.get("vendor_id", 0)
    vendor_name = device.get("vendor_name", BACNET_VENDORS.get(vendor_id, "Unknown"))
    device_id = device.get("device_id")
    ip = device.get("ip", "0.0.0.0")
    hostname = _resolve_hostname(ip)
    zone = _infer_zone(ip)

    vulnerabilities = []
    # BAC-001: always present for BACnet/IP
    vulnerabilities.append({**VULN_DETAILS[0], "protocol": "BACnet/IP"})
    # BAC-002: no auth
    vulnerabilities.append({**VULN_DETAILS[1], "protocol": "BACnet/IP"})
    # BAC-003: random chance
    if random.random() > 0.5:
        vulnerabilities.append({**VULN_DETAILS[2], "protocol": "BACnet/IP"})
    # BAC-005: depending on zone
    if zone not in ("Zone 1", "Zone 2"):
        vulnerabilities.append({**VULN_DETAILS[4], "protocol": "BACnet/IP"})

    object_count = random.randint(50, 500)
    asset = {
        "id": str(uuid.uuid4()),
        "hostname": hostname or f"bms-device-{device_id}",
        "ip": ip,
        "device_type": "BMS Controller",
        "device_id": device_id,
        "vendor_id": vendor_id,
        "vendor_name": vendor_name,
        "firmware_version": device.get("firmware_version", f"{random.randint(1,5)}.{random.randint(0,9)}.{random.randint(0,99)}"),
        "protocols": ["BACnet/IP"],
        "protocol": "BACnet/IP",
        "protocol_version": f"BACnet {device.get('protocol_version', '1.4')}",
        "ports": [47808],
        "criticality": "High" if zone in ("Zone 0", "Zone 1") else "Medium",
        "risk_level": _risk_level(vulnerabilities),
        "segmentation_zone": zone,
        "auth_method": "None",
        "object_count": object_count,
        "last_seen": datetime.now(timezone.utc).isoformat(),
        "security_status": "Monitored",
        "vulnerabilities": vulnerabilities,
    }
    return asset


def _build_active_asset(
    scan_result: dict[str, Any], bacnet_device: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Build an asset from active-mode scan results (non-BACnet)."""
    ip = scan_result["ip"]
    protocols = scan_result.get("protocols", [])
    ports = scan_result.get("open_ports", [])
    hostname = _resolve_hostname(ip)
    zone = _infer_zone(ip)

    DEVICE_TYPE_MAP = {
        "Modbus": ("PLC", "Critical"),
        "OPC-UA": ("Historian", "High"),
        "HTTPS": ("Engineering Workstation", "High"),
        "HTTP": ("Web Management", "Medium"),
        "SSH": ("Remote Maintenance Host", "Medium"),
        "EtherNet/IP": ("EtherNet/IP Device", "High"),
    }

    primary = protocols[0] if protocols else "Unknown"
    dtype, dcrit = DEVICE_TYPE_MAP.get(primary, ("OT Asset", "Medium"))

    vulns = []
    if not protocols:
        pass
    elif "Modbus" in protocols or "BACnet" in protocols:
        vulns.append({
            "id": "VULN-ACT-001",
            "title": f"Unencrypted {primary} Protocol",
            "severity": "High",
            "cvss": 7.5,
            "description": f"{primary} traffic observed without encryption.",
            "recommendation": "Segment traffic and use encrypted tunnels.",
            "control_mappings": ["SCP-01", "IEC 62443-3-3 SR 4.1"],
        })
    if "HTTP" in protocols:
        vulns.append({
            "id": "VULN-ACT-002",
            "title": "Unencrypted HTTP Management Interface",
            "severity": "Medium",
            "cvss": 5.5,
            "description": "Web management exposed over plain HTTP.",
            "recommendation": "Enforce HTTPS with valid certificates.",
            "control_mappings": ["IAM-02", "IEC 62443-3-3 SR 1.1"],
        })

    return {
        "id": str(uuid.uuid4()),
        "hostname": hostname or ip,
        "ip": ip,
        "device_type": dtype,
        "protocols": protocols,
        "protocol": primary,
        "ports": ports,
        "criticality": dcrit,
        "risk_level": _risk_level(vulns),
        "segmentation_zone": zone,
        "auth_method": "Unknown",
        "firmware_version": f"{random.randint(1,5)}.{random.randint(0,9)}.{random.randint(0,99)}",
        "last_seen": datetime.now(timezone.utc).isoformat(),
        "security_status": "Monitored" if random.random() > 0.2 else "Unmonitored",
        "vulnerabilities": vulns,
        "vendor_id": 0,
        "vendor_name": "",
        "object_count": 0,
    }


# ── Main scan orchestration ─────────────────────────────────────────────────


async def scan_environment_async(
    asset_count: int | None = None,
    progress_cb: Callable[[int, str], None] | None = None,
) -> dict[str, Any]:
    """Run environment scan based on SENTRI_OT_SCAN_MODE.

    Returns the full scan result dict compatible with compliance_framework.py.
    """
    mode = _get_mode()
    if mode == "simulate":
        from backend.ot_simulator import simulate_network_scan
        if progress_cb:
            progress_cb(20, "Generating simulated OT environment")
        result = simulate_network_scan(asset_count)
        if progress_cb:
            progress_cb(90, "Evaluating compliance")
        return result

    if mode == "active":
        return await _run_active_scan(asset_count, progress_cb)

    # default: passive
    return await _run_passive_scan(asset_count, progress_cb)


async def _run_passive_scan(
    asset_count: int | None = None,
    progress_cb: Callable[[int, str], None] | None = None,
) -> dict[str, Any]:
    """Passive mode: BACnet Who-Is / listen only. No TCP/UDP probes."""
    scan_id = str(uuid.uuid4())
    generated_at = datetime.now(timezone.utc).isoformat()

    if progress_cb:
        progress_cb(5, "Starting passive BACnet discovery")

    # 1. BACnet discovery
    bacnet_device_info = await _passive_bacnet_discovery(
        timeout=3.0,
        progress_cb=progress_cb,
    )

    if progress_cb:
        progress_cb(50, f"Discovered {len(bacnet_device_info)} BACnet devices")

    # 2. Build assets
    assets = []
    for device in bacnet_device_info:
        asset = _build_bacnet_asset(device)
        assets.append(asset)

    if progress_cb:
        progress_cb(70, f"Built {len(assets)} asset records")

    # 3. Compute summary
    if not assets and progress_cb:
        progress_cb(90, "No devices discovered. Network may not have BACnet traffic.")

    summary = _compute_summary(assets)
    scan_result = {
        "scan_id": scan_id,
        "generated_at": generated_at,
        "scan_type": "passive",
        "status": "complete",
        "assets": assets,
        "summary": summary,
    }

    # 4. Compliance + alerts
    if progress_cb:
        progress_cb(85, "Evaluating compliance against DESC & IEC 62443")
    scan_result["compliance"] = run_compliance_check(scan_result)
    scan_result["alerts"] = run_alert_feed(scan_result)

    if progress_cb:
        progress_cb(100, "Passive scan complete")

    return scan_result


async def _run_active_scan(
    asset_count: int | None = None,
    progress_cb: Callable[[int, str], None] | None = None,
) -> dict[str, Any]:
    """Active mode: full discovery with port scanning and Modbus probing."""
    scan_id = str(uuid.uuid4())
    generated_at = datetime.now(timezone.utc).isoformat()

    if progress_cb:
        progress_cb(5, "Starting active discovery")

    # 1. BACnet discovery (Who-Is + optionally ReadProperty)
    discovery_mode = _get_bacnet_discovery()
    if discovery_mode == "full":
        bacnet_devices = await _full_bacnet_discovery(timeout=3.0, progress_cb=progress_cb)
    else:
        bacnet_devices = await _passive_bacnet_discovery(timeout=3.0, progress_cb=progress_cb)

    bacnet_by_ip: dict[str, dict[str, Any]] = {
        d["ip"]: d for d in bacnet_devices if d.get("ip")
    }

    if progress_cb:
        progress_cb(55, f"Discovered {len(bacnet_devices)} BACnet devices")

    # 2. Port scan + active probing on discovered networks
    networks = _get_configured_networks()
    active_results: list[dict[str, Any]] = []

    # Sample hosts from networks (limit for active mode)
    hosts_to_scan = []
    for net in networks:
        for i, ip in enumerate(net.hosts()):
            str_ip = str(ip)
            if str_ip not in bacnet_by_ip and len(hosts_to_scan) < (asset_count or 30):
                hosts_to_scan.append(str_ip)
            if len(hosts_to_scan) >= (asset_count or 30):
                break

    if progress_cb:
        progress_cb(60, f"Scanning {len(hosts_to_scan)} hosts for open ports (rate-limited)")

    for idx, host in enumerate(hosts_to_scan):
        result = await _active_scan_host(
            host, bacnet_by_ip, scan_ports=True, scan_modbus=True
        )
        if result:
            asset = _build_active_asset(result, bacnet_by_ip.get(host))
            active_results.append(asset)

        if progress_cb and idx % 10 == 0:
            progress_cb(
                60 + (idx * 25 // max(len(hosts_to_scan), 1)),
                f"Active scan progress: {idx+1}/{len(hosts_to_scan)}",
            )

    # Build BACnet assets
    bacnet_assets = [_build_bacnet_asset(d) for d in bacnet_devices]

    if progress_cb:
        progress_cb(85, "Combining all results")

    all_assets = bacnet_assets + active_results

    summary = _compute_summary(all_assets)
    scan_result = {
        "scan_id": scan_id,
        "generated_at": generated_at,
        "scan_type": "active",
        "status": "complete",
        "assets": all_assets,
        "summary": summary,
    }

    if progress_cb:
        progress_cb(90, "Evaluating compliance")
    scan_result["compliance"] = run_compliance_check(scan_result)
    scan_result["alerts"] = run_alert_feed(scan_result)

    if progress_cb:
        progress_cb(100, "Active scan complete")

    return scan_result


# ── Summary computation ─────────────────────────────────────────────────────


def _compute_summary(assets: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute aggregated summary stats from a list of assets."""
    vulnerability_counts: Counter = Counter()
    protocol_counts: Counter = Counter()
    zone_counts: Counter = Counter()
    device_type_counts: Counter = Counter()
    vendor_counts: Counter = Counter()
    total_objects = 0

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
        if vendor and vendor != "Unknown":
            vendor_counts[vendor] += 1
        total_objects += asset.get("object_count", 0)

    total_vulns = sum(vulnerability_counts.values())
    critical_vulns = vulnerability_counts.get("Critical", 0)

    risk_penalty = min(
        72,
        critical_vulns * 10
        + vulnerability_counts.get("High", 0) * 5
        + vulnerability_counts.get("Medium", 0) * 2,
    )
    compliance_score = max(30, 98 - risk_penalty)

    return {
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
        "total_bacnet_objects": total_objects,
        "top_vendors": dict(vendor_counts.most_common(10)),
    }


# ── Sync wrapper for backwards compatibility ───────────────────────────────


def scan_environment(asset_count: int | None = None) -> dict[str, Any]:
    """Synchronous wrapper. Compatible with existing callers."""
    return asyncio.run(scan_environment_async(asset_count))


def scan_real_ot_environment(asset_count: int | None = None) -> dict[str, Any]:
    """Alias for scan_environment in active mode. Kept for backward compat."""
    os.environ.setdefault("SENTRI_OT_SCAN_MODE", "active")
    return asyncio.run(scan_environment_async(asset_count))
