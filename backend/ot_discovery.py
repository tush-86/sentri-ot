"""Sentri OT - BACnet discovery engine (Windows hotfix build).

This replacement keeps the public API expected by the backend:
- scan_environment_async()
- scan_environment()
- scan_real_ot_environment()

It uses a known-good raw BACnet/IP Who-Is flow tested on the live BMS PC:
- local BACnet NIC: 192.168.1.205
- broadcast: 192.168.1.255
- UDP/47808

Environment overrides:
- SENTRI_OT_SCAN_MODE=passive|active|simulate
- SENTRI_OT_SCAN_NETWORKS=192.168.1.0/24
- SENTRI_OT_BACNET_LOCAL_IP=192.168.1.205
- SENTRI_OT_BACNET_DISCOVERY=whois|listen|full
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import random
import socket
import struct
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Callable

try:
    from backend.ot_simulator import run_alert_feed, run_compliance_check
except Exception:  # keep module importable even if simulator deps are unavailable
    def run_alert_feed(*args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        return []

    def run_compliance_check(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {"score": 0, "controls": []}


BACNET_VENDORS: dict[int, str] = {
    2: "Johnson Controls",
    5: "Honeywell",
    7: "Siemens",
    8: "Delta Controls",
    15: "Trane",
    16: "Lutron",
    24: "Automated Logic",
    33: "Carrier",
    42: "Schneider Electric",
    65: "Distech Controls",
    95: "Reliable Controls",
    116: "Contemporary Controls",
    127: "KMC Controls",
    133: "Alerton",
    140: "EasyIO",
    260: "Loytec",
    330: "Yardi",
    347: "Neptronic",
    410: "Belimo",
    458: "Sauter",
}

# Vendor-specific model defaults when ReadProperty is not available
VENDOR_DEFAULT_MODELS: dict[int, str] = {
    7: "Siemens PXC Controller",
    5: "Honeywell CIPer Controller",
    2: "Johnson Controls FEC Controller",
    15: "Trane UC Controller",
    8: "Delta Controls eBCON Controller",
    42: "Schneider Electric AS-P Controller",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_mode() -> str:
    return os.environ.get("SENTRI_OT_SCAN_MODE", "passive").lower().strip()


def _get_bacnet_discovery() -> str:
    return os.environ.get("SENTRI_OT_BACNET_DISCOVERY", "whois").lower().strip()


def _get_configured_networks() -> list[ipaddress.IPv4Network]:
    raw = os.environ.get("SENTRI_OT_SCAN_NETWORKS", "").strip()
    networks: list[ipaddress.IPv4Network] = []
    if raw:
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                networks.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                pass
    return networks


def _discover_local_networks() -> list[ipaddress.IPv4Network]:
    configured = _get_configured_networks()
    if configured:
        return configured

    # Deployment-specific safe default for the BACnet Ethernet subnet.
    return [ipaddress.ip_network("192.168.1.0/24", strict=False)]


def _local_bacnet_ip() -> str:
    return os.environ.get("SENTRI_OT_BACNET_LOCAL_IP", "192.168.1.205").strip() or "192.168.1.205"


def _resolve_hostname(addr: str) -> str:
    try:
        return socket.getfqdn(addr)
    except Exception:
        return addr


def _infer_zone(ip_str: str) -> str:
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip_str.startswith("192.168.1."):
            last = int(ip_str.split(".")[-1])
            if 100 <= last <= 120:
                return "BMS Field Controllers"
            if last <= 30:
                return "BMS Supervisory / Server VLAN"
        if ip.is_private:
            return "OT / BMS Network"
    except Exception:
        pass
    return "Unknown"


def _risk_level(vulnerabilities: list[dict[str, Any]]) -> str:
    severities = {str(v.get("severity", "")).lower() for v in vulnerabilities}
    if "critical" in severities:
        return "Critical"
    if "high" in severities:
        return "High"
    if "medium" in severities:
        return "Medium"
    return "Low"


def _build_whois_packet() -> bytes:
    """Construct a known-good BACnet/IP global Who-Is broadcast packet."""
    return bytes([
        0x81, 0x0B, 0x00, 0x0C,  # BVLC: Original-Broadcast-NPDU, len=12
        0x01, 0x20,              # NPDU: version 1, destination present
        0xFF, 0xFF,              # DNET=65535 global broadcast
        0x00,                    # DLEN=0
        0xFF,                    # Hop count=255 for BACnet global broadcast
        0x10,                    # APDU: unconfirmed request
        0x08,                    # service choice: Who-Is
    ])


def _read_bacnet_app_int(buf: bytes, offset: int, tag_number: int) -> tuple[int | None, int]:
    """Read a BACnet application-tagged integer/enumerated value.

    Supports the normal one-, two-, four-byte and extended-length encodings used
    in BACnet I-Am fields.  Returns (value, next_offset); on mismatch it returns
    (None, original_offset).
    """
    if offset >= len(buf):
        return None, offset
    tag = buf[offset]
    if tag & 0x08:  # context-specific bit set; not an application tag
        return None, offset
    if (tag >> 4) != tag_number:
        return None, offset

    length = tag & 0x07
    pos = offset + 1
    if length == 5:  # extended length follows in the next octet
        if pos >= len(buf):
            return None, offset
        length = buf[pos]
        pos += 1
    if length <= 0 or pos + length > len(buf):
        return None, offset
    return int.from_bytes(buf[pos:pos + length], "big"), pos + length


def _parse_i_am(data: bytes, addr: tuple[str, int]) -> dict[str, Any] | None:
    """Parse BACnet I-Am responses.

    BACnet unconfirmed service choices:
    - I-Am = 0x00
    - I-Have = 0x01
    - Who-Is = 0x08

    Live devices returned packets like:
    81 0a 00 14 01 00 10 00 c4 02 00 00 66 22 05 c4 91 00 21 07
    """
    try:
        if len(data) < 8 or data[0] != 0x81:
            return None
        bvlc_len = int.from_bytes(data[2:4], "big")
        if bvlc_len > len(data):
            return None
        if data[1] not in (0x0A, 0x04):  # Original-Unicast-NPDU or Forwarded-NPDU
            return None

        # I-Am APDU marker: Unconfirmed-Request-PDU (0x10), service choice I-Am (0x00).
        # Search only after the BVLC header to avoid matching length/origin fields.
        marker = data.find(bytes([0x10, 0x00]), 4)
        if marker < 0:
            return None

        rest = data[marker + 2:]
        device_id: int | None = None
        vendor_id: int | None = None
        max_apdu: int | None = None
        segmentation = "Unknown"

        # Context tag 0, length 4: object identifier. For Device object, type=8.
        for i in range(0, max(0, len(rest) - 4)):
            if rest[i] != 0xC4:
                continue
            raw_id = struct.unpack_from("!I", rest, i + 1)[0]
            obj_type = (raw_id >> 22) & 0x3FF
            instance = raw_id & 0x3FFFFF
            if obj_type != 8:
                continue

            device_id = instance
            tail = rest[i + 5:]

            pos = 0
            max_apdu, pos = _read_bacnet_app_int(tail, pos, 2)
            seg_value, next_pos = _read_bacnet_app_int(tail, pos, 9)
            if seg_value is not None:
                segmentation = str(seg_value)
                pos = next_pos
            vendor_id, _ = _read_bacnet_app_int(tail, pos, 2)
            break

        if device_id is None:
            return None

        return {
            "device_id": device_id,
            "vendor_id": vendor_id,
            "vendor_name": BACNET_VENDORS.get(vendor_id, "Unknown") if vendor_id is not None else "Unknown",
            "segmentation": segmentation,
            "max_apdu": max_apdu,
            "ip": addr[0],
            "port": addr[1],
        }
    except Exception:
        return None


# ── BACnet ReadProperty for device enrichment ───────────────────────────────
# After Who-Is/I-Am discovery, we send unicast ReadProperty requests to each
# controller to pull firmware, model, vendor name, object names, and object
# count.  These are confirmed BACnet requests (expect Complex-ACK replies).


BACNET_OBJECT_DEVICE = 8

# Standard BACnet property identifiers (ASHRAE 135-2020)
BACNET_PROP_FIRMWARE_REVISION = 44
BACNET_PROP_MODEL_NAME = 70
BACNET_PROP_OBJECT_NAME = 77
BACNET_PROP_OBJECT_LIST = 76
BACNET_PROP_VENDOR_NAME = 121
BACNET_PROP_APPLICATION_SW_VERSION = 12



def _encode_context_unsigned(tag_number: int, value: int) -> bytes:
    """Encode a BACnet context-tagged unsigned integer/object identifier."""
    if value < 0:
        raise ValueError("BACnet unsigned value cannot be negative")
    if value <= 0xFF:
        raw = value.to_bytes(1, "big")
    elif value <= 0xFFFF:
        raw = value.to_bytes(2, "big")
    elif value <= 0xFFFFFF:
        raw = value.to_bytes(3, "big")
    else:
        raw = value.to_bytes(4, "big")
    if len(raw) <= 4:
        return bytes([(tag_number << 4) | 0x08 | len(raw)]) + raw
    return bytes([(tag_number << 4) | 0x08 | 0x05, len(raw)]) + raw


def _build_read_property_request(
    device_instance: int,
    property_id: int,
    object_type: int = BACNET_OBJECT_DEVICE,
    object_instance: int | None = None,
    invoke_id: int = 1,
    array_index: int | None = None,
) -> bytes:
    """Build a standards-compliant BACnet/IP Confirmed-Request ReadProperty.

    Packet layout:
    - BVLC Original-Unicast-NPDU
    - NPDU version 1, no destination/source
    - APDU Confirmed-Request with segmented-response accepted and max APDU 480
    - Service choice 0x0C (ReadProperty)
    - objectIdentifier context tag 0, propertyIdentifier context tag 1,
      optional arrayIndex context tag 2
    """
    instance = device_instance if object_instance is None else object_instance
    obj_id = ((object_type & 0x3FF) << 22) | (int(instance) & 0x3FFFFF)

    apdu = bytes([
        0x04,              # Confirmed-Request-PDU, segmented response accepted
        0x05,              # max-segments unspecified, max-APDU 480 octets
        invoke_id & 0xFF,
        0x0C,              # ReadProperty service choice
        0x0C,              # context tag 0, length 4: Object Identifier
    ]) + struct.pack("!I", obj_id) + _encode_context_unsigned(1, int(property_id))

    if array_index is not None:
        apdu += _encode_context_unsigned(2, int(array_index))

    npdu = bytes([0x01, 0x00]) + apdu  # version 1, APDU follows, no DNET/SNET
    return struct.pack("!BBH", 0x81, 0x0A, 4 + len(npdu)) + npdu


def _build_read_property_multiple_request(
    device_instance: int,
    property_ids: list[int],
    object_type: int = BACNET_OBJECT_DEVICE,
    invoke_id: int = 1,
) -> bytes:
    """Backward-compatible wrapper.

    Older code used this name while actually issuing one ReadProperty request at
    a time.  Keep the API but route to the corrected ReadProperty builder.
    """
    prop_id = property_ids[0] if property_ids else BACNET_PROP_OBJECT_NAME
    return _build_read_property_request(
        device_instance=device_instance,
        property_id=prop_id,
        object_type=object_type,
        invoke_id=invoke_id,
    )


def _bacnet_apdu_from_bvll(data: bytes) -> bytes | None:
    """Return the APDU bytes from a BACnet/IP BVLL packet."""
    if len(data) < 7 or data[0] != 0x81:
        return None
    bvlc_len = int.from_bytes(data[2:4], "big")
    if bvlc_len > len(data) or bvlc_len < 6:
        return None

    # Forwarded-NPDU includes originating IP + port after the BVLC header.
    pos = 10 if data[1] == 0x04 else 4
    if pos + 2 > bvlc_len or data[pos] != 0x01:
        return None

    control = data[pos + 1]
    pos += 2

    if control & 0x20:  # destination specifier present
        if pos + 3 > bvlc_len:
            return None
        dlen = data[pos + 2]
        pos += 3 + dlen  # DNET(2), DLEN(1), DADR
        if pos >= bvlc_len:
            return None
        pos += 1  # Hop count

    if control & 0x08:  # source specifier present
        if pos + 3 > bvlc_len:
            return None
        slen = data[pos + 2]
        pos += 3 + slen  # SNET(2), SLEN(1), SADR

    if control & 0x80:  # network layer message, not an APDU
        return None

    if pos >= bvlc_len:
        return None
    return data[pos:bvlc_len]


def _decode_bacnet_tag_value(buf: bytes) -> tuple[str | int | dict[str, int] | list[dict[str, int]] | bytes | None, int]:
    """Decode the BACnet application value at the start of *buf*."""
    if not buf:
        return None, 0
    tag = buf[0]
    tag_number = (tag >> 4) & 0x0F
    is_context = bool(tag & 0x08)
    length_code = tag & 0x07

    if length_code in (6, 7):  # opening/closing tag
        return None, 1

    pos = 1
    if length_code == 5:
        if pos >= len(buf):
            return None, 0
        length = buf[pos]
        pos += 1
    else:
        length = length_code
    if pos + length > len(buf):
        return None, 0

    raw = buf[pos:pos + length]
    consumed = pos + length

    if is_context:
        return int.from_bytes(raw, "big") if raw else None, consumed

    if tag_number == 7:  # CharacterString
        if not raw:
            return "", consumed
        encoding = raw[0]
        payload = raw[1:]
        if encoding == 0:
            return payload.decode("latin-1", errors="replace"), consumed
        if encoding == 4:
            return payload.decode("utf-8", errors="replace"), consumed
        if encoding == 3:
            return payload.decode("utf-32-be", errors="replace"), consumed
        if encoding == 5:
            return payload.decode("utf-16-be", errors="replace"), consumed
        return payload.decode("latin-1", errors="replace"), consumed
    if tag_number in (2, 9):  # Unsigned / Enumerated
        return int.from_bytes(raw, "big"), consumed
    if tag_number == 12 and length == 4:  # ObjectIdentifier
        obj_raw = int.from_bytes(raw, "big")
        return {"object_type": (obj_raw >> 22) & 0x3FF, "instance": obj_raw & 0x3FFFFF}, consumed
    if tag_number == 4 and length == 4:  # Real
        try:
            return round(struct.unpack("!f", raw)[0], 3), consumed
        except Exception:
            return raw, consumed
    if tag_number == 1:  # Boolean, length code carries value
        return bool(length_code), consumed
    return raw.hex(), consumed


def _parse_read_property_ack(data: bytes) -> str | int | dict[str, int] | list[dict[str, int]] | bytes | None:
    """Parse a BACnet Complex-ACK response to ReadProperty."""
    try:
        apdu = _bacnet_apdu_from_bvll(data)
        if not apdu or len(apdu) < 3:
            return None

        pdu_type = apdu[0] >> 4
        if pdu_type == 5:  # Error PDU
            return None
        if pdu_type != 3:  # Complex-ACK
            return None
        if len(apdu) < 3 or apdu[2] != 0x0C:
            return None

        tail = apdu[3:]  # invoke id + service choice already consumed

        # Skip objectIdentifier context tag 0.
        if len(tail) >= 5 and tail[0] == 0x0C:
            tail = tail[5:]
        else:
            return None

        # Skip propertyIdentifier context tag 1 (length may be 1/2/4).
        if not tail or ((tail[0] >> 4) & 0x0F) != 1 or not (tail[0] & 0x08):
            return None
        _, consumed = _decode_bacnet_tag_value(tail)
        if consumed <= 0:
            return None
        tail = tail[consumed:]

        # Optional array index context tag 2.
        if tail and ((tail[0] >> 4) & 0x0F) == 2 and (tail[0] & 0x08):
            _, consumed = _decode_bacnet_tag_value(tail)
            if consumed > 0:
                tail = tail[consumed:]

        # Result is wrapped in context tag 3 opening/closing: 0x3E ... 0x3F.
        if tail and tail[0] == 0x3E:
            tail = tail[1:]
        if not tail:
            return None

        # Object_List often returns multiple ObjectIdentifier values; collect them.
        objects: list[dict[str, int]] = []
        pos = 0
        while pos < len(tail):
            if tail[pos] == 0x3F:  # closing tag 3
                break
            value, consumed = _decode_bacnet_tag_value(tail[pos:])
            if consumed <= 0:
                pos += 1
                continue
            if isinstance(value, dict) and "object_type" in value:
                objects.append(value)
                pos += consumed
                continue
            if objects:
                break
            return value
        if objects:
            return objects
        return None
    except Exception:
        return None
def _read_property_with_socket(
    sock: socket.socket,
    ip: str,
    device_instance: int,
    property_id: int,
    object_type: int = BACNET_OBJECT_DEVICE,
    object_instance: int | None = None,
    invoke_id: int = 1,
    timeout: float = 2.0,
) -> Any:
    """Send one ReadProperty request over an existing UDP socket."""
    req = _build_read_property_request(
        device_instance=device_instance,
        property_id=property_id,
        object_type=object_type,
        object_instance=object_instance,
        invoke_id=invoke_id,
    )
    try:
        sock.sendto(req, (ip, 47808))
        saved = sock.gettimeout()
        sock.settimeout(timeout)
        deadline = time.monotonic() + timeout
        try:
            while time.monotonic() < deadline:
                data, _ = sock.recvfrom(8192)
                value = _parse_read_property_ack(data)
                if value is not None:
                    return value
        finally:
            sock.settimeout(saved)
    except (OSError, socket.timeout):
        return None
    return None


def _read_property_sync(
    sock: socket.socket,
    ip: str,
    device_instance: int,
    property_id: int,
    timeout: float = 2.0,
) -> Any:
    """Backward-compatible helper used by legacy enrichment paths."""
    return _read_property_with_socket(sock, ip, device_instance, property_id, timeout=timeout)


def read_bacnet_property(
    ip: str,
    device_instance: int,
    property_id: int,
    object_type: int = BACNET_OBJECT_DEVICE,
    object_instance: int | None = None,
    timeout: float = 2.0,
    local_ip: str | None = None,
) -> Any:
    """Public BACnet ReadProperty helper for API/UI diagnostics.

    Opens a short-lived UDP socket, sends a standards-compliant BACnet/IP
    ReadProperty request, and returns the decoded Complex-ACK value.  This is
    intentionally synchronous so it can be used from worker threads or wrapped
    with asyncio.to_thread() by FastAPI endpoints.
    """
    bind_ip = local_ip or _local_bacnet_ip()
    last_error: Exception | None = None
    for candidate in (bind_ip, "0.0.0.0", ""):
        sock: socket.socket | None = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((candidate, 0) if candidate else ("", 0))
            return _read_property_with_socket(
                sock=sock,
                ip=ip,
                device_instance=int(device_instance),
                property_id=int(property_id),
                object_type=int(object_type),
                object_instance=int(object_instance) if object_instance is not None else None,
                timeout=timeout,
            )
        except Exception as exc:
            last_error = exc
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
    raise RuntimeError(f"Could not open BACnet UDP socket for ReadProperty: {last_error}")


def _enrich_device_sync(
    sock: socket.socket,
    device: dict[str, Any],
    timeout: float = 1.5,
) -> dict[str, Any]:
    """Read Device-object properties to fill firmware, model, vendor, and object count.

    Returns a shallow copy of *device* with real values from the controller
    replacing the "Unknown"/"None" defaults set during I-Am discovery.
    """
    enriched = dict(device)
    ip = str(device.get("ip", ""))
    dev_id = device.get("device_id")
    if not ip or dev_id is None:
        return enriched

    prop_reads: list[tuple[int, str]] = [
        (BACNET_PROP_FIRMWARE_REVISION, "firmware"),
        (BACNET_PROP_MODEL_NAME, "model"),
        (BACNET_PROP_OBJECT_NAME, "name"),
        (BACNET_PROP_VENDOR_NAME, "vendor"),
        (BACNET_PROP_APPLICATION_SW_VERSION, "app_version"),
    ]

    # Send one ReadProperty per property (YABE-compatible: individual
    # ReadProperty calls, not batch ReadPropertyMultiple)
    for prop_id, field in prop_reads:
        value = _read_property_with_socket(sock, ip, int(dev_id), prop_id, timeout=timeout)
        if value is not None and isinstance(value, str) and value.strip():
            if field == "firmware":
                enriched["firmware"] = value
                enriched["firmware_version"] = value
            elif field == "model":
                enriched["model"] = value
                enriched["device_type"] = value
            elif field == "name":
                enriched["name"] = value
                enriched["hostname"] = value
            elif field == "vendor":
                enriched["vendor"] = value
                enriched["vendor_name"] = value
            elif field == "app_version":
                if not enriched.get("firmware_version") or enriched["firmware_version"] == "Unknown":
                    enriched["firmware"] = value
                    enriched["firmware_version"] = value

    obj_list = _read_property_with_socket(sock, ip, int(dev_id), BACNET_PROP_OBJECT_LIST, timeout=3.0)
    if isinstance(obj_list, list):
        enriched["object_count"] = len(obj_list)
    elif isinstance(obj_list, int):
        enriched["object_count"] = obj_list

    return enriched


def _read_object_names_sync(
    sock: socket.socket,
    ip: str,
    device_instance: int,
    max_objects: int = 30,
    timeout: float = 1.5,
) -> list[dict[str, Any]]:
    """Enumerate the first *max_objects* from the controller's object-list
    and read each object's name and type.

    Many Siemens controllers have 100+ objects; we cap at *max_objects* to
    keep scan times reasonable.  The full list can be read on-demand via the
    asset-detail page in a future release.
    """
    objects: list[dict[str, Any]] = []

    # Step 1: read object-list and collect ObjectIdentifier values.
    try:
        obj_list = _read_property_with_socket(
            sock, ip, int(device_instance), BACNET_PROP_OBJECT_LIST, timeout=timeout
        )
        if isinstance(obj_list, list):
            for item in obj_list[:max_objects]:
                obj_type = int(item.get("object_type", BACNET_OBJECT_DEVICE))
                obj_instance = int(item.get("instance", 0))
                if obj_type != BACNET_OBJECT_DEVICE:
                    objects.append({"object_type": obj_type, "instance": obj_instance, "name": None})

        # Step 2: read names for a subset of objects (first 20)
        name_budget = min(20, len(objects))
        for idx in range(name_budget):
            obj = objects[idx]
            name = _read_property_with_socket(
                sock,
                ip,
                int(device_instance),
                BACNET_PROP_OBJECT_NAME,
                object_type=int(obj["object_type"]),
                object_instance=int(obj["instance"]),
                invoke_id=(idx + 2) & 0xFF,
                timeout=1.0,
            )
            if isinstance(name, str) and name.strip():
                objects[idx]["name"] = name

    except (OSError, socket.timeout):
        pass

    return objects


def _enrich_assets_sync(
    devices: list[dict[str, Any]],
    progress_cb: Callable[[int, str], None] | None = None,
) -> dict[int, dict[str, Any]]:
    """Enrich a batch of discovered BACnet devices with ReadProperty.

    Opens one UDP socket, then reads Device-object properties (firmware,
    model, vendor, object count) and enumerates the first N object names
    for each controller.  Returns a dict keyed by device_id.
    """
    local_ip = _local_bacnet_ip()
    enriched: dict[int, dict[str, Any]] = {}
    sock: socket.socket | None = None

    # Windows may reject binding to a specific IP; fall back to auto
    for bind_ip in (local_ip, "0.0.0.0", ""):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((bind_ip, 0) if bind_ip else ("", 0))
            s.settimeout(0.25)
            actual_ip, actual_port = s.getsockname()[:2]
            print(f"[Sentri] Enrichment socket bound on {actual_ip}:{actual_port}")
            sock = s
            break
        except OSError:
            continue
    if sock is None:
        print("[Sentri] Enrichment socket bind failed — skipping ReadProperty")
        return enriched

    try:
        for idx, device in enumerate(devices):
            dev_id = device.get("device_id")
            ip = str(device.get("ip", ""))
            if dev_id is None or not ip:
                continue

            if progress_cb:
                progress_cb(55 + int(30 * idx / max(len(devices), 1)),
                           f"Reading properties from {ip} (device {dev_id})")

            extra = _enrich_device_sync(sock, device, timeout=1.5)
            enriched[dev_id] = extra

            # Read object names for the first few devices
            if idx < 5:
                objects = _read_object_names_sync(sock, ip, dev_id, max_objects=20, timeout=2.0)
                enriched[dev_id]["objects"] = objects
                enriched[dev_id]["object_count"] = len(objects)

    finally:
        try:
            sock.close()
        except OSError:
            pass

    return enriched


def _try_bacpypes_parse(data: bytes, addr: tuple[str, int]) -> dict[str, Any] | None:
    """Optional parser. Raw parser above is the primary path for this deployment."""
    try:
        from bacpypes3.apdu import IAmRequest  # type: ignore[import-not-found]
        from bacpypes3.pdu import PDU  # type: ignore[import-not-found]
    except Exception:
        return None

    try:
        marker = data.find(bytes([0x10, 0x00]))
        pdu_data = data[marker:] if marker >= 0 else data
        iam = IAmRequest()
        iam.decode(PDU(pdu_data))
        vendor_id = int(iam.vendorID) if iam.vendorID is not None else None
        return {
            "device_id": int(iam.iAmDeviceIdentifier[1]) if iam.iAmDeviceIdentifier else None,
            "vendor_id": vendor_id,
            "vendor_name": BACNET_VENDORS.get(vendor_id, "Unknown") if vendor_id is not None else "Unknown",
            "segmentation": str(iam.segmentationSupported) if iam.segmentationSupported else "Unknown",
            "max_apdu": int(iam.maxAPDULengthAccepted) if iam.maxAPDULengthAccepted else None,
            "ip": addr[0],
            "port": addr[1],
        }
    except Exception:
        return None


def _open_bacnet_udp_socket(local_ip: str, progress_cb: Callable[[int, str], None] | None = None) -> socket.socket:
    """Open a UDP socket for BACnet discovery with safe fallbacks.

    Preferred source is local_ip:47808, but Windows often fails if the selected
    NIC/IP differs or another BACnet tool owns 47808. Falling back to an
    ephemeral source port keeps the server responsive and still receives most
    direct I-Am replies because devices reply to the UDP source endpoint.
    """
    # Prefer ephemeral ports.  On systems with an existing BACnet daemon
    # (explorer, Wireshark, or a BMS stack) already bound to UDP 47808,
    # SO_REUSEADDR lets us bind too, but the OS delivers most I-Am replies
    # to the first-bound socket.  Using an ephemeral port avoids the
    # conflict entirely — BACnet devices reply to the source endpoint.
    bind_candidates = [
        (local_ip, 0),
        ("0.0.0.0", 0),
        (local_ip, 47808),
        ("0.0.0.0", 47808),
    ]
    last_error: Exception | None = None
    for bind_addr in bind_candidates:
        sock: socket.socket | None = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(bind_addr)
            sock.settimeout(0.25)
            if progress_cb:
                actual_ip, actual_port = sock.getsockname()[:2]
                progress_cb(6, f"BACnet socket bound on {actual_ip}:{actual_port}")
            return sock
        except Exception as exc:
            last_error = exc
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
    raise RuntimeError(f"Could not bind BACnet UDP socket: {last_error}")


def _blocking_bacnet_discovery(
    timeout: float,
    progress_cb: Callable[[int, str], None] | None = None,
    send_whois: bool = False,
) -> list[dict[str, Any]]:
    """Blocking BACnet socket work. Always run via asyncio.to_thread()."""
    local_ip = _local_bacnet_ip()
    networks = _discover_local_networks()
    discovered: dict[int, dict[str, Any]] = {}

    try:
        with _open_bacnet_udp_socket(local_ip, progress_cb) as sock:
            whois_pkt = _build_whois_packet()
            if send_whois:
                for idx, network in enumerate(networks):
                    bcast_addr = str(network.broadcast_address)
                    if progress_cb:
                        pct = 10 + (idx * 20 // max(len(networks), 1))
                        progress_cb(pct, f"Sending BACnet Who-Is to {bcast_addr}:47808")
                    for _ in range(3):
                        try:
                            sock.sendto(whois_pkt, (bcast_addr, 47808))
                        except OSError:
                            pass
                        time.sleep(0.1)

            if progress_cb:
                progress_cb(30, "Listening for BACnet I-Am responses")

            deadline = time.monotonic() + max(0.1, timeout)
            while time.monotonic() < deadline:
                try:
                    data, addr = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break

                device = _parse_i_am(data, addr)
                if device is None:
                    device = _try_bacpypes_parse(data, addr)
                if device is None:
                    continue

                dev_id = device.get("device_id")
                if dev_id is None:
                    continue
                discovered[int(dev_id)] = device

    except Exception as exc:
        if progress_cb:
            progress_cb(50, f"BACnet discovery error: {exc}")

    if progress_cb:
        progress_cb(50, f"Discovered {len(discovered)} BACnet devices")

    return list(discovered.values())


async def _passive_bacnet_discovery(
    timeout: float = 12.0,
    progress_cb: Callable[[int, str], None] | None = None,
    send_whois: bool = False,
) -> list[dict[str, Any]]:
    """Listen for BACnet/IP I-Am responses without blocking Uvicorn.

    send_whois is intentionally False for passive mode.  Active/full scans set
    it to True unless SENTRI_OT_BACNET_DISCOVERY=listen.
    """
    if progress_cb:
        action = "Who-Is discovery" if send_whois else "listen-only discovery"
        progress_cb(5, f"Preparing BACnet {action} on preferred NIC {_local_bacnet_ip()}")
    return await asyncio.to_thread(_blocking_bacnet_discovery, timeout, progress_cb, send_whois)


async def _active_bacnet_read_property(device: dict[str, Any]) -> dict[str, Any]:
    """Placeholder for future point/object reads. Discovery-only demo remains safe."""
    return {**device, "objects": [], "points_count": 0}


async def _full_bacnet_discovery(
    timeout: float = 12.0,
    progress_cb: Callable[[int, str], None] | None = None,
) -> list[dict[str, Any]]:
    devices = await _passive_bacnet_discovery(
        timeout=timeout,
        progress_cb=progress_cb,
        send_whois=_get_bacnet_discovery() != "listen",
    )
    enriched: list[dict[str, Any]] = []
    for dev in devices:
        enriched.append(await _active_bacnet_read_property(dev))
    return enriched


async def _active_tcp_port_scan(ip: str, ports: list[int] | None = None, timeout: float = 0.25) -> list[int]:
    """Non-blocking lightweight TCP check for explicitly selected active mode."""
    ports = ports or [47808, 502, 4840]
    open_ports: list[int] = []
    for port in ports:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
            writer.close()
            await writer.wait_closed()
            open_ports.append(port)
        except Exception:
            pass
    return open_ports


async def _active_scan_host(ip: str) -> dict[str, Any] | None:
    ports = await _active_tcp_port_scan(ip)
    if not ports:
        return None
    return _build_active_asset(ip, ports)


def _build_bacnet_asset(device: dict[str, Any]) -> dict[str, Any]:
    ip = str(device.get("ip", ""))
    vendor_id = device.get("vendor_id")
    vendor_name = device.get("vendor_name") or (BACNET_VENDORS.get(vendor_id, "Unknown") if vendor_id is not None else "Unknown")
    vulnerabilities = [
        {
            "id": "BACNET-IP-OPEN",
            "severity": "Medium",
            "title": "BACnet/IP service exposed on UDP/47808",
            "description": "BACnet/IP devices commonly expose discovery and management services without authentication.",
            "recommendation": "Restrict BACnet/IP to the BMS VLAN, monitor Who-Is/I-Am traffic, and control routed access via BBMD/firewall policy.",
            "protocol": "BACnet/IP",
        }
    ]

    device_id = device.get("device_id")
    now = _utc_now()
    return {
        "id": f"bacnet-{device_id or ip}",
        "asset_id": f"bacnet-{device_id or ip}",
        "name": f"BACnet Device {device_id}" if device_id is not None else f"BACnet Device {ip}",
        "hostname": _resolve_hostname(ip) if ip else "Unknown",
        "ip": ip,
        "ip_address": ip,
        "mac": None,
        "protocol": "BACnet/IP",
        "protocols": ["BACnet/IP"],
        "ports": [47808],
        "device_type": VENDOR_DEFAULT_MODELS.get(vendor_id, "BACnet Controller"),
        "type": "BMS Controller",
        "vendor": vendor_name,
        "vendor_id": vendor_id,
        "device_id": device_id,
        "model": VENDOR_DEFAULT_MODELS.get(vendor_id, "Unknown"),
        "firmware": "Unknown",
        "firmware_version": "Unknown",
        "segmentation": device.get("segmentation", "Unknown"),
        "max_apdu": device.get("max_apdu"),
        "zone": _infer_zone(ip),
        "criticality": "Medium",
        "risk_level": _risk_level(vulnerabilities),
        "vulnerabilities": vulnerabilities,
        "status": "online",
        "security_status": "Monitored",
        "last_seen": now,
        "discovered_at": now,
        "segmentation_zone": _infer_zone(ip),
        "auth_method": "None",
        "vendor_name": vendor_name,
        "object_count": device.get("points_count", 0),
        "objects": device.get("objects", []),
        "points_count": device.get("points_count", 0),
        "metadata": device,
    }


def _build_active_asset(ip: str, ports: list[int]) -> dict[str, Any]:
    now = _utc_now()
    protocols = []
    if 47808 in ports:
        protocols.append("BACnet/IP")
    if 502 in ports:
        protocols.append("Modbus/TCP")
    if 4840 in ports:
        protocols.append("OPC-UA")
    return {
        "id": f"host-{ip}",
        "asset_id": f"host-{ip}",
        "name": f"OT Host {ip}",
        "hostname": _resolve_hostname(ip),
        "ip": ip,
        "ip_address": ip,
        "protocol": protocols[0] if protocols else "Unknown",
        "protocols": protocols,
        "ports": ports,
        "device_type": "OT Host",
        "type": "OT Host",
        "vendor": "Unknown",
        "zone": _infer_zone(ip),
        "criticality": "Medium",
        "risk_level": "Medium" if ports else "Low",
        "vulnerabilities": [],
        "status": "online",
        "last_seen": now,
        "discovered_at": now,
    }


async def _run_passive_scan(progress_cb: Callable[[int, str], None] | None = None) -> list[dict[str, Any]]:
    devices = await _passive_bacnet_discovery(timeout=12.0, progress_cb=progress_cb, send_whois=False)
    return [_build_bacnet_asset(d) for d in devices]


async def _run_active_scan(progress_cb: Callable[[int, str], None] | None = None) -> list[dict[str, Any]]:
    # Step 1: BACnet Who-Is / I-Am discovery (fast)
    devices = await _full_bacnet_discovery(timeout=12.0, progress_cb=progress_cb)
    assets = [_build_bacnet_asset(d) for d in devices]

    # Step 2: Enrich each device with ReadProperty (firmware, model, vendor,
    #          object count, object names).  Run in a thread so Uvicorn stays
    #          responsive.
    if devices and progress_cb:
        progress_cb(55, f"Enriching {len(devices)} BACnet devices with ReadProperty")
    enriched = await asyncio.to_thread(_enrich_assets_sync, devices, progress_cb)
    # Merge enrichment back into assets
    for asset in assets:
        dev_id = asset.get("device_id")
        if dev_id is not None and dev_id in enriched:
            extra = enriched[dev_id]
            for key in ("firmware", "firmware_version", "model", "name", "hostname",
                        "vendor", "vendor_name", "object_count", "objects"):
                if key in extra and extra[key] is not None:
                    asset[key] = extra[key]
            if extra.get("device_type"):
                asset["device_type"] = extra["device_type"]

    # Step 3: Optional TCP scan ("full" discovery mode only)
    networks = _discover_local_networks()
    if _get_bacnet_discovery() == "full":
        for network in networks:
            # Cap to avoid scanning entire large networks by accident; do not materialize huge networks.
            for idx, ip in enumerate(network.hosts()):
                if idx >= 254:
                    break
                if progress_cb and idx % 25 == 0:
                    progress_cb(55, f"Optional TCP OT check on {ip}")
                asset = await _active_scan_host(str(ip))
                if asset and not any(a.get("ip") == asset.get("ip") for a in assets):
                    assets.append(asset)
    return assets


def _build_simulated_assets(count: int = 20) -> list[dict[str, Any]]:
    assets = []
    for i in range(count):
        ip = f"192.168.1.{100 + i}"
        assets.append(_build_bacnet_asset({
            "device_id": 100 + i,
            "vendor_id": random.choice([5, 7, 42, 65, 95]),
            "vendor_name": "Simulated Vendor",
            "segmentation": "Unknown",
            "max_apdu": 1476,
            "ip": ip,
            "port": 47808,
        }))
    return assets


def _compute_summary(assets: list[dict[str, Any]]) -> dict[str, Any]:
    protocols = Counter()
    vendors = Counter()
    zones = Counter()
    risk = Counter()
    for asset in assets:
        for proto in asset.get("protocols", []) or [asset.get("protocol", "Unknown")]:
            protocols[proto or "Unknown"] += 1
        vendors[asset.get("vendor", "Unknown")] += 1
        zones[asset.get("zone", "Unknown")] += 1
        risk[asset.get("risk_level", "unknown")] += 1

    return {
        "total_assets": len(assets),
        "protocols": dict(protocols),
        "vendors": dict(vendors),
        "zones": dict(zones),
        "risk_levels": dict(risk),
        "online_assets": sum(1 for a in assets if a.get("status") == "online"),
        "bacnet_devices": sum(1 for a in assets if "BACnet/IP" in (a.get("protocols") or [])),
    }


async def scan_environment_async(
    asset_count: int | None = None,
    progress_cb: Callable[[int, str], None] | None = None,
) -> dict[str, Any]:
    """Run environment scan based on SENTRI_OT_SCAN_MODE."""
    mode = _get_mode()
    scan_id = str(uuid.uuid4())
    started_at = _utc_now()

    if progress_cb:
        progress_cb(1, f"Starting Sentri-OT scan in {mode} mode")

    if mode == "simulate":
        assets = _build_simulated_assets(asset_count or 20)
    elif mode == "active":
        assets = await _run_active_scan(progress_cb=progress_cb)
    else:
        assets = await _run_passive_scan(progress_cb=progress_cb)

    summary = _compute_summary(assets)
    compliance_score = 0

    result: dict[str, Any] = {
        "scan_id": scan_id,
        "generated_at": started_at,
        "scan_type": mode,
        "status": "complete",
        "progress": 100,
        "message": "Scan complete",
        "started_at": started_at,
        "completed_at": _utc_now(),
        "assets": assets,
        "devices": assets,
        "total_assets": len(assets),
        "devices_found": len(assets),
        "summary": summary,
        "compliance_score": compliance_score,
    }

    try:
        result["compliance"] = run_compliance_check(result) if callable(run_compliance_check) else {"score": compliance_score}
        if isinstance(result["compliance"], dict):
            compliance_score = int(float(result["compliance"].get("score", compliance_score) or 0))
            result["compliance_score"] = compliance_score
            result["summary"]["compliance_score"] = compliance_score
    except Exception as exc:
        result["compliance"] = {"score": compliance_score, "error": str(exc)}

    try:
        result["alerts"] = run_alert_feed(result) if callable(run_alert_feed) else []
    except Exception as exc:
        result["alerts"] = [{
            "id": f"ALERT-SCAN-{scan_id[:8]}",
            "timestamp": _utc_now(),
            "severity": "Info",
            "title": "Alert generation skipped",
            "message": str(exc),
            "asset_id": None,
            "status": "Info",
        }]

    if progress_cb:
        progress_cb(100, f"Scan complete: {len(assets)} assets discovered")

    return result


def scan_environment(asset_count: int | None = None) -> dict[str, Any]:
    """Synchronous wrapper for scan_environment_async."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # This path should rarely be used by FastAPI; return a clear safe result instead of crashing.
            return {
                "scan_id": str(uuid.uuid4()),
                "status": "error",
                "progress": 100,
                "message": "scan_environment called from running event loop; use scan_environment_async",
                "assets": [],
                "devices": [],
                "total_assets": 0,
                "devices_found": 0,
                "summary": _compute_summary([]),
                "compliance_score": 0,
            }
        return loop.run_until_complete(scan_environment_async(asset_count=asset_count))
    except RuntimeError:
        return asyncio.run(scan_environment_async(asset_count=asset_count))


def scan_real_ot_environment(asset_count: int | None = None) -> dict[str, Any]:
    """Compatibility entry point used by older backend code."""
    os.environ.setdefault("SENTRI_OT_SCAN_MODE", "passive")
    os.environ.setdefault("SENTRI_OT_SCAN_NETWORKS", "192.168.1.0/24")
    os.environ.setdefault("SENTRI_OT_BACNET_LOCAL_IP", "192.168.1.205")
    os.environ.setdefault("SENTRI_OT_BACNET_DISCOVERY", "whois")
    return scan_environment(asset_count=asset_count)
