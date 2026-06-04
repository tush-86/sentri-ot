#!/usr/bin/env python3
"""
Sentri OT - BACnet Device Simulator
Runs as an external process to simulate BACnet/IP devices responding to Who-Is.
Usage: python3 bacnet_device_simulator.py --device-id 123 --ip 192.168.0.109 --port 47808
"""

import argparse
import socket
import struct
import time
import select
import os


def build_i_am_packet(device_id: int, vendor_id: int = 0, port: int = 47808) -> bytes:
    """Build a BACnet I-Am response (BVLL + NPDU + APDU).

    APDU layout (unconfirmed request, service choice = I-Am = 0x00):
        0x10 0x00
        Application tag 12 [0xC4] + 4-byte BACnetObjectIdentifier (device object type=8)
        Application tag 2 [0x22] + 2-byte Max APDU length accepted (1476)
        Application tag 9 [0x91] + 1-byte segmentation supported (0x03 = no segmentation)
        Application tag 2 [0x22] + 2-byte vendor ID
    """
    # BACnet Object Identifier: type=8 (device), instance=device_id
    obj_id = (8 << 22) | (device_id & 0x3FFFFF)

    # APDU I-Am
    apdu = bytes([
        0x10, 0x00,  # unconfirmed-request, I-Am service
        # Device object identifier (application tag 12, length=4 -> 0xC4)
        0xC4,
    ]) + struct.pack("!I", obj_id)

    # Max APDU length accepted (application tag 2, length=2 -> 0x22)
    apdu += bytes([0x22]) + struct.pack(">H", 1476)

    # Segmentation supported (application tag 9, length=1 -> 0x91)
    apdu += bytes([0x91, 0x03])

    # Vendor ID (application tag 2, length=2 -> 0x22)
    apdu += bytes([0x22]) + struct.pack(">H", vendor_id)

    # NPDU: version=0x01, control=0x20 (no dest, source present, expecting reply)
    # source addr = MAC length 1 + MAC addr (let's use 0xFF for broadcast-like)
    npdu = bytes([
        0x01,  # version
        # Set DNET/DADR/SLEN/SADR/HOP/DMSG correctly for a proper I-Am
        # Actually use control=0x00 for simplest valid NPDU (no dest, no source)
        0x00,
    ]) + apdu

    # BVLL: type=0x81, func=0x0A (Original-Unicast-NPDU) or 0x0B (Original-Broadcast-NPDU)
    # For I-Am from device to requester, Original-Unicast-NPDU (0x0A) is fine.
    bvlci_function = 0x0A
    bvlci_length = 4 + len(npdu)
    bvll = struct.pack("!BBH", 0x81, bvlci_function, bvlci_length) + npdu

    return bvll


def main():
    parser = argparse.ArgumentParser(description="Simulate a BACnet/IP device")
    parser.add_argument("--device-id", type=int, default=123, help="BACnet device instance")
    parser.add_argument("--vendor-id", type=int, default=0, help="Vendor ID (0=ASHRAE)")
    parser.add_argument("--ip", type=str, default="0.0.0.0", help="IP to bind/listen on")
    parser.add_argument("--port", type=int, default=47808, help="UDP port")
    parser.add_argument("--reply-to", type=str, default=None, help="IP to reply to (default: requester)")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.ip, args.port))

    print(f"[{args.device_id}] BACnet device simulator listening on {args.ip}:{args.port}")
    print(f"[{args.device_id}] Vendor ID={args.vendor_id}")
    print(f"[{args.device_id}] Waiting for Who-Is on UDP/{args.port} ...")

    try:
        while True:
            ready, _, _ = select.select([sock], [], [], 1.0)
            if not ready:
                continue
            data, addr = sock.recvfrom(4096)
            if len(data) < 6:
                continue
            # Quick check: BVLL type 0x81 and function 0x0B (broadcast) or 0x0A (unicast)
            if data[0] != 0x81 or data[1] not in (0x0A, 0x0B):
                continue
            # Check APDU for unconfirmed request Who-Is (service choice 0x08)
            if b"\x10\x08" in data or (len(data) >= 6 and data[-2:] == b"\x10\x08"):
                print(f"[{args.device_id}] Received Who-Is from {addr[0]}:{addr[1]}")
                reply_ip = args.reply_to if args.reply_to else addr[0]
                response = build_i_am_packet(args.device_id, args.vendor_id, args.port)
                # Send unicast response back to requester
                sock.sendto(response, (reply_ip, addr[1]))
                print(f"[{args.device_id}] Sent I-Am to {reply_ip}:{addr[1]}")
    except KeyboardInterrupt:
        print(f"\n[{args.device_id}] Simulator exiting.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
