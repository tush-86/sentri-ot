#!/usr/bin/env bash
set -euo pipefail

# Sentri OT -- BACnet Network Connectivity Test
# Sends a Who-Is broadcast and listens for I-Am responses

echo "============================================"
echo "  Sentri OT -- BACnet Connectivity Test"
echo "============================================"
echo ""

if [[ $EUID -ne 0 ]]; then
    echo "[WARN] Packet capture requires root. Consider: sudo $0"
    echo ""
fi

echo "[INFO] Testing BACnet network on UDP port 47808..."
echo ""
echo "[1/3] Listening for BACnet traffic on all interfaces..."
echo "      (capturing up to 10 packets, 5 second timeout)"
echo ""

timeout 5 tcpdump -i any -c 10 'udp port 47808' 2>/dev/null | head -20 || true

echo ""
echo "[2/3] Sending BACnet Who-Is broadcast..."
if command -v nc &>/dev/null; then
    # BACnet/IP Original-Broadcast-NPDU Who-Is packet (BVLC function 0x0B).
    printf '\x81\x0b\x00\x0c\x01\x20\xff\xff\x00\xff\x10\x08' | nc -u -b -w 2 255.255.255.255 47808 2>/dev/null || true
    echo "      Who-Is broadcast sent. Watch for I-Am responses in packet capture."
else
    echo "      netcat not installed; skipping active Who-Is send."
fi

echo ""
echo "[3/3] Summary"
echo "      If you see BACnet packets above:"
echo "        BACnet devices are present and reachable."
echo "      If you see NO packets:"
echo "        No BACnet traffic detected."
echo "        Check that this device is on the same VLAN/subnet"
echo "        as the BMS network with BACnet controllers."
echo ""

exit 0
