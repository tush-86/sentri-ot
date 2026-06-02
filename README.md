# Sentri OT — BMS Cybersecurity Compliance Platform

Passive OT security monitoring and compliance reporting for Building Management Systems.
Designed for DESC (Dubai Electronic Security Center) and ISA/IEC 62443 compliance.

---

## Architecture

```
  ┌──────────────────────────────────────────────────────────────┐
  │                     Sentri OT Appliance                      │
  │  ┌──────────────────────────────────────────────────────┐   │
  │  │  Web UI (Vue.js / Vite)        Port 8000             │   │
  │  │        │                                              │   │
  │  │  API (FastAPI / Uvicorn)       Port 8000              │   │
  │  │        │                                              │   │
  │  │  BACnet Scanner (bacpypes)     UDP 47808              │   │
  │  └──────────┬───────────────────────────────────────────┘   │
  └─────────────┼───────────────────────────────────────────────┘
                │
                │         BMS Network
                │     (BACnet/IP, UDP 47808)
                │
  ┌─────────────┼───────────────────────────────────────────────┐
  │             │                                               │
  │  ┌──────────▼──────────┐    ┌──────────▼──────────┐        │
  │  │   BACnet Controller  │    │   BACnet Controller  │        │
  │  │   (e.g. Siemens,     │    │   (e.g. Honeywell,   │        │
  │  │    Johnson Controls) │    │    Schneider, Distech)│       │
  │  └─────────────────────┘    └───────────────────────┘        │
  │                                                              │
  │  ┌──────────▼──────────┐    ┌──────────▼──────────┐        │
  │  │   VAV Controller     │    │   VAV Controller     │        │
  │  │   & Sensors          │    │   & Sensors          │        │
  │  └─────────────────────┘    └───────────────────────┘        │
  └──────────────────────────────────────────────────────────────┘
                │
                │ (Optional) HTTPS 443
                ▼
  ┌──────────────────────────────┐
  │   Sentri Cloud Dashboard     │
  │   (Multi-site aggregation)   │
  └──────────────────────────────┘
```

The Sentri OT appliance passively monitors BACnet/IP traffic on the BMS network segment.
No changes to existing BMS hardware, no software on the BMS server, no network disruption.

---

## Quick Start

### Option 1: Docker (Recommended)

```bash
git clone https://github.com/tush-86/flying-unicorn.git sentri-ot
cd sentri-ot
cp .env.example .env
# Edit .env to configure networks
docker compose up -d
```

Open **http://localhost:8000**

### Option 2: Raspberry Pi

```bash
# Flash Raspberry Pi OS Lite to SD card
# Enable SSH, connect to BMS network
ssh pi@sentri-ot.local
curl -sSL https://raw.githubusercontent.com/tush-86/flying-unicorn/main/scripts/install.sh | sudo bash
```

### Option 3: Local Development

```bash
# Backend
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
SENTRI_OT_SCAN_MODE=simulate uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# Frontend (separate terminal)
cd frontend
npm install
npm run dev
```

---

## Deployment Architecture

The Sentri OT appliance is designed to run on a **Raspberry Pi 5** (or equivalent single-board computer) deployed directly on the BMS network segment.

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU       | ARM Cortex-A72 (4 cores) | Raspberry Pi 5 (BCM2712) |
| RAM       | 2 GB | 4 GB+ |
| Storage   | 16 GB SD card | 32 GB+ SSD (via USB or NVMe HAT) |
| Network   | 1x Ethernet (100 Mbps) | 1x Ethernet (1 Gbps) |
| Power     | 5V/3A USB-C | PoE+ HAT (802.3at) |

Installation:
- **Raspberry Pi 5** (4GB+ RAM) or equivalent ARM SBC
- **32GB+** SD card or SSD for reliable storage
- **PoE HAT** or USB-C power supply
- Connected to **BMS network switch** via Ethernet

### Network Requirements

- Same **VLAN/subnet** as BACnet controllers
- **UDP 47808** (BACnet/IP) must be reachable
- Outbound **HTTPS (443)** to Sentri cloud (optional, for multi-site aggregation)
- **No changes** to existing BMS network configuration required

---

## How It Works

1. **Passive Discovery** — Listens on UDP 47808 for BACnet I-Am messages broadcast by controllers
2. **Who-Is Broadcast** — Sends periodic Who-Is broadcasts (standard BACnet behavior, no disruption)
3. **Device Fingerprinting** — Identifies vendor, model, firmware version from I-Am responses
4. **Compliance Evaluation** — Maps findings to DESC ICS/OT and IEC 62443 control requirements
5. **Continuous Monitoring** — Optional COV (Change of Value) subscription for real-time change detection
6. **Report Generation** — Generates PDF compliance reports ready for DESC inspection

### Scan Modes

| Mode | Description | BACnet Impact |
|------|-------------|---------------|
| `passive` | Listen only — captures existing BACnet traffic | **None.** No network packets sent |
| `active`  | Send Who-Is broadcasts to discover controllers | Minimal — standard BACnet discovery |
| `simulate` | Generate realistic simulated BMS data | **None.** For demos and development |

---

## Compliance Coverage

### DESC (Dubai Electronic Security Center) — ICS/OT Standard

| Domain | Controls | Status |
|--------|----------|--------|
| **Asset Management** | AST-01 to AST-05 | ✅ Mapped |
| **Identity & Access Management** | IAM-01 to IAM-06 | ✅ Mapped |
| **Network Security** | NWS-01 to NWS-08 | ✅ Mapped |
| **System & Communication Protection** | SCP-01 to SCP-05 | ✅ Mapped |
| **Logging & Monitoring** | LOG-01 to LOG-04 | ✅ Mapped |
| **Vulnerability Management** | VLM-01 to VLM-04 | ✅ Mapped |
| **Incident Response** | IR-01 to IR-04 | ✅ Mapped |
| **Business Continuity** | BCM-01 to BCM-04 | ✅ Mapped |
| **Physical Security** | PHS-01 to PHS-03 | ✅ Mapped |
| **Supply Chain Security** | SCS-01 to SCS-03 | ✅ Mapped |

### ISA/IEC 62443-3-3

Security Requirements SR 1.1 through SR 7.8 — Full system security requirements coverage for:
- Identification and authentication control (SR 1.x)
- Use control (SR 2.x)
- System integrity (SR 3.x)
- Data confidentiality (SR 4.x)
- Restricted data flow (SR 5.x)
- Timely response to events (SR 6.x)
- Resource availability (SR 7.x)

---

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `SENTRI_OT_SCAN_MODE` | `passive` | Scan mode: `passive`, `active`, or `simulate` |
| `SENTRI_OT_SCAN_NETWORKS` | *(auto)* | CIDR networks to scan (comma-separated) |
| `SENTRI_OT_SCAN_INTERVAL` | `60` | Auto-scan interval in minutes (`0` = manual only) |
| `SENTRI_OT_DB_PATH` | `/data/sentri_ot.db` | SQLite database file path |

### CORS Configuration

For local development with the frontend dev server (Vite on port 5173), add the origin:

```bash
SENTRI_OT_CORS_ORIGINS=http://localhost:5173,http://localhost:8000
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check |
| `GET` | `/api/devices` | List discovered BACnet devices |
| `GET` | `/api/devices/{id}` | Device details |
| `POST` | `/api/scan` | Trigger an ad-hoc network scan |
| `GET` | `/api/scans` | List scan history |
| `GET` | `/api/compliance/overview` | Compliance status summary |
| `GET` | `/api/compliance/desc` | DESC ICS/OT control mapping |
| `GET` | `/api/compliance/iec62443` | IEC 62443-3-3 control mapping |
| `GET` | `/api/reports` | List generated compliance reports |
| `POST` | `/api/reports/generate` | Generate a compliance report (PDF) |
| `GET` | `/api/reports/{id}/download` | Download a generated report |

### Example: Trigger a scan

```bash
curl -X POST http://localhost:8000/api/scan
```

### Example: Get compliance overview

```bash
curl http://localhost:8000/api/compliance/overview
```

---

## Demo Mode

```bash
SENTRI_OT_SCAN_MODE=simulate docker compose up -d
```

Generates realistic simulated BMS network data with hundreds of BACnet devices for demonstrations, testing, and compliance walkthroughs. No actual BACnet network required.

---

## Maintenance

### View logs

```bash
# Docker
docker compose logs -f

# Systemd deployment
sudo journalctl -u sentri-ot -f
```

### Update

```bash
# Docker
docker compose pull
docker compose up -d

# Systemd deployment
sudo /opt/sentri-ot/scripts/update.sh
```

### BACnet connectivity test

```bash
sudo /opt/sentri-ot/scripts/bacnet_test.sh
```

---

## Security

- This tool performs **ONLY passive BACnet monitoring by default**
- **No active probing** of BMS controllers without explicit user configuration
- `active` mode requires explicit opt-in and authorization from the BMS owner
- All data stored locally in SQLite database — no cloud egress without user consent
- Runs as non-root `sentri` user inside the container

---

## License

MIT — see [LICENSE](LICENSE) file for details.


## Compliance Scope Notes

Sentri OT provides evidence-based alignment scoring for the DESC ICS/OT Security Standard and ISA/IEC 62443-3-3 base security requirements using observable BMS/BACnet telemetry and configuration evidence. It is not a certification tool and does not claim official DESC or IEC certification. DESC ISR v3 is treated as governance context only unless organization-level ISR evidence is added. DESC IoT Security Standard assessment is not implemented yet and should be added as a separate module before presenting IoT compliance coverage.

For real deployments, set `SENTRI_OT_API_KEY` before exposing the API outside a trusted lab/LAN and set `SENTRI_OT_CORS_ORIGINS` to the production origin.
