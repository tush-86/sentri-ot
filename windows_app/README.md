# Sentri OT — Windows Desktop App

Native Windows desktop application for Sentri OT, built with PyQt6. Replaces the React web UI with a fast, responsive native experience.

## Features

- **Dashboard**: Real-time stat cards (assets, critical alerts, compliance score, active scans) with summary breakdown.
- **Scan**: Start scans, watch live progress, browse scan history, and inspect per-scan asset details.
- **Assets**: Searchable, filterable, sortable asset inventory. Double-click any asset to open a detail dialog.
- **Asset Detail**: Full property view + vulnerabilities. Includes a **Read Property** panel that calls `/api/read-property` for BACnet diagnostics.
- **Alerts**: Severity-colored table with Acknowledge and Resolve actions.
- **Compliance**: DESC and IEC framework tabs with score bars, category breakdowns, and per-control detail dialogs.
- **Settings**: Backend URL, BACnet IP, scan networks, interval, and API key saved to Windows registry via `QSettings`. Built-in **Start Backend** button to launch the local FastAPI server as a subprocess.
- **System Tray**: Minimize to tray with right-click menu — Show, Start Scan, Exit.

## Design

- Dark theme matching Sentri OT web UI: slate-900 background, emerald accents, amber warnings, red critical alerts.
- Left sidebar navigation + right stacked content widget.
- Clean, professional Qt stylesheet theming.

## Requirements

- Python 3.10+
- Windows 10/11

## Setup

```bash
cd windows_app
python -m venv venv
venv\Scripts\activate.bat
pip install -r requirements.txt
```

## Run

```bash
python main.py
```

The app expects the Sentri OT FastAPI backend to be running on `http://127.0.0.1:8000` by default. Open **Settings** and click **Start Backend** to launch the local bundled/source backend. You can change the backend URL in **Settings**.

## Build Standalone Executable

A batch script is provided for convenience:

```bash
build.bat
```

The build script installs both backend and desktop dependencies and bundles the backend folder into the executable. Output: `dist\SentriOT.exe`.

To create a setup wizard, build the executable first, then compile `..\installer\sentriot.iss` with Inno Setup.

## File Structure

```
windows_app/
├── main.py               # Entry point, main window, sidebar, system tray
├── api_client.py         # Async HTTP client (requests in QThreadPool)
├── dashboard.py          # Dashboard tab
├── scan_tab.py           # Scan tab
├── assets_tab.py         # Assets tab + AssetDetailDialog + Read Property
├── alerts_tab.py         # Alerts tab
├── compliance_tab.py     # Compliance tab + framework sub-tabs
├── settings_tab.py       # Settings tab + backend launcher
├── styles.py             # Shared stylesheet constants
├── requirements.txt      # Python dependencies
├── build.bat             # PyInstaller build script
└── README.md             # This file
```

## API Integration

The app talks to the local FastAPI backend over these endpoints:

| Endpoint | Method | Description |
|---|---|---|
| `/api/health` | GET | Backend health check |
| `/api/version` | GET | Backend version |
| `/api/stats/summary` | GET | Dashboard stats |
| `/api/scan/start` | POST | Start a new scan |
| `/api/scan/latest/result` | GET | Latest scan result |
| `/api/scan/history` | GET | Scan history list |
| `/api/scan/status` | GET | Current scan status |
| `/api/assets` | GET | Asset inventory (paginated, searchable, filterable) |
| `/api/assets/{id}` | GET | Single asset detail |
| `/api/alerts` | GET | Alerts list (filterable) |
| `/api/alerts/{id}/acknowledge` | POST | Acknowledge alert |
| `/api/alerts/{id}/resolve` | POST | Resolve alert |
| `/api/compliance` | GET | Compliance report |
| `/api/reports/compliance/{scan_id}` | GET | Download PDF report |
| `/api/read-property` | GET | Read BACnet property from device |

## License

Sentri OT internal use.
