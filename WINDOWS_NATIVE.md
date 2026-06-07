# Sentri OT Windows Native Build

This branch converts Sentri OT from a React web UI + FastAPI backend into a Windows-native desktop application.

## What changed

- Backend is API-only; React static serving has been removed from `backend/main.py`.
- Added PyQt6 desktop application in `windows_app/`.
- Fixed BACnet ReadProperty packet building and Complex-ACK parsing in `backend/ot_discovery.py`.
- Added `/api/read-property` for on-demand BACnet diagnostics from the desktop app.
- Added Windows service wrapper: `backend/windows_service.py`.
- Added PyInstaller build script: `windows_app/build.bat`.
- Added Inno Setup installer script: `installer/sentriot.iss`.

## Run from source on Windows

```bat
git clone https://github.com/tush-86/sentri-ot.git
cd sentri-ot
python -m venv .venv
.venv\Scripts\activate.bat
pip install -r backend\requirements.txt
pip install -r windows_app\requirements.txt
python windows_app\main.py
```

In the app, open **Settings** and click **Start Backend**. The backend listens on `http://127.0.0.1:8000`.

## Build app executable

```bat
cd windows_app
build.bat
```

Output:

```text
windows_app\dist\SentriOT.exe
```

The same executable can launch the bundled backend using the hidden `--backend` mode. The desktop app uses this internally when the **Start Backend** button is clicked.

## Build installer

1. Install Inno Setup.
2. Build the executable first with `windows_app\build.bat`.
3. Open `installer\sentriot.iss` in Inno Setup and compile it.

Output:

```text
installer\output\SentriOT-Setup.exe
```

## Optional Windows service

From an elevated terminal:

```bat
pip install -r backend\requirements.txt
python backend\windows_service.py install
python backend\windows_service.py start
```

Stop/remove:

```bat
python backend\windows_service.py stop
python backend\windows_service.py remove
```

## BACnet ReadProperty diagnostic

Desktop path:

- Assets → double-click asset → Read Property panel

API path:

```text
GET /api/read-property?ip=192.168.1.101&device_instance=102&property_id=77
```

Typical property IDs:

- `77` Object_Name
- `70` Model_Name
- `44` Firmware_Revision
- `121` Vendor_Name
- `76` Object_List
