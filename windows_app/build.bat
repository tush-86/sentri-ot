@echo off
REM Build script for Sentri OT Windows Desktop App
REM Run this from the windows_app folder on Windows with Python 3.10+ installed.

setlocal
cd /d "%~dp0"

echo ===========================================
echo  Sentri OT Windows Desktop App Builder
echo ===========================================

if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)

call venv\Scripts\activate.bat

echo Installing backend and desktop dependencies...
python -m pip install --upgrade pip
pip install -r ..\backend\requirements.txt
pip install -r requirements.txt
pip install pyinstaller

echo Building executable with PyInstaller...
pyinstaller --noconfirm --onefile --windowed --name "SentriOT" ^
    --paths ".." ^
    --add-data "..\backend;backend" ^
    --hidden-import "backend.main" ^
    --hidden-import "backend.ot_discovery" ^
    --hidden-import "backend.db" ^
    --hidden-import "backend.report_gen" ^
    --hidden-import "uvicorn" ^
    --collect-submodules "uvicorn" ^
    main.py

echo.
echo Build complete. Output: windows_app\dist\SentriOT.exe
echo Use installer\sentriot.iss with Inno Setup to create a setup wizard.
echo.
pause
