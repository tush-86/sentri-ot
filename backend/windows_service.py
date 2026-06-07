r"""Windows service wrapper for Sentri OT backend.

Usage from an elevated PowerShell/CMD after installing requirements:

    python backend\windows_service.py install
    python backend\windows_service.py start
    python backend\windows_service.py stop
    python backend\windows_service.py remove

The service runs the FastAPI app on 127.0.0.1:8000 by default. Override with
SENTRI_OT_HOST and SENTRI_OT_PORT environment variables.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import servicemanager
import win32event
import win32service
import win32serviceutil


class SentriOTService(win32serviceutil.ServiceFramework):
    _svc_name_ = "SentriOTBackend"
    _svc_display_name_ = "Sentri OT Backend"
    _svc_description_ = "Local Sentri OT FastAPI backend for the Windows desktop application."

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.server = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        if self.server is not None:
            self.server.should_exit = True
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        self._run_uvicorn()

    def _run_uvicorn(self):
        repo_root = Path(__file__).resolve().parents[1]
        os.chdir(repo_root)
        if str(repo_root) not in sys.path:
            sys.path.insert(0, str(repo_root))

        import uvicorn
        from backend.main import app

        host = os.environ.get("SENTRI_OT_HOST", "127.0.0.1")
        port = int(os.environ.get("SENTRI_OT_PORT", "8000"))
        config = uvicorn.Config(app, host=host, port=port, log_level="info")
        self.server = uvicorn.Server(config)
        self.server.run()


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(SentriOTService)
