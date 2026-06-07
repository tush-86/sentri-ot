"""
Async HTTP client for the Sentri OT backend using requests in a QThread pool.
Emits Qt signals for each response so the UI stays responsive.
"""
import json
from typing import Any, Dict, Optional

import requests
from PyQt6.QtCore import QObject, QRunnable, QThreadPool, pyqtSignal


class _WorkerSignals(QObject):
    finished = pyqtSignal(object)   # response dict or None on error
    error = pyqtSignal(str)


class _ApiWorker(QRunnable):
    def __init__(self, method: str, url: str, params: Optional[Dict] = None,
                 json_data: Optional[Dict] = None, headers: Optional[Dict] = None):
        super().__init__()
        self.method = method.upper()
        self.url = url
        self.params = params or {}
        self.json_data = json_data or {}
        self.headers = headers or {}
        self.signals = _WorkerSignals()

    def run(self):
        try:
            kwargs = {"params": self.params, "headers": self.headers, "timeout": 30}
            if self.json_data:
                kwargs["json"] = self.json_data
            if self.method == "GET":
                resp = requests.get(self.url, **kwargs)
            elif self.method == "POST":
                resp = requests.post(self.url, **kwargs)
            else:
                self.signals.error.emit(f"Unsupported method: {self.method}")
                return

            resp.raise_for_status()
            try:
                data = resp.json()
            except ValueError:
                data = {"raw": resp.text}
            self.signals.finished.emit(data)
        except requests.exceptions.ConnectionError:
            self.signals.error.emit("Cannot connect to backend. Is it running?")
        except requests.exceptions.Timeout:
            self.signals.error.emit("Request timed out.")
        except requests.exceptions.HTTPError as e:
            self.signals.error.emit(f"HTTP {e.response.status_code}: {e.response.text}")
        except Exception as e:
            self.signals.error.emit(str(e))


class SentriApiClient(QObject):
    """
    High-level API client. Every method returns a worker whose signals
    the caller can connect to. The worker is automatically started.
    """

    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        super().__init__()
        self.base_url = base_url.rstrip("/")
        self._thread_pool = QThreadPool.globalInstance()
        self.api_key: Optional[str] = None

    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["X-API-Key"] = self.api_key
        return h

    def _dispatch(self, method: str, path: str, params: Optional[Dict] = None,
                  json_data: Optional[Dict] = None) -> _ApiWorker:
        url = f"{self.base_url}{path}"
        worker = _ApiWorker(method, url, params=params, json_data=json_data,
                            headers=self._headers())
        self._thread_pool.start(worker)
        return worker

    # ── Health & Meta ──
    def health(self) -> _ApiWorker:
        return self._dispatch("GET", "/api/health")

    def version(self) -> _ApiWorker:
        return self._dispatch("GET", "/api/version")

    # ── Dashboard ──
    def stats_summary(self) -> _ApiWorker:
        return self._dispatch("GET", "/api/stats/summary")

    # ── Scan ──
    def scan_start(self) -> _ApiWorker:
        return self._dispatch("POST", "/api/scan/start")

    def scan_latest_result(self) -> _ApiWorker:
        return self._dispatch("GET", "/api/scan/latest/result")

    def scan_history(self) -> _ApiWorker:
        return self._dispatch("GET", "/api/scan/history")

    def scan_status(self) -> _ApiWorker:
        return self._dispatch("GET", "/api/scan/status")

    # ── Assets ──
    def assets(self, search: str = "", protocol: str = "", zone: str = "",
               criticality: str = "", page: int = 1, page_size: int = 50) -> _ApiWorker:
        params = {
            "search": search,
            "protocol": protocol,
            "zone": zone,
            "criticality": criticality,
            "page": page,
            "page_size": page_size,
        }
        return self._dispatch("GET", "/api/assets", params=params)

    def asset_detail(self, asset_id: str) -> _ApiWorker:
        return self._dispatch("GET", f"/api/assets/{asset_id}")

    # ── Alerts ──
    def alerts(self, severity: str = "", status: str = "") -> _ApiWorker:
        params = {"severity": severity, "status": status}
        return self._dispatch("GET", "/api/alerts", params=params)

    def alert_acknowledge(self, alert_id: str) -> _ApiWorker:
        return self._dispatch("POST", f"/api/alerts/{alert_id}/acknowledge")

    def alert_resolve(self, alert_id: str) -> _ApiWorker:
        return self._dispatch("POST", f"/api/alerts/{alert_id}/resolve")

    # ── Compliance ──
    def compliance(self, framework: str = "") -> _ApiWorker:
        params = {"framework": framework}
        return self._dispatch("GET", "/api/compliance", params=params)

    def compliance_report(self, scan_id: str) -> _ApiWorker:
        return self._dispatch("GET", f"/api/reports/compliance/{scan_id}")

    # ── Read Property ──
    def read_property(self, ip: str, device_instance: str, property_id: str,
                      object_type: str = "8", object_instance: str = "") -> _ApiWorker:
        params = {
            "ip": ip,
            "device_instance": device_instance,
            "property_id": property_id,
            "object_type": object_type or "8",
        }
        if object_instance:
            params["object_instance"] = object_instance
        return self._dispatch("GET", "/api/read-property", params=params)
