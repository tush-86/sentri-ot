"""
Settings tab: backend URL, BACnet config, scan config, API key.
Save to QSettings (registry on Windows).
Also provides a "Start Backend" button that launches the backend as a subprocess.
"""
import os
import subprocess
import sys

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QGroupBox, QFormLayout, QMessageBox, QSpinBox
)
from PyQt6.QtCore import Qt, QSettings, QDir

from api_client import SentriApiClient


class SettingsTab(QWidget):
    def __init__(self, api: SentriApiClient, parent=None):
        super().__init__(parent)
        self.api = api
        self._backend_proc = None
        self.settings = QSettings("SentriOT", "SentriDesktop")
        self._setup_ui()
        self._load_settings()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)

        header = QLabel("Settings")
        header.setStyleSheet("font-size: 24px; font-weight: 700; color: #f8fafc;")
        layout.addWidget(header)

        # Connection
        conn_group = QGroupBox("Connection")
        conn_form = QFormLayout(conn_group)
        self.backend_url = QLineEdit("http://127.0.0.1:8000")
        conn_form.addRow("Backend URL:", self.backend_url)
        self.api_key = QLineEdit()
        self.api_key.setEchoMode(QLineEdit.EchoMode.Password)
        conn_form.addRow("API Key:", self.api_key)
        layout.addWidget(conn_group)

        # BACnet
        bacnet_group = QGroupBox("BACnet")
        bacnet_form = QFormLayout(bacnet_group)
        self.bacnet_ip = QLineEdit("0.0.0.0")
        bacnet_form.addRow("Local BACnet IP:", self.bacnet_ip)
        layout.addWidget(bacnet_group)

        # Scan config
        scan_group = QGroupBox("Scanning")
        scan_form = QFormLayout(scan_group)
        self.scan_networks = QLineEdit("192.168.0.0/24")
        scan_form.addRow("Networks (comma-separated):", self.scan_networks)
        self.scan_interval = QSpinBox()
        self.scan_interval.setRange(0, 1440)
        self.scan_interval.setSuffix(" min")
        self.scan_interval.setValue(60)
        scan_form.addRow("Scan interval:", self.scan_interval)
        layout.addWidget(scan_group)

        # Backend launcher
        backend_group = QGroupBox("Backend Launcher")
        backend_layout = QVBoxLayout(backend_group)
        self.backend_status = QLabel("Backend not running")
        self.backend_status.setStyleSheet("color: #94a3b8;")
        backend_layout.addWidget(self.backend_status)

        btn_row = QHBoxLayout()
        self.start_backend_btn = QPushButton("Start Backend")
        self.start_backend_btn.setObjectName("primary")
        self.start_backend_btn.clicked.connect(self._start_backend)
        btn_row.addWidget(self.start_backend_btn)

        self.stop_backend_btn = QPushButton("Stop Backend")
        self.stop_backend_btn.setObjectName("danger")
        self.stop_backend_btn.clicked.connect(self._stop_backend)
        self.stop_backend_btn.setEnabled(False)
        btn_row.addWidget(self.stop_backend_btn)

        btn_row.addStretch()
        backend_layout.addLayout(btn_row)
        layout.addWidget(backend_group)

        # Save row
        save_row = QHBoxLayout()
        save_btn = QPushButton("Save Settings")
        save_btn.setObjectName("primary")
        save_btn.clicked.connect(self._save_settings)
        save_row.addWidget(save_btn)

        test_btn = QPushButton("Test Connection")
        test_btn.clicked.connect(self._test_connection)
        save_row.addWidget(test_btn)
        save_row.addStretch()
        layout.addLayout(save_row)

        layout.addStretch()

    def _load_settings(self):
        self.backend_url.setText(self.settings.value("backend_url", "http://127.0.0.1:8000", str))
        self.api_key.setText(self.settings.value("api_key", "", str))
        self.bacnet_ip.setText(self.settings.value("bacnet_ip", "0.0.0.0", str))
        self.scan_networks.setText(self.settings.value("scan_networks", "192.168.0.0/24", str))
        self.scan_interval.setValue(int(self.settings.value("scan_interval", 60, int)))
        self._apply_api_settings()

    def _save_settings(self):
        self.settings.setValue("backend_url", self.backend_url.text().strip())
        self.settings.setValue("api_key", self.api_key.text().strip())
        self.settings.setValue("bacnet_ip", self.bacnet_ip.text().strip())
        self.settings.setValue("scan_networks", self.scan_networks.text().strip())
        self.settings.setValue("scan_interval", self.scan_interval.value())
        self._apply_api_settings()
        QMessageBox.information(self, "Saved", "Settings saved successfully.")

    def _apply_api_settings(self):
        self.api.base_url = self.backend_url.text().strip().rstrip("/")
        self.api.api_key = self.api_key.text().strip() or None

    def _test_connection(self):
        self._apply_api_settings()
        worker = self.api.health()
        worker.signals.finished.connect(
            lambda _d: QMessageBox.information(self, "Connection", "Backend is reachable.")
        )
        worker.signals.error.connect(
            lambda msg: QMessageBox.critical(self, "Connection Failed", msg)
        )

    def _start_backend(self):
        if self._backend_proc is not None:
            return
        repo_root = QDir.current().absolutePath()
        backend_script = os.path.join(repo_root, "..", "backend", "main.py")
        if not os.path.exists(backend_script):
            # Try relative to our own directory
            our_dir = os.path.dirname(os.path.abspath(__file__))
            backend_script = os.path.join(our_dir, "..", "backend", "main.py")
            backend_script = os.path.normpath(backend_script)

        python_exe = sys.executable
        if getattr(sys, "frozen", False):
            cmd = [python_exe, "--backend"]
            cwd = os.path.dirname(python_exe)
        else:
            cmd = [python_exe, backend_script]
            cwd = os.path.dirname(backend_script)
        try:
            self._backend_proc = subprocess.Popen(
                cmd,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            self.backend_status.setText("Backend starting...")
            self.backend_status.setStyleSheet("color: #f59e0b;")
            self.start_backend_btn.setEnabled(False)
            self.stop_backend_btn.setEnabled(True)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start backend: {e}")

    def _stop_backend(self):
        if self._backend_proc is None:
            return
        try:
            self._backend_proc.terminate()
            self._backend_proc.wait(timeout=5)
        except Exception:
            try:
                self._backend_proc.kill()
            except Exception:
                pass
        self._backend_proc = None
        self.backend_status.setText("Backend not running")
        self.backend_status.setStyleSheet("color: #94a3b8;")
        self.start_backend_btn.setEnabled(True)
        self.stop_backend_btn.setEnabled(False)

    def closeEvent(self, event):
        self._stop_backend()
        super().closeEvent(event)
