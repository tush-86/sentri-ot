"""
Scan tab: start scan, progress, status, history, and scan detail viewer.
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QProgressBar, QListWidget, QListWidgetItem, QMessageBox,
    QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt6.QtCore import Qt, QTimer

from api_client import SentriApiClient
from styles import ACCENT_EMERALD, ACCENT_RED, ACCENT_AMBER


class ScanTab(QWidget):
    def __init__(self, api: SentriApiClient, parent=None):
        super().__init__(parent)
        self.api = api
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(2000)
        self._poll_timer.timeout.connect(self._poll_status)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        header = QLabel("Scan")
        header.setStyleSheet("font-size: 24px; font-weight: 700; color: #f8fafc;")
        layout.addWidget(header)

        # Controls row
        controls = QHBoxLayout()
        self.start_btn = QPushButton("Start Scan")
        self.start_btn.setObjectName("primary")
        self.start_btn.clicked.connect(self._on_start_scan)
        controls.addWidget(self.start_btn)

        self.status_lbl = QLabel("Idle")
        self.status_lbl.setStyleSheet("color: #94a3b8; font-size: 13px;")
        controls.addWidget(self.status_lbl)
        controls.addStretch()
        layout.addLayout(controls)

        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        # History list
        history_label = QLabel("Scan History")
        history_label.setStyleSheet("font-size: 16px; font-weight: 600; color: #f8fafc;")
        layout.addWidget(history_label)

        self.history_list = QListWidget()
        self.history_list.setMaximumHeight(200)
        self.history_list.itemClicked.connect(self._on_history_selected)
        layout.addWidget(self.history_list)

        # Detail table
        detail_label = QLabel("Scan Details")
        detail_label.setStyleSheet("font-size: 16px; font-weight: 600; color: #f8fafc;")
        layout.addWidget(detail_label)

        self.detail_table = QTableWidget()
        self.detail_table.setColumnCount(4)
        self.detail_table.setHorizontalHeaderLabels(["IP", "Hostname", "Vendor", "Risk"])
        self.detail_table.horizontalHeader().setStretchLastSection(True)
        self.detail_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.detail_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.detail_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.detail_table)

        self.refresh_history()

    def _on_start_scan(self):
        self.start_btn.setEnabled(False)
        self.status_lbl.setText("Starting...")
        worker = self.api.scan_start()
        worker.signals.finished.connect(self._on_start_ok)
        worker.signals.error.connect(self._on_start_error)

    def _on_start_ok(self, data):
        self.status_lbl.setText("Scan started")
        self._poll_timer.start()
        self.refresh_history()

    def _on_start_error(self, msg: str):
        self.status_lbl.setText(f"Error: {msg}")
        self.start_btn.setEnabled(True)

    def _poll_status(self):
        worker = self.api.scan_status()
        worker.signals.finished.connect(self._on_status)

    def _on_status(self, data: dict):
        status = data.get("status", "unknown") if isinstance(data, dict) else "unknown"
        progress = data.get("progress", 0) if isinstance(data, dict) else 0
        self.status_lbl.setText(f"Status: {status}")
        self.progress_bar.setValue(int(progress))

        if status in ("completed", "failed", "idle"):
            self._poll_timer.stop()
            self.start_btn.setEnabled(True)
            self.refresh_history()

    def refresh_history(self):
        worker = self.api.scan_history()
        worker.signals.finished.connect(self._on_history)

    def _on_history(self, data):
        self.history_list.clear()
        if not isinstance(data, list):
            return
        for scan in data:
            ts = scan.get("created_at", "?")
            cnt = scan.get("asset_count", 0)
            st = scan.get("status", "unknown")
            item_text = f"{ts}  |  Assets: {cnt}  |  Status: {st}"
            item = QListWidgetItem(item_text)
            item.setData(Qt.ItemDataRole.UserRole, scan)
            if st == "completed":
                item.setForeground(Qt.GlobalColor.green)
            elif st == "failed":
                item.setForeground(Qt.GlobalColor.red)
            elif st == "running":
                item.setForeground(Qt.GlobalColor.yellow)
            self.history_list.addItem(item)

    def _on_history_selected(self, item: QListWidgetItem):
        scan = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(scan, dict):
            return
        scan_id = scan.get("id")
        # Prefer showing latest result if no explicit id, or fetch scan detail endpoint if available
        worker = self.api.scan_latest_result()
        worker.signals.finished.connect(lambda data, sid=scan_id: self._on_scan_detail(data, sid))

    def _on_scan_detail(self, data: dict, scan_id: str):
        assets = []
        if isinstance(data, dict):
            assets = data.get("assets", [])
        self.detail_table.setRowCount(len(assets))
        for row, a in enumerate(assets):
            self.detail_table.setItem(row, 0, QTableWidgetItem(str(a.get("ip", ""))))
            self.detail_table.setItem(row, 1, QTableWidgetItem(str(a.get("hostname", ""))))
            self.detail_table.setItem(row, 2, QTableWidgetItem(str(a.get("vendor", ""))))
            self.detail_table.setItem(row, 3, QTableWidgetItem(str(a.get("risk", ""))))
