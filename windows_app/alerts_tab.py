"""
Alerts tab with severity colors and acknowledge/resolve actions.
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox
)
from PyQt6.QtCore import Qt

from api_client import SentriApiClient
from styles import ACCENT_EMERALD, ACCENT_RED, ACCENT_AMBER


class AlertsTab(QWidget):
    def __init__(self, api: SentriApiClient, parent=None):
        super().__init__(parent)
        self.api = api
        self._setup_ui()
        self.refresh()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        header = QLabel("Alerts")
        header.setStyleSheet("font-size: 24px; font-weight: 700; color: #f8fafc;")
        layout.addWidget(header)

        # Filters
        filters = QHBoxLayout()
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All Severities", "Critical", "High", "Medium", "Low"])
        filters.addWidget(self.severity_filter)

        self.status_filter = QComboBox()
        self.status_filter.addItems(["All Statuses", "Open", "Acknowledged", "Resolved"])
        filters.addWidget(self.status_filter)

        apply_btn = QPushButton("Apply Filters")
        apply_btn.setObjectName("primary")
        apply_btn.clicked.connect(self.refresh)
        filters.addWidget(apply_btn)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)
        filters.addWidget(refresh_btn)
        filters.addStretch()
        layout.addLayout(filters)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "ID", "Severity", "Message", "Status", "Created", "Actions"
        ])
        hdr = self.table.horizontalHeader()
        hdr.setStretchLastSection(True)
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table)

        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #94a3b8;")
        layout.addWidget(self.status_label)

    def refresh(self):
        severity = self.severity_filter.currentText()
        status = self.status_filter.currentText()
        if severity == "All Severities":
            severity = ""
        if status == "All Statuses":
            status = ""

        self.status_label.setText("Loading alerts...")
        worker = self.api.alerts(severity=severity, status=status)
        worker.signals.finished.connect(self._on_alerts)
        worker.signals.error.connect(self._on_error)

    def _on_alerts(self, data):
        items = []
        if isinstance(data, dict):
            items = data.get("items", data.get("alerts", []))
        elif isinstance(data, list):
            items = data

        self.table.setRowCount(len(items))
        for row, a in enumerate(items):
            alert_id = str(a.get("id", ""))
            sev = str(a.get("severity", ""))
            msg = str(a.get("message", ""))
            st = str(a.get("status", ""))
            created = str(a.get("created_at", ""))

            self.table.setItem(row, 0, QTableWidgetItem(alert_id))
            self.table.setItem(row, 1, QTableWidgetItem(sev))
            self.table.setItem(row, 2, QTableWidgetItem(msg))
            self.table.setItem(row, 3, QTableWidgetItem(st))
            self.table.setItem(row, 4, QTableWidgetItem(created))

            # Severity color
            sev_lower = sev.lower()
            if sev_lower == "critical":
                self.table.item(row, 1).setForeground(Qt.GlobalColor.red)
            elif sev_lower == "high":
                self.table.item(row, 1).setForeground(Qt.GlobalColor.darkYellow)
            elif sev_lower == "medium":
                self.table.item(row, 1).setForeground(Qt.GlobalColor.yellow)
            elif sev_lower == "low":
                self.table.item(row, 1).setForeground(Qt.GlobalColor.green)

            # Actions cell with buttons (store row data)
            actions_widget = QWidget()
            actions_layout = QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(4, 2, 4, 2)
            actions_layout.setSpacing(6)

            ack_btn = QPushButton("Ack")
            ack_btn.setObjectName("warning")
            ack_btn.setStyleSheet("padding: 2px 8px; font-size: 11px;")
            ack_btn.clicked.connect(lambda _c, rid=alert_id: self._ack_alert(rid))
            if st.lower() in ("acknowledged", "resolved"):
                ack_btn.setEnabled(False)

            res_btn = QPushButton("Resolve")
            res_btn.setObjectName("primary")
            res_btn.setStyleSheet("padding: 2px 8px; font-size: 11px;")
            res_btn.clicked.connect(lambda _c, rid=alert_id: self._resolve_alert(rid))
            if st.lower() == "resolved":
                res_btn.setEnabled(False)

            actions_layout.addWidget(ack_btn)
            actions_layout.addWidget(res_btn)
            actions_layout.addStretch()
            self.table.setCellWidget(row, 5, actions_widget)

        self.status_label.setText(f"Showing {len(items)} alerts")

    def _on_error(self, msg: str):
        self.status_label.setText(f"Error: {msg}")

    def _ack_alert(self, alert_id: str):
        worker = self.api.alert_acknowledge(alert_id)
        worker.signals.finished.connect(lambda _d: self.refresh())
        worker.signals.error.connect(self._on_error)

    def _resolve_alert(self, alert_id: str):
        worker = self.api.alert_resolve(alert_id)
        worker.signals.finished.connect(lambda _d: self.refresh())
        worker.signals.error.connect(self._on_error)
