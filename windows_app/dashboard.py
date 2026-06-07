"""
Dashboard tab with stat cards and a summary layout.
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QGridLayout, QFrame,
    QSizePolicy
)
from PyQt6.QtCore import Qt

from api_client import SentriApiClient
from styles import ACCENT_EMERALD, ACCENT_RED, ACCENT_AMBER, ACCENT_BLUE


class StatCard(QFrame):
    def __init__(self, title: str, value: str, color: str, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setStyleSheet(f"""
            QFrame#Card {{
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 10px;
                padding: 12px;
            }}
        """)
        self.setMinimumHeight(100)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(4)

        self.value_label = QLabel(value)
        self.value_label.setStyleSheet(f"color: {color}; font-size: 32px; font-weight: 700;")
        self.value_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        self.title_label = QLabel(title)
        self.title_label.setStyleSheet("color: #94a3b8; font-size: 13px; font-weight: 500;")

        layout.addWidget(self.value_label)
        layout.addWidget(self.title_label)

    def set_value(self, value: str):
        self.value_label.setText(str(value))


class DashboardTab(QWidget):
    def __init__(self, api: SentriApiClient, parent=None):
        super().__init__(parent)
        self.api = api
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)

        # Header
        header = QLabel("Dashboard")
        header.setStyleSheet("font-size: 24px; font-weight: 700; color: #f8fafc;")
        layout.addWidget(header)

        # Stat cards
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(16)

        self.card_assets = StatCard("Total Assets", "—", ACCENT_BLUE)
        self.card_alerts = StatCard("Critical Alerts", "—", ACCENT_RED)
        self.card_compliance = StatCard("Compliance Score", "—", ACCENT_EMERALD)
        self.card_scans = StatCard("Active Scans", "—", ACCENT_AMBER)

        cards_layout.addWidget(self.card_assets)
        cards_layout.addWidget(self.card_alerts)
        cards_layout.addWidget(self.card_compliance)
        cards_layout.addWidget(self.card_scans)
        layout.addLayout(cards_layout)

        # Status / summary area
        self.status_label = QLabel("Loading...")
        self.status_label.setStyleSheet("color: #94a3b8; font-size: 13px;")
        layout.addWidget(self.status_label)

        # Placeholder for a simple bar summary (filled dynamically)
        self.summary_grid = QGridLayout()
        self.summary_grid.setSpacing(12)
        layout.addLayout(self.summary_grid)

        layout.addStretch()

    def refresh(self):
        self.status_label.setText("Fetching dashboard data...")
        worker = self.api.stats_summary()
        worker.signals.finished.connect(self._on_stats)
        worker.signals.error.connect(self._on_error)

    def _on_stats(self, data: dict):
        self.status_label.setText("Last updated: just now")
        summary = data if isinstance(data, dict) else {}

        total_assets = summary.get("total_assets", 0)
        critical_alerts = summary.get("critical_alerts", 0)
        compliance_score = summary.get("compliance_score", 0)
        active_scans = summary.get("active_scans", 0)

        self.card_assets.set_value(str(total_assets))
        self.card_alerts.set_value(str(critical_alerts))
        self.card_compliance.set_value(f"{compliance_score}%")
        self.card_scans.set_value(str(active_scans))

        # Clear old summary rows
        while self.summary_grid.count():
            item = self.summary_grid.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        # Populate summary rows if available
        breakdown = summary.get("breakdown", {})
        row = 0
        for key, value in breakdown.items():
            lbl_key = QLabel(str(key).replace("_", " ").title())
            lbl_key.setStyleSheet("color: #94a3b8; font-size: 13px;")
            lbl_val = QLabel(str(value))
            lbl_val.setStyleSheet("color: #f8fafc; font-size: 14px; font-weight: 600;")
            lbl_val.setAlignment(Qt.AlignmentFlag.AlignRight)
            self.summary_grid.addWidget(lbl_key, row, 0)
            self.summary_grid.addWidget(lbl_val, row, 1)
            row += 1

    def _on_error(self, msg: str):
        self.status_label.setText(f"Error: {msg}")
