"""
Compliance tab with DESC / IEC framework tabs, score, category breakdown,
and per-control detail view.
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTabWidget, QTableWidget,
    QTableWidgetItem, QHeaderView, QProgressBar, QDialog, QTextEdit,
    QPushButton, QMessageBox
)
from PyQt6.QtCore import Qt

from api_client import SentriApiClient
from styles import ACCENT_EMERALD, ACCENT_RED, ACCENT_AMBER


class ControlDetailDialog(QDialog):
    def __init__(self, control: dict, parent=None):
        super().__init__(parent)
        self.control = control
        self.setWindowTitle(f"Control: {control.get('id', 'Detail')}")
        self.setMinimumSize(550, 400)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        title = QLabel(f"<b>{self.control.get('id', '')}</b> — {self.control.get('title', '')}")
        title.setStyleSheet("font-size: 16px; color: #f8fafc;")
        layout.addWidget(title)

        description = QLabel(self.control.get("description", "No description."))
        description.setWordWrap(True)
        description.setStyleSheet("color: #94a3b8;")
        layout.addWidget(description)

        status = QLabel(f"Status: <b>{self.control.get('status', 'Unknown')}</b>")
        status.setStyleSheet("color: #f8fafc;")
        layout.addWidget(status)

        evidence = QTextEdit()
        evidence.setReadOnly(True)
        evidence.setPlainText(self.control.get("evidence", "No evidence provided."))
        layout.addWidget(evidence)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn, alignment=Qt.AlignmentFlag.AlignRight)


class ComplianceFrameworkTab(QWidget):
    def __init__(self, api: SentriApiClient, framework: str, parent=None):
        super().__init__(parent)
        self.api = api
        self.framework = framework
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        # Score bar
        score_row = QHBoxLayout()
        self.score_label = QLabel("Compliance Score: —")
        self.score_label.setStyleSheet("font-size: 16px; font-weight: 600; color: #f8fafc;")
        score_row.addWidget(self.score_label)
        score_row.addStretch()
        layout.addLayout(score_row)

        self.score_bar = QProgressBar()
        self.score_bar.setRange(0, 100)
        self.score_bar.setValue(0)
        self.score_bar.setTextVisible(True)
        layout.addWidget(self.score_bar)

        # Category breakdown
        layout.addWidget(QLabel("Category Breakdown"))
        self.cat_table = QTableWidget()
        self.cat_table.setColumnCount(3)
        self.cat_table.setHorizontalHeaderLabels(["Category", "Score (%)", "Status"])
        self.cat_table.horizontalHeader().setStretchLastSection(True)
        self.cat_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.cat_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.cat_table.doubleClicked.connect(self._on_cat_double_click)
        layout.addWidget(self.cat_table)

        # Controls detail
        layout.addWidget(QLabel("Controls"))
        self.controls_table = QTableWidget()
        self.controls_table.setColumnCount(4)
        self.controls_table.setHorizontalHeaderLabels(["ID", "Title", "Category", "Status"])
        self.controls_table.horizontalHeader().setStretchLastSection(True)
        self.controls_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.controls_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.controls_table.doubleClicked.connect(self._on_control_double_click)
        layout.addWidget(self.controls_table)

        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #94a3b8;")
        layout.addWidget(self.status_label)

    def refresh(self):
        self.status_label.setText("Loading compliance data...")
        worker = self.api.compliance(framework=self.framework)
        worker.signals.finished.connect(self._on_data)
        worker.signals.error.connect(self._on_error)

    def _on_data(self, data):
        if not isinstance(data, dict):
            self.status_label.setText("Invalid response format.")
            return

        score = data.get("score", 0)
        self.score_label.setText(f"Compliance Score: {score}%")
        self.score_bar.setValue(int(score))
        if score >= 80:
            self.score_bar.setStyleSheet("QProgressBar::chunk { background-color: #22c55e; }")
        elif score >= 50:
            self.score_bar.setStyleSheet("QProgressBar::chunk { background-color: #f59e0b; }")
        else:
            self.score_bar.setStyleSheet("QProgressBar::chunk { background-color: #ef4444; }")

        # Categories
        categories = data.get("categories", [])
        self.cat_table.setRowCount(len(categories))
        for row, cat in enumerate(categories):
            name = cat.get("name", "")
            cscore = cat.get("score", 0)
            cstatus = cat.get("status", "")
            self.cat_table.setItem(row, 0, QTableWidgetItem(name))
            self.cat_table.setItem(row, 1, QTableWidgetItem(str(cscore)))
            self.cat_table.setItem(row, 2, QTableWidgetItem(cstatus))
            if cstatus.lower() == "pass":
                self.cat_table.item(row, 2).setForeground(Qt.GlobalColor.green)
            elif cstatus.lower() == "fail":
                self.cat_table.item(row, 2).setForeground(Qt.GlobalColor.red)
            else:
                self.cat_table.item(row, 2).setForeground(Qt.GlobalColor.yellow)

        # Controls
        controls = data.get("controls", [])
        self.controls_table.setRowCount(len(controls))
        for row, ctrl in enumerate(controls):
            cid = ctrl.get("id", "")
            title = ctrl.get("title", "")
            category = ctrl.get("category", "")
            status = ctrl.get("status", "")
            self.controls_table.setItem(row, 0, QTableWidgetItem(cid))
            self.controls_table.setItem(row, 1, QTableWidgetItem(title))
            self.controls_table.setItem(row, 2, QTableWidgetItem(category))
            self.controls_table.setItem(row, 3, QTableWidgetItem(status))
            if status.lower() == "pass":
                self.controls_table.item(row, 3).setForeground(Qt.GlobalColor.green)
            elif status.lower() == "fail":
                self.controls_table.item(row, 3).setForeground(Qt.GlobalColor.red)
            else:
                self.controls_table.item(row, 3).setForeground(Qt.GlobalColor.yellow)

        self.status_label.setText(f"Loaded {len(controls)} controls")

    def _on_error(self, msg: str):
        self.status_label.setText(f"Error: {msg}")

    def _on_control_double_click(self):
        row = self.controls_table.currentRow()
        if row < 0:
            return
        ctrl = {
            "id": self.controls_table.item(row, 0).text(),
            "title": self.controls_table.item(row, 1).text(),
            "category": self.controls_table.item(row, 2).text(),
            "status": self.controls_table.item(row, 3).text(),
            "description": "",
            "evidence": "",
        }
        dialog = ControlDetailDialog(ctrl, self)
        dialog.exec()

    def _on_cat_double_click(self):
        row = self.cat_table.currentRow()
        if row < 0:
            return
        cat_name = self.cat_table.item(row, 0).text()
        # Filter controls table to this category
        for r in range(self.controls_table.rowCount()):
            item = self.controls_table.item(r, 2)
            if item and item.text() == cat_name:
                self.controls_table.selectRow(r)
                self.controls_table.scrollToItem(item)
                break


class ComplianceTab(QWidget):
    def __init__(self, api: SentriApiClient, parent=None):
        super().__init__(parent)
        self.api = api
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        header = QLabel("Compliance")
        header.setStyleSheet("font-size: 24px; font-weight: 700; color: #f8fafc;")
        layout.addWidget(header)

        self.tabs = QTabWidget()
        self.desc_tab = ComplianceFrameworkTab(self.api, "DESC")
        self.iec_tab = ComplianceFrameworkTab(self.api, "IEC")
        self.tabs.addTab(self.desc_tab, "DESC")
        self.tabs.addTab(self.iec_tab, "IEC")
        layout.addWidget(self.tabs)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setObjectName("primary")
        self.refresh_btn.clicked.connect(self.refresh)
        layout.addWidget(self.refresh_btn, alignment=Qt.AlignmentFlag.AlignLeft)

    def refresh(self):
        self.desc_tab.refresh()
        self.iec_tab.refresh()
