"""
Assets tab: search, filters, sortable table, and asset detail dialog with Read Property.
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
    QDialog, QGridLayout, QTextEdit, QGroupBox, QSizePolicy, QSplitter,
    QProgressBar
)
from PyQt6.QtCore import Qt

from api_client import SentriApiClient
from styles import ACCENT_EMERALD, ACCENT_RED, ACCENT_AMBER, ACCENT_BLUE


class AssetDetailDialog(QDialog):
    def __init__(self, api: SentriApiClient, asset: dict, parent=None):
        super().__init__(parent)
        self.api = api
        self.asset = asset
        self.setWindowTitle(f"Asset Detail — {asset.get('ip', 'Unknown')}")
        self.setMinimumSize(700, 550)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        # Header info
        info_grid = QGridLayout()
        info_grid.setSpacing(8)

        fields = [
            ("IP", self.asset.get("ip", "—")),
            ("Hostname", self.asset.get("hostname", "—")),
            ("Vendor", self.asset.get("vendor", "—")),
            ("Model", self.asset.get("model", "—")),
            ("Firmware", self.asset.get("firmware", "—")),
            ("Protocol", self.asset.get("protocol", "—")),
            ("Zone", self.asset.get("zone", "—")),
            ("Criticality", self.asset.get("criticality", "—")),
            ("Risk", self.asset.get("risk", "—")),
        ]
        for row, (label, value) in enumerate(fields):
            lbl = QLabel(f"<b>{label}:</b>")
            lbl.setStyleSheet("color: #94a3b8;")
            val = QLabel(str(value))
            val.setStyleSheet("color: #f8fafc; font-weight: 600;")
            info_grid.addWidget(lbl, row // 3, (row % 3) * 2)
            info_grid.addWidget(val, row // 3, (row % 3) * 2 + 1)

        layout.addLayout(info_grid)

        # Vulnerabilities
        vuln_group = QGroupBox("Vulnerabilities")
        vuln_layout = QVBoxLayout(vuln_group)
        vulns = self.asset.get("vulnerabilities", [])
        if vulns:
            self.vuln_text = QTextEdit()
            self.vuln_text.setReadOnly(True)
            self.vuln_text.setText("\n".join(f"• {v}" for v in vulns))
            vuln_layout.addWidget(self.vuln_text)
        else:
            none_lbl = QLabel("No known vulnerabilities.")
            none_lbl.setStyleSheet("color: #94a3b8;")
            vuln_layout.addWidget(none_lbl)
        layout.addWidget(vuln_group)

        # Read Property section
        rp_group = QGroupBox("Read BACnet Property (/api/read-property)")
        rp_layout = QGridLayout(rp_group)
        rp_layout.setSpacing(8)

        rp_layout.addWidget(QLabel("IP Address:"), 0, 0)
        self.rp_ip = QLineEdit(self.asset.get("ip", ""))
        rp_layout.addWidget(self.rp_ip, 0, 1)

        rp_layout.addWidget(QLabel("Device Instance:"), 0, 2)
        self.rp_instance = QLineEdit(str(self.asset.get("device_id", "")))
        rp_layout.addWidget(self.rp_instance, 0, 3)

        rp_layout.addWidget(QLabel("Object Type:"), 1, 0)
        self.rp_object_type = QLineEdit("8")
        rp_layout.addWidget(self.rp_object_type, 1, 1)

        rp_layout.addWidget(QLabel("Object Instance:"), 1, 2)
        self.rp_object_instance = QLineEdit("")
        self.rp_object_instance.setPlaceholderText("blank = device instance")
        rp_layout.addWidget(self.rp_object_instance, 1, 3)

        rp_layout.addWidget(QLabel("Property ID:"), 2, 0)
        self.rp_prop = QLineEdit("77")
        self.rp_prop.setPlaceholderText("77 = Object_Name")
        rp_layout.addWidget(self.rp_prop, 2, 1)

        self.rp_send_btn = QPushButton("Send")
        self.rp_send_btn.setObjectName("primary")
        self.rp_send_btn.clicked.connect(self._on_read_property)
        rp_layout.addWidget(self.rp_send_btn, 2, 3)

        self.rp_result = QTextEdit()
        self.rp_result.setReadOnly(True)
        self.rp_result.setPlaceholderText("Response will appear here...")
        rp_layout.addWidget(self.rp_result, 3, 0, 1, 4)

        layout.addWidget(rp_group)

        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn, alignment=Qt.AlignmentFlag.AlignRight)

    def _on_read_property(self):
        ip = self.rp_ip.text().strip()
        inst = self.rp_instance.text().strip()
        prop = self.rp_prop.text().strip()
        obj_type = self.rp_object_type.text().strip() or "8"
        obj_instance = self.rp_object_instance.text().strip()
        if not ip or not inst or not prop:
            QMessageBox.warning(self, "Missing Fields", "Please fill IP, Device Instance, and Property ID.")
            return

        self.rp_send_btn.setEnabled(False)
        self.rp_result.setText("Requesting...")
        worker = self.api.read_property(ip, inst, prop, object_type=obj_type, object_instance=obj_instance)
        worker.signals.finished.connect(self._on_rp_ok)
        worker.signals.error.connect(self._on_rp_error)

    def _on_rp_ok(self, data):
        import json
        self.rp_result.setText(json.dumps(data, indent=2))
        self.rp_send_btn.setEnabled(True)

    def _on_rp_error(self, msg):
        self.rp_result.setText(f"Error: {msg}")
        self.rp_send_btn.setEnabled(True)


class AssetsTab(QWidget):
    def __init__(self, api: SentriApiClient, parent=None):
        super().__init__(parent)
        self.api = api
        self._current_page = 1
        self._page_size = 50
        self._items = []
        self._setup_ui()
        self.refresh()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        header = QLabel("Assets")
        header.setStyleSheet("font-size: 24px; font-weight: 700; color: #f8fafc;")
        layout.addWidget(header)

        # Filters row
        filters = QHBoxLayout()
        filters.setSpacing(12)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search IP, hostname, vendor...")
        self.search_input.setMinimumWidth(240)
        self.search_input.returnPressed.connect(self.refresh)
        filters.addWidget(self.search_input)

        self.protocol_filter = QComboBox()
        self.protocol_filter.addItems(["All Protocols", "BACnet", "Modbus", "DNP3", "Ethernet/IP", "OPC-UA"])
        filters.addWidget(self.protocol_filter)

        self.zone_filter = QComboBox()
        self.zone_filter.addItems(["All Zones", "OT", "IT", "DMZ", "Safety"])
        filters.addWidget(self.zone_filter)

        self.criticality_filter = QComboBox()
        self.criticality_filter.addItems(["All Criticalities", "Low", "Medium", "High", "Critical"])
        filters.addWidget(self.criticality_filter)

        btn = QPushButton("Apply Filters")
        btn.setObjectName("primary")
        btn.clicked.connect(self.refresh)
        filters.addWidget(btn)

        filters.addStretch()
        layout.addLayout(filters)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "IP", "Hostname", "Vendor", "Model", "Firmware",
            "Risk", "Protocol", "Zone"
        ])
        header_view = self.table.horizontalHeader()
        header_view.setStretchLastSection(True)
        header_view.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.doubleClicked.connect(self._on_double_click)
        layout.addWidget(self.table)

        # Status
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #94a3b8;")
        layout.addWidget(self.status_label)

    def refresh(self):
        search = self.search_input.text().strip()
        protocol = self.protocol_filter.currentText()
        zone = self.zone_filter.currentText()
        criticality = self.criticality_filter.currentText()

        if protocol == "All Protocols":
            protocol = ""
        if zone == "All Zones":
            zone = ""
        if criticality == "All Criticalities":
            criticality = ""

        self.status_label.setText("Loading assets...")
        worker = self.api.assets(
            search=search, protocol=protocol, zone=zone,
            criticality=criticality, page=self._current_page, page_size=self._page_size
        )
        worker.signals.finished.connect(self._on_assets)
        worker.signals.error.connect(self._on_error)

    def _on_assets(self, data):
        items = []
        if isinstance(data, dict):
            items = data.get("items", data.get("assets", []))
        elif isinstance(data, list):
            items = data

        self._items = items
        self.table.setRowCount(len(items))
        for row, a in enumerate(items):
            self.table.setItem(row, 0, QTableWidgetItem(str(a.get("ip", ""))))
            self.table.setItem(row, 1, QTableWidgetItem(str(a.get("hostname", ""))))
            self.table.setItem(row, 2, QTableWidgetItem(str(a.get("vendor", ""))))
            self.table.setItem(row, 3, QTableWidgetItem(str(a.get("model", ""))))
            self.table.setItem(row, 4, QTableWidgetItem(str(a.get("firmware", ""))))
            self.table.setItem(row, 5, QTableWidgetItem(str(a.get("risk", ""))))
            self.table.setItem(row, 6, QTableWidgetItem(str(a.get("protocol", ""))))
            self.table.setItem(row, 7, QTableWidgetItem(str(a.get("zone", ""))))

            # Color risk column
            risk = str(a.get("risk", "")).lower()
            if risk in ("critical", "high"):
                self.table.item(row, 5).setForeground(Qt.GlobalColor.red)
            elif risk == "medium":
                self.table.item(row, 5).setForeground(Qt.GlobalColor.yellow)
            elif risk == "low":
                self.table.item(row, 5).setForeground(Qt.GlobalColor.green)

        self.status_label.setText(f"Showing {len(items)} assets")

    def _on_error(self, msg: str):
        self.status_label.setText(f"Error: {msg}")

    def _on_double_click(self):
        row = self.table.currentRow()
        if row < 0:
            return
        asset = self._items[row] if row < len(self._items) else {}
        asset_id = asset.get("id")
        if not asset_id:
            self._open_detail(asset)
            return

        # Try to fetch full detail; fallback to the table row payload.
        worker = self.api.asset_detail(str(asset_id))
        worker.signals.finished.connect(
            lambda d, a=asset: self._open_detail(d if isinstance(d, dict) else a)
        )
        worker.signals.error.connect(lambda _m, a=asset: self._open_detail(a))

    def _open_detail(self, asset: dict):
        dialog = AssetDetailDialog(self.api, asset, self)
        dialog.exec()
