"""
Sentri OT Windows Desktop Application — Main Entry Point
PyQt6 native desktop app replacing the React web UI.
"""
import os
import sys


def _resource_base() -> str:
    return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))


def _run_backend_mode() -> None:
    """Run the bundled/local FastAPI backend from the same executable."""
    base = _resource_base()
    repo_root = os.path.abspath(os.path.join(base, ".."))
    for path in (base, repo_root):
        if path not in sys.path:
            sys.path.insert(0, path)

    import uvicorn
    from backend.main import app

    uvicorn.run(
        app,
        host=os.environ.get("SENTRI_OT_HOST", "127.0.0.1"),
        port=int(os.environ.get("SENTRI_OT_PORT", "8000")),
        reload=False,
    )


if "--backend" in sys.argv:
    _run_backend_mode()
    raise SystemExit(0)

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QPushButton, QStackedWidget, QLabel, QSystemTrayIcon, QMenu,
    QMessageBox
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QIcon, QAction

from api_client import SentriApiClient
from dashboard import DashboardTab
from scan_tab import ScanTab
from assets_tab import AssetsTab
from alerts_tab import AlertsTab
from compliance_tab import ComplianceTab
from settings_tab import SettingsTab
from styles import BASE_STYLESHEET, SIDEBAR_STYLESHEET, ACCENT_EMERALD, FG_GRAY


class SentriMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sentri OT")
        self.setMinimumSize(1200, 750)
        self.resize(1400, 850)

        self.api = SentriApiClient()

        self._setup_ui()
        self._setup_system_tray()
        self._apply_styles()

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Sidebar ──
        self.sidebar = QWidget()
        self.sidebar.setObjectName("Sidebar")
        self.sidebar.setFixedWidth(200)
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(8, 16, 8, 16)
        sidebar_layout.setSpacing(4)

        # Logo / title
        logo = QLabel("🛡 Sentri OT")
        logo.setStyleSheet(f"font-size: 18px; font-weight: 700; color: {ACCENT_EMERALD}; padding: 8px;")
        sidebar_layout.addWidget(logo)

        # Separator
        sep = QWidget()
        sep.setFixedHeight(1)
        sep.setStyleSheet("background-color: #334155;")
        sidebar_layout.addWidget(sep)
        sidebar_layout.addSpacing(8)

        self.nav_buttons: list[QPushButton] = []
        self.nav_pages: list[QWidget] = []

        self._add_nav("Dashboard", DashboardTab(self.api))
        self._add_nav("Scan", ScanTab(self.api))
        self._add_nav("Assets", AssetsTab(self.api))
        self._add_nav("Alerts", AlertsTab(self.api))
        self._add_nav("Compliance", ComplianceTab(self.api))
        self._add_nav("Settings", SettingsTab(self.api))

        sidebar_layout.addStretch()

        # Footer
        footer = QLabel("v1.0.0")
        footer.setStyleSheet(f"color: {FG_GRAY}; font-size: 11px; padding: 4px;")
        sidebar_layout.addWidget(footer)

        layout.addWidget(self.sidebar)

        # ── Content Area ──
        self.stack = QStackedWidget()
        for page in self.nav_pages:
            self.stack.addWidget(page)
        layout.addWidget(self.stack, 1)

        # Default selection
        self._select_nav(0)

    def _add_nav(self, label: str, page: QWidget):
        btn = QPushButton(label)
        btn.setObjectName("nav_button")
        btn.setCheckable(True)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.clicked.connect(lambda _c, idx=len(self.nav_buttons): self._select_nav(idx))
        self.nav_buttons.append(btn)
        self.nav_pages.append(page)
        self.sidebar.layout().addWidget(btn)

    def _select_nav(self, index: int):
        for i, btn in enumerate(self.nav_buttons):
            btn.setChecked(i == index)
        self.stack.setCurrentIndex(index)
        # Trigger refresh on dashboard and compliance when selected
        page = self.nav_pages[index]
        if hasattr(page, "refresh"):
            page.refresh()

    def _apply_styles(self):
        self.setStyleSheet(BASE_STYLESHEET + SIDEBAR_STYLESHEET)

    def _setup_system_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setToolTip("Sentri OT")

        tray_menu = QMenu(self)
        show_action = QAction("Show", self)
        show_action.triggered.connect(self.showNormal)
        show_action.triggered.connect(self.raise_)
        show_action.triggered.connect(self.activateWindow)

        scan_action = QAction("Start Scan", self)
        scan_action.triggered.connect(self._tray_start_scan)

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self._exit_app)

        tray_menu.addAction(show_action)
        tray_menu.addAction(scan_action)
        tray_menu.addSeparator()
        tray_menu.addAction(exit_action)

        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self._on_tray_activated)
        self.tray_icon.show()

    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.showNormal()
            self.raise_()
            self.activateWindow()

    def _tray_start_scan(self):
        self._select_nav(1)  # Scan tab
        scan_page = self.nav_pages[1]
        if hasattr(scan_page, "_on_start_scan"):
            scan_page._on_start_scan()

    def _exit_app(self):
        # Stop backend if running via settings tab
        settings_page = self.nav_pages[5]
        if isinstance(settings_page, SettingsTab):
            settings_page._stop_backend()
        self.tray_icon.hide()
        QApplication.quit()

    def closeEvent(self, event):
        if hasattr(self, "tray_icon") and self.tray_icon.isVisible():
            self.hide()
            event.ignore()
        else:
            event.accept()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Sentri OT")
    app.setOrganizationName("SentriOT")

    # Enable high-DPI scaling
    app.setStyle("Fusion")

    window = SentriMainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
