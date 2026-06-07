"""
Shared stylesheet constants for the Sentri OT Windows Desktop App.
Dark theme matching the existing web UI.
"""

# ── Colors ──
BG_SLATE_900 = "#0f172a"
BG_SLATE_800 = "#1e293b"
BG_SLATE_700 = "#334155"
BG_SLATE_600 = "#475569"
FG_WHITE = "#f8fafc"
FG_GRAY = "#94a3b8"
ACCENT_EMERALD = "#22c55e"
ACCENT_AMBER = "#f59e0b"
ACCENT_RED = "#ef4444"
ACCENT_BLUE = "#3b82f6"
BORDER_COLOR = "#334155"

# ── Base Stylesheet ──
BASE_STYLESHEET = f"""
QMainWindow {{
    background-color: {BG_SLATE_900};
    color: {FG_WHITE};
}}

QWidget {{
    background-color: {BG_SLATE_900};
    color: {FG_WHITE};
    font-family: "Segoe UI", "Helvetica Neue", sans-serif;
    font-size: 13px;
}}

QLabel {{
    color: {FG_WHITE};
    background: transparent;
}}

QPushButton {{
    background-color: {BG_SLATE_700};
    color: {FG_WHITE};
    border: 1px solid {BORDER_COLOR};
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 500;
}}

QPushButton:hover {{
    background-color: {BG_SLATE_600};
    border-color: {ACCENT_EMERALD};
}}

QPushButton:pressed {{
    background-color: {BG_SLATE_800};
}}

QPushButton:disabled {{
    background-color: {BG_SLATE_800};
    color: {FG_GRAY};
    border-color: {BG_SLATE_700};
}}

QPushButton#primary {{
    background-color: {ACCENT_EMERALD};
    color: {BG_SLATE_900};
    border: none;
    font-weight: 600;
}}

QPushButton#primary:hover {{
    background-color: #16a34a;
}}

QPushButton#danger {{
    background-color: {ACCENT_RED};
    color: {FG_WHITE};
    border: none;
    font-weight: 600;
}}

QPushButton#danger:hover {{
    background-color: #dc2626;
}}

QPushButton#warning {{
    background-color: {ACCENT_AMBER};
    color: {BG_SLATE_900};
    border: none;
    font-weight: 600;
}}

QLineEdit {{
    background-color: {BG_SLATE_800};
    color: {FG_WHITE};
    border: 1px solid {BORDER_COLOR};
    border-radius: 6px;
    padding: 6px 10px;
}}

QLineEdit:focus {{
    border-color: {ACCENT_EMERALD};
}}

QComboBox {{
    background-color: {BG_SLATE_800};
    color: {FG_WHITE};
    border: 1px solid {BORDER_COLOR};
    border-radius: 6px;
    padding: 6px 10px;
}}

QComboBox:focus {{
    border-color: {ACCENT_EMERALD};
}}

QComboBox::drop-down {{
    border: none;
    width: 24px;
}}

QComboBox QAbstractItemView {{
    background-color: {BG_SLATE_800};
    color: {FG_WHITE};
    selection-background-color: {BG_SLATE_700};
    border: 1px solid {BORDER_COLOR};
}}

QTableWidget {{
    background-color: {BG_SLATE_800};
    color: {FG_WHITE};
    border: 1px solid {BORDER_COLOR};
    border-radius: 6px;
    gridline-color: {BG_SLATE_700};
}}

QTableWidget::item {{
    padding: 6px;
    border-bottom: 1px solid {BG_SLATE_700};
}}

QTableWidget::item:selected {{
    background-color: {BG_SLATE_700};
    color: {FG_WHITE};
}}

QHeaderView::section {{
    background-color: {BG_SLATE_700};
    color: {FG_WHITE};
    padding: 8px;
    font-weight: 600;
    border: none;
    border-right: 1px solid {BG_SLATE_600};
}}

QProgressBar {{
    background-color: {BG_SLATE_800};
    color: {FG_WHITE};
    border: 1px solid {BORDER_COLOR};
    border-radius: 4px;
    text-align: center;
}}

QProgressBar::chunk {{
    background-color: {ACCENT_EMERALD};
    border-radius: 4px;
}}

QProgressBar#critical_bar::chunk {{
    background-color: {ACCENT_RED};
}}

QProgressBar#warning_bar::chunk {{
    background-color: {ACCENT_AMBER};
}}

QTabWidget::pane {{
    border: 1px solid {BORDER_COLOR};
    border-radius: 6px;
    background-color: {BG_SLATE_800};
}}

QTabBar::tab {{
    background-color: {BG_SLATE_700};
    color: {FG_WHITE};
    padding: 8px 16px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    margin-right: 2px;
}}

QTabBar::tab:selected {{
    background-color: {ACCENT_EMERALD};
    color: {BG_SLATE_900};
    font-weight: 600;
}}

QTabBar::tab:hover:!selected {{
    background-color: {BG_SLATE_600};
}}

QScrollArea {{
    border: none;
}}

QGroupBox {{
    border: 1px solid {BORDER_COLOR};
    border-radius: 6px;
    margin-top: 12px;
    padding-top: 12px;
    font-weight: 600;
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    color: {ACCENT_EMERALD};
}}

QTextEdit {{
    background-color: {BG_SLATE_800};
    color: {FG_WHITE};
    border: 1px solid {BORDER_COLOR};
    border-radius: 6px;
    padding: 8px;
}}

QListWidget {{
    background-color: {BG_SLATE_800};
    color: {FG_WHITE};
    border: 1px solid {BORDER_COLOR};
    border-radius: 6px;
}}

QListWidget::item {{
    padding: 8px;
    border-bottom: 1px solid {BG_SLATE_700};
}}

QListWidget::item:selected {{
    background-color: {BG_SLATE_700};
}}

QListWidget::item:hover {{
    background-color: {BG_SLATE_600};
}}
"""

SIDEBAR_STYLESHEET = f"""
QWidget#Sidebar {{
    background-color: {BG_SLATE_800};
    border-right: 1px solid {BORDER_COLOR};
}}

QPushButton#nav_button {{
    background-color: transparent;
    color: {FG_GRAY};
    border: none;
    border-radius: 8px;
    padding: 12px 16px;
    text-align: left;
    font-size: 14px;
    font-weight: 500;
}}

QPushButton#nav_button:hover {{
    background-color: {BG_SLATE_700};
    color: {FG_WHITE};
}}

QPushButton#nav_button:checked {{
    background-color: {BG_SLATE_700};
    color: {ACCENT_EMERALD};
    font-weight: 600;
}}
"""

CARD_STYLESHEET = f"""
QWidget#Card {{
    background-color: {BG_SLATE_800};
    border: 1px solid {BORDER_COLOR};
    border-radius: 8px;
}}
"""
