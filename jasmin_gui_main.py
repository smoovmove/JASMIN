#!/usr/bin/env python3
"""
JASMIN Workbench (redesigned to match original layout)
- Top: Tabs (Notes / Scans / State / Shells)
- Middle: Jobs panel (optional)
- Bottom: Terminal
- Directly calls jasmin.py handlers (no separate API layer)
"""

import sys, io, json, contextlib, os, shlex, platform, subprocess, shutil, time, re
from pathlib import Path
from typing import Dict, Any, Optional, List

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QLabel, QPlainTextEdit, QLineEdit, QPushButton, QListWidget, QListWidgetItem,
    QTabWidget, QMessageBox, QInputDialog, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QDialog, QDialogButtonBox, QTextEdit
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer, QProcess
from PyQt6.QtGui import QFont, QKeySequence, QAction, QTextCursor

# --- Import handlers directly from jasmin.py ---
# IMPORTANT: to avoid circular imports, jasmin.py should only import launch_gui()
# inside handle_gui_launch(), not at top-level.
from jasmin import (
    handle_target_command, handle_scan_command, handle_payload_command,
    handle_scans_command, handle_session_integrated_ip_command,
    handle_intel_command, handle_ad_command, handle_notes_command,
    handle_upload_command, view_file, show_help, check_web_tools_status,
    get_current_session_env
)

# Optional helpers
try:
    from state import load_state  # if present
except Exception:
    load_state = None

# Optional colon-commands (e.g., :goto notes)
try:
    from cli_verbs import CLIVerbs
except Exception:
    CLIVerbs = None

# Optional jobs system (kept for the Jobs panel design)
try:
    from jobs_system import JobsManager, JobStatus, create_jobs_manager  # type: ignore
    JOBS_AVAILABLE = True
except Exception as e:
    JobsManager = None
    JobStatus = None
    create_jobs_manager = None
    JOBS_AVAILABLE = False
    print(f"[*] Jobs system not available: {e}")

# Optional file watcher hooks
try:
    from file_watcher import setup_file_watchers, cleanup_file_watchers  # type: ignore
    WATCHERS_AVAILABLE = True
except Exception as e:
    setup_file_watchers = None
    cleanup_file_watchers = None
    WATCHERS_AVAILABLE = False
    print(f"[*] File watchers not available: {e}")


COSMIC = {
    "bg": "#0f1117", "panel": "#1f2229", "surface": "#151922",
    "border": "#2a2f3a", "text": "#d2d8e4", "muted": "#8b93a6",
    "accent": "#23d7e6", "green": "#8fe388", "red": "#ff6b6b", "yellow": "#ffd166",
}


class JobDetailsDialog(QDialog):
    """Dialog for showing detailed job information"""
    
    def __init__(self, parent, job):
        super().__init__(parent)
        self.job = job
        self.setWindowTitle(f"Job Details - {job.name}")
        self.resize(600, 500)
        
        layout = QVBoxLayout(self)
        
        # Details text area
        self.details_text = QPlainTextEdit()
        self.details_text.setFont(QFont("JetBrains Mono", 9))
        self.details_text.setReadOnly(True)
        layout.addWidget(self.details_text)
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.close)
        layout.addWidget(buttons)
        
        # Load job details
        self._load_details()
    
    def _load_details(self):
        """Load and display job details"""
        details = []
        
        # Basic info
        details.append(f"JOB DETAILS")
        details.append("=" * 50)
        details.append(f"ID: {self.job.id}")
        details.append(f"Type: {self.job.job_type.value if hasattr(self.job.job_type, 'value') else self.job.job_type}")
        details.append(f"Status: {self.job.status.value if hasattr(self.job.status, 'value') else self.job.status}")
        details.append(f"Progress: {self.job.progress}%")
        details.append(f"Created: {self.job.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
        
        if self.job.started_at:
            details.append(f"Started: {self.job.started_at.strftime('%Y-%m-%d %H:%M:%S')}")
        if self.job.completed_at:
            details.append(f"Completed: {self.job.completed_at.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Files
        details.append("")
        details.append("FILES")
        details.append("-" * 20)
        if self.job.artifact:
            details.append(f"Output: {self.job.artifact}")
            if self.job.artifact.exists():
                size = self.job.artifact.stat().st_size
                details.append(f"  Size: {size} bytes")
            else:
                details.append("  (file does not exist)")
        
        if self.job.log_path:
            details.append(f"Log: {self.job.log_path}")
            if not self.job.log_path.exists():
                details.append("  (log file does not exist)")
        
        # Error message
        if self.job.error_message:
            details.append("")
            details.append("ERROR MESSAGE")
            details.append("-" * 20)
            details.append(self.job.error_message)
        
        # Metadata
        if self.job.metadata:
            details.append("")
            details.append("METADATA")
            details.append("-" * 20)
            for key, value in self.job.metadata.items():
                details.append(f"{key}: {value}")
        
        # Log contents
        if self.job.log_path and self.job.log_path.exists():
            details.append("")
            details.append("LOG CONTENTS (last 50 lines)")
            details.append("-" * 40)
            try:
                with open(self.job.log_path, 'r') as f:
                    lines = f.readlines()
                    for line in lines[-50:]:
                        details.append(line.rstrip())
            except Exception as e:
                details.append(f"Error reading log: {e}")
        
        self.details_text.setPlainText("\n".join(details))


# ---------- tmux adapter ----------
class Tmux:
    """Tiny helper around a private tmux server (socket per target)."""
    def __init__(self, sock: str):
        self.sock = sock
        self.bin = shutil.which("tmux")
        self.available = bool(self.bin)

    def run(self, *args) -> subprocess.CompletedProcess:
        return subprocess.run([self.bin or "tmux", "-L", self.sock, *args],
                              capture_output=True, text=True)

    def ensure_session(self, session: str, cwd: str) -> bool:
        if not self.available:
            return False
        if self.run("has-session", "-t", session).returncode != 0:
            self.run("new-session", "-d", "-s", session, "-n", "gui", "-c", cwd)
            # branding & guardrails
            self.run("set-option", "-g", "automatic-rename", "off")
            self.run("set-window-option", "-g", "allow-rename", "off")
            self.run("set-option", "-g", "status-left", f"#[bold] JASMIN:{session} #[default]")
            self.run("set-option", "-g", "status-bg", "colour235")
            self.run("set-option", "-g", "status-fg", "colour45")
        return True

    def list_windows(self, session: str) -> list[str]:
        r = self.run("list-windows", "-t", session, "-F", "#{window_name}")
        return r.stdout.strip().splitlines() if r.returncode == 0 and r.stdout.strip() else []

    def window_exists(self, session: str, name: str) -> bool:
        return name in self.list_windows(session)

    def new_window(self, session: str, name: str, cwd: str):
        self.run("new-window", "-t", session, "-n", name, "-c", cwd)

    def rename_window(self, session: str, old: str, new: str):
        self.run("rename-window", "-t", f"{session}:{old}", new)

    def kill_window(self, session: str, name: str):
        self.run("kill-window", "-t", f"{session}:{name}")

    def first_pane_id(self, session: str, win_name: str) -> str | None:
        r = self.run("list-panes", "-t", f"{session}:{win_name}", "-F", "#{pane_id}")
        lines = r.stdout.strip().splitlines()
        return lines[0] if r.returncode == 0 and lines else None

    def is_piped(self, pane_id: str) -> bool:
        r = self.run("display-message", "-p", "-t", pane_id, "#{pane_pipe}")
        return bool(r.stdout.strip())

    def pipe_to_file(self, pane_id: str, filepath: str):
        self.run("pipe-pane", "-o", "-t", pane_id, f"stdbuf -oL cat >> {shlex.quote(filepath)}")

    def attach_cmd(self, session: str, win_name: str) -> list[str]:
        return ["tmux", "-L", self.sock, "attach", "-t", f"{session}:{win_name}"]


class JasminGUIWorkbench(QMainWindow):
    # Signals
    session_switched = pyqtSignal(str)  # session_name
    command_executed = pyqtSignal(str)  # command

    def __init__(self, env: Dict[str, Any]):
        super().__init__()
        if not env or "BOXNAME" not in env or "IP" not in env:
            raise ValueError("Invalid JASMIN session environment. Missing BOXNAME or IP.")
        
        # Validate environment
        if not env["BOXNAME"].strip():
            raise ValueError("BOXNAME cannot be empty")
        if not env["IP"].strip():
            raise ValueError("IP cannot be empty")

        # Session
        self.env = env
        self.target_name = env["BOXNAME"]
        self.target_ip = env["IP"]
        
        # Validate and setup output directory
        outdir_str = env.get("OUTDIR", ".")
        try:
            self.outdir = Path(outdir_str).resolve()
            # Ensure outdir exists
            self.outdir.mkdir(parents=True, exist_ok=True)
            print(f"[*] Output directory: {self.outdir}")
        except Exception as e:
            print(f"[!] Warning: Could not setup output directory '{outdir_str}': {e}")
            self.outdir = Path(".").resolve()

        # Validate target name for tmux compatibility
        if not self.target_name.replace("-", "").replace("_", "").isalnum():
            print(f"[!] Warning: target name '{self.target_name}' may cause tmux issues")

        # States
        self.notes_dirty = False
        self.current_shell_name = None  # Track current shell for interactive mode

        # Optional integrations
        self.cli_verbs = CLIVerbs(self) if CLIVerbs else None
        
        # Initialize jobs manager with better error handling
        if JOBS_AVAILABLE and create_jobs_manager:
            try:
                self.jobs_manager = create_jobs_manager(self.env)
                print(f"[+] Jobs system initialized successfully")
            except Exception as e:
                print(f"[!] Jobs system failed to initialize: {e}")
                self.jobs_manager = None
        else:
            self.jobs_manager = None

        # tmux integration
        self.sock = f"jasmin-{self.target_name}"
        self.tmux = Tmux(self.sock)
        self.shell_popouts: Dict[str, object] = {}
        
        if self.tmux.available:
            try:
                self.tmux.ensure_session(self.target_name, str(self.outdir))
                print(f"[+] tmux session '{self.target_name}' initialized")
            except Exception as e:
                print(f"[!] tmux session setup failed: {e}")
                print("[!] Shells panel will run in mock mode.")
                self.tmux.available = False
        else:
            print("[!] tmux not found - Shells panel will run in mock mode.")

        # UI setup
        self.apply_theme()
        self._build_ui()
        self._load_all()
        self._setup_file_watchers()

        # adopt loop for tmux windows (and start piping logs)
        if self.tmux.available:
            self._adopt_timer = QTimer(self)
            self._adopt_timer.setInterval(2000)
            self._adopt_timer.timeout.connect(self._tmux_adopt_safe)
            self._adopt_timer.start()
            self._tmux_adopt_safe()

        # Auto-refresh jobs panel
        if self.jobs_manager:
            self._jobs_refresh_timer = QTimer(self)
            self._jobs_refresh_timer.setInterval(5000)  # Every 5 seconds
            self._jobs_refresh_timer.timeout.connect(self._refresh_jobs)
            self._jobs_refresh_timer.start()

    def apply_theme(self):
        """Apply the COSMIC dark theme"""
        self.setStyleSheet(f"""
            QMainWindow {{ background: {COSMIC['bg']}; color: {COSMIC['text']}; }}
            QWidget {{ background: {COSMIC['bg']}; color: {COSMIC['text']}; }}
            QTabWidget::pane {{ border: 1px solid {COSMIC['border']}; }}
            QTabBar::tab {{ 
                background: {COSMIC['panel']}; color: {COSMIC['text']};
                border: 1px solid {COSMIC['border']}; padding: 6px 10px;
            }}
            QTabBar::tab:selected {{ background: {COSMIC['surface']}; }}
            QPlainTextEdit, QLineEdit {{
                background: {COSMIC['surface']}; color: {COSMIC['text']};
                border: 1px solid {COSMIC['border']}; padding: 4px;
            }}
            QPushButton {{
                background: {COSMIC['panel']}; color: {COSMIC['text']};
                border: 1px solid {COSMIC['border']}; padding: 6px 10px;
            }}
            QPushButton:hover {{ background: {COSMIC['surface']}; }}
            QListWidget {{
                background: {COSMIC['surface']}; color: {COSMIC['text']};
                border: 1px solid {COSMIC['border']};
            }}
            QTableWidget {{
                background: {COSMIC['surface']}; color: {COSMIC['text']};
                border: 1px solid {COSMIC['border']};
                gridline-color: {COSMIC['border']};
            }}
            QLabel {{ color: {COSMIC['text']}; }}
        """)

    def _build_ui(self):
        self.setWindowTitle(f"JASMIN Workbench - {self.target_name} ({self.target_ip})")
        self.resize(1320, 860)

        # Central/root
        central = QWidget(self)
        self.setCentralWidget(central)
        self.root_layout = QVBoxLayout(central)

        # Header (creates self.state_summary used later)
        self._build_header(self.root_layout)

        # Main splitter
        self.main_splitter = QSplitter(Qt.Orientation.Vertical)
        self.root_layout.addWidget(self.main_splitter)

        # TOP: Terminal
        self.terminal_widget = self._panel_terminal()
        self.main_splitter.addWidget(self.terminal_widget)

        # MIDDLE: Jobs
        self.jobs_panel = self._panel_jobs()
        self.main_splitter.addWidget(self.jobs_panel)

        # BOTTOM: Tabs
        self.main_tabs = QTabWidget()
        self.main_tabs.addTab(self._tab_notes(),  "Notes")
        self.main_tabs.addTab(self._tab_scans(),  "Scans")
        self.main_tabs.addTab(self._tab_state(),  "State")
        
        # Store shells panel reference for pop-out functionality
        self.shells_panel = self._tab_shells()
        self.main_tabs.addTab(self.shells_panel, "Shells")
        
        self.main_splitter.addWidget(self.main_tabs)

        # Proportions & collapsible sections
        self.default_split_sizes = [260, 100, 500]
        self.main_splitter.setSizes(self.default_split_sizes)
        self.main_splitter.setCollapsible(1, True)
        self.main_splitter.setCollapsible(2, True)

        # Menus (creates actions used by _focus_terminal/_restore_layout toggles)
        self._build_menu_bar()

    def _build_menu_bar(self):
        menubar = self.menuBar()

        # Session menu
        session_menu = menubar.addMenu('Session')

        act_refresh = QAction('Refresh Session', self)
        act_refresh.triggered.connect(self._refresh_session)
        session_menu.addAction(act_refresh)

        act_switch = QAction('Switch Sessionâ€¦', self)
        act_switch.triggered.connect(self._switch_session)
        session_menu.addAction(act_switch)

        # View menu
        view_menu = menubar.addMenu('View')

        self.act_toggle_jobs = QAction('Show Jobs Panel', self)
        self.act_toggle_jobs.setCheckable(True)
        self.act_toggle_jobs.setChecked(True)
        self.act_toggle_jobs.triggered.connect(self._toggle_jobs)
        view_menu.addAction(self.act_toggle_jobs)

        self.act_toggle_tabs = QAction('Show Main Tabs', self)
        self.act_toggle_tabs.setCheckable(True)
        self.act_toggle_tabs.setChecked(True)
        self.act_toggle_tabs.triggered.connect(self._toggle_tabs)
        view_menu.addAction(self.act_toggle_tabs)

        view_menu.addSeparator()

        act_focus_term = QAction('Focus Terminal', self)
        act_focus_term.setShortcut(QKeySequence("F11"))
        act_focus_term.triggered.connect(self._focus_terminal)
        view_menu.addAction(act_focus_term)

        act_restore = QAction('Restore Layout', self)
        act_restore.setShortcut(QKeySequence("Shift+F11"))
        act_restore.triggered.connect(self._restore_layout)
        view_menu.addAction(act_restore)

    def _build_header(self, parent_layout):
        row = QHBoxLayout()

        # Title/status
        title = QLabel(f"Session: {self.target_name} ({self.target_ip})")
        title.setFont(QFont("JetBrains Mono", 12, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {COSMIC['accent']};")
        row.addWidget(title)

        row.addStretch()

        # Summary of state (ports, services, etc.) - placeholder for now
        self.state_summary = QLabel("State: loading...")
        self.state_summary.setStyleSheet(f"color: {COSMIC['muted']};")
        row.addWidget(self.state_summary)

        parent_layout.addLayout(row)

    # -------------------------- Tab builders --------------------------
    def _tab_notes(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)

        row = QHBoxLayout()
        title = QLabel("Notes")
        title.setFont(QFont("JetBrains Mono", 11, QFont.Weight.Bold))
        row.addWidget(title)
        row.addStretch()

        btn_save = QPushButton("Save")
        btn_save.clicked.connect(self._save_notes)
        row.addWidget(btn_save)

        v.addLayout(row)

        self.notes_editor = QPlainTextEdit()
        self.notes_editor.setFont(QFont("JetBrains Mono", 10))
        self.notes_editor.textChanged.connect(lambda: setattr(self, 'notes_dirty', True))
        v.addWidget(self.notes_editor)

        return w

    def _tab_scans(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)

        row = QHBoxLayout()
        title = QLabel("Scans")
        title.setFont(QFont("JetBrains Mono", 11, QFont.Weight.Bold))
        row.addWidget(title)
        row.addStretch()

        btn_refresh = QPushButton("Refresh")
        btn_refresh.clicked.connect(self.refresh_scan_files)
        row.addWidget(btn_refresh)

        v.addLayout(row)

        # File list
        self.scan_files_list = QListWidget()
        self.scan_files_list.currentItemChanged.connect(self._on_scan_file_selected)
        v.addWidget(self.scan_files_list)

        return w

    def _tab_state(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)

        row = QHBoxLayout()
        title = QLabel("Session State (state.json)")
        title.setFont(QFont("JetBrains Mono", 11, QFont.Weight.Bold))
        row.addWidget(title)
        row.addStretch()

        btn_refresh = QPushButton("Refresh")
        btn_refresh.clicked.connect(self._load_state_view)
        row.addWidget(btn_refresh)
        v.addLayout(row)

        self.ports_list = QListWidget()
        self.services_list = QListWidget()
        self.creds_list = QListWidget()
        self.state_notes_list = QListWidget()

        tabs = QTabWidget()
        tabs.addTab(self.ports_list, "Ports")
        tabs.addTab(self.services_list, "Services")
        tabs.addTab(self.creds_list, "Credentials")
        tabs.addTab(self.state_notes_list, "State Notes")
        v.addWidget(tabs)

        return w

    def _tab_shells(self) -> QWidget:
        """Create shell management tab matching gui_demo layout"""
        wrap = QWidget()
        lay = QHBoxLayout(wrap)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.setSpacing(8)
        
        # Left column: header + list
        left = QVBoxLayout()
        hdr = QHBoxLayout()
        
        lbl = QLabel("Shells")
        lbl.setFont(QFont("JetBrains Mono", 11, QFont.Weight.Bold))
        
        btn_new = QPushButton("New shell")
        btn_new.clicked.connect(lambda: self._shell_new())
        
        btn_rename = QPushButton("Rename")
        btn_rename.clicked.connect(self._shell_rename_prompt)
        
        btn_kill = QPushButton("Kill")
        btn_kill.clicked.connect(self._shell_kill)
        
        btn_pop = QPushButton("Pop out/in")
        btn_pop.clicked.connect(self._shell_pop_selected)
        
        hdr.addWidget(lbl)
        hdr.addStretch()
        hdr.addWidget(btn_new)
        hdr.addWidget(btn_rename)
        hdr.addWidget(btn_kill)
        hdr.addWidget(btn_pop)
        
        self.shell_list = QListWidget()
        self.shell_list.currentItemChanged.connect(self._shell_show)
        
        left.addLayout(hdr)
        left.addWidget(self.shell_list)
        
        # Right column: title + output
        right = QVBoxLayout()
        
        self.shell_title = QLabel("No shell")
        self.shell_title.setFont(QFont("JetBrains Mono", 10, QFont.Weight.Bold))
        
        self.shells_output = QTextEdit()  # Using QTextEdit like demo
        self.shells_output.setReadOnly(False)  # Make it interactive!
        self.shells_output.setFont(QFont("JetBrains Mono", 10))
        self.shells_output.installEventFilter(self)  # Capture key events
        
        # Track current shell for interactive mode
        self.current_shell_name = None
        
        right.addWidget(self.shell_title)
        right.addWidget(self.shells_output)
        
        # Add to main layout with proportions (1:2 ratio like demo)
        lay.addLayout(left, 1)
        lay.addLayout(right, 2)
        
        return wrap

    # -------------------------- Panels --------------------------
    def _panel_terminal(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)

        row = QHBoxLayout()
        title = QLabel("JASMIN Terminal")
        title.setFont(QFont("JetBrains Mono", 11, QFont.Weight.Bold))
        row.addWidget(title)
        row.addStretch()

        btn_clear = QPushButton("Clear")
        btn_clear.clicked.connect(lambda: self.terminal.clear())
        row.addWidget(btn_clear)

        btn_max = QPushButton("â–² Max")
        btn_max.setToolTip("Maximize Terminal (F11)")
        btn_max.clicked.connect(self._focus_terminal)
        row.addWidget(btn_max)

        btn_restore = QPushButton("Restore")
        btn_restore.setToolTip("Restore Layout (Shift+F11)")
        btn_restore.clicked.connect(self._restore_layout)
        row.addWidget(btn_restore)

        v.addLayout(row)

        self.terminal = QPlainTextEdit()
        self.terminal.setFont(QFont("JetBrains Mono", 10))
        self.terminal.setReadOnly(True)
        v.addWidget(self.terminal)

        input_row = QHBoxLayout()
        self.prompt_label = QLabel(f"jasmin({self.target_name})>")
        self.prompt_label.setFont(QFont("JetBrains Mono", 10, QFont.Weight.Bold))
        input_row.addWidget(self.prompt_label)

        self.command_input = QLineEdit()
        self.command_input.setFont(QFont("JetBrains Mono", 10))
        self.command_input.returnPressed.connect(self._exec_command)
        input_row.addWidget(self.command_input)
        v.addLayout(input_row)

        # Welcome
        self._println("JASMIN GUI Mode - Integrated with JASMIN session")
        self._println(f"Session: {self.target_name} ({self.target_ip})")
        self._println(f"Directory: {self.outdir}")
        
        if self.jobs_manager:
            self._println("[+] Jobs system available - scans will run in background")
            self._println("    Use 'Cancel' button in jobs panel to stop running scans")
            self._println("    Use 'Details' button or double-click jobs to see error messages")
            self._println("    Old failed jobs are automatically cleaned up on startup")
        else:
            self._println("[*] Jobs system unavailable - scans will run synchronously")
            
        self._println("Type 'help' for commands or ':help' for GUI colon verbs\n")

        return w

    def _panel_jobs(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)

        row = QHBoxLayout()
        title = QLabel("Background Jobs")
        title.setFont(QFont("JetBrains Mono", 11, QFont.Weight.Bold))
        row.addWidget(title)
        row.addStretch()

        btn_refresh = QPushButton("Refresh")
        btn_refresh.clicked.connect(self._refresh_jobs)
        row.addWidget(btn_refresh)

        btn_details = QPushButton("Details")
        btn_details.clicked.connect(self._show_job_details)
        row.addWidget(btn_details)

        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self._cancel_selected_job)
        btn_cancel.setStyleSheet(f"QPushButton {{ background: {COSMIC['red']}; }}")
        row.addWidget(btn_cancel)

        btn_clear = QPushButton("Clear Completed")
        btn_clear.clicked.connect(self._clear_completed_jobs)
        row.addWidget(btn_clear)

        btn_clear_all = QPushButton("Clear All")
        btn_clear_all.clicked.connect(self._clear_all_jobs)
        btn_clear_all.setToolTip("Clear all jobs (including failed ones)")
        row.addWidget(btn_clear_all)

        btn_validate = QPushButton("Validate")
        btn_validate.clicked.connect(self._validate_jobs)
        btn_validate.setToolTip("Remove completed jobs with missing artifacts")
        row.addWidget(btn_validate)

        v.addLayout(row)

        self.jobs_table = QTableWidget(0, 4)
        self.jobs_table.setHorizontalHeaderLabels(["Name", "Status", "Progress", "Output"])
        header = self.jobs_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.jobs_table.setMaximumHeight(160)
        # Select entire rows when clicking
        self.jobs_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        # Enable double-click to view details
        self.jobs_table.itemDoubleClicked.connect(self._show_job_details)
        v.addWidget(self.jobs_table)

        if not self.jobs_manager:
            note = QLabel("Jobs system unavailable - scans will run synchronously (GUI may freeze)")
            note.setStyleSheet(f"color: {COSMIC['yellow']}; font-style: italic;")
            note.setWordWrap(True)
            v.addWidget(note)

        return w

    def _show_job_details(self):
        """Show detailed information about the selected job in a popup dialog"""
        if not self.jobs_manager:
            self._println("[!] Jobs system not available")
            return
            
        current_row = self.jobs_table.currentRow()
        if current_row < 0:
            self._println("[!] No job selected. Select a job to view details.")
            return
            
        try:
            # Get job info from the table
            job_name_item = self.jobs_table.item(current_row, 0)
            if not job_name_item:
                self._println("[!] Could not get job information")
                return
                
            display_name = job_name_item.text()
            
            # Find the job in the jobs manager by checking all jobs
            job = None
            for j in self.jobs_manager.get_all_jobs():
                if self._get_job_display_name(j) == display_name:
                    job = j
                    break
                    
            if not job:
                self._println(f"[!] Could not find job details for '{display_name}'")
                return
            
            # Show details dialog
            dialog = JobDetailsDialog(self, job)
            dialog.exec()
            
        except Exception as e:
            self._println(f"[!] Error showing job details: {e}")

    def _cancel_selected_job(self):
        """Cancel the currently selected job"""
        if not self.jobs_manager:
            self._println("[!] Jobs system not available")
            return
            
        current_row = self.jobs_table.currentRow()
        if current_row < 0:
            self._println("[!] No job selected. Select a job to cancel.")
            return
            
        try:
            job_name_item = self.jobs_table.item(current_row, 0)
            if not job_name_item:
                return
                
            job_name = job_name_item.text()
            
            # Find job by display name and cancel it
            for job in self.jobs_manager.get_all_jobs():
                if self._get_job_display_name(job) == job_name:
                    if hasattr(self.jobs_manager, 'cancel_job'):
                        self.jobs_manager.cancel_job(job.id)
                        self._println(f"[*] Cancelled job: {job_name}")
                    else:
                        self._println(f"[!] Job cancellation not supported")
                    break
            else:
                self._println(f"[!] Failed to cancel job: {job_name}")
                
            self._refresh_jobs()
            
        except Exception as e:
            self._println(f"[!] Error cancelling job: {e}")

    def _validate_jobs(self):
        """Manually validate jobs and remove bogus ones"""
        if self.jobs_manager:
            try:
                jobs_to_remove = []
                for job in self.jobs_manager.get_all_jobs():
                    # Check completed jobs for missing artifacts
                    if job.status.value == "completed":
                        if job.artifact and not job.artifact.exists():
                            jobs_to_remove.append((job.id, job.name, "missing artifact"))
                        elif not job.artifact:
                            jobs_to_remove.append((job.id, job.name, "no artifact specified"))
                
                # Remove invalid jobs
                for job_id, job_name, reason in jobs_to_remove:
                    if job_id in self.jobs_manager.jobs:
                        del self.jobs_manager.jobs[job_id]
                    if job_id in self.jobs_manager.workers:
                        del self.jobs_manager.workers[job_id]
                    self._println(f"[*] Removed invalid job '{job_name}': {reason}")
                
                if jobs_to_remove:
                    self.jobs_manager._save_jobs()
                    self._refresh_jobs()
                    self._println(f"[*] Validated jobs: removed {len(jobs_to_remove)} invalid entries")
                else:
                    self._println("[*] All jobs validated successfully - no issues found")
                    
            except Exception as e:
                self._println(f"[!] Error validating jobs: {e}")
        else:
            self._println("[!] Jobs system not available")

    def _clear_all_jobs(self):
        """Clear all jobs from the jobs manager"""
        if self.jobs_manager:
            try:
                # Clear all jobs
                self.jobs_manager.jobs.clear()
                self.jobs_manager.workers.clear()
                self.jobs_manager._save_jobs()
                self._refresh_jobs()
                self._println("[*] Cleared all jobs")
            except Exception as e:
                self._println(f"[!] Error clearing all jobs: {e}")
        else:
            # Just clear the table if no jobs manager
            self.jobs_table.setRowCount(0)
            self._println("[*] Cleared jobs display")

    # -------------------------- Scan helpers --------------------------
    def _start_scan(self, kind: str):
        """Start a scan using jobs system if available, otherwise run synchronously"""
        if self.jobs_manager:
            try:
                job_id = self.jobs_manager.start_scan(kind, self.target_ip)
                self._println(f"[*] Started {kind} scan in background (Job ID: {job_id})")
                self._println(f"[*] Use jobs panel to monitor progress or cancel")
                self._refresh_jobs()
                return
            except Exception as e:
                self._println(f"[!] JobsManager error: {e}")
                self._println(f"[*] Falling back to synchronous execution")

        # Fallback: route to core synchronously (will block GUI)
        self._println(f"[!] Jobs system unavailable - running {kind} scan synchronously")
        self._println(f"[!] GUI will be unresponsive until scan completes")
        
        mapping = {"tcp": "tcp", "full": "fs", "web": "web", "udp": "udp", "ss": "ss", "fs": "fs", "script": "script"}
        base_cmd = mapping.get(kind, kind)
        out = self._route_to_core(base_cmd)
        if out:
            self._println(out)

    def refresh_scan_files(self):
        """Refresh scan files list (exclude notes; show only scan artifacts)."""
        self.scan_files_list.clear()

        # extensions commonly produced by scanners / enumerators
        scan_exts = {'.nmap', '.gnmap', '.xml', '.nessus', '.csv', '.json', '.html', '.txt'}

        # filenames to always exclude
        deny_names = {
            f"{self.target_name}_notes.txt",
            "notes.txt",
            "README.txt",
        }

        # include rules: either extension in scan_exts and not in denylist,
        # and (a) name starts with target prefix, or (b) likely scan keyword
        likely_keywords = ("scan", "nmap", "udp", "tcp", "enum", "web", "gobuster", "ferox", "ffuf")

        def is_scan_file(path):
            name = path.name.lower()
            if name in (x.lower() for x in deny_names):
                return False
            if path.suffix.lower() not in scan_exts:
                return False
            if name.startswith(self.target_name.lower() + "_"):
                return True
            return any(k in name for k in likely_keywords)

        for p in sorted(self.outdir.glob("*")):
            if p.is_file() and is_scan_file(p):
                size = p.stat().st_size
                item_text = f"{p.name}  -  {size} bytes"
                item = QListWidgetItem(item_text)
                item.setData(Qt.ItemDataRole.UserRole, {"name": p.name, "path": str(p), "size": size, "type": p.suffix})
                self.scan_files_list.addItem(item)

    def _on_scan_file_selected(self, current: QListWidgetItem, previous):
        if not current:
            return
        data = current.data(Qt.ItemDataRole.UserRole)
        if data:
            filepath = data["path"]
            self._println(f"[*] Selected scan file: {data['name']}")
            # Optionally preview the file or open it
            try:
                with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                    preview = f.read(2000)  # First 2KB
                self._println(f"Preview:\n{preview}")
                if len(preview) >= 2000:
                    self._println("... (truncated)")
            except Exception as e:
                self._println(f"[!] Could not preview file: {e}")

    # -------------------------- Session & Data --------------------------
    def _notes_path(self) -> Path:
        return self.outdir / f"{self.target_name}_notes.txt"

    def _load_all(self):
        self._load_notes()
        self.refresh_scan_files()
        self._load_state_view()
        self._update_summary()

    def _load_notes(self):
        p = self._notes_path()
        self.notes_editor.setPlainText(p.read_text(encoding="utf-8") if p.exists() else "")
        self.notes_dirty = False

    def _save_notes(self):
        p = self._notes_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.notes_editor.toPlainText(), encoding="utf-8")
        self.notes_dirty = False
        self._println("[+] Notes saved.")

    def _load_state_view(self):
        """Load state.json and populate the various lists"""
        state_path = self.outdir / "state.json"
        if not state_path.exists():
            self._update_state_lists({})
            return

        try:
            with open(state_path, 'r', encoding='utf-8') as f:
                state = json.load(f)
            self._update_state_lists(state)
        except Exception as e:
            self._println(f"[!] Error loading state.json: {e}")
            self._update_state_lists({})

    def _update_state_lists(self, state: dict):
        """Update the state tab lists with data from state.json"""
        # Clear existing items
        for widget in [self.ports_list, self.services_list, self.creds_list, self.state_notes_list]:
            widget.clear()

        # Ports - handle both dict and list formats
        ports = state.get("ports", {})
        try:
            if isinstance(ports, dict):
                for port, info in ports.items():
                    if isinstance(info, dict):
                        status = info.get("status", "unknown")
                        service = info.get("service", "unknown")
                        self.ports_list.addItem(f"{port} ({status}) - {service}")
                    else:
                        self.ports_list.addItem(f"{port} - {info}")
            elif isinstance(ports, list):
                for port_item in ports:
                    if isinstance(port_item, dict):
                        port = port_item.get("port", "?")
                        status = port_item.get("status", "unknown")
                        service = port_item.get("service", "unknown")
                        self.ports_list.addItem(f"{port} ({status}) - {service}")
                    else:
                        self.ports_list.addItem(str(port_item))
        except Exception as e:
            self.ports_list.addItem(f"Error parsing ports: {e}")

        # Services - handle both dict and list formats
        services = state.get("services", {})
        try:
            if isinstance(services, dict):
                for service, info in services.items():
                    if isinstance(info, dict):
                        port = info.get("port", "?")
                        version = info.get("version", "")
                        self.services_list.addItem(f"{service} (:{port}) - {version}")
                    else:
                        self.services_list.addItem(f"{service} - {info}")
            elif isinstance(services, list):
                for service_item in services:
                    if isinstance(service_item, dict):
                        name = service_item.get("name", service_item.get("service", "?"))
                        port = service_item.get("port", "?")
                        version = service_item.get("version", "")
                        self.services_list.addItem(f"{name} (:{port}) - {version}")
                    else:
                        self.services_list.addItem(str(service_item))
        except Exception as e:
            self.services_list.addItem(f"Error parsing services: {e}")

        # Credentials - should be a list
        creds = state.get("credentials", [])
        try:
            for cred in creds:
                if isinstance(cred, dict):
                    user = cred.get("username", cred.get("user", "?"))
                    password = cred.get("password", cred.get("pass", "?"))
                    self.creds_list.addItem(f"{user}:{password}")
                else:
                    self.creds_list.addItem(str(cred))
        except Exception as e:
            self.creds_list.addItem(f"Error parsing credentials: {e}")

        # State notes - should always be a list
        notes = state.get("notes", [])
        try:
            for note in notes:
                self.state_notes_list.addItem(str(note))
        except Exception as e:
            self.state_notes_list.addItem(f"Error parsing notes: {e}")

    def _update_summary(self):
        """Update the header summary with key stats"""
        state_path = self.outdir / "state.json"
        if not state_path.exists():
            self.state_summary.setText("State: no state.json")
            return

        try:
            with open(state_path, 'r', encoding='utf-8') as f:
                state = json.load(f)
            
            # Handle different data structures
            ports = state.get("ports", {})
            port_count = len(ports) if isinstance(ports, (dict, list)) else 0
            
            services = state.get("services", {})
            service_count = len(services) if isinstance(services, (dict, list)) else 0
            
            creds = state.get("credentials", [])
            cred_count = len(creds) if isinstance(creds, list) else 0
            
            self.state_summary.setText(f"State: {port_count} ports, {service_count} services, {cred_count} creds")
        except Exception as e:
            self.state_summary.setText(f"State: error loading ({e})")

    def _refresh_session(self):
        """Reload all data from disk"""
        self._load_all()
        self._println("[*] Session data refreshed")

    def _switch_session(self):
        """Switch to a different session"""
        # This would need to be implemented based on your session management
        session_name, ok = QInputDialog.getText(self, "Switch Session", "Session name:")
        if ok and session_name:
            self._println(f"[*] Session switching to '{session_name}' not yet implemented")

    def _refresh_jobs(self):
        """Refresh the jobs table"""
        if not self.jobs_manager:
            return

        # Clear existing rows
        self.jobs_table.setRowCount(0)

        # Add current jobs
        try:
            jobs = self.jobs_manager.get_all_jobs()
            for i, job in enumerate(jobs):
                self.jobs_table.insertRow(i)
                self.jobs_table.setItem(i, 0, QTableWidgetItem(self._get_job_display_name(job)))
                self.jobs_table.setItem(i, 1, QTableWidgetItem(job.status.name))
                self.jobs_table.setItem(i, 2, QTableWidgetItem(f"{job.progress}%"))
                self.jobs_table.setItem(i, 3, QTableWidgetItem(str(job.artifact) if job.artifact else ""))
        except Exception as e:
            self._println(f"[!] Error refreshing jobs: {e}")
            # Add a row showing the error
            self.jobs_table.insertRow(0)
            self.jobs_table.setItem(0, 0, QTableWidgetItem("Error loading jobs"))
            self.jobs_table.setItem(0, 1, QTableWidgetItem("ERROR"))
            self.jobs_table.setItem(0, 2, QTableWidgetItem("0%"))
            self.jobs_table.setItem(0, 3, QTableWidgetItem("Check console"))

    def _get_job_display_name(self, job):
        """Get a user-friendly display name for the job"""
        if job.job_type.value == "scan_tcp":
            return "TCP Scan"
        elif job.job_type.value == "scan_full":
            return "Full Scan"
        elif job.job_type.value == "scan_web":
            return "Web Scan"
        elif job.job_type.value == "scan_udp":
            return "UDP Scan"
        elif job.job_type.value == "scan_script":
            return "Script Scan"
        elif job.job_type.value == "payload_generate":
            return "Payload Generation"
        else:
            return job.name

    def _clear_completed_jobs(self):
        """Clear completed jobs from the jobs manager and refresh display"""
        if self.jobs_manager:
            try:
                self.jobs_manager.clear_completed_jobs()
                self._refresh_jobs()
                self._println("[*] Cleared completed jobs")
            except Exception as e:
                self._println(f"[!] Error clearing jobs: {e}")
        else:
            # Just clear the table if no jobs manager
            self.jobs_table.setRowCount(0)
            self._println("[*] Cleared jobs display")

    # -------------------------- Terminal --------------------------
    def _exec_command(self):
        cmd = self.command_input.text().strip()
        if not cmd:
            return
        self._println(f"jasmin({self.target_name})> {cmd}")
        self.command_input.clear()

        # colon verbs
        if cmd.startswith(":") and self.cli_verbs and self.cli_verbs.execute_command(cmd):
            return

        # quick local helpers
        if cmd == "clear":
            self.terminal.clear()
            return
        if cmd == "state":
            self._load_state_view()
            return
        if cmd == "help":
            out = self._route_to_core("help")
            if out:
                self._println(out)
            return

        # Parse command
        tokens = cmd.split()
        if not tokens:
            return
        
        main_cmd = tokens[0].lower()

        # Route scan commands through jobs system (background execution)
        scan_commands = {"fs", "tcp", "udp", "web", "ss", "script"}
        
        if main_cmd in scan_commands:
            # Direct scan command (e.g., "tcp", "web")
            self._start_scan(main_cmd)
            
        elif main_cmd == "scan" and len(tokens) > 1:
            # Scan subcommand (e.g., "scan tcp", "scan full")
            sub_cmd = tokens[1].lower()
            if sub_cmd == "full":
                sub_cmd = "fs"  # map "scan full" to "fs"
            if sub_cmd in scan_commands:
                self._start_scan(sub_cmd)
            else:
                self._println("[!] Unknown scan type. Try: tcp, udp, web, fs, ss, script")
                
        else:
            # Route to core jasmin.py
            out = self._route_to_core(cmd)
            if out:
                self._println(out)
            else:
                self._println(f"[*] Unknown command: {cmd}")

    def _route_to_core(self, cmd: str) -> Optional[str]:
        """Route command to jasmin.py handlers with proper output capture"""
        buf_out = io.StringIO()
        buf_err = io.StringIO()

        try:
            with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
                # This should ideally route to your existing jasmin command parser
                # For now, just show that the command was received
                self._println(f"[*] Unknown command: {cmd}")

        except Exception as e:
            print(f"[!] Command error: {e}")

        captured_out = buf_out.getvalue()
        captured_err = buf_err.getvalue()
        result = captured_out + captured_err if captured_out or captured_err else None
        return result.strip() if result else None

    def eventFilter(self, obj, event):
        """Handle key events in the shell output widget for interactive mode"""
        if obj is self.shells_output and event.type() == event.Type.KeyPress:
            if self.current_shell_name and self.tmux.available:
                key = event.key()
                text = event.text()
                
                # Handle special keys
                if key == Qt.Key.Key_Return.value or key == Qt.Key.Key_Enter.value:
                    self._send_to_shell("\n")
                    return True
                elif key == Qt.Key.Key_Tab.value:
                    self._send_to_shell("\t")
                    return True
                elif key == Qt.Key.Key_Backspace.value:
                    self._send_to_shell("\b")
                    return True
                elif key == Qt.Key.Key_Up.value:
                    self._send_to_shell("\033[A")  # Up arrow
                    return True
                elif key == Qt.Key.Key_Down.value:
                    self._send_to_shell("\033[B")  # Down arrow
                    return True
                elif key == Qt.Key.Key_Left.value:
                    self._send_to_shell("\033[D")  # Left arrow
                    return True
                elif key == Qt.Key.Key_Right.value:
                    self._send_to_shell("\033[C")  # Right arrow
                    return True
                elif event.modifiers() & Qt.KeyboardModifier.ControlModifier:
                    # Handle Ctrl+C, Ctrl+D, etc.
                    if key == Qt.Key.Key_C.value:
                        self._send_to_shell("\003")  # Ctrl+C
                        return True
                    elif key == Qt.Key.Key_D.value:
                        self._send_to_shell("\004")  # Ctrl+D
                        return True
                    elif key == Qt.Key.Key_Z.value:
                        self._send_to_shell("\032")  # Ctrl+Z
                        return True
                elif text and text.isprintable():
                    # Regular printable characters
                    self._send_to_shell(text)
                    return True
        
        return super().eventFilter(obj, event)

    def _send_to_shell(self, text: str):
        """Send text to the current tmux shell"""
        if not self.current_shell_name or not self.tmux.available:
            return
        
        # Send keys to tmux session
        try:
            # Escape the text for tmux
            escaped_text = text.replace("'", "\\'")
            self.tmux.run("send-keys", "-t", f"{self.target_name}:{self.current_shell_name}", escaped_text)
        except Exception as e:
            self._println(f"[!] Failed to send to shell: {e}")

    def _strip_ansi_codes(self, text: str) -> str:
        """Remove only color ANSI escape sequences, keep formatting"""
        # Remove color codes but keep cursor positioning and other formatting
        color_codes = re.compile(r'\x1B\[[0-9;]*[mK]')  # Only color/erase codes
        return color_codes.sub('', text)

    def _println(self, text: str):
        """Print to terminal widget"""
        self.terminal.appendPlainText(text)

    def _update_shell_output_interactive(self, shell_name: str):
        """Update shell output while preserving cursor position for interactive mode"""
        try:
            log_content = self._strip_ansi_codes(self._read_log_tail(self._shell_log_path(shell_name)))
            
            # Only update if content changed
            current_content = self.shells_output.toPlainText()
            if log_content != current_content:
                # Remember cursor position
                cursor = self.shells_output.textCursor()
                scroll_pos = self.shells_output.verticalScrollBar().value()
                was_at_bottom = scroll_pos == self.shells_output.verticalScrollBar().maximum()
                
                # Update content
                self.shells_output.setPlainText(log_content)
                
                # Restore cursor to end and scroll position
                if was_at_bottom:
                    cursor.movePosition(cursor.MoveOperation.End)
                    self.shells_output.setTextCursor(cursor)
                    self.shells_output.verticalScrollBar().setValue(
                        self.shells_output.verticalScrollBar().maximum())
                else:
                    self.shells_output.verticalScrollBar().setValue(scroll_pos)
                    
        except Exception as e:
            pass

    # -------------------------- Visibility / Layout --------------------------
    def _toggle_jobs(self, checked: bool):
        self.jobs_panel.setVisible(checked)
        self._reflow_splitter()

    def _toggle_tabs(self, checked: bool):
        self.main_tabs.setVisible(checked)
        self._reflow_splitter()

    def _focus_terminal(self):
        self.jobs_panel.setVisible(False)
        self.main_tabs.setVisible(False)
        self.act_toggle_jobs.setChecked(False)
        self.act_toggle_tabs.setChecked(False)
        self._set_sizes(1, 0, 0)
        self.command_input.setFocus()

    def _restore_layout(self):
        self.jobs_panel.setVisible(True)
        self.main_tabs.setVisible(True)
        self.act_toggle_jobs.setChecked(True)
        self.act_toggle_tabs.setChecked(True)
        self._set_sizes(*self.default_split_sizes)

    def _reflow_splitter(self):
        terminal = self.terminal_widget.isVisible()
        jobs = self.jobs_panel.isVisible()
        tabs = self.main_tabs.isVisible()
        if terminal and not jobs and not tabs:
            self._set_sizes(1, 0, 0)
        elif terminal and jobs and not tabs:
            self._set_sizes(self.default_split_sizes[0], self.default_split_sizes[1], 0)
        elif terminal and tabs and not jobs:
            self._set_sizes(self.default_split_sizes[0], 0, self.default_split_sizes[2])
        else:
            self._set_sizes(*self.default_split_sizes)

    def _set_sizes(self, terminal: int, jobs: int, tabs: int):
        sizes = [0, 0, 0]
        sizes[self.main_splitter.indexOf(self.terminal_widget)] = terminal
        sizes[self.main_splitter.indexOf(self.jobs_panel)] = jobs
        sizes[self.main_splitter.indexOf(self.main_tabs)] = tabs
        self.main_splitter.setSizes(sizes)

    def _sync_prompt(self):
        new_name = self.env.get("BOXNAME", self.target_name)
        new_ip = self.env.get("IP", self.target_ip)
        if (new_name, new_ip) != (self.target_name, self.target_ip):
            self.target_name, self.target_ip = new_name, new_ip
            self.prompt_label.setText(f"jasmin({self.target_name})>")
            self.setWindowTitle(f"JASMIN Workbench - {self.target_name} ({self.target_ip})")

    # -------------------------- Shell helpers --------------------------
    def _tmux_available(self) -> bool:
        return self.tmux.available

    def _run_cmd_capture(self, args, cwd=None) -> tuple[int, str, str]:
        """Synchronous helper for small tmux commands."""
        try:
            p = subprocess.Popen(args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            out, err = p.communicate()
            return p.returncode, out or "", err or ""
        except Exception as e:
            return 1, "", str(e)

    def _shell_tmux_name(self) -> str:
        # per-target tmux session name
        return f"jasmin_{self.target_name}"

    def _shell_new(self, name: Optional[str] = None):
        """Create a new shell session"""
        if self.tmux.available:
            base = name or f"shell-{len(self.tmux.list_windows(self.target_name))+1}"
            name = self._unique_tmux_name(base)
            self.tmux.new_window(self.target_name, name, str(self.outdir))
            pane = self.tmux.first_pane_id(self.target_name, name)
            if pane:
                self.tmux.pipe_to_file(pane, self._shell_log_path(name))
            self._tmux_adopt_safe()
            items = self.shell_list.findItems(name, Qt.MatchFlag.MatchExactly)
            if items:
                self.shell_list.setCurrentItem(items[0])
            self._println(f"[*] Spawned tmux window {name}")
        else:
            if not name:
                name = self._unique_shell_name(f"shell-{self.shell_list.count()+1}")
            else:
                name = self._unique_shell_name(name)
            self.shell_list.addItem(QListWidgetItem(name))
            self.shell_list.setCurrentRow(self.shell_list.count()-1)
            self._println(f"[*] Spawned {name} (mock)")

    def _shell_rename_prompt(self):
        """Prompt user to rename selected shell"""
        it = self.shell_list.currentItem()
        if not it:
            return
        old = it.text()
        new, ok = QInputDialog.getText(self, "Rename shell", "New name:", text=old)
        if ok and new and new != old:
            self._shell_rename(old, new)

    def _shell_rename(self, old: str, new: str):
        """Rename a shell"""
        if self.tmux.available:
            new = self._unique_tmux_name(new)
            self.tmux.rename_window(self.target_name, old, new)
            pane = self.tmux.first_pane_id(self.target_name, new)
            if pane:
                self.tmux.pipe_to_file(pane, self._shell_log_path(new))
            self._tmux_adopt_safe()
            self._println(f"[*] Renamed {old} → {new}")
            items = self.shell_list.findItems(new, Qt.MatchFlag.MatchExactly)
            if items:
                self.shell_list.setCurrentItem(items[0])
                self.shell_title.setText(new)
            return
        # mock
        for i in range(self.shell_list.count()):
            it = self.shell_list.item(i)
            if it.text() == old:
                it.setText(self._unique_shell_name(new))
                if self.shell_title.text() == old:
                    self.shell_title.setText(it.text())
                self._println(f"[*] Renamed {old} → {it.text()}")
                return

    def _shell_kill(self):
        """Kill selected shell"""
        it = self.shell_list.currentItem()
        if not it:
            return
        name = it.text()
        
        # Clear current shell if we're killing it
        if self.current_shell_name == name:
            self.current_shell_name = None
        
        if self.tmux.available:
            self.tmux.kill_window(self.target_name, name)
            self._tmux_adopt_safe()
            self.shell_title.setText("No shell")
            self.shells_output.clear()
            self._println(f"[*] Killed {name}")
            return
        # mock
        row = self.shell_list.row(it)
        self.shell_list.takeItem(row)
        self.shell_title.setText("No shell")
        self.shells_output.clear()
        self._println(f"[*] Killed {name} (mock)")

    def _shell_show(self, it: QListWidgetItem):
        """Show current shell and make it interactive"""
        if not it:
            self.shell_title.setText("No shell")
            self.shells_output.clear()
            self.current_shell_name = None
            return
        
        name = it.text()
        self.shell_title.setText(f"{name} (interactive)")
        self.current_shell_name = name
        
        if self.tmux.available:
            # Stop any existing timer
            if hasattr(self, "_shell_tail_timer") and self._shell_tail_timer.isActive():
                self._shell_tail_timer.stop()
            
            # Load initial content with ANSI codes stripped
            initial_content = self._strip_ansi_codes(self._read_log_tail(self._shell_log_path(name)))
            self.shells_output.setPlainText(initial_content)
            
            # Set cursor to end
            cursor = self.shells_output.textCursor()
            cursor.movePosition(cursor.MoveOperation.End)
            self.shells_output.setTextCursor(cursor)
            
            # Set up real-time updates
            self._shell_tail_timer = QTimer(self)
            self._shell_tail_timer.setInterval(800)
            self._shell_tail_timer.timeout.connect(
                lambda n=name: self._update_shell_output_interactive(n))
            self._shell_tail_timer.start()
            
            # Focus the output widget so user can type immediately
            self.shells_output.setFocus()
        else:
            self.current_shell_name = None
            self.shells_output.setPlainText(f"{name} connected (mock)\n$ whoami\nkali\n$ pwd\n{self.outdir}\n$ ")

    def _shell_pop_selected(self):
        """Pop out selected shell to external terminal"""
        it = self.shell_list.currentItem()
        if it:
            self._shell_pop_toggle(it.text())

    def _shell_pop_toggle(self, name: str):
        """Toggle shell between GUI and external terminal"""
        if not name:
            return
        if self.tmux.available:
            proc = self.shell_popouts.get(name)
            if proc and getattr(proc, "poll", lambda: None)() is None:
                try:
                    proc.terminate()
                except Exception:
                    pass
                self.shell_popouts.pop(name, None)
                self._println(f"[*] Closed external client for {name}")
                return
            p = self._spawn_external_terminal(self.target_name, name)
            if p:
                self.shell_popouts[name] = p
                self._println(f"[*] Popped out {name}")
            return
        # mock fallback: detach widget to a window
        if name in self.shell_popouts:
            self.shell_popouts[name].close()
            self.shell_popouts.pop(name, None)
            return
        self.shells_output.setParent(None)
        win = QMainWindow(self)
        win.setWindowTitle(name)
        win.setCentralWidget(self.shells_output)
        win.resize(720, 460)
        win.show()
        self.shell_popouts[name] = win
        self.shells_output = QTextEdit()
        self.shells_output.setReadOnly(True)
        self.shells_output.setFont(QFont("JetBrains Mono", 10))
        # Re-add to right layout
        right_layout = self.shells_panel.layout().itemAt(1).layout()
        right_layout.addWidget(self.shells_output)

    def _unique_shell_name(self, base: str) -> str:
        """Generate unique shell name for mock mode"""
        existing_names = {self.shell_list.item(i).text() for i in range(self.shell_list.count())}
        if base not in existing_names:
            return base
        
        counter = 2
        while f"{base}-{counter}" in existing_names:
            counter += 1
        return f"{base}-{counter}"

    def _unique_tmux_name(self, base: str) -> str:
        """Generate unique tmux window name"""
        if not self.tmux.available:
            return self._unique_shell_name(base)
        
        existing_windows = set(self.tmux.list_windows(self.target_name))
        if base not in existing_windows:
            return base
        
        counter = 2
        while f"{base}-{counter}" in existing_windows:
            counter += 1
        return f"{base}-{counter}"

    def _spawn_external_terminal(self, session: str, window_name: str):
        """Spawn external terminal for tmux attachment"""
        # Build tmux attach command
        attach_cmd = self.tmux.attach_cmd(session, window_name)
        
        # Try different terminal emulators based on platform
        if platform.system() == "Darwin":
            # macOS
            script = f'tell app "Terminal" to do script "{" ".join(attach_cmd)}"'
            try:
                return subprocess.Popen(["osascript", "-e", script])
            except Exception:
                pass
        
        elif platform.system() == "Linux":
            # Linux - try common terminal emulators
            terminals = [
                ["gnome-terminal", "--", *attach_cmd],
                ["konsole", "-e", *attach_cmd],
                ["xfce4-terminal", "-e", " ".join(attach_cmd)],
                ["alacritty", "-e", *attach_cmd],
                ["kitty", *attach_cmd],
                ["xterm", "-e", " ".join(attach_cmd)]
            ]
            
            for term_cmd in terminals:
                try:
                    proc = subprocess.Popen(term_cmd)
                    return proc
                except (FileNotFoundError, subprocess.SubprocessError):
                    continue
        
        # Fallback: just show command to run manually
        self._println(f"[!] Could not launch terminal. Run manually: {' '.join(attach_cmd)}")
        return None

    def _shell_list(self):
        """List tmux sessions for debugging"""
        if self._tmux_available():
            rc, out, err = self._run_cmd_capture(["tmux", "list-sessions"])
            self._println(out or err or "[*] No tmux sessions.")
        else:
            self._println("[*] tmux not available; external terminals are not tracked.")

    def _shell_attach(self):
        """Attach to tmux session in external terminal"""
        if not self._tmux_available():
            self._println("[!] tmux not available.")
            return
        sess = self._shell_tmux_name()
        # try to attach in a new external terminal window so GUI doesn't block
        for cmd in (["x-terminal-emulator", "-e", f"tmux attach -t {sess}"],
                    ["gnome-terminal", "--", "tmux", "attach", "-t", sess],
                    ["xterm", "-e", f"tmux attach -t {sess}"]):
            try:
                proc = QProcess(self)
                proc.setProgram(cmd[0])
                proc.setArguments(cmd[1:])
                proc.setWorkingDirectory(str(self.outdir))
                if proc.startDetached():
                    self._println(f"[+] Attach launched for session {sess}")
                    return
            except Exception:
                continue
        self._println("[!] Could not open a terminal to attach. Run manually: tmux attach -t " + sess)

    def _shell_log_path(self, name: str) -> str:
        return str(Path(self.outdir, f"{name}.log"))

    def _read_log_tail(self, path: str, max_lines: int = 1500) -> str:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except Exception:
            return "(no output yet)"
        lines = text.splitlines()
        if len(lines) > max_lines:
            lines = lines[-max_lines:]
        return "\n".join(lines)

    def _tmux_adopt(self):
        """Discover windows, ensure logging, and reflect them in the Shells list."""
        if not self.tmux.available:
            return
        wins = self.tmux.list_windows(self.target_name)
        # ensure piping for each window
        for w in wins:
            pane = self.tmux.first_pane_id(self.target_name, w)
            if pane and not self.tmux.is_piped(pane):
                self.tmux.pipe_to_file(pane, self._shell_log_path(w))
        # sync GUI list
        existing = {self.shell_list.item(i).text() for i in range(self.shell_list.count())}
        for w in wins:
            if w not in existing:
                self.shell_list.addItem(QListWidgetItem(w))
        i = 0
        while i < self.shell_list.count():
            if self.shell_list.item(i).text() not in wins:
                self.shell_list.takeItem(i)
            else:
                i += 1

    def _tmux_adopt_safe(self):
        """Safe wrapper for tmux adopt that handles errors gracefully"""
        try:
            self._tmux_adopt()
        except Exception as e:
            print(f"[!] tmux adopt error: {e}")
            # Disable tmux if it's consistently failing
            if hasattr(self, '_tmux_error_count'):
                self._tmux_error_count += 1
                if self._tmux_error_count > 5:
                    print("[!] Too many tmux errors, disabling tmux integration")
                    self.tmux.available = False
                    if hasattr(self, '_adopt_timer'):
                        self._adopt_timer.stop()
            else:
                self._tmux_error_count = 1

    # -------------------------- File watchers --------------------------
    def _setup_file_watchers(self):
        """Set up file watchers if available"""
        if not WATCHERS_AVAILABLE or not setup_file_watchers:
            return
            
        try:
            # Some file watcher systems expect an 'api' attribute
            # Create a minimal stub if needed
            if not hasattr(self, 'api'):
                self.api = self  # Use self as a fallback
                
            # Some file watchers expect get_session_info method
            if not hasattr(self, 'get_session_info'):
                # Create a simple session info object
                class SessionInfo:
                    def __init__(self, name, ip, outdir):
                        self.name = name
                        self.ip = ip
                        self.outdir = outdir
                        self.scans_dir = outdir
                        
                self.get_session_info = lambda: SessionInfo(self.target_name, self.target_ip, self.outdir)
                
            setup_file_watchers(self)
            print("[*] File watchers enabled")
        except Exception as e:
            # Don't spam the user with watcher errors - they're optional
            print(f"[*] File watchers disabled: {e}")

    def closeEvent(self, event):
        if self.notes_dirty:
            reply = QMessageBox.question(
                self, "Unsaved Changes",
                "You have unsaved notes. Save before closing?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel
            )
            if reply == QMessageBox.StandardButton.Yes:
                self._save_notes()
                event.accept()
            elif reply == QMessageBox.StandardButton.No:
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()

        # Cleanup
        if cleanup_file_watchers:
            try:
                cleanup_file_watchers()
            except Exception:
                pass


# ============================================================================
# ENTRY POINT
# ============================================================================

def launch_gui(env: Dict[str, Any]) -> bool:
    """Launch the GUI workbench"""
    try:
        # Ensure we have Qt
        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv)

        # Create and show the workbench
        print(f"[*] Creating GUI workbench for {env.get('BOXNAME', 'unknown')}...")
        workbench = JasminGUIWorkbench(env)
        workbench.show()
        
        print("[+] JASMIN GUI launched successfully")
        # Run the GUI event loop
        app.exec()
        return True

    except ImportError as e:
        print(f"[!] GUI dependency missing: {e}")
        print("[*] Install with: pip install PyQt6")
        return False
    except Exception as e:
        import traceback
        print(f"[!] GUI launch failed: {e}")
        print(f"[!] Traceback: {traceback.format_exc()}")
        return False