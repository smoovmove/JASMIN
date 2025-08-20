# gui/file_watcher.py
"""
File Watcher System for JASMIN GUI - CORRECTED
Properly integrates with JASMIN's directory structure and file conventions
"""

import os
from pathlib import Path
from typing import Dict, List, Optional, Set
from PyQt6.QtCore import QObject, QFileSystemWatcher, pyqtSignal, QTimer

class JasminFileWatcher(QObject):
    """
    File system watcher for JASMIN - CORRECTED
    Monitors JASMIN's actual directory structure and file naming conventions
    """
    
    # Signals for different file events
    scan_file_added = pyqtSignal(str)      # filename
    scan_file_modified = pyqtSignal(str)   # filename  
    scan_file_removed = pyqtSignal(str)    # filename
    
    notes_file_modified = pyqtSignal(str)  # filepath
    log_file_modified = pyqtSignal(str)    # filepath
    state_file_modified = pyqtSignal(str)  # filepath - NEW: Watch state.json
    session_changed = pyqtSignal()         # session files changed
    
    def __init__(self, jasmin_api):
        super().__init__()
        self.jasmin_api = jasmin_api
        self.watcher = QFileSystemWatcher()
        
        # Track what we're watching
        self.watched_files: Set[str] = set()
        self.watched_dirs: Set[str] = set()
        self.scan_files: Set[str] = set()
        
        # Connect watcher signals
        self.watcher.fileChanged.connect(self._on_file_changed)
        self.watcher.directoryChanged.connect(self._on_directory_changed)
        
        # Timer for periodic refresh (JASMIN files can change rapidly during scans)
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self._refresh_scan_files)
        self.refresh_timer.start(3000)  # Every 3 seconds for active scanning
        
        # Initialize watching using JASMIN's structure
        self._setup_jasmin_watchers()
    
    def _setup_jasmin_watchers(self):
        """Set up file/directory watchers for JASMIN's structure"""
        session_info = self.jasmin_api.get_session_info()
        
        # Watch JASMIN's scans directory
        self.watch_directory(session_info.scans_dir)
        
        # Watch JASMIN's notes file ({target_name}_notes.txt)
        self.watch_file(session_info.notes_path)
        
        # Watch JASMIN's command log
        self.watch_file(session_info.record_log)
        
        # Watch JASMIN's state.json file
        self.watch_file(session_info.state_file)
        
        # Watch JASMIN's main session directory
        self.watch_directory(session_info.outdir)
        
        # Watch Screenshots directory (JASMIN creates this)
        self.watch_directory(session_info.screenshots_dir)
        
        # Initialize scan files tracking
        self._refresh_scan_files()
        
        print(f"[+] File watchers set up for JASMIN session: {session_info.name}")
        print(f"[*] Watching: {session_info.outdir}")
    
    def watch_file(self, filepath: Path):
        """Add file to watcher - handles JASMIN file creation patterns"""
        str_path = str(filepath)
        if str_path not in self.watched_files:
            # Ensure parent directory exists (JASMIN creates directories dynamically)
            filepath.parent.mkdir(parents=True, exist_ok=True)
            
            # For JASMIN files, only watch if they exist
            # Don't auto-create files - let JASMIN create them naturally
            if filepath.exists():
                if self.watcher.addPath(str_path):
                    self.watched_files.add(str_path)
                    print(f"[*] Watching JASMIN file: {filepath.name}")
                else:
                    print(f"[!] Failed to watch file: {filepath}")
            else:
                # Queue for watching once created
                print(f"[*] Queued for watching: {filepath.name}")
    
    def watch_directory(self, dirpath: Path):
        """Add directory to watcher - handles JASMIN directory structure"""
        str_path = str(dirpath)
        if str_path not in self.watched_dirs:
            # Ensure directory exists (JASMIN creates subdirectories as needed)
            dirpath.mkdir(parents=True, exist_ok=True)
            
            if self.watcher.addPath(str_path):
                self.watched_dirs.add(str_path)
                print(f"[*] Watching JASMIN directory: {dirpath.name}")
            else:
                print(f"[!] Failed to watch directory: {dirpath}")
    
    def _on_file_changed(self, filepath: str):
        """Handle file change events - JASMIN specific handling"""
        path = Path(filepath)
        session_info = self.jasmin_api.get_session_info()
        
        try:
            # JASMIN notes file changed ({target_name}_notes.txt)
            if path == session_info.notes_path:
                self.notes_file_modified.emit(filepath)
                print(f"[*] JASMIN notes file changed: {path.name}")
            
            # JASMIN command log changed
            elif path == session_info.record_log:
                self.log_file_modified.emit(filepath)
                print(f"[*] JASMIN log file changed: {path.name}")
            
            # JASMIN state.json changed
            elif path == session_info.state_file:
                self.state_file_modified.emit(filepath)
                print(f"[*] JASMIN state file changed: {path.name}")
            
            # Other session files
            elif path.parent == session_info.outdir:
                self.session_changed.emit()
                print(f"[*] JASMIN session file changed: {path.name}")
            
        except Exception as e:
            print(f"[!] Error handling file change {filepath}: {e}")
    
    def _on_directory_changed(self, dirpath: str):
        """Handle directory change events - JASMIN specific"""
        path = Path(dirpath)
        session_info = self.jasmin_api.get_session_info()
        
        try:
            # JASMIN scans directory changed
            if path == session_info.scans_dir:
                self._handle_jasmin_scans_directory_change()
                print(f"[*] JASMIN scans directory changed")
            
            # JASMIN screenshots directory changed
            elif path == session_info.screenshots_dir:
                print(f"[*] JASMIN screenshots directory changed")
                self.session_changed.emit()
            
            # Main JASMIN session directory changed
            elif path == session_info.outdir:
                self._handle_jasmin_session_directory_change()
                print(f"[*] JASMIN session directory changed")
            
        except Exception as e:
            print(f"[!] Error handling directory change {dirpath}: {e}")
    
    def _handle_jasmin_scans_directory_change(self):
        """Handle changes in JASMIN scans directory"""
        session_info = self.jasmin_api.get_session_info()
        
        try:
            # Get current scan files (JASMIN naming patterns)
            current_files = set()
            if session_info.scans_dir.exists():
                for file_path in session_info.scans_dir.iterdir():
                    if file_path.is_file() and self._is_jasmin_scan_file(file_path):
                        current_files.add(file_path.name)
            
            # Check for new scan files
            new_files = current_files - self.scan_files
            for filename in new_files:
                self.scan_file_added.emit(filename)
                print(f"[+] New JASMIN scan file: {filename}")
            
            # Check for removed scan files
            removed_files = self.scan_files - current_files
            for filename in removed_files:
                self.scan_file_removed.emit(filename)
                print(f"[-] Removed JASMIN scan file: {filename}")
            
            # Check for modified scan files (size or time changes)
            for filename in current_files.intersection(self.scan_files):
                file_path = session_info.scans_dir / filename
                # Could implement more sophisticated modification detection
                # For now, assume any existing file might be modified
                
            # Update tracked files
            self.scan_files = current_files
            
        except Exception as e:
            print(f"[!] Error handling JASMIN scans directory change: {e}")
    
    def _handle_jasmin_session_directory_change(self):
        """Handle changes in main JASMIN session directory"""
        session_info = self.jasmin_api.get_session_info()
        
        try:
            # Check for new files that JASMIN might have created
            new_files = []
            for file_path in session_info.outdir.iterdir():
                if file_path.is_file():
                    str_path = str(file_path)
                    
                    # Watch important JASMIN files if they're newly created
                    if (file_path.name.endswith('_notes.txt') or 
                        file_path.name == 'commands.log' or
                        file_path.name == 'state.json' or
                        file_path.name == 'session.env'):
                        
                        if str_path not in self.watched_files:
                            self.watch_file(file_path)
                            new_files.append(file_path.name)
            
            if new_files:
                print(f"[+] Started watching new JASMIN files: {', '.join(new_files)}")
            
            self.session_changed.emit()
            
        except Exception as e:
            print(f"[!] Error handling JASMIN session directory change: {e}")
    
    def _is_jasmin_scan_file(self, file_path: Path) -> bool:
        """Check if file matches JASMIN scan file patterns"""
        filename = file_path.name.lower()
        
        # JASMIN scan file patterns
        jasmin_patterns = [
            # Nmap scans
            'nmap', 'tcp_scan', 'udp_scan', 'service_scan', 'script_scan',
            # Web enumeration
            'gobuster', 'dirb', 'nikto', 'web_headers', 'web_enum',
            # Other scan tools
            'masscan', 'rustscan', 'feroxbuster',
            # File extensions
            '.xml', '.txt', '.json', '.csv'
        ]
        
        return any(pattern in filename for pattern in jasmin_patterns)
    
    def _refresh_scan_files(self):
        """Periodically refresh scan files tracking"""
        try:
            session_info = self.jasmin_api.get_session_info()
            
            if not session_info.scans_dir.exists():
                return
            
            current_files = set()
            for file_path in session_info.scans_dir.iterdir():
                if file_path.is_file() and self._is_jasmin_scan_file(file_path):
                    current_files.add(file_path.name)
            
            # Check for changes
            if current_files != self.scan_files:
                self._handle_jasmin_scans_directory_change()
            
        except Exception as e:
            print(f"[!] Error refreshing JASMIN scan files: {e}")
    
    def refresh_watchers(self):
        """Refresh all watchers (call when JASMIN session changes)"""
        print("[*] Refreshing file watchers for new JASMIN session")
        
        # Remove all current watchers
        for path in list(self.watched_files):
            self.watcher.removePath(path)
        for path in list(self.watched_dirs):
            self.watcher.removePath(path)
        
        self.watched_files.clear()
        self.watched_dirs.clear()
        self.scan_files.clear()
        
        # Re-setup watchers for new JASMIN session
        self._setup_jasmin_watchers()
    
    def stop_watching(self):
        """Stop all file watching"""
        print("[*] Stopping JASMIN file watchers")
        
        self.refresh_timer.stop()
        
        # Remove all watchers
        for path in list(self.watched_files):
            self.watcher.removePath(path)
        for path in list(self.watched_dirs):
            self.watcher.removePath(path)
        
        self.watched_files.clear()
        self.watched_dirs.clear()
        self.scan_files.clear()

# Setup function for GUI integration
def setup_file_watchers(gui_instance):
    """Set up file watchers for GUI - CORRECTED for JASMIN integration"""
    gui_instance.file_watcher = JasminFileWatcher(gui_instance.api)
    
    # Connect signals to GUI methods
    gui_instance.file_watcher.scan_file_added.connect(gui_instance.on_scan_file_added)
    gui_instance.file_watcher.scan_file_modified.connect(gui_instance.on_scan_file_modified)
    gui_instance.file_watcher.scan_file_removed.connect(gui_instance.on_scan_file_removed)
    gui_instance.file_watcher.notes_file_modified.connect(gui_instance.on_notes_file_modified)
    gui_instance.file_watcher.log_file_modified.connect(gui_instance.on_log_file_modified)
    gui_instance.file_watcher.state_file_modified.connect(gui_instance.on_state_file_modified)
    gui_instance.file_watcher.session_changed.connect(gui_instance.on_session_changed)
    
    print("[+] JASMIN file watchers initialized")

def cleanup_file_watchers(gui_instance):
    """Clean up file watchers"""
    if hasattr(gui_instance, 'file_watcher'):
        gui_instance.file_watcher.stop_watching()
        print("[+] JASMIN file watchers cleaned up")