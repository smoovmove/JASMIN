# gui/cli_verbs.py
"""
Enhanced CLI Verbs System for JASMIN GUI
Colon commands for rapid GUI navigation and operations
"""

import re
import subprocess
import platform
import os 
from pathlib import Path
from typing import Dict, List, Optional, Callable, Any
from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWidgets import QMessageBox

class CLIVerbsHandler(QObject):
    """
    Handles colon commands (:command) for GUI navigation and operations
    """
    
    # Signals for GUI actions
    goto_tab = pyqtSignal(str)      # tab_name
    message_output = pyqtSignal(str) # message
    
    def __init__(self, gui_instance):
        super().__init__()
        self.gui = gui_instance
        self.api = gui_instance.api
        
        # Command registry
        self.commands = self._build_command_registry()
        
        print("[+] CLI Verbs handler initialized")
    
    def _build_command_registry(self) -> Dict[str, Callable]:
        """Build registry of available commands"""
        return {
            # Navigation commands
            'goto': self._cmd_goto,
            'tab': self._cmd_goto,  # alias
            
            # Shell commands
            'shell': self._cmd_shell,
            
            # Notes commands
            'notes': self._cmd_notes,
            
            # Scans commands
            'scans': self._cmd_scans,
            
            # Payload commands
            'payload': self._cmd_payload,
            
            # File operations
            'open': self._cmd_open,
            'outdir': self._cmd_outdir,
            
            # System commands
            'ip': self._cmd_ip,
            'mark': self._cmd_mark,
            'jobs': self._cmd_jobs,
            
            # Search commands
            'find': self._cmd_find,
            'grep': self._cmd_grep,
            
            # Help
            'help': self._cmd_help,
        }
    
    def execute_command(self, command: str) -> bool:
        """
        Execute a colon command
        Returns True if command was handled, False otherwise
        """
        if not command.startswith(':'):
            return False
        
        # Parse command
        command = command[1:]  # Remove colon
        parts = command.split()
        if not parts:
            return False
        
        cmd_name = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        # Execute command
        try:
            if cmd_name in self.commands:
                self.commands[cmd_name](args)
                return True
            else:
                self.message_output.emit(f"Unknown command: :{cmd_name}")
                return True
        except Exception as e:
            self.message_output.emit(f"Error executing :{cmd_name}: {e}")
            return True
    
    def get_available_commands(self) -> List[str]:
        """Get list of available commands for autocomplete"""
        commands = []
        for cmd in self.commands.keys():
            commands.append(f":{cmd}")
        
        # Add specific subcommands
        commands.extend([
            ":goto notes", ":goto scans", ":goto state", ":goto shells",
            ":shell new", ":shell pop", ":shell pin", ":shell rename",
            ":notes save", ":notes open", ":notes quick", ":notes insert", ":notes find",
            ":scans list", ":scans open", ":scans grep",
            ":state show", ":state refresh", ":state ports", ":state creds",
            ":ip copy", ":outdir open", ":mark",
            ":jobs toggle", ":jobs clear"
        ])
        
        return commands
    
    # === Command Implementations ===
    
    def _cmd_goto(self, args: List[str]):
        """Navigate to different tabs"""
        if not args:
            self.message_output.emit("Usage: :goto <tab>")
            return
        
        tab_name = args[0].lower()
        tab_map = {
            'notes': 0,
            'scans': 1, 
            'shells': 2,
            'shell': 2,
            'payload': 3,
            'payloads': 3,
            'terminal': 4
        }
        
        if tab_name in tab_map:
            self.gui.main_tabs.setCurrentIndex(tab_map[tab_name])
            self.message_output.emit(f"Switched to {tab_name}")
        else:
            self.message_output.emit(f"Unknown tab: {tab_name}")
    
    def _cmd_shell(self, args: List[str]):
        """Shell management commands"""
        if not args:
            self.message_output.emit("Usage: :shell <new|pop|pin|rename|list>")
            return
        
        action = args[0].lower()
        
        if action == 'new':
            name = args[1] if len(args) > 1 else "Shell"
            shell_id = self.api.create_shell_session(name)
            self.message_output.emit(f"Created shell: {name}")
            
        elif action == 'list':
            shells = self.api.get_shell_sessions()
            if shells:
                shell_list = "\n".join([f"  {s['name']} ({s['status']})" for s in shells])
                self.message_output.emit(f"Active shells:\n{shell_list}")
            else:
                self.message_output.emit("No active shells")
                
        elif action == 'pop':
            # TODO: Implement shell popup window
            self.message_output.emit("Shell popup not implemented yet")
            
        elif action == 'pin':
            self.message_output.emit("Shell pinning not implemented yet")
            
        elif action == 'rename':
            self.message_output.emit("Shell renaming not implemented yet")
            
        else:
            self.message_output.emit(f"Unknown shell action: {action}")
    
    def _cmd_notes(self, args: List[str]):
        """Notes management commands - CORRECTED to use JASMIN notes system"""
        if not args:
            self.message_output.emit("Usage: :notes <save|open|insert|find|quick>")
            return
        
        action = args[0].lower()
        
        if action == 'save':
            if hasattr(self.gui, 'save_notes'):
                self.gui.save_notes()
            else:
                self.message_output.emit("Notes save not available")
                
        elif action == 'open':
            notes_path = self.api.get_session_info().notes_path
            self._open_in_editor(notes_path)
            
        elif action == 'quick':
            # Use JASMIN's quick note system
            note_text = ' '.join(args[1:]) if len(args) > 1 else ""
            if note_text:
                if self.api.add_quick_note(note_text):
                    self.message_output.emit(f"Quick note added: {note_text}")
                    if hasattr(self.gui, 'load_session_data'):
                        self.gui.load_session_data()  # Refresh GUI
                else:
                    self.message_output.emit("Failed to add quick note")
            else:
                self.message_output.emit("Usage: :notes quick <text>")
                
        elif action == 'insert':
            text = ' '.join(args[1:]) if len(args) > 1 else ""
            if hasattr(self.gui, 'notes_editor'):
                cursor = self.gui.notes_editor.textCursor()
                cursor.insertText(text + "\n")
                self.message_output.emit("Text inserted")
            else:
                self.message_output.emit("Notes editor not available")
                
        elif action == 'find':
            search_term = ' '.join(args[1:]) if len(args) > 1 else ""
            if search_term and hasattr(self.gui, 'notes_editor'):
                # Simple find in notes
                content = self.gui.notes_editor.toPlainText()
                if search_term.lower() in content.lower():
                    self.message_output.emit(f"Found '{search_term}' in notes")
                else:
                    self.message_output.emit(f"'{search_term}' not found in notes")
            else:
                self.message_output.emit("Usage: :notes find <text>")
                
        else:
            self.message_output.emit(f"Unknown notes action: {action}")
    
    def _cmd_scans(self, args: List[str]):
        """Scans management commands"""
        if not args:
            self.message_output.emit("Usage: :scans <list|open|grep>")
            return
        
        action = args[0].lower()
        
        if action == 'list':
            scan_files = self.api.list_scan_files()
            if scan_files:
                file_list = "\n".join([f"  {f['name']} ({f['type']})" for f in scan_files])
                self.message_output.emit(f"Scan files:\n{file_list}")
            else:
                self.message_output.emit("No scan files found")
                
        elif action == 'open':
            if len(args) > 1:
                filename = args[1]
                scan_files = self.api.list_scan_files()
                matching_files = [f for f in scan_files if filename.lower() in f['name'].lower()]
                
                if matching_files:
                    file_path = matching_files[0]['path']
                    self._open_file(file_path)
                else:
                    self.message_output.emit(f"Scan file not found: {filename}")
            else:
                self.message_output.emit("Usage: :scans open <filename>")
                
        elif action == 'grep':
            if len(args) > 1:
                search_term = ' '.join(args[1:])
                self._grep_scan_files(search_term)
            else:
                self.message_output.emit("Usage: :scans grep <pattern>")
                
        else:
            self.message_output.emit(f"Unknown scans action: {action}")
    
    def _cmd_payload(self, args: List[str]):
        """Payload commands"""
        if not args:
            self.message_output.emit("Usage: :payload <set|generate>")
            return
        
        action = args[0].lower()
        
        if action == 'set':
            # Switch to payload tab
            self.gui.main_tabs.setCurrentIndex(3)
            self.message_output.emit("Switched to payload tab")
            
        elif action == 'generate':
            # TODO: Quick payload generation
            self.message_output.emit("Quick payload generation not implemented yet")
            
        else:
            self.message_output.emit(f"Unknown payload action: {action}")
    
    def _cmd_open(self, args: List[str]):
        """Open files or directories"""
        if not args:
            self.message_output.emit("Usage: :open <file|directory>")
            return
        
        target = ' '.join(args)
        
        # Try different interpretations
        session_info = self.api.get_session_info()
        
        # Check if it's a relative path in session directory
        relative_path = session_info.outdir / target
        if relative_path.exists():
            self._open_file(relative_path)
            return
        
        # Check if it's an absolute path
        abs_path = Path(target)
        if abs_path.exists():
            self._open_file(abs_path)
            return
        
        self.message_output.emit(f"File not found: {target}")
    
    def _cmd_outdir(self, args: List[str]):
        """Open output directory"""
        action = args[0] if args else 'open'
        
        if action == 'open':
            outdir = self.api.get_session_info().outdir
            self._open_in_file_manager(outdir)
            self.message_output.emit(f"Opened: {outdir}")
        else:
            self.message_output.emit(f"Unknown outdir action: {action}")
    
    def _cmd_ip(self, args: List[str]):
        """IP address operations"""
        action = args[0] if args else 'show'
        
        if action == 'copy':
            # Copy IP to clipboard
            ip = self.api.get_session_info().ip
            try:
                import pyperclip
                pyperclip.copy(ip)
                self.message_output.emit(f"Copied IP to clipboard: {ip}")
            except ImportError:
                self.message_output.emit(f"IP address: {ip} (pyperclip not available)")
        else:
            ip = self.api.get_session_info().ip
            self.message_output.emit(f"Target IP: {ip}")
    
    def _cmd_mark(self, args: List[str]):
        """Mark important findings"""
        if args:
            mark_text = ' '.join(args)
            timestamp = self.api.get_session_info().created_at if hasattr(self.api.get_session_info(), 'created_at') else "now"
            mark_entry = f"[MARK] {timestamp}: {mark_text}\n"
            
            # Add to notes
            if hasattr(self.gui, 'notes_editor'):
                cursor = self.gui.notes_editor.textCursor()
                cursor.movePosition(cursor.MoveOperation.End)
                cursor.insertText(mark_entry)
                self.message_output.emit(f"Marked: {mark_text}")
            else:
                self.message_output.emit("Notes editor not available")
        else:
            self.message_output.emit("Usage: :mark <text>")
    
    def _cmd_state(self, args: List[str]):
        """State management commands - NEW: Uses JASMIN's state.json"""
        action = args[0] if args else 'show'
        
        if action == 'show':
            # Show current state summary
            try:
                state = self.api.get_state()
                ports_count = len(state.get('ports', []))
                creds_count = len(state.get('credentials', []))
                services_count = len(state.get('services', []))
                notes_count = len(state.get('notes', []))
                
                summary = f"""State Summary:
  Ports: {ports_count}
  Services: {services_count}  
  Credentials: {creds_count}
  Notes: {notes_count}"""
                self.message_output.emit(summary)
            except Exception as e:
                self.message_output.emit(f"Error reading state: {e}")
                
        elif action == 'refresh':
            # Refresh state display
            if hasattr(self.gui, 'refresh_state_display'):
                self.gui.refresh_state_display()
                self.message_output.emit("State display refreshed")
            else:
                self.message_output.emit("State refresh not available")
                
        elif action == 'ports':
            # Show ports from state
            try:
                state = self.api.get_state()
                ports = state.get('ports', [])
                if ports:
                    port_list = "\n".join([f"  {port}" for port in ports])
                    self.message_output.emit(f"Discovered ports:\n{port_list}")
                else:
                    self.message_output.emit("No ports in state")
            except Exception as e:
                self.message_output.emit(f"Error reading ports: {e}")
                
        elif action == 'creds':
            # Show credentials from state  
            try:
                state = self.api.get_state()
                creds = state.get('credentials', [])
                if creds:
                    cred_list = "\n".join([f"  {cred}" for cred in creds])
                    self.message_output.emit(f"Stored credentials:\n{cred_list}")
                else:
                    self.message_output.emit("No credentials in state")
            except Exception as e:
                self.message_output.emit(f"Error reading credentials: {e}")
                
        else:
            self.message_output.emit(f"Unknown state action: {action}")
    
    def _cmd_jobs(self, args: List[str]):
        """Jobs management commands"""
        action = args[0] if args else 'list'
        
        if action == 'toggle':
            # Toggle jobs panel visibility
            if hasattr(self.gui, 'jobs_visible'):
                self.gui.jobs_visible = not self.gui.jobs_visible
                # TODO: Implement actual jobs panel toggle
                self.message_output.emit(f"Jobs panel: {'visible' if self.gui.jobs_visible else 'hidden'}")
            else:
                self.message_output.emit("Jobs panel toggle not available")
                
        elif action == 'clear':
            if hasattr(self.gui, 'jobs_manager'):
                self.gui.jobs_manager.clear_completed_jobs()
                self.message_output.emit("Cleared completed jobs")
            else:
                self.message_output.emit("Jobs manager not available")
                
        elif action == 'list':
            if hasattr(self.gui, 'jobs_manager'):
                jobs = self.gui.jobs_manager.get_all_jobs()
                if jobs:
                    job_list = "\n".join([f"  {j.name} ({j.status.value})" for j in jobs])
                    self.message_output.emit(f"Jobs:\n{job_list}")
                else:
                    self.message_output.emit("No jobs")
            else:
                self.message_output.emit("Jobs manager not available")
                
        else:
            self.message_output.emit(f"Unknown jobs action: {action}")
    
    def _cmd_find(self, args: List[str]):
        """Global search"""
        if not args:
            self.message_output.emit("Usage: :find <search_term>")
            return
        
        search_term = ' '.join(args)
        # TODO: Implement global search across notes and scan files
        self.message_output.emit(f"Global search not implemented yet: {search_term}")
    
    def _cmd_grep(self, args: List[str]):
        """Grep scan files"""
        if not args:
            self.message_output.emit("Usage: :grep <pattern>")
            return
        
        pattern = ' '.join(args)
        self._grep_scan_files(pattern)
    
    def _cmd_help(self, args: List[str]):
        """Show help for colon commands"""
        help_text = """
Available colon commands:

Navigation:
  :goto <tab>        Switch to tab (notes, scans, state, shells)
  
Shell Management:
  :shell new [name]  Create new shell session
  :shell list        List active shells
  
Notes (JASMIN Integration):
  :notes save        Save notes
  :notes open        Open notes in external editor
  :notes quick <text>  Add quick note to [Quick Notes] section
  :notes insert <text>  Insert text at cursor
  :notes find <text>    Find text in notes
  
State (JASMIN state.json):
  :state show        Show state summary
  :state refresh     Refresh state display
  :state ports       Show discovered ports
  :state creds       Show stored credentials
  
Scans:
  :scans list        List scan files
  :scans open <file> Open scan file
  :scans grep <pattern>  Search in scan files
  
Files:
  :open <path>       Open file/directory
  :outdir open       Open output directory
  
Utilities:
  :ip copy           Copy target IP to clipboard
  :mark <text>       Mark important finding in notes
  :jobs toggle       Toggle jobs panel
  :jobs clear        Clear completed jobs
  :find <term>       Global search
  :grep <pattern>    Search scan files
  
  :help              Show this help
"""
        self.message_output.emit(help_text)
    
    # === Helper Methods ===
    
    def _open_file(self, file_path: Path):
        """Open file in default application"""
        try:
            if platform.system() == "Darwin":
                subprocess.run(["open", str(file_path)])
            elif platform.system() == "Windows":
                os.startfile(str(file_path))
            else:
                subprocess.run(["xdg-open", str(file_path)])
        except Exception as e:
            self.message_output.emit(f"Error opening file: {e}")
    
    def _open_in_file_manager(self, dir_path: Path):
        """Open directory in file manager"""
        try:
            if platform.system() == "Darwin":
                subprocess.run(["open", str(dir_path)])
            elif platform.system() == "Windows":
                subprocess.run(["explorer", str(dir_path)])
            else:
                subprocess.run(["xdg-open", str(dir_path)])
        except Exception as e:
            self.message_output.emit(f"Error opening directory: {e}")
    
    def _open_in_editor(self, file_path: Path):
        """Open file in external editor"""
        try:
            if platform.system() == "Darwin":
                subprocess.run(["open", "-e", str(file_path)])
            elif platform.system() == "Windows":
                subprocess.run(["notepad", str(file_path)])
            else:
                # Try common Linux editors
                for editor in ["gedit", "kate", "nano", "vim"]:
                    try:
                        subprocess.run([editor, str(file_path)])
                        return
                    except FileNotFoundError:
                        continue
                self.message_output.emit("No suitable editor found")
        except Exception as e:
            self.message_output.emit(f"Error opening editor: {e}")
    
    def _grep_scan_files(self, pattern: str):
        """Search pattern in scan files"""
        try:
            session_info = self.api.get_session_info()
            scan_files = self.api.list_scan_files()
            
            results = []
            for file_info in scan_files:
                file_path = file_info['path']
                try:
                    content = self.api.read_file(file_path)
                    lines = content.split('\n')
                    
                    for line_num, line in enumerate(lines, 1):
                        if re.search(pattern, line, re.IGNORECASE):
                            results.append(f"{file_info['name']}:{line_num}: {line.strip()}")
                            
                except Exception as e:
                    continue
            
            if results:
                # Limit results to prevent overwhelming output
                limited_results = results[:20]
                result_text = "\n".join(limited_results)
                if len(results) > 20:
                    result_text += f"\n... and {len(results) - 20} more matches"
                self.message_output.emit(f"Search results for '{pattern}':\n{result_text}")
            else:
                self.message_output.emit(f"No matches found for '{pattern}'")
                
        except Exception as e:
            self.message_output.emit(f"Error searching: {e}")

# Setup function for GUI integration
def setup_cli_verbs(gui_instance) -> CLIVerbsHandler:
    """Set up CLI verbs handler for GUI"""
    cli_handler = CLIVerbsHandler(gui_instance)
    
    # Connect signals
    cli_handler.message_output.connect(
        lambda msg: gui_instance.terminal.appendPlainText(msg)
    )
    
    print("[+] CLI verbs handler initialized")
    return cli_handler