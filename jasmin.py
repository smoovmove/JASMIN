#!/usr/bin/env python3
"""
JASMIN - Just A Smooth Machine Infiltrating Networks
Advanced Penetration Testing Framework
Main application file with integrated banner and loading system
"""

import argparse
import sys
import time
import os
import re 
import subprocess
import platform
import json
import shutil 
from pathlib import Path
from datetime import datetime
import importlib.util

from state import load_state, get_state_path, update_ip_variables
from cli import get_current_prompt

# Color codes
COLORS = {
    'cyan': '\033[96m',
    'green': '\033[92m',
    'yellow': '\033[93m',
    'blue': '\033[94m',
    'red': '\033[91m',
    'white': '\033[97m',
    'bold': '\033[1m',
    'purple': '\033[95m',
    'reset': '\033[0m'
}

# =============================================================================
# JASMIN SETUP CLASS 
# =============================================================================

class JasminSetupManager:
    """Integrated setup and dependency management for JASMIN"""
    
    def __init__(self):
        self.distro = self.detect_distro()
        self.missing_tools = []
        self.missing_python_modules = []
        
    def detect_distro(self):
        """Detect Linux distribution"""
        try:
            if Path('/etc/os-release').exists():
                with open('/etc/os-release') as f:
                    content = f.read().lower()
                    if 'ubuntu' in content or 'debian' in content:
                        return 'debian'
                    elif 'centos' in content or 'rhel' in content or 'fedora' in content:
                        return 'redhat'
                    elif 'arch' in content:
                        return 'arch'
        except:
            pass
        return 'unknown'
    
    def check_command(self, command):
        """Check if a command exists"""
        try:
            result = subprocess.run(['which', command], capture_output=True)
            return result.returncode == 0
        except:
            return False
    
    def check_python_module(self, module):
        """Check if Python module is available (clean, no warnings)"""
        # Map package names to their import names
        import_mapping = {
            'beautifulsoup4': 'bs4',
            'python-nmap': 'nmap', 
            'python-whois': 'whois',
            'pycryptodome': 'Crypto',
            'pillow': 'PIL',
            'pyyaml': 'yaml'
        }
        
        # Get the actual import name
        import_name = import_mapping.get(module, module)
        
        # Use importlib to check if module exists
        spec = importlib.util.find_spec(import_name)
        return spec is not None
    
    def quick_dependency_check(self):
        """Quick check of essential dependencies"""
        essential_tools = ['nmap', 'python3', 'curl']
        essential_modules = ['requests']
        
        missing_tools = [tool for tool in essential_tools if not self.check_command(tool)]
        missing_modules = [mod for mod in essential_modules if not self.check_python_module(mod)]
        
        return len(missing_tools) == 0 and len(missing_modules) == 0
    
    def show_missing_tools(self):
        """Show what tools are missing with install commands"""
        core_tools = ['nmap', 'curl', 'wget', 'nc', 'python3', 'pip3']
        enhanced_tools = ['feroxbuster', 'gobuster', 'whatweb', 'smbclient']
        python_modules = ['requests', 'beautifulsoup4', 'paramiko', 'colorama']
        
        missing_core = [t for t in core_tools if not self.check_command(t)]
        missing_enhanced = [t for t in enhanced_tools if not self.check_command(t)]
        missing_python = [m for m in python_modules if not self.check_python_module(m)]
        
        if missing_core or missing_enhanced or missing_python:
            print(f"\n{COLORS['yellow']}⚠️  Missing Dependencies:{COLORS['reset']}")
            
            if missing_core:
                print(f"\n{COLORS['red']}Critical (JASMIN won't work properly):{COLORS['reset']}")
                for tool in missing_core:
                    print(f"  ❌ {tool}")
            
            if missing_enhanced:
                print(f"\n{COLORS['yellow']}Optional (reduced functionality):{COLORS['reset']}")
                for tool in missing_enhanced:
                    print(f"  ⚠️  {tool}")
            
            if missing_python:
                print(f"\n{COLORS['yellow']}Python modules:{COLORS['reset']}")
                for module in missing_python:
                    print(f"  ❌ {module}")
            
            print(f"\n{COLORS['cyan']}Quick Fix:{COLORS['reset']}")
            if self.distro == 'debian':
                print("  sudo apt update && sudo apt install nmap curl wget python3-pip")
                print("  pip3 install requests beautifulsoup4 colorama")
            elif self.distro == 'redhat':
                print("  sudo dnf install nmap curl wget python3-pip")
                print("  pip3 install requests beautifulsoup4 colorama")
            elif self.distro == 'arch':
                print("  sudo pacman -S nmap curl wget python-pip")
                print("  pip3 install requests beautifulsoup4 colorama")
            
            print(f"\n{COLORS['green']}Automated Install:{COLORS['reset']}")
            print("  python3 jasmin.py setup install")
            
            return False
        
        return True
    
    def auto_install(self):
        """Automated installation"""
        print(f"\n{COLORS['cyan']}🚀 JASMIN Automated Setup{COLORS['reset']}")
        print("=" * 30)
        
        success = True
        
        # Install basic packages
        print(f"\n{COLORS['blue']}📦 Installing core tools...{COLORS['reset']}")
        if self.distro == 'debian':
            cmd = 'sudo apt update && sudo apt install -y nmap curl wget netcat-traditional python3-pip git'
        elif self.distro == 'redhat':
            cmd = 'sudo dnf install -y nmap curl wget nc python3-pip git'
        elif self.distro == 'arch':
            cmd = 'sudo pacman -S --noconfirm nmap curl wget openbsd-netcat python-pip git'
        else:
            print(f"{COLORS['red']}❌ Unknown distribution{COLORS['reset']}")
            success = False
            cmd = None
        
        if cmd and os.system(cmd) != 0:
            success = False
        
        # Install Python modules
        print(f"\n{COLORS['blue']}🐍 Installing Python modules...{COLORS['reset']}")
        python_cmd = f'{sys.executable} -m pip install --user requests beautifulsoup4 paramiko colorama tabulate rich'
        if os.system(python_cmd) != 0:
            success = False
        
        # Try to install enhanced tools
        print(f"\n{COLORS['blue']}🔧 Installing enhanced tools...{COLORS['reset']}")
        if self.distro == 'debian':
            os.system('sudo apt install -y gobuster whatweb feroxbuster 2>/dev/null')
        elif self.check_command('cargo'):
            os.system('cargo install feroxbuster 2>/dev/null')
        
        # Setup PATH
        self.setup_path()
        
        if success:
            print(f"\n{COLORS['green']}🎉 Setup completed! You can now use JASMIN.{COLORS['reset']}")
            print(f"{COLORS['yellow']}💡 Restart your terminal or run: source ~/.bashrc{COLORS['reset']}")
        else:
            print(f"\n{COLORS['yellow']}⚠️  Setup completed with some issues.{COLORS['reset']}")
            print(f"{COLORS['blue']}💡 JASMIN should still work for basic functionality.{COLORS['reset']}")
        
        return success
    
    def setup_path(self):
        """Add JASMIN to PATH"""
        script_path = None
        for name in ['jasmin.py', 'jarvis.py']:
            if Path(name).exists():
                script_path = Path(name).resolve()
                break
        
        if not script_path:
            return False
        
        os.chmod(script_path, 0o755)
        
        # User-local installation
        local_bin = Path.home() / '.local' / 'bin'
        local_bin.mkdir(parents=True, exist_ok=True)
        
        target = local_bin / 'jasmin'
        try:
            shutil.copy2(script_path, target)
            os.chmod(target, 0o755)
            
            # Add to bashrc
            bashrc = Path.home() / '.bashrc'
            if bashrc.exists():
                content = bashrc.read_text()
                if '.local/bin' not in content:
                    with open(bashrc, 'a') as f:
                        f.write('\n# JASMIN PATH\nexport PATH="$HOME/.local/bin:$PATH"\n')
            
            print(f"{COLORS['green']}✅ Added JASMIN to PATH{COLORS['reset']}")
            return True
        except Exception as e:
            print(f"{COLORS['yellow']}⚠️  PATH setup failed: {e}{COLORS['reset']}")
            return False

# ============================================================================
# JASMIN STARTUP BANNER AND LOADING SYSTEM
# ============================================================================

def show_loading_animation():
    """Display animated loading bar"""
    print(f"{COLORS['green']}[*] Initializing JASMIN systems...{COLORS['reset']}")
    
    # Loading bar animation
    bar_length = 40
    for i in range(bar_length + 1):
        percent = int((i / bar_length) * 100)
        filled = '█' * i
        empty = '░' * (bar_length - i)
        
        # Clear line and show progress
        sys.stdout.write(f'\r{COLORS["blue"]}[{filled}{empty}] {percent:3d}%{COLORS['reset']}')
        sys.stdout.flush()
        
        # Vary the speed for realistic feel
        if i < 10:
            time.sleep(0.1)  # Start fast
        elif i < 30:
            time.sleep(0.05)  # Speed up
        else:
            time.sleep(0.08)  # Slow down at end
    
    print(f"\n{COLORS['green']}[+] Framework ready!{COLORS['reset']}\n")

def show_jasmin_banner():
    """Display the main JASMIN banner"""
    banner = f"""{COLORS['cyan']}╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║       ██╗ █████╗ ███████╗███╗   ███╗██╗███╗   ██╗                          ║
║       ██║██╔══██╗██╔════╝████╗ ████║██║████╗  ██║                          ║
║       ██║███████║███████╗██╔████╔██║██║██╔██╗ ██║                          ║
║  ██   ██║██╔══██║╚════██║██║╚██╔╝██║██║██║╚██╗██║                          ║
║  ╚█████╔╝██║  ██║███████║██║ ╚═╝ ██║██║██║ ╚████║                          ║
║   ╚════╝ ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝                          ║
║                                                                              ║
║               Just A Smooth Machine Infiltrating Networks                   ║
║                          Pentester's Assistant v2.1                        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝{COLORS['reset']}

{COLORS['green']}Welcome to JASMIN!{COLORS['reset']} Type 'help' to see available commands."""

    print(banner)

def jasmin_startup():
    """Complete JASMIN startup sequence"""
    # Clear screen
    print("\033[2J\033[H", end="")
    
    # Show loading animation
    show_loading_animation()
    
    # Show banner
    show_jasmin_banner()

# ============================================================================
# MODULE AVAILABILITY CHECKS AND IMPORTS
# ============================================================================

# Check for enhanced features
try:
    import readline
    READLINE_AVAILABLE = True
except ImportError:
    READLINE_AVAILABLE = False

# Import session and target management
try:
    from session import (
        get_current_session_env, create_target_session, 
        resume_target_session, resume_host_session
    )
    from target import (
        list_targets, list_hosts, get_current_context, 
        set_current_context, target_exists, resolve_use_target
    )
    TARGET_MANAGEMENT_AVAILABLE = True
except ImportError:
    print("[!] Warning: Target management modules not available")
    TARGET_MANAGEMENT_AVAILABLE = False

# Import scanning modules
try:
    from scans import (
        run_full_scan, run_tcp_scan, check_udp_progress, 
        run_script_scan, web_enum, run_host_discovery_only, run_sweep_scan
    )
    SCANNING_AVAILABLE = True
except ImportError:
    print("[!] Warning: Scanning modules not available")
    SCANNING_AVAILABLE = False

# Import payload system
from payload import PayloadManager, create_payload_manager
PAYLOAD_AVAILABLE = True
_payload_manager = None

# Import intelligence system
try:
    from intelligence_integration import handle_intel_command
    INTEL_AVAILABLE = True
except ImportError:
    INTEL_AVAILABLE = False

# Import AD enumeration
try:
    from ad_enum import (
        ad_enum_full, ad_enum_users, ad_bloodhound, ad_kerberos, 
        ad_policy, ad_creds, ad_help
    )
    AD_AVAILABLE = True
except ImportError:
    AD_AVAILABLE = False

# Import notes system
try:
    from notes import notes_quick, notes_creds, notes_users, open_notes
    from notes import view_file as notes_view_file
    NOTES_AVAILABLE = True
except ImportError:
    NOTES_AVAILABLE = False

# Import upload server
try:
    from upload_server import handle_upload_command as upload_handler
    UPLOAD_AVAILABLE = True
except ImportError:
    UPLOAD_AVAILABLE = False



# ============================================================================
# Payload Mode Checker
# ============================================================================

def get_payload_manager(env):
    """Get or create payload manager for current session"""
    global _payload_manager
    if not PAYLOAD_AVAILABLE:
        return None
    
    if _payload_manager is None:
        try:
            _payload_manager = create_payload_manager()
        except Exception as e:
            print(f"[!] Failed to initialize payload manager: {e}")
            return None
    
    return _payload_manager

def is_in_payload_mode():
    """Check if currently in payload build/browse mode"""
    global _payload_manager
    if not PAYLOAD_AVAILABLE or _payload_manager is None:
        return False
    
    return _payload_manager.current_mode in ["build", "browse"]

# ============================================================================
# HELP SYSTEM
# ============================================================================

def show_help():
    """Show comprehensive help information"""
    print(f"""
{COLORS['cyan']}╔══════════════════════════════════════════════════════════════════════════════╗
║                            JASMIN Command Reference                          ║                     
╚══════════════════════════════════════════════════════════════════════════════╝{COLORS['reset']}

{COLORS['blue']}Dependency Management:{COLORS['reset']}
  setup                     System setup and dependency management

{COLORS['blue']}Target Management:{COLORS['reset']}
  target new <n> <ip>        Create new target session
  target set <n>                Switch to target session
  target list                   Show all target sessions
  target current                Show current target info
  target delete <n>             Delete target session

{COLORS['blue']}IP Address Management:{COLORS['reset']}
  ip                           Show current target IP and copy to clipboard
  ip set <new_ip>              Update primary target IP for current session
  ip save <n> <ip> [desc]      Save IP with variable name (optional description)
  ip get <n>                   Retrieve and copy saved IP by variable name
  ip list                      List all saved IP variables for current target
  ip export <format>           Export IPs (list/hosts/nmap formats)

{COLORS['blue']}Scanning & Enumeration:{COLORS['reset']}
  fs                            Full TCP scan with service detection
  tcp                           TCP port scan
  udp                           UDP port scan 
  discovery [ip/cidr]           Host discovery/ping sweep (saves results)
  sweep                         Scan all discovered hosts (runs discovery if needed)
  sweep --include <file>        Scan targets from custom file 
  web                           Web application enumeration
  script                        Run NSE scripts
  ss                           Short scan (top 1000 ports)

{COLORS['green']}Web Enumeration Options:{COLORS['reset']}
  web [port] [options]      Web enumeration (use 'web help' for details)
  web 8080                  Custom port (auto-detect HTTP/HTTPS)
  web --http                Force HTTP on default port 80
  web --https               Force HTTPS on default port 443
  web 8443 --https          Force HTTPS on port 8443
  web 443 --http            Force HTTP on port 443 (unusual)
  web --ferox               Use feroxbuster (faster, recursive)
  web --gobuster            Use gobuster (traditional)
  web --internal            Internal scan settings (lower threads)
  web --intel               Intelligence analysis integration

{COLORS['blue']}File Management:{COLORS['reset']}
  ls                           List files in current session directory (alias for 'scans list')

{COLORS['blue']}Scan Results:{COLORS['reset']}
  scans list                    List all scan files in session
  scans view <file|number>      View scan file contents
  scans search <term>           Search across all scan files

{COLORS['blue']}Active Directory:{COLORS['reset']}
  ad enum                       AD enumeration suite
  ad users                      Enumerate domain users
  ad computers                  Enumerate domain computers
  ad shares                     Enumerate SMB shares

{COLORS['blue']}Payload Generation:{COLORS['reset']}
  payload                       Enter payload generation mode
  payload search <term>         Search for payloads
  payload list                  Show available payloads
  payload help                  Payload module help

{COLORS['blue']}Intelligence & Analysis:{COLORS['reset']}
  intel dashboard               Show intelligence overview for current target
  intel suggest                 Get database-driven attack recommendations
  intel analyze                 Re-run intelligence analysis on scan results
  intel show port <n>           Deep analysis of specific port
  intel show service <name>     Analyze service attack techniques
  intel cve <name>              Lookup CVE details and exploits
  intel lookup <service>        Service-specific attack techniques
  intel show attack             Show available attack patterns
  intel stats                   Show system performance & database stats

{COLORS['blue']}Session Management:{COLORS['reset']}
  notes                         Session notes and documentation
  upload                        File upload server management
  view <file>                   View files in session directory
  
{COLORS['blue']}General:{COLORS['reset']}
  help                          Show this help message
  exit                          Exit JASMIN
  clear                         Clear screen

{COLORS['yellow']}Examples:{COLORS['reset']}
  jasmin> target new box1 192.168.1.100
  jasmin> fs
  jasmin> web
  jasmin> payload search windows reverse
  jasmin> intel dashboard
  jasmin> intel show port 445

{COLORS['blue']}Command Line Options:{COLORS['reset']}
  python jasmin.py               Start with full banner
  python jasmin.py -q            Start in quiet mode (no banner)
  python jasmin.py --quiet       Same as -q
""")
    
def show_web_help():
    """Display detailed web enumeration help"""
    help_text = f"""
{COLORS['blue']}JASMIN Web Enumeration{COLORS['reset']} - Comprehensive Directory & Technology Discovery

{COLORS['green']}Basic Usage:{COLORS['reset']}
  web                       Auto-detect protocol, use best available tool
  web <port>                Scan custom port with auto-detection
  web help                  Show this help message

{COLORS['green']}Protocol Selection:{COLORS['reset']}
  web --http                Force HTTP on port 80
  web --https               Force HTTPS on port 443  
  web --ssl                 Alias for --https
  web <port> --http         Force HTTP on custom port
  web <port> --https        Force HTTPS on custom port

{COLORS['green']}Tool Selection:{COLORS['reset']}
  web --ferox               Use feroxbuster (faster, recursive)
  web --feroxbuster         Alias for --ferox
  web --gobuster            Use gobuster (traditional)
  web --gobust              Alias for --gobuster
  web                       Auto-select best available tool

{COLORS['green']}Scan Modes:{COLORS['reset']}
  web --internal            Internal scan (lower threads, longer timeout)
  web --intel               Enable intelligence analysis integration

{COLORS['green']}Common Examples:{COLORS['reset']}
  web                       HTTP/HTTPS on default ports, best tool
  web 8080                  HTTP on port 8080 (auto-detected)
  web 8443                  HTTPS on port 8443 (auto-detected)
  web --https --ferox       HTTPS on 443 with feroxbuster
  web 9000 --http           Force HTTP on port 9000
  web 10443 --ssl           HTTPS on port 10443
  web --gobuster --internal Gobuster with internal settings

{COLORS['green']}Advanced Examples:{COLORS['reset']}
  web 8080 --https --ferox --internal    # HTTPS + feroxbuster + internal
  web 9443 --ssl --gobuster --intel      # HTTPS + gobuster + intelligence
  web 443 --http                         # Force HTTP on HTTPS port
  web --https --internal --intel          # All HTTPS options

{COLORS['green']}Protocol Auto-Detection:{COLORS['reset']}
  {COLORS['cyan']}HTTPS Ports (auto):{COLORS['reset']} 443, 8443, 9443, 10443
  {COLORS['cyan']}HTTP Ports (auto):{COLORS['reset']}  80, 8080, 3000, 5000, 8000, others
  {COLORS['cyan']}Override:{COLORS['reset']}           Use --http or --https to force protocol

{COLORS['green']}Tool Comparison:{COLORS['reset']}
  {COLORS['cyan']}Feroxbuster:{COLORS['reset']}
    ✓ 3-5x faster than gobuster
    ✓ Recursive directory discovery
    ✓ Smart filtering (404s, empty responses)
    ✓ Real-time progress with ETA
    ✓ Better wordlist selection
    ✓ Content analysis and backup detection

  {COLORS['cyan']}Gobuster:{COLORS['reset']}
    ✓ Traditional, reliable scanning
    ✓ Lower resource usage
    ✓ Simple, predictable output
    ✓ Wide compatibility
    ✓ Stable performance

{COLORS['green']}Output Files:{COLORS['reset']}
  target_feroxbuster_https_port8443.txt  # Feroxbuster HTTPS custom port
  target_gobuster_http_port8080.txt      # Gobuster HTTP custom port
  target_feroxbuster_https.txt           # Feroxbuster HTTPS default
  target_whatweb_https_port9443.txt      # Technology detection

{COLORS['green']}Scan Settings:{COLORS['reset']}
  {COLORS['cyan']}External Mode (default):{COLORS['reset']}
    - Feroxbuster: 30 threads, 3s timeout, depth 3
    - Gobuster: 20 threads, 3s timeout
    - Higher performance, shorter timeouts

  {COLORS['cyan']}Internal Mode (--internal):{COLORS['reset']}
    - Feroxbuster: 10 threads, 5s timeout, depth 2  
    - Gobuster: 10 threads, 5s timeout
    - Lower performance, longer timeouts, tunnel-friendly

{COLORS['green']}SSL/HTTPS Features:{COLORS['reset']}
  ✓ Automatic certificate bypass (-k flag)
  ✓ Self-signed certificate support
  ✓ SSL connection error handling
  ✓ HTTPS-specific optimizations

{COLORS['green']}Flag Combinations:{COLORS['reset']}
  All flags can be combined in any order:
  web 9000 --https --ferox --internal --intel
  web --ssl --gobuster --intel
  web 8080 --http --internal

{COLORS['green']}Installation Check:{COLORS['reset']}
  Run 'tools' command to check tool availability:
  ✓ Feroxbuster: cargo install feroxbuster
  ✓ Gobuster: apt install gobuster

{COLORS['yellow']}Pro Tips:{COLORS['reset']}
  • Use feroxbuster for faster, more comprehensive scans
  • Use --internal for pivoted/tunneled targets  
  • HTTPS ports are auto-detected for common configurations
  • Combine --intel with scans for automatic analysis
  • Output files include protocol and port for easy identification

{COLORS['yellow']}Quick Reference:{COLORS['reset']}
  web help          # This help
  web               # Smart defaults
  web 8443          # Auto HTTPS
  web --https       # Force HTTPS  
  web --ferox       # Force feroxbuster
  web --internal    # Internal mode
"""
    print(help_text)

# ============================================================================
# SESSION AND TARGET MANAGEMENT
# ============================================================================

def handle_target_command(tokens, env):
    """Handle target management commands"""
    if not TARGET_MANAGEMENT_AVAILABLE:
        print("[!] Target management system not available")
        return env
        
    if len(tokens) < 2:
        print("[!] Usage: target <command>")
        print("Available commands: new, set, list, current, delete")
        return env
    
    cmd = tokens[1].lower()
    
    if cmd == "new":
        if len(tokens) < 4:
            print("[!] Usage: target new <name> <ip>")
            return env
        name = tokens[2]
        ip = tokens[3]
        try:
            env = create_target_session(name, ip)
            print(f"[+] Created and switched to target: {name} ({ip})")
        except Exception as e:
            print(f"[!] Error creating target: {e}")
        return env
        
    elif cmd == "list":
        print("[*] Available target sessions:")
        try:
            targets = list_targets()
            if targets:
                for i, target in enumerate(targets, 1):
                    print(f"  [{i}] {target}")
            else:
                print("  No targets found in ~/Boxes directory")
        except Exception as e:
            print(f"[!] Error listing targets: {e}")
            
    elif cmd == "current":
        try:
            target, host = get_current_context()
            if target:
                if host:
                    print(f"[*] Current context: {target}:{host}")
                else:
                    print(f"[*] Current target: {target}")
            else:
                print("[*] No active target session")
        except Exception as e:
            print(f"[!] Error getting current context: {e}")
            
    elif cmd == "set":
        if len(tokens) < 3:
            print("[!] Usage: target set <name_or_number>")
            return env
        
        identifier = tokens[2]
        try:
            # If it's a number, get the target by index
            if identifier.isdigit():
                targets = list_targets()
                index = int(identifier) - 1
                if 0 <= index < len(targets):
                    target_name = targets[index]
                else:
                    print(f"[!] Invalid target number. Use 1-{len(targets)}")
                    return env
            else:
                target_name = identifier
            
            # Resume the target session
            env = resume_target_session(target_name)
            print(f"[+] Switched to target: {target_name}")
            
        except Exception as e:
            print(f"[!] Error switching to target: {e}")
            
    elif cmd == "delete":
        if len(tokens) < 3:
            print("[!] Usage: target delete <name_or_number>")
            return env
        
        identifier = tokens[2]
        try:
            if identifier.isdigit():
                targets = list_targets()
                index = int(identifier) - 1
                if 0 <= index < len(targets):
                    target_name = targets[index]
                else:
                    print(f"[!] Invalid target number. Use 1-{len(targets)}")
                    return env
            else:
                target_name = identifier
                
            # Delete target directory
            target_dir = Path.home() / "Boxes" / target_name
            if target_dir.exists():
                import shutil
                shutil.rmtree(target_dir)
                print(f"[+] Deleted target: {target_name}")
                
                # Clear current context if we deleted the active target
                current_target, _ = get_current_context()
                if current_target == target_name:
                    set_current_context(None)
                    env = None
            else:
                print(f"[!] Target {target_name} not found")
                
        except Exception as e:
            print(f"[!] Error deleting target: {e}")
        
    else:
        print(f"[!] Unknown target command: {cmd}")
    
    return env


# ============================================================================
# SCAN RESULT VIEWING FUNCTIONS
# ============================================================================

def _get_scan_files(env):
    """Get scan files list without printing (helper function)"""
    if not env or 'OUTDIR' not in env:
        return []
    
    # Look in scans subdirectory
    scans_dir = Path(env['OUTDIR']) / "scans"
    if not scans_dir.exists():
        return []
    
    # Get all files in scans directory since it only contains scan output
    scan_files = [f for f in scans_dir.iterdir() if f.is_file()]
    
    return sorted(scan_files)

def list_scan_files(env):
    """List all scan files in the current target scans directory"""
    if not env or 'OUTDIR' not in env:
        print("[!] No active session")
        return []
    
    scan_files = _get_scan_files(env)
    boxname = env.get('BOXNAME', '')
    
    if scan_files:
        print(f"[*] Available scan files for {boxname}:")
        for i, scan_file in enumerate(scan_files, 1):
            file_size = scan_file.stat().st_size
            size_kb = file_size / 1024
            print(f"  [{i:2d}] {scan_file.name:<25} ({size_kb:.1f} KB)")
    else:
        print(f"[*] No scan files found in {boxname}/scans/")
        print(f"[*] Run some scans first: fs, tcp, web")
    
    return scan_files

def view_scan_file(env, filename_or_number):
    """View a scan file by name or number from list"""
    if not env or 'OUTDIR' not in env:
        print("[!] No active session")
        return
    
    outdir = Path(env['OUTDIR'])
    scans_dir = outdir / "scans"  # Add this line
    
    # If it's a number, get from file list (silently)
    if filename_or_number.isdigit():
        scan_files = _get_scan_files(env)
        if not scan_files:
            print("[!] No scan files found. Run some scans first: fs, tcp, web")
            return
        
        file_num = int(filename_or_number) - 1
        if 0 <= file_num < len(scan_files):
            target_file = scan_files[file_num]
        else:
            print(f"[!] Invalid file number. Use 'scans list' to see available files.")
            return
    else:
        # Direct filename - try exact match first
        target_file = scans_dir / filename_or_number
        if not target_file.exists():
            # Try partial matching
            boxname = env.get('BOXNAME', '')
            possible_files = []
            
            # Check common patterns
            patterns_to_try = [
                f"{boxname}_{filename_or_number}*.nmap",
                f"{boxname}_{filename_or_number}*.txt", 
                f"{boxname}*{filename_or_number}*.txt",
                f"{boxname}*{filename_or_number}*.nmap"
            ]
            
            for pattern in patterns_to_try:
                matches = list(scans_dir.glob(pattern))
                possible_files.extend(matches)
            
            if possible_files:
                target_file = possible_files[0]  # Take first match
                print(f"[*] Found: {target_file.name}")
            else:
                print(f"[!] File not found: {filename_or_number}")
                print(f"[*] Use 'scans list' to see available files")
                return
    
    if not target_file.exists():
        print(f"[!] File not found: {target_file.name}")
        return
    
    print(f"[*] Viewing: {target_file.name}")
    print("=" * 70)
    
    try:
        with open(target_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        # Apply syntax highlighting based on file type
        if target_file.suffix == '.xml':
            _display_xml_content(content)
                
        elif 'nmap' in target_file.name or target_file.suffix == '.nmap':
            _display_nmap_content(content)
                    
        elif 'gobuster' in target_file.name or 'feroxbuster' in target_file.name:
            _display_directory_enum_content(content)
                    
        elif 'nikto' in target_file.name:
            _display_nikto_content(content)
            
        else:
            # Plain text output with basic highlighting
            _display_plain_content(content)
            
    except Exception as e:
        print(f"[!] Error reading file: {e}")

def _display_xml_content(content):
    """Display XML content with basic formatting"""
    print("[XML Format - Nmap XML Output]")
    lines = content.split('\n')
    for line in lines[:50]:  # Show first 50 lines
        if '<host' in line or '<port' in line or '<service' in line:
            print(f"→ {line.strip()}")
        elif line.strip():
            print(f"  {line.strip()}")
    if len(lines) > 50:
        print(f"\n... ({len(lines)-50} more lines)")
        print(f"[*] Use 'scans search <term>' to find specific content")

def _display_nmap_content(content):
    """Display nmap content with highlighting"""
    print("[Nmap Scan Results]")
    lines = content.split('\n')
    for line in lines:
        line_lower = line.lower()
        if 'open' in line_lower and ('tcp' in line or 'udp' in line):
            print(f"🟢 {line}")
        elif 'closed' in line_lower:
            print(f"🔴 {line}")
        elif 'filtered' in line_lower:
            print(f"🟡 {line}")
        elif line.strip().startswith('PORT'):
            print(f"📋 {line}")
        elif 'Nmap scan report' in line:
            print(f"🎯 {line}")
        elif 'Service Info:' in line:
            print(f"🔍 {line}")
        else:
            print(line)

def _display_directory_enum_content(content):
    """Display directory enumeration results with highlighting"""
    print("[Directory Enumeration Results]")
    lines = content.split('\n')
    for line in lines:
        if '200' in line:
            print(f"✅ {line}")
        elif '301' in line or '302' in line:
            print(f"↗️  {line}")
        elif '403' in line:
            print(f"🚫 {line}")
        elif '401' in line:
            print(f"🔐 {line}")
        elif '500' in line:
            print(f"💥 {line}")
        elif '404' in line:
            continue  # Skip 404s unless they're interesting
        elif line.strip() and not line.startswith('='):
            print(line)

def _display_nikto_content(content):
    """Display nikto results with highlighting"""
    print("[Nikto Vulnerability Scan Results]")
    lines = content.split('\n')
    for line in lines:
        if '+ OSVDB-' in line or 'CVE-' in line:
            print(f"🚨 {line}")
        elif '+ ' in line and ('Server:' in line or 'X-' in line):
            print(f"🔍 {line}")
        elif '+ ' in line:
            print(f"⚠️  {line}")
        elif line.strip() and not line.startswith('-'):
            print(line)

def _display_plain_content(content):
    """Display plain content with basic highlighting"""
    lines = content.split('\n')
    
    # If content is very long, show first part and offer search
    if len(lines) > 100:
        print(f"[Large file - {len(lines)} lines]")
        for line in lines[:50]:
            print(line)
        print(f"\n... ({len(lines)-50} more lines)")
        print(f"[*] Use 'scans search <term>' to find specific content")
    else:
        print(content)

def search_scan_results(env, search_term):
    """Search for a term across all scan files"""
    if not env or 'OUTDIR' not in env:
        print("[!] No active session")
        return
    
    if not search_term:
        print("[!] Usage: scans search <term>")
        return
    
    # Get all scan files using helper function
    scan_files = _get_scan_files(env)
    
    if not scan_files:
        print(f"[*] No scan files found to search")
        print(f"[*] Run some scans first: fs, tcp, web")
        return
    
    print(f"[*] Searching for '{search_term}' in scan results...")
    print("=" * 60)
    
    results_found = False
    for scan_file in scan_files:
        try:
            with open(scan_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            matches = []
            for i, line in enumerate(lines, 1):
                if search_term.lower() in line.lower():
                    matches.append((i, line.strip()))
            
            if matches:
                results_found = True
                print(f"\n📄 {scan_file.name}:")
                for line_num, line in matches[:10]:  # Show max 10 matches per file
                    # Highlight the search term
                    highlighted_line = re.sub(
                        re.escape(search_term), 
                        f"**{search_term}**", 
                        line, 
                        flags=re.IGNORECASE
                    )
                    print(f"   {line_num:4d}: {highlighted_line}")
                
                if len(matches) > 10:
                    print(f"        ... and {len(matches)-10} more matches")
                    
        except Exception as e:
            print(f"[!] Error searching {scan_file.name}: {e}")
    
    if not results_found:
        print(f"[*] No results found for '{search_term}'")
        print(f"[*] Try different terms like: ssh, http, ssl, port, open")

# ============================================================================
# MAIN SCANS COMMAND HANDLER
# ============================================================================

def handle_scans_command(tokens, env):
    """Handle scans command for viewing scan results"""
    if len(tokens) < 2:
        print("[*] Scans Commands:")
        print("    scans list                    - List all scan files")
        print("    scans view <file|number>      - View scan file")
        print("    scans search <term>           - Search across scan files")
        print()
        print("Examples:")
        print("    scans list")
        print("    scans view 1")
        print("    scans view tcp.nmap")
        print("    scans search ssh")
        return env
    
    subcommand = tokens[1].lower()
    
    if subcommand == "list":
        list_scan_files(env)
        
    elif subcommand == "view":
        if len(tokens) >= 3:
            filename_or_number = tokens[2]
            view_scan_file(env, filename_or_number)
        else:
            print("[!] Usage: scans view <file|number>")
            print("    Use 'scans list' to see available files")
        
    elif subcommand == "search":
        if len(tokens) >= 3:
            search_term = " ".join(tokens[2:])
            search_scan_results(env, search_term)
        else:
            print("[!] Usage: scans search <term>")
            print("    Example: scans search 'port 443'")
        
    else:
        print(f"[!] Unknown scans command: {subcommand}")
        print("[*] Available: list, view, search")
    
    return env

def parse_scan_flags(tokens):
    """Parse scanning flags and parameters"""
    flags = {
        'internal': False,
        'internal_ip': None,
        'intel': False,
        'wordlist_size': 'short'  # ADD THIS - default to short/common.txt
    }
    
    i = 1  # Start after the scan command
    while i < len(tokens):
        token = tokens[i]
        
        if token == "--internal":
            # Check if next token is an IP address
            if i + 1 < len(tokens) and is_valid_ip(tokens[i + 1]):
                flags['internal'] = True
                flags['internal_ip'] = tokens[i + 1]
                i += 2  # Skip both --internal and the IP
            else:
                # Just --internal flag without IP (scan current target internally)
                flags['internal'] = True
                i += 1
                
        elif token == "--intel":
            flags['intel'] = True
            i += 1
        # ADD THESE NEW FLAGS:
        elif token == "--short":
            flags['wordlist_size'] = 'short'
            i += 1
        elif token == "--medium":
            flags['wordlist_size'] = 'medium'
            i += 1
        elif token == "--large":
            flags['wordlist_size'] = 'large'
            i += 1
        else:
            i += 1
    
    return flags

# ============================================================================
# WEB TOOL CHECKER
# ============================================================================

def check_web_tools_status():
    """Check and display web enumeration tool status"""
    print(f"{COLORS['blue']}[*] Web Enumeration Tool Status:{COLORS['reset']}")
    
    # Check feroxbuster
    try:
        result = subprocess.run(["feroxbuster", "--version"], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            version = result.stdout.strip().split('\n')[0]
            print(f"  {COLORS['green']}✓{COLORS['reset']} Feroxbuster: {version}")
        else:
            print(f"  {COLORS['red']}✗{COLORS['reset']} Feroxbuster: Error getting version")
    except FileNotFoundError:
        print(f"  {COLORS['red']}✗{COLORS['reset']} Feroxbuster: Not installed")
        print(f"    {COLORS['yellow']}Install:{COLORS['reset']} cargo install feroxbuster")
    except Exception as e:
        print(f"  {COLORS['red']}✗{COLORS['reset']} Feroxbuster: {e}")
    
    # Check gobuster
    try:
        result = subprocess.run(["gobuster", "version"], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            version = result.stdout.strip()
            print(f"  {COLORS['green']}✓{COLORS['reset']} Gobuster: {version}")
        else:
            print(f"  {COLORS['red']}✗{COLORS['reset']} Gobuster: Error getting version")
    except FileNotFoundError:
        print(f"  {COLORS['red']}✗{COLORS['reset']} Gobuster: Not installed")
        print(f"    {COLORS['yellow']}Install:{COLORS['reset']} apt install gobuster")
    except Exception as e:
        print(f"  {COLORS['red']}✗{COLORS['reset']} Gobuster: {e}")
    
    # Check common wordlists
    print(f"\n{COLORS['blue']}[*] Wordlist Status:{COLORS['reset']}")
    
    wordlists = [
        ("/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt", "SecLists (preferred)"),
        ("/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt", "DirBuster"),
        ("/usr/share/wordlists/dirb/common.txt", "Dirb (fallback)")
    ]
    
    for wl_path, wl_name in wordlists:
        if Path(wl_path).exists():
            size = Path(wl_path).stat().st_size / 1024 / 1024  # MB
            print(f"  {COLORS['green']}✓{COLORS['reset']} {wl_name}: {size:.1f}MB")
        else:
            print(f"  {COLORS['red']}✗{COLORS['reset']} {wl_name}: Not found")
    
    print(f"\n{COLORS['yellow']}Note:{COLORS['reset']} JASMIN will auto-select the best available wordlist")

# ============================================================================
# CLIPBOARD FUNCTIONALITY
# ============================================================================

def copy_to_clipboard(text):
    """Copy text to system clipboard"""
    try:
        system = platform.system().lower()
        if system == "linux":
            # Try xclip first, then xsel
            try:
                subprocess.run(['xclip', '-selection', 'clipboard'], 
                             input=text.encode(), check=True)
                return True
            except (subprocess.CalledProcessError, FileNotFoundError):
                try:
                    subprocess.run(['xsel', '--clipboard', '--input'], 
                                 input=text.encode(), check=True)
                    return True
                except (subprocess.CalledProcessError, FileNotFoundError):
                    return False
        elif system == "darwin":  # macOS
            subprocess.run(['pbcopy'], input=text.encode(), check=True)
            return True
        elif system == "windows":
            subprocess.run(['clip'], input=text.encode(), check=True)
            return True
    except Exception:
        return False
    return False

# ============================================================================
# STATE-INTEGRATED IP VARIABLE MANAGEMENT
# ============================================================================

def load_ip_variables(env):
    """Load IP variables from state.json"""
    if not env or 'OUTDIR' not in env:
        return {}
    
    try:
        outdir = Path(env['OUTDIR'])
        session_dir = outdir / "session"  # Add this line
        state = load_state(session_dir)   # Changed from outdir
        return state.get('ip_variables', {})
    except Exception as e:
        print(f"[!] Error loading IP variables: {e}")
        return {}

def save_ip_variables(env, ip_variables):
    """Save IP variables to state.json"""
    if not env or 'OUTDIR' not in env:
        return False
    
    try:
        outdir = Path(env['OUTDIR'])
        session_dir = outdir / "session"  # Add this line
        
        # Load current state
        state_path = get_state_path(session_dir)  # Changed from outdir
        if state_path.exists():
            with open(state_path, 'r') as f:
                state = json.load(f)
        else:
            # This shouldn't happen, but just in case
            state = {
                "hostname": "", "os": "", "ports": [], "services": [],
                "web_tech": "", "modules_used": [], "credentials": [],
                "notes": [], "last_updated": datetime.now().isoformat()
            }
        
        # Update IP variables and timestamp
        state['ip_variables'] = ip_variables
        state['last_updated'] = datetime.now().isoformat()
        
        # Save back to file
        with open(state_path, 'w') as f:
            json.dump(state, f, indent=2)
        
        return True
    except Exception as e:
        print(f"[!] Error saving IP variables: {e}")
        return False

def save_ip_variable(env, name, ip_address, description=None):
    """Save an IP address as a named variable in session state"""
    if not env:
        print("[!] No active target session")
        return False
    
    # Validate IP format
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    if not re.match(ip_pattern, ip_address):
        print(f"[!] Invalid IP address format: {ip_address}")
        return False
    
    # Load existing variables
    ip_variables = load_ip_variables(env)
    
    # Save variable with metadata
    ip_variables[name] = {
        'ip': ip_address,
        'description': description or f"IP variable for {name}",
        'saved_at': datetime.now().isoformat(),
        'target': env.get('BOXNAME', 'unknown')
    }
    
    # Save to state
    if save_ip_variables(env, ip_variables):
        boxname = env.get('BOXNAME', 'target')
        print(f"[+] Saved IP variable for {boxname}: {name} = {ip_address}")
        if description:
            print(f"    Description: {description}")
        return True
    
    return False

def get_ip_variable(env, name, copy_clipboard=True):
    """Get an IP address by variable name and optionally copy to clipboard"""
    if not env:
        print("[!] No active target session")
        return None
    
    ip_variables = load_ip_variables(env)
    
    if name not in ip_variables:
        print(f"[!] IP variable '{name}' not found for this target")
        # Show available variables
        if ip_variables:
            print(f"[*] Available variables: {', '.join(ip_variables.keys())}")
        return None
    
    var_data = ip_variables[name]
    ip_address = var_data['ip']
    description = var_data.get('description', '')
    
    print(f"[*] {name} = {ip_address}")
    if description:
        print(f"    {description}")
    
    # Copy to clipboard
    if copy_clipboard:
        if copy_to_clipboard(ip_address):
            print(f"[+] Copied {ip_address} to clipboard! 📋")
        else:
            print(f"[!] Could not copy to clipboard (install xclip/xsel on Linux)")
    
    return ip_address

def list_ip_variables(env):
    """List all saved IP variables for current target"""
    if not env:
        print("[!] No active target session")
        return
    
    ip_variables = load_ip_variables(env)
    boxname = env.get('BOXNAME', 'target')
    
    if not ip_variables:
        print(f"[*] No IP variables saved for {boxname}")
        print(f"[*] Use 'ip save <n> <ip> [description]' to save IPs")
        return
    
    print(f"[*] IP Variables for {boxname}:")
    print("─" * 50)
    
    # Common variables first, then alphabetical
    common_vars = ['dc', 'web', 'db', 'mail', 'dns', 'ftp', 'ssh']
    sorted_vars = []
    
    # Add common variables that exist
    for var in common_vars:
        if var in ip_variables:
            sorted_vars.append(var)
    
    # Add remaining variables alphabetically
    remaining = sorted([k for k in ip_variables.keys() if k not in common_vars])
    sorted_vars.extend(remaining)
    
    for name in sorted_vars:
        var_data = ip_variables[name]
        ip = var_data['ip']
        desc = var_data.get('description', '')
        
        print(f"  📍 {name:<12} = {ip:<15} {desc}")

def delete_ip_variable(env, name):
    """Delete an IP variable for current target"""
    if not env:
        print("[!] No active target session")
        return False
    
    ip_variables = load_ip_variables(env)
    
    if name not in ip_variables:
        print(f"[!] IP variable '{name}' not found")
        return False
    
    deleted_var = ip_variables.pop(name)
    deleted_ip = deleted_var['ip']
    
    if save_ip_variables(env, ip_variables):
        boxname = env.get('BOXNAME', 'target')
        print(f"[+] Deleted IP variable for {boxname}: {name} = {deleted_ip}")
        return True
    
    return False

def show_current_ip(env, copy_clipboard=True):
    """Display current target IP for easy copy/paste"""
    if not env or 'IP' not in env:
        print("[!] No active target session")
        return None
    
    ip = env['IP']
    boxname = env.get('BOXNAME', 'unknown')
    
    print(f"[*] Current Target: {boxname}")
    print(f"[*] Primary IP: {ip}")
    
    if copy_clipboard:
        if copy_to_clipboard(ip):
            print(f"[+] Copied {ip} to clipboard! 📋")
        else:
            print(f"[!] Could not copy to clipboard")
    
    # Also show saved variables for this target
    ip_variables = load_ip_variables(env)
    if ip_variables:
        print(f"[*] Saved variables: {', '.join(ip_variables.keys())}")
    
    return ip

def suggest_common_variables(env):
    """Suggest common IP variable names for the current target"""
    if not env:
        print("[!] No active target session")
        return
    
    boxname = env.get('BOXNAME', 'target')
    primary_ip = env.get('IP', 'unknown')
    
    print(f"[*] Common IP variable suggestions for {boxname}:")
    print("─" * 45)
    print("  dc      - Domain Controller")
    print("  web     - Web Server") 
    print("  db      - Database Server")
    print("  mail    - Mail Server")
    print("  dns     - DNS Server")
    print("  ftp     - FTP Server")
    print("  ssh     - SSH Server/Jump Box")
    print("  backup  - Backup Server")
    print("  admin   - Admin Interface")
    print("  api     - API Endpoint")
    print()
    print(f"Example: ip save dc 10.10.10.5 \"Active Directory Domain Controller\"")
    print(f"Example: ip save web {primary_ip} \"Primary web application\"")

def import_ips_from_scan(env):
    """Import IPs from scan results and suggest variables"""
    if not env:
        print("[!] No active target session")
        return
    
    outdir = Path(env['OUTDIR'])
    scans_dir = outdir / "scans"     # Add this line
    boxname = env.get('BOXNAME', '')
    
    # Look for IPs in scan files
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    found_ips = set()
    
    # Search in common scan files
    scan_files = list(scans_dir.glob(f"{boxname}_*.nmap")) + list(scans_dir.glob(f"{boxname}_*.txt"))
    
    for scan_file in scan_files:
        try:
            with open(scan_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                ips = re.findall(ip_pattern, content)
                found_ips.update(ips)
        except Exception:
            continue
    
    # Remove current target IP and common non-host IPs
    current_ip = env.get('IP', '')
    found_ips.discard(current_ip)
    found_ips.discard('127.0.0.1')
    found_ips.discard('0.0.0.0')
    
    if found_ips:
        print(f"[*] Found additional IPs in scan results:")
        for i, ip in enumerate(sorted(found_ips), 1):
            print(f"  [{i}] {ip}")
        print()
        print("[*] Save interesting IPs with: ip save <n> <ip> [description]")
    else:
        print(f"[*] No additional IPs found in scan results")

def export_ip_variables(env, format_type="list"):
    """Export IP variables in different formats for external tools"""
    if not env:
        print("[!] No active target session")
        return
    
    ip_variables = load_ip_variables(env)
    
    if not ip_variables:
        print("[!] No IP variables to export")
        return
    
    boxname = env.get('BOXNAME', 'target')
    
    if format_type == "list":
        # Simple IP list
        ips = [var['ip'] for var in ip_variables.values()]
        ip_list = '\n'.join(ips)
        print(f"[*] IP List for {boxname}:")
        print(ip_list)
        
        if copy_to_clipboard(ip_list):
            print(f"[+] IP list copied to clipboard! 📋")
    
    elif format_type == "hosts":
        # /etc/hosts format
        hosts_entries = []
        for name, var in ip_variables.items():
            hosts_entries.append(f"{var['ip']}\t{name}.{boxname}")
        
        hosts_format = '\n'.join(hosts_entries)
        print(f"[*] /etc/hosts format for {boxname}:")
        print(hosts_format)
        
        if copy_to_clipboard(hosts_format):
            print(f"[+] Hosts entries copied to clipboard! 📋")
    
    elif format_type == "nmap":
        # Nmap target list
        ips = [var['ip'] for var in ip_variables.values()]
        nmap_targets = ' '.join(ips)
        print(f"[*] Nmap targets for {boxname}:")
        print(nmap_targets)
        
        if copy_to_clipboard(nmap_targets):
            print(f"[+] Nmap targets copied to clipboard! 📋")

def update_session_ip(env, new_ip):
    """Update the primary IP for the current target session"""
    if not env:
        print("[!] No active target session")
        return False
    
    # Validate IP format (using same validation as existing functions)
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    if not re.match(ip_pattern, new_ip):
        print(f"[!] Invalid IP address format: {new_ip}")
        return False
    
    old_ip = env.get('IP', 'unknown')
    boxname = env.get('BOXNAME', 'target')
    outdir = env.get('OUTDIR', '')
    
    if old_ip == new_ip:
        print(f"[*] IP is already set to {new_ip}")
        return True
    
    try:
        # Update session.env file
        if outdir:
            session_dir = Path(outdir) / "session"       # Add this line
            session_file = session_dir / "session.env"   # Changed from outdir
            if session_file.exists():
                # Read current session file
                with open(session_file, 'r') as f:
                    lines = f.readlines()
                
                # Update IP line
                updated_lines = []
                for line in lines:
                    if line.startswith('IP='):
                        updated_lines.append(f"IP={new_ip}\n")
                    else:
                        updated_lines.append(line)
                
                # Write back to file
                with open(session_file, 'w') as f:
                    f.writelines(updated_lines)
        
        # Update current environment
        env['IP'] = new_ip
        
        # Update notes file with new IP
        try:
            from notes import update_field_in_section
            session_dir = Path(outdir) / "session"                    # Add this line
            notes_file = session_dir / f"{boxname}_notes.txt"         # Changed from outdir
            if notes_file.exists():
                update_field_in_section(notes_file, "System Info", "IP", new_ip)
        except ImportError:
            pass  # Notes module might not be available
        
        print(f"[+] Updated target IP for {boxname}: {old_ip} → {new_ip}")
        print(f"[*] Session files updated")
        
        # Copy new IP to clipboard
        if copy_to_clipboard(new_ip):
            print(f"[+] Copied {new_ip} to clipboard! 📋")
        
        return True
        
    except Exception as e:
        print(f"[!] Error updating session IP: {e}")
        return False

# ============================================================================
# IP COMMAND HANDLER
# ============================================================================

def handle_session_integrated_ip_command(tokens, env):
    """Handle IP variable management commands integrated with session state"""
    if len(tokens) < 2:
        # Just 'ip' - show current IP and copy to clipboard
        show_current_ip(env)
        return env
    
    subcommand = tokens[1].lower()
    
    if subcommand == "save":
        if len(tokens) >= 4:
            # ip save <n> <ip> [description]
            name = tokens[2]
            ip_address = tokens[3]
            description = " ".join(tokens[4:]) if len(tokens) > 4 else None
            save_ip_variable(env, name, ip_address, description)
        else:
            print("[!] Usage: ip save <n> <ip> [description]")
            print("    Example: ip save dc 10.10.10.5 \"Domain Controller\"")

    
    elif subcommand == "set":
        if len(tokens) >= 3:
            # ip set <new_ip>
            new_ip = tokens[2]
            update_session_ip(env, new_ip)
        else:
            print("[!] Usage: ip set <new_ip>")
            print("    Example: ip set 10.10.10.25")
            print("    Updates the primary target IP for this session")
    
    elif subcommand == "get":
        if len(tokens) >= 3:
            # ip get <n>
            name = tokens[2]
            get_ip_variable(env, name)
        else:
            print("[!] Usage: ip get <n>")
    
    elif subcommand == "list":
        # ip list
        list_ip_variables(env)
    
    elif subcommand == "delete" or subcommand == "del":
        if len(tokens) >= 3:
            # ip delete <n>
            name = tokens[2]
            delete_ip_variable(env, name)
        else:
            print("[!] Usage: ip delete <n>")
    
    elif subcommand == "suggest":
        # ip suggest - show common variable suggestions
        suggest_common_variables(env)
    
    elif subcommand == "import":
        # ip import - import IPs from scan results
        import_ips_from_scan(env)
    
    elif subcommand == "export":
        # ip export [format] - export IPs in different formats
        export_format = tokens[2] if len(tokens) > 2 else "list"
        if export_format in ["list", "hosts", "nmap"]:
            export_ip_variables(env, export_format)
        else:
            print("[!] Export formats: list, hosts, nmap")
    
    elif subcommand == "help":
        print(f"[*] Enhanced IP Management (Session-Integrated):")
        print("    ip                          - Show current IP + copy to clipboard")
        print("    ip set <new_ip>             - Update primary target IP")
        print("    ip save <n> <ip> [desc]  - Save IP variable in session state")
        print("    ip get <n>               - Get IP variable + copy to clipboard")
        print("    ip list                     - List all IPs for this target")
        print("    ip delete <n>            - Delete IP variable")
        print("    ip suggest                  - Show common variable names")
        print("    ip import                   - Import IPs from scan results")
        print("    ip export [list|hosts|nmap] - Export IPs in various formats")
        print()
        print("    Variables stored in state.json with session data")
        print("    All IPs automatically copied to clipboard! 📋")
    
    else:
        print("[*] IP Management Commands:")
        print("    ip               - Show current target IP")
        print("    ip set <new_ip>   - Update primary target IP")
        print("    ip save <n> <ip> - Save IP variable")
        print("    ip get <n>       - Get saved IP (copies to clipboard)")
        print("    ip list           - List all saved IPs for this target")
        print("    ip suggest        - Show common variable suggestions")
        print("    ip help           - Show detailed help")
    
    return env

# ============================================================================
# SCANNING COMMANDS
# ============================================================================

def is_valid_ip(ip_str):
    """Check if string is a valid IP address"""
    import re
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if not ip_pattern.match(ip_str):
        return False
    
    # Check each octet is 0-255
    parts = ip_str.split('.')
    return all(0 <= int(part) <= 255 for part in parts)

def handle_scan_command(scan_type, tokens, env):
    """Handle various scanning commands with enhanced internal IP support"""
    if not SCANNING_AVAILABLE:
        print("[!] Scanning modules not available")
        return env
    if not env or 'IP' not in env:
        print("[!] No active target. Use 'target new <n> <ip>' first")
        return env
    
    # Parse flags
    flags = parse_scan_flags(tokens)
    
    # Determine target IP and scan context
    if flags['internal_ip']:
        target_ip = flags['internal_ip']
        scan_context = f"internal scan of {target_ip} via {env['IP']}"
        # Tunneled scan: internal_10_10_10_50
        modified_boxname = f"internal_{target_ip.replace('.', '_')}"
    elif flags['internal']:
        target_ip = env['IP']
        scan_context = f"internal scan of {target_ip}"
        # Internal methodology: just "internal"
        modified_boxname = "internal"
    else:
        target_ip = env['IP']
        scan_context = f"external scan of {target_ip}"
        # External scan: use original boxname
        modified_boxname = env['BOXNAME']
    
    outdir = Path(env['OUTDIR'])
    logfile = Path(env['LOGFILE'])
    
    try:
        if scan_type in ["fs", "fullscan", "full"]:
            print(f"[*] Running full TCP scan - {scan_context}")
            
            # Log the scan context
            with open(logfile, "a") as f:
                timestamp = datetime.now().strftime("%F %T")
                f.write(f"[{timestamp}] Starting full scan - {scan_context}\n")
            
            run_full_scan(
                target_ip, 
                modified_boxname,
                outdir, 
                logfile, 
                internal=flags['internal'], 
                intel=flags['intel']
            )
            
        elif scan_type == "tcp":
            print(f"[*] Running TCP port scan - {scan_context}")
            
            with open(logfile, "a") as f:
                timestamp = datetime.now().strftime("%F %T")
                f.write(f"[{timestamp}] Starting TCP scan - {scan_context}\n")
            
            run_tcp_scan(
                target_ip, 
                modified_boxname, 
                outdir, 
                logfile, 
                internal=flags['internal'], 
                intel=flags['intel']
            )
            
        elif scan_type == "udp":
            print(f"[*] Running UDP port scan - {scan_context}")
            # Note: UDP doesn't work well through tunnels, warn user
            if flags['internal_ip']:
                print("[!] Warning: UDP scans through tunnels may be unreliable")
            
            check_udp_progress(target_ip, modified_boxname, outdir, logfile)
            
        # REMOVE OR MODIFY THIS SECTION - What do you want for "ss"?
        # elif scan_type == "ss":
        #     print("[!] Short scan not implemented")
        #     return env
            
        elif scan_type == "script":
            print(f"[*] Running NSE scripts - {scan_context}")
            
            run_script_scan(
                target_ip, 
                modified_boxname, 
                outdir, 
                logfile, 
                internal=flags['internal'], 
                intel=flags['intel']
            )
        
        elif scan_type == "sweep":
            print(f"[*] Running sweep scan - {scan_context}")
            
            # Parse --include flag
            include_file = None
            for i, token in enumerate(tokens):
                if token == "--include" and i + 1 < len(tokens):
                    include_file = tokens[i + 1]
                    break
            
            # Log the scan context
            with open(logfile, "a") as f:
                timestamp = datetime.now().strftime("%F %T")
                source = f" using {include_file}" if include_file else ""
                f.write(f"[{timestamp}] Starting sweep scan{source}\n")
            
            # Call the sweep function from scans.py
            success = run_sweep_scan(
                target_ip,
                modified_boxname,
                outdir,
                logfile,
                internal=flags['internal'],
                intel=flags['intel'],
                include_file=include_file
            )
            
            if not success and include_file:
                # Show available files if include failed
                print(f"[*] Available files in session:")
                list_scan_files(env)

        elif scan_type == "discovery":
            # Check if a specific IP/CIDR was provided as parameter
            discovery_target = None
            for token in tokens[1:]:  # Skip the command itself
                if token not in ["--internal", "--intel"]:  # Skip flags
                    # Use existing is_ip_range function to validate
                    from session import is_ip_range
                    valid, is_range = is_ip_range(token)
                    if valid:
                        discovery_target = token
                        break
            
            # Use provided target or fall back to session IP
            if discovery_target:
                target_ip = discovery_target
                scan_context = f"host discovery on {discovery_target}"
                if flags['internal']:
                    scan_context += f" via {env['IP']}"
            else:
                # Use session IP (original behavior)
                scan_context = f"host discovery - external scan of {target_ip}"
            
            print(f"[*] Running {scan_context}")
            
            # Host discovery works best with CIDR ranges
            if discovery_target:
                _, is_range = is_ip_range(discovery_target)  # Fixed syntax error
                if not is_range:
                    print(f"[!] Tip: Host discovery works best with CIDR notation (e.g. 192.168.127.0/24)")
            
            # Log the scan context
            with open(logfile, "a") as f:
                timestamp = datetime.now().strftime("%F %T")
                f.write(f"[{timestamp}] Starting {scan_context}\n")
            
            # Run discovery with file output (pass the boxname)
            live_ips = run_host_discovery_only(
                target_ip,
                internal=flags['internal'],
                outdir=outdir,
                boxname=modified_boxname,  # This ensures proper naming
                save_results=True
            )
            
            if live_ips:
                print(f"[+] Discovery complete: {len(live_ips)} live hosts found")
                print(f"[*] Use 'sweep' to scan all discovered hosts")
            else:
                print("[*] No live hosts discovered")
            
        elif scan_type in ["web", "we"]:
            # Parse additional web-specific parameters
            port = None
            tool = "auto"
            protocol = None
            
            # Look for web-specific parameters (keep existing logic)
            i = 1
            while i < len(tokens):
                token = tokens[i]
                if token.isdigit():
                    port = token
                elif token in ["--ferox", "--feroxbuster"]:
                    tool = "ferox"
                elif token in ["--gobuster", "--gobust"]:
                    tool = "gobuster"
                elif token in ["--http", "http"]:
                    protocol = "http"
                elif token in ["--https", "https"]:
                    protocol = "https"
                elif token == "--ssl":
                    protocol = "https"
                i += 1
            
            # Build description for output
            web_desc = f"web enumeration - {scan_context}"
            if port:
                web_desc += f" on port {port}"
            if protocol:
                web_desc += f" ({protocol.upper()})"
                
            print(f"[*] Running {web_desc}")
            
            web_enum(
                target_ip, 
                modified_boxname, 
                outdir, 
                logfile, 
                port=port,
                internal=flags['internal'], 
                intel=flags['intel'], 
                tool=tool, 
                protocol=protocol
            )
                    
    except Exception as e:
        import traceback
        print(f"[!] Scan error: {e}")
        print(f"[!] Full traceback:")
        traceback.print_exc()
        
    return env

# ============================================================================
# PAYLOAD SYSTEM INTEGRATION
# ============================================================================

def get_payload_manager(env=None):
    """Get or create payload manager instance"""
    global _payload_manager
    
    if not PAYLOAD_AVAILABLE:
        return None
    
    if _payload_manager is None:
        # Determine base directory from environment
        if env and 'OUTDIR' in env:
            base_dir = str(Path(env['OUTDIR']).parent)
        else:
            base_dir = os.getcwd()
        
        _payload_manager = create_payload_manager(base_dir)
        
        # Set target name if available
        if env and 'BOXNAME' in env:
            _payload_manager.jasmin_env.config['target_name'] = env['BOXNAME']
    
    return _payload_manager

def handle_payload_command(tokens, env):
    """Handle payload commands with global manager tracking"""
    global _payload_manager
    
    if not PAYLOAD_AVAILABLE:
        print("[!] Enhanced payload module not available")
        print("[!] Install the payload module: jasmin_payload_complete.py")
        return env
    
    # Get or create the global manager
    _payload_manager = get_payload_manager(env)
    if not _payload_manager:
        print("[!] Failed to initialize payload manager")
        return env
    
    # Reconstruct full command
    full_command = "payload " + " ".join(tokens[1:]) if len(tokens) > 1 else "payload help"
    
    try:
        response = _payload_manager.handle_command(full_command)
        print(response)
        
        # Handle special cases that might need user interaction
        if "[?]" in response and "(G)enerate" in response:
            # Tier 1 confirmation prompt
            while True:
                user_response = input("").strip().lower()
                if user_response:
                    confirmation_response = _payload_manager.handle_confirmation(user_response)
                    print(confirmation_response)
                    break
        
    except Exception as e:
        print(f"[!] Payload command error: {e}")
        # Reset payload manager on error
        if _payload_manager:
            _payload_manager.current_mode = "command" 
            _payload_manager.build_interface = None
    
    return env

# ============================================================================
# INTELLIGENCE SYSTEM INTEGRATION - Fixed Database Path
# ============================================================================

def find_intelligence_database():
    """Find the intelligence database in the current directory structure"""
    # Try common locations relative to current directory
    possible_paths = [
        "intelligence.db",              # Current directory (where it actually is!)
        "./intelligence.db",
        "intelligence_db/intelligence.db",
        "./intelligence_db/intelligence.db"
    ]
    
    for path in possible_paths:
        if Path(path).exists():
            return str(Path(path).resolve())
    
    # If not found, return the most likely location
    return "intelligence.db"

def init_jasmin_intelligence():
    """Initialize the intelligence system with proper path resolution"""
    if INTEL_AVAILABLE:
        try:
            # Find the database
            db_path = find_intelligence_database()
            
            # Check if database exists
            if not Path(db_path).exists():
                print(f"[!] Intelligence database not found at: {db_path}")
                print("[!] Expected location: intelligence.db (in current directory)")
                print("[!] Run 'python intelligence_main.py' to build the database")
                return None
            
            from intelligence_integration import init_intelligence_system
            return init_intelligence_system()
        except Exception as e:
            print(f"[!] Failed to initialize intelligence system: {e}")
            return None
    return None

# ============================================================================
# ACTIVE DIRECTORY COMMANDS
# ============================================================================

def handle_ad_command(tokens, env):
    """Handle Active Directory enumeration commands"""
    if not AD_AVAILABLE:
        print("[!] AD enumeration modules not available")
        return env
        
    if len(tokens) < 2:
        print("[!] Usage: ad <command>")
        print("Available commands: enum, users, bloodhound, kerberos, policy, creds, help")
        return env
    
    cmd = tokens[1].lower()
    
    if not env or 'IP' not in env:
        print("[!] No active target. Use 'target new <n> <ip>' first")
        return env
    
    try:
        if cmd == "enum":
            print(f"[*] Running full AD enumeration on {env['IP']}")
            ad_enum_full(env, tokens[2:])
            
        elif cmd == "users":
            print(f"[*] Enumerating domain users on {env['IP']}")
            ad_enum_users(env, tokens[2:])
            
        elif cmd == "bloodhound":
            print(f"[*] Running BloodHound collection on {env['IP']}")
            ad_bloodhound(env, tokens[2:])
            
        elif cmd == "kerberos":
            print(f"[*] Running Kerberos enumeration on {env['IP']}")
            ad_kerberos(env, tokens[2:])
            
        elif cmd == "policy":
            print(f"[*] Enumerating domain policy on {env['IP']}")
            ad_policy(env, tokens[2:])
            
        elif cmd == "creds":
            print(f"[*] Testing credentials on {env['IP']}")
            ad_creds(env, tokens[2:])
            
        elif cmd == "help":
            ad_help()
            
        else:
            print(f"[!] Unknown AD command: {cmd}")
            print("Available commands: enum, users, bloodhound, kerberos, policy, creds, help")
    
    except Exception as e:
        print(f"[!] AD enumeration error: {e}")
    
    return env

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def handle_notes_command(cmd, tokens, env):
    """Handle notes and documentation"""
    if not NOTES_AVAILABLE:
        print("[!] Notes system not available")
        return
        
    if not env:
        print("[!] No active session for notes")
        return
    
    try:
        # Extract required parameters from env
        outdir = Path(env["OUTDIR"])
        session_dir = outdir / "session"  # Add this line
        boxname = env["BOXNAME"]
        
        # Determine correct notes file based on context
        if 'HOST' in env:
            host_ip = env['HOST']
            notes_path = session_dir / f"{boxname}_{host_ip.replace('.', '_')}_notes.txt"
        else:
            notes_path = session_dir / f"{boxname}_notes.txt"
        
        if len(tokens) > 1:
            subcmd = tokens[1].lower()
            if subcmd == "quick":
                notes_quick(notes_path)  # Fixed: pass notes_path instead of env
            elif subcmd == "creds":
                notes_creds(notes_path)  # Fixed: pass notes_path instead of env
            elif subcmd == "users":
                notes_users(notes_path)  # Fixed: pass notes_path instead of env
            elif subcmd == "open":
                open_notes(boxname, session_dir)  # Fixed: pass boxname and outdir
            else:
                print("[!] Unknown notes command")
                print("Available: quick, creds, users, open")
        else:
            open_notes(boxname, session_dir)  # Fixed: pass boxname and outdir
    except Exception as e:
        print(f"[!] Notes error: {e}")

def handle_upload_command(env, tokens):
    """Handle file upload server"""
    if not UPLOAD_AVAILABLE:
        print("[!] Upload server not available")
        return
        
    try:
        upload_handler(env, tokens)
    except Exception as e:
        print(f"[!] Upload server error: {e}")

def view_file(env, args):
    """View files in session directory"""
    if not NOTES_AVAILABLE:
        print("[!] File viewing not available")
        return
        
    if not args:
        print("[!] Usage: view <filename>")
        return
    
    if not env:
        print("[!] No active session")
        return
    
    try:
        notes_view_file(env, args)
    except Exception as e:
        print(f"[!] Error viewing file: {e}")

def format_prompt(target, host):
    """Format the command prompt"""
    if target:
        if host:
            return f"{COLORS['blue']}jasmin{COLORS['reset']}({COLORS['red']}{target}:{host}{COLORS['reset']})> "
        else:
            return f"{COLORS['blue']}jasmin{COLORS['reset']}({COLORS['red']}{target}{COLORS['reset']})> "
    else:
        return f"{COLORS['blue']}jasmin{COLORS['reset']}> "

def get_current_context():
    """Get current target context for prompt"""
    if TARGET_MANAGEMENT_AVAILABLE:
        try:
            from target import get_current_context as get_context
            return get_context()
        except Exception:
            return None, None
    return None, None

def show_status_message(message, msg_type="info"):
    """Show formatted status message"""
    color = COLORS['blue']
    if msg_type == "warning":
        color = COLORS['yellow']
    elif msg_type == "error":
        color = COLORS['red']
    elif msg_type == "success":
        color = COLORS['green']
    
    print(f"{color}[{msg_type.upper()}]{COLORS['reset']} {message}")

def startup_dependency_check():
    """Check dependencies on startup and offer to install if missing"""
    setup_manager = JasminSetupManager()
    
    if not setup_manager.quick_dependency_check():
        print(f"\n{COLORS['yellow']}⚠️  JASMIN Setup Required{COLORS['reset']}")
        print(f"Essential tools are missing for full functionality.")
        
        try:
            response = input(f"\n{COLORS['cyan']}Run automated setup now? (y/N): {COLORS['reset']}").strip().lower()
            if response in ['y', 'yes']:
                if setup_manager.auto_install():
                    print(f"\n{COLORS['green']}🎉 Setup complete! Please restart JASMIN.{COLORS['reset']}")
                    return False  # Exit to restart
                else:
                    print(f"\n{COLORS['yellow']}Setup had issues but continuing...{COLORS['reset']}")
            else:
                print(f"{COLORS['blue']}💡 Run 'setup install' anytime to install dependencies{COLORS['reset']}")
        except KeyboardInterrupt:
            print(f"\n{COLORS['blue']}💡 Run 'setup install' anytime to install dependencies{COLORS['reset']}")
    
    return True  # Continue normal startup

# =============================================================================
# SETUP COMMAND HANDLER
# =============================================================================

def handle_setup_command(tokens, env):
    """Handle setup-related commands"""
    setup_manager = JasminSetupManager()
    
    if len(tokens) == 1 or (len(tokens) > 1 and tokens[1] == "status"):
        # Show status
        print(f"\n{COLORS['cyan']}🔍 JASMIN Dependency Status{COLORS['reset']}")
        if setup_manager.show_missing_tools():
            print(f"{COLORS['green']}✅ All essential dependencies satisfied!{COLORS['reset']}")
        
    elif len(tokens) > 1 and tokens[1] in ["install", "auto"]:
        # Automated installation
        print(f"{COLORS['yellow']}⚠️  This will install packages on your system.{COLORS['reset']}")
        try:
            response = input("Continue? (y/N): ").strip().lower()
            if response in ['y', 'yes']:
                setup_manager.auto_install()
            else:
                print("Setup cancelled.")
        except KeyboardInterrupt:
            print("\nSetup cancelled.")
            
    elif len(tokens) > 1 and tokens[1] == "check":
        # Detailed check
        if setup_manager.quick_dependency_check():
            print(f"{COLORS['green']}✅ Core dependencies satisfied{COLORS['reset']}")
        setup_manager.show_missing_tools()
        
    elif len(tokens) > 1 and tokens[1] == "path":
        # PATH setup only
        setup_manager.setup_path()
        
    elif len(tokens) > 1 and tokens[1] == "help":
        show_setup_help()
        
    else:
        show_setup_help()
    
    return env

def show_setup_help():
    """Show setup command help"""
    print(f"""
{COLORS['blue']}JASMIN Setup & Installation{COLORS['reset']}

{COLORS['green']}Commands:{COLORS['reset']}
  setup                     Show dependency status
  setup check               Detailed dependency check
  setup install             Automated installation
  setup path                Add JASMIN to PATH
  setup help                Show this help

{COLORS['green']}Quick Start:{COLORS['reset']}
  1. python3 jasmin.py setup install
  2. Restart terminal or: source ~/.bashrc  
  3. Test with: jasmin help

{COLORS['yellow']}What Gets Installed:{COLORS['reset']}
  ✓ Core tools: nmap, curl, wget, netcat
  ✓ Python modules: requests, beautifulsoup4, colorama
  ✓ Enhanced tools: feroxbuster, gobuster, whatweb
  ✓ PATH configuration for 'jasmin' command

{COLORS['blue']}Manual Installation:{COLORS['reset']}
  Ubuntu/Debian: sudo apt install nmap curl wget python3-pip
  CentOS/RHEL:   sudo dnf install nmap curl wget python3-pip
  Arch Linux:    sudo pacman -S nmap curl wget python-pip
  
  Python:        pip3 install requests beautifulsoup4 colorama
""")

# ============================================================================
# GUI COMMAND HANDLER (thin shim; launches only on explicit `gui` command)
# ============================================================================

# Keep a module-level error holder for status messages
_GUI_IMPORT_ERROR = None

def check_gui_requirements() -> bool:
    """Return True if PyQt6 and the GUI module are importable."""
    global _GUI_IMPORT_ERROR
    try:
        # Import checks only (no side effects)
        from PyQt6.QtWidgets import QApplication  # noqa: F401
        _GUI_IMPORT_ERROR = None
        return True
    except Exception as e:
        _GUI_IMPORT_ERROR = e
        return False

def show_gui_status():
    ok = check_gui_requirements()
    print("JASMIN GUI Status:")
    print(f"  Available: {'✓' if ok else '✗'}")
    if not ok and _GUI_IMPORT_ERROR:
        print(f"  Reason: {_GUI_IMPORT_ERROR}")

def handle_gui_command(tokens, env):
    """Handle `gui` subcommands."""
    # Parse subcommand
    subcommand = tokens[1].lower() if len(tokens) > 1 else "launch"
    args = tokens[2:] if len(tokens) > 2 else []

    if subcommand in ("help", "h"):
        return handle_gui_help(args, env)
    if subcommand in ("status", "check"):
        return handle_gui_status(args, env)
    if subcommand in ("launch", "start", "open") or True:
        # Default to launch for unknown subcommands, preserving old behavior
        return handle_gui_launch(args, env)

def handle_gui_launch(_args, env):
    """Launch the Qt GUI for the current session (explicit command only)."""
    if not check_gui_requirements():
        print("[!] GUI integration not available")
        print("[*] Install: pip install PyQt6")
        return env

    if not env or 'BOXNAME' not in env or 'IP' not in env:
        print("[!] No active JASMIN session found.")
        print("[*] Start a session first:")
        print("    jasmin> target <name> <ip>")
        print("    jasmin> resume <name>")
        return env

    print(f"[+] Launching GUI for session: {env['BOXNAME']} ({env['IP']})")
    print(f"[+] Session directory: {env.get('OUTDIR', '?')}")

    try:
        from jasmin_gui_main import launch_gui
        ok = launch_gui(env)  # Blocks until window closes
        if not ok:
            print("[!] GUI launch failed")
    except Exception as e:
        print(f"[!] GUI launch error: {e}")

    return env

def handle_gui_status(_args, env):
    show_gui_status()
    return env

def handle_gui_help(_args, env):
    help_text = f"""
{COLORS.get('cyan', '')}GUI Commands:{COLORS.get('reset', '')}

  gui                         Launch visual workbench (default)
  gui launch                  Launch visual workbench
  gui status                  Check GUI availability and status
  gui help                    Show this help

{COLORS.get('yellow', '')}GUI Features:{COLORS.get('reset', '')}
  • Visual interface to session data
  • Real-time scan monitoring
  • State.json visualization
  • Integrated notes editing
  • Session management
  • File system browsing

{COLORS.get('green', '')}Examples:{COLORS.get('reset', '')}
  jasmin[mybox]> gui                    # Launch GUI
  jasmin[mybox]> gui status             # Check GUI status
  jasmin> gui help                      # Show this help

{COLORS.get('yellow', '')}Requirements:{COLORS.get('reset', '')}
  • PyQt6 (required)
  • pyperclip (optional)
  • netifaces (optional)

Install with: pip install PyQt6 pyperclip netifaces
"""
    print(help_text)
    return env


# ============================================================================
# MAIN REPL LOOP
# ============================================================================

def jasmin_repl(env=None):
    """Main JASMIN REPL loop"""
    
    # Show module availability
    if PAYLOAD_AVAILABLE:
        print(f"{COLORS['green']}[+] Enhanced Payload Module loaded{COLORS['reset']} - use 'payload help' for details")
    
    if READLINE_AVAILABLE:
        print(f"{COLORS['green']}[+] Command history and tab completion enabled{COLORS['reset']}")
        
    if INTEL_AVAILABLE:
        print(f"{COLORS['green']}[+] Intelligence system loaded{COLORS['reset']} - use 'intel help' for details")
    
    print()  # Extra line for clarity
    
    while True:
        try:
            # Get current prompt (this will be updated as we go)
            prompt = get_current_prompt(env)
            cmd = input(prompt).strip()
            
            try:
                in_payload_mode = is_in_payload_mode()
            except NameError:
                in_payload_mode = False
            except Exception as e:
                in_payload_mode = False
            
            if not cmd:
                continue
                
            tokens = cmd.split()
            base_cmd = tokens[0].lower()
            
            # Handle exit/quit - check payload mode first
            if base_cmd in ["exit", "quit", "q"]:
                # Check if we're in payload mode and need to exit that first
                if PAYLOAD_AVAILABLE and _payload_manager and _payload_manager.current_mode in ["build", "browse"]:
                    try:
                        result = _payload_manager.handle_command(cmd)
                        print(result)
                        # After exiting payload mode, continue loop (don't exit JASMIN)
                        continue
                    except Exception as e:
                        print(f"[!] Error exiting payload mode: {e}")
                        # Force exit payload mode
                        _payload_manager.current_mode = "command"
                        _payload_manager.build_interface = None
                        print("[*] Forced exit from payload mode")
                        continue
                
                # Full JASMIN exit
                print(f"{COLORS['green']}Thanks for using JASMIN!{COLORS['reset']}")
                
                # Inline upload server cleanup
                if UPLOAD_AVAILABLE:
                    try:
                        from upload_server import _upload_server
                        if hasattr(_upload_server, 'running') and _upload_server.running:
                            print("\n[*] Stopping upload server...")
                            _upload_server.stop_server()
                    except (ImportError, AttributeError):
                        pass
                
                break
            
            # CRITICAL: Check if we're in payload mode and route accordingly
            # BUT do this check AFTER potentially executing payload commands
            currently_in_payload_mode = False
            if PAYLOAD_AVAILABLE and _payload_manager:
                if hasattr(_payload_manager, 'current_mode') and _payload_manager.current_mode in ["build", "browse"]:
                    if hasattr(_payload_manager, 'build_interface') and _payload_manager.build_interface:
                        if hasattr(_payload_manager.build_interface, 'active') and _payload_manager.build_interface.active:
                            currently_in_payload_mode = True
            
            # Route commands based on mode
            if currently_in_payload_mode:
                # Route ALL commands to payload manager when in payload mode
                try:
                    result = _payload_manager.handle_command(cmd)
                    print(result)
                    # Continue to next iteration - this will refresh the prompt
                    continue
                except Exception as e:
                    print(f"[!] Payload command error: {e}")
                    # Reset payload mode on error
                    if _payload_manager:
                        _payload_manager.current_mode = "command"
                        _payload_manager.build_interface = None
                        print("[*] Reset to command mode due to error")
                    continue
            
            # Handle help
            elif base_cmd == "help":
                show_help()

            #Shows tools for web enumeration
            elif base_cmd == "tools":
                check_web_tools_status()
            
            # Handle clear screen
            elif base_cmd == "clear":
                print("\033[2J\033[H", end="")
                
            # Handle target management
            elif base_cmd == "target":
                env = handle_target_command(tokens, env)
            
            # Handle scanning commands
            elif base_cmd in ["fs", "fullscan", "full", "tcp", "udp", "web", "we", "ss", "script", "discovery", "sweep"]:
                env = handle_scan_command(base_cmd, tokens, env)
            
            #Handle viewing scans commands
            elif base_cmd == "scans":
                env = handle_scans_command(tokens, env)
            elif base_cmd == "ls": 
                env = handle_scans_command(["scans", "list"], env)

            #Handle IP commands
            elif base_cmd == "ip":
                env = handle_session_integrated_ip_command(tokens, env)
            
            elif base_cmd == "payload":
                env = handle_payload_command(tokens, env)
                continue

            elif base_cmd == "setup":
                env = handle_setup_command(tokens, env)

            elif base_cmd == "gui":
                env = handle_gui_command(tokens, env)

            # ============================================================================
            # ALSO: Let's verify which functions actually exist
            # Add this test command to see what functions are loaded:
            # ============================================================================
                
                # Check if there are multiple versions
                import inspect
                if 'handle_payload_command' in globals():
                    print(f"handle_payload_command source file: {inspect.getfile(handle_payload_command)}")
                continue
            
            # Handle intelligence commands
            elif base_cmd == "intel":
                env = handle_intel_command(env, tokens)
            
            # Handle AD commands
            elif base_cmd == "ad":
                env = handle_ad_command(tokens, env)
            
            # Handle notes
            elif base_cmd == "notes":
                handle_notes_command(cmd, tokens, env)
            
            # Handle upload
            elif base_cmd == "upload":
                handle_upload_command(env, tokens)
            
            # Handle view
            elif base_cmd == "view":
                if env:
                    view_file(env, tokens[1:])
                else:
                    print("[!] No active session.")
            
            
            # Unknown command
            else:
                print(f"[!] Unknown command: {base_cmd}. Type 'help' for available commands.")
                
                # Provide helpful suggestions
                if any(word in base_cmd for word in ['payload', 'msfvenom', 'shell', 'meterpreter']):
                    print("[*] Did you mean to use the payload module? Try 'payload help'")
                elif base_cmd in ['scan', 'nmap']:
                    print("[*] Try: fs (full scan), tcp (TCP scan), or web (web enum)")
                # ADD THIS LINE:
                elif base_cmd in ['visual', 'interface', 'workbench']:
                    print("[*] Try: gui (launch visual interface)")
                
        except KeyboardInterrupt:
            print()  # New line after ^C
            show_status_message("Use 'exit' to quit JASMIN", "info")
            
        except Exception as e:
            print(f"[!] Unexpected error: {e}")

# ============================================================================
# MAIN FUNCTION
# ============================================================================

def main():
    """Main JASMIN function"""

    # Parse command line arguments first to check for quiet mode
    parser = argparse.ArgumentParser(description="JASMIN - Just A Smooth Machine Infiltrating Networks")
    parser.add_argument('command', nargs='*', help='Command to execute')
    parser.add_argument('--target', help='Target to use')
    parser.add_argument('-q', '--quiet', action='store_true', help='Skip startup banner and loading animation')
    
    args = parser.parse_args()

    # Check dependencies on startup (unless quiet mode)
    if not args.quiet:
        if not startup_dependency_check():
            return  # Exit to restart after setup
    
    
    # Show JASMIN startup sequence (unless quiet mode)
    if not args.quiet:
        jasmin_startup()
    else:
        print(f"{COLORS['blue']}JASMIN v2.1{COLORS['reset']} - Just A Smooth Machine Infiltrating Networks")
    
    if args.command:
        # Non-interactive mode
        cmd = " ".join(args.command)
        print(f"[*] Executing command: {cmd}")
        # Handle non-interactive command execution here
        return
    
    # Interactive REPL mode
    env = None
    if TARGET_MANAGEMENT_AVAILABLE:
        try:
            env = get_current_session_env()
        except Exception as e:
            print(f"[!] Warning: Could not load current session: {e}")
            env = None
    
    if not env:
        print(f"{COLORS['yellow']}[*] No active session found.{COLORS['reset']}")
        print(f"{COLORS['yellow']}[*] Use 'target new <name> <ip>' to create a target session.{COLORS['reset']}")
        
        # Show available targets if any exist
        if TARGET_MANAGEMENT_AVAILABLE:
            try:
                targets = list_targets()
                if targets:
                    print(f"{COLORS['blue']}[*] Available targets:{COLORS['reset']}")
                    for i, target in enumerate(targets, 1):
                        print(f"    [{i}] {target}")
                    print(f"{COLORS['yellow']}[*] Use 'target set <number>' to resume a session.{COLORS['reset']}")
            except Exception as e:
                print(f"[!] Could not list targets: {e}")
    else:
        # Show current active session
        boxname = env.get('BOXNAME', 'unknown')
        ip = env.get('IP', 'unknown')
        print(f"{COLORS['green']}[+] Active session: {boxname} ({ip}){COLORS['reset']}")
    
    # Start REPL
    jasmin_repl(env)

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    main()