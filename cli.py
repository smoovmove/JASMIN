#!/usr/bin/env python3
"""
JASMIN CLI Module - Enhanced with Payload Integration
Command dispatch and handlers for JASMIN framework
"""

import argparse
from pathlib import Path
import sys
import os

try:
    from jasmin_gui_integration import handle_gui_command, check_gui_requirements
    GUI_INTEGRATION_AVAILABLE = True
except ImportError:
    GUI_INTEGRATION_AVAILABLE = False

# Import existing JASMIN modules
from scans import run_full_scan, run_tcp_scan, check_udp_progress, run_script_scan, run_host_discovery_only, web_enum
from session import (
    new_session, get_session_file, list_all_targets, 
    create_target_session, resume_target_session, resume_host_session,
    get_current_session_env
)
from target import (
    get_last_target, set_last_target, get_jarvis_file,
    get_current_context, set_current_context, list_targets, list_hosts,
    resolve_use_target, format_prompt, target_exists
)
from notes import notes_quick, notes_creds, notes_users, open_notes, view_file
from upload_server import handle_upload_command

# Import enhanced payload module
try:
    from payload import create_payload_manager
    PAYLOAD_AVAILABLE = True
    # Global payload manager instance
    #_payload_manager = None
except ImportError:
    print("[!] Warning: Enhanced payload module not available")
    PAYLOAD_AVAILABLE = False
    #_payload_manager = None

_global_payload_manager = None

def set_global_payload_manager(manager):
    """Set the global payload manager - called from jasmin.py"""
    global _global_payload_manager
    _global_payload_manager = manager

def get_global_payload_manager():
    """Get the global payload manager"""
    global _global_payload_manager
    return _global_payload_manager

def is_in_payload_mode():
    """Check if we're currently in payload mode"""
    if not PAYLOAD_AVAILABLE:
        return False
    
    payload_manager = get_global_payload_manager()
    if not payload_manager:
        return False
    
    try:
        in_build_mode = (payload_manager.current_mode == "build" and 
                        hasattr(payload_manager, 'build_interface') and 
                        payload_manager.build_interface and 
                        payload_manager.build_interface.active)
        
        in_browse_mode = payload_manager.current_mode == "browse"
        
        result = in_build_mode or in_browse_mode
        return result
    except Exception as e:
        return False
    
# Try to import intelligence system  
try:
    from intelligence_integration import handle_intel_command, init_intelligence_system
    INTEL_AVAILABLE = True
except ImportError:
    INTEL_AVAILABLE = False

# Try to import AD enumeration
try:
    from ad_enum import (
        ad_enum_full, ad_enum_users, ad_bloodhound, ad_kerberos, 
        ad_policy, ad_creds, ad_help
    )
    AD_AVAILABLE = True
except ImportError:
    AD_AVAILABLE = False

def get_payload_manager(env):
    """Ensure global payload manager is initialized and returned"""
    if not PAYLOAD_AVAILABLE:
        return None

    try:
        import jasmin

        # Create and assign to global if missing
        if not hasattr(jasmin, '_payload_manager') or jasmin._payload_manager is None:
            manager = create_payload_manager()
            jasmin._payload_manager = manager  # ✅ set global in jasmin
        return jasmin._payload_manager
    except Exception as e:
        print(f"[!] Failed to initialize payload manager: {e}")
        return None


def handle_payload_command(env, subargs):
    """Handle payload module commands"""
    if not PAYLOAD_AVAILABLE:
        print("[!] Enhanced payload module not available")
        print("[!] Install the payload module: jasmin_payload_complete.py")
        return env
    
    manager = get_payload_manager(env)
    if not manager:
        print("[!] Failed to initialize payload manager")
        return env
    
    # Reconstruct full command
    full_command = "payload " + " ".join(subargs) if subargs else "payload help"
    
    try:
        response = manager.handle_command(full_command)
        print(response)
        
        # Handle special cases that might need user interaction
        if "[?]" in response and "(G)enerate" in response:
            # Tier 1 confirmation prompt
            while True:
                user_response = input("").strip().lower()
                if user_response:
                    confirmation_response = manager.handle_confirmation(user_response)
                    print(confirmation_response)
                    break
        
    except Exception as e:
        print(f"[!] Payload command error: {e}")
        # Reset payload manager on error
        global _payload_manager
        _payload_manager = None
    
    return env

def handle_payload_mode_input(env, command):
    """Handle input when in payload mode (browse/build)"""
    if not PAYLOAD_AVAILABLE:
        return env, False
    
    manager = get_payload_manager(env)
    if not manager or manager.current_mode == "command":
        return env, False
    
    try:
        response = manager.handle_command(command)
        print(response)
        return env, True
    except Exception as e:
        print(f"[!] Payload mode error: {e}")
        # Reset to command mode on error
        if manager:
            manager.current_mode = "command"
            manager.build_interface = None
        return env, False


def get_current_prompt(env):
    """Get appropriate prompt based on current mode with payload support"""
    # SIMPLE FIX: Get payload manager directly from jasmin module using sys.modules
    payload_manager = None
    if PAYLOAD_AVAILABLE:
        try:
            import sys
            main_module = sys.modules.get('__main__')
            if main_module and hasattr(main_module, '_payload_manager'):
                payload_manager = main_module._payload_manager
            else:
                import jasmin
                payload_manager = getattr(jasmin, '_payload_manager', None)
        except Exception:
            payload_manager = None
    
    # Check if we're in payload mode FIRST
    if PAYLOAD_AVAILABLE and payload_manager:
        try:
            if (payload_manager.current_mode == "build" and 
                payload_manager.build_interface and 
                payload_manager.build_interface.active):
                
                # Get payload type for prompt
                config = payload_manager.current_config
                if config and config.payload_type:
                    # Extract platform from payload type (e.g., "windows/shell_reverse_tcp" -> "windows")
                    platform = config.payload_type.split('/')[0] if '/' in config.payload_type else config.payload_type
                    return f"jasmin [\033[94mpayload\033[0m(\033[91m{platform}\033[0m)] >> "
                else:
                    return f"jasmin [\033[94mpayload\033[0m(\033[91mconfig\033[0m)] >> "
                
            elif payload_manager.current_mode == "browse":
                return f"jasmin [\033[94mbrowse\033[0m] >> "
        except Exception:
            pass  # Fall through to default prompt
    
    # Default JASMIN prompt with colors
    if env and 'BOXNAME' in env:
        if 'HOST' in env:
            return f"jasmin [\033[94m{env['BOXNAME']}:{env['HOST']}\033[0m] >> "
        else:
            return f"jasmin [\033[94m{env['BOXNAME']}\033[0m] >> "
    else:
        return "jasmin>> "

def handle_quick_note(env, subargs):
    """Handle quick notes"""
    if not env or 'OUTDIR' not in env:
        print("[!] No active session.")
        return
    
    outdir = Path(env["OUTDIR"])
    boxname = env["BOXNAME"]
    
    # Determine correct notes file based on context
    if 'HOST' in env:
        host_ip = env['HOST']
        notes_path = outdir / f"{boxname}_{host_ip.replace('.', '_')}_notes.txt"
    else:
        notes_path = outdir / f"{boxname}_notes.txt"
    
    notes_quick(notes_path)

def handle_creds_note(env, subargs):
    """Handle credentials notes"""
    if not env or 'OUTDIR' not in env:
        print("[!] No active session.")
        return
    
    outdir = Path(env["OUTDIR"])
    boxname = env["BOXNAME"]
    
    if 'HOST' in env:
        host_ip = env['HOST']
        notes_path = outdir / f"{boxname}_{host_ip.replace('.', '_')}_notes.txt"
    else:
        notes_path = outdir / f"{boxname}_notes.txt"
    
    notes_creds(notes_path)

def handle_users_note(env, subargs):
    """Handle users notes"""
    if not env or 'OUTDIR' not in env:
        print("[!] No active session.")
        return
    
    outdir = Path(env["OUTDIR"])
    boxname = env["BOXNAME"]
    
    if 'HOST' in env:
        host_ip = env['HOST']
        notes_path = outdir / f"{boxname}_{host_ip.replace('.', '_')}_notes.txt"
    else:
        notes_path = outdir / f"{boxname}_notes.txt"
    
    notes_users(notes_path)

def handle_open_notes(env, subargs):
    """Handle opening notes file"""
    if not env or 'OUTDIR' not in env:
        print("[!] No active session.")
        return
    
    outdir = Path(env["OUTDIR"])
    boxname = env["BOXNAME"]
    open_notes(boxname, outdir)

def handle_view_file(env, subargs):
    """Handle viewing files"""
    if not env:
        print("[!] No active session.")
        return
    
    view_file(env, subargs)

def handle_target_operations(env, subargs):
    """Handle target operations"""
    # This is handled in main jasmin.py
    return env

def handle_use_command(env, subargs):
    """Handle use command"""
    # This is handled in main jasmin.py  
    return env

def handle_intel_wrapper(env, subargs):
    """Wrapper to handle intel commands with availability check"""
    if INTEL_AVAILABLE:
        return handle_intel_command(env, ["intel"] + subargs)
    else:
        print("[!] Intelligence system not available")
        print("[!] Install intelligence modules and run 'python intelligence_main.py' to build the database")
        print("[!] Or check that intelligence_db/ directory exists in your JASMIN folder")
        return env

def handle_ad_wrapper(env, subargs):
    """Wrapper to handle AD commands with availability check"""
    if not AD_AVAILABLE:
        print("[!] Active Directory enumeration not available")
        print("[!] Check that ad_enum.py is in your JASMIN directory")
        return env
    
    # Route to specific AD functions based on subcommand
    if not subargs:
        print("[!] Usage: ad <enum|users|bloodhound|kerberos|policy|creds|help>")
        return env
    
    subcmd = subargs[0].lower()
    remaining_args = subargs[1:]
    
    if subcmd == "enum":
        return ad_enum_full(env, remaining_args)
    elif subcmd == "users":
        return ad_enum_users(env, remaining_args)
    elif subcmd == "bloodhound":
        return ad_bloodhound(env, remaining_args)
    elif subcmd == "kerberos":
        return ad_kerberos(env, remaining_args)
    elif subcmd == "policy":
        return ad_policy(env, remaining_args)
    elif subcmd == "creds":
        return ad_creds(env, remaining_args)
    elif subcmd == "help":
        return ad_help(env, remaining_args)
    else:
        print(f"[!] Unknown AD command: {subcmd}")
        print("[!] Available: enum, users, bloodhound, kerberos, policy, help")
    
    return env

# ENHANCED COMMANDS DICTIONARY WITH PAYLOAD INTEGRATION
COMMANDS = {
    ("fs",): lambda env, sub: run_full_scan(
        env["IP"], env["BOXNAME"], Path(env["OUTDIR"]), Path(env["LOGFILE"]),
        internal="--internal" in sub, intel="--intel" in sub
    ) if env else print("[!] No active session."),
    
    ("fullscan",): lambda env, sub: run_full_scan(
        env["IP"], env["BOXNAME"], Path(env["OUTDIR"]), Path(env["LOGFILE"]),
        internal="--internal" in sub, intel="--intel" in sub
    ) if env else print("[!] No active session."),
    
    ("tcp",): lambda env, sub: run_tcp_scan(
        env["IP"], env["BOXNAME"], Path(env["OUTDIR"]), Path(env["LOGFILE"]),
        internal="--internal" in sub, intel="--intel" in sub
    ) if env else print("[!] No active session."),
    
    ("udp", "progress"): lambda env, sub: check_udp_progress(
        env["BOXNAME"], Path(env["OUTDIR"])
    ) if env else print("[!] No active session."),
    
    ("web",): lambda env, sub: web_enum(
    env["IP"], env["BOXNAME"], Path(env["OUTDIR"]), Path(env["LOGFILE"]),
    port=next((arg for arg in sub if arg.isdigit()), None),
    internal="--internal" in sub, 
    intel="--intel" in sub,
    tool="ferox" if any(flag in sub for flag in ["--ferox", "--feroxbuster"]) 
         else "gobuster" if any(flag in sub for flag in ["--gobuster", "--gobust"])
         else "auto",
    protocol="http" if any(flag in sub for flag in ["--http", "http"])
             else "https" if any(flag in sub for flag in ["--https", "https", "--ssl"])
             else None
    ) if env else print("[!] No active session."),

    
    # Add script scan support
    ("ss",): lambda env, sub: run_script_scan(
        env["IP"], env["BOXNAME"], Path(env["OUTDIR"]), Path(env["LOGFILE"]),
        internal="--internal" in sub, intel="--intel" in sub
    ) if env else print("[!] No active session."),
    
    ("script",): lambda env, sub: run_script_scan(
        env["IP"], env["BOXNAME"], Path(env["OUTDIR"]), Path(env["LOGFILE"]),
        internal="--internal" in sub, intel="--intel" in sub
    ) if env else print("[!] No active session."),
    
    # Add hostscan support
    ("hostscan",): lambda env, sub: run_host_discovery_only(
        env["IP"], internal="--internal" in sub
    ) if env else print("[!] No active session."),
    
    # Notes commands
    ("notes", "quick"): handle_quick_note,
    ("notes", "creds"): handle_creds_note,
    ("notes", "user"): handle_users_note,
    ("notes", "open"): handle_open_notes,
    
    # File operations
    ("view",): handle_view_file,
    
    # Target and session management
    ("target",): handle_target_operations,
    ("use",): handle_use_command,
    
    # Intelligence system
    ("intel",): handle_intel_wrapper,
    
    # Active Directory enumeration
    ("ad",): handle_ad_wrapper,
    
    # Upload server
    ("upload",): lambda env, sub: handle_upload_command(env, ["upload"] + sub),
    
    # PAYLOAD MODULE INTEGRATION
    ("payload",): handle_payload_command,
}

def cli_dispatch(actions, subargs, env):
    """Enhanced command dispatcher with payload support"""
    if not actions:
        print("[!] No action specified.")
        return env
    
    # Check if we're in payload mode first
    if PAYLOAD_AVAILABLE:
        handled, new_env = handle_payload_mode_input(env, " ".join(list(actions) + subargs))
        if handled:
            return new_env
    
    # Convert actions to tuple for lookup
    actions_tuple = tuple(sorted(actions))
    
    # Try direct match first
    if actions_tuple in COMMANDS:
        result = COMMANDS[actions_tuple](env, subargs)
        return result if result is not None else env
    
    # Try partial matches
    for key, handler in COMMANDS.items():
        if all(k in actions for k in key):
            result = handler(env, subargs)
            return result if result is not None else env
    
    # Handle single action cases
    single_action = list(actions)[0] if len(actions) == 1 else None
    
    if single_action == "target":
        return handle_target_operations(env, subargs)
    elif single_action == "use":
        return handle_use_command(env, subargs)
    elif single_action == "intel":
        return handle_intel_wrapper(env, subargs)
    elif single_action == "ad":
        return handle_ad_wrapper(env, subargs)
    elif single_action == "upload":
        handle_upload_command(env, ["upload"] + subargs)
        return env
    elif single_action == "payload":
        return handle_payload_command(env, subargs)
    
    if "gui" in actions:
        if GUI_INTEGRATION_AVAILABLE:
            return handle_gui_command(env, subargs)
        else:
            print("[!] GUI integration not available")
            return env
    
    print(f"[!] No matching command found for: {', '.join(actions)}")
    return env

def parse_jarvis_command(cmd):
    """Parse JASMIN command line arguments"""
    # Split command preserving quoted arguments
    import shlex
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        # Fallback to simple split if shlex fails
        tokens = cmd.split()
    
    if not tokens:
        return {"actions": set(), "subargs": [], "box": None, "ip": None}
    
    actions = set()
    subargs = []
    box = None
    ip = None
    
    i = 0
    while i < len(tokens):
        token = tokens[i].lower()
        
        # Special handling for target command
        if token == "target" and i + 1 < len(tokens):
            actions.add("target")
            subargs.extend(tokens[i+1:])
            break
        # Special handling for payload command
        elif token == "payload":
            actions.add("payload")
            subargs.extend(tokens[i+1:])
            break
        # Other commands
        elif token in ["fs", "fullscan", "tcp", "udp", "web", "ss", "script", 
               "hostscan", "notes", "view", "use", "intel", "ad", "upload", "gui"]:
            actions.add(token)
        else:
            subargs.append(tokens[i])
        
        i += 1
    
    return {
        "actions": actions,
        "subargs": subargs,
        "box": box,
        "ip": ip
    }

def main():
    """Enhanced main function with payload integration"""
    if len(sys.argv) > 1:
        # Parse command line
        cmd = " ".join(sys.argv[1:])
        parsed = parse_jarvis_command(cmd)
        
        if "target" in parsed["actions"]:
            # Handle target command through main jasmin.py
            print("[*] Target operations should be run through main jasmin.py")
            return
            
        # Load current session
        env = None
        try:
            env = get_current_session_env()
        except Exception as e:
            print(f"[!] Could not load session: {e}")
            env = None
            
        cli_dispatch(parsed["actions"], parsed["subargs"], env)
        return
    
    print("[*] JASMIN CLI - Enhanced with Payload Module")
    print("[*] Available commands: fs, tcp, web, payload, upload, intel, ad, notes")
    print("[*] Use 'python jasmin.py' for full interactive session")

if __name__ == "__main__":
    main()