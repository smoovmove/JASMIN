# sesion.py

from pathlib import Path

#for system interactiom
import sys 

#for timestamping command logs
from datetime import datetime

from notes import default_note_template, update_notes_section, update_field_in_section
from state import create_initial_state_file
from target import (
    set_last_target, set_current_context, get_target_dir, 
    get_host_dir, create_host_entry
)

from ipaddress import ip_network, ip_address

#Create the "Boxes" directory if it doesn't exist yet
jasmin_dir = Path.home() / "Boxes"
jasmin_dir.mkdir(parents=True, exist_ok=True)

def is_ip_range(value: str) -> tuple[bool, bool]: 
    try: 
        if "/" in value: 
            ip_network(value, strict=False)
            return True, True #valid CIDR
        else: 
            ip_address(value)
            return True, False #valid single IP
    except ValueError: 
        return False, False #invalid input

def get_session_file(boxname: str) -> Path: 
    return Path.home() / "Boxes" / boxname / "session.env"

def create_target_session(target_name: str, ip_or_range: str) -> dict:
    """Create a new top-level target session"""
    valid, is_range = is_ip_range(ip_or_range)
    if not valid:
        raise ValueError(f"Invalid IP or CIDR: {ip_or_range}")
    
    outdir = get_target_dir(target_name)
    outdir.mkdir(parents=True, exist_ok=True)
    
    # Create screenshots directory
    screenshots = outdir / "Screenshots"
    screenshots.mkdir(parents=True, exist_ok=True)
    
    # Create notes file
    notes_file = outdir / f"{target_name}_notes.txt"
    if not notes_file.exists():
        notes_file.write_text(default_note_template)
        print(f"[+] Notes file created at {notes_file}")
    
    update_field_in_section(notes_file, "System Info", "IP", ip_or_range)
    
    # Create session files
    logfile = outdir / "commands.log"
    session_file = outdir / "session.env"
    
    with open(session_file, "w") as f:
        f.write(f"BOXNAME={target_name}\n")
        f.write(f"IP={ip_or_range}\n")
        f.write(f"OUTDIR={outdir}\n")
        f.write(f"LOGFILE={logfile}\n")
    
    # Initialize state
    create_initial_state_file(outdir, target_name, ip_or_range)
    
    # Set as current target
    set_last_target(target_name)
    set_current_context(target_name)
    
    print(f"[+] New target session created: {target_name} ({ip_or_range})")
    
    return {
        "BOXNAME": target_name,
        "IP": ip_or_range,
        "OUTDIR": str(outdir),
        "LOGFILE": str(logfile)
    }

def create_host_session(target: str, host_ip: str) -> dict:
    """Create a session for a specific host under a target"""
    if not get_target_dir(target).exists():
        raise ValueError(f"Target {target} does not exist")
    
    valid, is_range = is_ip_range(host_ip)
    if not valid or is_range:
        raise ValueError(f"Invalid host IP: {host_ip}")
    
    host_dir = create_host_entry(target, host_ip)
    
    # Create notes file for the host
    notes_file = host_dir / f"{target}_{host_ip.replace('.', '_')}_notes.txt"
    if not notes_file.exists():
        notes_file.write_text(default_note_template)
        update_notes_section(notes_file, "IP:", host_ip)
        print(f"[+] Host notes file created at {notes_file}")
    
    logfile = host_dir / "commands.log"
    
    print(f"[+] Host session created: {target}:{host_ip}")
    
    return {
        "BOXNAME": target,
        "HOST": host_ip,
        "IP": host_ip,
        "OUTDIR": str(host_dir),
        "LOGFILE": str(logfile)
    }

#To hop back into a session after leaving it
def resume_session():
    """Legacy function - interactive session resume"""
    print("Available targets:")
    targets = []
    for d in jasmin_dir.iterdir():
        if d.is_dir():
            targets.append(d.name)
            print(f"- {d.name}")
    
    if not targets:
        print("[!] No targets found.")
        return None
    
    boxname = input("Enter target name to resume session: ").strip()
    return resume_target_session(boxname)

def resume_target_session(target_name: str) -> dict:
    """Resume a target-level session"""
    session_file = get_target_dir(target_name) / "session.env"
    
    if not session_file.exists():
        raise FileNotFoundError(f"No session found for target: {target_name}")
    
    env = {}
    with open(session_file) as f:
        for line in f:
            if '=' in line:
                key, val = line.strip().split("=", 1)
                env[key] = val
    
    # Ensure notes file exists
    outdir = Path(env["OUTDIR"])
    notes_file = outdir / f"{target_name}_notes.txt"
    if not notes_file.exists():
        notes_file.write_text(default_note_template)
        print(f"[+] Notes file was missing - created new one at {notes_file}")
    
    set_last_target(target_name)
    set_current_context(target_name)
    
    print(f"[+] Resumed target session: {target_name} ({env.get('IP', 'unknown')})")
    return env

def resume_host_session(target: str, host_ip: str) -> dict:
    """Resume a host-specific session"""
    host_dir = get_host_dir(target, host_ip)
    session_file = host_dir / "session.env"
    
    if not session_file.exists():
        # Create the host session if it doesn't exist
        return create_host_session(target, host_ip)
    
    env = {}
    with open(session_file) as f:
        for line in f:
            if '=' in line:
                key, val = line.strip().split("=", 1)
                env[key] = val
    
    # Ensure notes file exists
    notes_file = host_dir / f"{target}_{host_ip.replace('.', '_')}_notes.txt"
    if not notes_file.exists():
        notes_file.write_text(default_note_template)
        update_notes_section(notes_file, "IP:", host_ip)
        print(f"[+] Host notes file was missing - created new one at {notes_file}")
    
    set_current_context(target, host_ip)
    
    print(f"[+] Resumed host session: {target}:{host_ip}")
    return env

# Legacy function for backward compatibility
def new_session():
    """Interactive new session creation"""
    while True: 
        ip = input("Target IP or CIDR: ").strip()
        valid, is_range = is_ip_range(ip)
        if valid:
            break
        else: 
            print("[!] Invalid IP address or CIDR. Try again.")
    
    boxname = input("Target name: ").strip()
    return create_target_session(boxname, ip)

def list_all_targets():
    """List all available targets and their hosts"""
    from target import list_targets, list_hosts
    
    print("[*] Available targets:")
    targets = list_targets()
    
    if not targets:
        print("  No targets found.")
        return
    
    for target in targets:
        print(f" - {target}")
        hosts = list_hosts(target)
        if hosts:
            for i, (host_ip, _) in enumerate(hosts, 1):
                print(f"   [{i}] {host_ip}")
        else:
            print("   (no hosts discovered)")

def get_current_session_env():
    """Get the environment for the current context"""
    from target import get_current_context, get_session_env
    
    target, host = get_current_context()
    if not target:
        return None
    
    try:
        return get_session_env(target, host)
    except FileNotFoundError:
        return None