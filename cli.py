# cli.py

from notes import open_notes, notes_creds, notes_users, notes_quick, append_to_notes_section
from scans import run_full_scan, run_tcp_scan, run_service_scan, run_script_scan, run_udp_scan, check_udp_progress, web_enum
from state import create_initial_state_file
from target import set_last_target
from pretty import view_file
from pathlib import Path
from datetime import datetime
import sys
import re

def new_session_cli(boxname, ip):
    print(f"[*] Creating new session: {boxname} ({ip})")
    outdir = Path.home() / "Boxes" / boxname
    outdir.mkdir(parents = True, exist_ok = True)
    
    notes_file = outdir / f"{boxname}_notes.txt"
    if not notes_file.exists():
        from notes import default_note_template
        notes_file.write_text(default_note_template)
        
    logfile = outdir / "commands.log" 
    session_file = outdir / "session.env"

    with open(session_file, "w") as f: 
        f.write(f"BOXNAME={boxname}\n")
        f.write(f"IP={ip}\n")
        f.write(f"OUTDIR={outdir}\n")
        f.write(f"LOGFILE={logfile}")

    print(f"[+] New session started for {boxname} ({ip})")
    create_initial_state_file(outdir, boxname, ip)
    set_last_target(boxname)
    
    
    return{
        "BOXNAME": boxname, 
        "IP": ip,
        "OUTDIR": str(outdir),
        "LOGFILE": str(logfile)
    }
    
def resume_session_cli(boxname):
    session_file = Path.home() / "Boxes" / boxname / "session.env"
    
    if not session_file.exists():
        print(f"[!] No session found for {boxname}")
        sys.exit(1)
        
    env = {}
    with open(session_file) as f:
        for line in f:
            key, val = line.strip().split("=", 1)
            env[key] = val
            
    set_last_target(boxname)

    return env

def parse_fuzzy_args(args):
    known_actions = {"new", "resume", "notes", "quick", "user", "creds", "fs", "fullscan", "script", "ss", "tcp", "udp", "progress", "web", "open", "view"}
    ip_regex = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

    actions = set()
    ip = None
    box = None
    subargs = []

    action_found = False

    for arg in args:
        lower = arg.lower()
        if lower in known_actions and not action_found:
            actions.add(lower)
            action_found = True
        elif ip_regex.match(arg):
            ip = arg
        elif not box:
            box = arg
        else:
            subargs.append(arg)

    return {
        "box": box,
        "ip": ip,
        "actions": actions,
        "subargs": subargs
    }
    
def handle_quick_note(env, subargs):
    notes_path = Path(env["OUTDIR"]) / f"{env['BOXNAME']}_notes.txt"
    if subargs:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        note = f"- [{timestamp}] {' '.join(subargs)}"
        append_to_notes_section(notes_path, "[Quick Notes]:", note)
        print(f"[+] Added quick note: {' '.join(subargs)}")
    else:
        notes_quick(notes_path)

def handle_creds_note(env, subargs):
    notes_creds(Path(env["OUTDIR"]) / f"{env['BOXNAME']}_notes.txt")

def handle_users_note(env, subargs):
    notes_users(Path(env["OUTDIR"]) / f"{env['BOXNAME']}_notes.txt")

def handle_open_notes(env, subargs):
    open_notes(env["BOXNAME"], Path(env["OUTDIR"]))

def handle_view_file(env, subgargs):
    view_file(env, subgargs)


COMMANDS = {
    frozenset(["fs"]): lambda env, sub: run_full_scan(env["IP"], env["BOXNAME"], Path(env["OUTDIR"]), Path(env["LOGFILE"])),
    frozenset(["fullscan"]): lambda env, sub: run_full_scan(env["IP"], env["BOXNAME"], Path(env["OUTDIR"]), Path(env["LOGFILE"])),
    frozenset(["ss"]): lambda env, sub: run_script_scan(env["IP"], env["BOXNAME"], Path(env["OUTDIR"]), Path(env["LOGFILE"])),
    frozenset(["script"]): lambda env, sub: run_script_scan(env["IP"], env["BOXNAME"], Path(env["OUTDIR"]), Path(env["LOGFILE"])),
    frozenset(["tcp"]): lambda env, sub: run_tcp_scan(env["IP"], env["BOXNAME"], Path(env["OUTDIR"]), Path(env["LOGFILE"])),
    frozenset(["udp", "progress"]): lambda env, sub: check_udp_progress(env["BOXNAME"], Path(env["OUTDIR"])),

    frozenset(["web"]): lambda env, sub: web_enum(env["IP"], env["BOXNAME"], Path(env["OUTDIR"]), Path(env["LOGFILE"])),

    frozenset(["notes", "quick"]): handle_quick_note,
    frozenset(["notes", "creds"]): handle_creds_note,
    frozenset(["notes", "user"]): handle_users_note,
    frozenset(["notes", "open"]): handle_open_notes,    

    frozenset(["view"]): handle_view_file
}

def cli_dispatch(actions, subargs, env):

    for key_combo, handler in COMMANDS.items():
        if key_combo == actions:
            handler(env, subargs)
            return
        
    for key_combo, handler in COMMANDS.items():
        if key_combo.issubset(actions):
            handler(env, subargs)
            return
    print("[!] No matching CLI command found")
    
