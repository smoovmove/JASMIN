# logger.py

from target import get_jarvis_file

from pathlib import Path 
import subprocess

#for the logger 
from datetime import datetime

#for system interactiom
import os 
import sys 

import shutil

def is_terminator_installed():
    return shutil.which("terminator") is not None

def is_inside_terminator():
    parent = os.environ.get("TERMINTATOR_UUID") or ""
    return bool(parent)

def get_log_path(outdir: Path) -> Path:
    return outdir / "terminator.log"

def start_tmux_logger(boxname: str, outdir: Path):
    logfile = outdir / f"{boxname}_session.log"
    session_name = f"{boxname}"
    
    # Check if session exists; if not, create it
    check = subprocess.run(["tmux", "has-session", "-t", session_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if check.returncode != 0:
        subprocess.run(["tmux", "new-session", "-d", "-s", session_name], check=True)

    # Pipe-pane logging for the default pane
    subprocess.run([
        "tmux", "pipe-pane", "-o", "-t", f"{session_name}:0", f"cat >> {logfile}"
    ], check=True)

    # Attach to the tmux session
    subprocess.run(["tmux", "attach-session", "-t", session_name])

def show_log_hint_once():
    marker = get_jarvis_file("log_hint_shown")
    if not marker.exists():
        print("[💡] Tip: Jasmin works best when run inside a logging terminal (eg. Terminator)")
        print("     Run `log set` to open a logging window.")
        marker.touch()  # Create the marker file to indicate the hint has been shown
