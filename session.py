# sesion.py

from pathlib import Path
import subprocess
import signal

#for system interactiom
import os 
import sys 

#for timestamping command logs
from datetime import datetime

from notes import default_note_template, update_notes_section
from state import create_initial_state_file
from target import set_last_target

import json 

import re

#Create the "Boxes" directory if it doesn't exist yet
jarvis_dir = Path.home() / "Boxes"
jarvis_dir.mkdir(parents=True, exist_ok=True)

def get_session_file(boxname: str) -> Path: 
    return Path.home() / "Boxes" / boxname / "session.env"

#Prompt a choice for the type of session 
def prompt_session(): 
    print("Welcome to the jarvis. Are you resuming or starting a new session")
    print("1) Starting a new box")
    print("2) Resuming an existing box")
    print("3) Exit" )
    choice = input("Choice: ").strip()

    return choice

#To hop back into a session after leaving it
def resume_session():
    print("Availble boxes:")
    for d in jarvis_dir.iterdir():
        if d.is_dir():
            print(f"- {d.name}")
    
    boxname = input("Enter box name to resume session: ").strip()
    session_file = jarvis_dir / boxname / "session.env"

    if session_file.exists():
        env = {}
        with open(session_file) as f: 
            for line in f: 
                key, val = line.strip().split("=",1)
                env[key] = val 
        
        print(f"[+] Resuming session for {env['BOXNAME']} ({env ['IP']})")

        if "OUTDIR" in env: 
            outdir = Path(env["OUTDIR"])
        
        else: 
            outdir = jarvis_dir / boxname
            env["OUTDIR"] = str (outdir)

        notes_file = outdir / f"{boxname}_notes.txt"
        if not notes_file.exists(): 
            notes_file.write_text(default_note_template)
            print(f"[+] Notes file was missing - created new one at {notes_file}")
        
        set_last_target(boxname)
        
        return env

    else: 
        print(f"[!] No session found for {boxname}")
        sys.exit(0)

#To start a new session which inclides the box and the IP
def new_session():
    while True: 
        ip = input("Target IP: ").strip()
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            break
        else: 
            print("[!] Invalid IP format. Try again.")
    boxname = input("Box name: ").strip()
    outdir = jarvis_dir / boxname
    screenshots = outdir / "Screenshots"
    outdir.mkdir(parents=True, exist_ok=True)
    screenshots.mkdir(parents=True, exist_ok=True)

    notes_file = outdir / f"{boxname}_notes.txt"
    if not notes_file.exists():
        notes_file.write_text(default_note_template)
        print(f"[+] Notes file created at {notes_file}")
    update_notes_section(notes_file, "IP:", ip)

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
