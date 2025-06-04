#!/usr/bin/env python3

#for system interactiom
import os 
import sys 

#clean way to handle file paths
from pathlib import Path 

#for timestamping command logs
from datetime import datetime

from session import prompt_session, resume_session, new_session

from scans import run_full_scan, check_udp_progress, run_script_scan, web_enum

from notes import open_notes, notes_quick, notes_creds, notes_users

sys.path.append(str(Path(__file__).parent.resolve()))



def cockpit_repl(env):
    print("[+] Starting cockpit session. Type 'help' to see a list of available commands")

    while True: 

        try: 
            cmd = input(">> ").strip()
            timestamp = datetime.now().strftime("%F %T")
            
            with open(env["LOGFILE"], "a") as f: 
                f.write(f"[{timestamp}] {cmd}\n")
            
            if cmd in ["full scan", "fullscan", "fs"]:
                run_full_scan(env["IP"], env["BOXNAME"], Path(env["OUTDIR"]), Path(env["LOGFILE"]))

            elif cmd in ["service", "service scan", "ss"]:
                run_script_scan(env["IP"], env["BOXNAME"], Path(env["OUTDIR"]), Path(env["LOGFILE"]))
            
            elif cmd in ["udp progress", "UDP progress", "UDP Progress"]: 
                check_udp_progress(env["BOXNAME"], Path(env["OUTDIR"]))

            elif cmd in ["web", "we", "web enum"]:
                web_enum(env["IP"], env["BOXNAME"], Path(env["OUTDIR"]), Path(env["LOGFILE"]))
            
            elif cmd.startswith("notes"): 
                tokens = cmd.split()

                notes_path = Path(env['OUTDIR']) / f"{env['BOXNAME']}_notes.txt"
                
                if len(tokens) == 1: 
                    open_notes(env["BOXNAME"], Path(env["OUTDIR"]))
                elif tokens[1] == "quick":
                    notes_quick(notes_path)
                elif tokens[1] == "creds": 
                    notes_creds(notes_path)
                elif tokens[1] == "user": 
                    notes_users(notes_path)
            
            elif cmd in ["help"]: 
                print("""Available commands:

  fs / full scan            - Run full TCP scan + service + UDP
  ss / script scan          - Run targeted script scan
  we / web enum             - Run web enumeration scan
  udp progress              - Show progress of background UDP scan

  notes                     - Open the notes file in your editor
  notes quick               - Add a quick note (multi-line supported)
  notes creds               - Log discovered credentials
  notes user                - Log discovered usernames

  help                      - Show this help menu
  exit / quit               - Exit the session
""")
            
            elif cmd in ["exit", "quit", "done", "finish", "q"]:
                print(f"[*] Session for {env['BOXNAME']} closed")
                break
            else: 
                print("Unknown command. Type 'help' for a list of avaialble commands.")
        except KeyboardInterrupt: 
            print(f"\n[*] Ctrl+C detected. Session for {env['BOXNAME']} closed.")
            sys.exit(0)

def main(): 
    choice = prompt_session()
    if choice == "1": 
        env = new_session()
    if choice == "2": 
        env = resume_session()
    if choice == "3": 
        sys.exit(0)
    #else:
        #print("Invalid option.")
        #return

    cockpit_repl(env)

if __name__ == "__main__":
    main()

