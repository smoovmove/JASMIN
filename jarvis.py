#!/usr/bin/env python3

#for system interactiom
import os 
import sys 

#clean way to handle file paths
from pathlib import Path 

#for timestamping command logs
from datetime import datetime

#all of the created functions called here in the main function
from session import prompt_session, resume_session, new_session, get_session_file
from scans import run_full_scan, check_udp_progress, run_script_scan, web_enum, run_tcp_scan
from notes import open_notes, notes_quick, notes_creds, notes_users
from cli import parse_fuzzy_args, new_session_cli, resume_session_cli, cli_dispatch
from target import get_last_target, get_target_path, set_last_target
from pretty import view_file

import shutil 
import subprocess

sys.path.append(str(Path(__file__).parent.resolve()))

def check_and_install_deps():

    deps_marker = Path.home() / ".jarvis_deps_checked"

    if deps_marker.exists():
        return
    
    tools = ["nmap", "gobuster", "feroxbuster", "curl", "python3"]
    missing = [t for t in tools if not shutil.which(t)]
    
    if missing: 
        print(f"[!] Misisng required tools: {', '.join(missing)}")
        script = Path("install_deps.sh")
        if not script.exists():
            print("[!] install_deps.sh not found in current directory.")
            sys.exit(1)
        print("[*] Running install_deps.sh to set up environment...")
        subprocess.run(["chmod", "+x", "install_deps.sh"], check=True)
        subprocess.run(["bash", "install_deps.sh"], check=True)

    deps_marker.touch()
    print("[+] Dependencies verified. Skipping future checks unless you delete ~/.jarvis_deps_checked.")

def jarvis_repl(env):
    print("[+] Starting jarvis session. Type 'help' to see a list of available commands")

    while True: 

        try: 
            prompt = f"\033[94m[{env['BOXNAME']}]\033[0m >> " if env and 'BOXNAME' in env else ">> " 
            cmd = input(prompt).strip()
            timestamp = datetime.now().strftime("%F %T")
            
            with open(env["LOGFILE"], "a") as f: 
                f.write(f"[{timestamp}] {cmd}\n")
            
            if cmd in ["full scan", "fullscan", "fs"]:
                run_full_scan(env["IP"], env["BOXNAME"], Path(env["OUTDIR"]), Path(env["LOGFILE"]))
                
            if cmd in ["tcp scan", "tcp"]:
                run_tcp_scan(env["IP"], env["BOXNAME"], Path(env["OUTDIR"]), Path(env["LOGFILE"]))

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
            elif cmd.startswith("target"):
                tokens = cmd.split()
                if len(tokens) >= 2:
                    subcmd = tokens[1]

                    if subcmd == "set" and len(tokens) == 3:
                        box = tokens[2]
                        session_file = get_session_file(box)
                        if session_file.exists():
                            env = resume_session_cli(box)
                            set_last_target(box)
                            print(f"[+] Switched to target: {box}")
                        else:
                            print(f"[!] No session found for '{box}'.")

                    elif subcmd == "new":
                        env = new_session()
                        set_last_target(env["BOXNAME"])
                        print(f"[+] Created and switched to new target: {env['BOXNAME']}")

                    elif subcmd == "list":
                        print("[*] Available targets in ~/Boxes/:")
                        for d in (Path.home() / "Boxes").iterdir():
                            if d.is_dir():
                                print(f" - {d.name}")

                    elif subcmd == "show":
                        current = get_last_target()
                        if current:
                            print(f"[+] Current target: {current}")
                        else:
                            print("[!] No target currently set.")

                    else:
                        print("[!] Unknown target command. Use: set, new, list, or show.")
                else:
                    print("[!] Incomplete target command. Try: target set <box>")
            
            elif cmd.startswith("view"):
                tokens = cmd.split()
                view_file(env, tokens[1:])
            
            elif cmd in ["help"]: 
                print("""Available commands:

  fs / full scan            - Run full TCP scan + service + UDP
  tcp / tcp scan            - Run TCP scan only
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
                print(f"[*] Acknoweldged. Closing session for {env['BOXNAME']}...")
                break
            else: 
                print("Unknown command. Type 'help' for a list of avaialble commands.")
        except KeyboardInterrupt: 
            print(f"\n[*] Ctrl+C detected. Very well, session for {env['BOXNAME']} closed.")
            sys.exit(0)

def main(): 
    check_and_install_deps()
    args = sys.argv[1:]
    parsed = parse_fuzzy_args(args)
    env = None
    
    if args:
        if parsed["box"]:
            # ✅ Handle case where box is explicitly provided
            box_path = Path.home() / "Boxes" / parsed["box"]
            session_file = box_path / "session.env"

            if not session_file.exists() and "new" not in parsed["actions"]:
                confirm = input(f"[?] Detected new box name: '{parsed['box']}'. Start a new session? (y/n): ").strip().lower()
                if confirm != "y":
                    print("[!] Aborted.")
                    return
                ip = parsed["ip"] or input("[?] Enter IP for new session: ").strip()
                env = new_session_cli(parsed["box"], ip)
                cli_dispatch(parsed["actions"], parsed["subargs"], env)
                return

            env = resume_session_cli(parsed["box"])
            cli_dispatch(parsed["actions"], parsed["subargs"], env)
            return

        elif not parsed["box"]:
            # ✅ Fallback: no box, try last known target
            last_target = get_last_target()
            if last_target:
                print(f"[*] No box specified. Using last active target: {last_target}")
                session_file = get_session_file(last_target)
                if session_file.exists():
                    env = resume_session_cli(last_target)
                    set_last_target(last_target)
                    cli_dispatch(parsed["actions"], parsed["subargs"], env)
                    return
                else:
                    print(f"[!] Could not find session file for {last_target}.")
                    print("[!] Run `target set <box>` or `target new` to fix.")
                    return
            else:
                print("[!] No box name provided and no active target found.")
                print("[!] Use: `jarvis <boxname> <command>` or run `target set <box>` first.")
                return

    # fallback for zero-arg REPL
    
    if not args: 
        last_target = get_last_target()
        if last_target:
            session_file = get_session_file(last_target)
            if session_file.exists():
                print(f"[*] Resuming sessio for last target: {last_target}")
                env = resume_session_cli(last_target)
                jarvis_repl(env)
                return
            else: 
                print(f"[!] .jarvis_last_target points to '{last_target}', but no session.env found.")
      
        print("[!] No active target found. Use 'target set <box>' or 'target new' to begin")
        env = None
        
        while not env: 
            cmd = input(">> ").strip()
                           
            if cmd.startswith("target"):
                tokens = cmd.split()
                if len(tokens) >= 2: 
                    subcmd = tokens[1]
                    
                    if subcmd == "set" and len(tokens) == 3: 
                        box = tokens [2]
                        session_file = get_session_file(box)
                        if session_file.exists():
                            env = resume_session_cli(box)
                            set_last_target(box)
                            print(f"[+] Switched to target: {box}")
                        else:
                            print(f"[!] No session found for '{box}'.")
                            
                    elif subcmd == "new":
                        env = new_session()
                        set_last_target(env["BOXNAME"])
                        print(f"[+] Created and switched to new target: {env['BOXNAME']}")
                        
                    elif subcmd == "list":
                        print("[*] Available targets in ~/Boxes/:")
                        for d in (Path.home() / "Boxes").iterdir():
                            if d.is_dir():
                                print(f" - {d.name}")
                                
                    elif subcmd == "show":
                        current = get_last_target()
                        if current: 
                            print(f"[+] Current target: {current}")
                        else:
                            print("[!] No target currently set.")

                    else:
                        print("[!] Unknown target command. Use: set, new, list, or show.")
                else:
                    print("[!] Incomplete target command. Try: target set <box>")
            
            elif cmd in {"exit", "quit", "q"}:
                print("Very well. Halting system operations.")
                sys.exit(0)
                
            else: 
                print("[!] Invalid command. Use 'target set <box>' or 'target new'.") 

    jarvis_repl(env)

if __name__ == "__main__":
    main()

