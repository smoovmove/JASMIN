# notes.py

import os 
import subprocess

from pathlib import Path

from datetime import datetime

from state import append_to_state_list

default_note_template = """=========================================================================

[System Info]
OS: 
Hostname: 
IP: 
Web Technology: 
Users:

=========================================================================

[Active Directory]:
Domain: 
Users Enumerated: 
AS-REP Roastable: 
Kerberoastable: 
BloodHound: 
Password Policy:

=========================================================================

[Credentials]:

=========================================================================

[Quick Notes]:

=========================================================================

[NMAP RESULTS]:

=========================================================================

[Web Services Enumeration]:

=========================================================================

Take Away Concepts (for the flat-file reference system):
* 
* 
* 
"""

def open_notes(boxname: str, outdir: Path):
    notes_path = outdir / f"{boxname}_notes.txt"

    editor = os.environ.get("EDITOR", "nano")

    print(f"[*] Opening notes for {boxname} in {editor}... (close the editor to return to JASMIN)")

    try: 
        subprocess.run(
            [editor, str(notes_path)]
        )
    except FileNotFoundError: 
        print(f"[!] Editor {editor} not found.")


#this replaces the entire section in question 
def update_notes_section(notes_path: Path, section_header: str, new_content: str):
    if not notes_path.exists():
        print(f"[!] Notes file not found at {notes_path}")
    
    lines = notes_path.read_text().splitlines(keepends=True)

    updated_lines = []
    inside_target_section = False
    section_found = False

    for idx, line in enumerate(lines):
        stripped_line = line.strip()
        
        if stripped_line == section_header:  
            section_found = True
            inside_target_section = True
            updated_lines.append(line) #keep the header itself
            # Add new content with trailing newlines
            updated_lines.append(new_content.strip() + "\n\n")
            continue

        if inside_target_section and stripped_line.startswith("="): 
            if line.strip().startswith("[") and line.strip() != section_header: 
                #reached the next section
                inside_target_section = False
                updated_lines.append(line)
                continue
            
        if inside_target_section: 
            continue
        
        updated_lines.append(line)

    if not section_found: 
        print(f"[!] Section header '{section_header}' not found in notes file")

    notes_path.write_text("".join(updated_lines))

#this appends to the section in question 
def append_to_notes_section(notes_path: Path, section_header: str, new_content: str):
    if not notes_path.exists():
        print(f"[!] Notes file not found at {notes_path}")
    
    lines = notes_path.read_text().splitlines(keepends=True)

    updated_lines = []
    inside_target_section = False
    section_found = False
    content_appended = False
    temp_selection_content = []

    for i, line in enumerate(lines):

        stripped_line = line.strip()

        #Match the section header exactly
        if stripped_line == section_header: 
            section_found = True 
            inside_target_section = True 
            updated_lines.append(line)
            continue

        #If we are inside the target section
        if inside_target_section and stripped_line.startswith("="): 
            #if we hit the next section
            if not content_appended: 
                updated_lines.append(new_content.strip() + "\n\n")
                content_appended = True
                    
            inside_target_section = False
        
        #add the current line
        updated_lines.append(line)

        #if file ended while still inside target section, append at end
    if inside_target_section and not content_appended: 
        updated_lines.append(new_content.strip() + "\n\n")
        content_appended = True

    if not section_found: 
        print(f"[!] Section header '{section_header}' not found in notes file")

    notes_path.write_text("".join(updated_lines))

def notes_quick(notes_path: Path):
    print("┌" + "─" * 46 + "┐")
    print("│ Write your note. Press ENTER twice to save.  │")
    print("└" + "─" * 46 + "┘")

    lines = []
    while True: 
        line = input("  > ").rstrip()
        if not line: 
            break
        lines.append(line)

    if not lines: 
        print("[-] Empty note. Nothing added.")
        return
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    note = f"- [{timestamp}] {lines[0]}"
    for line in lines[1:]: 
        note += f"\n      {line}"

    append_to_notes_section(notes_path, "[Quick Notes]:", note)
    print("[+] Multi-line note added to [Quick Notes]")
    
    outdir = notes_path.parent
    append_to_state_list(outdir, "notes", {
        "timestamp": timestamp,
        "content": "\n".join(lines)
    })

def notes_creds(notes_path: Path):
    print("┌" + "─" * 46 + "┐")
    print("│ Enter a discovered credential.               │")
    print("└" + "─" * 46 + "┘")

    service = input("  Service (e.g., FTP, SSH): ").strip()
    username = input("  Username: ").strip()
    password = input("  Password: ").strip()

    if not (username and password):
        print("[-] Username and password are required. The credential hasn't been added.")
        return
    
    if service: 
        formatted_cred = f"- {service} → {username}:{password}"
    else: 
        formatted_cred = f"- {username}:{password}"

    append_to_notes_section(notes_path, "[Credentials]:", formatted_cred)
    print(f"[+] Credential added under [Credentials]")
    
    outdir = notes_path.parent
    append_to_state_list(outdir, "credentials", {
        "service": service or "unknown",
        "username": username,
        "password": password
    })

def notes_users(notes_path: Path):
    print("┌" + "─" * 46 + "┐")
    print("│ Enter a discovered username.                 │")
    print("│ Press ENTER twice to save.                   │")
    print("└" + "─" * 46 + "┘")

    users = []
    while True: 
        user = input("  > ").strip()
        if not user: 
            break
        users.append(f"- {user}")

    if not users: 
        print("[-] No users entered.")
        return
    
    append_to_notes_section(notes_path, "Users:", "\n".join(users))
    print(f"[+] {len(users)} user(s) added to Users")

def view_file(env, subargs):
    """View file contents from JASMIN session directory"""
    if not subargs:
        print("[!] Usage: view <filename>")
        return
    
    filename = subargs[0]
    outdir = Path(env["OUTDIR"])
    
    # Try different possible locations for the file
    possible_paths = [
        outdir / filename,  # Direct path in output directory
        outdir / f"{env['BOXNAME']}_{filename}",  # With boxname prefix
        outdir / f"{filename}.txt",  # With .txt extension
        outdir / f"{env['BOXNAME']}_{filename}.txt",  # With prefix and extension
    ]
    
    # Also try common scan file patterns
    if 'HOST' in env:
        host_prefix = env['HOST'].replace('.', '_')
        possible_paths.extend([
            outdir / f"{env['BOXNAME']}_{host_prefix}_{filename}",
            outdir / f"{env['BOXNAME']}_{host_prefix}_{filename}.txt",
        ])
    
    file_path = None
    for path in possible_paths:
        if path.exists():
            file_path = path
            break
    
    if not file_path:
        # List available files to help user
        print(f"[!] File '{filename}' not found. Available files:")
        try:
            for file in sorted(outdir.iterdir()):
                if file.is_file() and not file.name.startswith('.'):
                    print(f"    - {file.name}")
        except Exception as e:
            print(f"[!] Error listing files: {e}")
        return
    
    try:
        print(f"[*] Viewing: {file_path}")
        print("=" * 60)
        
        # Check file size to avoid displaying huge files
        file_size = file_path.stat().st_size
        if file_size > 1024 * 1024:  # 1MB
            print(f"[!] File is large ({file_size // 1024}KB). Display first 50 lines? (y/n): ", end="")
            response = input().strip().lower()
            if response != 'y':
                return
            
            # Display first 50 lines
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f):
                    if i >= 50:
                        print("\n[...] (truncated - file continues)")
                        break
                    print(line.rstrip())
        else:
            # Display entire file
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                print(content)
        
        print("=" * 60)
        
    except Exception as e:
        print(f"[!] Error reading file: {e}")


def update_field_in_section(notes_path: Path, section_name: str, field_name: str, new_value: str):
    """Update a specific field within a section of the notes file"""
    if not notes_path.exists():
        print(f"[!] Notes file not found at {notes_path}")
        return
    
    lines = notes_path.read_text().splitlines(keepends=True)
    updated_lines = []
    inside_target_section = False
    field_updated = False
    
    for line in lines:
        stripped_line = line.strip()
        
        # Check if we're entering the target section
        if stripped_line == f"[{section_name}]":
            inside_target_section = True
            updated_lines.append(line)
            continue
        
        # Check if we're leaving the target section
        if inside_target_section and stripped_line.startswith("[") and stripped_line.endswith("]"):
            if stripped_line != f"[{section_name}]":
                inside_target_section = False
        
        # If we're inside the target section and this line starts with our field
        if inside_target_section and stripped_line.startswith(f"{field_name}:"):
            # Replace this line with the updated value
            updated_lines.append(f"{field_name}: {new_value}\n")
            field_updated = True
            continue
        
        # Keep all other lines as-is
        updated_lines.append(line)
    
    if field_updated:
        notes_path.write_text("".join(updated_lines))
        print(f"[+] Updated {field_name} in [{section_name}] section")
    else:
        print(f"[!] Field '{field_name}' not found in [{section_name}] section")