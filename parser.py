# parser.py

import subprocess
import json
from pathlib import Path

def extract_nmap_services(scan_file: Path) -> str: 
    if not scan_file.exists():
        return "[!] Scan file not found."
    
    extracted = []
    for line in scan_file.read_text().splitlines():
        if line and line[0].isdigit() and ("/tcp" in line or "/udp" in line): 
            parts = line.split()
            if "open" in parts: 
                # Find the index of "open"
                open_index = parts.index("open")

                #reconstruct everything from port/protocol up to the end 
                service_info = " ".join(parts[:open_index + 1]) 
            if len(parts) > open_index + 1:
                service_info += " " + " ".join(parts[open_index + 1]) # adds service and version

            extracted.append(" ".join(parts[:3])) #eg, "135/tcp open msrpc"

    return "\n".join(extracted) if extracted else "[!] No services found."

def extract_os_from_nmap(scan_file: Path) -> str: 
    if not scan_file.exists():
        return "[!] Scan file not found."
    
    lines = scan_file.read_text().splitlines()
    
    #try specific match from service info 
    for line in lines: 
        if line.startswith("Service Info:") and "OS:" in line: 
            try: 
                os_part = line.split("OS:")[1]
                os_value = os_part.split(";")[0].strip()
                return os_value
            except IndexError: 
                continue
    
    #fallback: keyword match
    os_keywords = ["Windows", "Linux", "Ubuntu", "Debian", "CentOS", "FreeBSD", "Unix", "Fedora"]
    for line in scan_file.read_text().splitlines(): 
        for keyword in os_keywords: 
            if keyword.lower() in line.lower():
                return line.strip()
            
    return "[!] No OS found."

def extract_web_tech(header_text: str) -> str: 
    header_lines = []
    for line in header_text.splitlines():
        if line.lower().startswith("server") or line.lower().startswith("x-powered-by:"):
            header_lines.append(line.strip())

    return "\n".join(header_lines) if header_lines else ""