#state.py

import json 
from pathlib import Path
#for timestamping command logs
from datetime import datetime
from parser import extract_os_from_nmap, extract_nmap_services, extract_web_tech

def create_initial_state_file(outdir: Path, boxname: str, ip:str):
    state = {
        "hostname" : "", 
        "os" : "",
        "ports" : [],
        "services" : [], 
        "web_tech" : "", 
        "modules_used" : [], 
        "credentials" : [], 
        "notes" : [],
        "ip_variables": {}, 
        "last_updated" : datetime.now().isoformat() 
        
    }
    
    state_path = outdir / "state.json"
    with open(state_path, "w") as f: 
        json.dump(state, f, indent=2)
    print(f"[+] state.json initialized at {state_path}")
    
def get_state_path(outdir: Path) -> dict: 
    return outdir / "state.json"

def load_state(outdir: Path) -> Path: 
    
    path = get_state_path(outdir)
    if not path.exists():
        print(f"[!] state.json not found at {path}, creating file now...")
        boxname = outdir.name
        session_file = outdir / "session.env"

        if not session_file.exists():
            print("[!] session.env not found either. Cannot recover automatically.")
            raise FileNotFoundError("Missing session.emv - unable to initialize state.json.")
        
        ip = None
        
        with open(session_file) as f: 
            for line in f: 
                if line.startswith("IP="):
                    ip = line.strip().split("=")[1]
                    break

        if not ip: 
            raise ValueError("[!] Could not extract IP from session.env")
        
        #1. create blank state
        create_initial_state_file(outdir, boxname, ip)

        #2. try to populate from existing files
        state = {
        "hostname": "",
        "os": "",
        "ports": [],
        "services": [],
        "web_tech": "",
        "modules_used": [],
        "credentials": [],
        "notes": [],
        "last_updated": datetime.now().isoformat()
    }
        #ports from tcp 
        tcp_file = outdir / f"{boxname}.tcp_scan.txt"
        if tcp_file.exists():
            open_ports = []
            for line in tcp_file.read_text().splitlines():
                if line and line[0].isdigit():
                    port = line.split("/")[0]
                    open_ports.append(port)
            update_state_field(outdir, "ports", open_ports)
            mark_module_used(outdir, "tcp_scan")

        #populate from service scan 
        service_file = outdir / f"{boxname}.service_scan.txt"
        if service_file.exists():
            os_info = extract_os_from_nmap(service_file)
            update_state_field(outdir, "os", os_info)
            
            raw_services = extract_nmap_services(service_file).splitlines()
            for s in raw_services: 
                append_to_state_list(outdir, "services", {"version": s})

        mark_module_used(outdir, "service_scan")

        #populate from web_headers
        header_file = list(outdir.glob("web_headers_*.txt"))

        if header_file: 
            latest = max(header_file, key=lambda f: f.stat().st_mtime)
            header_text = latest.read_text()
            web_tech = extract_web_tech(header_text)

            if web_tech: 
                update_state_field(outdir, "web_tech", web_tech)
                mark_module_used(outdir, "web_enum")

    print(f"[+] Reconstructed state.json at {path}")

    with open(path) as f: 
        return json.load(f)

def update_discovered_hosts(boxname, outdir: Path, live_hosts: list): 
    hosts_dir = outdir / "Hosts"
    hosts_dir.mkdir(exist_ok=True, parents=True)

    for ip in live_hosts: 
        label = f"{boxname}_{ip.replace('.', '_')}"
        host_path = hosts_dir / label
        host_path.mkdir(exist_ok=True, parents=True)
        create_initial_state_file(host_path, label, ip)

    
def save_state(outdir: Path, state: dict) -> Path:
    path = get_state_path(outdir)
    state["last_updated"] = datetime.now().isoformat()
    with open(path, "w") as f: 
        json.dump(state, f, indent=2)
        
def update_state_field(outdir: Path, field:str, value):
    state = load_state(outdir)
    state[field] = value
    save_state(outdir, state)
    
def append_to_state_list(outdir: Path, field: str, item: dict):
    state = load_state(outdir)
    if field not in state: 
        state[field] = []
    state[field].append(item)
    save_state(outdir, state) 
    
def mark_module_used(outdir: Path, module_name: str): 
    state = load_state(outdir)
    if "modules_used" not in state: 
        state["modules_used"] = []
    if module_name not in state["modules_used"]: 
        state["modules_used"].append(module_name)
    save_state(outdir,state)

def list_discovered_hosts(boxname): 
    hosts_dir = Path.home() / "Boxes" / boxname / "Hosts"
    if not hosts_dir.exists(): 
        print("[!] No discovered hosts found.")
        return []
    
    hosts = sorted([d.name for d in hosts_dir.iterdir() if d.is_dir()])
    for idx, host in enumerate(hosts): 
        ip = host.replace(f"{boxname}_", "").replace("_", ".")
        print(f"[{idx}] {ip}")

    return hosts

def resolve_host_selection(boxname, user_input): 
    hosts = list_discovered_hosts(boxname)

    if not hosts: 
        return None
    if user_input.isdigit(): 
        idx = int(user_input)
        if 0 <= idx < len(hosts): 
            return hosts[idx]
        
    label = f"{boxname}_{user_input.replace('.', '_')}"
    if label in hosts:
        return label

    print("[!] Invalid host selection.")
    return None

def update_ip_variables(outdir: Path, ip_variables: dict):
    """Update IP variables in state.json"""
    state_path = get_state_path(outdir)
    
    if state_path.exists():
        with open(state_path, 'r') as f:
            state = json.load(f)
    else:
        return False
    
    state['ip_variables'] = ip_variables
    state['last_updated'] = datetime.now().isoformat()
    
    with open(state_path, 'w') as f:
        json.dump(state, f, indent=2)
    
    return True