#state.py

import json 
from pathlib import Path
#for timestamping command logs
from datetime import datetime

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
        "last_updated" : datetime.now().isoformat() 
        
    }
    
    state_path = outdir / "state.json"
    with open(state_path, "w") as f: 
        json.dump(state, f, indent=2)
    print(f"[+] state.json initialized at {state_path}")
    
def get_state_path(outdir: Path) -> Path: 
    return outdir / "state.json"

def load_state(outdir: Path) -> Path: 
    path = get_state_path(outdir)
    if not path.exists():
        raise FileNotFoundError("state.json not found")
    with open(path) as f: 
        return json.load(f)
    
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
    save_state(outdir)
    
def mark_module_used(outdir: Path, module_name: str): 
    state = load_state(outdir)
    if "modules_used" not in state: 
        state["modules_used"] = []
    if module_name not in state["modules_used"]: 
        state["modules_used"].append(module_name)
    save_state(outdir,state)
        