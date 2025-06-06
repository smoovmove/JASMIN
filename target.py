# target.py

from pathlib import Path 


def get_target_path() -> Path: 
    return Path.home() / ".jarvis_last_target"

def set_last_target(boxname: str):
    with open(get_target_path(), "w") as f: 
        f.write(boxname.strip())

def get_last_target() -> str | None: 
    
    path = get_target_path()
    
    if path.exists():
        return path.read_text().strip()
    return None