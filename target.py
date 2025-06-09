# target.py

from pathlib import Path 

def get_jarvis_dir() -> Path: 
    path = Path.home() / ".jarvis"
    path.mkdir(parents = True, exist_ok= True)
    return path

def get_jarvis_file(name: str) -> Path: 
    return get_jarvis_dir() / name

def get_target_path() -> Path: 
    return get_jarvis_file("last_target")

def set_last_target(boxname: str):
    path = get_jarvis_file("last_target")
    path.write_text(boxname.strip())

def get_last_target() -> str | None: 
    
    path = get_jarvis_file("last_target")
    
    if path.exists():
        return path.read_text().strip()
    return None

