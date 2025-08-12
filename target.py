# target.py

from pathlib import Path 
import json 
from typing import Optional, List, Tuple

def get_jarvis_dir() -> Path: 
    path = Path.home() / ".jasmin"
    path.mkdir(parents = True, exist_ok= True)
    return path

def get_jarvis_file(name: str) -> Path: 
    return get_jarvis_dir() / name

def get_target_path() -> Path: 
    return get_jarvis_file("last_target")

def get_context_path() -> Path: 
    """Stores the current context (target + optional host)"""
    return get_jarvis_file("current_context")

def set_last_target(boxname: str):
    """Set the last active top-level target"""
    path = get_jarvis_file("last_target")
    path.write_text(boxname.strip())

def get_last_target() -> Optional[str]: 
    """Get the last active top-level target"""
    path = get_jarvis_file("last_target")
    if path.exists():
        return path.read_text().strip()
    return None 

def set_current_context(target: str, host: Optional[str] = None): 
    """Set current context (target + optional host)"""
    context = {"target": target, "host": host}
    path = get_context_path()
    path.write_text(json.dumps(context))

def get_current_context() -> Tuple[Optional[str], Optional[str]]:
    """Get current context as (target, host)"""
    path = get_context_path()
    if path.exists():
        try: 
            context = json.loads(path.read_text())
            return context.get("target"), context.get("host")
        except (json.JSONDecodeError, KeyError): 
            pass
    return None, None

def get_target_dir(target: str) -> Path: 
    """Get the directory for a top-level target"""
    return Path.home() / "Boxes" / target

def get_hosts_dir(target: str) -> Path: 
    """Get the hosts directory for a target"""
    return get_target_dir(target) / "Hosts"

def get_host_dir(target: str, host_ip:str) -> Path: 
    """ Get the directory for a specific host under a target"""
    host_label = host_ip.replace(".", "_")
    return get_hosts_dir(target) / host_label

def list_targets() -> List[str]: 
    """List all top-level targets"""
    boxes_dir = Path.home() / "Boxes"
    if not boxes_dir.exists():
        return []
    
    targets = []
    for item in boxes_dir.iterdir():
        if item.is_dir():
            targets.append(item.name)
    return sorted(targets)

def list_hosts(target: str) -> List[Tuple[str, str]]:
    """List all discovered hosts for a target. Returns [(ip, label), ...]"""
    hosts_dir = get_hosts_dir(target)
    if not hosts_dir.exists():
        return []
    
    hosts = []
    for item in hosts_dir.iterdir():
        if item.is_dir():
            # Convert label back to IP
            ip = item.name.replace("_", ".")
            hosts.append((ip, item.name))
    
    # Sort by IP
    try:
        hosts.sort(key=lambda x: tuple(map(int, x[0].split('.'))))
    except ValueError:
        hosts.sort()  # Fallback to string sort
    
    return hosts

def target_exists(target: str) -> bool:
    """Check if a target exists"""
    return get_target_dir(target).exists()

def host_exists(target: str, host_ip: str) -> bool:
    """Check if a host exists under a target"""
    return get_host_dir(target, host_ip).exists()

def get_session_env(target: str, host: Optional[str] = None) -> dict:
    """Get session environment for target or host"""
    if host:
        # Host-specific session
        host_dir = get_host_dir(target, host)
        session_file = host_dir / "session.env"
        
        if session_file.exists():
            env = {}
            with open(session_file) as f:
                for line in f:
                    if '=' in line:
                        key, val = line.strip().split("=", 1)
                        env[key] = val
            return env
        else:
            # Create host session if it doesn't exist
            from session import create_host_session
            return create_host_session(target, host)
    else:
        # Target-level session
        target_dir = get_target_dir(target)
        session_file = target_dir / "session.env"
        
        if session_file.exists():
            env = {}
            with open(session_file) as f:
                for line in f:
                    if '=' in line:
                        key, val = line.strip().split("=", 1)
                        env[key] = val
            return env
        else:
            raise FileNotFoundError(f"No session found for target: {target}")

def create_host_entry(target: str, host_ip: str) -> Path:
    """Create a new host entry under a target"""
    host_dir = get_host_dir(target, host_ip)
    host_dir.mkdir(parents=True, exist_ok=True)
    
    # Create session.env for the host
    session_file = host_dir / "session.env"
    logfile = host_dir / "commands.log"
    
    with open(session_file, "w") as f:
        f.write(f"BOXNAME={target}\n")
        f.write(f"HOST={host_ip}\n")
        f.write(f"IP={host_ip}\n")
        f.write(f"OUTDIR={host_dir}\n")
        f.write(f"LOGFILE={logfile}\n")
    
    # Create initial state file for the host
    from state import create_initial_state_file
    create_initial_state_file(host_dir, f"{target}_{host_ip.replace('.', '_')}", host_ip)
    
    return host_dir

def resolve_use_target(identifier: str, current_target: Optional[str] = None) -> Tuple[str, str, Optional[str]]:
    """
    Resolve a 'use' command identifier to (action, target, host)
    
    Args:
        identifier: What the user typed after 'use'
        current_target: Currently active target
    
    Returns:
        (action, target, host) where:
        - action: 'target' or 'host' 
        - target: target name
        - host: host IP (None for target-level)
    """
    # Check if it's a target name
    if target_exists(identifier):
        return 'target', identifier, None
    
    # Check if it's an IP address
    if _is_ip_address(identifier):
        if not current_target:
            raise ValueError("No current target set. Cannot switch to host without target context.")
        
        if host_exists(current_target, identifier):
            return 'host', current_target, identifier
        else:
            raise ValueError(f"Host {identifier} not found under target {current_target}")
    
    # Check if it's a numeric index for hosts
    if identifier.isdigit() and current_target:
        hosts = list_hosts(current_target)
        index = int(identifier) - 1  # 1-based indexing
        
        if 0 <= index < len(hosts):
            host_ip = hosts[index][0]
            return 'host', current_target, host_ip
        else:
            raise ValueError(f"Host index {identifier} out of range (1-{len(hosts)})")
    
    raise ValueError(f"Cannot resolve '{identifier}' to a target or host")

def _is_ip_address(value: str) -> bool:
    """Check if a string looks like an IP address"""
    parts = value.split('.')
    if len(parts) != 4:
        return False
    
    try:
        for part in parts:
            num = int(part)
            if not 0 <= num <= 255:
                return False
        return True
    except ValueError:
        return False

def format_prompt(target: Optional[str], host: Optional[str]) -> str:
    """Format the command prompt based on current context"""
    if not target:
        return ">> "
    elif not host:
        return f"\033[94m[{target}]\033[0m >> "
    else:
        return f"\033[94m[{target}:{host}]\033[0m >> "