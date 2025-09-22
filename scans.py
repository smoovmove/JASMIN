#!/usr/bin/env python3

import subprocess
import time
import threading
from pathlib import Path
from datetime import datetime

def get_scan_context(ip, boxname, internal=False):
    """Extract scan context information from parameters"""
    context = {
        'target_ip': ip,
        'is_internal': internal,
        'is_tunneled': False,
        'original_boxname': boxname,
        'clean_boxname': boxname
    }
    
    # Check if this is a tunneled internal scan (boxname has internal IP suffix)
    if "_internal_" in boxname:
        context['is_tunneled'] = True
        context['clean_boxname'] = boxname.split("_internal_")[0]
        # Extract tunneled IP from suffix
        ip_suffix = boxname.split("_internal_")[1]
        tunneled_ip = ip_suffix.replace('_', '.')
        context['display_name'] = f"{context['clean_boxname']} -> {tunneled_ip}"
    elif "_internal" in boxname and boxname.endswith("_internal"):
        context['clean_boxname'] = boxname.replace("_internal", "")
        context['display_name'] = f"{context['clean_boxname']} (internal)"
    else:
        context['display_name'] = context['clean_boxname']
    
    return context

def run_sweep_scan(target_ip, boxname, outdir, logfile, internal=False, include_file=None):
    """
    Run sweep scan on multiple targets
    - Uses existing discovery results if available
    - Runs discovery first if needed
    - Supports custom target files via include_file parameter
    """
    outdir = Path(outdir)
    scans_dir = outdir / "scans"
    scans_dir.mkdir(exist_ok=True)
    logfile = Path(logfile)
    live_ips = []
    
    if include_file:
        # Use custom targets file
        custom_file_path = outdir / include_file
        if custom_file_path.exists():
            print(f"[*] Loading targets from: {include_file}")
            try:
                with open(custom_file_path, 'r') as f:
                    live_ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                
                # Validate IPs
                from session import is_ip_range
                valid_ips = []
                for ip in live_ips:
                    valid, _ = is_ip_range(ip)
                    if valid:
                        valid_ips.append(ip)
                    else:
                        print(f"[!] Skipping invalid IP: {ip}")
                
                live_ips = valid_ips
                
                if live_ips:
                    print(f"[+] Loaded {len(live_ips)} targets from {include_file}")
                else:
                    print(f"[!] No valid IPs found in {include_file}")
                    return False
                    
            except Exception as e:
                print(f"[!] Error reading {include_file}: {e}")
                return False
        else:
            print(f"[!] File not found: {include_file}")
            return False
    
    else:
        # Use existing discovery logic with proper naming
        live_hosts_file = scans_dir / f"{boxname}_live_hosts.txt"
        
        if live_hosts_file.exists():
            with open(live_hosts_file, 'r') as f:
                live_ips = [line.strip() for line in f if line.strip()]
            
            if live_ips:
                print(f"[+] Found existing discovery results: {len(live_ips)} hosts")
            else:
                print("[!] Empty discovery file, running discovery first...")
                live_ips = run_host_discovery_only(
                    target_ip, 
                    internal=internal,
                    outdir=outdir,
                    boxname=boxname,
                    save_results=True
                )
        else:
            print("[*] No discovery results found, running discovery first...")
            live_ips = run_host_discovery_only(
                target_ip, 
                internal=internal,
                outdir=outdir,
                boxname=boxname,
                save_results=True
            )
    
    if not live_ips:
        print("[!] No live hosts to scan")
        return False
    
    print(f"[*] Starting sweep scan on {len(live_ips)} live hosts...")
    
    # Log sweep start
    with open(logfile, "a") as f:
        timestamp = datetime.now().strftime("%F %T")
        source = f"from {include_file}" if include_file else f"from {boxname}_live_hosts.txt"
        f.write(f"[{timestamp}] Starting sweep scan on {len(live_ips)} hosts {source}\n")
    
    # Scan each live host
    for i, host_ip in enumerate(live_ips, 1):
        print(f"[*] Scanning host {i}/{len(live_ips)}: {host_ip}")
        
        # Generate boxname for this host
        host_boxname = f"{boxname}_{host_ip.replace('.', '_')}"
        
        # Run scan on this host - using TCP scan for speed
        run_tcp_scan(
            host_ip,
            host_boxname,
            outdir,
            logfile,
            internal=internal,
        )
    
    print(f"[+] Sweep scan completed on {len(live_ips)} hosts")
    return True


def run_tcp_scan(ip, boxname, outdir, logfile, internal=False):
    """Run TCP port scan with service detection"""
    
    context = get_scan_context(ip, boxname, internal)
    
    print(f"[*] Starting TCP scan on {ip}...")
    if context['is_tunneled']:
        print(f"[*] Target: {context['display_name']}")

    outdir = Path(outdir)
    scans_dir = outdir / "scans"
    scans_dir.mkdir(exist_ok=True)
    
    # Build command based on internal/external
    if internal or context['is_tunneled']:
        # Internal: Connect scan, no ping, faster rate
        output_file = scans_dir / f"{boxname}_tcp"
        command = [
        "nmap", "-sT", "-p-", "-Pn",
        "--min-rate=500", "--max-retries=2", "--host-timeout=10m",
        "--stats-every=30s", "-oA", str(output_file), ip
    ]      
        scan_method = "internal TCP scan (connect scan, no ping)"
    else:
        # External: SYN scan, standard discovery
        output_file = scans_dir / f"{boxname}_tcp"
        command = [
        "nmap", "-sS", "-p-", 
        "--min-rate=400", "--max-retries=2", "--host-timeout=10m",
        "--stats-every=30s", "-oA", str(output_file), ip
    ]
        scan_method = "external TCP scan (SYN scan)"
    
    print(f"[*] Running {scan_method}")
    
    # Execute scan
    start_time = time.time()
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=600)
        elapsed = time.time() - start_time
        
        if result.returncode == 0:
            print(f"[+] TCP scan completed in {elapsed:.1f} seconds")
            
            # Log to file with context
            with open(logfile, "a") as f:
                timestamp = datetime.now().strftime("%F %T")
                context_desc = f"TCP scan on {context['display_name']} ({ip})"
                f.write(f"[{timestamp}] {context_desc} completed in {elapsed:.1f}s\n")
                f.write(f"[{timestamp}] Command: {' '.join(command)}\n")
                
        else:
            print(f"[!] TCP scan failed: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print("[!] TCP scan timed out after 10 minutes")
    except Exception as e:
        print(f"[!] TCP scan error: {e}")

def run_detailed_scan(ip, boxname, outdir, logfile, internal=False):
    """Run combined script and service detection scan"""
    
    context = get_scan_context(ip, boxname, internal)
    
    print(f"[*] Starting detailed scan on {ip}...")
    if context['is_tunneled']:
        print(f"[*] Target: {context['display_name']}")

    outdir = Path(outdir)
    scans_dir = outdir / "scans"
    scans_dir.mkdir(exist_ok=True)

    # Get open ports from TCP scan
    tcp_file = scans_dir / f"{boxname}_tcp.gnmap"
    open_ports = parse_open_ports(tcp_file)  # You'd need to implement this
    port_list = ",".join(open_ports)
    
    # Build command based on internal/external
    if internal or context['is_tunneled']:
        # Internal: Connect scan + scripts + version detection
        output_file = scans_dir / f"{boxname}_detailed"
        command = [
            "nmap", "-sT", "-sC", "-sV", "-T3", "-Pn", "-p", port_list,
            "--min-rate=500", "--max-retries=2", "--host-timeout=10m",
            "--stats-every=30s", "-oA", str(output_file), ip
        ]
        scan_method = "internal detailed scan (connect + scripts + version)"
    else:
        # External: SYN scan + scripts + version detection
        output_file = scans_dir / f"{boxname}_detailed"
        command = [
            "nmap", "-sS", "-sC", "-sV", "-T3", "-p", port_list,
            "--min-rate=500", "--max-retries=2", "--host-timeout=10m",
            "--stats-every=30s", "-oA", str(output_file), ip
        ]
        scan_method = "external detailed scan (SYN + scripts + version)"
    
    print(f"[*] Running {scan_method}")
    
    # Execute scan
    start_time = time.time()
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=1200)  # 20 min timeout
        elapsed = time.time() - start_time
        
        if result.returncode == 0:
            print(f"[+] Detailed scan completed in {elapsed:.1f} seconds")
            
            # Log to file with context
            with open(logfile, "a") as f:
                timestamp = datetime.now().strftime("%F %T")
                context_desc = f"Detailed scan on {context['display_name']} ({ip})"
                f.write(f"[{timestamp}] {context_desc} completed in {elapsed:.1f}s\n")
                f.write(f"[{timestamp}] Command: {' '.join(command)}\n")
                
        else:
            print(f"[!] Detailed scan failed: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print("[!] Detailed scan timed out after 20 minutes")
    except Exception as e:
        print(f"[!] Detailed scan error: {e}")
    
def run_script_scan(ip, boxname, outdir, logfile, internal=False):
    """Run targeted script scan based on open ports"""
    
    context = get_scan_context(ip, boxname, internal)
    
    print(f"[*] Starting script scan on {ip}...")
    if context['is_tunneled']:
        print(f"[*] Target: {context['display_name']}")

    outdir = Path(outdir)
    scans_dir = outdir / "scans"
    scans_dir.mkdir(exist_ok=True)
    
    # Build command based on internal/external
    if internal or context['is_tunneled']:
        # Internal: Connect scan + default scripts only
        output_file = scans_dir / f"{boxname}_script"
        command = [
            "nmap", "-sT", "-sC", "-T4",
            "--min-rate=1000", "--max-retries=1", "-Pn",
            "-oA", str(output_file), ip
        ]
        scan_method = "internal script scan (connect + default scripts)"
    else:
        # External: SYN scan + scripts + version detection
        output_file = scans_dir / f"{boxname}_script"
        command = [
            "nmap", "-sS", "-sC", "-sV", "-T4",
            "--min-rate=1000", "--max-retries=1",
            "-oA", str(output_file), ip
        ]
        scan_method = "external script scan (SYN + scripts + version)"
    
    print(f"[*] Running {scan_method}")
    
    # Execute scan
    start_time = time.time()
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=900)
        elapsed = time.time() - start_time
        
        if result.returncode == 0:
            print(f"[+] Script scan completed in {elapsed:.1f} seconds")
            
            # Log to file with context
            with open(logfile, "a") as f:
                timestamp = datetime.now().strftime("%F %T")
                context_desc = f"Script scan on {context['display_name']} ({ip})"
                f.write(f"[{timestamp}] {context_desc} completed in {elapsed:.1f}s\n")
                f.write(f"[{timestamp}] Command: {' '.join(command)}\n")
                
        else:
            print(f"[!] Script scan failed: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print("[!] Script scan timed out after 15 minutes")
    except Exception as e:
        print(f"[!] Script scan error: {e}")

def run_service_scan(ip, boxname, outdir, logfile, internal=False):
    """Run service version detection on discovered ports"""
    
    context = get_scan_context(ip, boxname, internal)

    outdir = Path(outdir)
    scans_dir = outdir / "scans"
    scans_dir.mkdir(exist_ok=True)
    
    print(f"[*] Starting service detection on {ip}...")
    if context['is_tunneled']:
        print(f"[*] Target: {context['display_name']}")
    
    # Build command based on internal/external
    if internal or context['is_tunneled']:
        # Internal: Connect scan + version detection
        output_file = scans_dir / f"{boxname}_service"
        command = [
            "nmap", "-sT", "-sV", "-T4",
            "--min-rate=1000", "--max-retries=1", "-Pn",
            "-oA", str(output_file), ip
        ]
        scan_method = "internal service scan (connect + version)"
    else:
        # External: SYN scan + version detection
        output_file = scans_dir / f"{boxname}_service"
        command = [
            "nmap", "-sS", "-sV", "-T4",
            "--min-rate=1000", "--max-retries=1",
            "-oA", str(output_file), ip
        ]
        scan_method = "external service scan (SYN + version)"
    
    print(f"[*] Running {scan_method}")
    
    # Execute scan
    start_time = time.time()
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=600)
        elapsed = time.time() - start_time
        
        if result.returncode == 0:
            print(f"[+] Service scan completed in {elapsed:.1f} seconds")
            
            # Log to file with context
            with open(logfile, "a") as f:
                timestamp = datetime.now().strftime("%F %T")
                context_desc = f"Service scan on {context['display_name']} ({ip})"
                f.write(f"[{timestamp}] {context_desc} completed in {elapsed:.1f}s\n")
                f.write(f"[{timestamp}] Command: {' '.join(command)}\n")
                
        else:
            print(f"[!] Service scan failed: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print("[!] Service scan timed out after 10 minutes")
    except Exception as e:
        print(f"[!] Service scan error: {e}")

def run_full_scan(ip, boxname, outdir, logfile, internal=False):
    """Run comprehensive scan: TCP + Service + UDP + Scripts"""
    
    context = get_scan_context(ip, boxname, internal)
    
    print(f"[*] Starting full scan on {ip}...")
    print(f"[*] Target: {context['display_name']}")
    print(f"[*] Mode: {'Internal' if internal or context['is_tunneled'] else 'External'}")
    
    if context['is_tunneled']:
        print(f"[*] Tunneled scan - UDP will be skipped")
    
    scan_start = time.time()
    
    # Log scan start with full context
    with open(logfile, "a") as f:
        timestamp = datetime.now().strftime("%F %T")
        mode = "internal" if internal or context['is_tunneled'] else "external"
        f.write(f"[{timestamp}] Starting full scan ({mode}) on {context['display_name']} ({ip})\n")
    
    # 1. TCP Scan
    print(f"[*] Step 1/3: TCP port discovery...")
    run_tcp_scan(ip, boxname, outdir, logfile, internal=internal)
    
    # 2. Service Detection
    print(f"[*] Step 2/3: Service detection...")
    run_detailed_scan(ip, boxname, outdir, logfile, internal=False)
    
    # 4. UDP Scan (only for external scans, skip for tunneled)
    if not internal and not context['is_tunneled']:
        print(f"[*] Step 3/3: UDP scan (background)...")
        run_udp_scan(ip, boxname, outdir, logfile)
    else:
        reason = "tunneled scan" if context['is_tunneled'] else "internal mode"
        print(f"[*] Step 4/4: Skipping UDP scan ({reason})")
    
    total_elapsed = time.time() - scan_start
    print(f"[+] Full scan sequence completed in {total_elapsed/60:.1f} minutes")
    print(f"[+] Target: {context['display_name']} ({ip})")
    
    # Log completion with context
    with open(logfile, "a") as f:
        timestamp = datetime.now().strftime("%F %T")
        mode = "internal" if internal or context['is_tunneled'] else "external"
        f.write(f"[{timestamp}] Full scan ({mode}) on {context['display_name']} completed in {total_elapsed/60:.1f} minutes\n")
    

def run_udp_scan(ip, boxname, outdir, logfile):
    """Run UDP scan in background (external only)"""
    
    context = get_scan_context(ip, boxname)
    
    print(f"[*] Starting UDP scan on {ip} (background process)...")
    if context['is_tunneled']:
        print(f"[*] Target: {context['display_name']}")

    outdir = Path(outdir)
    scans_dir = outdir / "scans"
    scans_dir.mkdir(exist_ok=True)
    
    output_file = scans_dir / f"{boxname}_udp"
    command = [
        "nmap", "-sU", "--top-ports=100", "-T4",
        "--max-retries=1", "--host-timeout=5m",
        "-oA", str(output_file), ip
    ]
    
    def run_udp_background():
        try:
            start_time = time.time()
            result = subprocess.run(command, capture_output=True, text=True, timeout=1800)
            elapsed = time.time() - start_time
            
            if result.returncode == 0:
                print(f"[+] UDP scan completed in {elapsed/60:.1f} minutes")
                print(f"[+] Target: {context['display_name']} ({ip})")
                
                # Log to file with context
                with open(logfile, "a") as f:
                    timestamp = datetime.now().strftime("%F %T")
                    context_desc = f"UDP scan on {context['display_name']} ({ip})"
                    f.write(f"[{timestamp}] {context_desc} completed in {elapsed/60:.1f} minutes\n")
            else:
                print(f"[!] UDP scan failed on {context['display_name']}: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print(f"[!] UDP scan timed out after 30 minutes on {context['display_name']}")
        except Exception as e:
            print(f"[!] UDP scan error on {context['display_name']}: {e}")
    
    # Run in background thread
    udp_thread = threading.Thread(target=run_udp_background, daemon=True)
    udp_thread.start()

def check_udp_progress(ip, boxname, outdir, logfile):
    """Check UDP scan progress and results"""
    
    context = get_scan_context(ip, boxname)
    
    outdir = Path(outdir)
    scans_dir = outdir / "scans"
    scans_dir.mkdir(exist_ok=True)
    
    output_file = scans_dir / f"{boxname}_udp"
    nmap_file = output_file.with_suffix('.nmap')
    
    if nmap_file.exists():
        print(f"[*] UDP scan results for {context['display_name']}:")
        
        # Read and display results
        try:
            with open(nmap_file, 'r') as f:
                content = f.read()
                
            # Extract open ports
            lines = content.split('\n')
            open_ports = []
            for line in lines:
                if 'open' in line and 'udp' in line.lower():
                    open_ports.append(line.strip())
            
            if open_ports:
                print(f"[+] Found {len(open_ports)} open UDP ports:")
                for port in open_ports:
                    print(f"    {port}")
            else:
                print(f"[*] No open UDP ports found on {context['display_name']}")
                
        except Exception as e:
            print(f"[!] Error reading UDP results: {e}")
    else:
        print(f"[*] No UDP scan results found for {context['display_name']}")
        print(f"[*] Run 'udp' command to start UDP scan")

def web_enum(ip, boxname, outdir, logfile, port=None, internal=False, tool="auto", protocol=None, wordlist_size="short"):
    """Enhanced web enumeration with custom port support, tool selection, and protocol specification"""
    
    # Context awareness
    context = get_scan_context(ip, boxname, internal)

    outdir = Path(outdir)
    scans_dir = outdir / "scans"
    scans_dir.mkdir(exist_ok=True)
    
    # Determine target URL, port, and protocol
    if port:
        target_port = int(port)
        
        # Determine protocol - explicit override takes precedence
        if protocol:
            scheme = protocol.lower()
        else:
            # Smart detection based on common ports
            if target_port == 443:
                scheme = "https"
            elif target_port in [8443, 9443, 10443]:  # Common HTTPS alternate ports
                scheme = "https"
            else:
                scheme = "http"
        
        # Build URL
        if scheme == "https":
            if target_port == 443:
                base_url = f"https://{ip}"
            else:
                base_url = f"https://{ip}:{port}"
        else:  # http
            if target_port == 80:
                base_url = f"http://{ip}"
            else:
                base_url = f"http://{ip}:{port}"
        
        print(f"[*] Starting web enumeration on {ip}:{port} ({scheme.upper()})")
        if context['is_tunneled']:
            print(f"[*] Target: {context['display_name']}")
        
    else:
        # No port specified - use protocol or default
        if protocol:
            scheme = protocol.lower()
            if scheme == "https":
                base_url = f"https://{ip}"
                target_port = 443
            else:
                base_url = f"http://{ip}"
                target_port = 80
            print(f"[*] Starting web enumeration on {ip} ({scheme.upper()})")
            if context['is_tunneled']:
                print(f"[*] Target: {context['display_name']}")
        else:
            # Default behavior - scan both HTTP and HTTPS
            print(f"[*] Starting web enumeration on {ip} (HTTP/HTTPS)")
            if context['is_tunneled']:
                print(f"[*] Target: {context['display_name']}")
            base_url = f"http://{ip}"
            target_port = 80
            scheme = "http"
    
    # Create output files with port and protocol info
    if port:
        port_suffix = f"_{scheme}_port{port}"
    elif protocol:
        port_suffix = f"_{scheme}"
    else:
        port_suffix = ""
    
    # 1. Basic connectivity check
    print(f"[*] Checking {scheme.upper()} connectivity...")
    try:
        curl_cmd = ["curl", "-s", "-I", "--max-time", "5"]
        
        # Add SSL options for HTTPS
        if scheme == "https":
            curl_cmd.extend(["-k"])  # Ignore SSL certificate errors
        
        curl_cmd.append(base_url)
        
        result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(f"[+] {scheme.upper()} service is responding")
        else:
            print(f"[!] {scheme.upper()} service not responding or filtered")
    except Exception as e:
        print(f"[!] Connectivity check failed: {e}")
    
    # 2. Directory enumeration with smart tool selection
    
    # Detect available tools
    feroxbuster_available = False
    gobuster_available = False
    
    try:
        subprocess.run(["feroxbuster", "--version"], capture_output=True, timeout=5)
        feroxbuster_available = True
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    try:
        subprocess.run(["gobuster", "version"], capture_output=True, timeout=5)
        gobuster_available = True
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    # Determine which tool to use
    use_feroxbuster = False
    
    if tool == "ferox" and feroxbuster_available:
        use_feroxbuster = True
        print("[*] Using feroxbuster (user specified)")
    elif tool == "gobuster" and gobuster_available:
        use_feroxbuster = False
        print("[*] Using gobuster (user specified)")
    elif tool == "auto":
        if feroxbuster_available:
            use_feroxbuster = True
            print("[*] Using feroxbuster (faster, more features)")
        elif gobuster_available:
            use_feroxbuster = False
            print("[*] Using gobuster (feroxbuster not available)")
        else:
            print("[!] No directory enumeration tools available")
            print("[!] Install feroxbuster or gobuster for directory enumeration")
    
    # Run directory enumeration
    # REPLACE feroxbuster section with this version that shows progress:

    if use_feroxbuster and feroxbuster_available:
        # FEROXBUSTER IMPLEMENTATION - WITH REAL-TIME PROGRESS
        
        # Use smaller, faster wordlists by default
        wordlist_map = {
            'short': {
                'path': '/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt',
                'count': '4,713',
                'time': '1-2 min',
                'desc': 'common.txt (fast)'
            },
            'medium': {
                'path': '/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt', 
                'count': '30,000',
                'time': '5-8 min',
                'desc': 'raft-medium-directories.txt'
            },
            'large': {
                'path': '/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt',
                'count': '62,284', 
                'time': '15-25 min',
                'desc': 'raft-large-directories.txt'
            }
        }
        
        # Select wordlist based on size parameter (wordlist_size now comes from jasmin.py)
        wordlist_info = wordlist_map.get(wordlist_size, wordlist_map['short'])
        wordlist = wordlist_info['path']  # This replaces: wordlist = None
        
        # Check if selected wordlist exists, fallback if needed
        if not Path(wordlist).exists():
            print(f"[!] Wordlist not found: {wordlist}")
            fallbacks = ['/usr/share/wordlists/dirb/common.txt', '/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt']
            wordlist = None
            for fallback in fallbacks:
                if Path(fallback).exists():
                    wordlist = fallback
                    wordlist_info = {'desc': f'fallback: {Path(fallback).name}', 'count': 'unknown', 'time': 'unknown'}
                    break
            
            if not wordlist:
                print("[!] No suitable wordlist found for feroxbuster")
                return
        
        if wordlist:
            output_file = outdir / f"{boxname}_feroxbuster{port_suffix}.txt"
            
            print(f"[*] Wordlist: {wordlist_info['desc']} ({wordlist_info['count']} entries, ~{wordlist_info['time']})")
            
            ferox_cmd = [
                "feroxbuster",
                "-u", base_url,
                "-w", wordlist,
                "-o", str(output_file),   # Save to file
                # Remove --quiet to show progress!
            ]
            
            # Add SSL support if HTTPS
            if scheme == "https":
                ferox_cmd.append("-k")
            
            # Conservative settings
            if internal:
                ferox_cmd.extend([
                    "-t", "8",            # Low thread count for internal
                    "--timeout", "10",    # Longer timeout for tunneled
                    "--depth", "1",       # No recursion
                    "--rate-limit", "15", # Conservative rate
                ])
                if context['is_tunneled']:
                    print(f"[*] Running feroxbuster on {base_url} (internal mode via {context['display_name']})")
                else:
                    print(f"[*] Running feroxbuster on {base_url} (internal mode)")
            else:
                ferox_cmd.extend([
                    "-t", "15",           # Moderate threads
                    "--timeout", "5",     # Standard timeout
                    "--depth", "2",       # Limited recursion
                    "--rate-limit", "30", # Reasonable rate
                ])
                if context['is_tunneled']:
                    print(f"[*] Running feroxbuster on {base_url} (external mode via {context['display_name']})")
                else:
                    print(f"[*] Running feroxbuster on {base_url} (external mode)")
            
            # Add filtering
            ferox_cmd.extend([
                "--filter-status", "404",
                "--filter-words", "0",
            ])
            
            print(f"[*] Output saving to: {output_file.name}")
            print(f"[*] Progress will be shown below (Press Ctrl+C to stop):")
            print("-" * 60)
            
            try:
                # Run WITHOUT capturing output so user sees real-time progress
                result = subprocess.run(ferox_cmd, timeout=600)  # 10 minute max
                print("-" * 60)
                if result.returncode == 0:
                    if context['is_tunneled']:
                        print(f"[+] Directory enumeration completed on {context['display_name']}")
                    else:
                        print(f"[+] Directory enumeration completed")
                    
                    # 🧹 CLEAN THE OUTPUT FILE HERE (ADD THIS LINE):
                    clean_feroxbuster_output(output_file)
                    
                    # Show summary from saved file
                    show_feroxbuster_summary(output_file)
                    
            except subprocess.TimeoutExpired:
                print("\n" + "-" * 60)
                print("[!] Feroxbuster timed out after 10 minutes")
                print(f"[*] Partial results saved in: {output_file.name}")
                
                # 🧹 CLEAN PARTIAL RESULTS TOO (ADD THIS LINE):
                clean_feroxbuster_output(output_file)
                
                show_feroxbuster_summary(output_file)
                
            except KeyboardInterrupt:
                print("\n" + "-" * 60)
                print("[!] Feroxbuster stopped by user")
                print(f"[*] Partial results saved in: {output_file.name}")
                
                # 🧹 CLEAN INTERRUPTED RESULTS (ADD THIS LINE):
                clean_feroxbuster_output(output_file)
                
                show_feroxbuster_summary(output_file)
                
            except Exception as e:
                print(f"\n[!] Feroxbuster error: {e}")
                
            else:
                print("[!] No suitable wordlist found for feroxbuster")
    
    elif gobuster_available:
        # GOBUSTER IMPLEMENTATION
        
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if Path(wordlist).exists():
            output_file = scans_dir / f"{boxname}_gobuster{port_suffix}.txt"
            
            gobuster_cmd = [
                "gobuster", "dir",
                "-u", base_url,
                "-w", wordlist,
                "-o", str(output_file)
            ]
            
            # Add SSL support if HTTPS
            if scheme == "https":
                gobuster_cmd.append("-k")  # Ignore SSL certificate
            
            # Adjust threading based on internal/external
            if internal:
                gobuster_cmd.extend(["-t", "10", "--timeout", "5s"])
                if context['is_tunneled']:
                    print(f"[*] Running gobuster on {base_url} (internal mode via {context['display_name']})")
                else:
                    print(f"[*] Running gobuster on {base_url} (internal mode)")
            else:
                gobuster_cmd.extend(["-t", "20", "--timeout", "3s"])
                if context['is_tunneled']:
                    print(f"[*] Running gobuster on {base_url} (via {context['display_name']})")
                else:
                    print(f"[*] Running gobuster on {base_url}")
            
            try:
                result = subprocess.run(gobuster_cmd, capture_output=True, text=True, timeout=300)
                if result.returncode == 0:
                    if context['is_tunneled']:
                        print(f"[+] Directory enumeration completed on {context['display_name']} -> {output_file.name}")
                    else:
                        print(f"[+] Directory enumeration completed -> {output_file.name}")
                else:
                    print(f"[!] Gobuster failed: {result.stderr}")
            except Exception as e:
                print(f"[!] Gobuster error: {e}")
        else:
            print("[!] Gobuster wordlist not found: {wordlist}")
    
    # 3. Additional web tools for custom ports (moved)
    
    # 4. Technology detection
    whatweb_file = scans_dir / f"{boxname}_whatweb{port_suffix}.txt"
    print(f"[*] Running technology detection...")
    try:
        whatweb_cmd = ["whatweb", "-a", "3", base_url]
        result = subprocess.run(whatweb_cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            with open(whatweb_file, 'w') as f:
                f.write(result.stdout)
            if context['is_tunneled']:
                print(f"[+] Technology detection completed on {context['display_name']} -> {whatweb_file.name}")
            else:
                print(f"[+] Technology detection completed -> {whatweb_file.name}")
    except Exception as e:
        print(f"[!] Technology detection failed: {e}")

# ADD this helper function to your scans.py file:
# REPLACE the clean_feroxbuster_output function in scans.py with this fixed version:

def clean_feroxbuster_output(output_file):
    """Clean feroxbuster output file to remove configuration noise"""
    try:
        # Convert PosixPath to string if needed
        file_path = str(output_file)
        
        # Read the original file
        with open(file_path, 'r') as f:
            content = f.read()
        
        lines = content.split('\n')
        clean_lines = []
        
        # Skip everything until we find the first HTTP result
        found_results = False
        
        for line in lines:
            # Look for actual HTTP results (status codes + URLs)
            if any(code in line for code in [' 200 ', ' 301 ', ' 302 ', ' 403 ', ' 404 ', ' 500 ']):
                if 'http' in line:
                    found_results = True
                    clean_lines.append(line.strip())
            elif found_results and line.strip() and 'http' in line:
                # Keep any additional result lines after we start finding them
                clean_lines.append(line.strip())
        
        # Write clean version back to same file
        with open(file_path, 'w') as f:
            f.write("# Feroxbuster Results\n")
            f.write("# " + "="*50 + "\n\n")
            f.write('\n'.join(clean_lines))
        
        print(f"[*] Cleaned output file: {len(clean_lines)} results")
        return len(clean_lines)
        
    except Exception as e:
        print(f"[!] Error cleaning feroxbuster output: {e}")
        return 0


# ALSO REPLACE the show_feroxbuster_summary function with this fixed version:

def show_feroxbuster_summary(output_file):
    """Show summary of feroxbuster results"""
    try:
        # Convert PosixPath to string if needed
        file_path = str(output_file)
        
        if not Path(file_path).exists():
            print("[!] No output file found")
            return
            
        with open(file_path, 'r') as f:
            content = f.read()
        
        if not content.strip():
            print("[!] Output file is empty")
            return
            
        lines = content.split('\n')
        
        # Count different status codes
        status_counts = {}
        interesting_paths = []
        
        for line in lines:
            if 'http' in line and any(code in line for code in [' 200 ', ' 301 ', ' 302 ', ' 403 ', ' 401 ', ' 500 ']):
                # Extract status code
                for code in ['200', '301', '302', '403', '401', '500', '204', '400']:
                    if f' {code} ' in line:
                        status_counts[code] = status_counts.get(code, 0) + 1
                        if code in ['200', '301', '302']:
                            interesting_paths.append(line.strip())
                        break
        
        file_size = Path(file_path).stat().st_size
        filename = Path(file_path).name
        print(f"[*] Results: {filename} ({file_size:,} bytes)")
        
        if status_counts:
            print("[*] Status code summary:")
            for code, count in sorted(status_counts.items()):
                status_desc = {
                    '200': 'OK (accessible)',
                    '301': 'Moved Permanently', 
                    '302': 'Found (redirect)',
                    '403': 'Forbidden',
                    '401': 'Unauthorized',
                    '500': 'Internal Server Error'
                }.get(code, 'Unknown')
                print(f"    {code}: {count} ({status_desc})")
        
        # Show first few interesting paths
        if interesting_paths:
            print(f"[*] First {min(3, len(interesting_paths))} interesting paths:")
            for path in interesting_paths[:3]:
                print(f"    {path}")
            if len(interesting_paths) > 3:
                print(f"    ... and {len(interesting_paths) - 3} more")
        else:
            print("[*] No accessible paths found")
            
    except Exception as e:
        print(f"[!] Error reading results: {e}")
    

# ADD this helper function to show results summary:
def show_feroxbuster_summary(output_file):
    """Show summary of feroxbuster results"""
    if not output_file.exists():
        print("[!] No output file found")
        return
        
    try:
        with open(output_file, 'r') as f:
            content = f.read()
        
        if not content.strip():
            print("[!] Output file is empty")
            return
            
        lines = content.split('\n')
        
        # Count different status codes
        status_counts = {}
        interesting_paths = []
        
        for line in lines:
            if 'http' in line and any(code in line for code in [' 200 ', ' 301 ', ' 302 ', ' 403 ', ' 401 ', ' 500 ']):
                # Extract status code
                for code in ['200', '301', '302', '403', '401', '500', '204', '400']:
                    if f' {code} ' in line:
                        status_counts[code] = status_counts.get(code, 0) + 1
                        if code in ['200', '301', '302']:
                            interesting_paths.append(line.strip())
                        break
        
        file_size = output_file.stat().st_size
        print(f"[*] Results: {output_file.name} ({file_size:,} bytes)")
        
        if status_counts:
            print("[*] Status code summary:")
            for code, count in sorted(status_counts.items()):
                status_desc = {
                    '200': 'OK (accessible)',
                    '301': 'Moved Permanently', 
                    '302': 'Found (redirect)',
                    '403': 'Forbidden',
                    '401': 'Unauthorized',
                    '500': 'Internal Server Error'
                }.get(code, 'Unknown')
                print(f"    {code}: {count} ({status_desc})")
        
        # Show first few interesting paths
        if interesting_paths:
            print(f"[*] First {min(3, len(interesting_paths))} interesting paths:")
            for path in interesting_paths[:3]:
                print(f"    {path}")
            if len(interesting_paths) > 3:
                print(f"    ... and {len(interesting_paths) - 3} more")
        else:
            print("[*] No accessible paths found")
            
    except Exception as e:
        print(f"[!] Error reading results: {e}")


# OPTIONAL: Add this quick progress checker function
def check_feroxbuster_progress(output_file):
    """Check progress of running feroxbuster scan"""
    if not output_file.exists():
        print("[*] Scan hasn't started yet...")
        return
        
    try:
        with open(output_file, 'r') as f:
            lines = f.readlines()
        
        result_lines = [l for l in lines if 'http' in l and any(code in l for code in [' 200 ', ' 301 ', ' 403 '])]
        
        if result_lines:
            print(f"[*] Progress: {len(result_lines)} results found so far...")
            if result_lines:
                print(f"[*] Latest: {result_lines[-1].strip()}")
        else:
            print("[*] Scan running, no results yet...")
            
    except Exception as e:
        print(f"[!] Can't check progress: {e}")

def run_host_discovery_only(ip, internal=False, outdir=None, boxname=None, save_results=True):
    """Host discovery only (use with CIDR) with optional file output"""
    
    print(f"[*] Starting host discovery on {ip}...")
    
    # Build output file paths if saving results
    if save_results and outdir and boxname:
        outdir = Path(outdir)
        scans_dir = outdir / "scans"
        scans_dir.mkdir(exist_ok=True)
        
        discovery_file = scans_dir / f"{boxname}_discovery"  # Changed
        live_hosts_file = scans_dir / f"{boxname}_live_hosts.txt"  # Changed
    else:
        discovery_file = None
        live_hosts_file = None
    
    if internal:
        print(f"[!] Warning: Host discovery may not work reliably in internal mode")
        print(f"[!] Consider running discovery from the jump host directly")
        command = [
            "nmap", "-sn", "-T4", "--min-rate=1000", "-Pn"
        ]
    else:
        command = [
            "nmap", "-sn", "-T4", "--min-rate=2000"
        ]
    
    # Add output file if saving
    if discovery_file:
        command.extend(["-oA", str(discovery_file)])
    
    # Add target
    command.append(ip)
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            print(f"[+] Host discovery completed")
            print(result.stdout)
            
            # Parse and save live hosts if requested
            if save_results and live_hosts_file:
                live_ips = parse_discovery_results(result.stdout)
                if live_ips:
                    with open(live_hosts_file, 'w') as f:
                        for ip in live_ips:
                            f.write(f"{ip}\n")
                    print(f"[+] Found {len(live_ips)} live hosts -> {live_hosts_file.name}")
                    return live_ips
                else:
                    print("[*] No live hosts found")
                    return []
        else:
            print(f"[!] Host discovery failed: {result.stderr}")
            return []
            
    except subprocess.TimeoutExpired:
        print("[!] Host discovery timed out")
        return []
    except Exception as e:
        print(f"[!] Host discovery error: {e}")
        return []
# Additional utility functions 

def extract_os_from_nmap(scan_file):
    """Extract OS information from nmap scan file"""
    try:
        with open(scan_file, 'r') as f:
            content = f.read()
        
        # Look for OS detection lines
        os_lines = [line for line in content.split('\n') if 'OS:' in line or 'Running:' in line]
        if os_lines:
            return os_lines[0].strip()
        
        return None
    except Exception:
        return None
    
def parse_open_ports(gnmap_file):
    """Extract open ports from .gnmap file"""
    ports = []
    with open(gnmap_file, 'r') as f:
        for line in f:
            if 'Ports:' in line:
                # Split on 'Ports: ' and get port section
                port_section = line.split('Ports: ')[1].split('\t')[0]
                # Each port is separated by comma
                for port_info in port_section.split(', '):
                    if '/open/' in port_info:
                        port = port_info.split('/')[0]
                        ports.append(port)
    return ports

def parse_discovery_results(nmap_output):
    """Parse nmap discovery output to extract live IP addresses"""
    live_ips = []
    try:
        lines = nmap_output.split('\n')
        current_ip = None
        
        for line in lines:
            # Look for scan report line with IP
            if 'Nmap scan report for' in line:
                parts = line.split()
                if len(parts) >= 5:
                    # Extract IP (usually at index 4: "Nmap scan report for 192.168.1.1")
                    ip_candidate = parts[4]
                    # Simple IP validation
                    if '.' in ip_candidate and ip_candidate.replace('.', '').replace(':', '').isdigit():
                        current_ip = ip_candidate
            
            # If we see "Host is up" and have a current IP, it's alive
            elif 'Host is up' in line and current_ip:
                if current_ip not in live_ips:
                    live_ips.append(current_ip)
                current_ip = None
        
        return sorted(live_ips)
    except Exception:
        return []

def extract_nmap_services(scan_file):
    """Extract services from nmap scan file"""
    services = []
    try:
        with open(scan_file, 'r') as f:
            for line in f:
                if '/tcp' in line and 'open' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port = parts[0].split('/')[0]
                        service = parts[2] if len(parts) > 2 else 'unknown'
                        services.append(f"{port}:{service}")
        
        return services
    except Exception:
        return []

def extract_hostname_from_nmap(scan_file):
    """Extract hostname from nmap scan file"""
    try:
        with open(scan_file, 'r') as f:
            content = f.read()
        
        # Look for hostname in various formats
        import re
        hostname_patterns = [
            r'Nmap scan report for ([^\s]+)',
            r'rDNS record for [^:]+: ([^\s]+)',
        ]
        
        for pattern in hostname_patterns:
            matches = re.findall(pattern, content)
            if matches:
                return matches[0]
        
        return None
    except Exception:
        return None