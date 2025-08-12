#!/usr/bin/env python3

"""
Enhanced scans.py with intelligence integration and internal/external methodology
"""

import subprocess
import time
import threading
from pathlib import Path
from datetime import datetime

# INTELLIGENCE INTEGRATION - ADD THESE IMPORTS
try:
    from intelligence_integration import auto_analyze_scan_results
    INTEL_AVAILABLE = True
except ImportError:
    INTEL_AVAILABLE = False

def run_tcp_scan(ip, boxname, outdir, logfile, internal=False, intel=False):
    """Run TCP port scan with service detection"""
    
    print(f"[*] Starting TCP scan on {ip}...")
    
    # Build command based on internal/external
    if internal:
        # Internal: Connect scan, no ping, faster rate
        output_file = outdir / f"{boxname}_tcp_internal"
        command = [
            "nmap", "-sT", "-p-", "-T4", 
            "--min-rate=1000", "--max-retries=1", "--host-timeout=2m", "-Pn",
            "-oA", str(output_file), ip
        ]
        print(f"[*] Running internal TCP scan (connect scan, no ping)")
    else:
        # External: SYN scan, standard discovery
        output_file = outdir / f"{boxname}_tcp"
        command = [
            "nmap", "-sS", "-p-", "-T4",
            "--min-rate=2000", "--max-retries=1", "--host-timeout=2m",
            "-oA", str(output_file), ip
        ]
        print(f"[*] Running external TCP scan (SYN scan)")
    
    # Execute scan
    start_time = time.time()
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=600)
        elapsed = time.time() - start_time
        
        if result.returncode == 0:
            print(f"[+] TCP scan completed in {elapsed:.1f} seconds")
            
            # Log to file
            with open(logfile, "a") as f:
                timestamp = datetime.now().strftime("%F %T")
                f.write(f"[{timestamp}] TCP scan completed: {' '.join(command)}\n")
                
        else:
            print(f"[!] TCP scan failed: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print("[!] TCP scan timed out after 10 minutes")
    except Exception as e:
        print(f"[!] TCP scan error: {e}")
    
    # Intelligence Analysis Integration (only if --intel flag provided)
    if intel and INTEL_AVAILABLE:
        env = {
            'IP': ip,
            'BOXNAME': boxname,
            'OUTDIR': str(outdir),
            'LOGFILE': str(logfile)
        }
        try:
            auto_analyze_scan_results(env)
        except Exception as e:
            print(f"[!] Intelligence analysis failed: {e}")

def run_script_scan(ip, boxname, outdir, logfile, internal=False, intel=False):
    """Run targeted script scan based on open ports"""
    
    print(f"[*] Starting script scan on {ip}...")
    
    # Build command based on internal/external
    if internal:
        # Internal: Connect scan + default scripts only
        output_file = outdir / f"{boxname}_script_internal"
        command = [
            "nmap", "-sT", "-sC", "-T4",
            "--min-rate=1000", "--max-retries=1", "-Pn",
            "-oA", str(output_file), ip
        ]
        print(f"[*] Running internal script scan (connect + default scripts)")
    else:
        # External: SYN scan + scripts + version detection
        output_file = outdir / f"{boxname}_script"
        command = [
            "nmap", "-sS", "-sC", "-sV", "-T4",
            "--min-rate=1000", "--max-retries=1",
            "-oA", str(output_file), ip
        ]
        print(f"[*] Running external script scan (SYN + scripts + version)")
    
    # Execute scan
    start_time = time.time()
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=900)
        elapsed = time.time() - start_time
        
        if result.returncode == 0:
            print(f"[+] Script scan completed in {elapsed:.1f} seconds")
            
            # Log to file
            with open(logfile, "a") as f:
                timestamp = datetime.now().strftime("%F %T")
                f.write(f"[{timestamp}] Script scan completed: {' '.join(command)}\n")
                
        else:
            print(f"[!] Script scan failed: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print("[!] Script scan timed out after 15 minutes")
    except Exception as e:
        print(f"[!] Script scan error: {e}")
    
    # Intelligence Analysis Integration (only if --intel flag provided)
    if intel and INTEL_AVAILABLE:
        env = {
            'IP': ip,
            'BOXNAME': boxname,
            'OUTDIR': str(outdir),
            'LOGFILE': str(logfile)
        }
        try:
            auto_analyze_scan_results(env)
        except Exception as e:
            print(f"[!] Intelligence analysis failed: {e}")

def run_full_scan(ip, boxname, outdir, logfile, internal=False, intel=False):
    """Run comprehensive scan: TCP + Service + UDP + Scripts"""
    
    print(f"[*] Starting full scan on {ip}...")
    print(f"[*] Mode: {'Internal' if internal else 'External'}")
    
    scan_start = time.time()
    
    # 1. TCP Scan
    print(f"[*] Step 1/4: TCP port discovery...")
    run_tcp_scan(ip, boxname, outdir, logfile, internal=internal, intel=False)
    
    # 2. Service Detection
    print(f"[*] Step 2/4: Service detection...")
    run_service_scan(ip, boxname, outdir, logfile, internal=internal)
    
    # 3. Script Scan
    print(f"[*] Step 3/4: Script enumeration...")
    run_script_scan(ip, boxname, outdir, logfile, internal=internal, intel=False)
    
    # 4. UDP Scan (only for external scans, internal doesn't work well with UDP)
    if not internal:
        print(f"[*] Step 4/4: UDP scan (background)...")
        run_udp_scan(ip, boxname, outdir, logfile)
    else:
        print(f"[*] Step 4/4: Skipping UDP scan (internal mode)")
    
    total_elapsed = time.time() - scan_start
    print(f"[+] Full scan sequence completed in {total_elapsed/60:.1f} minutes")
    
    # Log completion
    with open(logfile, "a") as f:
        timestamp = datetime.now().strftime("%F %T")
        mode = "internal" if internal else "external"
        f.write(f"[{timestamp}] Full scan ({mode}) completed in {total_elapsed/60:.1f} minutes\n")
    
    # Intelligence Analysis Integration (only if --intel flag provided)
    if intel and INTEL_AVAILABLE:
        env = {
            'IP': ip,
            'BOXNAME': boxname,
            'OUTDIR': str(outdir),
            'LOGFILE': str(logfile)
        }
        try:
            auto_analyze_scan_results(env)
        except Exception as e:
            print(f"[!] Intelligence analysis failed: {e}")

def run_service_scan(ip, boxname, outdir, logfile, internal=False):
    """Run service version detection on discovered ports"""
    
    print(f"[*] Starting service detection on {ip}...")
    
    # Build command based on internal/external
    if internal:
        # Internal: Connect scan + version detection
        output_file = outdir / f"{boxname}_service_internal"
        command = [
            "nmap", "-sT", "-sV", "-T4",
            "--min-rate=1000", "--max-retries=1", "-Pn",
            "-oA", str(output_file), ip
        ]
        print(f"[*] Running internal service scan (connect + version)")
    else:
        # External: SYN scan + version detection
        output_file = outdir / f"{boxname}_service"
        command = [
            "nmap", "-sS", "-sV", "-T4",
            "--min-rate=1000", "--max-retries=1",
            "-oA", str(output_file), ip
        ]
        print(f"[*] Running external service scan (SYN + version)")
    
    # Execute scan
    start_time = time.time()
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=600)
        elapsed = time.time() - start_time
        
        if result.returncode == 0:
            print(f"[+] Service scan completed in {elapsed:.1f} seconds")
            
            # Log to file
            with open(logfile, "a") as f:
                timestamp = datetime.now().strftime("%F %T")
                f.write(f"[{timestamp}] Service scan completed: {' '.join(command)}\n")
                
        else:
            print(f"[!] Service scan failed: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print("[!] Service scan timed out after 10 minutes")
    except Exception as e:
        print(f"[!] Service scan error: {e}")

def run_udp_scan(ip, boxname, outdir, logfile):
    """Run UDP scan in background (external only)"""
    
    print(f"[*] Starting UDP scan on {ip} (background process)...")
    
    output_file = outdir / f"{boxname}_udp"
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
                
                # Log to file
                with open(logfile, "a") as f:
                    timestamp = datetime.now().strftime("%F %T")
                    f.write(f"[{timestamp}] UDP scan completed: {' '.join(command)}\n")
            else:
                print(f"[!] UDP scan failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print("[!] UDP scan timed out after 30 minutes")
        except Exception as e:
            print(f"[!] UDP scan error: {e}")
    
    # Start UDP scan in background thread
    udp_thread = threading.Thread(target=run_udp_background, daemon=True)
    udp_thread.start()
    
    print(f"[*] UDP scan running in background. Use 'udp progress' to check status.")

def check_udp_progress(boxname, outdir):
    """Check UDP scan progress"""
    
    udp_file = outdir / f"{boxname}_udp.nmap"
    
    if not udp_file.exists():
        print("[!] No UDP scan file found. Run a full scan first.")
        return
    
    try:
        # Check file modification time
        mod_time = udp_file.stat().st_mtime
        current_time = time.time()
        age_minutes = (current_time - mod_time) / 60
        
        # Read current content
        with open(udp_file, 'r') as f:
            content = f.read()
        
        if "Nmap scan report" in content and "# Nmap done" in content:
            print(f"[+] UDP scan completed")
            
            # Count open ports
            open_ports = content.count("/udp open")
            if open_ports > 0:
                print(f"[+] Found {open_ports} open UDP ports")
            else:
                print(f"[*] No open UDP ports found")
        else:
            print(f"[*] UDP scan in progress... (running for {age_minutes:.1f} minutes)")
            
    except Exception as e:
        print(f"[!] Error checking UDP progress: {e}")

def web_enum(ip, boxname, outdir, logfile, port=None, internal=False, intel=False, tool="auto", protocol=None):
    """Enhanced web enumeration with custom port support, tool selection, and protocol specification"""
    
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
        else:
            # Default behavior - scan both HTTP and HTTPS
            print(f"[*] Starting web enumeration on {ip} (HTTP/HTTPS)")
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
    if use_feroxbuster and feroxbuster_available:
        # FEROXBUSTER IMPLEMENTATION
        
        # Select best available wordlist
        wordlists = [
            "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/dirb/common.txt"
        ]
        
        wordlist = None
        for wl in wordlists:
            if Path(wl).exists():
                wordlist = wl
                break
        
        if wordlist:
            output_file = outdir / f"{boxname}_feroxbuster{port_suffix}.txt"
            
            ferox_cmd = [
                "feroxbuster",
                "-u", base_url,
                "-w", wordlist,
                "-o", str(output_file),
            ]
            
            # Add SSL support if HTTPS
            if scheme == "https":
                ferox_cmd.append("-k")  # Ignore SSL certificate
            
            # Adjust settings based on internal/external
            if internal:
                ferox_cmd.extend([
                    "-t", "10",           # Lower thread count for internal
                    "--timeout", "5",     # 5 second timeout
                    "--depth", "2",       # Limit recursion depth
                ])
                print(f"[*] Running feroxbuster on {base_url} (internal mode)")
            else:
                ferox_cmd.extend([
                    "-t", "30",           # Higher thread count for external
                    "--timeout", "3",     # Faster timeout
                    "--depth", "3",       # More recursion
                ])
                print(f"[*] Running feroxbuster on {base_url} (external mode)")
            
            # Add smart filtering
            ferox_cmd.extend([
                "--filter-status", "404",     # Filter 404s
                "--filter-words", "0",        # Filter empty responses
            ])
            
            try:
                result = subprocess.run(ferox_cmd, capture_output=True, text=True, timeout=600)
                if result.returncode == 0:
                    print(f"[+] Directory enumeration completed -> {output_file.name}")
                    
                    # Show quick summary of findings
                    try:
                        with open(output_file, 'r') as f:
                            content = f.read()
                        
                        lines = content.split('\n')
                        status_200 = len([l for l in lines if ' 200 ' in l])
                        status_301 = len([l for l in lines if ' 301 ' in l])
                        status_403 = len([l for l in lines if ' 403 ' in l])
                        
                        if status_200 > 0:
                            print(f"[+] Found {status_200} accessible paths (200)")
                        if status_301 > 0:
                            print(f"[+] Found {status_301} redirects (301)")
                        if status_403 > 0:
                            print(f"[*] Found {status_403} forbidden paths (403)")
                            
                    except Exception:
                        pass  # Don't fail if we can't parse output
                        
                else:
                    print(f"[!] Feroxbuster failed: {result.stderr}")
            except subprocess.TimeoutExpired:
                print("[!] Feroxbuster timed out after 10 minutes")
            except Exception as e:
                print(f"[!] Feroxbuster error: {e}")
        else:
            print("[!] No suitable wordlist found for feroxbuster")
    
    elif gobuster_available:
        # GOBUSTER IMPLEMENTATION
        
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if Path(wordlist).exists():
            output_file = outdir / f"{boxname}_gobuster{port_suffix}.txt"
            
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
                print(f"[*] Running gobuster on {base_url} (internal mode)")
            else:
                gobuster_cmd.extend(["-t", "20", "--timeout", "3s"])
                print(f"[*] Running gobuster on {base_url}")
            
            try:
                result = subprocess.run(gobuster_cmd, capture_output=True, text=True, timeout=300)
                if result.returncode == 0:
                    print(f"[+] Directory enumeration completed -> {output_file.name}")
                else:
                    print(f"[!] Gobuster failed: {result.stderr}")
            except Exception as e:
                print(f"[!] Gobuster error: {e}")
        else:
            print("[!] Gobuster wordlist not found: {wordlist}")
    
    # 3. Additional web tools for custom ports (moved)
    
    # 4. Technology detection
    whatweb_file = outdir / f"{boxname}_whatweb{port_suffix}.txt"
    print(f"[*] Running technology detection...")
    try:
        whatweb_cmd = ["whatweb", "-a", "3", base_url]
        result = subprocess.run(whatweb_cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            with open(whatweb_file, 'w') as f:
                f.write(result.stdout)
            print(f"[+] Technology detection completed -> {whatweb_file.name}")
    except Exception as e:
        print(f"[!] Technology detection failed: {e}")

def run_host_discovery_only(ip, internal=False):
    """Host discovery only (use with CIDR)"""
    
    print(f"[*] Starting host discovery on {ip}...")
    
    if internal:
        # Internal host discovery might not work well through port forwarding
        print(f"[!] Warning: Host discovery may not work reliably in internal mode")
        print(f"[!] Consider running discovery from the jump host directly")
        command = [
            "nmap", "-sn", "-T4", "--min-rate=1000", "-Pn", ip
        ]
    else:
        # External host discovery
        command = [
            "nmap", "-sn", "-T4", "--min-rate=2000", ip
        ]
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            print(f"[+] Host discovery completed")
            print(result.stdout)
        else:
            print(f"[!] Host discovery failed: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print("[!] Host discovery timed out")
    except Exception as e:
        print(f"[!] Host discovery error: {e}")

# Additional utility functions (keep your existing ones)

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