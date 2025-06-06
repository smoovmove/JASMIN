# scans.py

from pathlib import Path
import subprocess

import sys

from logger import log_output

from notes import append_to_notes_section, extract_web_tech, extract_os_from_nmap, extract_nmap_services

from state import update_state_field, mark_module_used

#Function for tcp scans
def run_tcp_scan(ip:str, boxname:str, outdir:Path, logfile:Path):
    print(f"[*] Running full TCP port scan on {ip}...")
    tcp_output_file = outdir / f"{boxname}.tcp_scan.txt"

    try: 
        result = subprocess.run(
            ["nmap", "-p-", "--min-rate", "1000", "-T4", "-Pn", ip, "-oN", str(tcp_output_file)], 
            capture_output= True, text= True, check= True
        )

        log_output(logfile, "[TCP] TCP Scan Output", result.stdout)
    except subprocess.CalledProcessError as e: 
        print(f"[!] Error running full scan: {e}")
        return

    open_ports = []
    for line in result.stdout.splitlines():
        if line and line[0].isdigit():
            port = line.split("/")[0]
            open_ports.append(port)

    if not open_ports: 
        print("[-] No open ports found.")
        return
    
    port_string = ",".join(open_ports)
    print(f"[+] Open ports found: {port_string}")

    (outdir / "open_ports.txt").write_text(port_string)
    update_state_field(outdir, "ports" , open_ports)

    print(f"TCP Scan complete! Results saved to {tcp_output_file}")
    mark_module_used(outdir, "tcp_scan")



#Function for service scans
def run_service_scan(ip:str, boxname:str, outdir:Path, logfile:Path):
    print("[*] Now running a targeted service scan...")
    service_output_file = outdir / f"{boxname}.service_scan.txt"
    port_file = outdir / "open_ports.txt"
    note_file = outdir / f"{boxname}_notes.txt"

    if not port_file.exists():
        print(f"[-] Open ports file not found at: {outdir}")
        print(f"[-] Run the full scan first!")
        return
    
    port_string = port_file.read_text().strip()

    try: 
        result = subprocess.run(
            ["nmap", f"-p{port_string}", "-sC", "-sV", "-Pn", "-oN", str(service_output_file), ip], 
            capture_output= True, text= True, check= True
        )
        
        #log raw output
        log_output(logfile, "[SERVICE] Service Scan Output", result.stdout)
        
        #extract and write os
        os_info = extract_os_from_nmap(service_output_file)
        update_state_field(outdir, "os", os_info)
        
        #extract and write services
        raw_services = extract_nmap_services(service_output_file).splitlines()
        service_objects = [{"version":line} for line in raw_services]
        update_state_field(outdir, "services", service_objects)
        
        print(f"[+] OS Identified: {os_info}")
        print(f"[+] Services Extracted: {len(service_objects)} entries")

    except subprocess.CalledProcessError as e: 
        print(f"[!] Error running service scan: {e}")
        return
    
    
    print(f"Service scan complete! Scan saved to {service_output_file}")
    mark_module_used(outdir, "service_scan")



#Function for running TCP, Service and UDP Scan
def run_full_scan(ip:str, boxname:str, outdir:Path, logfile:Path):

    run_tcp_scan(ip, boxname, outdir, logfile)

    run_service_scan(ip, boxname, outdir, logfile)

    print(f"[+] Full scan complete! Open ports saved to {outdir}/open_ports.txt")

    #Prompt the user to run a target script scan
    user_input = input("Do you want to run a targeted script scan on the open ports? (y/n)").strip().lower()
    if user_input == "y":
        run_script_scan(ip, boxname, outdir, logfile)
    
    #Runs the UDP scan last
    run_udp_scan(ip, boxname, outdir, logfile)



#Function for script scans on the ports that were found from the tcp scan
def run_script_scan(ip:str, boxname: str, outdir: Path, logfile:Path):
    port_file = outdir / "open_ports.txt"
    service_scan_file = outdir / f"script_scan_port_{port}.txt"

    if not port_file.exists():
        print(f"[-] Open ports file not found at: {outdir}")
        print(f"[-] Run the full scan first!")
        return
    
    port_string = port_file.read_text().strip()
    ports = port_string.split(",")

    for port in ports: 
        port = port.strip()
        if port in ["80", "8000", "8080"]:
            scripts = "http-title,http-methods,http-enum,http-headers"
        elif port == "21": 
            scripts = "ftp-anon,ftp-syst"
        elif port == "22": 
            scripts = "ssh-hostkey,ssh-auth-methods"
        elif port in ["139", "445"]:
            scripts = "smb-os-discovery,smb-enum-shares,smb-enum-users"
        else: 
            scripts = "default,safe"

        print(f"[*] Scanning port {port} with scripts: {scripts}")
        try: 
            result = subprocess.run(
                    ["nmap", "-Pn", "-p", f"{port}", "--script", f"{scripts}", "-sV", "-T4", "-v0", "--script-timeout", "30s", "-oN", f"{outdir}/script_scan_port_{port}.txt", ip], 
                    capture_output= True, text= True, check= True
                )
            log_output(logfile, "[SCRIPT] Script Scan Output", result.stdout)
        except subprocess.CalledProcessError as e: 
            print(f"[!] Script scan failed for port {port}: {e}")
    
    print(f"[!] Script scan complete! Scan saved to {service_scan_file}")       
    mark_module_used(outdir, "script_scan")
    
    

#Function for running UDP Scans
def run_udp_scan(ip:str, boxname:str, outdir:Path, logfile:Path):
    udp_output_file = outdir / f"{boxname}.udp.txt"
    print(f"[*] Launching a UDP scan on {ip} in the background... (results will be in {udp_output_file})")

    #run the udp scan in the background
    try: 
        with open(udp_output_file, "w") as log_file: 
            result = subprocess.Popen(
                ["nmap", "-sU", "--top-ports", "100", "-Pn", "--stats-every", "5s",
                "-v", "-T4", "-oN", str(udp_output_file), ip], stdout=log_file, stderr=subprocess.STDOUT
            )
            log_output(logfile, "[UDP] UDP Scan Started",f"UDP Scan started in background, writing to {udp_output_file}")
    except subprocess.CalledProcessError as e: 
        print(f"[!] Error running UDP scan: {e}")
        return
         
    mark_module_used(outdir, "udp_scan")



#Since UDP scans are long, this gives the user a update on the progress of the scan
def check_udp_progress(boxname: str, outdir: Path):
    udp_log = outdir / f"{boxname}.udp.txt"
    if not udp_log.exists(): 
        print("[!] No UDP log file found.")
        return
    
    last_progress = None
    with open(udp_log) as f: 
        for line in f: 
            if "Stats:" in line: 
                last_progress = line.strip()
    
    if last_progress: 
        print(f"[UDP Progress] {last_progress}")
    else: 
        print("No progress reported yet.")



#To get user input on which wordlist to use
def choose_wordlist():
    default_wordlist = "/usr/share/wordlists/dirb/common.txt"
    seclists_dir = Path("/usr/share/seclists/Discovery/Web-Content")

    print("Which wordlist for web enumeration?")
    print("1) Use default (common.txt)")
    print("2) Browse Seclists/Web-Content")
    print("3) Enter custom path")

    choice = input("Enter choice: ").strip()

    #default choice
    if choice == "" or choice == "1": 
        return default_wordlist

    #choice number 2 
    if choice == "2": 
        wordlists = sorted(seclists_dir.glob(".txt"))
        if not wordlists: 
            print("[-] No wordlists found in Seclists. Using default wordlist.")
            return default_wordlist
        
        print("\nAvailable Seclists wordlists")
        for idx, wl in enumerate(wordlists):
            print(f"{idx + 1}) {wl.name}")

        sub_choice = input(f"Choose [1-{len(wordlists)}: ]").strip()

        try: 
            selected = wordlists[int(sub_choice) -1]
            return str(selected)
        except (ValueError, IndexError): 
            print("[-] Invalid input. Using default wordlist")
            return default_wordlist
    
    #choice number 3 
    elif choice == "3": 
        custom_path = input("Enter full path to wordlist: ").strip()
        return custom_path
    
    else: 
        print("[-] Invalid input. Using default wordlist")
        return default_wordlist



#Function for web enumeration
def web_enum(ip: str, boxname: str, outdir: Path, logfile:Path ):
    port_file = outdir / "open_ports.txt"
    notes_file = outdir / f"{boxname}_notes.txt"

    if not port_file.exists():
        print(f"[-] Open ports file not found at: {outdir}")
        print(f"[-] Run the full scan first!")
        return
    
    port_string = port_file.read_text().strip()
    ports = port_string.split(",")
    web_ports = []

    for port in ports: 
        port = port.strip()
        if port in ["80", "8080", "8000"]:
            web_ports.append(port)

    if len(web_ports) == 1: 
        web_port = web_ports[0]
        print(f"[+] Using detected web port: {web_port}")

    elif len(web_ports) > 1: 
        print(f"[!] Multiple web ports detected!: {web_ports}")
        chosen_port = input("Which port would you like to use?").strip()

        if chosen_port in web_ports: 
            web_port = chosen_port
        else: 
            print("[-] Invalid choice. Returning to main menu.")
        
    elif len(web_ports) == 0: 
        user_input = input("No standard web ports found. Use a non-standard port? (y/n)").strip().lower()
        if user_input == "y": 
            web_port = input("Please input the port you would like to use: ").strip()
        else: 
            print("Returning to main menu")
            return
    
    #Check if site is HTTP or HTTPS
    print("[*] Checking if site is HTTP or HTTPS...")

    try: 
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{scheme}", f"http://{ip}:{web_port}"], 
            capture_output= True, text= True, check= True)
        proto = result.stdout.strip()
        log_output(logfile, "[WEB] HTTP vs HTTPS Scan Output", result.stdout)
    except subprocess.CalledProcessError: 
        print("[!] Curl failed to connect, assuming HTTPS")
        proto = "https"

    #Fallback if for some reason curl doesnt return 'http'
    if proto != "http":
        proto = "https"

    url = f"{proto}://{ip}:{web_port}"

    print(f"[*] Detected protocol: {proto}")
    print(f" Target url: {url}")

    #Grab HTTP Headers
    print("[*] Grabbing HTTP Headers...")
    headers_file = outdir / f"web_headers_{web_port}.txt"

    try: 
        result = subprocess.run(
            ["curl", "-I", "--insecure", url], 
            capture_output=True, text=True, check=True
        )
        log_output(logfile, "[WEB] HTTP Headers Scan", result.stdout)

        #print headers to screen
        print(result.stdout)

        #save headers to file 
        headers_file.write_text(result.stdout)
        print(f"[+] Headers file saved to {headers_file}")

        #save headers to notes
        append_to_notes_section(notes_file, "[Web Services Enumeration]:", f"Headers for {url}:\n{result.stdout}")

        #extract and log web tech 
        tech_summary = extract_web_tech(tech_summary)
        if tech_summary: 
            #append_to_notes_section(notes_file, "Web Technology:", tech_summary)
            update_state_field(outdir, "web_tech", tech_summary)
        

    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to grab headers: {e}")

    #Gobuster Directory Bruteforce
    print("[*] Running Gobuster for Directories...")
    gobuster_file = outdir / "web_gobuster.txt"

    wordlist_path = choose_wordlist()

    try: 
        result = subprocess.run(
            ["gobuster", "dir", 
             "-u", url, 
             wordlist_path, 
             "-t", "40", "-o", "-w", str(gobuster_file)], 
            capture_output=True, text=True, check=True
        )

        log_output(logfile, "[WEB] Gobuster Scan Output", result.stdout)
        append_to_notes_section(notes_file, "[Web Services Enumeration]:", f"Gobuster Scan for {url}:\n{result.stdout}")
        
        #extract discovered paths from gobuster output
        paths = []
        for line in result.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2 and parts[1] in ("GET", "POST"): 
                path = parts[0]
                if path.startswith("/"):
                    paths.append(path)
                    
        #only update state.json if paths found
        if paths: 
            from state import load_state
            services = load_state(outdir).get("services", [])
            if services: 
                services[0]["discovered_paths"] = paths
            else: 
                services = [{"discovered_paths" : paths}]
            update_state_field(outdir, "services", services)

        print(f"[+] Gobuster output saved to {gobuster_file}")
    
    except subprocess.CalledProcessError as e: 
        print(f"[-] Gobuster scan failed: {e}")

    #Ferroxbuster Directory Bruteforce
    print("[*] Running Ferroxbuster to confirm directories...")
    ferrox_file = outdir / "web_ferrox.txt"

    wordlist_path = choose_wordlist()

    try: 
        result = subprocess.run(
            ["feroxbuster", "-u", 
             url, "-w", wordlist_path, 
             "-o", str(ferrox_file)], 
            capture_output=True, text=True, check=True
        )
        log_output(logfile, "[WEB] Feroxbuster Scan Result", result.stdout)
        append_to_notes_section(notes_file, "[Web Services Enumeration]:", f"Feroxbuster Scan for {url}:\n{result.stdout}")

        print(f"[+] Ferroxbuster output saved to {ferrox_file}")
    
    except subprocess.CalledProcessError as e: 
        print(f"[-] Ferroxbuster scan failed: {e}")
    
    print("[+] Web Enumertion Complete!")
    mark_module_used(outdir, "web_enum")
    

