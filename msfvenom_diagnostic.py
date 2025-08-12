#!/usr/bin/env python3
"""
Diagnostic script to find msfvenom installation
Run this to see where msfvenom is located on your system
"""

import subprocess
import shutil
from pathlib import Path

def find_msfvenom():
    print("=== MSFVENOM DIAGNOSTIC ===\n")
    
    # 1. Check PATH
    print("1. Checking PATH with shutil.which():")
    which_result = shutil.which('msfvenom')
    if which_result:
        print(f"   ✓ Found in PATH: {which_result}")
        
        # Test if it works
        try:
            result = subprocess.run([which_result, '--help'], capture_output=True, timeout=5)
            if result.returncode == 0:
                print(f"   ✓ Executable and working")
            else:
                print(f"   ✗ Found but not working (return code: {result.returncode})")
        except Exception as e:
            print(f"   ✗ Found but error testing: {e}")
    else:
        print("   ✗ Not found in PATH")
    
    # 2. Check common paths
    print("\n2. Checking common installation paths:")
    common_paths = [
        '/usr/bin/msfvenom',
        '/opt/metasploit-framework/msfvenom',
        '/usr/share/metasploit-framework/msfvenom',
        '/opt/metasploit-framework/bin/msfvenom',
        '/usr/local/bin/msfvenom',
        Path.home() / '.rbenv/shims/msfvenom'
    ]
    
    for path in common_paths:
        path_obj = Path(path).expanduser()
        if path_obj.exists():
            print(f"   ✓ Found: {path_obj}")
            
            # Test if executable
            try:
                result = subprocess.run([str(path_obj), '--help'], capture_output=True, timeout=5)
                if result.returncode == 0:
                    print(f"     ✓ Executable and working")
                else:
                    print(f"     ✗ Not working (return code: {result.returncode})")
            except Exception as e:
                print(f"     ✗ Error testing: {e}")
        else:
            print(f"   ✗ Not found: {path}")
    
    # 3. Search filesystem
    print("\n3. Searching filesystem for msfvenom:")
    search_dirs = ['/usr', '/opt', '/usr/local']
    found_any = False
    
    for search_dir in search_dirs:
        try:
            print(f"   Searching {search_dir}...")
            result = subprocess.run(
                ['find', search_dir, '-name', 'msfvenom', '-type', 'f', '2>/dev/null'],
                capture_output=True, text=True, timeout=10, shell=True
            )
            if result.stdout.strip():
                for found_path in result.stdout.strip().split('\n'):
                    print(f"   ✓ Found: {found_path}")
                    found_any = True
        except Exception as e:
            print(f"   Error searching {search_dir}: {e}")
    
    if not found_any:
        print("   No additional msfvenom installations found")
    
    # 4. Check if metasploit is installed
    print("\n4. Checking Metasploit installation:")
    metasploit_indicators = [
        '/opt/metasploit-framework',
        '/usr/share/metasploit-framework',
        '/usr/bin/msfconsole'
    ]
    
    for indicator in metasploit_indicators:
        if Path(indicator).exists():
            print(f"   ✓ Found Metasploit component: {indicator}")
        else:
            print(f"   ✗ Not found: {indicator}")
    
    # 5. Check package manager installation
    print("\n5. Checking package manager installation:")
    
    # Check apt (Debian/Ubuntu)
    try:
        result = subprocess.run(['dpkg', '-l', 'metasploit-framework'], capture_output=True, text=True)
        if result.returncode == 0 and 'ii' in result.stdout:
            print("   ✓ Metasploit installed via apt/dpkg")
        else:
            print("   ✗ Not installed via apt/dpkg")
    except:
        print("   ? Could not check apt/dpkg")
    
    print("\n=== RECOMMENDATIONS ===")
    
    if which_result:
        print(f"✓ msfvenom is available at: {which_result}")
        print("  The issue might be with JASMIN initialization. Try restarting JASMIN.")
    else:
        print("✗ msfvenom not found in PATH")
        print("  Solutions:")
        print("  1. Install Metasploit: sudo apt update && sudo apt install metasploit-framework")
        print("  2. Add msfvenom to PATH if installed elsewhere")
        print("  3. Create a symlink: sudo ln -s /path/to/msfvenom /usr/local/bin/msfvenom")

if __name__ == "__main__":
    find_msfvenom()