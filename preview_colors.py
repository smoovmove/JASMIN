#!/usr/bin/env python3

"""
Quick Color Preview - See your JASMIN colors in action
"""

# Your custom colors converted to ANSI
TEA_GREEN = '\033[38;2;124;185;135m'      # #7CB987
ROBINS_EGG = '\033[38;2;105;207;222m'     # #69CFDE
RESET = '\033[0m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'

def show_preview():
    """Show what JASMIN will look like with your colors"""
    
    print(f"\n{CYAN}🎨 JASMIN Color Preview{RESET}")
    print("=" * 50)
    
    # JASMIN Branding (Tea Green)
    print(f"\n{TEA_GREEN}🎯 JASMIN Branding & Success Messages (Tea Green - #7CB987):{RESET}")
    print(f"{TEA_GREEN}JASMIN v2.1{RESET} - Just A Smooth Machine Infiltrating Networks")
    print(f"{TEA_GREEN}✅ Setup completed successfully!{RESET}")
    print(f"{TEA_GREEN}[+] Target session created: testbox (192.168.1.100){RESET}")
    print(f"{TEA_GREEN}jasmin(testbox)> {RESET}fs")
    
    # General Output (Robins Egg)  
    print(f"\n{ROBINS_EGG}📋 General Output & Scan Results (Robins Egg - #69CFDE):{RESET}")
    print(f"{ROBINS_EGG}[*] Starting full TCP scan on 192.168.1.100...{RESET}")
    print(f"{ROBINS_EGG}[*] Running: nmap -p- --min-rate 10000 192.168.1.100{RESET}")
    print(f"{ROBINS_EGG}[*] Found open ports: 22, 80, 443{RESET}")
    print(f"{ROBINS_EGG}[*] Starting web enumeration...{RESET}")
    print(f"{ROBINS_EGG}[*] Directory enumeration completed{RESET}")
    
    # Error/Warning messages (standard colors)
    print(f"\n{RED}❌ Error Messages:{RESET}")
    print(f"{RED}[!] Scan failed: Connection timeout{RESET}")
    
    print(f"\n{YELLOW}⚠️  Warning Messages:{RESET}")
    print(f"{YELLOW}[!] Missing dependencies detected{RESET}")
    
    # ASCII Art preview
    print(f"\n{TEA_GREEN}🎨 JASMIN ASCII Art Preview:{RESET}")
    print(f"{TEA_GREEN}       ██╗ █████╗ ███████╗███╗   ███╗██╗███╗   ██╗{RESET}")
    print(f"{TEA_GREEN}       ██║██╔══██╗██╔════╝████╗ ████║██║████╗  ██║{RESET}")
    print(f"{TEA_GREEN}       ██║███████║███████╗██╔████╔██║██║██╔██╗ ██║{RESET}")
    
    # Interactive prompts
    print(f"\n{TEA_GREEN}🔧 Interactive Prompts:{RESET}")
    print(f"{ROBINS_EGG}Choose installation method:{RESET}")
    print(f"{ROBINS_EGG}1. System-wide installation{RESET}")
    print(f"{ROBINS_EGG}2. User-local installation{RESET}")
    print(f"{TEA_GREEN}Enter choice (1-2): {RESET}", end="")
    
    print(f"\n\n{CYAN}📝 Color Summary:{RESET}")
    print(f"  Tea Green:   {TEA_GREEN}#7CB987{RESET} - Branding, success, prompts")
    print(f"  Robins Egg:  {ROBINS_EGG}#69CFDE{RESET} - General output, scan results")
    print(f"  Red:         {RED}Standard{RESET} - Errors")
    print(f"  Yellow:      {YELLOW}Standard{RESET} - Warnings")

if __name__ == "__main__":
    show_preview()
    
    print(f"\n{CYAN}Ready to apply these colors to JASMIN?{RESET}")
    print(f"1. Run: python3 update_jasmin_colors.py")
    print(f"2. Choose option 3 (auto-update)")
    print(f"3. Or manually copy the COLORS dictionary from new_jasmin_colors.py")