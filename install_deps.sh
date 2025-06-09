#!/bin/bash

REQUIRED_TOOLS = (nmap gobuster feroxbuster curl python3)
MISSING_TOOLS = ()

echo "[*] Checking for required tools..."

for tool in "${REQUIRED_TOOLS[@]}"; do 
    if ! command -v "$tool" &> /dev/null; then 
        MISSING_TOOLS+=("$tool")
    fi 
done 

if [ ${#MISSING_TOOLS[@]} -eq 0 ]; then 
    echo "[*] All tools are already installed."
    exit 0
fi 

echo "[!] Missing tools detected: ${MISSING_TOOLS[*]}"
echo "[*] Installing missing tools..."

for tool in "${MISSING_TOOLS[@]}"; do 
    if [ "$tool" = "feroxbuster" ]; then 
        echo "[*] Installing feroxbuster..."
        wget -q https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster_amd64.deb -O /tmp/feroxbuster.deb
        sudo dpkg -i /tmp/feroxbuster.deb
        sudo apt-get install -f -y
    else
        echo "[*] Installing $tool..."
        sudo apt-get install -y "$tool"
    fi 
done 

echo "[+] All missing tools installed. You're good to go."