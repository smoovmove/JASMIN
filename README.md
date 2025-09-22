[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/yourusername/jasmin?color=green)
![GitHub last commit](https://img.shields.io/github/last-commit/yourusername/jasmin?color=blue)

# JASMIN: Just A Smooth Machine Infiltrating Networks
=====================================================

## Overview

**JASMIN** is a penetration testing workbench that combines an advanced CLI with a modern PyQt6 GUI.  
Originally built as a personal project for OSCP preparation, it has since grown into a **comprehensive framework** for reconnaissance, enumeration, payload management, and Active Directory testing.

⚠️ **Disclaimer:** JASMIN is under active development. Some features may be experimental, and bugs are expected. Feedback and bug reports are welcome.

---

## Core Features

### **Multi-Threaded Scanning Engine** — fast, adaptable reconnaissance
* **TCP Port Scanning** (`run_tcp_scan`) — full-port enumeration with adaptive timing  
* **Service Enumeration** (`run_service_scan`) — version detection and default scripts  
* **Script-Based Analysis** (`run_script_scan`) — auto-detects Nmap scripts (HTTP, FTP, SMB, etc.)  
* **Background UDP Scanning** (`run_udp_scan`) — non-blocking top-100 UDP ports with progress tracking  
* **Host Discovery** (`run_host_discovery_only`) — identify live hosts  
* **Sweep Scanning** (`run_sweep_scan`) — enumerate entire ranges  

### **Advanced Web Enumeration** — specialized HTTP/HTTPS discovery
* Automatic protocol detection (HTTP vs HTTPS)  
* HTTP header analysis and technology fingerprinting  
* Directory discovery via Gobuster/Feroxbuster  
* Automated web technology stack detection  
* Results automatically appended to structured notes  

### **Dynamic Payload Generation System** — contextual, modular payloads
* Support for multiple formats: reverse shells, web shells, custom payloads  
* Interactive build mode with real-time configuration  
* Searchable payload database with templates  
* Quick selection interface (`s<number>`, `sg<number>`, `sb<number>`)  

### **Professional GUI Workbench** — PyQt6-based interface
* Session management and context switching  
* Real-time scan/job monitoring  
* File browser for artifacts and logs  
* Integrated notes editor with syntax highlighting  
* Jobs panel for background task control  
* Tmux integration for persistent shell sessions  

### **Background Jobs System** — asynchronous task management
* Non-blocking operations with progress indicators  
* Job queue with prioritization and status tracking  
* Real-time monitoring and robust error handling  
* Job persistence across restarts  

### **Structured Documentation System** — automated notes
* Organized sections: `[OS]`, `[Hostname]`, `[Services]`, `[Web Services Enumeration]`, `[Quick Notes]`  
* Extraction functions:
  - `extract_os_from_nmap()`  
  - `extract_nmap_services()`  
  - `extract_hostname_from_nmap()`  
  - `extract_web_tech()`  
* Quick note commands: `notes_quick`, `notes_creds`, `notes_users`  
* Built-in file viewer for artifacts and logs  

### **Active Directory Enumeration** — specialized Windows domain assessment
* Full AD enumeration (`ad_enum_full`)  
* User/group analysis (`ad_enum_users`)  
* Kerberos attack integration (`ad_kerberos`) — Kerberoasting & ASREPRoast  
* BloodHound data collection (`ad_bloodhound`)  
* Group Policy and security configuration analysis (`ad_policy`)  
* Credential tracking and management (`ad_creds`)  

### **Session and Target Management** — engagement tracking
* Multi-target support with isolated sessions  
* Full session persistence and recovery  
* Quick target switching (`target set <number>`)  
* Dedicated output directories per session  

### **File Upload Server** — seamless transfers
* Built-in upload handler (`handle_upload_command`)  
* Integrated with session management  
* Organized file storage  

---

## Installation

### System Requirements
* **OS:** Linux (Kali, Ubuntu, Debian) or macOS  
* **Python:** 3.8+  
* **Core tools:** `nmap`, `curl`, `wget`, `netcat`  
* **Enhanced tools (optional):** `gobuster`, `feroxbuster`, `whatweb`, `smbclient`

### Automated Installation
```bash
git clone https://github.com/yourusername/jasmin.git
cd jasmin
python3 jasmin.py setup install
source ~/.bashrc
jasmin --version
````

### Manual Installation

```bash
sudo apt update && sudo apt install -y nmap curl wget netcat-traditional python3-pip git
sudo apt install -y gobuster feroxbuster whatweb smbclient   # optional
pip3 install --user requests beautifulsoup4 paramiko colorama tabulate rich PyQt6
python3 jasmin.py setup path
```

### Dependency Checking

```bash
jasmin setup check
jasmin --doctor
jasmin setup show-missing
```

---

## Quick Start

```bash
jasmin                          # launch JASMIN
jasmin> target new 1 10.10.10.50
jasmin[target1]> fs             # run full reconnaissance
jasmin[target1]> web            # start web enumeration
jasmin[target1]> udp progress   # check UDP scan status
jasmin[target1]> gui            # launch GUI workbench
```

Session management:

```bash
jasmin> target list
jasmin> target set 1
jasmin[target1]> session info
```

Background jobs:

```bash
jasmin[target1]> udp            # start background UDP scan
jasmin[target1]> jobs status    # monitor job status
jasmin[target1]> scans list     # view scan artifacts
```

---

## Advanced Usage

### Payload Generation

```bash
jasmin[target1]> payload search reverse shell linux
jasmin[target1]> s1
jasmin[target1]> sg2
jasmin[target1]> payload build
```

### Active Directory

```bash
jasmin[corp]> ad enum full
jasmin[corp]> ad kerberos
jasmin[corp]> ad bloodhound
jasmin[corp]> ad policy
```

### Notes & Documentation

```bash
jasmin[target1]> notes quick "Found SSH on port 2222"
jasmin[target1]> notes creds "admin:password123"
jasmin[target1]> notes users "john.doe@company.com"
jasmin[target1]> notes open
jasmin[target1]> view scan_results.nmap
```

---

## GUI Workbench

The **PyQt6 GUI Workbench** provides a modern interface for managing assessments.

### Features

* Multi-tab layout: Notes, Scans, State, Shells
* Real-time job updates and scan progress
* Drag-and-drop file management
* Visual session browser
* Integrated terminal

### Requirements

```bash
pip3 install PyQt6 pyperclip netifaces
jasmin[target1]> gui
```

---

## Documentation

Additional documentation is included in the repo:

* **README.md** — this manual
* **docs/INSTALL.md** — platform-specific installation
* **docs/COMMANDS.md** — complete command reference
* **docs/GUI.md** — GUI Workbench guide
* **docs/CONFIG.md** — configuration examples
* **CONTRIBUTING.md** — contributing guidelines

---

## Contributing

Contributions are welcome:

* Report bugs with reproduction steps
* Suggest new features with clear use cases
* Submit pull requests for improvements or docs

---

## License

Released under the [MIT License](LICENSE) — free to use, modify, and distribute for commercial or non-commercial purposes.

---

## Security Considerations

JASMIN is for **authorized penetration testing and research only**.
Always ensure you have explicit permission before testing, comply with applicable laws, and follow responsible disclosure practices.

---

**Happy Hacking!**
