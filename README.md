# JASMIN: A Pentester's Enumeration Assistant (Python Edition)

## Overview

**JASMIN** is a Python-based REPL-style toolkit built to streamline enumeration and documentation during penetration testing engagements. Originally designed with OSCP-like scenarios in mind, it automates scanning, notes generation, and service analysis in a structured and reusable way.

---

## 🚀 Features

### 🔍 Scanning Modules

* **`run_tcp_scan`**

  * Full-port TCP scan using Nmap with optimized speed
* **`run_service_scan`**

  * Targeted enumeration of open ports with default scripts and version detection
* **`run_script_scan`**

  * Auto-detects relevant Nmap scripts per port (HTTP, FTP, SMB, etc.)
* **`run_udp_scan`**

  * Launches a top-100 UDP scan in the background and tracks progress

### 🌐 Web Enumeration (`web_enum`)

* Detects HTTP vs HTTPS using curl
* Grabs HTTP headers and saves them
* Runs **Gobuster** and **Feroxbuster** using user-selected wordlists
* Results are appended to `[Web Services Enumeration]` in notes

### 📝 Notes System

Each target gets its own notes file: `~/Boxes/<boxname>_notes.txt`

* Organized into sections:

  * `[OS]`
  * `[Hostname]`
  * `[Services]`
  * `[Web Services Enumeration]`
  * `[Quick Notes]`
* Notes are appended automatically by scan modules or can be edited manually

### 🧠 Extractor Functions

Utility functions to extract and write relevant info into notes:

* `extract_os_from_nmap(scan_file)`
* `extract_nmap_services(scan_file)`
* `extract_hostname_from_nmap(scan_file)`
* `extract_web_tech(header_text)`

---

## 🛣️ Planned Features

### 📓 Notes Expansion

Enhance `jasmin notes` to support quick entries:

* `quick` — write to `[Quick Notes]`
* `attack` — log attack ideas under `[Attack Vectors]`
* `creds` — collect discovered credentials
* `timeline` — track actions in `[Timeline]`

### 🤖 AI-Assisted Recon (Optional)

Integrate local or cloud-based AI to:

* Summarize scan results
* Recommend next attack steps
* Suggest known CVEs

### 🔁 Smart Session Tracking

* Track scan progress and timestamps
* Resume where you left off
* Optional metadata file per session

---

## 🧰 Requirements

* Python 3.8+
* `nmap`, `gobuster`, `feroxbuster`, `curl` installed and accessible
* Linux (tested on Kali Linux)

---

## 🛠️ Usage

Start jasmin and use the REPL interface to:

```
run tcp <ip> <boxname>
run service <ip> <boxname>
run web <ip> <boxname>
notes <boxname>
```

---

## 💬 Contributing

Ideas, scripts, bug reports, and feature suggestions are welcome. This project is designed to evolve with the needs of OSCP students and working pentesters alike.

---

## 🔒 License

MIT License. See LICENSE for details.
