---
title: HTB: Mirai
url: https://0xdf.gitlab.io/2022/05/18/htb-mirai.html
date: 2022-05-18T09:00:00+00:00
difficulty: Easy [20]
os: Linux
tags: hackthebox, htb-mirai, ctf, nmap, raspberrypi, feroxbuster, plex, pihole, default-creds, deleted-file, extundelete, testdisk, photorec, oscp-like-v2
---

![Mirai](https://0xdfimages.gitlab.io/img/mirai-cover.png)

Mirai was a RaspberryPi device running PiHole that happens to still have the RaspberryPi default usename and password. That user can even sudo to root, but there is a bit of a hitch at the end. I’ll have to recover the deleted root flag from a usb drive.

## Box Info

| Name | [Mirai](https://hackthebox.com/machines/mirai)  [Mirai](https://hackthebox.com/machines/mirai) [Play on HackTheBox](https://hackthebox.com/machines/mirai) |
| --- | --- |
| Release Date | [01 Sep 2017](https://twitter.com/hackthebox_eu/status/902864622176362497) |
| Retire Date | 10 Feb 2018 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Mirai |
| Radar Graph | Radar chart for Mirai |
| First Blood User | 00:11:50[eks eks](https://app.hackthebox.com/users/302) |
| First Blood Root | 00:24:56[eks eks](https://app.hackthebox.com/users/302) |
| Creator | [Arrexel Arrexel](https://app.hackthebox.com/users/2904) |

## Recon

### nmap

`nmap` finds six open TCP ports, SSH (22), DNS (53), HTTP (80 and 32400), and Universal Plug and Play (UPnP) (1877 and 32469):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.10.48
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-13 20:32 UTC
Warning: 10.10.10.48 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.48
Host is up (0.10s latency).
Not shown: 58325 closed ports, 7204 filtered ports
PORT      STATE SERVICE
22/tcp    open  ssh
53/tcp    open  domain
80/tcp    open  http
1877/tcp  open  hp-webqosdb
32400/tcp open  plex
32469/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 44.36 seconds
oxdf@hacky$ nmap -p 22,53,80,1877,32400,32469 -sCV 10.10.10.48
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-13 20:34 UTC
Nmap scan report for 10.10.10.48
Host is up (0.11s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)
| ssh-hostkey: 
|   1024 aa:ef:5c:e0:8e:86:97:82:47:ff:4a:e5:40:18:90:c5 (DSA)
|   2048 e8:c1:9d:c5:43:ab:fe:61:23:3b:d7:e4:af:9b:74:18 (RSA)
|   256 b6:a0:78:38:d0:c8:10:94:8b:44:b2:ea:a0:17:42:2b (ECDSA)
|_  256 4d:68:40:f7:20:c4:e5:52:80:7a:44:38:b8:a2:a7:52 (ED25519)
53/tcp    open  domain  dnsmasq 2.76
| dns-nsid: 
|_  bind.version: dnsmasq-2.76
80/tcp    open  http    lighttpd 1.4.35
|_http-server-header: lighttpd/1.4.35
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
1877/tcp  open  upnp    Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
32400/tcp open  http    Plex Media Server httpd
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
|_http-cors: HEAD GET POST PUT DELETE OPTIONS
|_http-title: Unauthorized
32469/tcp open  upnp    Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.46 seconds

```

Based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server) versions, the host is likely running Debian 8 jessie.

### Website - TCP 80

#### Site

Visiting the site returns an empty page.

#### Tech Stack

The HTTP response headers give some hints about what I’m looking at:

```

HTTP/1.1 404 Not Found
X-Pi-hole: A black hole for Internet advertisements.
Content-type: text/html; charset=UTF-8
Content-Length: 0
Connection: close
Date: Fri, 13 May 2022 20:41:39 GMT
Server: lighttpd/1.4.35

```

`X-Pi-hole` implies this is (or is meant to look like) a [PiHole](https://pi-hole.net/), a small DNS server designed to run on a [RaspberryPi](https://www.raspberrypi.org/). The docs for PiHole suggest going to `/admin` to manage it. I’ll also discover that with `feroxbuster`.

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@hacky$ feroxbuster -u http://10.10.10.48

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.48
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        0l        0w        0c http://10.10.10.48/admin => http://10.10.10.48/admin/
301      GET        0l        0w        0c http://10.10.10.48/admin/scripts => http://10.10.10.48/admin/scripts/
301      GET        0l        0w        0c http://10.10.10.48/admin/img => http://10.10.10.48/admin/img/
301      GET        0l        0w        0c http://10.10.10.48/admin/style => http://10.10.10.48/admin/style/
301      GET        0l        0w        0c http://10.10.10.48/admin/style/vendor => http://10.10.10.48/admin/style/vendor/
301      GET        0l        0w        0c http://10.10.10.48/admin/scripts/vendor => http://10.10.10.48/admin/scripts/vendor/
200      GET        1l        1w       18c http://10.10.10.48/versions
200      GET      145l     2311w    14164c http://10.10.10.48/admin/LICENSE
200      GET       20l      170w     1085c http://10.10.10.48/admin/style/vendor/LICENSE
200      GET       20l      170w     1085c http://10.10.10.48/admin/scripts/vendor/LICENSE
[####################] - 1m    209993/209993  0s      found:10      errors:42     
[####################] - 1m     29999/29999   267/s   http://10.10.10.48 
[####################] - 1m     29999/29999   267/s   http://10.10.10.48/admin 
[####################] - 1m     29999/29999   263/s   http://10.10.10.48/admin/scripts 
[####################] - 1m     29999/29999   263/s   http://10.10.10.48/admin/img 
[####################] - 1m     29999/29999   268/s   http://10.10.10.48/admin/style 
[####################] - 1m     29999/29999   268/s   http://10.10.10.48/admin/style/vendor 
[####################] - 1m     29999/29999   268/s   http://10.10.10.48/admin/scripts/vendor

```

It finds `/admin` as expected.

#### /admin

This is a PiHole admin page:

[![image-20220513164854220](https://0xdfimages.gitlab.io/img/image-20220513164854220.png)](https://0xdfimages.gitlab.io/img/image-20220513164854220.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220513164854220.png)

I don’t have creds, and PiHole doesn’t have default creds.

### HTTP / Plex - TCP 32400

This site is a [Plex](https://www.plex.tv/) media server:

![image-20220513165649580](https://0xdfimages.gitlab.io/img/image-20220513165649580.png)

I’m not able to guess any creds, but I can create an account at the “Sign Up” link.

![image-20220513170101786](https://0xdfimages.gitlab.io/img/image-20220513170101786.png)

I won’t find much in here. On the Settings page, there is a version:

![image-20220513170142462](https://0xdfimages.gitlab.io/img/image-20220513170142462.png)

I am not able to find any exploits for this version or anything close.

### DNS - TCP 53

Given that Mirai is listening on TCP 53, I’ll want to check it for a zone transfer, using syntax like `dig axrf @10.10.10.48 [zone]`. I don’t have any hints towards hostnames so far. I can try `htb` and `mirai.htb`, but neither return anything interesting.

## Shell as pi

### Mirai Botnet Background

[Mirai](https://en.wikipedia.org/wiki/Mirai_(malware)) is a real malware that formed a huge network of bots, and is used to conduct distributed denial of service (DDOS) attacks. The compromised devices are largely made up of internet of things (IoT) devices running embedded processors like ARM and MIPS. The most famous Mirai attack was in October 2016, when the botnet degraded the service of Dyn, a DNS service provider, which resulted in making major sites across the internet (including NetFlix, Twitter, and GitHub) inaccessible. The sites were still up, but without DNS, no one could access them.

Mirai’s go-to attack was to brute force common default passwords. In fact, `mirai-botnet.txt` was added to [SecLists](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Malware/mirai-botnet.txt) in November 2017.

### SSH

The default creds for a Raspberry Pi device are pi / raspberry. I’ll try those here:

```

oxdf@hacky$ sshpass -p raspberry ssh pi@10.10.10.48
...[snip]...
pi@raspberrypi:~ $

```

It worked. I’ll grab `user.txt`:

```

pi@raspberrypi:~/Desktop $ cat user.txt
ff837707************************

```

## Shell as root

pi can run `sudo` as root for any command:

```

pi@raspberrypi:~/Desktop $ sudo -l
Matching Defaults entries for pi on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User pi may run the following commands on localhost:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL

```

`sudo su -` returns a root shell:

```

pi@raspberrypi:~/Desktop $ sudo su -

SSH is enabled and the default password for the 'pi' user has not been changed.
This is a security risk - please login as the 'pi' user and type 'passwd' to set a new password.

SSH is enabled and the default password for the 'pi' user has not been changed.
This is a security risk - please login as the 'pi' user and type 'passwd' to set a new password.

root@raspberrypi:~#

```

I use `-` at the end to tell `su` I want root’s environment variables, so it puts the shell in root’s homedirectory, etc. With or without the `-` get where I need to be here.

`sudo -i` also works:

```

pi@raspberrypi:~ $ sudo -i
...[snip]...
root@raspberrypi:~#

```

## root.txt

### Enumeration

`root.txt` isn’t the flag:

```

root@raspberrypi:~# cat root.txt 
I lost my original root.txt! I think I may have a backup on my USB stick...

```

USB media are typically mounted in `/media` on Linux. I can also look at `mount` to show all the mounted drives:

```

root@raspberrypi:~# mount
...[snip]...
/dev/sdb on /media/usbstick type ext4 (ro,nosuid,nodev,noexec,relatime,data=ordered)
tmpfs on /run/user/999 type tmpfs ...[snip]...

```

The raw device is `/dev/sdb`, and it is mounted on `/media/usbstick`. Another way to see this is `lsblk`:

```

root@raspberrypi:/# lsblk
NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
sda      8:0    0   10G  0 disk 
├─sda1   8:1    0  1.3G  0 part /lib/live/mount/persistence/sda1
└─sda2   8:2    0  8.7G  0 part /lib/live/mount/persistence/sda2
sdb      8:16   0   10M  0 disk /media/usbstick
sr0     11:0    1 1024M  0 rom  
loop0    7:0    0  1.2G  1 loop /lib/live/mount/rootfs/filesystem.squashfs

```

This directory has a single file, as well as an empty `lost+found` directory:

```

root@raspberrypi:/media/usbstick# find . -ls
     2    1 drwxr-xr-x   3 root     root         1024 Aug 14  2017 .
    11   12 drwx------   2 root     root        12288 Aug 14  2017 ./lost+found
    13    1 -rw-r--r--   1 root     root          129 Aug 14  2017 ./damnit.txt

```

### Recover Flag

#### Strategy

When I file gets deleted, the structure of the filesystem removes the metadata about that file. That includes the timestamps, filename, and a pointer to where the raw file is on disk. The delete operation does not go to that point on the disk and do anything to clean up the data, like write all nulls over it.

That means there’s a good chance that the contents of `root.txt` are still there, even if the filesystem no longer knows of a file by that name.

The raw USB device is `/dev/sdb`, and I can interact with that just like any other file. I’ll show a couple different ways to recover the flag.

#### grep / strings

`grep` is made to pull strings of a given pattern out of a file (which I can treat the raw device as). I’ll call with the following arguments:
- `-a` - Process a binary file as if it were text
- `-P` - Interpret PATTERN as a Perl regular expression
- `-o` - Print only the matched (non-empty) parts of a matching line, with each such part on a separate output line.

I’ll give it the pattern `[a-fA-F0-9]{32}`, which should find a 32-character hex string. It works:

```

root@raspberrypi:/# grep -aPo '[a-fA-F0-9]{32}' /dev/sdb
3d3e483143ff12ec505d026fa13e020b

```

Knowing that the flag is a string, I can also use `strings`:

```

root@raspberrypi:/# strings /dev/sdb -n 32
3d3e483143ff12ec505d026fa13e020b
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?

```

#### Copy Disk

I can also grab a copy of the USB disk and bring it back to my VM for more analysis. I’ll use a pipeline of commands to generate a copy on my machine in one line:

```

oxdf@hacky$ sshpass -p raspberry ssh pi@10.10.10.48 "sudo dd if=/dev/sdb | gzip -1 -" | dd of=usb.gz
512 bytes copied, 1 s, 0.4 kB/s20480+0 records in
20480+0 records out
10485760 bytes (10 MB) copied, 0.142368 s, 73.7 MB/s

93+1 records in
93+1 records out
48104 bytes (48 kB, 47 KiB) copied, 1.44623 s, 33.3 kB/s

```

I’ll break that down a bit:
- `sshpass -p raspberry` - use the password “raspberry” for the following SSH command (like `ssh` and `scp`)
- `ssh pi@10.10.10.48 "[command]"` - SSH into Mirai and run the command
- `sudo dd if=/dev/sdb` - read all of `/dev/sdb` and print it to STDOUT
- `| gzip -1 -` - compress the file read from STDIN (`-`) and print the result to STDOUT
- The result of that command run over SSH is now printed to STDOUT on my local VM
- `| dd =of=usb.gz` - write that output to `usb.gz`

I’ll decompress it:

```

oxdf@hacky$ file usb.gz 
usb.gz: gzip compressed data, last modified: Mon May 16 17:37:15 2022, max speed, from Unix, original size modulo 2^32 10485760
oxdf@hacky$ gunzip usb.gz 
oxdf@hacky$ file usb 
usb: Linux rev 1.0 ext4 filesystem data, UUID=635bcd7f-1d95-4229-bf13-3e722026db3c (extents) (huge files)
oxdf@hacky$ ls -hl usb 
-rwxrwx--- 1 root vboxsf 10M May 16 17:37 usb

```

The resulting file is a 10M ext4 partition.

#### extundelete

`extundelete` is a [data recovery utility](http://extundelete.sourceforge.net/) that works here to recover `root.txt`. I’ll install it (`sudo apt install extundelete`) and then run it with the `--recover-all` flag:

```

oxdf@hacky$ extundelete usb --restore-all
NOTICE: Extended attributes are not restored.
Loading filesystem metadata ... 2 groups loaded.
Loading journal descriptors ... 23 descriptors loaded.
Searching for recoverable inodes in directory / ... 
1 recoverable inodes found.
Looking through the directory structure for deleted files ... 
0 recoverable inodes still lost.

```

It claims to recover one file, and there’s a new `RECOVERED_FILES` directory. It has `root.txt`:

```

oxdf@hacky$ cat RECOVERED_FILES/root.txt
3d3e4831************************

```

#### Others

I did play around with some other recovery software. With `testdisk`, I was able to get it to list `root.txt`:

![image-20220516141246456](https://0xdfimages.gitlab.io/img/image-20220516141246456.png)

It’s in red because it’s deleted. Supposedly from here I can use `c` to copy the file and then `C` to store it somewhere, but the resulting file for me was still 0 bytes.

I tried `photorec` as well, but that program is tuned to look for images, and it doesn’t find `root.txt` at all. It will pull out `damnit.txt`.